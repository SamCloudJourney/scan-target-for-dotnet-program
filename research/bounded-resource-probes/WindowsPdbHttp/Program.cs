using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.DiaSymReader;

const string Base = "http://127.0.0.1:17789";
const int MaxPdbUpload = 128 * 1024;
const int MaxDeclared = 8 * 1024 * 1024;
if(args.Length != 1) throw new ArgumentException("Expected self-generated SourceSample.pdb path.");
byte[] original = File.ReadAllBytes(args[0]);
if(original.Length<8 || original.Length>MaxPdbUpload || !original.AsSpan(0,4).SequenceEqual("BSJB"u8))
    throw new InvalidDataException("Only controlled small Portable PDB accepted");
var altered = (byte[])original.Clone();
PatchDeclared(altered,MaxDeclared);

var builder = WebApplication.CreateBuilder(new WebApplicationOptions {
    Args=Array.Empty<string>(), EnvironmentName=Environments.Production
});
builder.Logging.ClearProviders();
builder.WebHost.UseUrls(Base);
builder.WebHost.ConfigureKestrel(o=>o.Limits.MaxRequestBodySize=MaxPdbUpload);
var app=builder.Build();
int healthCount=0;
app.MapGet("/health",() => Results.Json(new{ok=true,count=Interlocked.Increment(ref healthCount)}));

app.MapPost("/pdb", async (HttpContext ctx) => {
    var sw=Stopwatch.StartNew();
    bool guarded=ctx.Request.Query["guarded"]=="true";
    long before=GC.GetTotalAllocatedBytes();
    string state="ok",error="";
    int sourceBytes=-1, inputBytes=-1;
    try {
        using var incoming=new MemoryStream();
        await ctx.Request.Body.CopyToAsync(incoming,ctx.RequestAborted);
        inputBytes=checked((int)incoming.Length);
        if(inputBytes>MaxPdbUpload)throw new InvalidDataException("Owned upload cap");
        byte[] uploaded=incoming.ToArray();
        if(uploaded.Length<8 || !uploaded.AsSpan(0,4).SequenceEqual("BSJB"u8))
            throw new InvalidDataException("Missing Portable PDB magic");
        if(guarded) CheckEmbeddedSourceBudget(uploaded);
        sourceBytes=ReadRealWindowsEmbeddedSource(uploaded);
    }
    catch(Exception e){state="rejected";error=e.GetType().Name;}
    sw.Stop();
    ctx.Response.StatusCode=state=="ok" ? 200 : 422;
    await ctx.Response.WriteAsJsonAsync(new {
        state,error,guarded,sourceBytes,inputBytes,
        elapsedMs=Math.Round(sw.Elapsed.TotalMilliseconds,3),
        allocatedBytes=GC.GetTotalAllocatedBytes()-before
    });
});

await app.StartAsync();
using var client=new HttpClient(new SocketsHttpHandler{AllowAutoRedirect=false}) {
    BaseAddress=new Uri(Base),Timeout=TimeSpan.FromSeconds(8)
};
try {
    await Health("start");
    await Post("valid-native-extract",original,false);
    await Post("forged-native-extract",altered,false);
    await Health("after-forged-rejection");
    await Post("valid-after-rejection",original,false);
    await Post("guarded-valid",original,true);
    await Post("guarded-forged",altered,true);
    await Health("after-guarded-rejection");
    long before=GC.GetTotalAllocatedBytes();
    var three=Enumerable.Range(0,3).Select(i=>Post("three-parallel-"+i,altered,false)).ToArray();
    await Task.Delay(2);
    await Health("during-three-parallel");
    await Task.WhenAll(three);
    long allocated=GC.GetTotalAllocatedBytes()-before;
    Console.WriteLine(JsonSerializer.Serialize(new{
        test="parallel-global-allocation",count=3,allocatedBytes=allocated,
        framework=RuntimeInformation.FrameworkDescription
    }));
    await Health("after-three-parallel");
    await Post("valid-after-three-parallel",original,false);
    var modules=Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
        .Where(m=>m.ModuleName.Contains("DiaSymReader",StringComparison.OrdinalIgnoreCase))
        .Select(m=>m.ModuleName).Distinct().ToArray();
    Console.WriteLine(JsonSerializer.Serialize(new{
        test="native-symbol-reader-modules",modules,framework=RuntimeInformation.FrameworkDescription
    }));
}
finally {await app.StopAsync(TimeSpan.FromSeconds(2));}
return 0;

async Task Health(string name) {
    var sw=Stopwatch.StartNew();
    using var response=await client.GetAsync("/health");
    string data=await response.Content.ReadAsStringAsync();
    sw.Stop();
    Console.WriteLine(JsonSerializer.Serialize(new {
        test=name,kind="health",status=(int)response.StatusCode,
        elapsedMs=Math.Round(sw.Elapsed.TotalMilliseconds,3),
        body=data,framework=RuntimeInformation.FrameworkDescription
    }));
    if(response.StatusCode!=HttpStatusCode.OK)throw new InvalidOperationException("Health check unavailable");
}
async Task Post(string name,byte[] data,bool guard){
    var sw=Stopwatch.StartNew();
    using var body=new ByteArrayContent(data);
    using var r=await client.PostAsync(guard?"/pdb?guarded=true":"/pdb",body);
    string text=await r.Content.ReadAsStringAsync();
    sw.Stop();
    string expectedState=guard || name.StartsWith("valid") ? "ok" : "rejected";
    bool validName=name.StartsWith("valid") || name=="guarded-valid";
    int expected=validName ? 200 : 422;
    if((int)r.StatusCode != expected)
        throw new InvalidDataException("Unexpected controlled parser response for "+name+
           " expected="+expected+" actual="+(int)r.StatusCode+" "+text);
    Console.WriteLine(JsonSerializer.Serialize(new {
        test=name,kind="pdb-http",status=(int)r.StatusCode,
        bytesOnWire=data.Length,guarded=guard,
        elapsedMs=Math.Round(sw.Elapsed.TotalMilliseconds,3),
        response=text,framework=RuntimeInformation.FrameworkDescription
    }));
}
static int ReadRealWindowsEmbeddedSource(byte[] pdb){
    using var stream=new MemoryStream(pdb,writable:false);
    var reader=SymUnmanagedReaderFactory.CreateReader<ISymUnmanagedReader3>(
         stream,new LocalMetadataProvider());
    Marshal.ThrowExceptionForHR(reader.GetDocuments(0,out int count,Array.Empty<ISymUnmanagedDocument>()));
    if(count is <1 or >16) throw new InvalidDataException("Unexpected controlled PDB document count");
    var documents=new ISymUnmanagedDocument[count];
    Marshal.ThrowExceptionForHR(reader.GetDocuments(count,out int copied,documents));
    foreach(var doc in documents.Take(copied)) {
        if(doc is null)continue;
        Marshal.ThrowExceptionForHR(doc.HasEmbeddedSource(out bool has));
        if(!has)continue;
        return doc.GetEmbeddedSource().Count;
    }
    throw new InvalidDataException("No embedded source in test fixture");
}
static void PatchDeclared(byte[] pdb,int declared){
    int offset=FindSourceHeader(pdb);
    BitConverter.GetBytes(declared).CopyTo(pdb,offset);
}
static void CheckEmbeddedSourceBudget(byte[] pdb) {
    const int Budget=256*1024;
    int offset=FindSourceHeader(pdb);
    int declared=BitConverter.ToInt32(pdb,offset);
    if(declared<0 || declared>Budget)throw new InvalidDataException("Investigators guard: source size cap");
}
static int FindSourceHeader(byte[] pdb){
    var kind=new Guid("0E8A571B-6926-466E-B4AD-8AB04611F5FE");
    using var stream=new MemoryStream(pdb);
    using var provider=MetadataReaderProvider.FromPortablePdbStream(
        stream,MetadataStreamOptions.LeaveOpen);
    var md=provider.GetMetadataReader();
    foreach(var document in md.Documents) {
        foreach(var item in md.GetCustomDebugInformation(
            MetadataTokens.EntityHandle(MetadataTokens.GetToken(document)))) {
            var info=md.GetCustomDebugInformation(item);
            if(md.GetGuid(info.Kind)!=kind)continue;
            byte[] blob=md.GetBlobBytes(info.Value);
            if(blob.Length<4)continue;
            int off=pdb.AsSpan().IndexOf(blob);
            if(off>=0)return off;
        }
    }
    throw new InvalidDataException("Controlled fixture contains no embedded source record");
}
sealed class LocalMetadataProvider:ISymReaderMetadataProvider {
    public unsafe bool TryGetStandaloneSignature(int token,out byte* signature,out int length){
        signature=null;length=0;return false;
    }
    public bool TryGetTypeDefinitionInfo(int token,out string namespaceName,out string typeName,out TypeAttributes attributes){
        namespaceName="";typeName="";attributes=0;return false;
    }
    public bool TryGetTypeReferenceInfo(int token,out string namespaceName,out string typeName){
        namespaceName="";typeName="";return false;
    }
}
