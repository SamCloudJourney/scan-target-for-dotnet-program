using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.DiaSymReader.Tools;

bool repeat3=args.Length == 6 && args[5] == "repeat3";
if ((args.Length != 5 && !repeat3) || !int.TryParse(args[2],out int declared) ||
    (declared != 0 && declared != 1048576 && declared != 8388608) ||
    !bool.TryParse(args[3],out bool includeSources) ||
    !bool.TryParse(args[4],out bool useNative))
{
    Console.Error.WriteLine("Usage: XmlConsumer SourceSample.pdb SourceSample.dll 0|1048576|8388608 true|false true|false");
    return 2;
}
byte[] pdb=File.ReadAllBytes(args[0]);
byte[] pe=File.ReadAllBytes(args[1]);
if(pdb.Length > 128*1024 || pe.Length > 128*1024 || pdb.Length < 4 ||
   !pdb.AsSpan(0,4).SequenceEqual("BSJB"u8)) throw new InvalidDataException("Only owned small portable PDB input allowed");
int offset=-1, original=-1;
var kindGuid=new Guid("0E8A571B-6926-466E-B4AD-8AB04611F5FE");
using(var stream=new MemoryStream(pdb))
using(var provider=MetadataReaderProvider.FromPortablePdbStream(stream,MetadataStreamOptions.LeaveOpen)){
    var md=provider.GetMetadataReader();
    foreach(var document in md.Documents){
        foreach(var handle in md.GetCustomDebugInformation(MetadataTokens.EntityHandle(MetadataTokens.GetToken(document)))){
            var cdi=md.GetCustomDebugInformation(handle);
            if(md.GetGuid(cdi.Kind)!=kindGuid)continue;
            var blob=md.GetBlobBytes(cdi.Value);
            if(blob.Length<8)continue;
            offset=pdb.AsSpan().IndexOf(blob);
            if(offset>=0){original=BitConverter.ToInt32(blob);break;}
        }
        if(offset>=0)break;
    }
}
if(offset<0)throw new InvalidDataException("Fixture missing embedded source");
byte[] validPdb=(byte[])pdb.Clone();
if(declared>0)BitConverter.GetBytes(declared).CopyTo(pdb,offset);
var opts=PdbToXmlOptions.ExcludeMethods;
if(includeSources)opts|=PdbToXmlOptions.IncludeEmbeddedSources;
if(useNative)opts|=PdbToXmlOptions.UseNativeReader;
string status="ok", error="";int xmlChars=-1;
var timer=Stopwatch.StartNew();
long before=GC.GetTotalAllocatedBytes();
try{
    using var ps=new MemoryStream(pdb,writable:false);
    using var asm=new MemoryStream(pe,writable:false);
    string xml=PdbToXmlConverter.ToXml(ps,asm,opts);
    xmlChars=xml.Length;
}catch(Exception e){status="exception";error=e.GetType().FullName??e.GetType().Name;}
timer.Stop();
Console.WriteLine(JsonSerializer.Serialize(new {
    test="official-pdb2xml-embedded-source-consumer",status,error,
    includeSources,useNative,declared,original,pdbBytes=pdb.Length,peBytes=pe.Length,
    xmlChars,allocatedBytes=GC.GetTotalAllocatedBytes()-before,
    elapsedMs=Math.Round(timer.Elapsed.TotalMilliseconds,3),
    runtime=RuntimeInformation.FrameworkDescription,os=RuntimeInformation.OSDescription
}));
if (repeat3)
{
    var proc=Process.GetCurrentProcess();
    for(int iteration=1;iteration<=3;iteration++)
    {
        var timer2=Stopwatch.StartNew();
        long b=GC.GetTotalAllocatedBytes();
        int g=GC.CollectionCount(2);
        string bad=ConvertOnce(pdb,pe,opts);
        string good=ConvertOnce(validPdb,pe,opts);
        timer2.Stop();proc.Refresh();
        Console.WriteLine(JsonSerializer.Serialize(new {
            test="pdb2xml-same-process-recovery",iteration,declared,
            includeSources,useNative,malformedResult=bad,validResult=good,
            allocatedBytes=GC.GetTotalAllocatedBytes()-b,
            gen2Collections=GC.CollectionCount(2)-g,
            workingSet=proc.WorkingSet64,privateMemory=proc.PrivateMemorySize64,
            elapsedMs=Math.Round(timer2.Elapsed.TotalMilliseconds,3)
        }));
        if (good!="ok") throw new InvalidDataException("Controlled benign converter recovery failed");
    }
}
return 0;

static string ConvertOnce(byte[] p,byte[] a,PdbToXmlOptions opt)
{
    try{
        using var ps=new MemoryStream(p,writable:false);
        using var asm=new MemoryStream(a,writable:false);
        _=PdbToXmlConverter.ToXml(ps,asm,opt);
        return "ok";
    }catch(Exception e){return e.GetType().Name;}
}
