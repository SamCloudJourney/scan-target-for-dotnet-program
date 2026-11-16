using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;

const int Port = 17661;
AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
var builder=WebApplication.CreateBuilder(new WebApplicationOptions{Args=[],EnvironmentName=Environments.Production});
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(o=> {
    o.ListenLocalhost(Port,e=>e.Protocols=HttpProtocols.Http2);
    o.Limits.MaxRequestBodySize=128*1024;
});
builder.Services.Configure<FormOptions>(o=>{o.ValueLengthLimit=64*1024;o.KeyLengthLimit=2048;o.ValueCountLimit=4;});
var app=builder.Build();
app.MapGet("/health",(HttpContext ctx)=>Results.Json(new{alive=true,protocol=ctx.Request.Protocol,connectionId=ctx.Connection.Id}));
app.MapPost("/form",async (HttpContext ctx)=>{
    var watch=Stopwatch.StartNew();
    string state="ok",error="";int fields=-1,n=-1;
    try {var form=await ctx.Request.ReadFormAsync(ctx.RequestAborted);fields=form.Count;n=form["x"].ToString().Length;}
    catch(Exception e){state="rejected";error=e.GetType().Name;}
    watch.Stop();
    ctx.Response.StatusCode=state=="ok"?200:400;
    await ctx.Response.WriteAsJsonAsync(new {state,error,fields,xLength=n,protocol=ctx.Request.Protocol,
        processingMs=Math.Round(watch.Elapsed.TotalMilliseconds,3),connectionId=ctx.Connection.Id});
});
await app.StartAsync();
using var http=new HttpClient(new SocketsHttpHandler{AllowAutoRedirect=false,
    PooledConnectionLifetime=TimeSpan.FromSeconds(30)}) {
    BaseAddress=new Uri($"http://127.0.0.1:{Port}"),
    DefaultRequestVersion=HttpVersion.Version20,
    DefaultVersionPolicy=HttpVersionPolicy.RequestVersionExact,
    Timeout=TimeSpan.FromSeconds(7)
};
try {
    await Health("before");
    var cases=new (string Name,string Body,int Chunk,bool Abort)[] {
        ("h2-8k-single","x="+new string('A',8192),16384,false),
        ("h2-8k-128","x="+new string('A',8192),128,false),
        ("h2-8k-32","x="+new string('A',8192),32,false),
        ("h2-32k-512","x="+new string('B',32768),512,false),
        ("h2-percent-1","x=hello%20world&y=%E2%82%AC&z=A%2BB",1,false),
        ("h2-multifield","x="+new string('C',8192)+"&y=ok",64,false),
        ("h2-overcount","a=1&b=2&c=3&d=4&e=5",2,false),
        ("h2-overvalue","x="+new string('D',66*1024),512,false),
        ("h2-reset","x="+new string('E',16*1024),64,true),
        ("h2-post-reset","x=after&y=ok",16,false),
    };
    foreach(var (name,body,chunk,abort) in cases) {
        var bytes=Encoding.ASCII.GetBytes(body);
        if(bytes.Length>72*1024)throw new InvalidDataException("Input limit exceeded");
        var watch=Stopwatch.StartNew();
        var proc=Process.GetCurrentProcess();var cpu0=proc.TotalProcessorTime;
        string status="ok",error="",protocol="",responseText="";int statusCode=-1;
        try{
            using var content=new FragmentContent(bytes,chunk,abort?1024:-1);
            using var response=await http.PostAsync("/form",content);
            statusCode=(int)response.StatusCode;
            protocol=response.Version.ToString();
            responseText=await response.Content.ReadAsStringAsync();
            if(!abort && response.Version!=HttpVersion.Version20)throw new InvalidDataException("HTTP2 required");
            if(!abort && name.Contains("over") && statusCode!=400)throw new InvalidDataException("Expected form limits");
            if(!abort && !name.Contains("over") && statusCode!=200)throw new InvalidDataException("Valid form rejected");
        }catch(Exception e){
            status=abort?"controlled-reset":"exception";error=e.GetType().Name;
            if(!abort)throw;
        }
        watch.Stop();proc.Refresh();
        Console.WriteLine(JsonSerializer.Serialize(new {
            test=name,status,error,protocol,statusCode,bodyBytes=bytes.Length,chunkBytes=chunk,
            wallMs=Math.Round(watch.Elapsed.TotalMilliseconds,3),
            processCpuMs=Math.Round((proc.TotalProcessorTime-cpu0).TotalMilliseconds,3),
            response=responseText.Length>300?responseText[..300]:responseText,
            runtime=RuntimeInformation.FrameworkDescription
        }));
        await Health("after-"+name);
        if(name=="h2-reset")await Task.WhenAll(Health("after-reset-concurrent-a"),Health("after-reset-concurrent-b"));
    }
}finally{await app.StopAsync(TimeSpan.FromSeconds(2));}
return 0;
async Task Health(string name){
    using var response=await http.GetAsync("/health");
    var body=await response.Content.ReadAsStringAsync();
    Console.WriteLine(JsonSerializer.Serialize(new {
        test=name,category="health",statusCode=(int)response.StatusCode,
        protocol=response.Version.ToString(),body,runtime=RuntimeInformation.FrameworkDescription
    }));
    if(!response.IsSuccessStatusCode || response.Version!=HttpVersion.Version20)
        throw new InvalidDataException("Local HTTP2 health control failed");
}
sealed class FragmentContent:HttpContent{
    readonly byte[] bytes;readonly int chunk;readonly int abortAt;
    public FragmentContent(byte[] b,int c,int a){bytes=b;chunk=c;abortAt=a;Headers.ContentType=new MediaTypeHeaderValue("application/x-www-form-urlencoded");}
    protected override bool TryComputeLength(out long l){l=0;return false;}
    protected override async Task SerializeToStreamAsync(Stream stream,TransportContext? context){
        int i=0,k=0;
        for(;i<bytes.Length;i+=chunk){
            if(abortAt>=0 && i>=abortAt)throw new OperationCanceledException("Controlled stream reset");
            int n=Math.Min(chunk,bytes.Length-i);
            await stream.WriteAsync(bytes.AsMemory(i,n));
            await stream.FlushAsync();
            if((++k&15)==0)await Task.Delay(1);
        }
    }
}
