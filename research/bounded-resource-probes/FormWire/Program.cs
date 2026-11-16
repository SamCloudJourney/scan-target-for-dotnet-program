using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;

const string Endpoint="http://127.0.0.1:17651";
const int MaxBody=72*1024;
var builder=WebApplication.CreateBuilder(new WebApplicationOptions {EnvironmentName=Environments.Production});
builder.Logging.ClearProviders();
builder.WebHost.UseUrls(Endpoint);
builder.WebHost.ConfigureKestrel(k=>{k.Limits.MaxRequestBodySize=128*1024;});
builder.Services.Configure<FormOptions>(o=>{
    o.KeyLengthLimit=2048;o.ValueLengthLimit=64*1024;o.ValueCountLimit=4;
});
var app=builder.Build();
app.MapGet("/health",()=>Results.Ok(new {alive=true}));
app.MapPost("/form",async ctx=>{
    var sw=Stopwatch.StartNew();
    var proc=Process.GetCurrentProcess();
    var c0=proc.TotalProcessorTime;
    string status="ok",error="";int xLength=-1, count=-1;
    try {
        var form=await ctx.Request.ReadFormAsync(ctx.RequestAborted);
        xLength=form["x"].ToString().Length;
        count=form.Count;
    } catch(Exception ex) {
        status="exception";error=ex.GetType().Name;
    }
    sw.Stop();proc.Refresh();
    ctx.Response.StatusCode=status=="ok"?200:400;
    await ctx.Response.WriteAsJsonAsync(new {
        status,error,xLength,count,
        processingMs=Math.Round(sw.Elapsed.TotalMilliseconds,3),
        cpuMs=Math.Round((proc.TotalProcessorTime-c0).TotalMilliseconds,3)
    });
});
await app.StartAsync();
using var healthHttp=new HttpClient(new SocketsHttpHandler{AllowAutoRedirect=false}){
    BaseAddress=new Uri(Endpoint),Timeout=TimeSpan.FromSeconds(5)
};
try {
    await Health("initial");
    var tests=new (string Name,string Body,int Chunk,bool Abort)[] {
        ("wire-basic-8k-4096","x="+new string('A',8192),4096,false),
        ("wire-basic-8k-128","x="+new string('A',8192),128,false),
        ("wire-basic-32k-64","x="+new string('B',32768),64,false),
        ("wire-percent-1","x=hello%20world&y=%E2%82%AC&z=A%2BB",1,false),
        ("wire-multikey-64","x="+new string('C',8192)+"&y=end",64,false),
        ("wire-overcount-2","a=1&b=2&c=3&d=4&e=5",2,false),
        ("wire-overvalue-512","x="+new string('D',66*1024),512,false),
        ("wire-cancel-midbody-64","x="+new string('E',16384),64,true),
        ("wire-post-cancel-valid-128","x=postcancel&y=ok",128,false),
    };
    foreach(var (name,body,chunk,abort) in tests) {
        byte[] input=Encoding.ASCII.GetBytes(body);
        if(input.Length>MaxBody)throw new InvalidDataException("Owned bounded fixture exceeded cap");
        var sw=Stopwatch.StartNew();
        var proc=Process.GetCurrentProcess();
        var cpu0=proc.TotalProcessorTime;
        int sent=0;
        string outcome="ok",responseLine="",error="",preview="";
        try {
            using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(9));
            using var tcp=new TcpClient{NoDelay=true};
            await tcp.ConnectAsync(IPAddress.Loopback,17651,cts.Token);
            using var wire=tcp.GetStream();
            var headers=Encoding.ASCII.GetBytes(
              "POST /form HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
            await wire.WriteAsync(headers,cts.Token);
            for(int pos=0;pos<input.Length;pos+=chunk){
                if(abort && sent==16){outcome="client-aborted";break;}
                int n=Math.Min(chunk,input.Length-pos);
                var framing=Encoding.ASCII.GetBytes(n.ToString("X")+"\r\n");
                await wire.WriteAsync(framing,cts.Token);
                await wire.WriteAsync(input.AsMemory(pos,n),cts.Token);
                await wire.WriteAsync("\r\n"u8.ToArray(),cts.Token);
                sent++;
                if(chunk<4096)await Task.Delay(1,cts.Token);
            }
            if(!abort){
                await wire.WriteAsync("0\r\n\r\n"u8.ToArray(),cts.Token);
                await wire.FlushAsync(cts.Token);
                using var result=new MemoryStream();
                await wire.CopyToAsync(result,cts.Token);
                string raw=Encoding.ASCII.GetString(result.ToArray());
                responseLine=raw.Split("\r\n",2)[0];
                preview=raw.Length>500?raw[^500..]:raw;
            } else tcp.Close();
        }catch(Exception e) {
            outcome="exception";error=e.GetType().Name;
        }
        sw.Stop();proc.Refresh();
        Console.WriteLine(JsonSerializer.Serialize(new{
            test=name,status=outcome,error,responseLine,preview,
            payloadBytes=input.Length,writeChunkBytes=chunk,numberOfChunkFramesSent=sent,
            elapsedMs=Math.Round(sw.Elapsed.TotalMilliseconds,2),
            cpuMs=Math.Round((proc.TotalProcessorTime-cpu0).TotalMilliseconds,2),
            framework=RuntimeInformation.FrameworkDescription
        }));
        await Health("after-"+name);
    }
} finally {await app.StopAsync(TimeSpan.FromSeconds(2));}
return 0;

async Task Health(string test) {
    var sw=Stopwatch.StartNew();
    using var r=await healthHttp.GetAsync("/health");
    sw.Stop();
    Console.WriteLine(JsonSerializer.Serialize(new{
        test,category="health",statusCode=(int)r.StatusCode,
        elapsedMs=Math.Round(sw.Elapsed.TotalMilliseconds,2),
        framework=RuntimeInformation.FrameworkDescription
    }));
    if(!r.IsSuccessStatusCode)throw new Exception("Unrelated loopback service unavailable");
}
