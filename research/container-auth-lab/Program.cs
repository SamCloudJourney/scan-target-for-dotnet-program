// Synthetic loopback-only lab. Exercises Microsoft.NET.Build.Containers.dll from each installed SDK.
using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

await Laboratory.RunAsync();

record Observation(string Role, string Method, string Path, bool SyntheticBasic, bool SyntheticPasswordBody, bool SyntheticBearer);

sealed class LocalEndpoint : IAsyncDisposable
{
    public int Port {get;}
    private readonly WebApplication _app;
    private LocalEndpoint(WebApplication app, int port){_app=app;Port=port;}
    public static async Task<LocalEndpoint> Start(string ip, Func<HttpContext,Task> serve)
    {
        var b=WebApplication.CreateSlimBuilder();
        b.Logging.ClearProviders();
        b.WebHost.ConfigureKestrel(x => x.Listen(IPAddress.Parse(ip), 0));
        var app=b.Build();
        app.Run(serve);
        await app.StartAsync();
        var addresses=app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses;
        return new LocalEndpoint(app, new Uri(addresses.Single()).Port);
    }
    public async ValueTask DisposeAsync(){await _app.StopAsync();await _app.DisposeAsync();}
}

static class Laboratory
{
    private const string User="LAB_USER_NON_SECRET";
    private const string Pass="LAB_PASS_SYNTHETIC_ONLY_20261116";
    private const string Token="LAB_BEARER_NON_SECRET";
    private const string IpRegistry="127.0.0.1";
    private const string IpProtected="127.0.0.2";
    private const string DnsAlias="privateauth.lab.test";
    private static readonly List<object> Reports=[];
    private static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    private static readonly string AssemblyPath=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")??"";
    private static readonly bool Is11=Sdk.StartsWith("11.");
    private static Assembly? LoadedAssembly;

    public static async Task RunAsync()
    {
        if(!File.Exists(AssemblyPath))throw new FileNotFoundException("Missing target SDK assembly",AssemblyPath);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_UNAME",User);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_PWORD",Pass);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",User);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",Pass);
        var dir=Path.GetDirectoryName(AssemblyPath)!;
        AssemblyLoadContext.Default.Resolving+=(ctx,name)=>{
            var path=Path.Combine(dir,name.Name+".dll");
            return File.Exists(path)?ctx.LoadFromAssemblyPath(path):null;
        };
        LoadedAssembly=AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(AssemblyPath));
        Console.WriteLine("SDK "+Sdk+" assembly "+AssemblyPath+" version "+LoadedAssembly.GetName().Version);
        bool allPassed=true;
        try
        {
            foreach(var scenario in new[]{"normal","direct-protected","dns-protected","redirect307","redirect302"})
            {
                bool passed=await RunScenario(scenario);
                Console.WriteLine(scenario+": "+(passed?"PASS":"FAIL"));
                allPassed&=passed;
            }
        }
        finally
        {
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+".json",JsonSerializer.Serialize(new{sdk=Sdk,assembly=AssemblyPath,results=Reports},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!allPassed)throw new Exception("Auth boundary assertion(s) failed; consult evidence artifact");
    }
    private static HttpClient CreateClient(string registryHost)
    {
        var type=LoadedAssembly!.GetType("Microsoft.NET.Build.Containers.AuthHandshakeMessageHandler",true)!;
        var modeType=LoadedAssembly.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!;
        var mode=Enum.Parse(modeType,"Push");
        var inner=new SocketsHttpHandler{UseCookies=false,UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(4)};
        object[] args=Is11? [registryHost,true,inner,NullLogger.Instance,mode]:[registryHost,inner,NullLogger.Instance,mode];
        var ctor=type.GetConstructors(BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance).Single(c=>c.GetParameters().Length==args.Length);
        return new HttpClient((HttpMessageHandler)ctor.Invoke(args)){Timeout=TimeSpan.FromSeconds(10)};
    }
    private static Observation Capture(string role,HttpContext c,string body)
    {
        var header=c.Request.Headers.Authorization.ToString();
        var expected="Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(User+":"+Pass));
        return new Observation(role,c.Request.Method,c.Request.Path.ToString(),header==expected,body.Contains(Pass,StringComparison.Ordinal),header=="Bearer "+Token);
    }
    private static async Task Reply(HttpContext c,int status,string body="",string? location=null,string? challenge=null)
    {
        c.Response.StatusCode=status;
        if(location!=null)c.Response.Headers.Location=location;
        if(challenge!=null)c.Response.Headers.WWWAuthenticate=challenge;
        if(status==200)c.Response.ContentType="application/json";
        if(body.Length>0)await c.Response.WriteAsync(body);
    }
    private static string JsonToken=>"{\"token\":\""+Token+"\",\"expires_in\":300}";
    private static async Task<bool> RunScenario(string scenario)
    {
        var regObs=new ConcurrentQueue<Observation>();
        var allowedObs=new ConcurrentQueue<Observation>();
        var protectObs=new ConcurrentQueue<Observation>();
        string? realm=null,location=null;
        await using var protectedEnd=await LocalEndpoint.Start(IpProtected,async c=>{
            var body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            protectObs.Enqueue(Capture("protected",c,body));
            await Reply(c,200,JsonToken);
        });
        await using var allowed=await LocalEndpoint.Start(IpRegistry,async c=>{
            var body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            allowedObs.Enqueue(Capture("allowed",c,body));
            if(scenario.StartsWith("redirect"))
            {
                if(c.Request.Method=="GET")await Reply(c,405);
                else await Reply(c,scenario=="redirect307"?307:302,location:location);
            }
            else await Reply(c,200,JsonToken);
        });
        realm=scenario switch{
            "normal" or "redirect307" or "redirect302"=>"http://"+IpRegistry+":"+allowed.Port+"/token",
            "direct-protected"=>"http://"+IpProtected+":"+protectedEnd.Port+"/token",
            "dns-protected"=>"http://"+DnsAlias+":"+protectedEnd.Port+"/token",
            _=>throw new ArgumentOutOfRangeException(nameof(scenario))
        };
        location="http://"+IpProtected+":"+protectedEnd.Port+"/capture";
        await using var registry=await LocalEndpoint.Start(IpRegistry,async c=>{
            var body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            var sample=Capture("registry",c,body);
            regObs.Enqueue(sample);
            if(sample.SyntheticBearer)await Reply(c,200,"{}");
            else await Reply(c,401,challenge:"Bearer realm=\""+realm+"\",service=\"lab\",scope=\"repo:demo:push\"");
        });
        int? status=null;string? error=null;
        try
        {
            using var client=CreateClient(IpRegistry+":"+registry.Port);
            using var response=await client.GetAsync("http://"+IpRegistry+":"+registry.Port+"/v2/");
            status=(int)response.StatusCode;
        }
        catch(Exception ex){error=ex.GetBaseException().GetType().Name+": "+ex.GetBaseException().Message;}
        var pr=protectObs.ToArray();var al=allowedObs.ToArray();var rg=regObs.ToArray();
        bool basicProtected=pr.Any(e=>e.SyntheticBasic),passwordProtected=pr.Any(e=>e.SyntheticPasswordBody);
        bool privatePost=pr.Any(e=>e.Method=="POST"),registryToken=rg.Any(e=>e.SyntheticBearer);
        bool basicAllowed=al.Any(e=>e.SyntheticBasic),privateCalled=pr.Length>0;
        bool passed=scenario switch{
            "normal"=>status==200 && basicAllowed && registryToken && !privateCalled,
            "direct-protected"=>Is11?(!privateCalled && error!=null):(status==200 && basicProtected && registryToken),
            "dns-protected"=>status==200 && basicProtected && registryToken,
            "redirect307"=>status==200 && privatePost && passwordProtected && registryToken,
            "redirect302"=>status==200 && privateCalled && !passwordProtected && !privatePost && registryToken,
            _=>false
        };
        Reports.Add(new{scenario,passed,status,error,realmHost=new Uri(realm).Host,registryRequestCount=rg.Length,
            allowedRequestCount=al.Length,protectedRequestCount=pr.Length,registryGotSyntheticBearer=registryToken,
            allowedGotSyntheticBasic=basicAllowed,protectedGotSyntheticBasic=basicProtected,
            protectedGotSyntheticPasswordBody=passwordProtected,protectedGotPost=privatePost,
            observations=rg.Concat(al).Concat(pr)});
        Console.WriteLine($"[{Sdk}] {scenario}: status={status}, exception={error?.Split(':')[0]??"none"}, protectedHit={privateCalled}, protectedBasic={basicProtected}, protectedPasswordPost={passwordProtected}, registryBearer={registryToken}");
        return passed;
    }
}
