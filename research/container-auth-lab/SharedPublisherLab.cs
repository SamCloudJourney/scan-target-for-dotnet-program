// Isolated two-principal HTTP publishing service. Uses real shipped DefaultRegistryAPI.Manifest.PutAsync.
// Two independently authenticated callers, distinct synthetic registry credentials, one process.
// The protected resource, identity provider, and registry all live on the local CI runner.
using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

static class SharedPublisherLab
{
    const string AUser="SHARED_PUBLISH_ADMIN";
    const string APass="SHARED_PUBLISH_ADMIN_SECRET_SYNTH";
    const string BUser="SHARED_PUBLISH_READER";
    const string BPass="SHARED_PUBLISH_READER_SECRET_SYNTH";
    const string AToken="SHARED_PUBLISH_ADMIN_BEARER";
    const string BToken="SHARED_PUBLISH_READER_BEARER";
    const string Host="registry.lab.test";
    const string Other="registry-alt.lab.test";
    const string AuthHost="publicauth.lab.test";
    const string Repository="tenant-a/private";
    const string ManifestType="application/vnd.oci.image.manifest.v1+json";
    static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    static readonly bool Patched=Sdk.StartsWith("12.",StringComparison.Ordinal);
    static readonly List<object> Tests=[];
    static readonly ConcurrentQueue<object> Network=[];
    static int AWrites;
    static int BWritesWithAToken;
    static int IssuedA;
    static int IssuedB;
    static string Basic(string u,string p)=>"Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(u+":"+p));

    static object NewRegistryApi(Assembly asm,string hostname)
    {
        var type=asm.GetType("Microsoft.NET.Build.Containers.DefaultRegistryAPI",true)!;
        var modeType=asm.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!;
        return Activator.CreateInstance(type,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,null,
            [hostname,new Uri("https://"+hostname+"/"),false,NullLogger.Instance,Enum.Parse(modeType,"Push")],null)!;
    }

    static string Identity(HttpContext c)
    {
        string h=c.Request.Headers.Authorization.ToString();
        if(h==Basic(AUser,APass))return "basic-A";
        if(h==Basic(BUser,BPass))return "basic-B";
        if(h=="Bearer "+AToken)return "bearer-A";
        if(h=="Bearer "+BToken)return "bearer-B";
        return h.Length==0?"none":"unknown";
    }

    static void Credentials(string who)
    {
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",
            who=="A"?AUser:who=="B"?BUser:null);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
            who=="A"?APass:who=="B"?BPass:null);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_UNAME",null);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_PWORD",null);
    }

    static async Task<bool> PublishViaSdk(Assembly asm,string endpoint,string body)
    {
        try
        {
            var api=NewRegistryApi(asm,endpoint);
            object ops=api.GetType().GetProperty("Manifest")!.GetValue(api)!;
            MethodInfo method=ops.GetType().GetMethod("PutAsync")!;
            var task=(Task)method.Invoke(ops,[Repository,"latest",body,ManifestType,CancellationToken.None])!;
            await task;
            return true;
        }
        catch(Exception ex)
        {
            var root=ex is TargetInvocationException {InnerException:not null} ? ex.InnerException:ex;
            Console.WriteLine("[PUBLISHER "+Sdk+"] expected/possible deny "+root!.GetType().Name);
            return false;
        }
    }

    public static async Task RunAsync()
    {
        var keep=new Dictionary<string,string?>();
        foreach(var key in new[]{"DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
                     "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD","REGISTRY_AUTH_FILE","DOCKER_CONFIG"})
            keep[key]=Environment.GetEnvironmentVariable(key);
        IWebProxy previousProxy=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        string emptyAuth=Path.Combine(Path.GetTempPath(),"two-user-auth-"+Guid.NewGuid().ToString("N")+".json");
        File.WriteAllText(emptyAuth,"{\"auths\":{}}");
        Environment.SetEnvironmentVariable("REGISTRY_AUTH_FILE",emptyAuth);
        Environment.SetEnvironmentVariable("DOCKER_CONFIG",Path.GetDirectoryName(emptyAuth));
        bool passed=false;
        try{passed=await TestService();}
        finally
        {
            HttpClient.DefaultProxy=previousProxy;
            foreach(var kv in keep)Environment.SetEnvironmentVariable(kv.Key,kv.Value);
            File.Delete(emptyAuth);
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-shared-publisher.json",
                JsonSerializer.Serialize(new{sdk=Sdk,tests=Tests,network=Network.ToArray()},
                    new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!passed)throw new Exception("Two-user publishing boundary assertions failed");
    }

    static async Task<bool> TestService()
    {
        string assemblyPath=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")!;
        Assembly asm=AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(assemblyPath));
        await using var tokens=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            string id=Identity(ctx);
            Network.Enqueue(new{at="auth",method=ctx.Request.Method,identity=id});
            if(id is "basic-A" or "basic-B")
            {
                if(id=="basic-A")Interlocked.Increment(ref IssuedA);
                else Interlocked.Increment(ref IssuedB);
                ctx.Response.StatusCode=200;
                ctx.Response.ContentType="application/json";
                await ctx.Response.WriteAsync(JsonSerializer.Serialize(new{
                    token=id=="basic-A"?AToken:BToken,expires_in=300
                }));
            }
            else ctx.Response.StatusCode=403;
        },tls:true);
        string challenge="Bearer realm=\"https://"+AuthHost+":"+tokens.Port+"/token\",service=\"independent-auth\"";
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            string identity=Identity(ctx);
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            bool isWrite=ctx.Request.Method=="PUT"&&ctx.Request.Path.Value?.Contains("/manifests/",StringComparison.Ordinal)==true;
            string caller=body.Contains("\"caller\":\"B\"",StringComparison.Ordinal)?"B":
                body.Contains("\"caller\":\"A\"",StringComparison.Ordinal)?"A":"unknown";
            Network.Enqueue(new{at="registry",method=ctx.Request.Method,identity,caller,isWrite});
            if(identity=="bearer-A")
            {
                if(isWrite)
                {
                    if(caller=="A")Interlocked.Increment(ref AWrites);
                    if(caller=="B")Interlocked.Increment(ref BWritesWithAToken);
                }
                ctx.Response.StatusCode=201;
            }
            else if(identity=="bearer-B")ctx.Response.StatusCode=403;
            else {ctx.Response.StatusCode=401;ctx.Response.Headers.WWWAuthenticate=challenge;}
        },tls:true);
        string same=Host+":"+registry.Port,different=Other+":"+registry.Port;

        await using var publisher=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            string webToken=ctx.Request.Headers.Authorization.ToString();
            string caller=webToken=="Bearer LAB_WEB_USER_A"?"A":
                webToken=="Bearer LAB_WEB_USER_B"?"B":"invalid";
            if(caller=="invalid"){ctx.Response.StatusCode=401;return;}
            bool baseline=ctx.Request.Query.ContainsKey("baseline");
            bool noCredentials=ctx.Request.Query.ContainsKey("credentialless");
            Credentials(noCredentials?"none":caller);
            string manifest=JsonSerializer.Serialize(new {
                schemaVersion=2,mediaType=ManifestType,caller,
                test="synthetic-manifest-only",layers=Array.Empty<object>()
            });
            bool outcome=await PublishViaSdk(asm,baseline?different:same,manifest);
            ctx.Response.StatusCode=outcome?201:403;
            ctx.Response.ContentType="application/json";
            await ctx.Response.WriteAsync(JsonSerializer.Serialize(new{
                caller,allowed=outcome,credentialless=noCredentials,baseline
            }));
        },tls:false);

        async Task<int> Request(string? webToken,string query="")
        {
            using var http=new HttpClient(new SocketsHttpHandler{UseProxy=false,UseCookies=false});
            using var request=new HttpRequestMessage(HttpMethod.Post,"http://127.0.0.1:"+publisher.Port+"/publish"+query);
            if(webToken!=null)request.Headers.TryAddWithoutValidation("Authorization","Bearer "+webToken);
            using var response=await http.SendAsync(request);
            return (int)response.StatusCode;
        }

        int noUser=await Request(null);
        int bDenied=await Request("LAB_WEB_USER_B","?baseline=1");
        int aAllowed=await Request("LAB_WEB_USER_A");
        int issuedBeforeB=IssuedB;
        int bInherited=await Request("LAB_WEB_USER_B");
        int bNoCredentials=await Request("LAB_WEB_USER_B","?credentialless=1");
        var parallel=await Task.WhenAll(Enumerable.Range(0,4).Select(_=>Request("LAB_WEB_USER_B")));
        int issuedAfter=IssuedB;
        int writes=BWritesWithAToken;
        bool pass=Patched
            ? noUser==401&&bDenied==403&&aAllowed==201&&
              bInherited==403&&bNoCredentials==403&&parallel.All(x=>x==403)&&
              IssuedA==1&&IssuedB>=6&&AWrites==1&&writes==0
            : noUser==401&&bDenied==403&&aAllowed==201&&
              bInherited==201&&bNoCredentials==201&&parallel.All(x=>x==201)&&
              issuedBeforeB==1&&issuedAfter==1&&IssuedA==1&&
              AWrites==1&&writes==6;

        var details=new{
            scenario=Patched?"HTTP-multiuser-publisher-patched-SDK-isolation":"HTTP-multiuser-publishing-service-actual-sdk-PutAsync",
            sdk=Sdk,passed=pass,patchedSdk=Patched,
            anonymousRequest=noUser,
            userBIsolatedRegistryDenied=bDenied,
            userAPrivateManifestPublish=aAllowed,
            userBWithOwnCredentialsInheritedAPublish=bInherited,
            userBWithZeroRegistryCredentialsInheritedAPublish=bNoCredentials,
            fourConcurrentUserBPublishResults=parallel,
            tokenServiceIssuedA=IssuedA,tokenServiceIssuedB=IssuedB,
            noAdditionalBTokenExchange=issuedBeforeB==issuedAfter,
            freshBTokenExchangesInPatchedSdk=IssuedB-issuedBeforeB,
            syntheticManifestWritesUnderAToken=AWrites+BWritesWithAToken,
            unauthorizedBManifestWritesUsingAToken=BWritesWithAToken,
            requiresSameProcessAndSameRegistryAuthority=true,
            unauthorizedBWritesBlockedInPatchedSdk=Patched&&writes==0,
            realDotnetPublishCliUsed=false,
            actualSdkManifestPutAsyncUsed=true
        };
        Tests.Add(details);
        Console.WriteLine("[SHARED-PUBLISHER "+Sdk+"] "+JsonSerializer.Serialize(details));
        return pass;
    }
}
