// Tests an independently downloaded SDK daily build *only if its actual assembly contains the upstream fixes*.
// This is an actual shipped daily binary (not a handwritten mock patch); record DLL digest and version.
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

static class PatchedParityLab
{
    const string UserA="PATCH_COMPARE_A";
    const string PassA="PATCH_COMPARE_PASSWORD_A";
    const string UserB="PATCH_COMPARE_B";
    const string PassB="PATCH_COMPARE_PASSWORD_B";
    const string TokenA="PATCH_COMPARE_TOKEN_A";
    const string TokenB="PATCH_COMPARE_TOKEN_B";
    static readonly List<object> Tests=[];
    static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    static string Basic(string user,string password)=>"Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(user+":"+password));
    static Assembly _sdk=null!;
    static object RegistryApi(string registry)
    {
        Type api=_sdk.GetType("Microsoft.NET.Build.Containers.DefaultRegistryAPI",true)!;
        var mode=Enum.Parse(_sdk.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!,"Push");
        return Activator.CreateInstance(api,BindingFlags.NonPublic|BindingFlags.Public|BindingFlags.Instance,
            null,[registry,new Uri("https://"+registry+"/"),false,NullLogger.Instance,mode],null)!;
    }
    static void Creds(string user,string password)
    {
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",user);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",password);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_UNAME",null);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_REGISTRY_PWORD",null);
    }
    static async Task<bool> Exists(string registry)
    {
        try{
            object op=RegistryApi(registry).GetType().GetProperty("Manifest")!.GetValue(RegistryApi(registry))!;
            // Use one API instance for each call. A fresh instance must have an independent token.
            var task=(Task<bool>)op.GetType().GetMethod("ExistsAsync")!.Invoke(
                op,["tenant-a/private","latest",CancellationToken.None])!;
            return await task;
        }catch{return false;}
    }

    public static async Task RunAsync()
    {
        string? path=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY");
        if(path is null)throw new InvalidOperationException("Missing actual daily SDK library");
        byte[] bytes=await File.ReadAllBytesAsync(path);
        string hash=Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var taskDir=Path.GetDirectoryName(path)!;
        string sdkRoot=Directory.GetParent(Directory.GetParent(Directory.GetParent(taskDir)!.FullName)!.FullName)!.FullName;
        AssemblyLoadContext.Default.Resolving+=(ctx,name)=>{
            foreach(var dir in new[]{taskDir,sdkRoot})
            {
                string f=Path.Combine(dir,name.Name+".dll");
                if(File.Exists(f))return ctx.LoadFromAssemblyPath(f);
            }
            return null;
        };
        _sdk=AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(path));
        Type handler=_sdk.GetType("Microsoft.NET.Build.Containers.AuthHandshakeMessageHandler",true)!;
        bool handlerLocal=handler.GetField("_authentication",BindingFlags.NonPublic|BindingFlags.Instance)!=null &&
            handler.GetField("_authenticationHeaders",BindingFlags.NonPublic|BindingFlags.Static)==null;
        bool antiSsrfFactory=_sdk.GetType("Microsoft.NET.Build.Containers.AuthRealmHandlerFactory",false)!=null;
        bool patchFingerprint=handlerLocal&&antiSsrfFactory;
        Tests.Add(new{scenario="upstream-patch-binary-fingerprint",passed=patchFingerprint,
            sdk=Sdk,assemblySha256=hash,
            sourceBranches="dotnet/sdk main PR 56843 and 57092",
            handlerLocalAuthenticationField=handlerLocal,hasAntiSsrfRealmFactory=antiSsrfFactory,
            assemblyVersion=_sdk.GetName().Version?.ToString()});
        Console.WriteLine("[PATCH-PARITY "+Sdk+"] fingerprint="+JsonSerializer.Serialize(Tests[^1]));
        if(!patchFingerprint)throw new Exception("Official daily binary not known to include both upstream fix classes");

        var keys=new[]{"DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
            "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD",
            "DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES","DOTNET_CONTAINER_AUTH_REALM_POLICY"};
        var old=keys.ToDictionary(k=>k,k=>Environment.GetEnvironmentVariable(k));
        IWebProxy proxy=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        bool success=patchFingerprint;
        try{
            foreach(var mode in new[]{"default-direct","default-dns",
                        "allowlist-dns","redirect-307-allowlist","registry-302-basic"})
                success&=await CheckRealm(mode);
            success&=await CheckCache();
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_POLICY","Public");
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES","127.0.0.1");
            success&=await SharedPublisherLab.RunAsync();
            success&=await PublishDepthLab.RunPatchedSubsetAsync();
        }
        finally{
            HttpClient.DefaultProxy=proxy;
            foreach(var kv in old)Environment.SetEnvironmentVariable(kv.Key,kv.Value);
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-patched-parity.json",
                JsonSerializer.Serialize(new{sdk=Sdk,sha256=hash,tests=Tests},
                    new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!success)throw new Exception("Actual patched SDK parity test returned unexpected observation");
    }
    static async Task<bool> CheckRealm(string scenario)
    {
        bool redirect=scenario=="redirect-307-allowlist";
        bool originRedirect=scenario=="registry-302-basic";
        bool direct=scenario=="default-direct";
        bool explicitAllowed=scenario=="allowlist-dns";
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_POLICY","Public");
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES",
            redirect?"127.0.0.1":explicitAllowed?"127.0.0.2":null);
        Creds(UserA,PassA);
        int privateCalls=0,privateBasic=0,privatePassword=0,regBearer=0;
        string? destination=null;
        await using var privateHost=await LocalEndpoint.Start("127.0.0.2",async c=>{
            Interlocked.Increment(ref privateCalls);
            if(c.Request.Headers.Authorization.ToString()==Basic(UserA,PassA))
                Interlocked.Increment(ref privateBasic);
            var body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            if(body.Contains(PassA,StringComparison.Ordinal))Interlocked.Increment(ref privatePassword);
            if(originRedirect)
            {
                c.Response.StatusCode=401;c.Response.Headers.WWWAuthenticate="Basic realm=\"private\"";
            }
            else
            {
                c.Response.StatusCode=200;c.Response.ContentType="application/json";
                await c.Response.WriteAsync(JsonSerializer.Serialize(new{token=TokenA,expires_in=180}));
            }
        },tls:true);
        destination="https://privateauth.lab.test:"+privateHost.Port+"/token";
        await using var publicHost=await LocalEndpoint.Start("127.0.0.1",async c=>{
            if(c.Request.Method=="GET")c.Response.StatusCode=405;
            else {c.Response.StatusCode=307;c.Response.Headers.Location=destination;}
        },tls:true);
        string authRealm=direct?"https://127.0.0.2:"+privateHost.Port+"/token":
            redirect?"https://publicauth.lab.test:"+publicHost.Port+"/auth":destination;
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async c=>{
            string bearer=c.Request.Headers.Authorization.ToString();
            if(bearer=="Bearer "+TokenA){Interlocked.Increment(ref regBearer);c.Response.StatusCode=200;}
            else if(originRedirect)
            {
                c.Response.StatusCode=302;
                c.Response.Headers.Location="https://privateauth.lab.test:"+privateHost.Port+
                    "/v2/tenant-a/private/manifests/latest";
            }
            else{
                c.Response.StatusCode=401;
                c.Response.Headers.WWWAuthenticate="Bearer realm=\""+authRealm+"\",service=\"lab\"";
            }
        },tls:true);
        bool granted=await Exists("registry.lab.test:"+registry.Port);
        bool pass=scenario switch{
            "default-direct" or "default-dns"=>
                !granted&&privateCalls==0&&regBearer==0,
            "allowlist-dns"=>
                granted&&privateBasic>0&&regBearer>0,
            "redirect-307-allowlist"=>
                !granted&&privateCalls==0&&regBearer==0,
            "registry-302-basic"=>
                !granted&&privateBasic==0&&privateCalls>0&&regBearer==0,
            _=>false
        };
        var details=new{scenario,passed=pass,sdk=Sdk,clientGranted=granted,
            privateRequestCount=privateCalls,privateReceivedBasic=privateBasic,
            privateReceivedSyntheticPasswordForm=privatePassword,registryBearerCount=regBearer,
            policy="Public",allowedAddresses=redirect?"127.0.0.1":explicitAllowed?"127.0.0.2":"none"};
        Tests.Add(details);
        Console.WriteLine("[PATCH-PARITY "+Sdk+"] "+JsonSerializer.Serialize(details));
        return pass;
    }
    static async Task<bool> CheckCache()
    {
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_POLICY","Public");
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES","127.0.0.1");
        int issuedA=0,issuedB=0;
        await using var auth=await LocalEndpoint.Start("127.0.0.1",async c=>{
            string h=c.Request.Headers.Authorization.ToString();
            if(h==Basic(UserA,PassA)){Interlocked.Increment(ref issuedA);c.Response.StatusCode=200;
                await c.Response.WriteAsync(JsonSerializer.Serialize(new{token=TokenA,expires_in=180}));}
            else if(h==Basic(UserB,PassB)){Interlocked.Increment(ref issuedB);c.Response.StatusCode=200;
                await c.Response.WriteAsync(JsonSerializer.Serialize(new{token=TokenB,expires_in=180}));}
            else c.Response.StatusCode=403;
        },tls:true);
        string challenge="Bearer realm=\"https://publicauth.lab.test:"+auth.Port+"/token\",service=\"scope\"";
        int aResponses=0,bResponses=0;
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async c=>{
            string h=c.Request.Headers.Authorization.ToString();
            if(h=="Bearer "+TokenA){Interlocked.Increment(ref aResponses);c.Response.StatusCode=200;}
            else if(h=="Bearer "+TokenB){Interlocked.Increment(ref bResponses);c.Response.StatusCode=403;}
            else {c.Response.StatusCode=401;c.Response.Headers.WWWAuthenticate=challenge;}
        },tls:true);
        string reg="registry.lab.test:"+registry.Port;
        Creds(UserA,PassA);
        bool a=await Exists(reg);
        Creds(UserB,PassB);
        bool b=await Exists(reg);
        int lookupBefore=issuedB;
        var parallel=await Task.WhenAll(Enumerable.Range(0,5).Select(_=>Exists(reg)));
        bool pass=a&&!b&&parallel.All(v=>!v)&&issuedA==1&&issuedB>=1&&
            issuedB>lookupBefore&&aResponses==1&&bResponses>=1;
        var details=new{scenario="actual-patched-sdk-handler-local-cache-isolation",
            passed=pass,sdk=Sdk,principalAGranted=a,principalBGranted= b,
            parallelBGrants=parallel.Count(x=>x),tokensIssuedA=issuedA,tokensIssuedB=issuedB,
            registryAcceptedATokenCount=aResponses,registryDeniedBTokenCount=bResponses,
            note="A new SDK client with B credentials may not reuse A's token on the same registry authority"};
        Tests.Add(details);
        Console.WriteLine("[PATCH-PARITY "+Sdk+"] "+JsonSerializer.Serialize(details));
        return pass;
    }
}
