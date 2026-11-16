// Synthetic two-principal publishing gateway. All servers and credentials are lab-only.
// Uses the real installed Microsoft.NET.Build.Containers DefaultRegistryAPI, including
// manifest writes and digest-checked OCI blob reads, under two independent HTTP sessions.
using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

static class TenantGatewayLab
{
    const string AUser="SYNTH_TENANT_A";
    const string APass="SYNTH_TENANT_A_PASSWORD";
    const string AToken="SYNTH_TENANT_A_PRIVATE_BEARER";
    const string PrivateValue="SYNTHETIC_PRIVATE_LAYER_A_ONLY";
    const string RegistryHost="registry.lab.test";
    const string TokenHost="publicauth.lab.test";
    const string AuthUserHeader="X-Lab-Session";
    const string AuthOperationHeader="X-Lab-Operation";
    static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    static readonly bool IsPatched=Environment.GetEnvironmentVariable("SDK_EXPECT_PATCHED")=="1";
    static readonly List<object> Results=[];
    static string AAuth=>"Basic "+Convert.ToBase64String(Encoding.UTF8.GetBytes(AUser+":"+APass));
    record Hit(string At,string Method,string Path,bool AIdentity,bool BasicA);
    static async Task Reply(HttpContext c,int status,string? body=null,string? challenge=null)
    {
        c.Response.StatusCode=status;
        if(challenge is not null)c.Response.Headers.WWWAuthenticate=challenge;
        if(body is not null){c.Response.ContentType="application/json";await c.Response.WriteAsync(body);}
    }
    static Assembly SdkAssembly()
    {
        string path=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")??throw new InvalidOperationException("SDK assembly path missing");
        string task=Path.GetDirectoryName(path)!;
        string root=Directory.GetParent(Directory.GetParent(Directory.GetParent(task)!.FullName)!.FullName)!.FullName;
        AssemblyLoadContext.Default.Resolving+=(ctx,name)=>{
            foreach(string d in new[]{task,root}){string p=Path.Combine(d,name.Name+".dll");if(File.Exists(p))return ctx.LoadFromAssemblyPath(p);}
            return null;
        };
        return AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(path));
    }
    static object NewApi(Assembly sdk,string registry)
    {
        var t=sdk.GetType("Microsoft.NET.Build.Containers.DefaultRegistryAPI",true)!;
        var m=sdk.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!;
        return Activator.CreateInstance(t,BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public,null,
            [registry,new Uri("https://"+registry+"/"),false,NullLogger.Instance,Enum.Parse(m,"Push")],null)!;
    }
    static async Task<bool> TryRead(object api,string digest)
    {
        object blob=api.GetType().GetProperty("Blob")!.GetValue(api)!;
        var method=blob.GetType().GetMethod("GetJsonAsync")!;
        var task=(Task<JsonNode>)method.Invoke(blob,["protected/tenant-a",digest,CancellationToken.None])!;
        var result=await task;
        return result?["data"]?.ToString()==PrivateValue;
    }
    static async Task<bool> TryWrite(object api)
    {
        object m=api.GetType().GetProperty("Manifest")!.GetValue(api)!;
        var method=m.GetType().GetMethod("PutAsync")!;
        // Local mock only. No secrets, code, arbitrary files or real registries.
        var t=(Task)method.Invoke(m,["protected/tenant-a","audit-probe",
            """{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}""",
            "application/vnd.oci.image.manifest.v1+json",CancellationToken.None])!;
        await t;return true;
    }
    static void CredentialsFor(string principal,string emptyDockerDir)
    {
        foreach(string n in new[]{
            "DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
            "DOTNET_CONTAINER_PULL_REGISTRY_UNAME","DOTNET_CONTAINER_PULL_REGISTRY_PWORD",
            "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD",
            "SDK_CONTAINER_REGISTRY_UNAME","SDK_CONTAINER_REGISTRY_PWORD"})Environment.SetEnvironmentVariable(n,null);
        Environment.SetEnvironmentVariable("REGISTRY_AUTH_FILE",Path.Combine(emptyDockerDir,"config.json"));
        Environment.SetEnvironmentVariable("DOCKER_CONFIG",emptyDockerDir);
        if(principal=="A")
        {
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",AUser);
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",APass);
        }
    }
    public static async Task RunAsync()
    {
        var trackedEnv=new Dictionary<string,string?>();
        foreach(string n in new[]{
            "DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
            "DOTNET_CONTAINER_PULL_REGISTRY_UNAME","DOTNET_CONTAINER_PULL_REGISTRY_PWORD",
            "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD",
            "SDK_CONTAINER_REGISTRY_UNAME","SDK_CONTAINER_REGISTRY_PWORD","REGISTRY_AUTH_FILE","DOCKER_CONFIG"
        })trackedEnv[n]=Environment.GetEnvironmentVariable(n);
        var oldProxy=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        string temporary=Path.Combine(Path.GetTempPath(),"tenant-gateway-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        File.WriteAllText(Path.Combine(temporary,"config.json"),"""{"auths":{}}""");
        bool pass=false;
        try{pass=await Scenario(temporary);}
        finally
        {
            foreach(var kv in trackedEnv)Environment.SetEnvironmentVariable(kv.Key,kv.Value);
            HttpClient.DefaultProxy=oldProxy;
            try{Directory.Delete(temporary,true);}catch(IOException){}
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-tenant-gateway.json",
                JsonSerializer.Serialize(new{sdk=Sdk,checks=Results},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!pass)throw new Exception("Synthetic multi-principal gateway assertions failed");
    }
    static async Task<bool> Scenario(string emptyDockerDir)
    {
        var sdk=SdkAssembly();
        var log=new ConcurrentQueue<Hit>();
        var privateContent=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new{owner="A",data=PrivateValue}));
        string digest="sha256:"+Convert.ToHexString(SHA256.HashData(privateContent)).ToLowerInvariant();
        int tokenA=0, tokenAnonymous=0, privilegedReads=0, privilegedWrites=0;
        bool revokeA=false;
        await using var tokenServer=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            bool isA=c.Request.Headers.Authorization.ToString()==AAuth;
            log.Enqueue(new("token",c.Request.Method,c.Request.Path.ToString(),false,isA));
            if(isA){Interlocked.Increment(ref tokenA);await Reply(c,200,JsonSerializer.Serialize(new{token=AToken,expires_in=120}));}
            else{Interlocked.Increment(ref tokenAnonymous);await Reply(c,403);}
        },tls:true);
        string challenge="Bearer realm=\"https://"+TokenHost+":"+tokenServer.Port+"/token\",service=\"isolated\"";
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            bool isA=c.Request.Headers.Authorization.ToString()=="Bearer "+AToken;
            log.Enqueue(new("registry",c.Request.Method,c.Request.Path.ToString(),isA,false));
            if(!isA || revokeA){await Reply(c,401,challenge:challenge);return;}
            if(c.Request.Method=="GET" && c.Request.Path.Value?.EndsWith(digest,StringComparison.Ordinal)==true)
            {
                Interlocked.Increment(ref privilegedReads);
                c.Response.ContentType="application/octet-stream";
                await c.Response.Body.WriteAsync(privateContent);
            }
            else if(c.Request.Method=="PUT" && c.Request.Path.Value?.EndsWith("/audit-probe",StringComparison.Ordinal)==true)
            {
                Interlocked.Increment(ref privilegedWrites);
                await Reply(c,201,"{}");
            }
            else await Reply(c,404);
        },tls:true);
        string origin=RegistryHost+":"+registry.Port;
        await using var gateway=await LocalEndpoint.Start("127.0.0.3",async c=>
        {
            string session=c.Request.Headers[AuthUserHeader].ToString();
            string operation=c.Request.Headers[AuthOperationHeader].ToString();
            if(session is not ("A" or "B") || operation is not ("read" or "write")){await Reply(c,403);return;}
            CredentialsFor(session,emptyDockerDir);
            bool allowed=false;
            string? failure=null;
            try
            {
                object api=NewApi(sdk,origin);
                allowed=operation=="read" ? await TryRead(api,digest):await TryWrite(api);
            }
            catch(Exception ex){failure=ex.GetBaseException().GetType().Name;}
            await Reply(c,allowed?200:403,
                JsonSerializer.Serialize(new{principal=session,operation,allowed,
                    syntheticPrivateDataReturned=allowed&&operation=="read",failure}));
        },tls:true);
        async Task<(int Status,bool Data,bool Granted)> Request(string principal,string operation)
        {
            using var client=new HttpClient(new HttpClientHandler{UseProxy=false});
            using var msg=new HttpRequestMessage(HttpMethod.Get,"https://third.lab.test:"+gateway.Port+"/job");
            msg.Headers.Add(AuthUserHeader,principal);
            msg.Headers.Add(AuthOperationHeader,operation);
            using var response=await client.SendAsync(msg);
            string body=await response.Content.ReadAsStringAsync();
            using var json=JsonDocument.Parse(body);
            return ((int)response.StatusCode,
                json.RootElement.GetProperty("syntheticPrivateDataReturned").GetBoolean(),
                json.RootElement.GetProperty("allowed").GetBoolean());
        }
        var bBefore=await Request("B","read");
        var bWriteBefore=await Request("B","write");
        var aRead=await Request("A","read");
        int aTokenAtPrime=tokenA;
        var bRead=await Request("B","read");
        var bWrite=await Request("B","write");
        int aTokenAfterB=tokenA;
        revokeA=true;
        var bAfterRevocation=await Request("B","read");
        bool pass=bBefore.Status==403 && bWriteBefore.Status==403 &&
            aRead.Status==200 && aRead.Data &&
            aTokenAtPrime==1 &&
            bAfterRevocation.Status==403 && !bAfterRevocation.Granted &&
            (IsPatched
                ? bRead.Status==403 && !bRead.Data && bWrite.Status==403 && !bWrite.Granted &&
                  privilegedReads==1 && privilegedWrites==0
                : bRead.Status==200 && bRead.Data && bWrite.Status==200 && bWrite.Granted &&
                  aTokenAfterB==aTokenAtPrime && privilegedReads==2 && privilegedWrites==1);
        var evidence=new{scenario="two-principal-sdk-publishing-gateway",
            passed=pass,sdk=Sdk,expectedPatchedImplementation=IsPatched,beforePrimingBRead=bBefore,beforePrimingBWrite=bWrite,
            privilegedARead=aRead,afterPrimingBRead=bRead,afterPrimingBWrite=bWrite,
            afterRevocationBRead=bAfterRevocation,
            syntheticPrivateMarker=PrivateValue,privilegedReadCount=privilegedReads,
            privilegedWriteCount=privilegedWrites,privilegedTokenAcquisitionsBeforeB=aTokenAtPrime,
            privilegedTokenAcquisitionsAfterB=aTokenAfterB,totalPrivilegedTokenAcquisitions=tokenA,
            totalOtherTokenRequests=tokenAnonymous,requestTrace=log.ToArray()};
        Results.Add(evidence);
        Console.WriteLine("[TENANT "+Sdk+"] "+JsonSerializer.Serialize(evidence));
        return pass;
    }
}
