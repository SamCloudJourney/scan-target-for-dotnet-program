// End-to-end split-registry full publish: pull from one OCI authority; push to a different
// authority using DIFFERENT synthetic credentials. Demonstrates exactly which secret crosses
// which authentication boundary and tests protected-source/target negative controls.
// All endpoints are local GitHub-runner loopback; no Docker daemon or external registries.
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

static class SplitRegistryPublishLab
{
    const string PullUser="SPLIT_SOURCE_PULL_SYNTH_USER";
    const string PullPass="SPLIT_SOURCE_PULL_SYNTH_SECRET";
    const string PushUser="SPLIT_DEST_PUSH_SYNTH_USER";
    const string PushPass="SPLIT_DEST_PUSH_SYNTH_SECRET";
    const string PullToken="SPLIT_SOURCE_PULL_BEARER";
    const string PushToken="SPLIT_DEST_PUSH_BEARER";
    static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    static readonly bool Patched=Sdk.StartsWith("12.",StringComparison.Ordinal);
    static readonly List<object> Reports=[];
    private record Event(string At,string Method,string Path,bool PullBasic,bool PushBasic,
        bool PullForm,bool PushForm,bool PullBearer,bool PushBearer);
    static string Basic(string u,string p)=>"Basic "+Convert.ToBase64String(Encoding.UTF8.GetBytes(u+":"+p));
    static string Sha(byte[] bytes)=>"sha256:"+Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    static Event Observe(string role,HttpContext c,string body)
    {
        string h=c.Request.Headers.Authorization.ToString();
        return new(role,c.Request.Method,c.Request.Path.ToString(),
            h==Basic(PullUser,PullPass),h==Basic(PushUser,PushPass),
            body.Contains(PullPass,StringComparison.Ordinal),
            body.Contains(PushPass,StringComparison.Ordinal),
            h=="Bearer "+PullToken,h=="Bearer "+PushToken);
    }
    static async Task Reply(HttpContext c,int status,string? body=null,string? type=null,
        string? challenge=null,string? location=null,string? digest=null)
    {
        c.Response.StatusCode=status;
        if(type is not null)c.Response.ContentType=type;
        if(challenge is not null)c.Response.Headers.WWWAuthenticate=challenge;
        if(location is not null)c.Response.Headers.Location=location;
        if(digest is not null)c.Response.Headers["Docker-Content-Digest"]=digest;
        if(body is not null)await c.Response.WriteAsync(body);
    }
    public static async Task RunAsync()
    {
        string? oldPolicy=Environment.GetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_POLICY");
        string? oldAllowed=Environment.GetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES");
        bool pass=true;
        try
        {
            foreach(string mode in new[]{"split-public","split-dns-private","split-redirect307","split-no-pull","split-no-push"})
            {
                // Explicitly permit the two synthetic public-registry/token endpoints under patched policy.
                // Do NOT permit private auth alias 127.0.0.2.
                if(Patched)
                {
                    Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_POLICY","Public");
                    Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES","127.0.0.1;127.0.0.3");
                }
                bool result=await One(mode);
                pass&=result;
                Console.WriteLine("[SPLIT-PUBLISH "+Sdk+"] "+mode+": "+(result?"PASS":"FAIL"));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_POLICY",oldPolicy);
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES",oldAllowed);
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-split-registry-publish.json",
                JsonSerializer.Serialize(new{sdk=Sdk,scenarios=Reports},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!pass)throw new Exception("Cross-registry credential isolation expected result mismatch");
    }
    static async Task<bool> One(string mode)
    {
        bool noPull=mode=="split-no-pull";
        bool noPush=mode=="split-no-push";
        bool privateRealm=mode=="split-dns-private";
        bool redirect=mode=="split-redirect307";
        var trace=new ConcurrentQueue<Event>();
        byte[] cfg=Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux","config":{"Entrypoint":["dotnet"],"Env":["DOTNET_RUNNING_IN_CONTAINER=true"]},"rootfs":{"type":"layers","diff_ids":[]},"history":[]}""");
        string cfgHash=Sha(cfg);
        string manifest=JsonSerializer.Serialize(new{
            schemaVersion=2,mediaType="application/vnd.oci.image.manifest.v1+json",
            config=new{mediaType="application/vnd.oci.image.config.v1+json",size=cfg.Length,digest=cfgHash},
            layers=Array.Empty<object>()
        });
        string manifestHash=Sha(Encoding.UTF8.GetBytes(manifest));
        int sourceManifestGets=0,targetManifestWrites=0,targetAuthIssued=0;
        string? redirectLocation=null;

        await using var privateToken=await LocalEndpoint.Start("127.0.0.2",async c=>{
            string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            var eventInfo=Observe("untrusted-source-realm",c,body);
            trace.Enqueue(eventInfo);
            bool accepts=eventInfo.PullBasic||eventInfo.PullForm;
            if(accepts)await Reply(c,200,JsonSerializer.Serialize(new{token=PullToken,expires_in=180}),"application/json");
            else await Reply(c,403);
        },tls:true);
        redirectLocation="https://privateauth.lab.test:"+privateToken.Port+"/oauth";
        await using var publicToken=await LocalEndpoint.Start("127.0.0.1",async c=>{
            string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            var eventInfo=Observe("source-public-realm",c,body);
            trace.Enqueue(eventInfo);
            if(redirect)
            {
                if(c.Request.Method=="GET")await Reply(c,405);
                else await Reply(c,307,location:redirectLocation);
                return;
            }
            if(eventInfo.PullBasic||eventInfo.PullForm)
                await Reply(c,200,JsonSerializer.Serialize(new{token=PullToken,expires_in=180}),"application/json");
            else await Reply(c,403);
        },tls:true);
        await using var destinationToken=await LocalEndpoint.Start("127.0.0.3",async c=>{
            string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            var eventInfo=Observe("destination-token",c,body);
            trace.Enqueue(eventInfo);
            if(eventInfo.PushBasic||eventInfo.PushForm)
            {
                Interlocked.Increment(ref targetAuthIssued);
                await Reply(c,200,JsonSerializer.Serialize(new{token=PushToken,expires_in=180}),"application/json");
            }
            else await Reply(c,403);
        },tls:true);

        string originRealm=privateRealm?"https://privateauth.lab.test:"+privateToken.Port+"/token":
            "https://publicauth.lab.test:"+publicToken.Port+"/token";
        await using var sourceRegistry=await LocalEndpoint.Start("127.0.0.1",async c=>{
            string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            var e=Observe("source-registry",c,body);
            trace.Enqueue(e);
            if(!e.PullBearer)
            {
                await Reply(c,401,challenge:"Bearer realm=\""+originRealm+"\",service=\"source\",scope=\"repository:baseprobe:pull\"");
                return;
            }
            string path=c.Request.Path.Value??"";
            if(path.Contains("/manifests/",StringComparison.Ordinal)&&(c.Request.Method=="GET"||c.Request.Method=="HEAD"))
            {
                Interlocked.Increment(ref sourceManifestGets);
                await Reply(c,200,c.Request.Method=="HEAD"?null:manifest,"application/vnd.oci.image.manifest.v1+json",digest:manifestHash);
            }
            else if(path.EndsWith(cfgHash,StringComparison.Ordinal)&&c.Request.Method=="GET")
                await Reply(c,200,Encoding.UTF8.GetString(cfg),"application/octet-stream",digest:cfgHash);
            else if(path=="/v2"||path=="/v2/")await Reply(c,200,"{}","application/json");
            else await Reply(c,404);
        },tls:true);
        string targetRealm="https://third.lab.test:"+destinationToken.Port+"/token";
        await using var destinationRegistry=await LocalEndpoint.Start("127.0.0.1",async c=>{
            string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            var e=Observe("destination-registry",c,body);
            trace.Enqueue(e);
            if(!e.PushBearer)
            {
                await Reply(c,401,challenge:"Bearer realm=\""+targetRealm+"\",service=\"destination\",scope=\"repository:release:push\"");
                return;
            }
            string path=c.Request.Path.Value??"";
            if(path.Contains("/manifests/",StringComparison.Ordinal))
            {
                if(c.Request.Method=="PUT")
                {
                    Interlocked.Increment(ref targetManifestWrites);
                    await Reply(c,201,digest:Sha(Encoding.UTF8.GetBytes(body)));
                }
                else if(c.Request.Method=="HEAD"||c.Request.Method=="GET")await Reply(c,404);
                else await Reply(c,405);
            }
            else if(path.Contains("/blobs/uploads",StringComparison.Ordinal))
            {
                string location="/v2/release/blobs/uploads/synthetic-upload";
                c.Response.Headers["Docker-Upload-UUID"]="synthetic-upload";
                if(c.Request.Method=="PUT")await Reply(c,201,digest:c.Request.Query["digest"].ToString());
                else if(c.Request.Method=="POST"||c.Request.Method=="PATCH")await Reply(c,202,location:location);
                else await Reply(c,405);
            }
            else if(path.Contains("/blobs/",StringComparison.Ordinal)&&c.Request.Method=="HEAD")await Reply(c,404);
            else if(path=="/v2"||path=="/v2/")await Reply(c,200,"{}","application/json");
            else await Reply(c,404);
        },tls:true);
        string temp=Path.Combine(Path.GetTempPath(),"split-registry-proof-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        int? exitCode=null;bool timedOut=false;string diag="";
        try
        {
            File.WriteAllText(Path.Combine(temp,"global.json"),JsonSerializer.Serialize(new{sdk=new{version=Sdk,rollForward="disable"}}));
            File.WriteAllText(Path.Combine(temp,"NuGet.Config"),"""
                <?xml version="1.0" encoding="utf-8"?>
                <configuration><packageSources><clear /></packageSources></configuration>
                """);
            string major=Sdk.Split('.')[0];
            File.WriteAllText(Path.Combine(temp,"Probe.csproj"),$"""
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <OutputType>Exe</OutputType><TargetFramework>net{major}.0</TargetFramework>
                    <EnableSdkContainerSupport>true</EnableSdkContainerSupport><ImplicitUsings>enable</ImplicitUsings>
                  </PropertyGroup>
                </Project>
                """);
            File.WriteAllText(Path.Combine(temp,"Program.cs"),"Console.WriteLine(\"no external registry touched\");");
            var start=new ProcessStartInfo("dotnet"){WorkingDirectory=temp,
                RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};
            foreach(string a in new[]{
                "publish","Probe.csproj","-t:PublishContainer","--nologo","-v:minimal",
                "-p:ContainerBaseImage=registry.lab.test:"+sourceRegistry.Port+"/baseprobe:latest",
                "-p:ContainerRegistry=registry-alt.lab.test:"+destinationRegistry.Port,
                "-p:ContainerRepository=release","-p:ContainerImageTag=tag-synthetic",
                "-p:ContainerRuntimeIdentifier=linux-x64","-p:NuGetAudit=false"
            })start.ArgumentList.Add(a);
            foreach(string key in new[]{"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy",
                "DOTNET_CONTAINER_PULL_REGISTRY_UNAME","DOTNET_CONTAINER_PULL_REGISTRY_PWORD",
                "DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
                "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD",
                "REGISTRY_AUTH_FILE","DOCKER_CONFIG","SDK_CONTAINER_REGISTRY_UNAME","SDK_CONTAINER_REGISTRY_PWORD"})
                start.Environment.Remove(key);
            start.Environment["NO_PROXY"]="*";
            start.Environment["no_proxy"]="*";
            if(!noPull)
            {
                start.Environment["DOTNET_CONTAINER_PULL_REGISTRY_UNAME"]=PullUser;
                start.Environment["DOTNET_CONTAINER_PULL_REGISTRY_PWORD"]=PullPass;
            }
            if(!noPush)
            {
                start.Environment["DOTNET_CONTAINER_PUSH_REGISTRY_UNAME"]=PushUser;
                start.Environment["DOTNET_CONTAINER_PUSH_REGISTRY_PWORD"]=PushPass;
            }
            string emptyFile=Path.Combine(temp,"empty-auth.json");
            File.WriteAllText(emptyFile,"{\"auths\":{}}");
            start.Environment["REGISTRY_AUTH_FILE"]=emptyFile;
            start.Environment["DOCKER_CONFIG"]=temp;
            start.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"]="1";
            start.Environment["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"]="1";
            using var process=Process.Start(start)??throw new Exception("dotnet publish launch failed");
            var stdout=process.StandardOutput.ReadToEndAsync();
            var stderr=process.StandardError.ReadToEndAsync();
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(70));
            try{await process.WaitForExitAsync(deadline.Token);exitCode=process.ExitCode;}
            catch(OperationCanceledException){timedOut=true;process.Kill(entireProcessTree:true);await process.WaitForExitAsync();}
            string combined=await stdout+"\n"+await stderr;
            diag=string.Join("\n",combined.Split('\n').Where(x=>x.Contains("error ",StringComparison.OrdinalIgnoreCase)).Take(3).Select(x=>x.Length>260?x[..260]:x));
        }
        finally{try{Directory.Delete(temp,true);}catch(IOException){}}
        var t=trace.ToArray();
        bool pullPassedToSource=t.Any(e=>e.At=="untrusted-source-realm"&&(e.PullBasic||e.PullForm))||
            t.Any(e=>e.At=="source-public-realm"&&(e.PullBasic||e.PullForm));
        bool privateGotPull=t.Any(e=>e.At=="untrusted-source-realm"&&(e.PullBasic||e.PullForm));
        bool privateGotPush=t.Any(e=>e.At=="untrusted-source-realm"&&(e.PushBasic||e.PushForm||e.PushBearer));
        bool sourceGotPush=t.Any(e=>e.At.StartsWith("source-",StringComparison.Ordinal)&&(e.PushBasic||e.PushForm||e.PushBearer));
        bool destinationGotPull=t.Any(e=>e.At.StartsWith("destination-",StringComparison.Ordinal)&&(e.PullBasic||e.PullForm||e.PullBearer));
        bool destinationAuthenticated=t.Any(e=>e.At=="destination-registry"&&e.PushBearer);
        bool privateExpectedDenied=Patched&&(privateRealm||redirect);
        bool fullExpected=mode=="split-public"||(!Patched&&(privateRealm||redirect));
        bool pass= !timedOut&&!privateGotPush&&!sourceGotPush&&!destinationGotPull &&
            (fullExpected?
                exitCode==0&&targetManifestWrites==1&&sourceManifestGets>=1&&
                pullPassedToSource&&destinationAuthenticated&&targetAuthIssued>=1
            : privateExpectedDenied?
                exitCode!=0&&targetManifestWrites==0&&!privateGotPull&&!destinationAuthenticated
            : noPull?
                exitCode!=0&&targetManifestWrites==0&&!pullPassedToSource&&!destinationAuthenticated
            : noPush?
                exitCode!=0&&targetManifestWrites==0&&sourceManifestGets>=1&&pullPassedToSource&&!destinationAuthenticated
            : false);
        var report=new{mode,sdk=Sdk,passed=pass,patched=Patched,exitCode,timedOut,
            fullPublishCompleted=exitCode==0,
            sourceManifestFetchCount=sourceManifestGets,destinationManifestUploadCount=targetManifestWrites,
            destinationTokenIssued=targetAuthIssued,
            sourcePullCredentialReachedSourceRealm=pullPassedToSource,
            privateRealmReceivedPullCredential=privateGotPull,
            privateRealmReceivedDestinationPushCredential=privateGotPush,
            sourceAuthorityReceivedDestinationPushCredential=sourceGotPush,
            destinationAuthorityReceivedSourcePullCredential=destinationGotPull,
            destinationRegistryAuthenticatedWithPushToken=destinationAuthenticated,
            expectation=fullExpected?"both isolated credentials work":privateExpectedDenied?"patched blocks untrusted source realm":
                noPull?"source missing credentials":noPush?"destination missing credentials":"unknown",
            errorExcerpt=diag,network=t
        };
        Reports.Add(report);
        Console.WriteLine("[SPLIT-PUBLISH "+Sdk+"] "+mode+" "+JsonSerializer.Serialize(report));
        return pass;
    }
}
