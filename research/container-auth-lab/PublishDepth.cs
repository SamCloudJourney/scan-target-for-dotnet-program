// Real SDK "dotnet publish /t:PublishContainer" reproduction with a closed-loop fake OCI registry.
// No external registries, secrets or endpoints. The app is generated offline in a temporary directory.
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

static class PublishDepthLab
{
    private const string SyntheticUser="PUBLISH_LAB_USER";
    private const string SyntheticPass="PUBLISH_LAB_PASSWORD_NO_SECRET";
    private const string SyntheticToken="PUBLISH_LAB_BEARER_NO_SECRET";
    private const string SyntheticIdentity="PUBLISH_LAB_IDENTITY_TOKEN_NO_SECRET";
    private static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    private static readonly bool Is11=Sdk.StartsWith("11.");
    private static readonly bool IsPatched=Environment.GetEnvironmentVariable("SDK_EXPECT_PATCHED")=="1";
    private static readonly List<object> Reports=[];
    private record NetworkEvent(string Role,string Method,string Path,bool SyntheticBasic,bool SyntheticPasswordForm,bool SyntheticIdentityForm,bool SyntheticBearer);
    private static string Basic=>"Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(SyntheticUser+":"+SyntheticPass));

    public static async Task RunAsync()
    {
        bool success=true;
        try
        {
            string[] modes=IsPatched
                ? ["public-allowed","direct-ip","dns-private","redirect307","redirect308",
                   "identity-dns","identity-redirect307","registry-302-basic","no-credentials"]
                : ["public-allowed","direct-ip","dns-private","redirect301","redirect302","redirect303","redirect307",
                   "redirect308","redirect-http","identity-direct-ip","identity-dns",
                   "identity-redirect307","identity-redirect308","registry-302-basic","no-credentials"];
            foreach(var mode in modes)
            {
                bool verified=await RunOne(mode);
                Console.WriteLine("[PUBLISH "+Sdk+"] "+mode+": "+(verified?"PASS":"FAIL"));
                success&=verified;
            }
        }
        finally
        {
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-publish-depth.json",
                JsonSerializer.Serialize(new{sdk=Sdk,tests=Reports},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!success)throw new Exception("Real dotnet publish authentication boundary assertion failed.");
    }

    private static string RegistryHostName(int port)=>"registry.lab.test:"+port;
    private static string Hash(byte[] bytes)=>"sha256:"+Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static NetworkEvent Observe(string role,HttpContext ctx,string body)
    {
        string authorization=ctx.Request.Headers.Authorization.ToString();
        return new NetworkEvent(role,ctx.Request.Method,ctx.Request.Path.ToString(),
            authorization==Basic,
            body.Contains(SyntheticPass,StringComparison.Ordinal),
            body.Contains(SyntheticIdentity,StringComparison.Ordinal),
            authorization=="Bearer "+SyntheticToken);
    }
    private static async Task Reply(HttpContext c,int status,string? body=null,
        string? contentType=null,string? challenge=null,string? location=null,string? digest=null)
    {
        c.Response.StatusCode=status;
        if(contentType is not null)c.Response.ContentType=contentType;
        if(challenge is not null)c.Response.Headers.WWWAuthenticate=challenge;
        if(location is not null)c.Response.Headers.Location=location;
        if(digest is not null)c.Response.Headers["Docker-Content-Digest"]=digest;
        if(body is not null)await c.Response.WriteAsync(body);
    }

    private static async Task<bool> RunOne(string mode)
    {
        bool identityMode=mode.StartsWith("identity-",StringComparison.Ordinal);
        bool missingCredentials=mode=="no-credentials";
        bool redirectMode=mode.Contains("redirect",StringComparison.Ordinal);
        bool downgradeRedirect=mode=="redirect-http";
        int redirectStatus=mode.EndsWith("301",StringComparison.Ordinal)?301:
            mode.EndsWith("302",StringComparison.Ordinal)?302:
            mode.EndsWith("303",StringComparison.Ordinal)?303:
            mode.EndsWith("308",StringComparison.Ordinal)?308:307;
        bool registryRedirectBasic=mode=="registry-302-basic";
        bool directMode=mode.Contains("direct-ip",StringComparison.Ordinal);
        var events=new ConcurrentQueue<NetworkEvent>();
        string? tokenEndpoint=null;
        string? fallbackEndpoint=null;
        var cfg=Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux","config":{"Entrypoint":["dotnet"],"Env":["DOTNET_RUNNING_IN_CONTAINER=true"]},"rootfs":{"type":"layers","diff_ids":[]},"history":[]}""");
        string cfgHash=Hash(cfg);
        string manifest=JsonSerializer.Serialize(new {
            schemaVersion=2,
            mediaType="application/vnd.oci.image.manifest.v1+json",
            config=new {mediaType="application/vnd.oci.image.config.v1+json",size=cfg.Length,digest=cfgHash},
            layers=Array.Empty<object>()
        });
        string manifestHash=Hash(Encoding.UTF8.GetBytes(manifest));
        int producedManifest=0;
        int downloadedConfig=0;

        int downgradeEndpointRequests=0;
        await using var downgradeEndpoint=await LocalEndpoint.Start("127.0.0.2",async c=>
        {
            Interlocked.Increment(ref downgradeEndpointRequests);
            await Reply(c,200,JsonSerializer.Serialize(new{token=SyntheticToken}),"application/json");
        },tls:false);
        await using var privateEndpoint=await LocalEndpoint.Start("127.0.0.2",async c=>
        {
            string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            events.Enqueue(Observe("private-token",c,body));
            if(registryRedirectBasic)
            {
                if(c.Request.Headers.Authorization.ToString()!=Basic)
                    await Reply(c,401,challenge:"Basic realm=\"synthetic-cross-origin\"");
                else if(c.Request.Path.Value?.Contains("/manifests/",StringComparison.Ordinal)==true)
                    await Reply(c,200,c.Request.Method=="HEAD"?null:manifest,
                        "application/vnd.oci.image.manifest.v1+json",digest:manifestHash);
                else await Reply(c,404);
            }
            else await Reply(c,200,JsonSerializer.Serialize(new{token=SyntheticToken,expires_in=120}),
                "application/json");
        },tls:true);

        await using var publicEndpoint=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            events.Enqueue(Observe("public-token",c,body));
            if(redirectMode)
            {
                if(c.Request.Method=="GET")await Reply(c,405);
                else await Reply(c,redirectStatus,location:fallbackEndpoint);
            }
            else await Reply(c,200,JsonSerializer.Serialize(new{token=SyntheticToken,expires_in=120}),"application/json");
        },tls:true);

        fallbackEndpoint=downgradeRedirect
            ? "http://privateauth.lab.test:"+downgradeEndpoint.Port+"/oauth"
            : "https://privateauth.lab.test:"+privateEndpoint.Port+"/oauth";
        tokenEndpoint=mode switch
        {
            "direct-ip" or "identity-direct-ip"=>"https://127.0.0.2:"+privateEndpoint.Port+"/token",
            "dns-private" or "identity-dns" or "no-credentials"=>"https://privateauth.lab.test:"+privateEndpoint.Port+"/token",
            "public-allowed"=>"https://publicauth.lab.test:"+publicEndpoint.Port+"/token",
            "redirect301" or "redirect302" or "redirect303" or "redirect307" or "redirect308" or "redirect-http"
                or "identity-redirect307" or "identity-redirect308" or "registry-302-basic"=>
                    "https://publicauth.lab.test:"+publicEndpoint.Port+"/token",
            _=>throw new InvalidOperationException()
        };

        await using var registry=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            events.Enqueue(Observe("registry",c,body));
            string path=c.Request.Path.Value??"";
            string method=c.Request.Method;
            bool authenticated=c.Request.Headers.Authorization.ToString()=="Bearer "+SyntheticToken ||
                (registryRedirectBasic && c.Request.Headers.Authorization.ToString()==Basic);
            if(!authenticated)
            {
                if(registryRedirectBasic && path.Contains("/baseprobe/manifests/",StringComparison.Ordinal))
                    await Reply(c,302,location:"https://privateauth.lab.test:"+privateEndpoint.Port+path);
                else await Reply(c,401,challenge:"Bearer realm=\""+tokenEndpoint+"\",service=\"lab\",scope=\"repository:baseprobe:pull\"");
                return;
            }
            if(path.Contains("/manifests/",StringComparison.Ordinal))
            {
                if(method=="GET" || method=="HEAD")
                {
                    await Reply(c,200,method=="HEAD"?null:manifest,"application/vnd.oci.image.manifest.v1+json",digest:manifestHash);
                }
                else if(method=="PUT")
                {
                    Interlocked.Increment(ref producedManifest);
                    await Reply(c,201,digest:Hash(Encoding.UTF8.GetBytes(body)));
                }
                else await Reply(c,405);
            }
            else if(path.Contains("/blobs/uploads",StringComparison.Ordinal))
            {
                if(method=="POST" || method=="PATCH" || method=="PUT")
                {
                    string uuid="synthetic-upload-id";
                    string location="/v2/probe/blobs/uploads/"+uuid;
                    c.Response.Headers["Docker-Upload-UUID"]=uuid;
                    if(method=="PUT")await Reply(c,201,digest:c.Request.Query["digest"].ToString());
                    else await Reply(c,202,location:location);
                }
                else await Reply(c,405);
            }
            else if(path.Contains("/blobs/",StringComparison.Ordinal))
            {
                if(method=="GET" && path.EndsWith(cfgHash,StringComparison.Ordinal))
                {
                    Interlocked.Increment(ref downloadedConfig);
                    await Reply(c,200,Encoding.UTF8.GetString(cfg),"application/octet-stream",digest:cfgHash);
                }
                else await Reply(c,method=="HEAD"?404:404);
            }
            else if(path=="/v2/" || path=="/v2")
                await Reply(c,200,"{}","application/json");
            else await Reply(c,404);
        },tls:true);

        string temp=Path.Combine(Path.GetTempPath(),"oci-publish-proof-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        int? exitCode=null;
        bool timedOut=false;
        string outputExcerpt="";
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
                  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net{major}.0</TargetFramework>
                  <EnableSdkContainerSupport>true</EnableSdkContainerSupport>
                  <ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
                </Project>
                """);
            File.WriteAllText(Path.Combine(temp,"Program.cs"),"Console.WriteLine(\"synthetic OCI publish verification\");");
            var p=new ProcessStartInfo("dotnet") {
                WorkingDirectory=temp,
                RedirectStandardOutput=true,
                RedirectStandardError=true,
                UseShellExecute=false
            };
            foreach(string arg in new[]{
                "publish","Probe.csproj","-t:PublishContainer","--nologo","-v:minimal",
                "-p:ContainerBaseImage=registry.lab.test:"+registry.Port+"/baseprobe:latest",
                "-p:ContainerRegistry=registry.lab.test:"+registry.Port,
                "-p:ContainerRepository=probe",
                "-p:ContainerImageTag=authproof",
                "-p:ContainerRuntimeIdentifier=linux-x64",
                "-p:NuGetAudit=false"
            })p.ArgumentList.Add(arg);
            foreach(string key in new[]{"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy",
                "DOTNET_CONTAINER_PULL_REGISTRY_UNAME","DOTNET_CONTAINER_PULL_REGISTRY_PWORD",
                "DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
                "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD",
                "SDK_CONTAINER_REGISTRY_UNAME","SDK_CONTAINER_REGISTRY_PWORD"})
                p.Environment.Remove(key);
            p.Environment["NO_PROXY"]="*";
            p.Environment["no_proxy"]="*";
            if(!identityMode && !missingCredentials)
            {
                p.Environment["DOTNET_CONTAINER_PULL_REGISTRY_UNAME"]=SyntheticUser;
                p.Environment["DOTNET_CONTAINER_PULL_REGISTRY_PWORD"]=SyntheticPass;
                p.Environment["DOTNET_CONTAINER_PUSH_REGISTRY_UNAME"]=SyntheticUser;
                p.Environment["DOTNET_CONTAINER_PUSH_REGISTRY_PWORD"]=SyntheticPass;
                p.Environment["DOTNET_CONTAINER_REGISTRY_UNAME"]=SyntheticUser;
                p.Environment["DOTNET_CONTAINER_REGISTRY_PWORD"]=SyntheticPass;
            }
            else
            {
                // The SDK's real Docker credentials provider reads this temporary config.
                // A registry absent from the auths table should fail credential retrieval.
                string configPath=Path.Combine(temp,"synthetic-auth.json");
                string authConfig=missingCredentials
                    ? "{\"auths\":{}}"
                    : JsonSerializer.Serialize(new {
                        auths=new Dictionary<string,object>{
                            [RegistryHostName(registry.Port)]=new {
                                identitytoken=SyntheticIdentity,
                                auth=Convert.ToBase64String(Encoding.ASCII.GetBytes("placeholder:placeholder"))
                            }
                        }
                    });
                File.WriteAllText(configPath,authConfig);
                p.Environment["REGISTRY_AUTH_FILE"]=configPath;
                p.Environment["DOCKER_CONFIG"]=temp;
            }
            if(IsPatched)
            {
                p.Environment["DOTNET_CONTAINER_AUTH_REALM_POLICY"]="AllowlistOnly";
                p.Environment["DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES"]="127.0.0.1";
            }
            p.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"]="1";
            p.Environment["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"]="1";
            using Process process=Process.Start(p)??throw new InvalidOperationException("Cannot launch dotnet publish");
            var stdout=process.StandardOutput.ReadToEndAsync();
            var stderr=process.StandardError.ReadToEndAsync();
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(90));
            try{await process.WaitForExitAsync(timeout.Token);exitCode=process.ExitCode;}
            catch(OperationCanceledException){timedOut=true;process.Kill(entireProcessTree:true);await process.WaitForExitAsync();}
            string combined=(await stdout)+"\n"+(await stderr);
            // Whitelist diagnostic lines only, never include full untrusted process output in artifacts.
            outputExcerpt=string.Join("\n",combined.Split('\n')
                .Where(x=>x.Contains("error ",StringComparison.OrdinalIgnoreCase)
                    ||x.Contains("Successfully",StringComparison.OrdinalIgnoreCase)
                    ||x.Contains("Container",StringComparison.OrdinalIgnoreCase)
                    ||x.Contains("CONTAINER",StringComparison.OrdinalIgnoreCase))
                .Take(8).Select(x=>x.Length>350?x[..350]:x));
        }
        finally
        {
            try{Directory.Delete(temp,true);}catch(IOException){}
        }
        var records=events.ToArray();
        bool privateBasic=records.Any(x=>x.Role=="private-token"&&x.SyntheticBasic);
        bool publicBasic=records.Any(x=>x.Role=="public-token"&&x.SyntheticBasic);
        bool privateForm=records.Any(x=>x.Role=="private-token"&&x.SyntheticPasswordForm);
        bool privateIdentity=records.Any(x=>x.Role=="private-token"&&x.SyntheticIdentityForm);
        bool startedManifestPull=records.Any(x=>x.Role=="registry"&&x.Path.Contains("/baseprobe/manifests/",StringComparison.Ordinal));
        bool registryGotBasic=records.Any(x=>x.Role=="registry"&&x.SyntheticBasic);
        bool authRetry=records.Any(x=>x.Role=="registry"&&(x.SyntheticBearer||x.SyntheticBasic));
        bool directBlocked=directMode && (Is11||IsPatched);
        bool bodyPreserved=redirectStatus is 307 or 308;
        bool forwardedExpected=identityMode
            ? privateIdentity && !privateForm && !privateBasic
            : redirectMode ? (bodyPreserved ? privateForm && !privateBasic : !privateForm && !privateIdentity)
                : privateBasic;
        bool shouldBeRejected=missingCredentials || directBlocked || downgradeRedirect ||
            (IsPatched && (mode is not "public-allowed"));
        bool pass=startedManifestPull && !timedOut &&
            (shouldBeRejected ? exitCode!=0 && !privateBasic && !privateForm && !privateIdentity &&
                (downgradeEndpointRequests==0 || !downgradeRedirect) &&
                (missingCredentials || directBlocked || downgradeRedirect || IsPatched)
                : mode=="public-allowed" ? exitCode==0 && producedManifest==1 && authRetry &&
                    publicBasic && !privateBasic && !privateForm && !privateIdentity
                : registryRedirectBasic ? exitCode==0 && producedManifest==1 && privateBasic &&
                    !privateForm && !privateIdentity && authRetry && registryGotBasic &&
                    records.Count(x=>x.Role=="private-token")>=2
                : exitCode==0 && producedManifest==1 && forwardedExpected && authRetry);

        var report=new {
            mode,passed=pass,sdk=Sdk,exitCode,timedOut,
            fullPublishCompleted=exitCode==0,
            registryManifestUploadCount=producedManifest,
            baseConfigDownloaded=downloadedConfig,
            startedManifestPull,authenticationRetried=authRetry,
            protectedEndpointGotSyntheticBasic=privateBasic,
            allowedPublicEndpointGotSyntheticBasic=publicBasic,
            protectedEndpointGotSyntheticPasswordForm=privateForm,
            protectedEndpointGotSyntheticIdentityForm=privateIdentity,
            registryRedirectBasicChallenge=registryRedirectBasic,
            registryReceivedSyntheticBasic=registryGotBasic,
            expectedPatchedImplementation=IsPatched,
            downgradeEndpointRequests,
            redirectStatus=redirectMode?(int?)redirectStatus:null,
            usedSyntheticIdentityToken=identityMode,
            missingCredentialsControl=missingCredentials,
            protectedRequestCount=records.Count(x=>x.Role=="private-token"),
            publicRequestCount=records.Count(x=>x.Role=="public-token"),
            outputExcerpt,networkEvents=records
        };
        Reports.Add(report);
        Console.WriteLine("[PUBLISH "+Sdk+"] "+mode+" "+JsonSerializer.Serialize(report));
        return pass;
    }
}
