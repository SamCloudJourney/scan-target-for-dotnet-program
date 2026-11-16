// Entirely synthetic two-registry dotnet publish, with different source and destination authorities.
// Tests whether source-side realm challenges can see credentials intended for the destination,
// under three credential configurations. No real image repositories or credentials are contacted.
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

static class DualRegistryPublishLab
{
    const string User="DUAL_SYNTH_DESTINATION_USER";
    const string Pass="DUAL_SYNTH_DESTINATION_PASSWORD";
    const string Token="DUAL_SYNTH_SOURCE_TOKEN";
    static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    static readonly bool Fixed=Environment.GetEnvironmentVariable("SDK_EXPECT_PATCHED")=="1";
    static readonly List<object> Reports=[];
    static string Basic=>"Basic "+Convert.ToBase64String(Encoding.UTF8.GetBytes(User+":"+Pass));
    record WireHit(string Endpoint,string Method,string Path,bool BasicCredentials,bool Bearer);
    static string Digest(byte[] data)=>"sha256:"+Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
    static async Task Reply(HttpContext c,int status,string? body=null,string? mime=null,string? challenge=null,string? loc=null,string? digest=null)
    {
        c.Response.StatusCode=status;
        if(mime!=null)c.Response.ContentType=mime;
        if(challenge!=null)c.Response.Headers.WWWAuthenticate=challenge;
        if(loc!=null)c.Response.Headers.Location=loc;
        if(digest!=null)c.Response.Headers["Docker-Content-Digest"]=digest;
        if(body!=null)await c.Response.WriteAsync(body);
    }
    public static async Task RunAsync()
    {
        bool all=true;
        try
        {
            foreach(string mode in new[]{"global-both","push-only","docker-destination-only"})
            {
                bool result=await One(mode);
                all &=result;
            }
        }
        finally
        {
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-dual-registry-publish.json",
                JsonSerializer.Serialize(new{sdk=Sdk,expectedFixed=Fixed,tests=Reports},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!all)throw new Exception("Dual-registry publish safety and scoped-credential assertions failed");
    }
    static async Task<bool> One(string mode)
    {
        var hits=new ConcurrentQueue<WireHit>();
        int destinationManifestWrites=0,sourceManifestGets=0;
        int? status=null;bool timedOut=false;
        string diagnostic="";
        string? challengeUrl=null;
        byte[] config=Encoding.UTF8.GetBytes("""{"architecture":"amd64","os":"linux","config":{"Entrypoint":["dotnet"]},"rootfs":{"type":"layers","diff_ids":[]},"history":[]}""");
        string cfgHash=Digest(config);
        string manifest=JsonSerializer.Serialize(new {
            schemaVersion=2,mediaType="application/vnd.oci.image.manifest.v1+json",
            config=new {mediaType="application/vnd.oci.image.config.v1+json",size=config.Length,digest=cfgHash},
            layers=Array.Empty<object>()
        });
        string manifestHash=Digest(Encoding.UTF8.GetBytes(manifest));
        await using var collector=await LocalEndpoint.Start("127.0.0.2",async c=>
        {
            string auth=c.Request.Headers.Authorization.ToString();
            hits.Enqueue(new("lower-trust-source-auth-realm",c.Request.Method,c.Request.Path.ToString(),auth==Basic,false));
            if(auth==Basic)await Reply(c,200,JsonSerializer.Serialize(new{token=Token,expires_in=120}),"application/json");
            else await Reply(c,403);
        },tls:true);
        challengeUrl="https://privateauth.lab.test:"+collector.Port+"/token";
        await using var source=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            string path=c.Request.Path.ToString();
            bool bearer=c.Request.Headers.Authorization.ToString()=="Bearer "+Token;
            hits.Enqueue(new("untrusted-base-image-registry",c.Request.Method,path,false,bearer));
            if(!bearer)
            {
                await Reply(c,401,challenge:"Bearer realm=\""+challengeUrl+"\",service=\"base\"");return;
            }
            if(path.Contains("/manifests/",StringComparison.Ordinal))
            {
                Interlocked.Increment(ref sourceManifestGets);
                await Reply(c,200,c.Request.Method=="HEAD"?null:manifest,"application/vnd.oci.image.manifest.v1+json",digest:manifestHash);
            }
            else if(path.Contains("/blobs/",StringComparison.Ordinal)&&path.EndsWith(cfgHash,StringComparison.Ordinal))
                await Reply(c,200,Encoding.UTF8.GetString(config),"application/octet-stream",digest:cfgHash);
            else await Reply(c,404);
        },tls:true);
        await using var destination=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            string path=c.Request.Path.ToString();
            string auth=c.Request.Headers.Authorization.ToString();
            hits.Enqueue(new("independent-private-destination",c.Request.Method,path,auth==Basic,false));
            if(auth!=Basic){await Reply(c,401,challenge:"Basic realm=\"private-destination\"");return;}
            if(path.Contains("/manifests/",StringComparison.Ordinal))
            {
                if(c.Request.Method=="PUT")
                {
                    Interlocked.Increment(ref destinationManifestWrites);
                    await Reply(c,201,digest:Digest(Encoding.UTF8.GetBytes("synthetic-manifest")));
                }
                else await Reply(c,404);
            }
            else if(path.Contains("/blobs/uploads",StringComparison.Ordinal))
            {
                c.Response.Headers["Docker-Upload-UUID"]="synthetic-dual-upload";
                if(c.Request.Method=="PUT")await Reply(c,201,digest:c.Request.Query["digest"].ToString());
                else await Reply(c,202,loc:"/v2/mydestination/blobs/uploads/synthetic-dual-upload");
            }
            else if(path.Contains("/blobs/",StringComparison.Ordinal))await Reply(c,404);
            else if(path=="/v2/"||path=="/v2")await Reply(c,200,"{}","application/json");
            else await Reply(c,404);
        },tls:true);

        string temp=Path.Combine(Path.GetTempPath(),"dual-oci-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            File.WriteAllText(Path.Combine(temp,"global.json"),JsonSerializer.Serialize(new{sdk=new{version=Sdk,rollForward="disable"}}));
            File.WriteAllText(Path.Combine(temp,"NuGet.Config"),"""<configuration><packageSources><clear /></packageSources></configuration>""");
            File.WriteAllText(Path.Combine(temp,"Probe.csproj"),$"""
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net{Sdk.Split('.')[0]}.0</TargetFramework>
                  <EnableSdkContainerSupport>true</EnableSdkContainerSupport></PropertyGroup>
                </Project>
                """);
            File.WriteAllText(Path.Combine(temp,"Program.cs"),"""System.Console.WriteLine("synthetic dual registry run");""");
            var p=new ProcessStartInfo("dotnet") {
                WorkingDirectory=temp,RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false
            };
            foreach(string arg in new[]{
                "publish","Probe.csproj","-t:PublishContainer","-v:minimal","--nologo",
                "-p:ContainerBaseImage=registry.lab.test:"+source.Port+"/untrustedbase:latest",
                "-p:ContainerRegistry=registry-alt.lab.test:"+destination.Port,
                "-p:ContainerRepository=mydestination","-p:ContainerImageTag=proof",
                "-p:NuGetAudit=false"})p.ArgumentList.Add(arg);
            foreach(string key in new[]{
                "HTTPS_PROXY","HTTP_PROXY","ALL_PROXY","https_proxy","http_proxy","all_proxy",
                "DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",
                "DOTNET_CONTAINER_PULL_REGISTRY_UNAME","DOTNET_CONTAINER_PULL_REGISTRY_PWORD",
                "DOTNET_CONTAINER_REGISTRY_UNAME","DOTNET_CONTAINER_REGISTRY_PWORD",
                "REGISTRY_AUTH_FILE","DOCKER_CONFIG"})p.Environment.Remove(key);
            p.Environment["NO_PROXY"]="*";p.Environment["no_proxy"]="*";
            p.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"]="1";
            if(Fixed)
            {
                p.Environment["DOTNET_CONTAINER_AUTH_REALM_POLICY"]="AllowlistOnly";
                p.Environment["DOTNET_CONTAINER_AUTH_REALM_ALLOWED_ADDRESSES"]="127.0.0.1";
            }
            if(mode=="global-both" || mode=="push-only")
            {
                p.Environment["DOTNET_CONTAINER_PUSH_REGISTRY_UNAME"]=User;
                p.Environment["DOTNET_CONTAINER_PUSH_REGISTRY_PWORD"]=Pass;
                if(mode=="global-both")
                {
                    p.Environment["DOTNET_CONTAINER_PULL_REGISTRY_UNAME"]=User;
                    p.Environment["DOTNET_CONTAINER_PULL_REGISTRY_PWORD"]=Pass;
                }
            }
            else
            {
                // Docker config is scoped to the destination registry only.
                File.WriteAllText(Path.Combine(temp,"config.json"),
                    JsonSerializer.Serialize(new{auths=new Dictionary<string,object>{
                        ["registry-alt.lab.test:"+destination.Port]=new{
                            auth=Convert.ToBase64String(Encoding.UTF8.GetBytes(User+":"+Pass))}
                    }}));
                p.Environment["DOCKER_CONFIG"]=temp;
            }
            using var process=Process.Start(p)!;
            Task<string> stdout=process.StandardOutput.ReadToEndAsync();
            Task<string> stderr=process.StandardError.ReadToEndAsync();
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(85));
            try{await process.WaitForExitAsync(deadline.Token);status=process.ExitCode;}
            catch(OperationCanceledException){timedOut=true;process.Kill(entireProcessTree:true);await process.WaitForExitAsync();}
            string combined=(await stdout)+"\n"+(await stderr);
            diagnostic=string.Join("\n",combined.Split('\n').Where(x=>x.Contains("error ",StringComparison.OrdinalIgnoreCase))
                .Take(5).Select(x=>x.Length>250?x[..250]:x));
        }
        finally{try{Directory.Delete(temp,true);}catch(IOException){}}

        var wires=hits.ToArray();
        bool sourceContacted=wires.Any(x=>x.Endpoint=="untrusted-base-image-registry");
        bool leaked=wires.Any(x=>x.Endpoint=="lower-trust-source-auth-realm"&&x.BasicCredentials);
        bool destinationGotCredentials=wires.Any(x=>x.Endpoint=="independent-private-destination"&&x.BasicCredentials);
        // Two only intentionally asserted requirements: the official fixed SDK must
        // not leak via private realm, and destination-only Docker credentials must
        // not accidentally be reused for unrelated source registry authentication.
        // The push-only case is observational and may differ legitimately by SDK version.
        bool passed=!timedOut && sourceContacted &&
            (!Fixed || !leaked) &&
            (mode!="docker-destination-only" || !leaked);
        var report=new{scenario="dual-registry-"+mode,passed,sdk=Sdk,fixedBuild=Fixed,
            intendedCredentialConfiguration=mode,sourceRegistryContacted=sourceContacted,
            sourceRealmReceivedDestinationCredential=leaked,
            independentDestinationAcceptedCredentials=destinationGotCredentials,
            sourceManifestReadCount=sourceManifestGets,
            destinationManifestWriteCount=destinationManifestWrites,
            publishExitCode=status,completedPublish=status==0,timedOut,diagnostic,networkTrace=wires};
        Reports.Add(report);
        Console.WriteLine("[DUAL "+Sdk+"] "+JsonSerializer.Serialize(report));
        return passed;
    }
}
