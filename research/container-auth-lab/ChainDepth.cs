// Third wave: synthetic, loopback-only authentication boundary impact experiments.
using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

record ChainHit(string At,string Method,string Path,bool BasicA,bool BasicB,bool PasswordA,bool PasswordB,bool BearerA,bool BearerB);

static class ChainDepthLab
{
    const string RegistryHost="registry.lab.test";
    const string AlternateHost="registry-alt.lab.test";
    const string PrivateHost="privateauth.lab.test";
    const string ThirdHost="third.lab.test";
    const string PublicHost="publicauth.lab.test";
    const string AUser="SYNTH_USER_A";
    const string APass="SYNTH_PASSWORD_A";
    const string BUser="SYNTH_USER_B";
    const string BPass="SYNTH_PASSWORD_B";
    const string AToken="SYNTH_TOKEN_A";
    const string BToken="SYNTH_TOKEN_B";
    private static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unidentified";
    private static readonly bool Is11=Sdk.StartsWith("11.");
    private static readonly List<object> Results=[];
    private static Assembly _sdk=null!;
    private static readonly string Origin="https://";

    private static string Basic(string user,string password)=>
        "Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(user+":"+password));
    private static ChainHit Hit(string at,HttpContext req,string body)
    {
        string auth=req.Request.Headers.Authorization.ToString();
        return new ChainHit(at,req.Request.Method,req.Request.Path.ToString(),
            auth==Basic(AUser,APass), auth==Basic(BUser,BPass),
            body.Contains(APass,StringComparison.Ordinal),body.Contains(BPass,StringComparison.Ordinal),
            auth=="Bearer "+AToken,auth=="Bearer "+BToken);
    }
    private static void Credentials(string user,string pass)
    {
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",user);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",pass);
    }
    private static async Task Reply(HttpContext ctx,int status,string body="",string? challenge=null,string? redirect=null)
    {
        ctx.Response.StatusCode=status;
        if(challenge is not null)ctx.Response.Headers.WWWAuthenticate=challenge;
        if(redirect is not null)ctx.Response.Headers.Location=redirect;
        if(body.Length>0)
        {
            ctx.Response.ContentType="application/json";
            await ctx.Response.WriteAsync(body);
        }
    }
    private static string TokenBody(string token)=>JsonSerializer.Serialize(new{token,expires_in=60});
    private static string Address(string host,int port,string path)=>Origin+host+":"+port+path;
    private static HttpClient Client(string registry)
    {
        Type type=_sdk.GetType("Microsoft.NET.Build.Containers.AuthHandshakeMessageHandler",true)!;
        Type modeType=_sdk.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!;
        object mode=Enum.Parse(modeType,"Push");
        var sockets=new SocketsHttpHandler{UseCookies=false,UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(5)};
        object[] args=Is11?[registry,false,sockets,NullLogger.Instance,mode]:[registry,sockets,NullLogger.Instance,mode];
        var ctor=type.GetConstructors(BindingFlags.NonPublic|BindingFlags.Public|BindingFlags.Instance).Single(c=>c.GetParameters().Length==args.Length);
        return new HttpClient((HttpMessageHandler)ctor.Invoke(args)){Timeout=TimeSpan.FromSeconds(12)};
    }
    private static void Save(string scenario,bool pass,object details)
    {
        Results.Add(new{scenario,passed=pass,evidence=details});
        Console.WriteLine("[CHAIN "+Sdk+"] "+scenario+": "+(pass?"PASS":"FAIL")+" "+JsonSerializer.Serialize(details));
    }
    public static async Task RunAsync()
    {
        string sdkPath=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")??throw new InvalidOperationException("SDK assembly is missing");
        _sdk=AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(sdkPath));
        // Our local web servers do not use any corporate or shared runner proxy.
        var previousProxy=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        string? oldUser=Environment.GetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME");
        string? oldPass=Environment.GetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD");
        bool success=true;
        try
        {
            success &= await ActualSdkManifestOperation();
            success &= await RegistryRedirectToThirdRealm();
            success &= await CredentialIsolationByClient();
            success &= await TwoHopPasswordForwarding();
            foreach(var kind in new[]{"aws-imdsv2","azure-metadata-header","gcp-metadata-header","guarded-admin"})
                success &= await ProtectedEndpointGuard(kind);
        }
        finally
        {
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",oldUser);
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",oldPass);
            HttpClient.DefaultProxy=previousProxy;
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-chain-depth.json",
                JsonSerializer.Serialize(new{sdk=Sdk,assemblyPath=sdkPath,tests=Results},
                    new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!success)throw new Exception("Chain depth assertion failed: see sdk chain-depth evidence JSON");
    }

    // Exercise actual SDK registry API Manifest.ExistsAsync instead of constructing auth requests ourselves.
    private static async Task<bool> ActualSdkManifestOperation()
    {
        var observed=new ConcurrentQueue<ChainHit>();
        Credentials(AUser,APass);
        await using var protectedRealm=await LocalEndpoint.Start("127.0.0.2",async ctx=>
        {
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            observed.Enqueue(Hit("auth",ctx,body));
            await Reply(ctx,200,TokenBody(AToken));
        },tls:true);
        string tokenUrl=Address(PrivateHost,protectedRealm.Port,"/token");
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            observed.Enqueue(Hit("registry",ctx,""));
            if(ctx.Request.Headers.Authorization.ToString()=="Bearer "+AToken)
                await Reply(ctx,200);
            else await Reply(ctx,401,challenge:"Bearer realm=\""+tokenUrl+"\",service=\"lab\",scope=\"repository:demo:pull\"");
        },tls:true);
        string name=RegistryHost+":"+registry.Port;
        Type api=_sdk.GetType("Microsoft.NET.Build.Containers.DefaultRegistryAPI",true)!;
        object mode=Enum.Parse(_sdk.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!,"Push");
        object instance=Activator.CreateInstance(api,
            BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,
            binder:null,
            args:[name,new Uri(Origin+name+"/"),false,NullLogger.Instance,mode],
            culture:null)!;
        object manifests=api.GetProperty("Manifest")!.GetValue(instance)!;
        Task<bool> existsTask=(Task<bool>)manifests.GetType().GetMethod("ExistsAsync")!.Invoke(
            manifests,["demo","latest",CancellationToken.None])!;
        bool exists=await existsTask;
        var data=observed.ToArray();
        bool pass=exists && data.Any(x=>x.At=="auth"&&x.BasicA) &&
            data.Count(x=>x.At=="registry" && x.Method=="HEAD")==2 &&
            data.Any(x=>x.At=="registry"&&x.BearerA);
        Save("real-sdk-manifest-head",pass,new{exists,protectedRealmGotBasicA=data.Any(x=>x.At=="auth"&&x.BasicA),
            registryRetriedWithBearer=data.Any(x=>x.At=="registry"&&x.BearerA),
            requestSummary=data});
        return pass;
    }

    private static async Task<bool> RegistryRedirectToThirdRealm()
    {
        Credentials(AUser,APass);
        var log=new ConcurrentQueue<ChainHit>();
        await using var third=await LocalEndpoint.Start("127.0.0.3",async ctx=>
        {
            log.Enqueue(Hit("third-token",ctx,""));
            if(ctx.Request.Headers.Authorization.ToString()==Basic(AUser,APass))
                await Reply(ctx,200,TokenBody(AToken));
            else await Reply(ctx,403);
        },tls:true);
        string thirdRealm=Address(ThirdHost,third.Port,"/token");
        await using var privateService=await LocalEndpoint.Start("127.0.0.2",async ctx=>
        {
            log.Enqueue(Hit("private-service",ctx,""));
            if(ctx.Request.Headers.Authorization.ToString()=="Bearer "+AToken)
                await Reply(ctx,200,"{\"synthetic\":\"private-response\"}");
            else await Reply(ctx,401,challenge:"Bearer realm=\""+thirdRealm+"\",service=\"third\",scope=\"synthetic\"");
        },tls:true);
        string redirect=Address(PrivateHost,privateService.Port,"/v2/");
        await using var reg=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            log.Enqueue(Hit("registry",ctx,""));
            await Reply(ctx,302,redirect:redirect);
        },tls:true);
        int? result=null;string? error=null;
        try
        {
            using var sdk=Client(RegistryHost+":"+reg.Port);
            using var response=await sdk.GetAsync(Address(RegistryHost,reg.Port,"/v2/"));
            result=(int)response.StatusCode;
        }
        catch(Exception ex){error=ex.GetBaseException().GetType().Name;}
        var all=log.ToArray();
        bool pass=result==200 && all.Any(x=>x.At=="third-token"&&x.BasicA) &&
            all.Any(x=>x.At=="private-service"&&x.BearerA) &&
            !all.Any(x=>x.At=="registry" && x.BasicA);
        Save("redirected-private-401-third-realm",pass,new{status=result,error,
            thirdGotBasicA=all.Any(x=>x.At=="third-token"&&x.BasicA),
            privateGotBearerA=all.Any(x=>x.At=="private-service"&&x.BearerA),trace=all});
        return pass;
    }

    private static async Task<bool> CredentialIsolationByClient()
    {
        var logs=new ConcurrentQueue<ChainHit>();
        var tokenCalls=new ConcurrentQueue<string>();
        await using var tokenServer=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            string auth=ctx.Request.Headers.Authorization.ToString();
            string issued=auth==Basic(AUser,APass)?AToken:auth==Basic(BUser,BPass)?BToken:"none";
            tokenCalls.Enqueue(issued);
            await Reply(ctx,issued=="none"?403:200,issued=="none"?"":TokenBody(issued));
        },tls:true);
        string challenge="Bearer realm=\""+Address(PublicHost,tokenServer.Port,"/token")+"\",service=\"lab\"";
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            logs.Enqueue(Hit("registry",ctx,""));
            string auth=ctx.Request.Headers.Authorization.ToString();
            if(auth=="Bearer "+AToken)await Reply(ctx,200,"{\"principal\":\"tenant-A\"}");
            else if(auth=="Bearer "+BToken)await Reply(ctx,200,"{\"principal\":\"tenant-B\"}");
            else await Reply(ctx,401,challenge:challenge);
        },tls:true);

        async Task<(int,string)> Read(string host,string user,string password)
        {
            Credentials(user,password);
            using var sdk=Client(host+":"+registry.Port);
            using var response=await sdk.GetAsync(Address(host,registry.Port,"/tenant-resource"));
            return ((int)response.StatusCode,await response.Content.ReadAsStringAsync());
        }
        var first=await Read(RegistryHost,AUser,APass);
        int tokenCountBeforeSecond=tokenCalls.Count;
        var second=await Read(RegistryHost,BUser,BPass);
        int tokenCountAfterSecond=tokenCalls.Count;
        var differentHost=await Read(AlternateHost,BUser,BPass);
        var all=logs.ToArray();
        bool pass=first.Item1==200 && first.Item2.Contains("tenant-A") &&
            second.Item1==200 && second.Item2.Contains("tenant-A") &&
            tokenCountAfterSecond==tokenCountBeforeSecond &&
            differentHost.Item1==200 && differentHost.Item2.Contains("tenant-B") &&
            tokenCalls.Count==2;
        Save("process-wide-credential-cache-isolation",pass,new {
            firstStatus=first.Item1,firstPrincipal=first.Item2,
            secondStatus=second.Item1,secondPrincipal=second.Item2,
            differentOriginStatus=differentHost.Item1,differentOriginPrincipal=differentHost.Item2,
            tokenCalls=tokenCalls.ToArray(),secondTriggeredTokenLookup=tokenCountAfterSecond>tokenCountBeforeSecond,
            trace=all
        });
        return pass;
    }

    private static async Task<bool> TwoHopPasswordForwarding()
    {
        Credentials(AUser,APass);
        var hits=new ConcurrentQueue<ChainHit>();
        await using var final=await LocalEndpoint.Start("127.0.0.3",async ctx=>
        {
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            hits.Enqueue(Hit("hop-2",ctx,body));
            await Reply(ctx,200,TokenBody(AToken));
        },tls:true);
        string finalUrl=Address(ThirdHost,final.Port,"/hop2");
        await using var mid=await LocalEndpoint.Start("127.0.0.2",async ctx=>
        {
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            hits.Enqueue(Hit("hop-1",ctx,body));
            await Reply(ctx,307,redirect:finalUrl);
        },tls:true);
        string midUrl=Address(PrivateHost,mid.Port,"/hop1");
        await using var auth=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            hits.Enqueue(Hit("token-service",ctx,body));
            if(ctx.Request.Method=="GET")await Reply(ctx,405);
            else await Reply(ctx,307,redirect:midUrl);
        },tls:true);
        string authUrl=Address(PublicHost,auth.Port,"/token");
        await using var reg=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            hits.Enqueue(Hit("registry",ctx,""));
            if(ctx.Request.Headers.Authorization.ToString()=="Bearer "+AToken)
                await Reply(ctx,200,"{}");
            else await Reply(ctx,401,challenge:"Bearer realm=\""+authUrl+"\",service=\"lab\"");
        },tls:true);
        int? result=null;string? error=null;
        try
        {
            using var sdk=Client(RegistryHost+":"+reg.Port);
            using var response=await sdk.GetAsync(Address(RegistryHost,reg.Port,"/v2/"));
            result=(int)response.StatusCode;
        }
        catch(Exception ex){error=ex.GetBaseException().GetType().Name;}
        var all=hits.ToArray();
        bool hop1=all.Any(x=>x.At=="hop-1"&&x.Method=="POST"&&x.PasswordA);
        bool hop2=all.Any(x=>x.At=="hop-2"&&x.Method=="POST"&&x.PasswordA);
        bool pass=result==200 && hop1 && hop2 && all.Any(x=>x.At=="registry"&&x.BearerA);
        Save("two-hop-oauth-post-307-forwarding",pass,new{status=result,error,hop1GotPassword=hop1,hop2GotPassword=hop2,trace=all});
        return pass;
    }

    private static async Task<bool> ProtectedEndpointGuard(string scenario)
    {
        Credentials(AUser,APass);
        var requests=new ConcurrentQueue<object>();
        bool leaked=false;
        await using var privateEndpoint=await LocalEndpoint.Start("127.0.0.2",async ctx=>
        {
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            bool permitted=scenario switch
            {
                "aws-imdsv2"=>ctx.Request.Method=="GET" &&
                    ctx.Request.Headers.TryGetValue("X-aws-ec2-metadata-token",out var _),
                "azure-metadata-header"=>ctx.Request.Headers.TryGetValue("Metadata",out var md)
                    && md.ToString().Equals("true",StringComparison.OrdinalIgnoreCase),
                "gcp-metadata-header"=>ctx.Request.Headers.TryGetValue("Metadata-Flavor",out var gcp)
                    && gcp.ToString()=="Google",
                "guarded-admin"=>ctx.Request.Headers.Authorization.ToString()=="Bearer LAB_INTERNAL_ADMIN_TOKEN",
                _=>false
            };
            requests.Enqueue(new{method=ctx.Request.Method,path=ctx.Request.Path.ToString(),permitted,
                basic=ctx.Request.Headers.Authorization.ToString()==Basic(AUser,APass),
                formPassword=body.Contains(APass,StringComparison.Ordinal)});
            if(permitted)
            {
                leaked=true;
                await Reply(ctx,200,TokenBody(AToken));
            }
            else await Reply(ctx,403);
        },tls:true);
        string path=scenario switch{
            "aws-imdsv2"=>"/latest/meta-data/iam/security-credentials/test",
            "azure-metadata-header"=>"/metadata/identity/oauth2/token",
            "gcp-metadata-header"=>"/computeMetadata/v1/instance/service-accounts/default/token",
            "guarded-admin"=>"/admin/action",
            _=>"/token"
        };
        string realm=Address(PrivateHost,privateEndpoint.Port,path);
        int authenticatedRegistry=0;
        await using var reg=await LocalEndpoint.Start("127.0.0.1",async ctx=>
        {
            if(ctx.Request.Headers.Authorization.ToString()=="Bearer "+AToken){
                authenticatedRegistry++;
                await Reply(ctx,200,"{}");
            }
            else await Reply(ctx,401,challenge:"Bearer realm=\""+realm+"\",service=\"lab\"");
        },tls:true);
        int? result=null;string? error=null;
        try{
            using var sdk=Client(RegistryHost+":"+reg.Port);
            using var response=await sdk.GetAsync(Address(RegistryHost,reg.Port,"/v2/"));
            result=(int)response.StatusCode;
        }
        catch(Exception ex){error=ex.GetBaseException().GetType().Name;}
        var req=requests.ToArray();
        bool pass=!leaked && authenticatedRegistry==0 && req.Length>=1 && req.All(o=>!JsonSerializer.Serialize(o).Contains("\"permitted\":true"));
        Save("protected-endpoint-negative-"+scenario,pass,new{result,error,authRequests=req,canaryReleased=leaked,registryAuthenticated=authenticatedRegistry});
        return pass;
    }
}
