// HTTPS-only redirect and realm destination matrix using shipped SDK authentication handler.
// Closed-loop ports, random TLS certificate signed by ephemeral lab CA, dummy credentials only.
using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

static class RedirectMatrixLab
{
    const string User="REDIRECT_TEST_USER";
    const string Password="REDIRECT_TEST_PASSWORD_SYNTH";
    const string Token="REDIRECT_TEST_TOKEN";
    const string RegistryHost="registry.lab.test";
    const string PublicHost="publicauth.lab.test";
    const string PrivateHost="privateauth.lab.test";
    static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    static readonly bool Is11=Sdk.StartsWith("11.");
    static readonly List<object> Matrix=[];
    static string Basic=>"Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(User+":"+Password));
    static readonly string JsonToken="{\"token\":\""+Token+"\",\"expires_in\":180}";
    static readonly string[] Cases={"direct-private-dns","same-host-normal",
        "redirect-301","redirect-302","redirect-303","redirect-307","redirect-308",
        "https-to-http-307","redirect-loop-307","invalid-tls-certificate"};

    static HttpClient Client(Assembly asm,string registry)
    {
        var type=asm.GetType("Microsoft.NET.Build.Containers.AuthHandshakeMessageHandler",true)!;
        var mode=Enum.Parse(asm.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!,"Push");
        var inner=new SocketsHttpHandler{UseProxy=false,UseCookies=false,ConnectTimeout=TimeSpan.FromSeconds(3)};
        object[] args=Is11?[registry,false,inner,NullLogger.Instance,mode]:
            [registry,inner,NullLogger.Instance,mode];
        var ctor=type.GetConstructors(BindingFlags.NonPublic|BindingFlags.Public|BindingFlags.Instance).Single(c=>c.GetParameters().Length==args.Length);
        return new HttpClient((HttpMessageHandler)ctor.Invoke(args)){Timeout=TimeSpan.FromSeconds(15)};
    }
    public static async Task RunAsync()
    {
        string[] keys={"DOTNET_CONTAINER_PUSH_REGISTRY_UNAME","DOTNET_CONTAINER_PUSH_REGISTRY_PWORD"};
        var old=keys.ToDictionary(k=>k,k=>Environment.GetEnvironmentVariable(k));
        var proxy=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        Environment.SetEnvironmentVariable(keys[0],User);
        Environment.SetEnvironmentVariable(keys[1],Password);
        bool success=true;
        try
        {
            string dll=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")!;
            var asm=AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(dll));
            foreach(string mode in Cases)
                success&=await RunOne(asm,mode);
        }
        finally
        {
            HttpClient.DefaultProxy=proxy;
            foreach(var x in old)Environment.SetEnvironmentVariable(x.Key,x.Value);
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-redirect-matrix.json",
                JsonSerializer.Serialize(new{sdk=Sdk,results=Matrix},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!success)throw new Exception("Redirect matrix has unexpected behavior; see structured evidence");
    }

    private static async Task<bool> RunOne(Assembly asm,string mode)
    {
        var publicReq=new ConcurrentQueue<object>();
        var privateReq=new ConcurrentQueue<(string method,bool basic,bool password,bool bearer)>();
        var registryReq=new ConcurrentQueue<object>();
        int status=0;
        string? error=null;
        string? target=null;
        bool downgrade=mode=="https-to-http-307";
        bool wrongCertificate=mode=="invalid-tls-certificate";
        bool privateDns=mode=="direct-private-dns";
        bool normal=mode=="same-host-normal";
        bool loop=mode=="redirect-loop-307";
        int redirectCode=mode switch{
            "redirect-301"=>301,"redirect-302"=>302,"redirect-303"=>303,
            "redirect-307" or "redirect-loop-307" or "https-to-http-307"=>307,
            "redirect-308"=>308,_=>0
        };
        await using var final=await LocalEndpoint.Start(wrongCertificate?"127.0.0.3":"127.0.0.2",
            async c=>{
                string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
                privateReq.Enqueue((c.Request.Method,
                    c.Request.Headers.Authorization.ToString()==Basic,
                    body.Contains(Password,StringComparison.Ordinal),
                    c.Request.Headers.Authorization.ToString()=="Bearer "+Token));
                if(loop){c.Response.StatusCode=307;c.Response.Headers.Location=target;return;}
                c.Response.StatusCode=200;c.Response.ContentType="application/json";
                await c.Response.WriteAsync(JsonToken);
            },tls:!downgrade);
        string finalHost=wrongCertificate?"127.0.0.3":PrivateHost;
        target=(downgrade?"http://":"https://")+finalHost+":"+final.Port+"/redirect-target";
        await using var publicEnd=await LocalEndpoint.Start("127.0.0.1",async c=>{
            string body=await new StreamReader(c.Request.Body).ReadToEndAsync();
            publicReq.Enqueue(new{method=c.Request.Method,basic=c.Request.Headers.Authorization.ToString()==Basic,
                formPassword=body.Contains(Password,StringComparison.Ordinal)});
            if(normal)
            {
                c.Response.StatusCode=200;c.Response.ContentType="application/json";
                await c.Response.WriteAsync(JsonToken);return;
            }
            if(c.Request.Method=="GET"){c.Response.StatusCode=405;return;}
            c.Response.StatusCode=redirectCode;c.Response.Headers.Location=target;
        },tls:true);
        string realm=privateDns?target:
            wrongCertificate?target:
            "https://"+PublicHost+":"+publicEnd.Port+"/auth";
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async c=>{
            bool bearer=c.Request.Headers.Authorization.ToString()=="Bearer "+Token;
            registryReq.Enqueue(new{method=c.Request.Method,bearer});
            if(bearer){c.Response.StatusCode=200;await c.Response.WriteAsync("{}");}
            else
            {
                c.Response.StatusCode=401;
                c.Response.Headers.WWWAuthenticate="Bearer realm=\""+realm+"\",service=\"matrix\"";
            }
        },tls:true);
        try
        {
            using var client=Client(asm,RegistryHost+":"+registry.Port);
            using var r=await client.GetAsync("https://"+RegistryHost+":"+registry.Port+"/v2/");
            status=(int)r.StatusCode;
        }
        catch(Exception ex){error=ex.GetBaseException().GetType().Name;}
        var prs=privateReq.ToArray();
        bool privateBasic=prs.Any(x=>x.basic);
        bool privatePassword=prs.Any(x=>x.password);
        bool privateVisited=prs.Length>0;
        bool forwardedBearer=registryReq.ToArray().Any(x=>JsonSerializer.Serialize(x).Contains("\"bearer\":true"));
        bool bounded=prs.Length<=55;
        bool pass=mode switch
        {
            "direct-private-dns"=>status==200&&privateBasic&&forwardedBearer,
            "same-host-normal"=>status==200&&!privateVisited&&forwardedBearer,
            "redirect-301" or "redirect-302" or "redirect-303"=>
                status==200&&privateVisited&&!privatePassword&&forwardedBearer,
            "redirect-307" or "redirect-308"=>
                status==200&&privatePassword&&forwardedBearer,
            "https-to-http-307"=>
                !privateVisited&&!forwardedBearer&&status!=200,
            "redirect-loop-307"=>
                privateVisited&&privatePassword&&bounded&&!forwardedBearer&&status!=200,
            "invalid-tls-certificate"=>
                !privateVisited&&!forwardedBearer&&status!=200,
            _=>false
        };
        var item=new{scenario=mode,passed=pass,sdk=Sdk,httpStatus=status,error,
            protectedRequestCount=prs.Length,
            protectedReceivedSyntheticBasic=privateBasic,
            protectedReceivedSyntheticPasswordForm=privatePassword,
            registryAuthenticated=forwardedBearer,
            redirectBounded=bounded,
            protectedRequests=prs.Select(x=>new{method=x.method,basic=x.basic,passwordInBody=x.password}).ToArray(),
            publicRequests=publicReq.ToArray()};
        Matrix.Add(item);
        Console.WriteLine("[REDIRECT-MATRIX "+Sdk+"] "+JsonSerializer.Serialize(item));
        return pass;
    }
}
