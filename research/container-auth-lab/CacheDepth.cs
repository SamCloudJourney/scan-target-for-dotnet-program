// Fourth wave: principal isolation tested through the actual SDK DefaultRegistryAPI, not a standalone auth handler.
// Demonstrates the scope of a static per-registry token cache; synthetic credentials and loopback servers only.
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

static class CacheDepthLab
{
    private const string FirstUser="SDK_CACHE_TENANT_A";
    private const string FirstPass="SDK_CACHE_SECRET_A_SYNTHETIC";
    private const string SecondUser="SDK_CACHE_TENANT_B";
    private const string SecondPass="SDK_CACHE_SECRET_B_SYNTHETIC";
    private const string FirstBearer="SDK_CACHE_TOKEN_A";
    private const string SecondBearer="SDK_CACHE_TOKEN_B";
    private static readonly string Sdk=Environment.GetEnvironmentVariable("SDK_VER")??"unknown";
    private static bool Is11=>Sdk.StartsWith("11.");
    private const string RegistryHost="registry.lab.test";
    private const string RegistryOtherHost="registry-alt.lab.test";
    private const string TokenHost="publicauth.lab.test";
    private static readonly List<object> Reports=[];
    private record ServerHit(string Role,string Method,string Path,string AuthClass);
    private static string Basic(string u,string p)=>"Basic "+Convert.ToBase64String(Encoding.ASCII.GetBytes(u+":"+p));

    private static Assembly LoadSdk()
    {
        string path=Environment.GetEnvironmentVariable("DOTNET_SDK_CONTAINER_ASSEMBLY")??throw new InvalidOperationException("Missing installed SDK");
        var sdkRoot=new DirectoryInfo(path).Parent!.Parent!.Parent!.Parent!.FullName;
        var taskDir=Path.GetDirectoryName(path)!;
        AssemblyLoadContext.Default.Resolving+=(context,name)=>{
            foreach(string dir in new[]{taskDir,sdkRoot})
            {
                string dll=Path.Combine(dir,name.Name+".dll");
                if(File.Exists(dll))return context.LoadFromAssemblyPath(dll);
            }
            return null;
        };
        return AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(path));
    }
    private static string AuthClass(HttpContext c)
    {
        string h=c.Request.Headers.Authorization.ToString();
        return h==Basic(FirstUser,FirstPass)?"basic-A":
            h==Basic(SecondUser,SecondPass)?"basic-B":
            h=="Bearer "+FirstBearer?"bearer-A":
            h=="Bearer "+SecondBearer?"bearer-B":
            h==""?"none":"other";
    }
    private static async Task Response(HttpContext c,int code,string? challenge=null)
    {
        c.Response.StatusCode=code;
        if(challenge!=null)c.Response.Headers.WWWAuthenticate=challenge;
    }
    private static void Env(string user,string password)
    {
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",user);
        Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",password);
    }
    private static object CreateApi(Assembly asm,string hostAndPort)
    {
        var apiType=asm.GetType("Microsoft.NET.Build.Containers.DefaultRegistryAPI",true)!;
        var modeType=asm.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!;
        return Activator.CreateInstance(apiType,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,
            null,[hostAndPort,new Uri("https://"+hostAndPort+"/"),false,NullLogger.Instance,Enum.Parse(modeType,"Push")],null)!;
    }
    private static async Task<bool> AllowedForAdmin(object api)
    {
        object m=api.GetType().GetProperty("Manifest")!.GetValue(api)!;
        try
        {
            if(Is11)
            {
                var task=(Task<bool>)m.GetType().GetMethod("ExistsAsync")!.Invoke(m,["tenant-a/private","latest",CancellationToken.None])!;
                return await task;
            }
            else
            {
                var task=(Task<HttpResponseMessage>)m.GetType().GetMethod("GetAsync")!.Invoke(m,["tenant-a/private","latest",CancellationToken.None])!;
                using HttpResponseMessage response=await task;
                return response.IsSuccessStatusCode;
            }
        }
        catch(Exception ex)
        {
            // 10.x returns an exception for 403, whereas 11.x ExistsAsync returns false.
            var root=ex is TargetInvocationException {InnerException:not null} ? ex.InnerException : ex;
            if(root!.GetType().Name.Contains("UnableToAccessRepositoryException") ||
                root.GetType().Name.Contains("ContainerHttpException"))return false;
            throw;
        }
    }

    public static async Task ChildAsync(string registryAddress)
    {
        // Child process never accesses the parent's static authentication cache.
        var old=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        try
        {
            Env(SecondUser,SecondPass);
            var sdk=LoadSdk();
            bool permitted=await AllowedForAdmin(CreateApi(sdk,registryAddress));
            Console.WriteLine("CACHE_CHILD_RESULT="+JsonSerializer.Serialize(new{sdk=Sdk,adminAccess=permitted}));
        }
        finally{HttpClient.DefaultProxy=old;}
    }

    public static async Task RunAsync()
    {
        string? beforeUser=Environment.GetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME");
        string? beforePass=Environment.GetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD");
        IWebProxy originalProxy=HttpClient.DefaultProxy;
        HttpClient.DefaultProxy=new WebProxy();
        bool success=false;
        try{success=await RunScenario();}
        finally
        {
            HttpClient.DefaultProxy=originalProxy;
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_UNAME",beforeUser);
            Environment.SetEnvironmentVariable("DOTNET_CONTAINER_PUSH_REGISTRY_PWORD",beforePass);
            Directory.CreateDirectory("REPRODUCTION-EVIDENCE");
            File.WriteAllText("REPRODUCTION-EVIDENCE/sdk-"+Sdk+"-cache-depth.json",
                JsonSerializer.Serialize(new{sdk=Sdk,tests=Reports},new JsonSerializerOptions{WriteIndented=true}));
        }
        if(!success)throw new Exception("Real SDK cache boundary or process-isolation test failed.");
    }
    private static async Task<bool> RunScenario()
    {
        Assembly asm=LoadSdk();
        var log=new ConcurrentQueue<ServerHit>();
        int issuedA=0,issuedB=0;
        await using var tokens=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            string auth=AuthClass(c);
            log.Enqueue(new("token-service",c.Request.Method,c.Request.Path.ToString(),auth));
            if(auth=="basic-A")
            {
                Interlocked.Increment(ref issuedA);
                c.Response.StatusCode=200;
                await c.Response.WriteAsync(JsonSerializer.Serialize(new{token=FirstBearer,expires_in=180}));
            }
            else if(auth=="basic-B")
            {
                Interlocked.Increment(ref issuedB);
                c.Response.StatusCode=200;
                await c.Response.WriteAsync(JsonSerializer.Serialize(new{token=SecondBearer,expires_in=180}));
            }
            else c.Response.StatusCode=403;
        },tls:true);
        string challenge="Bearer realm=\"https://"+TokenHost+":"+tokens.Port+"/token\",service=\"isolated\"";
        await using var registry=await LocalEndpoint.Start("127.0.0.1",async c=>
        {
            string authorization=AuthClass(c);
            log.Enqueue(new("registry",c.Request.Method,c.Request.Path.ToString(),authorization));
            if(authorization=="bearer-A") await Response(c,200);
            else if(authorization=="bearer-B")await Response(c,403);
            else await Response(c,401,challenge);
        },tls:true);

        string same=RegistryHost+":"+registry.Port,other=RegistryOtherHost+":"+registry.Port;
        Env(FirstUser,FirstPass);
        bool a=await AllowedForAdmin(CreateApi(asm,same));
        // Simulate client A being disposed/finished and a logically separate client B using its own credentials.
        Env(SecondUser,SecondPass);
        bool b=await AllowedForAdmin(CreateApi(asm,same));
        int bCallsBefore=issuedB;
        var parallelClients=Enumerable.Range(0,6).Select(_=>AllowedForAdmin(CreateApi(asm,same))).ToArray();
        bool[] parallel=await Task.WhenAll(parallelClients);
        int bCallsAfter=issuedB;
        bool differentOrigin=await AllowedForAdmin(CreateApi(asm,other));

        bool? childAdmin=null;
        string? childError=null;
        try
        {
            string childDll=Assembly.GetExecutingAssembly().Location;
            var start=new ProcessStartInfo("dotnet"){RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};
            start.ArgumentList.Add(childDll);
            start.ArgumentList.Add("--cache-probe-child");
            start.ArgumentList.Add(same);
            foreach(var k in new[]{"HTTPS_PROXY","HTTP_PROXY","ALL_PROXY","https_proxy","http_proxy","all_proxy"})
                start.Environment.Remove(k);
            start.Environment["NO_PROXY"]="*";
            start.Environment["no_proxy"]="*";
            start.Environment["DOTNET_CONTAINER_PUSH_REGISTRY_UNAME"]=SecondUser;
            start.Environment["DOTNET_CONTAINER_PUSH_REGISTRY_PWORD"]=SecondPass;
            using var process=Process.Start(start)!;
            Task<string> stdout=process.StandardOutput.ReadToEndAsync();
            Task<string> stderr=process.StandardError.ReadToEndAsync();
            using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await process.WaitForExitAsync(limit.Token);
            string output=await stdout;
            string childStderr=await stderr;
            var childLine=output.Split('\n').FirstOrDefault(x=>x.StartsWith("CACHE_CHILD_RESULT="));
            if(childLine!=null)
            {
                using JsonDocument result=JsonDocument.Parse(childLine["CACHE_CHILD_RESULT=".Length..]);
                childAdmin=result.RootElement.GetProperty("adminAccess").GetBoolean();
            }
            else childError="No child result, exit="+process.ExitCode+" "+childStderr[..Math.Min(childStderr.Length,250)];
        }
        catch(Exception e){childError=e.GetBaseException().GetType().Name+": "+e.GetBaseException().Message;}

        bool success=a&&b&&parallel.All(x=>x)&&
            bCallsBefore==0 && bCallsAfter==0 &&
            !differentOrigin && childAdmin==false &&
            issuedA==1 && issuedB==2; // Different origin B and fresh child B each request a token.

        var report=new{scenario="actual-registry-api-cross-client-cache",
            passed=success,sdk=Sdk,
            privilegedFirstClient=a,
            unprivilegedSecondClientGrantedAIdentity=b,
            sixParallelUnprivilegedClientsGrantedAIdentity=parallel.All(x=>x),
            otherRegistryAuthorityGrantedAIdentity=differentOrigin,
            isolatedChildProcessGrantedAIdentity=childAdmin,
            tokenServiceIssuedA=issuedA,tokenServiceIssuedB=issuedB,
            secondClientTokenLookupCount=bCallsBefore,
            parallelClientAdditionalBLookups=bCallsAfter-bCallsBefore,
            childError,requestTrace=log.ToArray()};
        Reports.Add(report);
        Console.WriteLine("[CACHE "+Sdk+"] "+JsonSerializer.Serialize(report));
        return success;
    }
}
