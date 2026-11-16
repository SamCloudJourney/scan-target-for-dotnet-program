// Interactive, authorized two-account Windows VM experiment. MUST be executed as a
// genuine standard-user dotnet.exe process. A separate human administrator must
// explicitly approve each real UAC prompt. Do not run on someone else's machine.
// Only disposable self-created file, cache, registry and MSI fixtures are touched.
// NOTE: Requests are sent by this research client, NOT the ordinary dotnet workload client.
// A successful result proves the real UAC broker/transport effect but does not prove
// reachability from an unmodified workload command.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

internal static class Program
{
    private static readonly List<object> Tests = new();
    private static readonly List<object> Sessions = new();
    private static readonly List<string> Errors = new();
    private static int FailureCount;

    private sealed class Fixture
    {
        public string Root { get; set; } = "";
        public string ClientDir { get; set; } = "";
        public string ProtectedDir { get; set; } = "";
        public string PinnedCwd { get; set; } = "";
        public string JunctionCacheId { get; set; } = "";
        public string BroadCacheId { get; set; } = "";
        public string ProviderName { get; set; } = "";
        public string? ProductCode { get; set; }
        public string? ProductMarker { get; set; }
        public string JunctionSha256 { get; set; } = "";
        public string BroadSha256 { get; set; } = "";
        public string CreatedBySid { get; set; } = "";
    }
    private sealed class BrokerSession : IDisposable
    {
        public Process Broker { get; }
        public NamedPipeClientStream Request { get; }
        public NamedPipeClientStream Log { get; }
        private readonly Task DrainTask;
        public BrokerSession(Process broker, NamedPipeClientStream request, NamedPipeClientStream log)
        {
            Broker=broker; Request=request; Log=log;
            DrainTask=Task.Run(() =>
            {
                byte[] buf=new byte[8192];
                try { while (Log.IsConnected && Log.Read(buf)>0) {} }
                catch(IOException) {}
                catch(ObjectDisposedException) {}
            });
        }
        public void Dispose()
        {
            try { Request.Dispose(); } catch {}
            try { Log.Dispose(); } catch {}
            if(!Broker.HasExited)
            {
                try { if(!Broker.WaitForExit(12000))Broker.Kill(entireProcessTree:true); } catch {}
            }
            Broker.Dispose();
        }
    }
    private static void Check(string id,bool passed,string detail,string limitation)
    {
        Tests.Add(new {id,passed,detail,limitation});
        if(!passed)FailureCount++;
        Console.WriteLine("CHECK "+id+" "+(passed?"PASS ":"FAIL ")+detail);
    }
    private static string HostPath => Environment.ProcessPath ??
        throw new InvalidOperationException("dotnet.exe executable unknown");
    private static string SdkPath(string version)
        => Path.Combine(Path.GetDirectoryName(HostPath)!,"sdk",version,"dotnet.dll");
    private static string GetPipeName(Assembly sdk,int pid,string[] suffix)
    {
        Type utils=sdk.GetType("Microsoft.DotNet.Cli.Installer.Windows.WindowsUtils",true)!;
        return (string)utils.GetMethod("CreatePipeName",BindingFlags.Public|BindingFlags.Static)!
            .Invoke(null,new object[]{pid,suffix})!;
    }
    private static string Hash(string path)
        => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    private static (uint error,int hresult,string? message) Send(NamedPipeClientStream pipe,object request)
    {
        byte[] payload=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request));
        byte[] prefix=BitConverter.GetBytes(payload.Length);
        using CancellationTokenSource timeout=new(TimeSpan.FromSeconds(30));
        pipe.Write(prefix);
        pipe.Write(payload);
        pipe.Flush();
        byte[] lenBytes=new byte[4];
        pipe.ReadExactlyAsync(lenBytes,timeout.Token).AsTask().GetAwaiter().GetResult();
        int length=BitConverter.ToInt32(lenBytes);
        if(length<=0||length>65000)throw new InvalidDataException("Invalid reply size "+length);
        byte[] body=new byte[length];
        pipe.ReadExactlyAsync(body,timeout.Token).AsTask().GetAwaiter().GetResult();
        using JsonDocument doc=JsonDocument.Parse(body);
        JsonElement root=doc.RootElement;
        uint error=root.TryGetProperty("Error",out var e)?e.GetUInt32():uint.MaxValue;
        int hr=root.TryGetProperty("HResult",out var h)?h.GetInt32():int.MinValue;
        string? msg=root.TryGetProperty("Message",out var m)?m.ToString():null;
        return (error,hr,msg);
    }
    private static BrokerSession StartApprovedBroker(Assembly sdk,string version,string trustedRoot,string phase)
    {
        string selected=Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
        string expected=Path.GetFullPath(trustedRoot).TrimEnd(Path.DirectorySeparatorChar);
        Check("temp-root-"+phase,
            selected.Equals(expected,StringComparison.OrdinalIgnoreCase),
            "Path.GetTempPath()="+selected,
            "Replicates the normal client's root argument construction, but subsequent IPC is custom.");
        if(!selected.Equals(expected,StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Client temp root does not match expected fixture");
        var start=new ProcessStartInfo(HostPath,
            "workload elevate --client-temp \""+selected+"\"")
        {
            Verb="runas",UseShellExecute=true,CreateNoWindow=true,
            WindowStyle=ProcessWindowStyle.Hidden,
            WorkingDirectory=Directory.GetCurrentDirectory()
        };
        Console.WriteLine("HUMAN_APPROVAL_REQUIRED: phase "+phase+
            " — check that the UAC request identifies the expected dotnet.exe on your own VM.");
        Console.WriteLine("If a separate administrator has NOT explicitly approved this test, cancel the prompt.");
        Process broker=Process.Start(start) ??
            throw new InvalidOperationException("ShellExecute produced no process");
        string pipeName=GetPipeName(sdk,broker.Id,Array.Empty<string>());
        string logName=GetPipeName(sdk,broker.Id,["log"]);
        var req=new NamedPipeClientStream(".",pipeName,PipeDirection.InOut);
        var log=new NamedPipeClientStream(".",logName,PipeDirection.InOut);
        try
        {
            using CancellationTokenSource cts=new(TimeSpan.FromSeconds(30));
            Task a=req.ConnectAsync(cts.Token);
            Task b=log.ConnectAsync(cts.Token);
            Task.WhenAll(a,b).WaitAsync(cts.Token).GetAwaiter().GetResult();
            req.ReadMode=PipeTransmissionMode.Message;
            log.ReadMode=PipeTransmissionMode.Message;
            Sessions.Add(new {
                phase,brokerPid=broker.Id,
                initialClientSid=WindowsIdentity.GetCurrent().User?.Value,
                approvedLauncher="actual ProcessStartInfo Verb=runas, UseShellExecute=true",
                userApprovalObservedIndirectly="ShellExecute returned and both broker pipes connected",
                note="Explicit human administrator approval is required; IPC requests still originate in this custom harness"
            });
            Check("uac-pipes-"+phase,true,
                "Real UAC-launched dotnet broker connected to standard-user request and log pipes",
                "The harness cannot independently attest the administrator's identity at the consent UI.");
            return new BrokerSession(broker,req,log);
        }
        catch
        {
            req.Dispose();log.Dispose();
            try {if(!broker.HasExited)broker.Kill(entireProcessTree:true);}catch{}
            broker.Dispose();
            throw;
        }
    }
    private static void Junction(string from,string to)
    {
        if(Directory.Exists(from)||File.Exists(from))
            throw new IOException("Refusing pre-existing path "+from);
        using var p=new Process {
            StartInfo=new ProcessStartInfo("cmd.exe","/c mklink /J \""+from+"\" \""+to+"\""){
                UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true,
                RedirectStandardOutput=true
            }
        };
        p.Start();string output=p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd();
        p.WaitForExit();
        if(p.ExitCode!=0||!Directory.Exists(from))throw new IOException("Junction failed: "+output);
    }
    private static void SetTemp(string root)
    {
        Environment.SetEnvironmentVariable("TEMP",root,EnvironmentVariableTarget.Process);
        Environment.SetEnvironmentVariable("TMP",root,EnvironmentVariableTarget.Process);
    }
    private static string CachePath(string id,string file) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "dotnet","workloads",id,"1.0.0",file);
    private static bool ReplyOkay((uint error,int hresult,string? message) r)
        => r.error==0 && r.hresult>=0;

    private static void Narrow(Assembly sdk,string version,Fixture fx)
    {
        SetTemp(fx.ClientDir);
        string link=Path.Combine(fx.ClientDir,"junction");
        Junction(link,fx.ProtectedDir);
        Check("junction-created",true,"Standard-user-created NTFS junction points into admin-only fixture",
            "The low user must not be able to read the protected payload directly.");
        using BrokerSession s=StartApprovedBroker(sdk,version,fx.ClientDir,"narrow");
        string direct=Path.Combine(fx.ProtectedDir,"junction.msi.json");
        var denied=Send(s.Request,new {
            RequestType=100,PackageId="LabRejected."+Guid.NewGuid().ToString("N"),
            PackageVersion="1.0.0",ManifestPath=direct
        });
        Check("12-direct-protected-path-denied",!ReplyOkay(denied),
            "Broker rejected direct protected manifest outside the trusted low-user root",
            "This negative control does not prove the junction request will be allowed.");
        string viaLink=Path.Combine(link,"junction.msi.json");
        var cache=Send(s.Request,new {
            RequestType=100,PackageId=fx.JunctionCacheId,
            PackageVersion="1.0.0",ManifestPath=viaLink
        });
        string cached=CachePath(fx.JunctionCacheId,"junction-payload.dat");
        bool readable=false,matched=false;
        try {readable=File.Exists(cached);matched=readable&&Hash(cached)==fx.JunctionSha256;}
        catch(UnauthorizedAccessException) {}
        Check("12-protected-readback-through-junction",ReplyOkay(cache)&&matched,
            "Actual elevated broker moved admin-only disposable data through the low-user junction; cached hash matched",
            "Genuine UAC IPC, but custom research client requests—not an ordinary workload operation.");
        var provider=Send(s.Request,new {
            RequestType=200,ProviderKeyName=fx.ProviderName,
            Dependent="LabDependent."+Guid.NewGuid().ToString("N")
        });
        Check("13-isolated-hklm-provider-request",ReplyOkay(provider),
            "Administrator broker processed low-user request for self-authored registry provider",
            "Admin verification script must separately confirm the provider state.");
        if(!string.IsNullOrWhiteSpace(fx.ProductCode))
        {
            var uninstall=Send(s.Request,new {
                RequestType=301,ProductCode=fx.ProductCode,
                LogFile=Path.Combine(fx.ClientDir,"isolated-msi-uninstall.log")
            });
            Check("13-disposable-unrelated-msi-uninstall",
                (uninstall.error==0||uninstall.error==3010)&&uninstall.hresult>=0,
                "Broker returned "+uninstall.error+" for unrelated self-authored disposable MSI uninstall",
                "Only fixture ProductCode, never another installed product; administrator independently verifies removal.");
        }
        else
        {
            Sessions.Add(new{phase="narrow",msiTest="SKIPPED - no self-authored MSI fixture provided"});
        }
        var shutdown=Send(s.Request,new{RequestType=0});
        Sessions.Add(new{phase="narrow",shutdown,cache,directControl=denied,provider});
    }
    private static void Broad(Assembly sdk,string version,Fixture fx)
    {
        SetTemp(fx.Root);
        using BrokerSession s=StartApprovedBroker(sdk,version,fx.Root,"broad");
        string source=Path.Combine(fx.ProtectedDir,"broad.msi.json");
        var reply=Send(s.Request,new {
            RequestType=100,PackageId=fx.BroadCacheId,PackageVersion="1.0.0",
            ManifestPath=source
        });
        string dest=CachePath(fx.BroadCacheId,"broad-payload.dat");
        bool match=false;
        try{match=File.Exists(dest)&&Hash(dest)==fx.BroadSha256;}
        catch(UnauthorizedAccessException){}
        Check("11-broad-root-protected-readback",ReplyOkay(reply)&&match,
            "Broker accepted source under broad client-selected trust root; protected data became readable",
            "Custom client supplies manifest path; no unmodified workload command reachability proved.");
        var shutdown=Send(s.Request,new{RequestType=0});
        Sessions.Add(new{phase="broad",cacheReply=reply,shutdown});
    }
    static int Main(string[] args)
    {
        if(args.Length!=3)
        {
            Console.Error.WriteLine("Usage: dotnet InteractiveApprovalHarness.dll <fixture.json> <SDK VERSION> <evidence.json>");
            return 2;
        }
        string evidence=args[2],version=args[1];
        string status="STARTING";
        string? userSid=null;
        Fixture? fx=null;
        try
        {
            if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows VM required");
            if(!Path.GetFileName(HostPath).Equals("dotnet.exe",StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Run with dotnet.exe, not the apphost.");
            using WindowsIdentity identity=WindowsIdentity.GetCurrent();
            userSid=identity.User?.Value;
            if(new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new UnauthorizedAccessException("Client must run under a non-administrator user");
            fx=JsonSerializer.Deserialize<Fixture>(File.ReadAllText(args[0]),new JsonSerializerOptions{
                PropertyNameCaseInsensitive=true
            }) ?? throw new InvalidDataException("Invalid fixture config");
            if(!fx.CreatedBySid.Equals(userSid,StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Fixture was not prepared for current standard-user SID");
            // Do not accept arbitrary fixture roots: administrator preparation uses a
            // unique disposable directory beneath the Windows Public profile.
            string expectedPrefix=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments),"..");
            string publicRoot=Path.GetFullPath(expectedPrefix);
            string fullFixtureRoot=Path.GetFullPath(fx.Root);
            if(!fullFixtureRoot.StartsWith(publicRoot+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)
                || !Path.GetFileName(fullFixtureRoot).StartsWith("msrc-windows-elevation-lab-",StringComparison.Ordinal))
                throw new InvalidDataException("Fixture root is outside the designated disposable lab directory");
            Directory.SetCurrentDirectory(fx.PinnedCwd);
            string assemblyPath=SdkPath(version);
            if(!File.Exists(assemblyPath))throw new FileNotFoundException("Requested SDK not installed",assemblyPath);
            var assembly=Assembly.LoadFrom(assemblyPath);
            Check("low-user-identity",true,"Harness runs as ordinary user "+identity.Name,
                "Only this user can approve nothing; a separate administrator must consent.");
            bool denied=false;
            try{File.ReadAllBytes(Path.Combine(fx.ProtectedDir,"junction-payload.dat"));}
            catch(UnauthorizedAccessException){denied=true;}
            Check("protected-read-denied-before-uac",denied,
                "Standard-user direct read of protected test payload denied",
                "Protected fixture created by administrator during setup.");
            if(!denied)throw new UnauthorizedAccessException("Abort: protected data is already readable.");
            Narrow(assembly,version,fx);
            Broad(assembly,version,fx);
            status=FailureCount==0?"COMPLETED_REAL_UAC_CUSTOM_CLIENT":"ASSERTION_FAILURE";
        }
        catch(Exception ex){status="INCOMPLETE";Errors.Add(ex.ToString());Console.WriteLine("ERROR "+ex);}
        finally
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(evidence))!);
                File.WriteAllText(evidence,JsonSerializer.Serialize(new {
                    timestampUtc=DateTimeOffset.UtcNow.ToString("O"),status,version,
                    runAsUserSid=userSid,
                    evidenceKind="Real ShellExecute runas UAC + separate standard-user IPC (not unmodified workload client)",
                    fixtureRoot=fx?.Root,
                    checks=Tests,sessions=Sessions,errors=Errors
                },new JsonSerializerOptions{WriteIndented=true}));
                Console.WriteLine("EVIDENCE_FILE="+evidence);
            }
            catch(Exception ex){Console.WriteLine("EVIDENCE_ERROR "+ex);}
            Console.WriteLine("RUN_STATUS="+status);
        }
        return status=="COMPLETED_REAL_UAC_CUSTOM_CLIENT"?0:1;
    }
}
