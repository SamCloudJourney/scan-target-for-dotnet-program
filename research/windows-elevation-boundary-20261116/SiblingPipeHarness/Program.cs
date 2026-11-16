// Authorized, disposable same-SID peer regression for the actual Windows SDK workload broker.
// No UAC transition, no privileged third-party installation, no real system file modification.
// A sibling process (not the broker's parent) sends a harmless unknown-product MSI request
// causing a test log to be created only in a newly generated scratch folder.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

internal static class Program
{
    static readonly List<object> Checks=[];
    static readonly List<string> Errors=[];
    static void Record(string id,bool ok,string detail,string limitation)
    {
        Checks.Add(new{id,ok,detail,limitation});
        Console.WriteLine("CASE "+id+" "+(ok?"PASS ":"FAIL ")+detail);
    }
    static string PipeName(Assembly sdk,int pid,params string[] extra)
    {
        var type=sdk.GetType("Microsoft.DotNet.Cli.Installer.Windows.WindowsUtils",true)!;
        var method=type.GetMethod("CreatePipeName",BindingFlags.Public|BindingFlags.Static)!;
        return (string)method.Invoke(null,new object[]{pid,extra})!;
    }
    static (uint error,int hresult,string? message) Send(NamedPipeClientStream stream,object req)
    {
        byte[] msg=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(req));
        byte[] packet=new byte[msg.Length+4];
        BitConverter.GetBytes(msg.Length).CopyTo(packet,0);
        Buffer.BlockCopy(msg,0,packet,4,msg.Length);
        stream.Write(packet);
        stream.Flush();
        stream.WaitForPipeDrain();

        var task=Task.Run(()=>{
            byte[] bytes=new byte[4096];
            int n=stream.Read(bytes);
            if(n<4)throw new EndOfStreamException("SDK response had no length");
            int len=BitConverter.ToInt32(bytes,0);
            if(len<0||len>n-4)throw new InvalidDataException("Invalid response length: "+len);
            using var doc=JsonDocument.Parse(bytes.AsMemory(4,len));
            var root=doc.RootElement;
            uint e=root.TryGetProperty("Error",out var value)?value.GetUInt32():uint.MaxValue;
            int hr=root.TryGetProperty("HResult",out var result)?result.GetInt32():int.MinValue;
            string? m=root.TryGetProperty("Message",out var message)?message.ToString():null;
            return (e,hr,m);
        });
        if(!task.Wait(TimeSpan.FromSeconds(25)))throw new TimeoutException("SDK broker did not reply in 25 seconds");
        return task.GetAwaiter().GetResult();
    }
    static int Peer(string[] args)
    {
        string pipeName=args[1],logPath=args[2],reportPath=args[3];
        var result=new Dictionary<string,object?>{
            ["peerPid"]=Environment.ProcessId,
            ["peerSid"]=WindowsIdentity.GetCurrent().User?.Value,
            ["pipeNameSuppliedByParentHarness"]=true,
            ["brokerLogPath"]=logPath
        };
        bool ok=false;
        try
        {
            using NamedPipeClientStream p=new(".",pipeName,PipeDirection.InOut);
            p.Connect(18000);
            p.ReadMode=PipeTransmissionMode.Message;
            string randomCode="{"+Guid.NewGuid().ToString().ToUpperInvariant()+"}";
            var reply=Send(p,new {RequestType=301,ProductCode=randomCode,LogFile=logPath});
            bool created=File.Exists(logPath);
            result["msiError"]=reply.error;
            result["brokerHresult"]=reply.hresult;
            result["isolatedLogCreated"]=created;
            result["replyMessage"]=reply.message;
            Record("same-sid-sibling-broker-request",reply.error==1605 && created,
                "Sibling same-SID process sent UninstallMsi for an unregistered GUID and real broker created a disposable log.",
                "Client and broker were already authorized under the same administrator SID; this is not cross-user EoP.");
            var shutdown=Send(p,new {RequestType=0});
            result["shutdownHresult"]=shutdown.hresult;
            ok=reply.error==1605&&created;
        }
        catch(Exception e){Errors.Add(e.ToString());Console.WriteLine("PEER_ERROR "+e);}
        finally
        {
            result["status"]=ok?"SUCCESS":"ERROR";
            result["errors"]=Errors;
            result["checks"]=Checks;
            File.WriteAllText(reportPath,JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));
        }
        return ok?0:1;
    }
    static int Parent(string sdkVersion)
    {
        string workspace=Environment.GetEnvironmentVariable("GITHUB_WORKSPACE")??Directory.GetCurrentDirectory();
        string temp=Environment.GetEnvironmentVariable("RUNNER_TEMP")??Path.GetTempPath();
        string root=Path.Combine(workspace,".isolated-sibling-"+Guid.NewGuid().ToString("N"));
        string report=Path.Combine(temp,"sibling-pipe-"+sdkVersion+".json");
        var metadata=new Dictionary<string,object?>();
        bool ok=false;
        string status="RUNNING";
        Process? broker=null,peer=null;
        NamedPipeClientStream? logger=null;
        try
        {
            if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
            using WindowsIdentity ident=WindowsIdentity.GetCurrent();
            var wp=new WindowsPrincipal(ident);
            if(!wp.IsInRole(WindowsBuiltInRole.Administrator))throw new UnauthorizedAccessException("Requires pre-authorized CI administrator");
            string host=Environment.ProcessPath!;
            if(!string.Equals(Path.GetFileName(host),"dotnet.exe",StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Harness must start under dotnet.exe host");
            Directory.CreateDirectory(root);
            string client=Directory.CreateDirectory(Path.Combine(root,"client")).FullName;
            string cwd=Directory.CreateDirectory(Path.Combine(root,"sdk-pinned")).FullName;
            File.WriteAllText(Path.Combine(cwd,"global.json"),
                JsonSerializer.Serialize(new {sdk=new {version=sdkVersion,rollForward="disable"}}));
            string sdkPath=Path.Combine(Path.GetDirectoryName(host)!,"sdk",sdkVersion,"dotnet.dll");
            metadata["sdkDllSha256"]=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sdkPath)));
            metadata["sdkVersion"]=sdkVersion;
            metadata["runnerSid"]=ident.User?.Value;
            metadata["parentPid"]=Environment.ProcessId;
            metadata["runnerIsAdmin"]=true;
            metadata["noUacTransition"]=true;
            var asm=Assembly.LoadFrom(sdkPath);
            string logPath=Path.Combine(client,"sibling-only.log");
            string peerReport=Path.Combine(temp,"sibling-peer-"+sdkVersion+".json");
            string wuauserv;
            {
                using Process sc=new(){StartInfo=new ProcessStartInfo("sc.exe","query wuauserv")
                {
                    RedirectStandardOutput=true,UseShellExecute=false,CreateNoWindow=true
                }};
                sc.Start();wuauserv=sc.StandardOutput.ReadToEnd();sc.WaitForExit();
            }
            if(wuauserv.Contains("RUNNING",StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Refusing to stop an active Windows Update service");

            var serverStart=new ProcessStartInfo(host){
                UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=cwd,
                RedirectStandardOutput=true,RedirectStandardError=true
            };
            serverStart.ArgumentList.Add("workload");
            serverStart.ArgumentList.Add("elevate");
            serverStart.ArgumentList.Add("--client-temp");
            serverStart.ArgumentList.Add(client);
            broker=new Process(){StartInfo=serverStart,EnableRaisingEvents=true};
            broker.Start();
            metadata["brokerPid"]=broker.Id;
            string requestName=PipeName(asm,broker.Id);
            string logName=PipeName(asm,broker.Id,"log");

            var siblingStart=new ProcessStartInfo(host){
                UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=cwd,
                RedirectStandardOutput=true,RedirectStandardError=true
            };
            siblingStart.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
            siblingStart.ArgumentList.Add("peer");
            siblingStart.ArgumentList.Add(requestName);
            siblingStart.ArgumentList.Add(logPath);
            siblingStart.ArgumentList.Add(peerReport);
            peer=new Process(){StartInfo=siblingStart,EnableRaisingEvents=true};
            peer.Start();
            metadata["siblingPid"]=peer.Id;
            metadata["siblingDistinctFromParent"]=peer.Id!=Environment.ProcessId && peer.Id!=broker.Id;

            logger=new NamedPipeClientStream(".",logName,PipeDirection.InOut);
            logger.Connect(20000);
            logger.ReadMode=PipeTransmissionMode.Message;
            NamedPipeClientStream liveLog=logger;
            Task draining=Task.Run(()=>{
                try{byte[] buf=new byte[2048];while(liveLog.IsConnected){if(liveLog.Read(buf)<=0)break;}}
                catch(IOException){}catch(ObjectDisposedException){}
            });
            if(!peer.WaitForExit(30000))throw new TimeoutException("Separate sibling peer did not finish");
            string peerStdout=peer.StandardOutput.ReadToEnd();
            string peerStderr=peer.StandardError.ReadToEnd();
            metadata["peerOutput"]=peerStdout.Length>3500?peerStdout[..3500]:peerStdout;
            metadata["peerError"]=peerStderr.Length>1000?peerStderr[..1000]:peerStderr;
            if(!broker.WaitForExit(12000))throw new TimeoutException("Actual SDK broker did not exit after sibling shutdown");
            if(!File.Exists(peerReport))throw new FileNotFoundException("Sibling evidence missing",peerReport);
            using var peerData=JsonDocument.Parse(File.ReadAllText(peerReport));
            bool peerOk=peerData.RootElement.GetProperty("status").GetString()=="SUCCESS";
            bool sameSid=peerData.RootElement.GetProperty("peerSid").GetString()==ident.User?.Value;
            bool distinct=peer.Id!=Environment.ProcessId&&broker.Id!=peer.Id;
            bool file=File.Exists(logPath);
            Record("same-sid-nonparent-pipe-authorized",peer.ExitCode==0 && peerOk && sameSid && distinct && file,
                "A distinct sibling process with the same SID connected to a real workload broker and triggered disposable MSI log creation.",
                "Pre-authorized admin session and explicitly handed-off pipe name; cannot claim a UAC or cross-SID bypass.");
            Record("broker-still-validated-parent",broker.ExitCode==0 && distinct,
                "Broker was launched by main dotnet harness but accepted a different same-SID peer process as its command sender.",
                "Parent image check cannot alone bind named-pipe peer to original process.");
            metadata["brokerExitCode"]=broker.ExitCode;
            metadata["peerExitCode"]=peer.ExitCode;
            metadata["peerEvidence"]=peerData.RootElement.Clone();
            ok=Checks.All(c=>c.GetType().GetProperty("ok")?.GetValue(c) as bool? == true);
            status=ok?"COMPLETED":"ASSERTION_FAILURE";
        }
        catch(Exception e)
        {
            Errors.Add(e.ToString());
            Console.WriteLine("ERROR "+e);
            status="ERROR";
        }
        finally
        {
            try{logger?.Dispose();}catch{}
            try{if(peer!=null&&!peer.HasExited){peer.Kill(entireProcessTree:true);peer.WaitForExit(5000);}}catch{}
            try{if(broker!=null&&!broker.HasExited){broker.Kill(entireProcessTree:true);broker.WaitForExit(5000);}}catch{}
            peer?.Dispose();
            broker?.Dispose();
            try{if(Directory.Exists(root))Directory.Delete(root,true);}catch(Exception e){Errors.Add("Cleanup:"+e.Message);}
            var result=new {timestampUtc=DateTimeOffset.UtcNow.ToString("O"),status,
                evidenceType="Actual elevated SDK broker and distinct same-SID sibling IPC peer; no UAC transition",
                metadata,checks=Checks,errors=Errors};
            File.WriteAllText(report,JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));
            Console.WriteLine("EVIDENCE_FILE="+report);
            Console.WriteLine("RUN_STATUS="+status);
        }
        return ok?0:1;
    }
    static int Main(string[] args)
    {
        if(args.Length>0 && args[0]=="peer")return Peer(args);
        return Parent(args.Length>0?args[0]:"11.0.100");
    }
}
