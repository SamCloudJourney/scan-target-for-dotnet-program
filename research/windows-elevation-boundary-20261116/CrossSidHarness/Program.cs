// SECURITY LAB ONLY: shipped Microsoft SDK workload broker + separate real standard user.
// Test administrator synthetically associates the elevated child with a preexisting
// standard-user dotnet.exe parent, using explicit admin token and Windows process
// creation attributes. This is NOT a UAC prompt, not an EoP, and not an attack against
// any other software or account. All affected file/MSI/registry objects are disposable.
using System;
using System.Collections.Generic;
using System.ComponentModel;
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
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

internal static class Program
{
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    internal struct STARTUPINFO
    {
        public int cb;
        [MarshalAs(UnmanagedType.LPWStr)]public string? lpReserved;
        [MarshalAs(UnmanagedType.LPWStr)]public string? lpDesktop;
        [MarshalAs(UnmanagedType.LPWStr)]public string? lpTitle;
        public int dwX,dwY,dwXSize,dwYSize,dwXCountChars,dwYCountChars,dwFillAttribute,dwFlags;
        public short wShowWindow,cbReserved2;
        public IntPtr lpReserved2,hStdInput,hStdOutput,hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess,hThread;
        public int dwProcessId,dwThreadId;
    }
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern IntPtr OpenProcess(uint rights,bool inherit,int pid);
    [DllImport("kernel32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr bytes);
    [DllImport("kernel32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr prev,IntPtr returned);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr process,uint rights,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool DuplicateTokenEx(IntPtr existing,uint access,IntPtr attrs,int impersonationLevel,int type,out IntPtr duplicated);
    [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="CreateProcessAsUserW")]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateProcessAsUser(IntPtr token,string app,StringBuilder command,
        IntPtr procAttrs,IntPtr threadAttrs,bool inherit,uint creationFlags,IntPtr environment,
        string cwd,ref STARTUPINFOEX info,out PROCESS_INFORMATION process);
    [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool LookupPrivilegeValue(string? host,string name,out LUID luid);
    [DllImport("advapi32.dll",SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    static extern bool AdjustTokenPrivileges(IntPtr token,bool disableAll,ref TOKEN_PRIVILEGES priv,int length,IntPtr previous,IntPtr returned);

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }
    [StructLayout(LayoutKind.Sequential)]
    struct LUID_ATTRIBUTES {public LUID Luid;public uint Attributes;}
    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES {public int Count;public LUID_ATTRIBUTES Item;}
    static void EnableIfHeld(IntPtr token,string privilege)
    {
        if(!LookupPrivilegeValue(null,privilege,out var luid))return;
        var t=new TOKEN_PRIVILEGES{Count=1,Item=new LUID_ATTRIBUTES{Luid=luid,Attributes=2}};
        AdjustTokenPrivileges(token,false,ref t,0,IntPtr.Zero,IntPtr.Zero);
    }
    static string PathFor(string sdk)
    {
        return Path.Combine(Path.GetDirectoryName(Environment.ProcessPath!)!,"sdk",sdk,"dotnet.dll");
    }
    static string CreatePipeName(Assembly sdk,int pid,params string[] values)
    {
        Type utils=sdk.GetType("Microsoft.DotNet.Cli.Installer.Windows.WindowsUtils",true)!;
        return (string)utils.GetMethod("CreatePipeName",BindingFlags.Static|BindingFlags.Public)!
            .Invoke(null,[pid,values])!;
    }
    static object Send(NamedPipeClientStream pipe,object req)
    {
        byte[] bytes=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(req));
        byte[] data=new byte[4+bytes.Length];
        BitConverter.GetBytes(bytes.Length).CopyTo(data,0);
        bytes.CopyTo(data,4);
        pipe.Write(data);pipe.Flush();pipe.WaitForPipeDrain();
        byte[] buffer=new byte[8192];
        Task<JsonElement> reader=Task.Run(()=>{
            int n=pipe.Read(buffer);
            if(n<4)throw new EndOfStreamException("Broker response lacked prefix");
            int len=BitConverter.ToInt32(buffer,0);
            if(len<0||len>n-4||len>8000)throw new InvalidDataException("Invalid broker reply length="+len);
            using JsonDocument d=JsonDocument.Parse(buffer.AsMemory(4,len));
            return d.RootElement.Clone();
        });
        if(!reader.Wait(TimeSpan.FromSeconds(25)))throw new TimeoutException("Broker reply timeout");
        return reader.GetAwaiter().GetResult();
    }
    static uint ErrorOf(object value)
    {
        var j=(JsonElement)value;
        return j.TryGetProperty("Error",out var x)?x.GetUInt32():uint.MaxValue;
    }
    static string Sha256(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    static int AdminLauncher(string[] args)
    {
        string sdk=args[1],lowPidString=args[2],client=args[3],cwd=args[4],control=args[5],result=args[6];
        int lowPid=int.Parse(lowPidString);
        string status="ERROR";
        var env=new Dictionary<string,object?>();
        var errors=new List<string>();
        IntPtr low=IntPtr.Zero,original=IntPtr.Zero,adminToken=IntPtr.Zero,list=IntPtr.Zero,
            ptr=IntPtr.Zero;
        PROCESS_INFORMATION pi=default;
        bool attrReady=false;
        try
        {
            using WindowsIdentity ident=WindowsIdentity.GetCurrent();
            bool administrator=new WindowsPrincipal(ident).IsInRole(WindowsBuiltInRole.Administrator);
            if(!administrator)throw new UnauthorizedAccessException("Admin test launcher requires existing authorization");
            Process p=Process.GetProcessById(lowPid);
            string host=Environment.ProcessPath!;
            if(Path.GetFullPath(p.MainModule!.FileName)!=Path.GetFullPath(host))
                throw new IOException("Refuse synthetic parent not using the same installed dotnet.exe");
            if(p.StartTime>=Process.GetCurrentProcess().StartTime)throw new IOException("Standard-user parent did not predate launcher");
            env["adminLauncherSid"]=ident.User?.Value;
            env["candidateLowProcess"]=lowPid;
            env["lowProcessExecutable"]=p.MainModule.FileName;
            env["sdkDllSha256"]=Sha256(PathFor(sdk));
            env["syntheticParentAttribute"]=true;
            env["actualInteractiveUacApproval"]=false;
            low=OpenProcess(0x0080|0x1000,false,lowPid);
            if(low==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error(),"OpenProcess low parent failed");
            if(!OpenProcessToken(GetCurrentProcess(),0x000F01FF,out original))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"OpenProcessToken admin failed");
            if(!DuplicateTokenEx(original,0x02000000,IntPtr.Zero,2,1,out adminToken))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"DuplicateTokenEx admin failed");
            EnableIfHeld(adminToken,"SeIncreaseQuotaPrivilege");
            EnableIfHeld(adminToken,"SeAssignPrimaryTokenPrivilege");
            IntPtr needed=IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref needed);
            list=Marshal.AllocHGlobal(needed);
            if(!InitializeProcThreadAttributeList(list,1,0,ref needed))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"InitializeProcThreadAttributeList failed");
            attrReady=true;
            ptr=Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(ptr,low);
            if(!UpdateProcThreadAttribute(list,0,new IntPtr(0x00020000),ptr,new IntPtr(IntPtr.Size),
                IntPtr.Zero,IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"ParentProcess attribute rejected");
            var start=new STARTUPINFOEX{
                StartupInfo=new STARTUPINFO{cb=Marshal.SizeOf<STARTUPINFOEX>()},
                lpAttributeList=list
            };
            var command=new StringBuilder("\""+host+"\" workload elevate --client-temp \""+client+"\"");
            const uint flags=0x00080000|0x08000000;
            bool created=CreateProcessAsUser(adminToken,host,command,IntPtr.Zero,IntPtr.Zero,false,flags,
                IntPtr.Zero,cwd,ref start,out pi);
            if(!created)
            {
                int code=Marshal.GetLastWin32Error();
                env["createProcessWin32Error"]=code;
                status=code==1314||code==5?"BLOCKED_BY_RUNNER_TOKEN_PRIVILEGES":"ERROR";
                errors.Add("CreateProcessAsUserW failed Win32="+code);
                Console.WriteLine("CROSS_SID_SYNTHETIC_STATUS="+status+" Win32="+code);
            }
            else
            {
                using Process child=Process.GetProcessById(pi.dwProcessId);
                env["brokerPid"]=pi.dwProcessId;
                env["brokerStartTimeUtc"]=child.StartTime.ToUniversalTime().ToString("O");
                File.WriteAllText(control,pi.dwProcessId.ToString());
                status="BROKER_CREATED_SYNTHETIC_PARENT";
                Console.WriteLine("BROKER_PID="+pi.dwProcessId+" SYNTHETIC_PARENT_LOW_PID="+lowPid);
            }
        }
        catch(Exception e){errors.Add(e.ToString());Console.WriteLine("ERROR "+e);}
        finally
        {
            if(pi.hThread!=IntPtr.Zero)CloseHandle(pi.hThread);
            if(pi.hProcess!=IntPtr.Zero)CloseHandle(pi.hProcess);
            if(ptr!=IntPtr.Zero)Marshal.FreeHGlobal(ptr);
            if(attrReady)DeleteProcThreadAttributeList(list);
            if(list!=IntPtr.Zero)Marshal.FreeHGlobal(list);
            if(adminToken!=IntPtr.Zero)CloseHandle(adminToken);
            if(original!=IntPtr.Zero)CloseHandle(original);
            if(low!=IntPtr.Zero)CloseHandle(low);
            File.WriteAllText(result,JsonSerializer.Serialize(new{sdk,status,environment=env,errors},
                new JsonSerializerOptions{WriteIndented=true}));
            Console.WriteLine("RUN_STATUS="+status);
        }
        return status=="BROKER_CREATED_SYNTHETIC_PARENT"?0:2;
    }

    static int LowParent(string[] args)
    {
        string sdk=args[1],client=args[2],adminFolder=args[3],control=args[4],
            cacheId=args[5],provider=args[6],result=args[7];
        var checks=new List<object>();
        var errors=new List<string>();
        var env=new Dictionary<string,object?>();
        string status="RUNNING";
        NamedPipeClientStream? request=null,logs=null;
        int? brokerPid=null;
        try
        {
            using WindowsIdentity ident=WindowsIdentity.GetCurrent();
            bool isAdmin=new WindowsPrincipal(ident).IsInRole(WindowsBuiltInRole.Administrator);
            env["lowSid"]=ident.User?.Value;
            env["lowAccount"]=ident.Name;
            env["isAdministrator"]=isAdmin;
            env["parentPid"]=Environment.ProcessId;
            env["parentImage"]=Environment.ProcessPath;
            if(isAdmin)throw new UnauthorizedAccessException("Refusing to run low-user probe as admin");
            var sdkAssembly=Assembly.LoadFrom(PathFor(sdk));
            string target=Path.Combine(adminFolder,"protected-payload.dat");
            bool deniedRead=false,deniedWrite=false,deniedRegistry=false;
            try{File.ReadAllBytes(target);}catch(UnauthorizedAccessException){deniedRead=true;}
            try{File.AppendAllText(target,"unexpected");}catch(UnauthorizedAccessException){deniedWrite=true;}
            try{
                using var reg=Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Classes\Installer\Dependencies",writable:true);
                reg?.CreateSubKey(provider);
            }catch(UnauthorizedAccessException){deniedRegistry=true;}
            catch(System.Security.SecurityException){deniedRegistry=true;}
            Record("low-direct-read-denied",deniedRead);
            Record("low-direct-write-denied",deniedWrite);
            Record("low-direct-registry-denied",deniedRegistry);
            string link=Path.Combine(client,"linked-admin");
            using(Process mk=new(){StartInfo=new ProcessStartInfo("cmd.exe",
                "/c mklink /J \""+link+"\" \""+adminFolder+"\""){
                    RedirectStandardOutput=true,RedirectStandardError=true,
                    UseShellExecute=false,CreateNoWindow=true
                }})
            {
                mk.Start();string stdout=mk.StandardOutput.ReadToEnd()+mk.StandardError.ReadToEnd();mk.WaitForExit();
                if(mk.ExitCode!=0)throw new IOException("Junction setup failed: "+stdout);
            }
            Record("low-created-junction",Directory.Exists(link));
            File.WriteAllText(Path.Combine(client,"low-parent-ready"),Environment.ProcessId.ToString());
            DateTime until=DateTime.UtcNow.AddSeconds(55);
            while(!File.Exists(control) && DateTime.UtcNow<until)System.Threading.Thread.Sleep(125);
            if(!File.Exists(control))throw new TimeoutException("No admin test broker child announced");
            brokerPid=int.Parse(File.ReadAllText(control).Trim());
            string pipe=CreatePipeName(sdkAssembly,brokerPid.Value);
            string logPipe=CreatePipeName(sdkAssembly,brokerPid.Value,"log");
            request=new NamedPipeClientStream(".",pipe,PipeDirection.InOut);
            logs=new NamedPipeClientStream(".",logPipe,PipeDirection.InOut);
            Task a=Task.Run(()=>request.Connect(22000));
            Task b=Task.Run(()=>logs.Connect(22000));
            if(!Task.WaitAll([a,b],TimeSpan.FromSeconds(25)))
                throw new TimeoutException("Standard-user pipe connection timed out");
            request.ReadMode=PipeTransmissionMode.Message;
            logs.ReadMode=PipeTransmissionMode.Message;
            NamedPipeClientStream logStream=logs;
            Task logTask=Task.Run(()=>{
                try{byte[] temp=new byte[4096];while(logStream.IsConnected){if(logStream.Read(temp)<=0)break;}}
                catch(IOException){}catch(ObjectDisposedException){}
            });
            Record("real-low-sid-connected-broker",request.IsConnected&&logs.IsConnected);

            // #11: ordinary workload log path in low-user-owned directory.
            string logPath=Path.Combine(client,"low-real-request.log");
            uint invalidProduct=ErrorOf(Send(request,new {
                RequestType=301,ProductCode="{"+Guid.NewGuid().ToString().ToUpperInvariant()+"}",
                LogFile=logPath
            }));
            Record("cross-sid-broker-log-created",invalidProduct==1605&&File.Exists(logPath));
            env["unregisteredMsiResponse"]=invalidProduct;

            // #12: source under admin-only ACL, standard-user-created junction under client root.
            string manifest=Path.Combine(link,"fixture.msi.json");
            uint cacheError=ErrorOf(Send(request,new{
                RequestType=100,PackageId=cacheId,PackageVersion="1.0.0",ManifestPath=manifest
            }));
            string cacheFile=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "dotnet","workloads",cacheId,"1.0.0","protected-payload.dat");
            // The standard user cannot reliably determine protected-file existence:
            // File.Exists may return false solely because the ACL blocks enumeration.
            // Source disappearance is verified independently by the administrator controller.
            bool nowReadable=false;string? readHash=null;
            try{
                readHash=Sha256(cacheFile);
                nowReadable=true;
            }catch(Exception e){env["cacheReadFailure"]=e.GetType().Name;}
            Record("cross-sid-broker-cache-request-accepted",cacheError==0);
            Record("cross-sid-standard-user-read-cache",nowReadable&&readHash!=null);
            env["cacheRequestError"]=cacheError;
            env["protectedSourceRemovalVerifiedByLowUser"]=false;
            env["standardUserCachedSha256"]=readHash;
            env["cacheFile"]=cacheFile;

            // #13: isolated dependency-provider record, direct low-user registry creation denied.
            var add=Send(request,new{
                RequestType=200,ProviderKeyName=provider,Dependent="SyntheticLow."+
                    Guid.NewGuid().ToString("N")
            });
            uint regError=ErrorOf(add);
            env["providerAddError"]=regError;
            Record("cross-sid-admin-only-registry-write",regError==0&&deniedRegistry);
            var shutdown=Send(request,new{RequestType=0});
            env["brokerShutdownReplyError"]=ErrorOf(shutdown);
            env["brokerPid"]=brokerPid;
            status=checks.All(t=>(bool)t.GetType().GetProperty("passed")!.GetValue(t)!)
                ?"COMPLETED":"ASSERTION_FAILURE";
        }
        catch(Exception e){errors.Add(e.ToString());status="ERROR";Console.WriteLine("LOW_ERROR "+e);}
        finally
        {
            try{request?.Dispose();}catch{}
            try{logs?.Dispose();}catch{}
            File.WriteAllText(result,JsonSerializer.Serialize(new{
                timestampUtc=DateTimeOffset.UtcNow.ToString("O"),sdk,status,
                proofType="real low-user token connects to actual admin broker; synthetic parent established by admin test controller, not interactive UAC",
                environment=env,checks,errors
            },new JsonSerializerOptions{WriteIndented=true}));
            Console.WriteLine("LOW_STATUS="+status);
        }
        return status=="COMPLETED"?0:1;

        void Record(string id,bool passed)
        {
            checks.Add(new{id,passed});
            Console.WriteLine("CASE "+id+" "+(passed?"PASS":"FAIL"));
        }
    }
    static int Main(string[] args)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows-only test");
        return args[0] switch{
            "admin-launch"=>AdminLauncher(args),
            "low-parent"=>LowParent(args),
            _=>throw new ArgumentException("Requires admin-launch or low-parent")
        };
    }
}
