// Isolated Microsoft .NET SDK broker *process* test on a disposable GitHub-hosted Windows VM.
// No UAC bypass: runneradmin launches a child broker with UseShellExecute=false under the same token.
// No genuine MSI products, providers, Windows directories, system files or customer data are modified.
// The only broker-owned writes are log files in a random, temporary workspace fixture.

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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

internal static class Program
{
    private static readonly List<object> Cases = new();
    private static readonly List<string> Errors = new();
    private static readonly List<object> Sessions = new();
    private static int Failures;

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out SafeAccessTokenHandle tokenHandle);

    private static void Check(string id, bool passed, string result, string limitation)
    {
        Cases.Add(new { id, passed, result, limitation });
        if (!passed) Failures++;
        Console.WriteLine("CASE " + id + " " + (passed ? "PASS " : "FAIL ") + result);
    }

    private static (int code, string output) Run(string command, string arguments)
    {
        using Process p = new()
        {
            StartInfo = new ProcessStartInfo(command, arguments)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            }
        };
        p.Start();
        string stdout = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, stdout);
    }

    private static void Junction(string path, string destination)
    {
        (int code, string output) = Run("cmd.exe", "/c mklink /J \"" + path + "\" \"" + destination + "\"");
        if (code != 0 || !Directory.Exists(path)) throw new Exception("mklink/J failed: " + output);
    }

    private static string PipeName(Assembly sdk, int pid, string[] additionalValues)
    {
        Type utils = sdk.GetType("Microsoft.DotNet.Cli.Installer.Windows.WindowsUtils", throwOnError:true)!;
        MethodInfo name = utils.GetMethod("CreatePipeName", BindingFlags.Static | BindingFlags.Public)
            ?? throw new Exception("SDK WindowsUtils.CreatePipeName not found");
        return (string)name.Invoke(null, new object[] { pid, additionalValues })!;
    }

    private static object ReadResponse(NamedPipeClientStream pipe, string message)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(message);
        byte[] packet = new byte[bytes.Length + 4];
        Buffer.BlockCopy(BitConverter.GetBytes(bytes.Length), 0, packet, 0, 4);
        Buffer.BlockCopy(bytes, 0, packet, 4, bytes.Length);
        pipe.Write(packet);
        pipe.Flush();
        pipe.WaitForPipeDrain();

        // Always cap a hung or unhealthy broker's time in a disposable runner.
        Task<object> task = Task.Run(() =>
        {
            byte[] buffer = new byte[4096];
            int n = pipe.Read(buffer);
            if (n < 4) throw new EndOfStreamException("Broker closed before response");
            int length = BitConverter.ToInt32(buffer, 0);
            if (length < 0 || length > n - 4 || length > 3500)
                throw new InvalidDataException("Malformed broker response; payload=" + n + " length=" + length);
            using JsonDocument document = JsonDocument.Parse(buffer.AsMemory(4, length));
            var root = document.RootElement;
            uint error = root.TryGetProperty("Error", out var e) ? e.GetUInt32() : uint.MaxValue;
            int hresult = root.TryGetProperty("HResult", out var hr) ? hr.GetInt32() : int.MinValue;
            string? description = root.TryGetProperty("Message", out var m) ? m.ToString() : null;
            return new { error, hresult, description };
        });
        if (!task.Wait(TimeSpan.FromSeconds(30)))
            throw new TimeoutException("Actual SDK broker did not answer IPC within 30 seconds");
        return task.GetAwaiter().GetResult();
    }

    private static uint ErrorOf(object result)
    {
        return (uint)(result.GetType().GetProperty("error")?.GetValue(result) ?? uint.MaxValue);
    }

    private static string? BrokerUser(Process broker)
    {
        try
        {
            if (!OpenProcessToken(broker.Handle, 0x0008, out SafeAccessTokenHandle handle))
                return "OpenProcessToken failed: " + Marshal.GetLastWin32Error();
            using (handle)
            using (WindowsIdentity identity = new(handle.DangerousGetHandle()))
                return identity.Name + " " + identity.User?.Value;
        }
        catch (Exception e)
        {
            return e.GetType().Name + ": " + e.Message;
        }
    }

    private static void Session(string sdkVersion, string dotnetExe, Assembly sdk, string cwd,
        string trustedRoot, string label, string clientDir, string outsideDir)
    {
        using Process broker = new()
        {
            StartInfo = new ProcessStartInfo(dotnetExe)
            {
                UseShellExecute = false, CreateNoWindow = true,
                WorkingDirectory = cwd,
                RedirectStandardOutput = true, RedirectStandardError = true
            },
            EnableRaisingEvents = true
        };
        broker.StartInfo.ArgumentList.Add("workload");
        broker.StartInfo.ArgumentList.Add("elevate");
        broker.StartInfo.ArgumentList.Add("--client-temp");
        broker.StartInfo.ArgumentList.Add(trustedRoot);
        broker.Start();
        Task<string> stderrTask = broker.StandardError.ReadToEndAsync();
        Task<string> stdoutTask = broker.StandardOutput.ReadToEndAsync();
        string? brokerIdentity = BrokerUser(broker);
        var receivedLogs = new List<string>();
        string brokerName = PipeName(sdk, broker.Id, Array.Empty<string>());
        string logName = PipeName(sdk, broker.Id, new[] { "log" });

        using NamedPipeClientStream request = new(".", brokerName, PipeDirection.InOut);
        using NamedPipeClientStream logs = new(".", logName, PipeDirection.InOut);
        try
        {
            // WaitForConnection is performed by the *real* SDK broker. No parent/SID checks are bypassed.
            Task a = Task.Run(() => request.Connect(15000));
            Task b = Task.Run(() => logs.Connect(15000));
            if (!Task.WaitAll(new[] { a, b }, TimeSpan.FromSeconds(20)))
                throw new TimeoutException("The SDK broker did not create both named pipes");
            request.ReadMode = PipeTransmissionMode.Message;
            logs.ReadMode = PipeTransmissionMode.Message;
            Task readLog = Task.Run(() =>
            {
                try
                {
                    byte[] chunk = new byte[4096];
                    while (logs.IsConnected)
                    {
                        int n = logs.Read(chunk);
                        if (n <= 0) break;
                        if (n > 4)
                        {
                            int len = BitConverter.ToInt32(chunk, 0);
                            if (len >= 0 && len <= n - 4)
                                lock (receivedLogs)
                                {
                                    if (receivedLogs.Count < 30)
                                        receivedLogs.Add(Encoding.UTF8.GetString(chunk, 4, len));
                                }
                        }
                    }
                }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
            });

            Check("broker-"+label+"-connected", broker.HasExited == false,
                "Connected to real SDK workload-elevation broker process " + broker.Id,
                "Parent and broker share runneradmin token. This is not a UAC EoP test.");

            string randomProduct = "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}";
            uint Uninstall(string path)
            {
                string req = JsonSerializer.Serialize(new { RequestType = 301, ProductCode = randomProduct, LogFile = path });
                object reply = ReadResponse(request, req);
                uint error = ErrorOf(reply);
                Sessions.Add(new { sdkVersion, label, brokerPID = broker.Id, brokerIdentity, requestType = "UninstallMsi",
                    productFixture = "random unregistered GUID", logFile = path, error,
                    brokerReply = reply });
                return error;
            }

            uint Repair(string path)
            {
                string req = JsonSerializer.Serialize(new { RequestType = 302, ProductCode = randomProduct, LogFile = path });
                object reply = ReadResponse(request, req);
                uint error = ErrorOf(reply);
                Sessions.Add(new { sdkVersion, label, brokerPID = broker.Id, brokerIdentity, requestType = "RepairMsi",
                    productFixture = "random unregistered GUID", logFile = path, error,
                    brokerReply = reply });
                return error;
            }

            if (label == "narrow")
            {
                string denied = Path.Combine(outsideDir, "outside-control.log");
                uint err0 = Uninstall(denied);
                Check("11-broker-outside-control", !File.Exists(denied) && err0 == 1605,
                    "Live broker rejected direct outside-root log destination; uninstall returned ERROR_UNKNOWN_PRODUCT 1605.",
                    "Only one administrator token; fallback might be server temp.");
                string normal = Path.Combine(clientDir, "inside.log");
                uint err1 = Uninstall(normal);
                Check("11-broker-normal-client", File.Exists(normal) && err1 == 1605,
                    "Live broker created log in explicitly selected client root; MSI nonexistent product rejected.",
                    "Not a protected destination or EoP.");
                string viaJunction = Path.Combine(clientDir, "junction", "junction.log");
                uint err2 = Uninstall(viaJunction);
                string final = Path.Combine(outsideDir, "junction.log");
                Check("12-broker-junction-file-create", File.Exists(final) && err2 == 1605,
                    "Real SDK broker File.Create followed an NTFS junction outside trusted client root.",
                    "Both broker and client had the same already-elevated runner token; no standard-user boundary crossed.");
                string repairLog = Path.Combine(clientDir, "repair-negative.log");
                uint err3 = Repair(repairLog);
                Check("13-broker-unregistered-repair", File.Exists(repairLog) && err3 == 1605,
                    "Broker accepted serialized RepairMsi for arbitrary GUID, created log and forwarded to Windows Installer, which rejected unknown product.",
                    "No existing product modified; no transaction-specific authorization proved.");
            }
            else
            {
                string broadened = Path.Combine(outsideDir, "broad-trust-root.log");
                uint err = Uninstall(broadened);
                Check("11-broker-broad-client-root", File.Exists(broadened) && err == 1605,
                    "Real broker created log outside narrow client directory after explicit overbroad --client-temp.",
                    "Broker was directly started by already-elevated test process. No UAC approval or EoP.");
            }

            var shutdown = ReadResponse(request, JsonSerializer.Serialize(new { RequestType = 0 }));
            if (!broker.WaitForExit(12000)) throw new TimeoutException("Broker ignored Shutdown request");
            Check("broker-"+label+"-shutdown", broker.ExitCode == 0,
                "Real broker handled shutdown and exited with code " + broker.ExitCode,
                "Runner service account had prior administrator authority.");
            lock (receivedLogs)
                Sessions.Add(new { sdkVersion, label, brokerPID = broker.Id, brokerIdentity,
                    sdkHost=dotnetExe, clientTemp=trustedRoot,
                    logMessages = receivedLogs.Take(12).ToArray() });
        }
        catch (Exception e)
        {
            Errors.Add("Broker session " + label + ": " + e);
            Console.WriteLine("BROKER_ERROR " + label + " " + e);
            if (!broker.HasExited) broker.Kill(entireProcessTree:true);
            try { broker.WaitForExit(5000); } catch { }
            string stderr = stderrTask.IsCompletedSuccessfully ? stderrTask.Result : "";
            string stdout = stdoutTask.IsCompletedSuccessfully ? stdoutTask.Result : "";
            Errors.Add("Broker startup stdout=" + stdout.Substring(0, Math.Min(stdout.Length, 4000))
                + " stderr=" + stderr.Substring(0, Math.Min(stderr.Length, 4000)));
            Failures++;
        }
        finally
        {
            if (!broker.HasExited)
            {
                broker.Kill(entireProcessTree:true);
                try { broker.WaitForExit(5000); } catch { }
            }
        }
    }

    public static int Main(string[] args)
    {
        string sdkVersion = args.Length > 0 ? args[0] : "11.0.100";
        string workspace = Environment.GetEnvironmentVariable("GITHUB_WORKSPACE") ?? Directory.GetCurrentDirectory();
        string runnerTemp = Environment.GetEnvironmentVariable("RUNNER_TEMP") ?? Path.GetTempPath();
        string root = Path.Combine(workspace, ".disposable-elevation-fixture-" + Guid.NewGuid().ToString("N"));
        string reportPath = Path.Combine(runnerTemp, "broker-process-" + sdkVersion + ".json");
        var env = new Dictionary<string, object?>();
        string status = "RUNNING";
        try
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows VM required");
            string ownTemp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
            if (Path.GetFullPath(root).StartsWith(ownTemp + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
                throw new Exception("Isolation error: scratch root unexpectedly under server's default temp");

            Directory.CreateDirectory(root);
            string client = Directory.CreateDirectory(Path.Combine(root, "client")).FullName;
            string outside = Directory.CreateDirectory(Path.Combine(root, "outside")).FullName;
            string cwd = Directory.CreateDirectory(Path.Combine(root, "sdk-pinned")).FullName;
            File.WriteAllText(Path.Combine(cwd, "global.json"), JsonSerializer.Serialize(
                new { sdk = new { version = sdkVersion, rollForward = "disable" } }));
            Junction(Path.Combine(client, "junction"), outside);

            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            env["runnerUser"] = identity.Name;
            env["runnerSid"] = identity.User?.Value;
            env["runnerAdministrator"] = principal.IsInRole(WindowsBuiltInRole.Administrator);
            env["os"] = RuntimeInformation.OSDescription;
            env["framework"] = RuntimeInformation.FrameworkDescription;
            env["uacEnableLUA"] = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA", null);
            env["whoamiGroups"] = Run("whoami.exe", "/groups").output;

            string dotnetExe = Environment.ProcessPath!;
            if (!string.Equals(Path.GetFileName(dotnetExe), "dotnet.exe", StringComparison.OrdinalIgnoreCase))
                throw new Exception("Harness must be started via dotnet BrokerHarness.dll to match SDK parent-process rule");
            string dotnetRoot = Path.GetDirectoryName(dotnetExe)!;
            string dll = Path.Combine(dotnetRoot, "sdk", sdkVersion, "dotnet.dll");
            env["dotnetExe"] = dotnetExe;
            env["sdkCliAssembly"] = dll;
            env["sdkCliSha256"] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(dll)));
            Assembly sdk = Assembly.LoadFrom(dll);

            // SDK broker explicitly stops Windows Update service during Run; avoid altering an active service.
            string query = Run("sc.exe", "query wuauserv").output;
            env["wuauservBefore"] = query;
            if (query.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
            {
                status = "SKIPPED_SERVICE_RUNNING";
                Console.WriteLine("SKIP: Windows Update service running; no real broker started");
            }
            else
            {
                Session(sdkVersion, dotnetExe, sdk, cwd, client, "narrow", client, outside);
                Session(sdkVersion, dotnetExe, sdk, cwd, root, "broad", client, outside);
                status = Failures == 0 ? "COMPLETED" : "TEST_FAILURE";
                env["wuauservAfter"] = Run("sc.exe", "query wuauserv").output;
            }
        }
        catch (Exception e)
        {
            status = "ERROR";
            Errors.Add(e.ToString());
            Console.WriteLine("ERROR " + e);
        }
        finally
        {
            try
            {
                string junction = Path.Combine(root, "client", "junction");
                if (Directory.Exists(junction)) Directory.Delete(junction, recursive:false);
                if (Directory.Exists(root)) Directory.Delete(root, recursive:true);
            }
            catch (Exception e) { Errors.Add("Cleanup: " + e); }
            var record = new
            {
                timestampUtc = DateTimeOffset.UtcNow.ToString("O"),
                sdkVersion, status, runnerEvidence = "real Microsoft .NET workload broker, elevated *before* launch",
                noUacTransition = true, environment=env, cases=Cases, brokerRequests=Sessions, errors=Errors
            };
            File.WriteAllText(reportPath, JsonSerializer.Serialize(record, new JsonSerializerOptions{WriteIndented=true}));
            Console.WriteLine("EVIDENCE_FILE=" + reportPath);
            Console.WriteLine("RUN_STATUS=" + status);
        }
        return status == "COMPLETED" || status == "SKIPPED_SERVICE_RUNNING" ? 0 : 1;
    }
}
