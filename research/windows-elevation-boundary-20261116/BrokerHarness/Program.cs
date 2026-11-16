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

    private static void Hardlink(string link, string target)
    {
        (int code, string output) = Run("cmd.exe", "/c mklink /H \"" + link + "\" \"" + target + "\"");
        if (code != 0 || !File.Exists(link))
            throw new Exception("mklink/H failed for disposable fixture: " + output);
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
            return (object)new { error, hresult, description };
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

    private sealed record MsiFixture(string ProductCode, string InstalledMarker, string MsiPath);

    private static MsiFixture PrepareDisposableMsi(string root)
    {
        string productCode = Guid.NewGuid().ToString("B").ToUpperInvariant();
        string upgradeCode = Guid.NewGuid().ToString("B").ToUpperInvariant();
        string componentGuid = Guid.NewGuid().ToString("B").ToUpperInvariant();
        string buildDir = Directory.CreateDirectory(Path.Combine(root, "disposable-msi-build")).FullName;
        string destination = Directory.CreateDirectory(Path.Combine(root, "disposable-msi-install")).FullName;
        string source = Path.Combine(buildDir, "marker-input.txt");
        string marker = Path.Combine(destination, "marker-input.txt");
        string wxs = Path.Combine(buildDir, "fixture.wxs");
        string obj = Path.Combine(buildDir, "fixture.wixobj");
        string msi = Path.Combine(buildDir, "fixture.msi");
        File.WriteAllText(source, "Owned disposable .NET SDK broker test " + productCode);

        string escapedSource = System.Security.SecurityElement.Escape(source) ?? source;
        string xml = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<Wix xmlns=""http://schemas.microsoft.com/wix/2006/wi"">
  <Product Id=""{productCode}"" Name=""Isolated Windows Broker Regression Fixture"" Language=""1033""
           Version=""1.0.0.0"" Manufacturer=""AuthorizedRegressionTests"" UpgradeCode=""{upgradeCode}"">
    <Package InstallerVersion=""200"" Compressed=""yes"" InstallScope=""perMachine"" />
    <MediaTemplate EmbedCab=""yes"" />
    <Directory Id=""TARGETDIR"" Name=""SourceDir"">
      <Directory Id=""ProgramFilesFolder"">
        <Directory Id=""INSTALLDIR"" Name=""DisposableBrokerFixture"">
          <Component Id=""FixtureFileComponent"" Guid=""{componentGuid}"">
            <File Id=""FixtureMarker"" Name=""marker-input.txt"" Source=""{escapedSource}"" KeyPath=""yes"" />
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id=""Complete"" Title=""Disposable fixture"" Level=""1"">
      <ComponentRef Id=""FixtureFileComponent"" />
    </Feature>
  </Product>
</Wix>";
        File.WriteAllText(wxs, xml);

        var dirs = new List<string>();
        string wixEnv = Environment.GetEnvironmentVariable("WIX") ?? "";
        if (!string.IsNullOrWhiteSpace(wixEnv))
        {
            dirs.Add(wixEnv);
            dirs.Add(Path.Combine(wixEnv, "bin"));
        }
        dirs.Add(@"C:\Program Files (x86)\WiX Toolset v3.14\bin");
        dirs.Add(@"C:\Program Files (x86)\WiX Toolset v3.11\bin");
        string? wixBin = dirs.FirstOrDefault(d => File.Exists(Path.Combine(d, "candle.exe"))
            && File.Exists(Path.Combine(d, "light.exe")));
        if (wixBin == null) throw new FileNotFoundException("Windows runner lacks WiX candle.exe + light.exe");

        (int candleExit, string candleOutput) = Run(Path.Combine(wixBin, "candle.exe"),
            "-nologo -out \"" + obj + "\" \"" + wxs + "\"");
        if (candleExit != 0) throw new InvalidOperationException("WiX compile: " + candleExit + " " + candleOutput);
        (int lightExit, string lightOutput) = Run(Path.Combine(wixBin, "light.exe"),
            "-nologo -out \"" + msi + "\" \"" + obj + "\"");
        if (lightExit != 0) throw new InvalidOperationException("WiX link: " + lightExit + " " + lightOutput);

        // Installation target is always a new, empty scratch directory in GITHUB_WORKSPACE.
        string installLog = Path.Combine(buildDir, "install.log");
        (int installExit, string installOutput) = Run("msiexec.exe",
            "/i \"" + msi + "\" /qn /norestart ALLUSERS=1 INSTALLDIR=\"" + destination
            + "\" /L*v \"" + installLog + "\"");
        if (installExit != 0 || !File.Exists(marker))
            throw new InvalidOperationException("Disposable MSI installation failed, code "
                + installExit + ", markerPresent=" + File.Exists(marker) + " " + installOutput);
        return new MsiFixture(productCode, marker, msi);
    }

    private static void Session(string sdkVersion, string dotnetExe, Assembly sdk, string cwd,
        string trustedRoot, string label, string clientDir, string outsideDir, MsiFixture? fixture)
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

            // Additional negative-control tests. Never install or execute any untrusted MSI.
            if (label == "narrow")
            {
                string unsigned = Path.Combine(clientDir,"unsigned-not-msi.msi");
                string attemptedLog = Path.Combine(clientDir,"invalid-install-negative.log");
                File.WriteAllText(unsigned,"FIXTURE-NOT-AN-MSI");
                object installRejected = ReadResponse(request, JsonSerializer.Serialize(new {
                    RequestType = 300, PackagePath = unsigned, LogFile = attemptedLog
                }));
                uint installError = ErrorOf(installRejected);
                Sessions.Add(new {sdkVersion,label,brokerPID=broker.Id,brokerIdentity,
                    requestType="InstallMsi",fixture="unsigned scratch file outside protected workload package cache",
                    error=installError,brokerReply=installRejected});
                Check("13-broker-outside-cache-install-blocked",installError == 1620 && !File.Exists(attemptedLog) && File.Exists(unsigned),
                    "Live SDK broker rejected a client-selected unsigned install package outside the secure workload cache before MSI logging or execution.",
                    "Only a negative control; does not weaken the observed unrelated-product UninstallMsi and RepairMsi authorization gap.");

                object malformedProvider = ReadResponse(request,JsonSerializer.Serialize(new {
                    RequestType=200,ProviderKeyName="",Dependent="IsolatedNegative."+Guid.NewGuid().ToString("N")
                }));
                int hr = (int)(malformedProvider.GetType().GetProperty("hresult")?.GetValue(malformedProvider) ?? int.MinValue);
                Sessions.Add(new {sdkVersion,label,brokerPID=broker.Id,brokerIdentity,
                    requestType="AddDependent",fixture="empty invalid provider name",hresult=hr,brokerReply=malformedProvider});
                Check("13-broker-empty-provider-denied",hr < 0,
                    "Live SDK broker rejected empty provider-key identifier with negative HRESULT.",
                    "Different from an unrelated but syntactically valid provider; no production record modified.");
            }

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
                string final = Path.Combine(outsideDir, "junction.log");
                string junctionSentinel = "JUNCTION-ORIGINAL-DISPOSABLE-" + Guid.NewGuid().ToString("N");
                File.WriteAllText(final, junctionSentinel);
                uint err2 = Uninstall(viaJunction);
                bool wasOverwritten = File.Exists(final) && File.ReadAllText(final) != junctionSentinel;
                Check("12-broker-junction-truncates-existing", wasOverwritten && err2 == 1605,
                    "Real SDK broker opened and altered an existing isolated file through an intermediate junction.",
                    "The source and destination are both disposable, already-admin-owned scratch data; no UAC transition.");
                Check("12-broker-junction-file-create", File.Exists(final) && err2 == 1605,
                    "Real SDK broker File.Create followed an NTFS junction outside trusted client root.",
                    "Both broker and client had the same already-elevated runner token; no standard-user boundary crossed.");
                // Distinguish directory junctions from filesystem hard links: same NTFS file identity,
                // an in-root name, and an out-of-root scratch destination.
                string hardlinkFinal = Path.Combine(outsideDir, "hardlink-target.log");
                string hardlinkSentinel = "HARDLINK-ORIGINAL-DISPOSABLE-" + Guid.NewGuid().ToString("N");
                File.WriteAllText(hardlinkFinal, hardlinkSentinel);
                string hardlinkAlias = Path.Combine(clientDir, "hardlink-alias.log");
                Hardlink(hardlinkAlias, hardlinkFinal);
                uint errHardlink = Uninstall(hardlinkAlias);
                bool hardlinkOverwritten = File.Exists(hardlinkFinal) && File.ReadAllText(hardlinkFinal) != hardlinkSentinel;
                Check("12-broker-hardlink-truncates-existing", errHardlink == 1605 && hardlinkOverwritten,
                    "Real SDK broker followed an in-root hard link and changed the same out-of-root scratch file object.",
                    "Hard links to protected files may be restricted by Windows ACLs; this does not prove an unprivileged attacker can create one.");

                // Machine-wide installer dependency record fixture. Never name a genuine product/provider.
                string provider = "IsolatedBrokerFixture." + Guid.NewGuid().ToString("N");
                string dependent = "IsolatedDependent." + Guid.NewGuid().ToString("N");
                string keyPath = @"SOFTWARE\Classes\Installer\Dependencies\" + provider;
                if (Registry.LocalMachine.OpenSubKey(keyPath) != null)
                    throw new InvalidOperationException("Refusing to alter pre-existing provider key.");
                try
                {
                    object addReply = ReadResponse(request,
                        JsonSerializer.Serialize(new { RequestType = 200, ProviderKeyName = provider, Dependent = dependent }));
                    uint addError = ErrorOf(addReply);
                    using RegistryKey? created = Registry.LocalMachine.OpenSubKey(keyPath + @"\Dependents\" + dependent);
                    bool createdMarker = created != null;
                    Sessions.Add(new { sdkVersion, label, brokerPID = broker.Id, brokerIdentity,
                        requestType = "AddDependent", providerFixture = provider, dependentFixture = dependent,
                        registryKeyCreated = createdMarker, error = addError, brokerReply = addReply });
                    Check("13-broker-disposable-provider-add", addError == 0 && createdMarker,
                        "Live SDK broker created an isolated HKLM installer-dependency record using client-selected identifiers.",
                        "Unique fixture only, not a genuine third-party provider; same pre-authorized administrator token.");
                    object removeReply = ReadResponse(request,
                        JsonSerializer.Serialize(new { RequestType = 201, ProviderKeyName = provider, Dependent = dependent }));
                    uint removeError = ErrorOf(removeReply);
                    using RegistryKey? removed = Registry.LocalMachine.OpenSubKey(keyPath + @"\Dependents\" + dependent);
                    bool removedMarker = removed == null;
                    Sessions.Add(new { sdkVersion, label, brokerPID = broker.Id, brokerIdentity,
                        requestType = "RemoveDependent", providerFixture = provider, dependentFixture = dependent,
                        registryRecordRemoved = removedMarker, error = removeError, brokerReply = removeReply });
                    Check("13-broker-disposable-provider-remove", removeError == 0 && removedMarker,
                        "Live SDK broker removed the isolated provider's dependent record by caller request.",
                        "No production dependency or installed software changed.");
                }
                finally
                {
                    // SDK RemoveDependent deliberately retains provider root. Remove only our generated fixture.
                    using RegistryKey? rootKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Classes\Installer\Dependencies", writable: true);
                    rootKey?.DeleteSubKeyTree(provider, throwOnMissingSubKey: false);
                }

                string repairLog = Path.Combine(clientDir, "repair-negative.log");
                uint err3 = Repair(repairLog);
                Check("13-broker-unregistered-repair", File.Exists(repairLog) && err3 == 1605,
                    "Broker accepted serialized RepairMsi for arbitrary GUID, created log and forwarded to Windows Installer, which rejected unknown product.",
                    "No existing product modified; no transaction-specific authorization proved.");
                if (fixture != null)
                {
                    // Repair an unrelated disposable installed MSI after deliberately deleting only its marker.
                    File.Delete(fixture.InstalledMarker);
                    string repairFixtureLog = Path.Combine(clientDir, "disposable-repair.log");
                    object repairFixtureReply = ReadResponse(request, JsonSerializer.Serialize(new
                    {
                        RequestType = 302, ProductCode = fixture.ProductCode, LogFile = repairFixtureLog
                    }));
                    uint repairFixtureError = ErrorOf(repairFixtureReply);
                    bool repairedMarker = File.Exists(fixture.InstalledMarker);
                    Sessions.Add(new { sdkVersion, label, brokerPID = broker.Id, brokerIdentity,
                        requestType = "RepairMsi", productFixture = "self-authored unrelated installed WiX MSI",
                        error = repairFixtureError, fileRestored = repairedMarker, logFile = repairFixtureLog,
                        brokerReply = repairFixtureReply });
                    Check("13-broker-disposable-unrelated-repair",
                        (repairFixtureError == 0 || repairFixtureError == 3010) && repairedMarker && File.Exists(repairFixtureLog),
                        "Live workload broker repaired unrelated installed disposable MSI, response " +
                        repairFixtureError + ", restoredMarker=" + repairedMarker,
                        "Both processes run as an existing administrator; no standard-user-to-admin exploit proved.");
                    string fixtureLog = Path.Combine(clientDir, "disposable-uninstall.log");
                    string requestJson = JsonSerializer.Serialize(new
                    {
                        RequestType = 301, ProductCode = fixture.ProductCode, LogFile = fixtureLog
                    });
                    object answer = ReadResponse(request, requestJson);
                    uint fixtureExit = ErrorOf(answer);
                    bool removed = !File.Exists(fixture.InstalledMarker);
                    Sessions.Add(new { sdkVersion, label, brokerPID=broker.Id, brokerIdentity,
                        requestType="UninstallMsi", productFixture="isolated self-authored installed WiX MSI",
                        productCode=fixture.ProductCode, logFile=fixtureLog,
                        error=fixtureExit, fileRemoved=removed, brokerReply=answer });
                    Check("13-broker-disposable-unrelated-product",
                        (fixtureExit == 0 || fixtureExit == 3010) && removed && File.Exists(fixtureLog),
                        "Genuine elevated workload broker attempted unrelated installed disposable MSI; error "
                            + fixtureExit + ", markerRemoved=" + removed,
                        "Admin runner deliberately authorized its own broker. This does not prove UAC EoP.");
                }
            }
            else if (label == "cross-junction" || label == "cross-broad")
            {
                // Controlled boundary experiment: the *real* SDK broker is still started
                // by an already-elevated runneradmin parent. The separately-created standard
                // user owns clientDir but is NOT the connecting IPC client. No UAC transition.
                string protectedCanary = Path.Combine(outsideDir,"canary.log");
                string markerBefore = File.ReadAllText(protectedCanary);
                if (label == "cross-junction")
                {
                    uint directError = Uninstall(protectedCanary);
                    bool directRemained = File.ReadAllText(protectedCanary) == markerBefore;
                    Check("11-standard-owned-client-direct-protected-control",
                        directError == 1605 && directRemained,
                        "With only the standard-user-owned client root trusted, the live broker did not alter the admin-only canary through its direct path.",
                        "Broker client is pre-authorized admin test harness, not the standard-user process.");

                    string viaJunction = Path.Combine(clientDir, "junction", "canary.log");
                    uint indirectError = Uninstall(viaJunction);
                    bool didChange = File.ReadAllText(protectedCanary) != markerBefore;
                    Check("12-standard-created-junction-admin-canary-modified",
                        indirectError == 1605 && didChange,
                        "The real SDK broker modified a disposable admin-only canary using a junction created by a separate standard user.",
                        "No UAC approval or standard-user IPC connection occurred; this tests distinct filesystem principals only.");

                    string provider = Environment.GetEnvironmentVariable("BROKER_CROSS_PROVIDER")
                        ?? throw new InvalidOperationException("Missing BROKER_CROSS_PROVIDER fixture name");
                    string dependent = "FixtureDependent." + Guid.NewGuid().ToString("N");
                    string keyPath = @"SOFTWARE\Classes\Installer\Dependencies\" + provider;
                    using (RegistryKey? existing = Registry.LocalMachine.OpenSubKey(keyPath))
                        if (existing != null) throw new IOException("Refusing existing HKLM provider");
                    try
                    {
                        object response = ReadResponse(request, JsonSerializer.Serialize(new {
                            RequestType=200,ProviderKeyName=provider,Dependent=dependent
                        }));
                        string dependentPath=keyPath+@"\Dependents\"+dependent;
                        using RegistryKey? created=Registry.LocalMachine.OpenSubKey(dependentPath);
                        bool registered=created!=null;
                        Check("13-admin-broker-changes-standard-denied-HKLM",
                            ErrorOf(response)==0 && registered,
                            "Actual elevated broker created a uniquely named HKLM installer dependency that the standard-user probe could not create directly.",
                            "Pre-approved administrator client retained access; no separate-user IPC was demonstrated.");
                        object deleted=ReadResponse(request, JsonSerializer.Serialize(new {
                            RequestType=201,ProviderKeyName=provider,Dependent=dependent
                        }));
                        using RegistryKey? after=Registry.LocalMachine.OpenSubKey(dependentPath);
                        Check("13-disposable-provider-cleanup",ErrorOf(deleted)==0 && after==null,
                            "Broker removed only the generated dependent.",
                            "Owner additionally removes fixture provider root.");
                    }
                    finally
                    {
                        using RegistryKey? dependencyRoot=Registry.LocalMachine.OpenSubKey(
                            @"SOFTWARE\Classes\Installer\Dependencies", writable:true);
                        dependencyRoot?.DeleteSubKeyTree(provider,throwOnMissingSubKey:false);
                    }
                }
                else
                {
                    uint broadError=Uninstall(protectedCanary);
                    bool changed=File.ReadAllText(protectedCanary)!=markerBefore;
                    Check("11-overbroad-root-admin-only-canary-modified",broadError==1605 && changed,
                        "Actual broker changed the same administrator-only scratch canary after trust root was broadened to its parent.",
                        "An already-elevated admin process supplied the overbroad root. Not proof of unauthorized elevation.");
                }
            }
            else
            {
                string broadened = Path.Combine(outsideDir, "broad-trust-root.log");
                string original = "BROAD-ROOT-ORIGINAL-DISPOSABLE-" + Guid.NewGuid().ToString("N");
                File.WriteAllText(broadened, original);
                uint err = Uninstall(broadened);
                bool changed = File.Exists(broadened) && File.ReadAllText(broadened) != original;
                Check("11-broker-broad-truncates-existing", changed && err == 1605,
                    "Real broker modified a pre-existing isolated file outside the ordinary client root after selecting a broad trust root.",
                    "The root was supplied by an already-elevated parent; no UAC crossing.");
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
        MsiFixture? fixture = null;
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
                try
                {
                    fixture = PrepareDisposableMsi(root);
                    Check("13-disposable-product-setup", File.Exists(fixture.InstalledMarker),
                        "Installed a unique, isolated WiX MSI fixture in workspace scratch storage.",
                        "The installer runs with already-elevated runneradmin token; only generated fixture is modified.");
                    env["disposableFixtureProductCode"] = fixture.ProductCode;
                    env["disposableFixtureMsiSha256"] = Convert.ToHexString(
                        SHA256.HashData(File.ReadAllBytes(fixture.MsiPath)));
                }
                catch (Exception e)
                {
                    Errors.Add("Disposable MSI setup: " + e);
                    Check("13-disposable-product-setup", false,
                        "Fixture setup failed; no installed-product authorization conclusion: " + e.Message,
                        "A harness/fixture failure is not evidence of broker authorization.");
                }
                Session(sdkVersion, dotnetExe, sdk, cwd, client, "narrow", client, outside, fixture);
                Session(sdkVersion, dotnetExe, sdk, cwd, root, "broad", client, outside, null);
                string? crossClient = Environment.GetEnvironmentVariable("BROKER_CROSS_CLIENT");
                string? crossProtected = Environment.GetEnvironmentVariable("BROKER_CROSS_PROTECTED");
                if (!string.IsNullOrWhiteSpace(crossClient) && !string.IsNullOrWhiteSpace(crossProtected))
                {
                    if (!Directory.Exists(crossClient) || !Directory.Exists(crossProtected))
                        throw new DirectoryNotFoundException("Cross-account test fixture missing");
                    env["crossClientRoot"] = crossClient;
                    env["crossAdminOnlyDirectory"] = crossProtected;
                    Session(sdkVersion, dotnetExe, sdk, cwd, crossClient, "cross-junction", crossClient, crossProtected, null);
                    Session(sdkVersion, dotnetExe, sdk, cwd, Path.GetDirectoryName(crossClient)!, "cross-broad", crossClient, crossProtected, null);
                }
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
                if (fixture != null)
                {
                    // Idempotent cleanup on the isolated fixture ONLY, never other installed products.
                    var cleanup = Run("msiexec.exe", "/x " + fixture.ProductCode + " /qn /norestart");
                    env["disposableFixtureCleanupExitCode"] = cleanup.code;
                }
            }
            catch (Exception e) { Errors.Add("Disposable MSI cleanup: " + e); }
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
