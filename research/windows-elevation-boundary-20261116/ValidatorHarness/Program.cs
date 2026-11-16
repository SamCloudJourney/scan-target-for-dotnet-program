// Isolated Windows workload validator regression: does not invoke the elevation broker.
// Intentionally writes only disposable objects inside RUNNER_TEMP, and records counterexamples.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;

internal static class Program
{
    private static readonly List<object> Cases = new();
    private static readonly List<string> Errors = new();
    private static int Failures;

    private static void Record(string id, bool pass, string observation, string limitation = "")
    {
        Cases.Add(new { id, pass, observation, limitation });
        if (!pass) Failures++;
        Console.WriteLine("TEST " + id + " " + (pass ? "PASS" : "FAIL") + " " + observation);
    }

    private static string InvokeLog(MethodInfo method, string path, string serverTemp)
        => (string)(method.Invoke(null, new object?[] { path, serverTemp })
            ?? throw new InvalidOperationException("Null log path response"));

    private static bool InvokeManifest(MethodInfo method, string path, string serverTemp)
        => (bool)(method.Invoke(null, new object?[] { path, serverTemp })
            ?? throw new InvalidOperationException("Null manifest response"));

    private static int RunProcess(string file, string arguments, out string stdout)
    {
        using Process proc = new()
        {
            StartInfo = new ProcessStartInfo(file, arguments)
            {
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true
            }
        };
        if (!proc.Start()) throw new Exception("Failed to start " + file);
        string output = proc.StandardOutput.ReadToEnd();
        string error = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        stdout = output + error;
        return proc.ExitCode;
    }

    private static void MakeJunction(string path, string dest)
    {
        var exit = RunProcess("cmd.exe", "/c mklink /J \"" + path + "\" \"" + dest + "\"", out string output);
        if (exit != 0 || !Directory.Exists(path))
            throw new InvalidOperationException("Junction creation failed: " + exit + " " + output);
    }

    private static void DeleteJunction(string path)
    {
        // Windows removes the reparse point itself, not the isolated target directory.
        Directory.Delete(path, recursive: false);
    }

    public static int Main(string[] args)
    {
        string sdk = args.Length > 0 ? args[0] : "11.0.100";
        string temp = Environment.GetEnvironmentVariable("RUNNER_TEMP") ?? Path.GetTempPath();
        string testRoot = Path.Combine(temp, "workload-boundary-" + Guid.NewGuid().ToString("N"));
        string reportPath = Path.Combine(temp, "windows-elevation-" + sdk + ".json");
        Dictionary<string, object?> env = new();
        string status = "RUNNING";
        try
        {
            Directory.CreateDirectory(testRoot);
            string client = Directory.CreateDirectory(Path.Combine(testRoot, "client")).FullName;
            string server = Directory.CreateDirectory(Path.Combine(testRoot, "server")).FullName;
            string outside = Directory.CreateDirectory(Path.Combine(testRoot, "isolated-outside")).FullName;
            string other = Directory.CreateDirectory(Path.Combine(testRoot, "other")).FullName;

            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);
            env["user"] = identity.Name;
            env["sid"] = identity.User?.Value;
            env["isAdministrator"] = principal.IsInRole(WindowsBuiltInRole.Administrator);
            env["osDescription"] = RuntimeInformation.OSDescription;
            env["runtime"] = RuntimeInformation.FrameworkDescription;
            env["uacEnableLUA"] = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", null);
            _ = RunProcess("whoami.exe", "/all", out string token);
            env["whoamiAll"] = token;
            string dotnetRoot = Environment.GetEnvironmentVariable("DOTNET_ROOT")
                ?? @"C:\Program Files\dotnet";
            string cliDll = Path.Combine(dotnetRoot, "sdk", sdk, "dotnet.dll");
            if (!File.Exists(cliDll)) throw new FileNotFoundException("SDK CLI assembly absent", cliDll);
            env["sdkCliAssembly"] = cliDll;
            env["sdkCliSha256"] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(cliDll)));
            _ = RunProcess("dotnet.exe", "--list-sdks", out string sdks);
            env["installedSdks"] = sdks;

            Assembly assembly = Assembly.LoadFrom(cliDll);
            Type utils = assembly.GetType("Microsoft.DotNet.Cli.Installer.Windows.WindowsUtils", throwOnError: true)!;
            Type installer = assembly.GetType("Microsoft.DotNet.Cli.Installer.Windows.InstallerBase", throwOnError: true)!;
            const BindingFlags PublicStatic = BindingFlags.Public | BindingFlags.Static;
            MethodInfo validateLog = utils.GetMethod("ValidateLogFilePath", PublicStatic)
                ?? throw new MissingMethodException("WindowsUtils.ValidateLogFilePath");
            MethodInfo validateManifest = utils.GetMethod("ValidateManifestPath", PublicStatic)
                ?? throw new MissingMethodException("WindowsUtils.ValidateManifestPath");
            PropertyInfo trustedRoot = installer.GetProperty("TrustedClientTempDirectory", PublicStatic)
                ?? throw new MissingMemberException("InstallerBase.TrustedClientTempDirectory");

            // #11: verify that normal client temp is accepted, unrelated temp is redirected,
            // then verify downstream behavior after the trusted root is deliberately broadened.
            trustedRoot.SetValue(null, client);
            string ordinary = Path.Combine(client, "normal.log");
            string acceptedNormal = InvokeLog(validateLog, ordinary, server);
            Record("11-normal-client-root", acceptedNormal == Path.GetFullPath(ordinary),
                "The SDK validator accepts a lexical child of the selected client root.");
            string unrelated = Path.Combine(outside, "unrelated.log");
            string fallback = InvokeLog(validateLog, unrelated, server);
            Record("11-outside-path-control", fallback == Path.Combine(server, "unrelated.log"),
                "An unrelated path is redirected under the test server root.");
            trustedRoot.SetValue(null, testRoot);
            string broadened = InvokeLog(validateLog, unrelated, server);
            Record("11-broad-trust-root", broadened == Path.GetFullPath(unrelated),
                "The SDK validator accepts a previously unrelated path when the trusted root is broadened.",
                "The harness sets the SDK static property, not a live elevated broker's --client-temp.");
            Record("11-broad-manifest", InvokeManifest(validateManifest, unrelated, server),
                "The SDK manifest validator accepts a child of the broadened root.",
                "No source manifest was opened or moved.");

            // #12: prove that an accepted lexical path can point outside the allowed client directory.
            trustedRoot.SetValue(null, client);
            string junction = Path.Combine(client, "junction");
            MakeJunction(junction, outside);
            string via = Path.Combine(junction, "followed.txt");
            string checkedPath = InvokeLog(validateLog, via, server);
            bool manifestResult = InvokeManifest(validateManifest, via, server);
            Record("12-junction-validation", checkedPath == Path.GetFullPath(via) && manifestResult,
                "Both SDK validators accept an intermediate NTFS junction under the client root.",
                "The SDK broker itself was not invoked.");
            string marker = "isolated-write-" + Guid.NewGuid().ToString("N");
            File.WriteAllText(checkedPath, marker);
            bool followed = File.Exists(Path.Combine(outside, "followed.txt"))
                && File.ReadAllText(Path.Combine(outside, "followed.txt")) == marker;
            Record("12-resolved-file-destination", followed,
                "Ordinary Windows file-open reaches the isolated outside directory via the accepted path.",
                "This file write was performed by the harness process under its own token, not by the broker.");
            env["junctionHasReparseAttribute"] = File.GetAttributes(junction).HasFlag(FileAttributes.ReparsePoint);
            env["junctionLinkTarget"] = new DirectoryInfo(junction).LinkTarget;

            // A deliberately staged change demonstrates non-atomic check/use, not a timing-dependent exploit.
            string swap = Path.Combine(client, "swap");
            MakeJunction(swap, outside);
            string requested = Path.Combine(swap, "swapped.txt");
            string before = InvokeLog(validateLog, requested, server);
            DeleteJunction(swap);
            MakeJunction(swap, other);
            File.WriteAllText(before, "staged-link-change");
            Record("12-staged-change-after-validation", File.Exists(Path.Combine(other, "swapped.txt")),
                "A post-validation junction change changes the destination of an ordinary file-open.",
                "Deterministic staged change; not evidence of a practical broker race.");

            // #13: minimal Windows Installer rejection control only. No products or providers are touched.
            string bogusProduct = "{" + Guid.NewGuid().ToString().ToUpperInvariant() + "}";
            int msiResult = RunProcess("msiexec.exe", "/x " + bogusProduct + " /qn /norestart", out string msiOutput);
            env["msiNonexistentProductExitCode"] = msiResult;
            env["msiNonexistentProductOutput"] = msiOutput;
            Record("13-msi-unregistered-negative", msiResult != 0,
                "Windows Installer rejects an unregistered random product GUID, exit code " + msiResult,
                "No request was sent to the workload broker; authorization of unrelated installed products remains untested.");

            status = Failures == 0 ? "COMPLETED" : "TEST_FAILURE";
        }
        catch (Exception ex)
        {
            status = "ERROR";
            Errors.Add(ex.ToString());
            Console.WriteLine("ERROR " + ex);
        }
        finally
        {
            try { if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true); }
            catch (Exception ex) { Errors.Add("Cleanup: " + ex); }
            var result = new
            {
                timestampUtc = DateTimeOffset.UtcNow.ToString("O"),
                sdkVersion = sdk, status,
                evidenceKind = "actual installed SDK path-validator reflection and isolated Windows filesystem",
                noBrokerOrUacInvocation = true,
                environment = env, cases = Cases, errors = Errors
            };
            File.WriteAllText(reportPath, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine("EVIDENCE_FILE=" + reportPath);
            Console.WriteLine("RUN_STATUS=" + status);
        }
        return status == "COMPLETED" ? 0 : 1;
    }
}
