// Disposable downstream tests of the ACTUAL installed SDK MsiPackageCache.
// No real MSI is installed, no live broker is launched, no production ProgramData paths
// are modified. Custom cache root, original files and junction targets are all under
// a random GITHUB_WORKSPACE scratch folder. These tests cannot demonstrate UAC/EoP.
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

static class Program
{
    static readonly List<object> Tests = [];
    static readonly List<string> Errors = [];
    static int Failed = 0;
    static void Check(string id, bool passed, string message, string limitation="")
    {
        Tests.Add(new {id, passed, message, limitation});
        if (!passed) Failed++;
        Console.WriteLine($"CASE {id}: {(passed?"PASS":"FAIL")} {message}");
    }
    static string HashFile(string p) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p)));
    static bool IsAuthorizationRejection(Exception ex)
    {
        Exception e = ex is TargetInvocationException t && t.InnerException != null ? t.InnerException : ex;
        return e is ArgumentException && e.Message.Contains("allowed temp directory", StringComparison.OrdinalIgnoreCase);
    }
    static string MakeJunction(string root, string target)
    {
        string path = Path.Combine(root, "junction");
        using Process p = new() { StartInfo = new ProcessStartInfo("cmd.exe")
        {
            UseShellExecute=false, CreateNoWindow=true, RedirectStandardOutput=true, RedirectStandardError=true
        }};
        p.StartInfo.ArgumentList.Add("/c");
        p.StartInfo.ArgumentList.Add($"mklink /J \"{path}\" \"{target}\"");
        p.Start();
        string logs = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0 || !Directory.Exists(path)) throw new IOException("Disposable junction failed: "+ logs);
        return path;
    }
    static string Fixture(string src, string marker)
    {
        Directory.CreateDirectory(src);
        File.WriteAllText(Path.Combine(src, "payload.msi"), marker, Encoding.UTF8);
        string manifest = Path.Combine(src, "pack.msi.json");
        File.WriteAllText(manifest, JsonSerializer.Serialize(new { Payload="payload.msi", ProductCode=Guid.NewGuid().ToString("B") }));
        return manifest;
    }
    static object NewCache(Assembly a, string customRoot, NamedPipeServerStream dummyPipe)
    {
        Type contextType = a.GetType("Microsoft.DotNet.Cli.Installer.Windows.InstallServerElevationContext", true)!;
        Type cacheType = a.GetType("Microsoft.DotNet.Cli.Installer.Windows.MsiPackageCache", true)!;
        ConstructorInfo serverCtor = contextType.GetConstructors(BindingFlags.NonPublic|BindingFlags.Public|BindingFlags.Instance)
            .Single(x=>x.GetParameters().Length==1);
        object ctx=serverCtor.Invoke([dummyPipe]);
        ConstructorInfo cacheCtor=cacheType.GetConstructors(BindingFlags.NonPublic|BindingFlags.Public|BindingFlags.Instance)
            .Single(x=>x.GetParameters().Length==4);
        // Signature verification stays enabled for retrieval/install. The cache operation
        // itself does not execute or verify a mock MSI.
        return cacheCtor.Invoke([ctx, null!, true, customRoot]);
    }
    static void Cache(Assembly a, object cache, string id, string ver, string manifest)
    {
        a.GetType("Microsoft.DotNet.Cli.Installer.Windows.MsiPackageCache", true)!
        .GetMethod("CachePayload", BindingFlags.Public|BindingFlags.Instance)!
        .Invoke(cache, [id,ver,manifest]);
    }

    static int Main(string[] args)
    {
        string sdk=args.Length>0?args[0]:"11.0.100";
        string basePath=Environment.GetEnvironmentVariable("GITHUB_WORKSPACE")??Directory.GetCurrentDirectory();
        string root=Path.Combine(basePath, ".cache-fixture-"+Guid.NewGuid().ToString("N"));
        string temp=Environment.GetEnvironmentVariable("RUNNER_TEMP")??Path.GetTempPath();
        string report=Path.Combine(temp,$"cache-downstream-{sdk}.json");
        string? junction=null; string status="RUNNING";
        var environment=new Dictionary<string,object?>();
        try
        {
            Directory.CreateDirectory(root);
            string client=Directory.CreateDirectory(Path.Combine(root,"client")).FullName;
            string outside=Directory.CreateDirectory(Path.Combine(root,"outside")).FullName;
            string cacheRoot=Directory.CreateDirectory(Path.Combine(root,"custom-cache")).FullName;
            using WindowsIdentity ident=WindowsIdentity.GetCurrent();
            environment["user"]=ident.Name;
            environment["sid"]=ident.User?.Value;
            environment["administrator"]=new WindowsPrincipal(ident).IsInRole(WindowsBuiltInRole.Administrator);
            environment["runtime"]=RuntimeInformation.FrameworkDescription;
            string dotnetRoot=Environment.GetEnvironmentVariable("DOTNET_ROOT")??@"C:\Program Files\dotnet";
            string dll=Path.Combine(dotnetRoot,"sdk",sdk,"dotnet.dll");
            environment["sdkCliSha256"]=HashFile(dll);
            environment["sdkCliAssembly"]=dll;
            Assembly a=Assembly.LoadFrom(dll);
            Type installer=a.GetType("Microsoft.DotNet.Cli.Installer.Windows.InstallerBase", true)!;
            PropertyInfo trusted=installer.GetProperty("TrustedClientTempDirectory", BindingFlags.Public|BindingFlags.Static)!;
            using NamedPipeServerStream dummy = new("cache-harness-"+Guid.NewGuid().ToString("N"),PipeDirection.InOut,
                1,PipeTransmissionMode.Byte, PipeOptions.None);
            object cache=NewCache(a,cacheRoot,dummy);
            if(!environment["administrator"]!.Equals(true)) throw new Exception("This lab expects pre-authorized admin runner");

            // Negative control: a manifest outside the nominated client root must not move.
            trusted.SetValue(null, client);
            string deniedSource=Directory.CreateDirectory(Path.Combine(outside,"control")).FullName;
            string deniedManifest=Fixture(deniedSource,"CONTROL-UNTOUCHED");
            string deniedHash=HashFile(deniedManifest);
            bool denied=false;
            try { Cache(a,cache,"fixture.control","1.0.0",deniedManifest); }
            catch(Exception e) { denied=IsAuthorizationRejection(e); }
            Check("11-cache-outside-negative",denied && File.Exists(deniedManifest)
                && HashFile(deniedManifest)==deniedHash,
                "Real SDK cache operation rejects a manifest outside the allowed root without moving it.",
                "Custom disposable cache root, already-admin caller.");

            // #11: overbroad trusted root changes the permission to move an otherwise denied source.
            trusted.SetValue(null, root);
            string broadSource=Directory.CreateDirectory(Path.Combine(outside,"broad")).FullName;
            string broadManifest=Fixture(broadSource,"BROAD-ROOT-SCRATCH-ONLY");
            string broadPayload=Path.Combine(broadSource,"payload.msi");
            string expectedHash=HashFile(broadPayload);
            Directory.CreateDirectory(Path.Combine(cacheRoot,"fixture.broad"));
            Cache(a,cache,"fixture.broad","1.0.0",broadManifest);
            string stored=Path.Combine(cacheRoot,"fixture.broad","1.0.0");
            bool broadMoved=File.Exists(Path.Combine(stored,"pack.msi.json"))
                && File.Exists(Path.Combine(stored,"payload.msi"))
                && HashFile(Path.Combine(stored,"payload.msi"))==expectedHash
                && !File.Exists(broadManifest) && !File.Exists(broadPayload);
            Check("11-cache-broad-root-source-moved",broadMoved,
                "Actual elevated SDK CachePayload moved a manifest and dummy payload from an otherwise disallowed root into a custom cache.",
                "Not a broker IPC request or real MSI installation.");

            // #12: intermediary junction points outside a narrower allowed client root.
            trusted.SetValue(null, client);
            string junctionSrc=Directory.CreateDirectory(Path.Combine(outside,"junction-target")).FullName;
            string externalManifest=Fixture(junctionSrc,"JUNCTION-SCRATCH-ONLY");
            string externalPayload=Path.Combine(junctionSrc,"payload.msi");
            expectedHash=HashFile(externalPayload);
            junction=MakeJunction(client,junctionSrc);
            Directory.CreateDirectory(Path.Combine(cacheRoot,"fixture.junction"));
            Cache(a,cache,"fixture.junction","1.0.0",Path.Combine(junction,"pack.msi.json"));
            stored=Path.Combine(cacheRoot,"fixture.junction","1.0.0");
            bool junctionMoved=File.Exists(Path.Combine(stored,"pack.msi.json"))
                && File.Exists(Path.Combine(stored,"payload.msi"))
                && HashFile(Path.Combine(stored,"payload.msi"))==expectedHash
                && !File.Exists(externalManifest) && !File.Exists(externalPayload);
            Check("12-cache-junction-external-read-and-delete",junctionMoved,
                "Actual SDK cache process copied and deleted dummy source files physically outside nominated client root via an intermediate junction.",
                "Same-token administrator test; final target was an owned disposable directory.");

            // Strengthen the counterevidence: traversal in package ID should fail closed before any move.
            trusted.SetValue(null, client);
            string traversalSource=Directory.CreateDirectory(Path.Combine(client,"traversal")).FullName;
            string traversalManifest=Fixture(traversalSource,"TRAVERSAL-NEGATIVE-CONTROL");
            bool traversalDenied=false;
            try { Cache(a,cache,@"..\escape","1.0.0",traversalManifest); }
            catch (Exception e)
            {
                var inner = e is TargetInvocationException t ? t.InnerException??e : e;
                traversalDenied=inner is ArgumentException;
            }
            Check("11-cache-packageid-traversal-denied",traversalDenied && File.Exists(traversalManifest),
                "Actual SDK path-component validation rejects attempted traversal in destination package ID.",
                "Counterexample: not every client-controlled path escapes confinement.");

            // #13: cached unauthenticated bytes do not imply execution: VerifyPackageSignature
            // must reject an unsigned dummy MSI before any InstallProduct operation.
            MethodInfo verify=a.GetType("Microsoft.DotNet.Cli.Installer.Windows.MsiPackageCache",true)!
                .GetMethod("VerifyPackageSignature",BindingFlags.Instance|BindingFlags.NonPublic|BindingFlags.Public)!;
            string unsigned=Path.Combine(stored,"payload.msi");
            bool signatureDenied=false; string? signatureError=null;
            try { verify.Invoke(cache,[unsigned]); }
            catch (Exception e) { signatureDenied=true; signatureError=(e.InnerException??e).GetType().Name; }
            Check("13-unsigned-cached-payload-denied",signatureDenied,
                "Actual SDK signature verifier rejects dummy unsigned MSI; exception type "+(signatureError??"none")+".",
                "Does not address unrelated-product uninstall/repair; no product installed.");
            environment["customCacheRoot"]=cacheRoot;
            environment["didNotTouchProgramDataDotnet"]=!cacheRoot.StartsWith(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),StringComparison.OrdinalIgnoreCase);
            status=Failed==0?"COMPLETED":"ASSERTION_FAILURE";
        }
        catch(Exception e)
        {
            status="ERROR";
            Errors.Add(e.ToString());
            Console.WriteLine("ERROR "+e);
        }
        finally
        {
            try
            {
                if(junction!=null && Directory.Exists(junction))Directory.Delete(junction,false);
                if(Directory.Exists(root)) Directory.Delete(root,true);
            }
            catch(Exception e){Errors.Add("Cleanup: "+e);}
            File.WriteAllText(report,JsonSerializer.Serialize(new
            {
                timestampUtc=DateTimeOffset.UtcNow.ToString("O"),sdk,status,
                evidenceKind="actual installed SDK cache implementation; fully custom scratch cache root; not broker/UAC",
                environment,tests=Tests,errors=Errors
            },new JsonSerializerOptions{WriteIndented=true}));
            Console.WriteLine("EVIDENCE_FILE="+report);
            Console.WriteLine("RUN_STATUS="+status);
        }
        return status=="COMPLETED"?0:1;
    }
}