// Authorized Windows CI research. Executes the *actual installed SDK* path validator
// using a manifest path shaped exactly like the normal workload client's
// <temp>/<random GUID>/data/msi.json, after an isolated standard user replaces
// its owned data directory with a junction. No UAC, broker, MSI or registry writes.
// The already-authorized administrator only reads the protected fixture.
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;
using System.Text.Json;

internal static class Program
{
    static readonly List<object> Cases=new();
    static readonly List<string> Errors=new();
    static int failures;
    static void Check(string id,bool ok,string finding,string caveat="")
    {
        Cases.Add(new{id,pass=ok,finding,caveat});
        if(!ok)failures++;
        Console.WriteLine("CASE "+id+" "+(ok?"PASS ":"FAIL ")+finding);
    }
    static string Hash(string path)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    // Controlled differential against a handle-based containment policy. This is NOT
    // Microsoft's code or a proposed complete fix. The caller must subsequently
    // operate on this SAME checked handle, not reopen the path (TOCTOU).
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateFileW")]
    static extern SafeFileHandle CreateFile(
        string path,uint desiredAccess,uint shareMode,IntPtr sec,
        uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="GetFinalPathNameByHandleW")]
    static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,StringBuilder buffer,uint length,uint flags);
    static string FinalPath(SafeFileHandle handle)
    {
        StringBuilder buffer=new(8192);
        uint size=GetFinalPathNameByHandle(handle,buffer,(uint)buffer.Capacity,0);
        if(size==0||size>=buffer.Capacity)
            throw new Win32Exception(Marshal.GetLastWin32Error(),"GetFinalPathNameByHandleW failed");
        return buffer.ToString();
    }
    static bool SameObjectRootPolicy(string filename,string trustedDirectory)
    {
        const uint ShareReadWriteDelete=0x1|0x2|0x4;
        const uint OpenExisting=3;
        const uint DirectoryHandle=0x02000000;
        // Opening the real object first, resolving the path from that handle,
        // protects only the object operated on through that SAME handle.
        using SafeFileHandle file=CreateFile(filename,0,ShareReadWriteDelete,
            IntPtr.Zero,OpenExisting,0,IntPtr.Zero);
        using SafeFileHandle root=CreateFile(trustedDirectory,0,ShareReadWriteDelete,
            IntPtr.Zero,OpenExisting,DirectoryHandle,IntPtr.Zero);
        if(file.IsInvalid||root.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(),"Could not open protected test object");
        string filePath=FinalPath(file);
        string rootPath=FinalPath(root).TrimEnd('\\');
        return filePath.StartsWith(rootPath+"\\",StringComparison.OrdinalIgnoreCase);
    }
    public static int Main(string[] args)
    {
        if(args.Length!=4)throw new ArgumentException("sdkVersion lowUserJson protectedDirectory outputPath");
        string sdk=args[0],input=args[1],protectedDir=args[2],output=args[3];
        string status="RUNNING";
        var info=new Dictionary<string,object?>();
        try
        {
            if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
            using JsonDocument low=JsonDocument.Parse(File.ReadAllText(input));
            JsonElement v=low.RootElement;
            string client=v.GetProperty("clientRoot").GetString()!;
            string broad=v.GetProperty("broadRoot").GetString()!;
            string linked=v.GetProperty("clientDerivedManifestPath").GetString()!;
            string original=v.GetProperty("originalExtractedManifestPath").GetString()!;
            string link=v.GetProperty("createdDataJunction").GetString()!;
            string actualProtected=Path.Combine(protectedDir,"msi.json");
            string sdkRoot=Environment.GetEnvironmentVariable("DOTNET_ROOT")
                ?? @"C:\Program Files\dotnet";
            string cli=Path.Combine(sdkRoot,"sdk",sdk,"dotnet.dll");
            if(!File.Exists(cli))throw new FileNotFoundException("Installed SDK assembly missing",cli);
            info["sdkCliSha256"]=Hash(cli);
            info["testedSdkVersion"]=sdk;
            info["lowUserSid"]=v.GetProperty("sid").GetString();
            info["adminOnlyDirectory"]=protectedDir;
            info["preflightStdUserCannotReadSource"]=v.GetProperty("protectedReadDenied").GetBoolean();
            info["preflightStdUserCannotWriteSource"]=v.GetProperty("protectedWriteDenied").GetBoolean();
            info["lowUserNormalClientCommandExit"]=v.GetProperty("workloadListExitCode").GetInt32();
            info["lowUserNormalClientCommand"]=v.GetProperty("workloadListCommand").GetString();
            Assembly loaded=Assembly.LoadFrom(cli);
            Type installer=loaded.GetType("Microsoft.DotNet.Cli.Installer.Windows.InstallerBase",true)!;
            Type utils=loaded.GetType("Microsoft.DotNet.Cli.Installer.Windows.WindowsUtils",true)!;
            const BindingFlags flags=BindingFlags.Public|BindingFlags.Static;
            PropertyInfo property=installer.GetProperty("TrustedClientTempDirectory",flags)
                ?? throw new MissingMemberException("InstallerBase.TrustedClientTempDirectory");
            MethodInfo method=utils.GetMethod("ValidateManifestPath",flags)
                ?? throw new MissingMemberException("WindowsUtils.ValidateManifestPath");
            string customServerTemp=Path.Combine(Environment.GetEnvironmentVariable("RUNNER_TEMP") ?? Path.GetTempPath(),"server-trust-root-does-not-exist");
            bool Validate(string candidate,string root)
            {
                property.SetValue(null,root);
                return (bool)(method.Invoke(null,new object?[]{candidate,customServerTemp})
                    ?? throw new InvalidOperationException("Null SDK manifest validator response"));
            }
            bool lowResult=v.GetProperty("protectedReadDenied").GetBoolean()
                && v.GetProperty("protectedWriteDenied").GetBoolean()
                && !v.GetProperty("isAdministrator").GetBoolean()
                && v.GetProperty("lowOwnExtractCreated").GetBoolean();
            Check("low-user-cross-account-acls",lowResult,
                "A distinct standard-user account created its own extraction folder but could not access the protected fixture.");
            Check("normal-workload-list-executed",v.GetProperty("workloadListExitCode").GetInt32()==0,
                "The unmodified dotnet workload list command completed under the nonadmin token.",
                "Read-only command; did not invoke CachePayload or broker elevation.");
            string normalizedClient=Path.GetFullPath(client).TrimEnd(Path.DirectorySeparatorChar);
            bool lexical=Path.GetFullPath(linked).StartsWith(normalizedClient+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase);
            Check("normal-client-derived-path-shape",lexical && Path.GetFileName(linked)=="msi.json"
                && Path.GetFileName(Path.GetDirectoryName(linked)!)=="data"
                && Guid.TryParse(Path.GetFileName(Path.GetDirectoryName(Path.GetDirectoryName(linked)!)!),out _),
                "Manifest path has normal client temp/GUID/data/msi.json shape, not an arbitrary protected path.",
                "Shape is created by our low-user fixture; it is not captured from a real workload extraction.");
            Check("low-user-created-data-junction",v.GetProperty("dataJunctionCreated").GetBoolean()
                && File.GetAttributes(link).HasFlag(FileAttributes.ReparsePoint),
                "The standard user replaced its own extraction data directory with an NTFS junction.");
            Check("low-user-still-protected-after-junction",v.GetProperty("linkedProtectedReadDenied").GetBoolean(),
                "The low-user process could not directly read administrator-only manifest through the link.");
            Check("narrow-root-original-allowed",Validate(original,client),
                "SDK validator accepts the user's original normal-shaped extracted manifest path.");
            Check("narrow-root-direct-protected-denied",!Validate(actualProtected,client),
                "SDK validator rejects direct protected manifest outside narrow client temp.");
            Check("narrow-root-sibling-prefix-denied",!Validate(Path.Combine(broad,"client-sibling","msi.json"),client),
                "SDK validator rejects a sibling-prefix lookalike outside the exact client root.");
            bool redirected=Validate(linked,client);
            Check("normal-shaped-linked-path-accepted",redirected,
                "SDK validator accepts an in-root normal-shaped manifest that now follows a reparse junction.",
                "Only validator admission; not evidence the unmodified client ever sent the linked path to a live broker.");
            string targetHash=Hash(actualProtected);
            string linkHash=Hash(linked);
            Check("normal-shaped-linked-path-reads-protected-object",redirected && targetHash==linkHash,
                "Administrator readback through in-root normal-shaped path matches admin-only source SHA256.",
                "Administrator test process performed the read; no broker or UAC effects tested.");
            Check("broad-root-direct-protected-allowed",Validate(actualProtected,broad),
                "SDK validator admits direct protected source if the broader parent root is trusted.",
                "No proof normal client selects this source as its actual manifest.");
            Check("narrow-root-direct-protected-still-denied",!Validate(actualProtected,client),
                "The same protected direct path is denied again after restoring a narrow root.");
            Check("handle-root-allows-original-ordinary-extraction",SameObjectRootPolicy(original,client),
                "Handle-resolved object remains under the narrow root for unmodified, owned data.");
            Check("handle-root-rejects-normal-shaped-junction",!SameObjectRootPolicy(linked,client),
                "Handle-resolved object lies in administrator-only directory outside narrow root.",
                "A real fix must operate using the checked handle to prevent a later swap.");
            Check("handle-root-rejects-direct-protected",!SameObjectRootPolicy(actualProtected,client),
                "Handle-based containment also denies the direct protected fixture.");
            // An actual sibling directory handle is required for a meaningful
            // file-identity boundary test (a nonexistent root would just throw).
            string siblingDirectory=Directory.CreateDirectory(Path.Combine(broad,"client-sibling")).FullName;
            Check("handle-root-rejects-sibling-prefix",!SameObjectRootPolicy(original,siblingDirectory),
                "Handle-based containment does not accept a sibling-prefix lookalike.");
            Check("handle-root-does-not-solve-overbroad-trust",SameObjectRootPolicy(actualProtected,broad),
                "A final-object check still allows protected data when the trusted root itself is too broad.",
                "Shows #11 requires separate root-provenance validation; final-path checking alone is insufficient.");

            info["normalClientShapedManifestPath"]=linked;
            info["protectedSourceSha256"]=targetHash;
            info["linkedPathSha256"]=linkHash;
            info["actualUacApprovalObserved"]=false;
            info["realBrokerInvoked"]=false;
            status=failures==0?"COMPLETED":"ASSERTION_FAILURE";
        }
        catch(Exception e)
        {
            status="ERROR";
            Errors.Add(e.ToString());
            Console.WriteLine("ERROR "+e);
        }
        finally
        {
            File.WriteAllText(output,JsonSerializer.Serialize(new {
                sdkVersion=sdk,utc=DateTimeOffset.UtcNow.ToString("O"),status,environment=info,
                checks=Cases,errors=Errors,limitations=new[]{
                    "Real installed SDK validator and real standard-user filesystem path, but custom harness",
                    "Unmodified workload list is read-only and does not prove package install/repro",
                    "No UAC or broker was started; this alone does not prove Important EoP"
                }
            },new JsonSerializerOptions{WriteIndented=true}));
            Console.WriteLine("VALIDATOR_STATUS="+status);
        }
        return status=="COMPLETED"?0:1;
    }
}
