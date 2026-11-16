// Read-only reflection test of ACTUAL installed SDK CreatePipeSecurity.
// The isolated standard-user SID is supplied by the accompanying cross-account fixture.
// No named pipe to an admin process is used here and this does not simulate UAC consent.
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text.Json;

internal static class Program
{
    static int Main(string[] args)
    {
        string sdk = args[0];
        string lowSid = args[1];
        string report = args[2];
        var checks=new List<object>();
        var rules=new List<object>();
        var errors=new List<string>();
        string status="RUNNING";
        var env=new Dictionary<string,object?>();
        try
        {
            using WindowsIdentity admin=WindowsIdentity.GetCurrent();
            var principal=new WindowsPrincipal(admin);
            string host=Environment.ProcessPath!;
            string path=Path.Combine(Path.GetDirectoryName(host)!,"sdk",sdk,"dotnet.dll");
            Type t=Assembly.LoadFrom(path)
                .GetType("Microsoft.DotNet.Cli.Installer.Windows.WindowsUtils",true)!;
            MethodInfo m=t.GetMethod("CreatePipeSecurity",BindingFlags.Static|BindingFlags.Public)!;
            var owner=admin.Owner!;
            var client=new SecurityIdentifier(lowSid);
            object acl=m.Invoke(null,[owner,client])!;
            env["sdkVersion"]=sdk;
            env["sdkSha256"]=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
            env["administratorSid"]=admin.User?.Value;
            env["pipeOwnerSid"]=owner.Value;
            env["delegateStandardUserSid"]=client.Value;
            env["alreadyAdmin"]=principal.IsInRole(WindowsBuiltInRole.Administrator);
            env["noInteractiveUac"]=true;
            var getRules=acl.GetType().GetMethod("GetAccessRules",BindingFlags.Public|BindingFlags.Instance)!;
            var access=(IEnumerable)getRules.Invoke(acl,[true,true,typeof(SecurityIdentifier)])!;
            bool lowAllow=false,ownerAllow=false,worldAllow=false;
            foreach(object entry in access)
            {
                Type ruleType=entry.GetType();
                object identity=ruleType.GetProperty("IdentityReference")!.GetValue(entry)!;
                string sid=(string)identity.GetType().GetProperty("Value")!.GetValue(identity)!;
                object permission=ruleType.GetProperty("PipeAccessRights")!.GetValue(entry)!;
                string rights=permission.ToString()!;
                string kind=ruleType.GetProperty("AccessControlType")!.GetValue(entry)!.ToString()!;
                rules.Add(new{sid,rights,kind});
                if(kind=="Allow" && sid==client.Value
                    && rights.Contains("Read") && rights.Contains("Write"))lowAllow=true;
                if(kind=="Allow" && sid==owner.Value && rights.Contains("FullControl"))ownerAllow=true;
                if(kind=="Allow" && sid=="S-1-1-0")worldAllow=true;
            }
            checks.Add(new{id="sdk-pipe-acl-delegate-low-sid",passed=lowAllow,
                result="SDK pipe ACL explicitly grants standard-user SID read/write rights",
                limitation="Source-backed predicted UAC broker DACL, not a live cross-SID broker session."});
            checks.Add(new{id="sdk-pipe-acl-owner-admin",passed=ownerAllow,
                result="SDK pipe ACL grants owner administrator full control",
                limitation="The admin owner was the already-elevated test process."});
            checks.Add(new{id="sdk-pipe-acl-no-world",passed=!worldAllow,
                result="SDK pipe ACL does not grant Everyone identity read/write",
                limitation="Does not test privileged default DACL inheritance or authenticated client process provenance."});
            checks.Add(new{id="sdk-pipe-acl-distinct-sids",passed=owner.Value!=client.Value && principal.IsInRole(WindowsBuiltInRole.Administrator),
                result="Owner SID and standard-user delegate SID are different",
                limitation="Synthetic ACL constructed with supplied delegate SID; no real user-approved UAC transition."});
            status=lowAllow&&ownerAllow&&!worldAllow&&owner.Value!=client.Value?"COMPLETED":"ASSERTION_FAILURE";
        }
        catch(Exception ex) {status="ERROR";errors.Add(ex.ToString()); Console.WriteLine("ERROR "+ex);}
        finally {
            var data=new {timestampUtc=DateTimeOffset.UtcNow.ToString("O"),sdk,status,
                evidenceKind="Actual shipped SDK CreatePipeSecurity with separate standard-user SID",
                environment=env,rules,checks,errors};
            File.WriteAllText(report,JsonSerializer.Serialize(data,new JsonSerializerOptions{WriteIndented=true}));
            Console.WriteLine("EVIDENCE_FILE="+report);
            Console.WriteLine("RUN_STATUS="+status);
        }
        return status=="COMPLETED"?0:1;
    }
}