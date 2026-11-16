#!/usr/bin/env python3
"""Isolated NuGet require/cached-policy boundary experiments; no external feeds."""
import json, os, pathlib, shutil, subprocess, tempfile, textwrap, xml.sax.saxutils, zipfile

ROOT=pathlib.Path(tempfile.mkdtemp(prefix="nuget-boundary-"))
ID="Probe.Policy.Boundary"
VERSION="1.0.0"
feed=ROOT/"untrusted-feed"
trusted=ROOT/"trusted-empty"
feed.mkdir(); trusted.mkdir()
cache=ROOT/"shared-global-packages"
TARGET="POLICY_BOUNDARY_CANARY_TARGET_RAN"

def cmd(args, *, verify="true", cwd=None):
    env=dict(os.environ, DOTNET_NUGET_SIGNATURE_VERIFICATION=verify,
             DOTNET_CLI_HOME=str(ROOT/"home"), DOTNET_NOLOGO="1",
             DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1")
    try:
        p=subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         cwd=cwd or ROOT, env=env, timeout=125)
        return {"exit":p.returncode,"log":p.stdout[-3400:]}
    except Exception as e:
        return {"exit":-999, "log":repr(e)}

sdk=cmd(["dotnet","--version"])
major=sdk["log"].strip().split(".")[0]
if major not in ("10","11","12"):
    major="11"
project=ROOT/"probe.csproj"
project.write_text(f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net{major}.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="{ID}" Version="{VERSION}"/></ItemGroup></Project>')
nuspec=f"""<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
 <metadata><id>{ID}</id><version>{VERSION}</version><authors>Boundary Lab</authors>
 <description>Harmless package-signature policy probe</description></metadata></package>"""
package=feed/f"{ID}.{VERSION}.nupkg"
with zipfile.ZipFile(package,"w",zipfile.ZIP_DEFLATED) as z:
    z.writestr(f"{ID}.nuspec", nuspec)
    z.writestr(f"buildTransitive/{ID}.targets",
        f'<Project><Target Name="BoundaryCanary" BeforeTargets="BeforeBuild"><Message Importance="high" Text="{TARGET}" /></Target></Project>')

def config(name, require, source, mapping=False):
    p=ROOT/f"{name}.config"
    src="<add key='Untrusted' value='"+xml.sax.saxutils.escape(str(feed),{"'":"&apos;"})+"' />" if source=="untrusted" else "<add key='Trusted' value='"+xml.sax.saxutils.escape(str(trusted),{"'":"&apos;"})+"' />"
    map_xml=f'<packageSourceMapping><packageSource key="Trusted"><package pattern="{ID}"/></packageSource></packageSourceMapping>' if mapping else ""
    p.write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear/>{src}</packageSources>
<config><add key="signatureValidationMode" value="{'require' if require else 'accept'}"/></config>
<trustedSigners><author name="BoundaryTestNonexistentSigner">
<certificate fingerprint="{'0'*64}" hashAlgorithm="SHA256" allowUntrustedRoot="false" />
</author></trustedSigners>{map_xml}</configuration>""")
    return p

accept=config("accept",False,"untrusted")
strict=config("require",True,"untrusted")
mapped=config("mapped",True,"trusted",True)
def restore(label, cfg, packages, verify):
    r=cmd(["dotnet","restore",str(project),"--configfile",str(cfg),
           "--packages",str(packages),"--force","--no-http-cache","--verbosity","minimal"],verify=verify)
    r.update({"label":label,"signature_verification_env":verify,
              "cache_complete":(packages/ID.lower()/VERSION/".nupkg.metadata").exists()})
    return r

results=[{"label":"sdk","result":sdk}]
results.append(restore("require_cold_verification_enabled", strict, ROOT/"cold-verify-on","true"))
results.append(restore("require_cold_verification_disabled", strict, ROOT/"cold-verify-off","false"))
results.append(restore("accept_seed_shared_cache", accept, cache, "true"))
results.append(restore("require_warm_cache_verification_enabled", strict, cache,"true"))
b=cmd(["dotnet","build",str(project),"--no-restore","--verbosity","normal"],verify="true")
results.append({"label":"build_after_strict_warm_cache","exit":b["exit"],"canary_target_executed":TARGET in b["log"],"log":b["log"]})
results.append(restore("require_cold_second_control",strict,ROOT/"cold-control-2","true"))
results.append(restore("mapped_trusted_feed_warm_shared_cache",mapped,cache,"true"))
results.append(restore("mapped_trusted_feed_cold_control",mapped,ROOT/"cold-mapped","true"))

report={"sdk":sdk["log"].strip(),"package_path":str(package),"tests":results,
        "insecure_transport":"separate harness"}
out=pathlib.Path(os.environ.get("BOUNDARY_OUTPUT","."))
out.mkdir(parents=True,exist_ok=True)
(out/"nuget-policy-results.json").write_text(json.dumps(report,indent=2))
for item in results:
    print(item["label"],"exit=",item.get("exit",item.get("result",{}).get("exit")),
          "cache_complete=",item.get("cache_complete"),"canary=",item.get("canary_target_executed"))
    if item.get("exit") not in (0,None): print(item.get("log","")[-550:])
print("WROTE",out/"nuget-policy-results.json")
