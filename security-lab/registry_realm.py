#!/usr/bin/env python3
"""Actual SDK AuthHandshakeMessageHandler probe against loopback fake registry/realm only."""
import base64, glob, http.server, json, os, pathlib, subprocess, tempfile, threading, socket
ROOT=pathlib.Path(tempfile.mkdtemp(prefix="registry-realm-boundary-"))
OUT=pathlib.Path(os.environ.get("BOUNDARY_OUTPUT","."))
OUT.mkdir(parents=True,exist_ok=True)
USERNAME="CANARY_REGISTRY_USER"
PASSWORD="CANARY_REGISTRY_PASSWORD"
alias="boundary-token.localdomain"
# This hostname is added to the disposable GitHub runner's hosts file only.
try:
    subprocess.run(["sudo","-n","tee","-a","/etc/hosts"],input=f"\n127.0.0.1 {alias}\n",text=True,capture_output=True,check=True,timeout=15)
    hosts_ready=(socket.gethostbyname(alias)=='127.0.0.1')
except Exception: hosts_ready=False
dll_candidates=glob.glob("/opt/hostedtoolcache/dotnet/**/Microsoft.NET.Build.Containers.dll",recursive=True)
if not dll_candidates:
    dll_candidates=glob.glob("/usr/share/dotnet/**/Microsoft.NET.Build.Containers.dll",recursive=True)
dll_candidates.sort(key=lambda p:(int(p.split("/sdk/")[1].split(".")[0]) if "/sdk/" in p else 0, "/Containers/" in p),reverse=True)
dll=dll_candidates[0] if dll_candidates else ""
proj=ROOT/"sdkprobe"
proj.mkdir()
(proj/"sdkprobe.csproj").write_text("""<Project Sdk="Microsoft.NET.Sdk">
<PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework></PropertyGroup>
<ItemGroup><FrameworkReference Include="Microsoft.AspNetCore.App"/>
<Reference Include="Microsoft.NET.Build.Containers"><HintPath>"""+dll+"""</HintPath></Reference></ItemGroup></Project>""")
(proj/"Program.cs").write_text(r"""
using System;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
var asm=Assembly.LoadFrom(args[0]);
var handlerType=asm.GetType("Microsoft.NET.Build.Containers.AuthHandshakeMessageHandler",true)!;
var modeType=asm.GetType("Microsoft.NET.Build.Containers.RegistryMode",true)!;
var mode=Enum.Parse(modeType,"Push");
var ctor=handlerType.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance).Single(c=>c.GetParameters().Length==5);
var inner=new HttpClientHandler{AllowAutoRedirect=true,UseProxy=false};
var handler=(HttpMessageHandler)ctor.Invoke(new object?[]{args[1],true,inner,NullLogger.Instance,mode});
using var client=new HttpClient(handler);
try {
    var resp=await client.GetAsync(args[2]);
    Console.WriteLine("SDK_RESULT status="+(int)resp.StatusCode);
} catch (Exception ex) {
    Console.WriteLine("SDK_ERROR type="+ex.GetType().Name+" message="+ex.Message.Replace('\n',' '));
}
""")
compile=subprocess.run(["dotnet","build",str(proj/"sdkprobe.csproj"),"-c","Release"],capture_output=True,text=True,timeout=130)
if not dll or compile.returncode!=0 or not hosts_ready:
    report={"ready":False,"dll_found":bool(dll),"hosts_ready":hosts_ready,"build_tail":compile.stdout[-1500:]+compile.stderr[-600:]}
else:
    report={"ready":True,"dll":dll,"resolved_alias":socket.gethostbyname(alias),"tests":[]}
    class LabHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def do_GET(self):
            if self.server.kind=="registry":
                self.send_response(401)
                self.send_header("WWW-Authenticate",f'Bearer realm="{self.server.realm}",service="boundary-lab"')
                self.send_header("Content-Length","0"); self.end_headers();return
            is_canary=(self.headers.get("Authorization","") ==
                "Basic "+base64.b64encode((USERNAME+":"+PASSWORD).encode()).decode())
            self.server.events.append({"method":"GET","path":self.path,"canary_basic_auth":is_canary})
            if self.path.startswith("/redirect"):
                self.send_response(401); self.send_header("Content-Length","0");self.end_headers();return
            payload=b'{"token":"synthetic-token","expires_in":60}'
            self.send_response(200);self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload)
        def do_POST(self):
            length=min(int(self.headers.get("Content-Length","0")),20000)
            body=self.rfile.read(length)
            hit=(b"CANARY_REGISTRY_USER" in body and b"CANARY_REGISTRY_PASSWORD" in body)
            self.server.events.append({"method":"POST","path":self.path,"canary_in_body":hit})
            if self.path.startswith("/redirect"):
                self.send_response(307);self.send_header("Location",f"http://127.0.0.1:{self.server.server_port}/posted")
                self.send_header("Content-Length","0");self.end_headers();return
            payload=b'{"token":"synthetic-token","expires_in":60}'
            self.send_response(200);self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload)
    reg=http.server.ThreadingHTTPServer(("127.0.0.1",0),LabHandler)
    realm=http.server.ThreadingHTTPServer(("127.0.0.1",0),LabHandler)
    reg.kind="registry";reg.events=[];realm.kind="realm";realm.events=[]
    threading.Thread(target=reg.serve_forever,daemon=True).start()
    threading.Thread(target=realm.serve_forever,daemon=True).start()
    modes=[("blocked_ip_literal",f"http://127.0.0.2:{realm.server_port}/token"),
           ("dns_name_resolves_to_loopback",f"http://{alias}:{realm.server_port}/token"),
           ("same_scheme_redirect_post",f"http://{alias}:{realm.server_port}/redirect")]
    for label,url in modes:
        reg.realm=url
        reg.events.clear();realm.events.clear()
        env=dict(os.environ,DOTNET_CONTAINER_REGISTRY_UNAME=USERNAME,DOTNET_CONTAINER_REGISTRY_PWORD=PASSWORD,
                 NO_PROXY="localhost,127.0.0.1,127.0.0.2,"+alias, no_proxy="localhost,127.0.0.1,127.0.0.2,"+alias,
                 DOTNET_CLI_TELEMETRY_OPTOUT="1")
        run=subprocess.run(["dotnet","run","--no-build","-c","Release","--project",str(proj/"sdkprobe.csproj"),"--",
                            dll,f"127.0.0.1:{reg.server_port}",f"http://127.0.0.1:{reg.server_port}/v2/"],
                           env=env,capture_output=True,text=True,timeout=35)
        report["tests"].append({"name":label,"sdk_exit":run.returncode,
                                "sdk_last_line":(run.stdout+run.stderr)[-1800:],"realm_events":list(realm.events)})
    reg.shutdown();realm.shutdown()
(OUT/"registry-realm-results.json").write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2)[-6500:])
