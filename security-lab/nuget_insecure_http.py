#!/usr/bin/env python3
"""Local-only HTTPS NuGet V3 feed delegating package bytes over HTTP; controls."""
import http.server as httpserver
import json, os, pathlib, ssl, subprocess, tempfile, threading, zipfile
ROOT=pathlib.Path(tempfile.mkdtemp(prefix="nuget-http-boundary-"))
OUT=pathlib.Path(os.environ.get("BOUNDARY_OUTPUT","."))
OUT.mkdir(parents=True,exist_ok=True)
ID="Probe.Transport"
LOW=ID.lower()
VERSION="1.0.0"
archive=ROOT/f"{LOW}.{VERSION}.nupkg"
with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as z:
    z.writestr(f"{ID}.nuspec",f"""<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
<metadata><id>{ID}</id><version>{VERSION}</version><authors>Lab</authors>
<description>Transport-only canary; no code execution</description></metadata></package>""")
    z.writestr("contentFiles/any/any/canary.txt","LOCAL_ONLY_NUPKG_CANARY")
class Handler(httpserver.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        self.server.visits.append(self.path)
        if self.path in (f"/flat/{LOW}/index.json",):
            body=json.dumps({"versions":[VERSION]}).encode()
        elif self.path in (f"/flat/{LOW}/{VERSION}/{LOW}.{VERSION}.nupkg",):
            body=archive.read_bytes()
        elif self.path.startswith("/index-") and self.path.endswith(".json"):
            httpbase=self.server.service_package_base
            httpsbase=f"https://localhost:{self.server.https_port}"
            body=json.dumps({"version":"3.0.0","resources":[
                {"@id":httpbase,"@type":"PackageBaseAddress/3.0.0"},
                {"@id":httpsbase+"/registrations/","@type":"RegistrationsBaseUrl/3.6.0"}
            ]}).encode()
        elif self.path==f"/registrations/{LOW}/index.json":
            httpsbase=f"https://localhost:{self.server.https_port}"
            body=json.dumps({"count":1,"items":[{"@id":httpsbase+"/registration-page",
                  "lower":VERSION,"upper":VERSION,"count":1,
                  "items":[{"@id":httpsbase+"/entry",
                     "catalogEntry":{"@id":httpsbase+"/catalog","id":ID,"version":VERSION,
                        "authors":"Lab","description":"Synthetic package","dependencyGroups":[]},
                     "packageContent":self.server.service_package_base+f"{LOW}/{VERSION}/{LOW}.{VERSION}.nupkg"}]}]}).encode()
        else:
            self.send_response(404);self.send_header("Content-Length","0");self.end_headers();return
        self.send_response(200)
        self.send_header("Content-Type","application/json" if not self.path.endswith(".nupkg") else "application/octet-stream")
        self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
http=httpserver.ThreadingHTTPServer(("127.0.0.1",0),Handler)
https=httpserver.ThreadingHTTPServer(("127.0.0.1",0),Handler)
for srv in (http,https):
    srv.visits=[];srv.https_port=https.server_port
    srv.service_package_base=f"http://localhost:{http.server_port}/flat/"
cert=ROOT/"ca.crt";key=ROOT/"key.pem"
openssl=subprocess.run(["openssl","req","-x509","-nodes","-newkey","rsa:2048",
                        "-days","1","-keyout",str(key),"-out",str(cert),
                        "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
trust={"openssl":openssl.returncode}
if openssl.returncode==0:
    t=subprocess.run(["sudo","-n","cp",str(cert),"/usr/local/share/ca-certificates/dotnet-boundary-probe.crt"],capture_output=True,text=True)
    upd=subprocess.run(["sudo","-n","update-ca-certificates"],capture_output=True,text=True)
    trust.update({"copied":t.returncode,"updated":upd.returncode})
    sslctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sslctx.load_cert_chain(str(cert),str(key))
    https.socket=sslctx.wrap_socket(https.socket,server_side=True)
threading.Thread(target=http.serve_forever,daemon=True).start()
threading.Thread(target=https.serve_forever,daemon=True).start()
major=subprocess.run(["dotnet","--version"],capture_output=True,text=True).stdout.split(".")[0]
project=ROOT/"probe.csproj"
project.write_text(f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net{major}.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="{ID}" Version="{VERSION}"/></ItemGroup></Project>')
cfg=ROOT/"NuGet.Config"
cfg.write_text(f"""<?xml version="1.0"?>
<configuration><packageSources><clear/>
<add key="HTTPS-Trusted" value="https://localhost:{https.server_port}/index.json" protocolVersion="3"/>
</packageSources></configuration>""")
tests=[]
for mode in ("delegated_https_control","delegated_http_candidate"):
    https.service_package_base=(f"https://localhost:{https.server_port}/flat/" if mode=="delegated_https_control"
                                else f"http://localhost:{http.server_port}/flat/")
    cfg.write_text(f'''<?xml version="1.0"?><configuration><packageSources><clear/><add key="HTTPS-{mode}" value="https://localhost:{https.server_port}/index-{mode}.json" protocolVersion="3"/></packageSources></configuration>''')
    http.visits.clear();https.visits.clear()
    package_cache=ROOT/("cache-"+mode)
    env=dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1",DOTNET_NOLOGO="1",
             DOTNET_CLI_HOME=str(ROOT/"home"),NUGET_HTTP_CACHE_PATH=str(ROOT/("http-cache-"+mode)),NO_PROXY="localhost,127.0.0.1",no_proxy="localhost,127.0.0.1")
    try:
        proc=subprocess.run(["dotnet","restore",str(project),"--configfile",str(cfg),
                             "--packages",str(package_cache),"--force","--no-http-cache","-v","normal"],
                            capture_output=True,text=True,env=env,timeout=110)
        result={"name":mode,"exit":proc.returncode,"http_package_requests":[x for x in http.visits if ".nupkg" in x],
                "http_requests":list(http.visits),"https_requests":list(https.visits),
                "cache_complete":(package_cache/LOW/VERSION/".nupkg.metadata").exists(),
                "log_tail":(proc.stdout+proc.stderr)[-2100:]}
    except Exception as e:result={"name":mode,"error":repr(e)}
    tests.append(result)
http.shutdown();https.shutdown()
report={"trust":trust,"tests":tests}
(OUT/"nuget-http-results.json").write_text(json.dumps(report,indent=2))
for t in tests:print(t["name"],"exit",t.get("exit"),"http_package_requests",t.get("http_package_requests"),"http_requests",t.get("http_requests"),"https_requests",t.get("https_requests"),"cache_complete",t.get("cache_complete"));print(t.get("log_tail","")[-400:])
