import base64
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import threading

ROOT = Path("f056-lab").resolve()
ROOT.mkdir(exist_ok=True)
MARKER_USER = "f056-synthetic-user"
MARKER_PASSWORD = "F056_SYNTHETIC_PASSWORD_20261120"
MARKER = MARKER_USER + ":" + MARKER_PASSWORD
CERT = ROOT / "localhost-cert.pem"
KEY = ROOT / "localhost-key.pem"

openssl = shutil.which("openssl")
if not openssl:
    candidate = Path("C:/Program Files/Git/usr/bin/openssl.exe")
    if candidate.exists():
        openssl = str(candidate)
if not openssl:
    raise RuntimeError("OpenSSL missing on runner")
cert_cmd = [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(KEY), "-out", str(CERT), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"]
subprocess.run(cert_cmd, check=True, capture_output=True, text=True)
DER = ROOT / "localhost-cert.cer"
subprocess.run([openssl, "x509", "-in", str(CERT), "-outform", "der", "-out", str(DER)], check=True, capture_output=True, text=True)
trust_script = "$c=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new('" + str(DER) + "'); $s=[System.Security.Cryptography.X509Certificates.X509Store]::new('Root',[System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser); $s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite); $s.Add($c); $s.Close(); $c.Thumbprint"
trust_cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-Command", trust_script]
trust = subprocess.run(trust_cmd, capture_output=True, text=True)
if trust.returncode != 0:
    print("CERT_IMPORT_STDOUT", trust.stdout)
    print("CERT_IMPORT_STDERR", trust.stderr)
    raise RuntimeError("Test certificate import failed")
print("TRUSTED_TEST_CERT_THUMBPRINT", trust.stdout.strip())

sdk_text = subprocess.run(["dotnet", "--list-sdks"], check=True, capture_output=True, text=True).stdout
print("INSTALLED_SDKS", sdk_text.strip())
sdk_versions = [line.split(" ", 1)[0] for line in sdk_text.splitlines()]
selected = {}
for major in (10, 11):
    matches = [v for v in sdk_versions if v.startswith(str(major) + ".")]
    if matches:
        selected[major] = matches[-1]
if 10 not in selected or 11 not in selected:
    raise RuntimeError("Both .NET 10 and .NET 11 SDKs are required")

class Recorder(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.seen.append({"path": self.path, "authorization": self.headers.get("Authorization")})
        if self.path == "/index.json" and hasattr(self.server, "resource_url"):
            body = json.dumps({"version": "3.0.0", "resources": [{"@id": self.server.resource_url, "@type": "PackageBaseAddress/3.0.0"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="f056-synthetic"')
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, format, *args):
        pass

def start_server(use_tls):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    server.seen = []
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(CERT), str(KEY))
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def decoded_auth(requests):
    output = []
    for row in requests:
        auth = row["authorization"]
        if auth and auth.startswith("Basic "):
            try:
                output.append(base64.b64decode(auth[6:]).decode("utf-8"))
            except Exception:
                output.append("<invalid Basic>")
    return output

def run_case(major, sdk, name, endpoint, include_credentials, allow_http, repeat):
    case = ROOT / (str(major) + "-" + name + "-" + str(repeat))
    case.mkdir()
    (case / "home").mkdir()
    (case / "packages").mkdir()
    (case / "cache").mkdir()
    (case / "global.json").write_text(json.dumps({"sdk": {"version": sdk}}))
    package = "F056.Probe." + str(major) + "." + name + "." + str(repeat)
    (case / "probe.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net' + str(major) + '.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="' + package + '" Version="1.0.0" /></ItemGroup></Project>')
    source = start_server(True)
    sink = start_server(endpoint != "http")
    try:
        source_url = "https://localhost:" + str(source.server_port) + "/index.json"
        if endpoint == "same":
            resource_url = "https://localhost:" + str(source.server_port) + "/flat/"
        elif endpoint == "http":
            resource_url = "http://localhost:" + str(sink.server_port) + "/flat/"
        else:
            resource_url = "https://localhost:" + str(sink.server_port) + "/flat/"
        source.resource_url = resource_url
        credentials = ""
        if include_credentials:
            credentials = '<packageSourceCredentials><synthetic><add key="Username" value="' + MARKER_USER + '"/><add key="ClearTextPassword" value="' + MARKER_PASSWORD + '"/></synthetic></packageSourceCredentials>'
        insecure = ' allowInsecureConnections="true"' if allow_http else ""
        (case / "NuGet.Config").write_text('<configuration><packageSources><clear/><add key="synthetic" value="' + source_url + '"' + insecure + '/></packageSources>' + credentials + '</configuration>')
        env = os.environ.copy()
        env.update({"DOTNET_CLI_HOME": str(case / "home"), "NUGET_PACKAGES": str(case / "packages"), "NUGET_HTTP_CACHE_PATH": str(case / "cache"), "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1", "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": ""})
        command = ["dotnet", "restore", "probe.csproj", "--configfile", "NuGet.Config", "--disable-parallel", "--no-cache", "--force", "--verbosity", "quiet"]
        result = subprocess.run(command, cwd=case, env=env, capture_output=True, text=True, timeout=90)
        source_flat_auth = decoded_auth([r for r in source.seen if r["path"].startswith("/flat/")])
        sink_auth = decoded_auth(sink.seen)
        record = {"sdk": sdk, "case": name, "repeat": repeat, "command": command, "source_url": source_url, "resource_url": resource_url, "source_flat_requests": len(source_flat_auth), "source_flat_basic_decoded": source_flat_auth, "sink_requests": len(sink.seen), "sink_basic_decoded": sink_auth, "exit": result.returncode, "stdout_tail": result.stdout[-1400:], "stderr_tail": result.stderr[-1000:]}
        print("F056_CASE", json.dumps(record, sort_keys=True), flush=True)
        if name == "same_origin":
            assert MARKER in source_flat_auth and not sink.seen, "same-origin credential baseline failed"
        elif name == "cross_https":
            assert MARKER in sink_auth, "cross-HTTPS credential observation failed"
        elif name == "cross_https_no_credentials":
            assert MARKER not in sink_auth, "no-credential control failed"
        elif name == "cross_http_default":
            assert not sink.seen and "NU1302" in result.stdout + result.stderr, "default downgrade guard failed"
        elif name == "cross_http_optin":
            assert MARKER in sink_auth, "explicit opt-in behavior failed"
    finally:
        source.shutdown()
        sink.shutdown()
        source.server_close()
        sink.server_close()

for major, sdk in selected.items():
    run_case(major, sdk, "same_origin", "same", True, False, 1)
    run_case(major, sdk, "cross_https", "https", True, False, 1)
    run_case(major, sdk, "cross_https", "https", True, False, 2)
    run_case(major, sdk, "cross_https_no_credentials", "https", False, False, 1)
    run_case(major, sdk, "cross_http_default", "http", True, False, 1)
    run_case(major, sdk, "cross_http_optin", "http", True, True, 1)
print("F056_ALL_ASSERTIONS_PASSED")
