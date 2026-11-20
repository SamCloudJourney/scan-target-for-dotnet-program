import base64
import http.server
import http.client
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
print("CHECKPOINT openssl certificate", flush=True)
subprocess.run(cert_cmd, check=True, capture_output=True, text=True, timeout=20)
print("CHECKPOINT certificate generated", flush=True)
DER = ROOT / "localhost-cert.cer"
subprocess.run([openssl, "x509", "-in", str(CERT), "-outform", "der", "-out", str(DER)], check=True, capture_output=True, text=True, timeout=20)
print("CHECKPOINT certificate converted", flush=True)
print("CHECKPOINT machine root trust begin", flush=True)
trust = subprocess.run(["certutil", "-f", "-addstore", "Root", str(DER)], capture_output=True, text=True, timeout=20)
print("CHECKPOINT machine root trust end", trust.returncode, flush=True)
if trust.returncode != 0:
    print("CERT_IMPORT_STDOUT", trust.stdout, flush=True)
    print("CERT_IMPORT_STDERR", trust.stderr, flush=True)
    raise RuntimeError("Test certificate import failed")
print("TRUSTED_TEST_CERT_RESULT", trust.stdout.strip(), flush=True)

print("CHECKPOINT sdk list begin", flush=True)
sdk_text = subprocess.run(["dotnet", "--list-sdks"], check=True, capture_output=True, text=True, timeout=20).stdout
print("INSTALLED_SDKS", sdk_text.strip(), flush=True)
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
            expected = "Basic " + base64.b64encode(MARKER.encode()).decode()
            if self.headers.get("Authorization") != expected:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="f056-index"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = json.dumps({"version": "3.0.0", "resources": [{"@id": self.server.resource_url, "@type": "PackageBaseAddress/3.0.0"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/protected":
            expected = "Basic " + base64.b64encode(MARKER.encode()).decode()
            if self.headers.get("Authorization") == expected:
                body = b"F056_PROTECTED_CANARY"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        if self.path.startswith("/flat/") and hasattr(self.server, "redirect_url"):
            self.send_response(302)
            self.send_header("Location", self.server.redirect_url + self.path[len("/flat/"):])
            self.send_header("Content-Length", "0")
            self.end_headers()
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

def protected_status(source_port, authorization):
    conn = http.client.HTTPSConnection("localhost", source_port, context=ssl.create_default_context(), timeout=5)
    try:
        conn.request("GET", "/protected", headers={"Authorization": authorization} if authorization else {})
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()

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
        elif endpoint == "redirect_https":
            resource_url = "https://localhost:" + str(source.server_port) + "/flat/"
            source.redirect_url = "https://127.0.0.1:" + str(sink.server_port) + "/flat/"
        elif endpoint == "https_ip":
            resource_url = "https://127.0.0.1:" + str(sink.server_port) + "/flat/"
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
        print("CHECKPOINT restore begin", sdk, name, repeat, flush=True)
        try:
            result = subprocess.run(command, cwd=case, env=env, capture_output=True, text=True, timeout=40)
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            out = exc.stdout or b""
            err = exc.stderr or b""
            result = subprocess.CompletedProcess(command, 124, out.decode(errors="replace") if isinstance(out, bytes) else out, err.decode(errors="replace") if isinstance(err, bytes) else err)
        print("CHECKPOINT restore end", sdk, name, repeat, "timed_out=" + str(timed_out), flush=True)
        source_flat_auth = decoded_auth([r for r in source.seen if r["path"].startswith("/flat/")])
        sink_auth = decoded_auth(sink.seen)
        captured = next((r["authorization"] for r in sink.seen if r["authorization"] and MARKER in decoded_auth([r])), None)
        denied_status = protected_status(source.server_port, None)
        replay_status = protected_status(source.server_port, captured) if captured else None
        authorized_index_requests = sum(r["path"] == "/index.json" and MARKER in decoded_auth([r]) for r in source.seen)
        record = {"authorized_index_requests": authorized_index_requests, "sdk": sdk, "case": name, "repeat": repeat, "command": command, "source_url": source_url, "resource_url": resource_url, "source_flat_requests": len(source_flat_auth), "source_flat_basic_decoded": source_flat_auth, "sink_requests": len(sink.seen), "sink_basic_decoded": sink_auth, "protected_denied_status": denied_status, "protected_replay_status": replay_status, "source_redirect_requests": sum(r["path"].startswith("/flat/") for r in source.seen), "exit": result.returncode, "timed_out": timed_out, "stdout_tail": result.stdout[-1400:], "stderr_tail": result.stderr[-1000:]}
        print("F056_CASE", json.dumps(record, sort_keys=True), flush=True)
        assert denied_status == 401, "protected resource did not deny anonymous access"
        if captured:
            assert replay_status == 200, "captured credential did not unlock protected resource"
        if include_credentials:
            assert authorized_index_requests > 0, "configured credential did not authenticate index"
        else:
            assert authorized_index_requests == 0 and not sink.seen, "anonymous index reached advertised resource"
        if name == "same_origin":
            assert MARKER in source_flat_auth and not sink.seen, "same-origin credential baseline failed"
        elif name in ("cross_https", "cross_https_ip"):
            assert MARKER in sink_auth, "cross-HTTPS credential observation failed"
        elif name == "redirect_https":
            assert source.redirect_url and any(r["path"].startswith("/flat/") for r in source.seen), "no source redirect"
            assert sink.seen, "redirect did not reach sink"
        elif name == "redirect_https_no_credentials":
            assert MARKER not in sink_auth and replay_status is None, "no credential control failed"
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
    run_case(major, sdk, "redirect_https", "redirect_https", True, False, 1)
    run_case(major, sdk, "redirect_https", "redirect_https", True, False, 2)
    run_case(major, sdk, "redirect_https_no_credentials", "redirect_https", False, False, 1)
print("F056_REDIRECT_ASSERTIONS_PASSED")
