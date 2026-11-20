#!/usr/bin/env bash
set -euo pipefail

root="$(mktemp -d /tmp/f042-apk.XXXXXX)"
chmod 711 "$root"
mobile="$root/Mobile"
mkdir -m 700 "$mobile"
dotnet new android -n F042Mobile -o "$mobile"
secret="$(openssl rand -hex 24)"
printf 'F042_SYNTH_SECRET=%s\n' "$secret" > "$root/secret.env"
chmod 600 "$root/secret.env"
sed -i 's#</Project>#<ItemGroup><AndroidEnvironment Include="'"${root}"'/secret.env" /></ItemGroup></Project>#' "$mobile/F042Mobile.csproj"
if grep -q '<ApplicationId>' "$mobile/F042Mobile.csproj"; then
    sed -i 's#<ApplicationId>.*</ApplicationId>#<ApplicationId>com.example.f042adb</ApplicationId>#' "$mobile/F042Mobile.csproj"
else
    sed -i '/<PropertyGroup>/a\    <ApplicationId>com.example.f042adb</ApplicationId>' "$mobile/F042Mobile.csproj"
fi
if ! dotnet build "$mobile/F042Mobile.csproj" -f net11.0-android -p:AndroidPackageFormat=apk --nologo > "$root/build.log" 2>&1; then
    tail -100 "$root/build.log"
    exit 1
fi
apk="$(find "$mobile/bin/Debug/net11.0-android" -name '*-Signed.apk' -print -quit)"
if [[ -z "$apk" ]]; then apk="$(find "$mobile/bin/Debug/net11.0-android" -name '*.apk' -print -quit)"; fi
echo "F042_OWNER_APK_FOUND=$([[ -f "$apk" ]] && echo True || echo False)"
if [[ ! -f "$apk" ]]; then tail -100 "$root/build.log"; exit 1; fi
adb devices
adb install -r "$apk"
echo "F042_OWNER_APK_PATH=$(adb shell pm path com.example.f042adb | head -1)"
sudo useradd -m -s /bin/bash f042_peer
echo "F042_OWNER_UID=$(id -u) F042_PEER_UID=$(id -u f042_peer)"
if sudo -u f042_peer test -r "$root/secret.env"; then echo F042_DIRECT_SECRET=READABLE; else echo F042_DIRECT_SECRET=DENIED; fi
adb_path="$(command -v adb)"
sudo -H -u f042_peer "$adb_path" devices
apk_path="$(sudo -H -u f042_peer "$adb_path" shell pm path com.example.f042adb | head -1 | sed 's/^package://')"
echo "F042_PEER_APK_PATH=$apk_path"
sudo -H -u f042_peer "$adb_path" pull "$apk_path" /home/f042_peer/base.apk
sudo -H -u f042_peer mkdir -p /home/f042_peer/extracted
sudo -H -u f042_peer unzip -qq /home/f042_peer/base.apk -d /home/f042_peer/extracted
if grep -R -a -F -q "$secret" /home/f042_peer/extracted; then echo F042_PEER_APK_CONTAINS_SECRET=True; else echo F042_PEER_APK_CONTAINS_SECRET=False; fi
echo "F042_PEER_APK_FILES=$(find /home/f042_peer/extracted -type f | wc -l)"
