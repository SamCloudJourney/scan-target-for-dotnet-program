#!/usr/bin/env bash
set -euo pipefail

# F-076: project AppHost in the ordinary shared /tmp tree, without chmod of
# any ancestor. The project uses the Aspire 17 supported C# AppHost layout.
src="$GITHUB_WORKSPACE/labs/f076-aspire-phpmyadmin-20261120"
out="$RUNNER_TEMP/f076-natural-results"
tool="$RUNNER_TEMP/f076-natural-tools"
mkdir -p "$out" "$tool/aspire"
printf 'runner=%s\ninitial_umask=%s\ntmp_mode=%s\n' \
  "$(uname -a)" "$(umask)" "$(stat -c %a /tmp)" > "$out/environment.txt"
dotnet --version >> "$out/environment.txt"
curl --fail --location --retry 3 --silent --show-error \
  https://github.com/microsoft/aspire/releases/download/v17.0.0/aspire-cli-linux-x64-17.0.0.tar.gz \
  --output "$tool/aspire-cli.tar.gz"
sha256sum "$tool/aspire-cli.tar.gz" > "$out/cli-sha256.txt"
tar -xzf "$tool/aspire-cli.tar.gz" -C "$tool/aspire"
chmod +x "$tool/aspire/aspire"
cli="$tool/aspire/aspire"
export PATH="$tool/aspire:$PATH"
"$cli" --version > "$out/cli-version.txt"
python3 -m pip install --disable-pip-version-check --quiet --target /tmp/f076-natural-pydeps 'PyMySQL[rsa]==1.1.1'
cp "$src/reader.py" /tmp/f076-natural-reader.py
chmod -R a+rX /tmp/f076-natural-pydeps
chmod 755 /tmp/f076-natural-reader.py

export ASPIRE_CLI_TELEMETRY_OPTOUT=1
export ASPIRE_VERSION_CHECK_DISABLED=true
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export ASPIRE_DASHBOARD_SUPPRESS_BROWSER_TOKEN_IN_OUTPUT=true
export ASPIRE_DASHBOARD_FRONTEND_BROWSERTOKEN="$(openssl rand -hex 32)"
echo "::add-mask::$ASPIRE_DASHBOARD_FRONTEND_BROWSERTOKEN"
app_pid=""
case_dir=""
current_label=""

sanitize_current() {
  if [ -n "$case_dir" ] && [ -f "$case_dir/aspire.log" ]; then
    python3 - "$case_dir/aspire.log" "$out/$current_label-aspire.log" <<'PY'
import os, re, sys
s = open(sys.argv[1], encoding='utf8', errors='replace').read()
for key in ('Parameters__f076one', 'Parameters__f076two', 'ASPIRE_DASHBOARD_FRONTEND_BROWSERTOKEN'):
    value = os.environ.get(key)
    if value:
        s = s.replace(value, '[REDACTED]')
s = re.sub(r'(/login[?]t=)[0-9a-fA-F]+', r'\1[REDACTED]', s)
s = re.sub(r'(?<![0-9a-fA-F])[0-9a-fA-F]{48,64}(?![0-9a-fA-F])', '[REDACTED]', s)
open(sys.argv[2], 'w', encoding='utf8').write(s)
PY
  fi
}

stop_app() {
  if [ -n "$app_pid" ]; then
    kill -TERM "$app_pid" 2>/dev/null || true
    for attempt in $(seq 1 15); do
      if ! kill -0 "$app_pid" 2>/dev/null; then break; fi
      sleep 1
    done
    kill -KILL "$app_pid" 2>/dev/null || true
    wait "$app_pid" 2>/dev/null || true
  fi
  docker rm -f f076-phpmyadmin f076-mysql-one f076-mysql-two >/dev/null 2>&1 || true
  app_pid=""
}

cleanup() {
  sanitize_current
  stop_app
  if [ -n "$case_dir" ] && [[ "$case_dir" == /tmp/f076-natural-* ]]; then
    rm -rf "$case_dir"
  fi
}
trap cleanup EXIT

reader() {
  sudo -u nobody -H /usr/bin/env -i PYTHONPATH=/tmp/f076-natural-pydeps PATH=/usr/bin:/bin \
    /usr/bin/python3 /tmp/f076-natural-reader.py "$@"
}

start_case() {
  current_label="$1"
  local mask="$2"
  case_dir="/tmp/f076-natural-$current_label-$GITHUB_RUN_ID"
  (umask "$mask"; mkdir "$case_dir"; tail -n +5 "$src/apphost.cs" > "$case_dir/AppHost.cs"; cat > "$case_dir/F076Natural.csproj" <<'XML'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <AspireUseCliBundle>true</AspireUseCliBundle>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Aspire.Hosting.AppHost" Version="17.0.0" />
    <PackageReference Include="Aspire.Hosting.MySql" Version="17.0.0" />
  </ItemGroup>
</Project>
XML
  )
  export Parameters__f076one="$(openssl rand -hex 24)"
  export Parameters__f076two="$(openssl rand -hex 24)"
  echo "::add-mask::$Parameters__f076one"
  echo "::add-mask::$Parameters__f076two"
  export ASPIRE_HOME="$RUNNER_TEMP/f076-natural-home-$current_label"
  echo "case=$current_label umask=$mask project=$case_dir" | tee -a "$out/environment.txt"
  (umask "$mask"; exec "$cli" run --apphost "$case_dir/F076Natural.csproj" --non-interactive --nologo) > "$case_dir/aspire.log" 2>&1 &
  app_pid=$!
  local ready=false
  for attempt in $(seq 1 180); do
    local names
    names="$(docker ps --format '{{.Names}}')"
    if printf '%s\n' "$names" | grep -qx f076-mysql-one &&
       printf '%s\n' "$names" | grep -qx f076-mysql-two &&
       printf '%s\n' "$names" | grep -qx f076-phpmyadmin; then
      ready=true
      break
    fi
    if ! kill -0 "$app_pid" 2>/dev/null; then
      echo "AppHost exited in $current_label"
      sanitize_current
      return 20
    fi
    sleep 2
  done
  test "$ready" = true
  local actual_port
  actual_port="$(docker inspect f076-mysql-one --format '{{(index (index .NetworkSettings.Ports "3306/tcp") 0).HostPort}}')"
  echo "actual_host_port=$actual_port" | tee -a "$out/$current_label-permissions.txt"
  test "$actual_port" = 13307
}

config_path() {
  docker inspect f076-phpmyadmin --format '{{range .Mounts}}{{if eq .Destination "/etc/phpmyadmin/config.user.inc.php"}}{{println .Source}}{{end}}{{end}}'
}

for iteration in 1 2; do
  label="default$iteration"
  start_case "$label" 022
  file="$(config_path)"
  test -n "$file"
  test "$(stat -c %a "$file")" = 644
  echo "file=$file" | tee -a "$out/$label-permissions.txt"
  namei -l "$file" | tee -a "$out/$label-permissions.txt"
  grep -Fq "$Parameters__f076one" "$file"
  grep -Fq "$Parameters__f076two" "$file"
  echo "owner_verified_two_synthetic_passwords=true" | tee -a "$out/$label-permissions.txt"

  # The local adversary is not passed either the file or the port. It finds
  # the file from /tmp and reads the fixed port from the readable AppHost.
  discovered="$(sudo -u nobody -H /usr/bin/env -i PATH=/usr/bin:/bin \
    /usr/bin/find /tmp -maxdepth 8 -type f -name 'f076mysqlone-config.user.inc.*.php' -print -quit 2>/dev/null || true)"
  echo "discovered_candidate=$discovered" | tee -a "$out/$label-permissions.txt"
  test "$discovered" = "$file"
  source_file="$(sudo -u nobody -H /usr/bin/env -i PATH=/usr/bin:/bin \
    /usr/bin/find /tmp -maxdepth 3 -type f -name AppHost.cs -print 2>/dev/null | head -1 || true)"
  echo "source_candidate=$source_file" | tee -a "$out/$label-permissions.txt"
  test "$source_file" = "$case_dir/AppHost.cs"
  discovered_port="$(sudo -u nobody -H /usr/bin/env -i PATH=/usr/bin:/bin \
    /usr/bin/grep -oE 'port: [0-9]+' "$source_file" | head -1 | cut -d' ' -f2)"
  test "$discovered_port" = 13307
  echo "second_principal_discovered_file=true" | tee -a "$out/$label-permissions.txt"
  echo "second_principal_discovered_fixed_port_from_source=true" | tee -a "$out/$label-permissions.txt"
  sudo -u nobody -H /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/test ! -r /var/run/docker.sock

  for attempt in $(seq 1 90); do
    if PYTHONPATH=/tmp/f076-natural-pydeps python3 /tmp/f076-natural-reader.py owner-init "$file" "$discovered_port" > "$out/$label-owner-init.json" 2>/dev/null; then break; fi
    sleep 2
  done
  test -s "$out/$label-owner-init.json"
  reader deny "$file" "$discovered_port" | tee "$out/$label-wrong-password.json"
  reader read "$discovered" "$discovered_port" | tee "$out/$label-cross-user.json"
  PYTHONPATH=/tmp/f076-natural-pydeps python3 /tmp/f076-natural-reader.py owner-check "$file" "$discovered_port" | tee "$out/$label-owner-after.json"
  chmod 600 "$file"
  reader read-permission "$file" "$discovered_port" | tee "$out/$label-file-0600.json"
  sanitize_current
  stop_app
  rm -rf "$case_dir"
  case_dir=""
done

start_case secureumask 077
secure_file="$(config_path)"
test -n "$secure_file"
test "$(stat -c %a "$secure_file")" = 644
namei -l "$secure_file" > "$out/secureumask-permissions.txt"
reader read-permission "$secure_file" 13307 | tee "$out/secureumask-denied.json"
sanitize_current
stop_app
echo 'f076_natural_lab_complete=true' | tee "$out/complete.txt"
