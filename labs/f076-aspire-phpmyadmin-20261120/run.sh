#!/usr/bin/env bash
set -euo pipefail
src="$GITHUB_WORKSPACE/labs/f076-aspire-phpmyadmin-20261120"
out="$RUNNER_TEMP/f076-results"
tool="$RUNNER_TEMP/f076-tools"
mkdir -p "$out" "$tool"
echo "runner=$(uname -a)" | tee "$out/environment.txt"
echo "initial_umask=$(umask)" | tee -a "$out/environment.txt"
dotnet --version | tee -a "$out/environment.txt"
curl --fail --location --retry 3 --silent --show-error "https://github.com/microsoft/aspire/releases/download/v17.0.0/aspire-cli-linux-x64-17.0.0.tar.gz" --output "$tool/aspire-cli.tar.gz"
sha256sum "$tool/aspire-cli.tar.gz" | tee "$out/cli-sha256.txt"
mkdir -p "$tool/aspire"
tar -xzf "$tool/aspire-cli.tar.gz" -C "$tool/aspire"
chmod +x "$tool/aspire/aspire"
cli="$tool/aspire/aspire"
"$cli" --version | tee "$out/cli-version.txt"
python3 -m pip install --disable-pip-version-check --quiet --target /tmp/f076-pydeps 'PyMySQL[rsa]==1.1.1'
cp "$src/reader.py" /tmp/f076-reader.py
chmod -R a+rX /tmp/f076-pydeps
chmod 755 /tmp/f076-reader.py
export ASPIRE_CLI_TELEMETRY_OPTOUT=1
export ASPIRE_VERSION_CHECK_DISABLED=true
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export ASPIRE_DASHBOARD_SUPPRESS_BROWSER_TOKEN_IN_OUTPUT=true
export ASPIRE_DASHBOARD_FRONTEND_BROWSERTOKEN="$(openssl rand -hex 32)"
echo "::add-mask::$ASPIRE_DASHBOARD_FRONTEND_BROWSERTOKEN"
app_pid=""
case_dir=""
mysql_port=""
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
sanitize_logs() {
  find "$src" -path '*/runtime-*/aspire.log' -type f -print0 | while IFS= read -r -d '' log; do
    base="$(basename "$(dirname "$log")")"
    python3 - "$log" "$out/$base-aspire.log" <<'PY'
import os, re, sys
s=open(sys.argv[1], encoding="utf-8", errors="replace").read()
for name in ("Parameters__f076one", "Parameters__f076two", "ASPIRE_DASHBOARD_FRONTEND_BROWSERTOKEN"):
    value=os.environ.get(name)
    if value: s=s.replace(value, "[REDACTED]")
s=re.sub(r"(/login[?]t=)[0-9a-fA-F]+", r"\1[REDACTED]", s)
s=re.sub(r"(?<![0-9a-fA-F])[0-9a-fA-F]{48,64}(?![0-9a-fA-F])", "[REDACTED]", s)
open(sys.argv[2], "w", encoding="utf-8").write(s)
PY
  done
}
cleanup() { stop_app; sanitize_logs; }
trap cleanup EXIT
reader() {
  sudo -u nobody -H /usr/bin/env -i PYTHONPATH=/tmp/f076-pydeps PATH=/usr/bin:/bin \
    /usr/bin/python3 /tmp/f076-reader.py "$@"
}
start_case() {
  local label="$1" mask="$2" single="$3"
  case_dir="$src/runtime-$label"
  mkdir "$case_dir"
  cp "$src/apphost.cs" "$case_dir/apphost.cs"
  export ASPIRE_HOME="$RUNNER_TEMP/f076-home-$label"
  export F076_SINGLE="$single"
  export Parameters__f076one="$(openssl rand -hex 24)"
  export Parameters__f076two="$(openssl rand -hex 24)"
  echo "::add-mask::$Parameters__f076one"
  echo "::add-mask::$Parameters__f076two"
  echo "case=$label configured_umask=$mask single=$single"
  (umask "$mask"; exec "$cli" run --apphost "$case_dir/apphost.cs" --isolated --non-interactive --nologo) > "$case_dir/aspire.log" 2>&1 &
  app_pid=$!
  local ready=false
  for attempt in $(seq 1 180); do
    local names
    names="$(docker ps --format '{{.Names}}')"
    if printf '%s\n' "$names" | grep -qx f076-mysql-one &&
       printf '%s\n' "$names" | grep -qx f076-phpmyadmin; then
      if [ "$single" = 1 ] || printf '%s\n' "$names" | grep -qx f076-mysql-two; then
        ready=true
        break
      fi
    fi
    if ! kill -0 "$app_pid" 2>/dev/null; then
      echo "AppHost exited in $label"
      return 20
    fi
    sleep 2
  done
  test "$ready" = true
  mysql_port="$(docker inspect f076-mysql-one --format '{{(index (index .NetworkSettings.Ports "3306/tcp") 0).HostPort}}')"
  test -n "$mysql_port"
  echo "containers_started=$label mysql_host_port=$mysql_port"
}
config_path() { docker inspect f076-phpmyadmin --format '{{range .Mounts}}{{if eq .Destination "/etc/phpmyadmin/config.user.inc.php"}}{{println .Source}}{{end}}{{end}}'; }
inspect_file() {
  local file="$1" label="$2"
  echo "file_mode_$label=$(stat -c '%a' "$file")" | tee -a "$out/permissions.txt"
  namei -l "$file" | tee -a "$out/permissions.txt"
  test "$(stat -c '%a' "$file")" = 644
  test "$(grep -c "\\['password'\\]" "$file")" = 2
  grep -Fq "$Parameters__f076one" "$file"
  grep -Fq "$Parameters__f076two" "$file"
  echo "owner_verified_two_synthetic_passwords=$label" | tee -a "$out/permissions.txt"
}
for iteration in 1 2; do
  label="default$iteration"
  start_case "$label" 022 0
  file="$(config_path)"
  test -n "$file"
  inspect_file "$file" "$label"
  for attempt in $(seq 1 90); do
    if PYTHONPATH=/tmp/f076-pydeps python3 /tmp/f076-reader.py owner-init "$file" "$mysql_port" > "$out/$label-owner-init.json" 2>/dev/null; then break; fi
    sleep 2
  done
  test -s "$out/$label-owner-init.json"
  reader deny "$file" "$mysql_port" | tee "$out/$label-denied.json"
  reader read "$file" "$mysql_port" | tee "$out/$label-cross-user.json"
  PYTHONPATH=/tmp/f076-pydeps python3 /tmp/f076-reader.py owner-check "$file" "$mysql_port" | tee "$out/$label-owner-after.json"
  chmod 600 "$file"
  reader read-permission "$file" "$mysql_port" | tee "$out/$label-file-0600.json"
  chmod 644 "$file"
  parent="$(dirname "$file")"
  chmod 700 "$parent"
  reader read-permission "$file" "$mysql_port" | tee "$out/$label-parent-0700.json"
  chmod 755 "$parent"
  stop_app
done
start_case secureumask 077 0
secure_file="$(config_path)"
test -n "$secure_file"
inspect_file "$secure_file" secureumask
reader read-permission "$secure_file" "$mysql_port" | tee "$out/secureumask-cross-user.json"
stop_app
start_case single 022 1
single_file="$(config_path)"
test -z "$single_file"
echo "single_instance_config_file_absent=true" | tee "$out/single.txt"
docker inspect f076-phpmyadmin --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -q '^PMA_PASSWORD='
echo "single_instance_uses_PMA_PASSWORD=true" | tee -a "$out/single.txt"
stop_app
echo "f076_lab_complete=true" | tee "$out/complete.txt"
