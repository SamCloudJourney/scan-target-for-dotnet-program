# Read-only post-cache observation under a disposable standard-user Windows token.
# All outputs are restricted to the user's own temporary evidence directory.
param(
  [Parameter(Mandatory=$true)][string]$CacheJunction,
  [Parameter(Mandatory=$true)][string]$CacheBroad,
  [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$data=[ordered]@{
  timestampUtc=(Get-Date).ToUniversalTime().ToString('o')
  user=$identity.Name; sid=$identity.User.Value
  isAdministrator=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  probes=@()
}
foreach($pair in @(@('junction',$CacheJunction),@('broad',$CacheBroad))) {
  $name=$pair[0];$path=$pair[1]
  $probe=[ordered]@{name=$name;path=$path;readable=$false;sha256=$null;error=$null}
  try {
    # Read the actual file under the SDK's machine-wide workload cache,
    # never a Windows/Program Files target or unrelated install.
    $bytes=[IO.File]::ReadAllBytes($path)
    $probe.sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
    $probe.readable=$true
  } catch {
    $probe.error=$_.Exception.GetType().FullName
  }
  $data.probes+= $probe
}
$data | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Output -Encoding utf8
Write-Host ("LOW_CACHE_PROBE "+($data.probes | ForEach-Object { $_.name+"="+$_.readable }) -join ",")
if($data.isAdministrator) { exit 1 }
