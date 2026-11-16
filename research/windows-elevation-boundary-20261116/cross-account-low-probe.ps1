# Disposable STANDARD USER account experiment. Write only unique scratch objects.
param(
  [Parameter(Mandatory=$true)][string]$Client,
  [Parameter(Mandatory=$true)][string]$Protected,
  [Parameter(Mandatory=$true)][string]$Provider,
  [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$data=[ordered]@{
  timestampUtc=(Get-Date).ToUniversalTime().ToString('o')
  user=$identity.Name
  sid=$identity.User.Value
  isAdministrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  canWriteOwn=$false
  directProtectedWriteDenied=$false
  protectedPayloadReadDenied=$false
  protectedPayloadReadError=''
  linkedProtectedWriteDenied=$false
  junctionCreated=$false
  overbroadTempSelected=$false
  requestedTempRoot=''
  hardlinkCreated=$false
  hardlinkWriteDenied=$false
  hardlinkDetail=''
  registryWriteDenied=$false
  junctionDetail=''
  directError=''
  linkedError=''
  registryError=''
  tokenGroups=(& whoami.exe /groups | Out-String)
}
try {
  $owned=Join-Path $Client 'standard-user-owned-file.txt'
  [IO.File]::WriteAllText($owned,'LOW-OWNED-SCRATCH')
  $data.canWriteOwn=([IO.File]::ReadAllText($owned) -eq 'LOW-OWNED-SCRATCH')
  $canary=Join-Path $Protected 'canary.log'
  # SDK's actual client uses Path.GetTempPath() as its --client-temp argument.
  # A user may select a root that contains restricted children without owning them.
  $oldTmp=$env:TMP
  try {
    $requestedRoot=[IO.Path]::GetFullPath((Split-Path $Client -Parent))
    $env:TMP=$requestedRoot
    $selected=[IO.Path]::GetTempPath()
    $data.requestedTempRoot=$selected
    $data.overbroadTempSelected=([IO.Path]::GetFullPath($selected).TrimEnd([IO.Path]::DirectorySeparatorChar) -eq $requestedRoot.TrimEnd([IO.Path]::DirectorySeparatorChar))
  } finally {
    $env:TMP=$oldTmp
  }
  $secretFile=Join-Path $Protected 'fixture-admin-only.dat'
  try { $null=[IO.File]::ReadAllBytes($secretFile); $data.protectedPayloadReadError='unexpected read succeeded' }
  catch { $data.protectedPayloadReadDenied=$true; $data.protectedPayloadReadError=$_.Exception.GetType().Name }
  try { [IO.File]::AppendAllText($canary,'LOW-UNEXPECTED'); $data.directError='unexpected write succeeded' }
  catch { $data.directProtectedWriteDenied=$true; $data.directError=$_.Exception.GetType().Name }
  $link=Join-Path $Client 'junction'
  $junctionCmd=('mklink /J "' + $link + '" "' + $Protected + '"')
  $outputText=& cmd.exe /c $junctionCmd 2>&1 | Out-String
  $data.junctionDetail=$outputText.Substring(0,[Math]::Min($outputText.Length,900))
  $data.junctionCreated=(Test-Path -LiteralPath $link)
  if($data.junctionCreated) {
    try { [IO.File]::AppendAllText((Join-Path $link 'canary.log'),'LOW-LINK-UNEXPECTED'); $data.linkedError='unexpected write succeeded' }
    catch { $data.linkedProtectedWriteDenied=$true; $data.linkedError=$_.Exception.GetType().Name }
  }
  # Hard-link subvector: the unprivileged creator must pass Windows checks on
  # the target. A protected target may prevent link creation entirely.
  $hardlink=Join-Path $Client 'hardlink-canary.log'
  $hardlinkCmd=('mklink /H "' + $hardlink + '" "' + $canary + '"')
  $hardlinkText=& cmd.exe /c $hardlinkCmd 2>&1 | Out-String
  $data.hardlinkDetail=$hardlinkText.Substring(0,[Math]::Min(900,$hardlinkText.Length))
  $data.hardlinkCreated=(Test-Path -LiteralPath $hardlink)
  if($data.hardlinkCreated) {
    try { [IO.File]::AppendAllText($hardlink,'LOW-HARDLINK-UNEXPECTED') }
    catch { $data.hardlinkWriteDenied=$true }
  }
  try {
    $reg="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Dependencies\$Provider\Dependents\StandardClientProbe"
    New-Item -Path $reg -Force -ErrorAction Stop | Out-Null
    $data.registryError='unexpected registry write succeeded'
  } catch { $data.registryWriteDenied=$true; $data.registryError=$_.Exception.GetType().Name }
} catch {
  $data.globalError=$_.Exception.ToString()
} finally {
  $data | ConvertTo-Json -Depth 5 | Set-Content -Path $Output -Encoding utf8
  Write-Host ("LOW_ACCOUNT_RECORD="+$Output)
}
if($data.isAdministrator -or !$data.canWriteOwn -or !$data.directProtectedWriteDenied -or !$data.protectedPayloadReadDenied -or !$data.registryWriteDenied){ exit 1 }
if($data.junctionCreated -and !$data.linkedProtectedWriteDenied){exit 1}
if($data.hardlinkCreated -and !$data.hardlinkWriteDenied){exit 1}
