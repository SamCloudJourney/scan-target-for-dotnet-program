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
  linkedProtectedWriteDenied=$false
  junctionCreated=$false
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
if($data.isAdministrator -or !$data.canWriteOwn -or !$data.directProtectedWriteDenied -or !$data.registryWriteDenied){ exit 1 }
if($data.junctionCreated -and !$data.linkedProtectedWriteDenied){exit 1}
