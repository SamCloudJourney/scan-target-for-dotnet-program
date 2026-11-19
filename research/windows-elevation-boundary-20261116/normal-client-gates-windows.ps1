# Real Windows public runner: distinct low SID, unmodified read-only dotnet
# workload list, GUID/data/msi.json junction, actual SDK validator and ACL controls.
# All writes in exact randomly named scratch directory. NO broker or UAC approval.
param([Parameter(Mandatory=$true)][ValidateSet('10.0.404','11.0.100')][string]$SdkVersion)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$uid=[guid]::NewGuid().ToString('N')
$account='nc'+$uid.Substring(0,12)
$root=Join-Path $env:PUBLIC ('normal-client-gate-'+$uid)
$client=Join-Path $root 'client-temp'
$protected=Join-Path $root 'admin-only'
$pinned=Join-Path $root 'sdk-pinned'
$sandboxHome=Join-Path $root 'home'
$lowReport=Join-Path $client 'standard-user.json'
$report=Join-Path $env:RUNNER_TEMP ('normal-client-gates-'+$SdkVersion+'.json')
$validator=Join-Path $env:RUNNER_TEMP ('normal-shaped-validator-'+$SdkVersion+'.json')
$created=$false
$summary=[ordered]@{
  timestampUtc=(Get-Date).ToUniversalTime().ToString('o')
  sdkVersion=$SdkVersion;status='RUNNING'
  goal='Test normal-client source-relevant filesystem path shape and user token, not claim EoP'
  interactiveUacApproved=$false
  actualElevatedBrokerStarted=$false
  ordinaryClientUsedForReadOnlyWorkloadList=$false
  sdkValidatorUsed=$false
  genuineLowSid=$null
  adminSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  lowResult=$null
  validatorResult=$null
  fileIdentityMatched=$false
  protectedSourceSha256=$null
  protectedSourceAcl=$null
  errors=@()
  cleanup=@()
}
try {
  $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
  if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw 'Requires authorized disposable Windows runner administrator'
  }
  New-Item -ItemType Directory -Force -Path $root,$client,$protected,$pinned,$sandboxHome|Out-Null
  $password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))+'Xy9!'
  Write-Host ('::add-mask::'+$password)
  $secure=ConvertTo-SecureString $password -AsPlainText -Force
  New-LocalUser -Name $account -Password $secure -PasswordNeverExpires -AccountNeverExpires|Out-Null
  $created=$true
  $sid=(Get-LocalUser -Name $account).SID.Value
  $summary.genuineLowSid=$sid
  & icacls.exe $root /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'|Out-Null
  if($LASTEXITCODE -ne 0){throw 'Failed root ACL setup'}
  $createGrant=('*{0}:(WD,AD)' -f $sid)
  & icacls.exe $root /grant $createGrant '*S-1-3-0:(OI)(CI)(IO)F'|Out-Null
  if($LASTEXITCODE -ne 0){throw 'Failed root low-user subdir permission'}
  & icacls.exe $protected /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F'|Out-Null
  if($LASTEXITCODE -ne 0){throw 'Failed admin-only ACL'}
  $lowGrant=('*{0}:(OI)(CI)M' -f $sid)
  foreach($d in @($client,$sandboxHome)){
    & icacls.exe $d /grant:r $lowGrant|Out-Null
    if($LASTEXITCODE -ne 0){throw ('Failed low-user writable path ACL '+$d)}
  }
  & icacls.exe $pinned /grant:r ('*{0}:(OI)(CI)RX' -f $sid)|Out-Null
  if($LASTEXITCODE -ne 0){throw 'Failed SDK directory read ACL'}
  $protectedManifest=Join-Path $protected 'msi.json'
  [IO.File]::WriteAllText($protectedManifest,'{"Payload":"protected.dat"}')
  [IO.File]::WriteAllText((Join-Path $protected 'protected.dat'),'ADMIN-ONLY-FIXTURE-'+$uid)
  $summary.protectedSourceSha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $protectedManifest).Hash
  $summary.protectedSourceAcl=(Get-Acl -LiteralPath $protectedManifest).Sddl
  @{sdk=@{version=$SdkVersion;rollForward='disable'}}|ConvertTo-Json -Depth 4 -Compress|
    Set-Content -LiteralPath (Join-Path $pinned 'global.json') -Encoding utf8
  $dotnet=(Get-Command dotnet.exe -ErrorAction Stop).Source
  $dll=Join-Path (Split-Path $dotnet -Parent) ('sdk\'+$SdkVersion+'\dotnet.dll')
  if(!(Test-Path -LiteralPath $dll)){throw 'Installed SDK assembly not found'}
  $argsText=('-NoLogo -NoProfile -NonInteractive -File "{0}" -SdkVersion "{1}" -DotnetExe "{2}" -BroadRoot "{3}" -ClientRoot "{4}" -ProtectedDir "{5}" -PinnedCwd "{6}" -Output "{7}"' -f
    (Join-Path $PSScriptRoot 'normal-client-low-probe.ps1'),$SdkVersion,$dotnet,$root,$client,$protected,$pinned,$lowReport)
  $stdout=Join-Path $client 'low.stdout'
  $stderr=Join-Path $client 'low.stderr'
  $creds=[pscredential]::new(($env:COMPUTERNAME+'\'+$account),$secure)
  $lowProc=Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList $argsText -Credential $creds -WorkingDirectory $pinned -PassThru -Wait -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Environment @{
    DOTNET_CLI_HOME=$sandboxHome
    DOTNET_NOLOGO='1'
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1'
    TMP=$client
    TEMP=$client
    HOME=$sandboxHome
    USERPROFILE=$sandboxHome
    APPDATA=$sandboxHome
    LOCALAPPDATA=$sandboxHome
  }
  $summary.lowProcessExitCode=$lowProc.ExitCode
  if(!(Test-Path -LiteralPath $lowReport)){
    $detail=''
    foreach($name in @($stdout,$stderr)){
      if(Test-Path -LiteralPath $name){$detail+=([IO.File]::ReadAllText($name))}
    }
    throw ('No low-user JSON; exit '+$lowProc.ExitCode+' '+$detail.Substring(0,[Math]::Min($detail.Length,1600)))
  }
  $low=Get-Content -Raw -LiteralPath $lowReport|ConvertFrom-Json
  $summary.lowResult=$low
  $summary.ordinaryClientUsedForReadOnlyWorkloadList=($low.workloadListExitCode -eq 0)
  if($lowProc.ExitCode -ne 0 -or $low.status -ne 'COMPLETED' -or
    $low.sid -ne $sid -or $low.isAdministrator){
    throw ('Low-user run failed identity or ACL checks: '+($low|ConvertTo-Json -Compress -Depth 5))
  }
  $realFile=(& fsutil.exe file queryfileid $protectedManifest 2>&1|Out-String).Trim()
  $viaFile=(& fsutil.exe file queryfileid $low.clientDerivedManifestPath 2>&1|Out-String).Trim()
  $summary.fileIdDirect=$realFile
  $summary.fileIdViaJunction=$viaFile
  $summary.fileIdentityMatched=($realFile -eq $viaFile -and $realFile -match '0x[0-9a-f]+')
  if(!$summary.fileIdentityMatched){throw 'Normal-shaped path did not resolve to same protected NTFS file ID'}
  $project=Join-Path $PSScriptRoot 'NormalClientGateHarness\NormalClientGateHarness.csproj'
  & dotnet build $project -c Release --nologo
  if($LASTEXITCODE -ne 0){throw 'Failed C# normal-client validator build'}
  $harness=Join-Path $PSScriptRoot 'NormalClientGateHarness\bin\Release\net11.0\NormalClientGateHarness.dll'
  & dotnet $harness $SdkVersion $lowReport $protected $validator
  if($LASTEXITCODE -ne 0){throw 'Real SDK validator harness failed'}
  $validation=Get-Content -Raw -LiteralPath $validator|ConvertFrom-Json
  $summary.validatorResult=$validation
  $summary.sdkValidatorUsed=($validation.status -eq 'COMPLETED')
  if(!$summary.sdkValidatorUsed){throw 'SDK validator checks did not all pass'}
  $summary.status='COMPLETED'
  Write-Host ('NORMAL_CLIENT_GATES_STATUS=COMPLETED SDK='+$SdkVersion)
} catch{
  $summary.status='ERROR'
  $summary.errors+=$_.Exception.ToString()
  Write-Host ('NORMAL_CLIENT_GATES_STATUS=ERROR '+$_.Exception.Message)
} finally {
  try {
    $junctionCandidates=@()
    if($summary.lowResult){
      $junctionCandidates+=@($summary.lowResult.createdDataJunction)
    }
    foreach($link in $junctionCandidates){
      if($link -and (Test-Path -LiteralPath $link) -and
        [IO.Path]::GetFullPath($link).StartsWith(([IO.Path]::GetFullPath($client)+'\'),[StringComparison]::OrdinalIgnoreCase)){
        & cmd.exe /c ('rmdir "'+$link+'"')|Out-Null
        if($LASTEXITCODE -ne 0){throw 'Failed junction-point-only cleanup'}
        $summary.cleanup+='Deleted only disposable junction, not its target'
      }
    }
  }catch{$summary.errors+=('Link cleanup: '+$_.Exception.Message)}
  try{
    if($created){
      Remove-LocalUser -Name $account -ErrorAction Stop
      $summary.cleanup+='Deleted only generated standard-user test account'
    }
  }catch{$summary.errors+=('Account cleanup: '+$_.Exception.Message)}
  try {
    if(Test-Path -LiteralPath $root){
      Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
      $summary.cleanup+='Deleted isolated scratch root'
    }
  }catch{$summary.errors+=('Scratch cleanup: '+$_.Exception.Message)}
  $summary|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $report -Encoding utf8
  Write-Host ('EVIDENCE_FILE='+$report)
  Write-Host ('RUN_STATUS='+$summary.status)
}
if($summary.status -ne 'COMPLETED'){exit 1}
