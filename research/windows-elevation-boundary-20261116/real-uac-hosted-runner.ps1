# Genuine UAC ShellExecute runas gate from a standard Windows user on an unattended runner.
# No credentials are supplied to the elevation request; no synthetic parent and no prompt approval.
param([Parameter(Mandatory=$true)][string]$SdkVersion)
$ErrorActionPreference="Stop"
$ProgressPreference="SilentlyContinue"
$uid=[guid]::NewGuid().ToString("N")
$account="uact"+$uid.Substring(0,10)
$root=Join-Path $env:PUBLIC ("uac-gate-"+$uid)
$client=Join-Path $root "client"
$sandboxHome=Join-Path $root "home"
$cwd=Join-Path $root "pinned-sdk"
$lowOutput=Join-Path $client "standard-user-uac.json"
$report=Join-Path $env:RUNNER_TEMP ("real-uac-gate-"+$SdkVersion+".json")
$created=$false
$lowProc=$null
$status="STARTING"
$issues=@()
$cleanup=@()
$info=[ordered]@{
  timestampUtc=(Get-Date).ToUniversalTime().ToString('o')
  sdkVersion=$SdkVersion
  status=$status
  source="real Windows ShellExecute runas from standard-user dotnet test process"
  interactiveAdministratorConsentProvided=$false
  syntheticParentUsed=$false
  lowAccount=$null
  lowSid=$null
  runnerAdminSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  lowProbePid=$null
  lowProbeExitCode=$null
  lowProbeTimedOut=$false
  lowEvidence=$null
  uacApprovedSessionProven=$false
  errors=@()
  cleanup=@()
}
try {
  if(-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw "Runner is not preauthorized administrator"
  }
  New-Item -ItemType Directory -Path $root,$client,$sandboxHome,$cwd -Force | Out-Null
  $password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))+"G7!q"
  Write-Host ("::add-mask::"+$password)
  $secure=ConvertTo-SecureString $password -AsPlainText -Force
  New-LocalUser -Name $account -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
  $created=$true
  $sid=(Get-LocalUser -Name $account).SID.Value
  $info.lowSid=$sid
  $info.lowAccount=$account
  & icacls.exe $root /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
  if($LASTEXITCODE -ne 0){throw "Scratch root ACL setup failed"}
  $lowGrant=("*{0}:(OI)(CI)M" -f $sid)
  & icacls.exe $client /grant:r $lowGrant | Out-Null
  if($LASTEXITCODE -ne 0){throw "Standard-user temp permission failed"}
  & icacls.exe $sandboxHome /grant:r $lowGrant | Out-Null
  if($LASTEXITCODE -ne 0){throw "Standard-user home permission failed"}
  @{sdk=@{version=$SdkVersion;rollForward="disable"}} |
    ConvertTo-Json -Depth 3 -Compress | Set-Content -LiteralPath (Join-Path $cwd "global.json") -Encoding utf8
  $serviceOutput=(& sc.exe query wuauserv | Out-String)
  $info.windowsUpdateInitiallyRunning=($serviceOutput -match 'STATE\s+:\s+\d+\s+RUNNING')
  if($info.windowsUpdateInitiallyRunning){
    $status="SKIPPED_WINDOWS_UPDATE_ACTIVE"
    throw "Refusing any potential broker start while Windows Update service is running"
  }
  $dotnet=(Get-Command dotnet.exe -ErrorAction Stop).Source
  $dotnetSdk=Join-Path (Split-Path $dotnet -Parent) ("sdk\"+$SdkVersion+"\dotnet.dll")
  if(-not (Test-Path -LiteralPath $dotnetSdk)){throw "Installed pinned .NET SDK assembly missing"}
  $info.installedSdkSha256=(Get-FileHash -LiteralPath $dotnetSdk -Algorithm SHA256).Hash
  $probe=Join-Path $PSScriptRoot "real-uac-low-user.ps1"
  $pwsh=Join-Path $PSHOME "pwsh.exe"
  $creds=[pscredential]::new(("$env:COMPUTERNAME\"+$account),$secure)
  $arguments=('-NoLogo -NoProfile -NonInteractive -File "{0}" -SdkVersion "{1}" -DotnetExe "{2}" -ClientTemp "{3}" -SdkPinnedCwd "{4}" -EvidencePath "{5}"' -f
    $probe,$SdkVersion,$dotnet,$client,$cwd,$lowOutput)
  $stdOut=Join-Path $client "low.stdout"
  $stdErr=Join-Path $client "low.stderr"
  $options=@{
    FilePath=$pwsh;ArgumentList=$arguments;Credential=$creds;WorkingDirectory=$cwd
    PassThru=$true;RedirectStandardOutput=$stdOut;RedirectStandardError=$stdErr
    Environment=@{
      DOTNET_CLI_HOME=$sandboxHome
      DOTNET_NOLOGO='1'
      HOME=$sandboxHome
      APPDATA=$sandboxHome
      LOCALAPPDATA=$sandboxHome
      USERPROFILE=$sandboxHome
      TMP=$client
      TEMP=$client
    }
  }
  $lowProc=Start-Process @options
  $info.lowProbePid=$lowProc.Id
  $status="LOW_PROCESS_STARTED"
  if(-not $lowProc.WaitForExit(35000)) {
    $info.lowProbeTimedOut=$true
    Stop-Process -Id $lowProc.Id -Force -ErrorAction Stop
    $cleanup+="Stopped only the generated low-user UAC probe after watchdog timeout"
  } else {
    $info.lowProbeExitCode=$lowProc.ExitCode
  }
  if(Test-Path -LiteralPath $lowOutput) {
    $low=Get-Content -Raw -LiteralPath $lowOutput | ConvertFrom-Json
    $info.lowEvidence=$low
    if($low.lowUserSid -ne $sid -or $low.lowUserIsAdministrator){
      throw "Expected standard-user token not observed"
    }
    switch ($low.status) {
      "RUNAS_SHELLEXECUTE_REJECTED" {$status="NO_UAC_APPROVAL_OBSERVED"}
      "RUNAS_EXCEPTION" {$status="RUNAS_EXCEPTION_WITHOUT_CONSENT"}
      "RUNAS_RETURNED_NO_PROCESS" {$status="RUNAS_RETURNED_NO_CHILD"}
      "RUNAS_RETURNED_CHILD_WITHOUT_TRACKED_CONSENT" {$status="UNVERIFIED_UAC_CHILD"}
      "RUNAS_CALLING" {if($info.lowProbeTimedOut){$status="UAC_PROMPT_HEADLESS_TIMEOUT"}else{$status="UNRESOLVED_RUNAS_CALL"}}
      default {$status="INCOMPLETE_LOW_PROBE"}
    }
  } else {
    $status="LOW_PROBE_RESULT_MISSING"
    foreach($file in @($stdOut,$stdErr)){
      if(Test-Path -LiteralPath $file){
        $msg=[IO.File]::ReadAllText($file)
        $issues+=("Low stdout/stderr: "+$msg.Substring(0,[Math]::Min($msg.Length,1500)))
      }
    }
  }
  Write-Host ("REAL_UAC_GATE="+$status)
} catch {
  if($status -in @("STARTING","LOW_PROCESS_STARTED")){$status="LAB_ERROR"}
  $issues+=$_.Exception.ToString()
  Write-Host ("REAL_UAC_GATE="+$status+" "+$_.Exception.Message)
} finally {
  try {
    if($lowProc -and !$lowProc.HasExited) {
      Stop-Process -Id $lowProc.Id -Force -ErrorAction Stop
      $cleanup+="Stopped owned standard-user probe"
    }
  } catch {$issues+=("Process cleanup: "+$_.Exception.Message)}
  try{
    if($created){
      Remove-LocalUser -Name $account -ErrorAction Stop
      $cleanup+="Deleted generated standard-user account"
    }
  }catch{$issues+=("User cleanup: "+$_.Exception.Message)}
  try {
    if(Test-Path -LiteralPath $root){
      Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
      $cleanup+="Deleted disposable scratch files"
    }
  } catch {$issues+=("Scratch cleanup: "+$_.Exception.Message)}
  $info.status=$status
  $info.errors=$issues
  $info.cleanup=$cleanup
  $info | ConvertTo-Json -Depth 11 | Set-Content -LiteralPath $report -Encoding utf8
  Write-Host ("EVIDENCE_FILE="+$report)
  Write-Host ("RUN_STATUS="+$status)
}
if($status -in @("NO_UAC_APPROVAL_OBSERVED","RUNAS_EXCEPTION_WITHOUT_CONSENT",
  "RUNAS_RETURNED_NO_CHILD","UNVERIFIED_UAC_CHILD","UAC_PROMPT_HEADLESS_TIMEOUT")){exit 0}
exit 1
