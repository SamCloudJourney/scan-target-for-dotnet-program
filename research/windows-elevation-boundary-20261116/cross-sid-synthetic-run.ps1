# Disposable Windows Server 2022 CI proof of actual cross-SID SDK broker transport.
# Requires the CI runner's already-administrator token to arrange a synthetic parent
# relationship. This is NOT a real UAC consent workflow, and CANNOT be reported as such.
param([Parameter(Mandatory=$true)][string]$SdkVersion)
$ErrorActionPreference="Stop"
$ProgressPreference="SilentlyContinue"
$id=[guid]::NewGuid().ToString("N")
$account="zbb"+$id.Substring(0,10)
$root=Join-Path $env:PUBLIC ("synthetic-cross-sid-"+$id)
$client=Join-Path $root "client"
$adminFolder=Join-Path $root "admin-only"
$sandboxHome=Join-Path $root "home"
$cwd=Join-Path $root "sdk-pinned"
$control=Join-Path $client "broker-pid.txt"
$lowReport=Join-Path $client "low-cross-sid.json"
$launcherReport=Join-Path $env:RUNNER_TEMP ("synthetic-launch-"+$SdkVersion+".json")
$report=Join-Path $env:RUNNER_TEMP ("cross-sid-synthetic-"+$SdkVersion+".json")
$cacheId="SandboxCrossSid."+$id
$provider="SandboxCrossSidProvider."+$id
$cacheFolder=Join-Path (Join-Path $env:ProgramData "dotnet\workloads") $cacheId
$protectedPayload=Join-Path $adminFolder "protected-payload.dat"
$harnessDll=Join-Path $PSScriptRoot "CrossSidHarness\bin\Release\net11.0\CrossSidHarness.dll"
$created=$false
$lowProcess=$null
$summary=[ordered]@{
  sdkVersion=$SdkVersion;timestampUtc=(Get-Date).ToUniversalTime().ToString("O")
  status="RUNNING";actualUacConsent=$false;syntheticParentByAdminController=$true
  testDescription="Real shipped SDK broker, real distinct low user client, controlled synthetic process parent"
  lowUserSid=$null;adminRunnerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  lowReport=$null;launcherResult=$null;actualProtectedSourceRemoved=$false
  cachedPayloadMatchesProtectedSource=$false;installedProductUntouched=$true
  registryProviderCreated=$false;cleanup=@();errors=@()
}
try {
  New-Item -ItemType Directory -Force -Path $root,$client,$adminFolder,$sandboxHome,$cwd | Out-Null
  $password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))+"A!9x"
  Write-Host ("::add-mask::"+$password)
  $secure=ConvertTo-SecureString $password -AsPlainText -Force
  New-LocalUser -Name $account -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
  $created=$true
  $sid=(Get-LocalUser -Name $account).SID.Value
  $summary.lowUserSid=$sid
  & icacls.exe $root /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
  if($LASTEXITCODE -ne 0){throw "Cannot set scratch parent ACL"}
  $grant=("*{0}:(OI)(CI)M" -f $sid)
  & icacls.exe $client /grant:r $grant | Out-Null
  if($LASTEXITCODE -ne 0){throw "Cannot authorize disposable client directory"}
  & icacls.exe $sandboxHome /grant:r $grant | Out-Null
  if($LASTEXITCODE -ne 0){throw "Cannot authorize disposable home directory"}
  & icacls.exe $adminFolder /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
  if($LASTEXITCODE -ne 0){throw "Cannot secure protected fixture"}
  [IO.File]::WriteAllText($protectedPayload,"ADMIN-FIXTURE-CROSS-SID-"+$id)
  $sourceHash=(Get-FileHash -LiteralPath $protectedPayload -Algorithm SHA256).Hash
  [IO.File]::WriteAllText((Join-Path $adminFolder "fixture.msi.json"),'{"Payload":"protected-payload.dat"}')
  @{sdk=@{version=$SdkVersion;rollForward="disable"}} | ConvertTo-Json -Depth 3 -Compress |
     Set-Content -LiteralPath (Join-Path $cwd "global.json") -Encoding utf8
  if(Test-Path -LiteralPath $cacheFolder){throw "Refuse preexisting workload cache ID"}
  $dotnet=(Get-Command dotnet.exe).Source
  if(-not (Test-Path -LiteralPath $harnessDll)){throw "CrossSidHarness build output missing"}
  # Avoid starting a real workload broker while Windows Update Agent is already active.
  $service=& sc.exe query wuauserv | Out-String
  if($service -match 'STATE\s+:\s+\d+\s+RUNNING'){
    $summary.status="SKIPPED_WU_SERVICE_ACTIVE"
    throw "Windows Update service active; refuse disruptive broker launch"
  }
  $creds=[pscredential]::new(("$env:COMPUTERNAME\"+$account),$secure)
  # low-parent takes seven arguments after the selector: sdk,client,admin,control,cache,provider,report.
  $lowArgs=('"{0}" low-parent "{1}" "{2}" "{3}" "{4}" "{5}" "{6}" "{7}"' -f
    $harnessDll,$SdkVersion,$client,$adminFolder,$control,$cacheId,$provider,$lowReport)
  $lowStart=@{
    FilePath=$dotnet;ArgumentList=$lowArgs;Credential=$creds;WorkingDirectory=$cwd
    PassThru=$true;RedirectStandardOutput=(Join-Path $client "low.stdout")
    RedirectStandardError=(Join-Path $client "low.stderr")
    Environment=@{
      DOTNET_CLI_HOME=$sandboxHome;DOTNET_NOLOGO="1";HOME=$sandboxHome
      TMP=$client;TEMP=$client;USERPROFILE=$sandboxHome
      APPDATA=$sandboxHome;LOCALAPPDATA=$sandboxHome
    }
  }
  $lowProcess=Start-Process @lowStart
  $ready=Join-Path $client "low-parent-ready"
  $deadline=(Get-Date).AddSeconds(35)
  while(!(Test-Path -LiteralPath $ready) -and (Get-Date) -lt $deadline){
    if($lowProcess.HasExited){break}
    Start-Sleep -Milliseconds 150
  }
  if(!(Test-Path -LiteralPath $ready)){
    $log=@()
    foreach($path in @((Join-Path $client "low.stdout"),(Join-Path $client "low.stderr"))){
      if(Test-Path -LiteralPath $path){$log+=[IO.File]::ReadAllText($path)}
    }
    throw ("Standard-user dotnet parent did not prepare; exit="+$lowProcess.HasExited+" "+($log -join " ").Substring(0,[Math]::Min(1000,($log -join " ").Length)))
  }
  $lowPid=[int](Get-Content -LiteralPath $ready -Raw).Trim()
  if($lowPid -ne $lowProcess.Id){throw "Standard parent PID mismatched"}
  $launcherArgs=@("admin-launch",$SdkVersion,$lowPid,$client,$cwd,$control,$launcherReport)
  & $dotnet $harnessDll @launcherArgs
  $launchExit=$LASTEXITCODE
  if(Test-Path -LiteralPath $launcherReport){
    $launcher=Get-Content -LiteralPath $launcherReport -Raw | ConvertFrom-Json
    $summary.launcherResult=$launcher
  }
  if($launchExit -ne 0){
    $summary.status="SYNTHETIC_LAUNCH_UNAVAILABLE"
    throw "Controlled process creation was rejected by runner platform or token, exit="+$launchExit
  }
  if(-not $lowProcess.WaitForExit(65000)){
    $summary.status="LOW_CLIENT_TIMEOUT"
    throw "Real standard-user IPC probe timed out"
  }
  $summary.lowExit=$lowProcess.ExitCode
  if(!(Test-Path -LiteralPath $lowReport)){
    throw "Standard-user JSON result missing; exit code="+$lowProcess.ExitCode
  }
  $low=Get-Content -LiteralPath $lowReport -Raw | ConvertFrom-Json
  $summary.lowReport=$low
  $summary.actualProtectedSourceRemoved=!(Test-Path -LiteralPath $protectedPayload)
  $cached=Join-Path $cacheFolder "1.0.0\protected-payload.dat"
  if(Test-Path -LiteralPath $cached){
    $summary.cachedPayloadMatchesProtectedSource=((Get-FileHash -LiteralPath $cached -Algorithm SHA256).Hash -eq $sourceHash)
  }
  $regPath="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Dependencies\"+$provider
  $summary.registryProviderCreated=(Test-Path -LiteralPath $regPath)
  $summary.originalProtectedSha256=$sourceHash
  if($lowProcess.ExitCode -ne 0 -or $low.status -ne "COMPLETED" -or
    $low.environment.lowSid -ne $sid -or !$summary.actualProtectedSourceRemoved -or
    !$summary.cachedPayloadMatchesProtectedSource -or !$summary.registryProviderCreated) {
    throw "Actual cross-SID broker fixture results failed positive assertions"
  }
  $summary.status="COMPLETED_SYNTHETIC_CROSS_SID"
  Write-Host ("CROSS_SID_RESULT=COMPLETED_SYNTHETIC_CROSS_SID")
} catch {
  if($summary.status -eq "RUNNING"){$summary.status="ERROR"}
  $summary.errors+=$_.Exception.ToString()
  Write-Host ("CROSS_SID_RESULT="+$summary.status+" "+$_.Exception.Message)
} finally {
  try{
    if($lowProcess -and !$lowProcess.HasExited){
      Stop-Process -Id $lowProcess.Id -Force -ErrorAction Stop
      $summary.cleanup+="Stopped only generated low-user dotnet test process"
    }
  }catch{$summary.errors+=("Low-parent cleanup: "+$_.Exception.Message)}
  try{
    # Admin-only cleanup of this exact randomized package fixture.
    if($cacheId.StartsWith("SandboxCrossSid.") -and (Test-Path -LiteralPath $cacheFolder)){
      Remove-Item -LiteralPath $cacheFolder -Recurse -Force -ErrorAction Stop
      $summary.cleanup+="Removed exact generated dotnet workload cache fixture"
    }
  }catch{$summary.errors+=("Cache cleanup: "+$_.Exception.Message)}
  try{
    $reg="Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Dependencies\"+$provider
    if($provider.StartsWith("SandboxCrossSidProvider.") -and (Test-Path -LiteralPath $reg)){
      Remove-Item -LiteralPath $reg -Recurse -Force -ErrorAction Stop
      $summary.cleanup+="Removed exact generated registry provider"
    }
  }catch{$summary.errors+=("Registry cleanup: "+$_.Exception.Message)}
  try{
    $junction=Join-Path $client "linked-admin"
    if(Test-Path -LiteralPath $junction){
      & cmd.exe /c ('rmdir "'+$junction+'"') | Out-Null
      $summary.cleanup+="Removed generated junction"
    }
  }catch{$summary.errors+=("Junction cleanup: "+$_.Exception.Message)}
  try{
    if($created){
      Remove-LocalUser -Name $account -ErrorAction Stop
      $summary.cleanup+="Removed generated standard-user account"
    }
  }catch{$summary.errors+=("User cleanup: "+$_.Exception.Message)}
  try{
    if(Test-Path -LiteralPath $root){
      Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
      $summary.cleanup+="Removed generated scratch root"
    }
  }catch{$summary.errors+=("Scratch cleanup: "+$_.Exception.Message)}
  $summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $report -Encoding utf8
  Write-Host ("EVIDENCE_FILE="+$report)
  Write-Host ("RUN_STATUS="+$summary.status)
}
if($summary.status -ne "COMPLETED_SYNTHETIC_CROSS_SID"){exit 1}
