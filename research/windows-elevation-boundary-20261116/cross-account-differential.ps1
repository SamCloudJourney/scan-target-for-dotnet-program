# Authorized Windows CI cross-account *ACL differential* with disposable fixtures.
# The actual SDK broker is started only by the pre-elevated runneradmin test harness.
# This is NOT interactive UAC consent or a standard-user named-pipe client.
param([Parameter(Mandatory=$true)][string]$SdkVersion)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$uid=[guid]::NewGuid().ToString('N')
$account='bb'+$uid.Substring(0,12)
$root=Join-Path $env:PUBLIC ('broker-cross-'+$uid)
$client=Join-Path $root 'client'
$protected=Join-Path $root 'admin-only'
$provider='IsolatedCrossAccount.'+$uid
$cacheIdJunction='SandboxJunction.'+$uid
$cacheIdBroad='SandboxBroad.'+$uid
$cacheRoot=Join-Path $env:ProgramData 'dotnet\workloads'
$cachedJunction=Join-Path (Join-Path (Join-Path $cacheRoot $cacheIdJunction) '1.0.0') 'fixture-admin-only.dat'
$cachedBroad=Join-Path (Join-Path (Join-Path $cacheRoot $cacheIdBroad) '1.0.0') 'fixture-broad-only.dat'
$lowCacheRecord=Join-Path $client 'standard-cache-read.json'
$cacheSourceHashes=@{}
$localRecord=Join-Path $client 'standard-user-probe.json'
$report=Join-Path $env:RUNNER_TEMP ('cross-account-'+$SdkVersion+'.json')
$brokerReport=Join-Path $env:RUNNER_TEMP ('broker-process-'+$SdkVersion+'.json')
$created=$false
$summary=[ordered]@{
  timestampUtc=(Get-Date).ToUniversalTime().ToString('o')
  sdkVersion=$SdkVersion
  test='standard user ACL versus actual pre-authorized administrator broker'
  noInteractiveUac=$true
  noStandardUserBrokerIpc=$true
  status='RUNNING'
  lowAccount=$account
  lowSid=$null
  lowRecord=$null
  lowCacheReadRecord=$null
  cacheRootInitiallyExists=(Test-Path -LiteralPath $cacheRoot)
  cacheMovePerformedByLiveBroker=$false
  postCacheReadByLowUser=$null
  adminBrokerCaseIds=@()
  errors=@()
  cleanup=@()
}
try {
  New-Item -ItemType Directory -Path $root,$client,$protected -Force | Out-Null
  foreach($sub in @('home','roaming','local','temp')) {
    New-Item -ItemType Directory -Path (Join-Path $root $sub) -Force | Out-Null
  }
  $password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))+'Aa1!'
  Write-Host ('::add-mask::'+$password)
  $secure=ConvertTo-SecureString $password -AsPlainText -Force
  New-LocalUser -Name $account -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
  $created=$true
  $sid=(Get-LocalUser -Name $account).SID.Value
  $summary.lowSid=$sid
  $rootAcl=@('*S-1-5-32-544:(OI)(CI)F','*S-1-5-18:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)RX')
  & icacls.exe $root /inheritance:r /grant:r $rootAcl | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Failed to set isolated root ACL'}
  & icacls.exe $protected /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Failed to set admin-only ACL'}
  $clientGrant=('*{0}:(OI)(CI)M' -f $sid)
  & icacls.exe $client /grant:r $clientGrant | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Failed to grant isolated standard-owned client directory'}
  foreach($sub in @('home','roaming','local','temp')) {
    & icacls.exe (Join-Path $root $sub) /grant:r $clientGrant | Out-Null
    if($LASTEXITCODE -ne 0){throw ('Failed to authorize fixture profile path '+$sub)}
  }
  [IO.File]::WriteAllText((Join-Path $protected 'canary.log'),'ADMIN-ONLY-CANARY-'+$uid)
  # Every file below is a random, disposable sentinel owned by the test administrator.
  # The low account cannot read this protected source folder.
  $adminPayload=Join-Path $protected 'fixture-admin-only.dat'
  $broadPayload=Join-Path $protected 'fixture-broad-only.dat'
  [IO.File]::WriteAllText($adminPayload,'ISOLATED-SECRET-JUNCTION-'+$uid)
  [IO.File]::WriteAllText($broadPayload,'ISOLATED-SECRET-BROAD-'+$uid)
  @{Payload='fixture-admin-only.dat'} | ConvertTo-Json -Compress | Set-Content (Join-Path $protected 'fixture-junction.msi.json') -Encoding utf8
  @{Payload='fixture-broad-only.dat'} | ConvertTo-Json -Compress | Set-Content (Join-Path $protected 'fixture-broad.msi.json') -Encoding utf8
  $cacheSourceHashes.junction=(Get-FileHash -Algorithm SHA256 -LiteralPath $adminPayload).Hash
  $cacheSourceHashes.broad=(Get-FileHash -Algorithm SHA256 -LiteralPath $broadPayload).Hash
  if((Test-Path -LiteralPath (Join-Path $cacheRoot $cacheIdJunction)) -or
     (Test-Path -LiteralPath (Join-Path $cacheRoot $cacheIdBroad))){
    throw 'Refusing collision with pre-existing workload cache entries'
  }
  $probe=Join-Path $PSScriptRoot 'cross-account-low-probe.ps1'
  $pwsh=Join-Path $PSHOME 'pwsh.exe'
  $creds=[pscredential]::new(("$env:COMPUTERNAME\"+$account),$secure)
  $argsText=('-NoProfile -NonInteractive -File "{0}" -Client "{1}" -Protected "{2}" -Provider "{3}" -Output "{4}"' -f $probe,$client,$protected,$provider,$localRecord)
  $stdout=Join-Path $client 'low.stdout'
  $stderr=Join-Path $client 'low.stderr'
  $args=@{
    FilePath=$pwsh;ArgumentList=$argsText;Credential=$creds;WorkingDirectory=$root
    Wait=$true;PassThru=$true;RedirectStandardOutput=$stdout;RedirectStandardError=$stderr
    Environment=@{
      DOTNET_CLI_HOME=(Join-Path $root 'home')
      DOTNET_NOLOGO='1'
      DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1'
      APPDATA=(Join-Path $root 'roaming')
      LOCALAPPDATA=(Join-Path $root 'local')
      HOME=(Join-Path $root 'home')
      USERPROFILE=(Join-Path $root 'home')
      TEMP=(Join-Path $root 'temp')
      TMP=(Join-Path $root 'temp')
    }
  }
  $lowProc=Start-Process @args
  $summary.lowProcessExitCode=$lowProc.ExitCode
  if(-not (Test-Path -LiteralPath $localRecord)) {
    $log=[IO.File]::ReadAllText($stdout)+[IO.File]::ReadAllText($stderr)
    throw ('Low user output absent, exit code '+$lowProc.ExitCode+': '+$log.Substring(0,[Math]::Min(800,$log.Length)))
  }
  $observations=Get-Content -Raw -LiteralPath $localRecord | ConvertFrom-Json
  $summary.lowRecord=$observations
  if($lowProc.ExitCode -ne 0 -or $observations.isAdministrator -or !$observations.canWriteOwn -or
     !$observations.directProtectedWriteDenied -or !$observations.protectedPayloadReadDenied -or !$observations.registryWriteDenied) {
    throw 'Low-user ACL negative controls were not upheld'
  }
  if(!$observations.junctionCreated -or !$observations.linkedProtectedWriteDenied) {
    $summary.status='JUNCTION_BLOCKED_OR_UNCERTAIN'
    throw 'Standard user did not establish a usable, denied-write junction into admin-only scratch'
  }
  Write-Host ('LOW-SID='+$sid+' LOW_DIRECT_DENIED=True LOW_JUNCTION_CREATED=True LOW_LINK_DENIED=True LOW_HKLM_DENIED=True')
  $env:BROKER_CROSS_CLIENT=$client
  $env:BROKER_CROSS_PROTECTED=$protected
  $env:BROKER_CROSS_PROVIDER=$provider
  $env:BROKER_CROSS_CACHE_JUNCTION_ID=$cacheIdJunction
  $env:BROKER_CROSS_CACHE_BROAD_ID=$cacheIdBroad
  $project=Join-Path $PSScriptRoot 'BrokerHarness\BrokerHarness.csproj'
  & dotnet build $project -c Release --nologo
  if($LASTEXITCODE -ne 0){throw 'BrokerHarness build failed'}
  $exe=Join-Path $PSScriptRoot 'BrokerHarness\bin\Release\net11.0\BrokerHarness.dll'
  & dotnet $exe $SdkVersion
  if($LASTEXITCODE -ne 0){throw 'BrokerHarness returned a failure'}
  if(-not (Test-Path -LiteralPath $brokerReport)) {throw 'Broker JSON missing'}
  $broker=Get-Content -Raw -LiteralPath $brokerReport | ConvertFrom-Json
  $expected=@(
    '11-standard-owned-client-direct-protected-control',
    '12-standard-created-junction-admin-canary-modified',
    '13-admin-broker-changes-standard-denied-HKLM',
    '13-disposable-provider-cleanup',
    '11-overbroad-root-admin-only-canary-modified',
    '12-standard-created-junction-admin-cache-moved',
    '11-broad-root-admin-cache-moved'
  )
  foreach($id in $expected) {
    $case=@($broker.cases | Where-Object {$_.id -eq $id})
    if($case.Count -ne 1 -or !$case[0].passed) { throw ('Missing or failing cross-account broker case: '+$id) }
    $summary.adminBrokerCaseIds+= $id
  }
  $summary.brokerStatus=$broker.status
  $summary.cacheMovePerformedByLiveBroker=$true
  if(!(Test-Path -LiteralPath $cachedJunction) -or !(Test-Path -LiteralPath $cachedBroad)){
    throw 'Broker cache destinations missing after reported successful IPC operations'
  }
  $postRead=Join-Path $PSScriptRoot 'cross-account-cache-postread.ps1'
  $lowReadArgs=('-NoProfile -NonInteractive -File "{0}" -CacheJunction "{1}" -CacheBroad "{2}" -Output "{3}"' -f $postRead,$cachedJunction,$cachedBroad,$lowCacheRecord)
  $postOut=Join-Path $client 'postread.stdout'
  $postErr=Join-Path $client 'postread.stderr'
  $postParams=@{
    FilePath=$pwsh;ArgumentList=$lowReadArgs;Credential=$creds;WorkingDirectory=$root
    Wait=$true;PassThru=$true;RedirectStandardOutput=$postOut;RedirectStandardError=$postErr
    Environment=@{
      DOTNET_CLI_HOME=(Join-Path $root 'home')
      APPDATA=(Join-Path $root 'roaming')
      LOCALAPPDATA=(Join-Path $root 'local')
      HOME=(Join-Path $root 'home')
      USERPROFILE=(Join-Path $root 'home')
      TEMP=(Join-Path $root 'temp')
      TMP=(Join-Path $root 'temp')
    }
  }
  $secondLow=Start-Process @postParams
  if($secondLow.ExitCode -ne 0 -or !(Test-Path -LiteralPath $lowCacheRecord)){
    throw ('Low-user post-cache read probe did not complete cleanly; exit='+$secondLow.ExitCode)
  }
  $lowReads=Get-Content -LiteralPath $lowCacheRecord -Raw | ConvertFrom-Json
  if($lowReads.isAdministrator -or $lowReads.sid -ne $sid){throw 'Post-read process did not use standard-user identity'}
  $summary.lowCacheReadRecord=$lowReads
  $junctionProbe=@($lowReads.probes | Where-Object {$_.name -eq 'junction'})
  $broadProbe=@($lowReads.probes | Where-Object {$_.name -eq 'broad'})
  $summary.postCacheReadByLowUser=[ordered]@{
    junction=(($junctionProbe.Count -eq 1) -and $junctionProbe[0].readable -and ($junctionProbe[0].sha256 -eq $cacheSourceHashes.junction))
    broad=(($broadProbe.Count -eq 1) -and $broadProbe[0].readable -and ($broadProbe[0].sha256 -eq $cacheSourceHashes.broad))
  }
  Write-Host ('LOW_CACHE_READ_RESULT: junction='+$summary.postCacheReadByLowUser.junction+' broad='+$summary.postCacheReadByLowUser.broad)

  $summary.adminBrokerIdentity=$broker.environment.runnerUser
  $summary.adminBrokerSid=$broker.environment.runnerSid
  $summary.status='COMPLETED'
  Write-Host 'CROSS_ACCOUNT_RESULT=COMPLETED'
} catch {
  if($summary.status -eq 'RUNNING'){$summary.status='ERROR'}
  $summary.errors += $_.Exception.ToString()
  Write-Host ('CROSS_ACCOUNT_RESULT='+$summary.status+' '+$_.Exception.Message)
} finally {
  # Remove only our unique, randomly-named .NET workload cache fixtures.
  # Never recurse on the package cache root or unknown package identifiers.
  foreach($id in @($cacheIdJunction,$cacheIdBroad)) {
    try {
      if(!$id.StartsWith('SandboxJunction.') -and !$id.StartsWith('SandboxBroad.')) {
        throw 'Refusing to clean non-fixture package ID'
      }
      $exact=Join-Path $cacheRoot $id
      if(Test-Path -LiteralPath $exact) {
        Remove-Item -LiteralPath $exact -Recurse -Force -ErrorAction Stop
        $summary.cleanup += ('removed only generated workload cache ID '+$id)
      }
    } catch {$summary.errors+=('Isolated cache cleanup error: '+$_.Exception.Message)}
  }
  try {
    $link=Join-Path $client 'junction'
    if(Test-Path -LiteralPath $link){
      & cmd.exe /c ('rmdir "'+$link+'"') | Out-Null
      $summary.cleanup += 'removed only fixture junction'
    }
  } catch {$summary.errors+=('Junction cleanup error: '+$_.Exception.Message)}
  try {
    $key='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Dependencies\'+$provider
    if(Test-Path -LiteralPath $key) {
      Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop
      $summary.cleanup += 'removed only generated provider fixture'
    }
  } catch {$summary.errors+=('Registry cleanup error: '+$_.Exception.Message)}
  try {
    if($created) {
      Remove-LocalUser -Name $account -ErrorAction Stop
      $summary.cleanup += 'removed generated standard-user account'
    }
  } catch {$summary.errors+=('User cleanup error: '+$_.Exception.Message)}
  try {
    if(Test-Path -LiteralPath $root) {
      Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
      $summary.cleanup += 'removed generated scratch directories'
    }
  } catch {$summary.errors+=('Scratch cleanup error: '+$_.Exception.Message)}
  $summary | ConvertTo-Json -Depth 8 | Set-Content -Path $report -Encoding utf8
  Write-Host ('EVIDENCE_FILE='+$report)
  Write-Host ('RUN_STATUS='+$summary.status)
}
if($summary.status -ne 'COMPLETED'){ exit 1 }
