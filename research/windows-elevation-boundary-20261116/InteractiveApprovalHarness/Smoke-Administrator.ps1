# CI-only: real disposable Windows standard-user ACL smoke for fixture preparation.
# DOES NOT approve UAC, start a broker, or touch real installed software.
$ErrorActionPreference="Stop"
$ProgressPreference="SilentlyContinue"
$id=[guid]::NewGuid().ToString('N')
$account='smk'+$id.Substring(0,10)
$readyBefore=@(Get-ChildItem -LiteralPath $env:PUBLIC -Directory -Filter 'msrc-windows-elevation-lab-*' -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FullName)
$password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))+'Qa!8'
Write-Host ('::add-mask::'+$password)
$secret=ConvertTo-SecureString $password -AsPlainText -Force
$created=$false
$fixture=$null
$record=Join-Path $env:RUNNER_TEMP 'interactive-fixture-smoke.json'
$report=[ordered]@{
  timestampUtc=(Get-Date).ToUniversalTime().ToString('O')
  status='RUNNING'
  standardUserSid=$null
  source='Actual hosted Windows standard-user ACL differential and real fixture preparation; no UAC'
  lowChecks=$null
  setupErrors=@()
  cleanupErrors=@()
}
try{
  New-LocalUser -Name $account -Password $secret -PasswordNeverExpires -AccountNeverExpires|Out-Null
  $created=$true
  $sid=(Get-LocalUser -Name $account).SID.Value
  $report.standardUserSid=$sid
  $prep=Join-Path $PSScriptRoot 'Prepare-InteractiveFixture.ps1'
  & $prep -StandardUser ($env:COMPUTERNAME+'\'+$account) -SdkVersion '11.0.100' -SkipMsi
  if($LASTEXITCODE -notin @(0,$null)){throw 'Fixture setup returned nonzero code'}
  $now=@(Get-ChildItem -LiteralPath $env:PUBLIC -Directory -Filter 'msrc-windows-elevation-lab-*'|Select-Object -ExpandProperty FullName)
  $new=@($now|Where-Object{$_ -notin $readyBefore})
  if($new.Count -ne 1){throw ('Expected exactly one generated scratch fixture, got '+$new.Count)}
  $fixture=Join-Path (Join-Path $new[0] 'client') 'fixture.json'
  if(!(Test-Path -LiteralPath $fixture)){throw 'No fixture JSON'}
  $cfg=Get-Content -Raw -LiteralPath $fixture|ConvertFrom-Json
  if($cfg.CreatedBySid -ne $sid){throw 'Fixture SID mismatch'}
  $low=Join-Path $PSScriptRoot 'Smoke-LowUser.ps1'
  $evidence=Join-Path $cfg.ClientDir 'low-fixture-smoke.json'
  $creds=[pscredential]::new(($env:COMPUTERNAME+'\'+$account),$secret)
  $pwsh=Join-Path $PSHOME 'pwsh.exe'
  $args=('-NoLogo -NoProfile -NonInteractive -File "{0}" -FixtureConfig "{1}" -EvidencePath "{2}"' -f $low,$fixture,$evidence)
  $out=Join-Path $cfg.ClientDir 'smoke.stdout'
  $err=Join-Path $cfg.ClientDir 'smoke.stderr'
  $options=@{
    FilePath=$pwsh;ArgumentList=$args;Credential=$creds;WorkingDirectory=$cfg.ClientDir
    Wait=$true;PassThru=$true;RedirectStandardOutput=$out;RedirectStandardError=$err
    Environment=@{
      DOTNET_CLI_HOME=$cfg.ClientDir
      TMP=$cfg.ClientDir
      TEMP=$cfg.ClientDir
      HOME=$cfg.ClientDir
      USERPROFILE=$cfg.ClientDir
      APPDATA=$cfg.ClientDir
      LOCALAPPDATA=$cfg.ClientDir
    }
  }
  $p=Start-Process @options
  if(!(Test-Path -LiteralPath $evidence)){
    throw ('Low probe failed with exit='+$p.ExitCode+' '+([IO.File]::ReadAllText($out))+' '+([IO.File]::ReadAllText($err)))
  }
  $lowResult=Get-Content -LiteralPath $evidence -Raw|ConvertFrom-Json
  $report.lowChecks=$lowResult
  $passed= $p.ExitCode -eq 0 -and !$lowResult.isAdmin -and
    $lowResult.matchedPreparedSid -and $lowResult.createdRandomExtractionDirectory -and
    $lowResult.wroteInsideNewExtractionDirectory -and
    $lowResult.protectedReadDenied -and $lowResult.protectedWriteDenied -and
    $lowResult.clientJunctionCreated -and $lowResult.junctionProtectedReadDenied -and
    $lowResult.rootTempSelectionMatches
  if(!$passed){throw ('Fixture ACL test failed: '+($lowResult|ConvertTo-Json -Compress))}
  $report.status='COMPLETED'
  Write-Host 'LOW_USER_FIXTURE_SMOKE=COMPLETED'
}catch{
  $report.status='ERROR'
  $report.setupErrors+=$_.Exception.ToString()
  Write-Host ('LOW_USER_FIXTURE_SMOKE=ERROR '+$_.Exception.Message)
}finally{
  if($fixture -and (Test-Path -LiteralPath $fixture)){
    try{
      $verify=Join-Path $PSScriptRoot 'Verify-And-Cleanup.ps1'
      & $verify -FixtureConfig $fixture -EvidenceDirectory (Join-Path $env:RUNNER_TEMP ('fixture-verification-'+$id)) -Cleanup
    }catch{$report.cleanupErrors+=('Verification/cleanup: '+$_.Exception.Message)}
  }
  try{
    if($created){Remove-LocalUser -Name $account -ErrorAction Stop}
  }catch{$report.cleanupErrors+=('Account cleanup: '+$_.Exception.Message)}
  $report|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $record -Encoding utf8
  Write-Host ('EVIDENCE_FILE='+$record)
  Write-Host ('RUN_STATUS='+$report.status)
}
if($report.status -ne 'COMPLETED' -or $report.cleanupErrors.Count -gt 0){exit 1}
