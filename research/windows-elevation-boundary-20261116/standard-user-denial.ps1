# Disposable local standard-user no-UAC negative control.
# A denial is evidence of the administrator gate; NOT an over-the-shoulder UAC simulation.
param([Parameter(Mandatory=$true)][string]$SdkVersion)
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:PUBLIC ('BrokerBoundaryNegative-' + [guid]::NewGuid().ToString('N'))
$user = 'bb' + ([guid]::NewGuid().ToString('N').Substring(0,12))
$reportPath = Join-Path $env:RUNNER_TEMP ("standard-user-no-uac-$SdkVersion.json")
$created = $false
$record = [ordered]@{
  sdkVersion=$SdkVersion
  timestampUtc=(Get-Date).ToUniversalTime().ToString('o')
  trial='Genuine dotnet workload elevate launched under disposable standard user with no UAC approval'
  status='RUNNING'
  standardUserSid=$null
  runnerIdentity=(& whoami.exe /user | Out-String)
  standardUserExitCode=$null
  consoleOutput=$null
  errors=@()
  cleanup=@()
}
try {
  New-Item -ItemType Directory -Path $work -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $work 'temp') -Force | Out-Null
  & icacls.exe $work /grant '*S-1-5-32-545:(OI)(CI)RX' /T | Out-Null
  if($LASTEXITCODE -ne 0) { throw 'Could not grant Users read permission to scratch folder' }
  @{sdk=@{version=$SdkVersion;rollForward='disable'}} | ConvertTo-Json -Depth 4 |
    Set-Content (Join-Path $work 'global.json') -Encoding utf8
  $secret = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)) + 'Aa1!'
  $secure = ConvertTo-SecureString $secret -AsPlainText -Force
  New-LocalUser -Name $user -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
  $created = $true
  $record.standardUserSid = (Get-LocalUser -Name $user).SID.Value
  $cred = [pscredential]::new("$env:COMPUTERNAME\$user", $secure)
  $dotnet = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
  $stdout = Join-Path $work 'child.out'
  $stderr = Join-Path $work 'child.err'
  $arg = 'workload elevate --client-temp "' + (Join-Path $work 'temp') + '"'
  $params = @{
    FilePath=$dotnet
    ArgumentList=$arg
    Credential=$cred
    WorkingDirectory=$work
    PassThru=$true
    Wait=$true
    RedirectStandardOutput=$stdout
    RedirectStandardError=$stderr
  }
  $p = Start-Process @params
  $record.standardUserExitCode = $p.ExitCode
  $output = [IO.File]::ReadAllText($stdout) + [IO.File]::ReadAllText($stderr)
  $record.consoleOutput = $output.Substring(0, [Math]::Min(2500,$output.Length))
  $record.status = if($p.ExitCode -ne 0){'EXPECTED_DENIAL'}else{'UNEXPECTED_SUCCESS'}
  Write-Host "Standard-user direct broker start exit=$($p.ExitCode), result=$($record.status)"
} catch {
  $record.status = 'HARNESS_ERROR'
  $record.errors += $_.Exception.ToString()
  Write-Host "HARNESS_ERROR: $($_.Exception.Message)"
} finally {
  try {
    if($created){ Remove-LocalUser -Name $user -ErrorAction Stop; $record.cleanup += 'disposable local user deleted' }
  } catch { $record.cleanup += "local user cleanup error: $($_.Exception.Message)" }
  try {
    if(Test-Path $work){Remove-Item $work -Recurse -Force -ErrorAction Stop; $record.cleanup += 'scratch files deleted' }
  } catch { $record.cleanup += "scratch cleanup error: $($_.Exception.Message)" }
  $record | ConvertTo-Json -Depth 8 | Set-Content $reportPath -Encoding utf8
  Write-Host "EVIDENCE_FILE=$reportPath"
  Write-Host "RUN_STATUS=$($record.status)"
}
if($record.status -ne 'EXPECTED_DENIAL'){ exit 1 }
