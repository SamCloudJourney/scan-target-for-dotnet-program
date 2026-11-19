# Separate real STANDARD USER token on an isolated GitHub Windows runner.
# Run the UNMODIFIED read-only "dotnet workload list" and create an exact
# normal-client-shaped <temp>/<GUID>/data/msi.json fixture. Replace only its own
# data directory with an NTFS junction. No elevation or actual broker IPC.
param(
  [Parameter(Mandatory=$true)][string]$SdkVersion,
  [Parameter(Mandatory=$true)][string]$DotnetExe,
  [Parameter(Mandatory=$true)][string]$BroadRoot,
  [Parameter(Mandatory=$true)][string]$ClientRoot,
  [Parameter(Mandatory=$true)][string]$ProtectedDir,
  [Parameter(Mandatory=$true)][string]$PinnedCwd,
  [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$guid=[guid]::NewGuid().ToString('N')
$extraction=Join-Path $ClientRoot $guid
$dataPath=Join-Path $extraction 'data'
$original=Join-Path $extraction 'data-owned-original'
$junction=Join-Path $extraction 'data'
$pathThroughLink=Join-Path $junction 'msi.json'
$protectedSource=Join-Path $ProtectedDir 'msi.json'
$report=[ordered]@{
  utc=(Get-Date).ToUniversalTime().ToString('o')
  sdkVersion=$SdkVersion
  status='RUNNING'
  sid=$identity.User.Value
  user=$identity.Name
  isAdministrator=$isAdmin
  clientRoot=$ClientRoot
  broadRoot=$BroadRoot
  normalGuid=$guid
  extractionDirectory=$extraction
  createdDataJunction=$junction
  clientDerivedManifestPath=$pathThroughLink
  originalExtractedManifestPath=(Join-Path $original 'msi.json')
  protectedReadDenied=$false
  protectedWriteDenied=$false
  linkedProtectedReadDenied=$false
  lowOwnExtractCreated=$false
  dataJunctionCreated=$false
  narrowTempMatches=$false
  broadTempMatches=$false
  workloadListCommand='dotnet workload list (read-only)'
  workloadListExitCode=-999
  workloadListStdout=''
  workloadListStderr=''
  workloadRecordHKLMPath='SOFTWARE\Microsoft\dotnet\InstalledWorkloads\Standalone'
  workloadRecordKeyPresent=$null
  workloadRecordWritableByLowUser=$null
  workloadRecordProbeResult=''
  errors=@()
}
try {
  if($isAdmin){throw 'Refusing test: this is not a standard-user token'}
  $protectedData=Join-Path $ProtectedDir 'protected.dat'
  try{
    $null=[IO.File]::ReadAllBytes($protectedSource)
    throw 'Unexpectedly read administrator-only source'
  }catch [UnauthorizedAccessException]{$report.protectedReadDenied=$true}
  catch [Security.SecurityException]{$report.protectedReadDenied=$true}
  try{
    [IO.File]::AppendAllText($protectedData,'LOW-UNEXPECTED')
    throw 'Unexpectedly wrote administrator-only data'
  }catch [UnauthorizedAccessException]{$report.protectedWriteDenied=$true}
  catch [Security.SecurityException]{$report.protectedWriteDenied=$true}
  New-Item -ItemType Directory -Path $dataPath -Force|Out-Null
  [IO.File]::WriteAllText((Join-Path $dataPath 'msi.json'),'{"Payload":"low-owned-disposable.dat"}')
  [IO.File]::WriteAllText((Join-Path $dataPath 'low-owned-disposable.dat'),'OWNED-EXTRACTION-'+$guid)
  $report.lowOwnExtractCreated=(Test-Path -LiteralPath (Join-Path $dataPath 'msi.json'))
  if(!$report.lowOwnExtractCreated){throw 'Failed normal client-shaped extraction setup'}
  Rename-Item -LiteralPath $dataPath -NewName 'data-owned-original'
  if(Test-Path -LiteralPath $dataPath){throw 'Post-rename junction destination unexpectedly exists'}
  $linkOutput=(& cmd.exe /c ('mklink /J "'+$junction+'" "'+$ProtectedDir+'"') 2>&1 | Out-String)
  $report.dataJunctionCreated=($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $junction))
  if(!$report.dataJunctionCreated){throw ('Standard user could not create junction: '+$linkOutput)}
  try{
    $null=[IO.File]::ReadAllBytes($pathThroughLink)
    throw 'Unexpectedly read administrator-only data through junction'
  }catch [UnauthorizedAccessException]{$report.linkedProtectedReadDenied=$true}
  catch [Security.SecurityException]{$report.linkedProtectedReadDenied=$true}
  $oldTmp=$env:TMP;$oldTemp=$env:TEMP
  try {
    $env:TMP=$ClientRoot;$env:TEMP=$ClientRoot
    $report.narrowTempMatches=([IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -eq
      [IO.Path]::GetFullPath($ClientRoot).TrimEnd('\'))
    $env:TMP=$BroadRoot;$env:TEMP=$BroadRoot
    $report.broadTempMatches=([IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -eq
      [IO.Path]::GetFullPath($BroadRoot).TrimEnd('\'))
    # Real unmodified CLI, but READ-ONLY; never an install, repair or uninstall.
    $psi=[Diagnostics.ProcessStartInfo]::new($DotnetExe)
    $psi.ArgumentList.Add('workload')
    $psi.ArgumentList.Add('list')
    $psi.WorkingDirectory=$PinnedCwd
    $psi.UseShellExecute=$false
    $psi.CreateNoWindow=$true
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.Environment['DOTNET_CLI_HOME']=$ClientRoot
    $psi.Environment['DOTNET_NOLOGO']='1'
    $psi.Environment['DOTNET_SKIP_FIRST_TIME_EXPERIENCE']='1'
    $child=[Diagnostics.Process]::new()
    $child.StartInfo=$psi
    if(!$child.Start()){throw 'Normal workload list did not launch'}
    $outputTask=$child.StandardOutput.ReadToEndAsync()
    $errorTask=$child.StandardError.ReadToEndAsync()
    if(!$child.WaitForExit(30000)){
      $child.Kill($true);$child.WaitForExit()
      throw 'Normal workload list timed out'
    }
    $report.workloadListExitCode=$child.ExitCode
    $stdout=$outputTask.GetAwaiter().GetResult()
    $stderr=$errorTask.GetAwaiter().GetResult()
    $report.workloadListStdout=$stdout.Substring(0,[Math]::Min(1500,$stdout.Length))
    $report.workloadListStderr=$stderr.Substring(0,[Math]::Min(1500,$stderr.Length))
    $child.Dispose()
  } finally {$env:TMP=$oldTmp;$env:TEMP=$oldTemp}
  # Query the exact *real* SDK workload-registry root without creating or
  # altering keys. Missing root is recorded as INCONCLUSIVE, never a denial.
  try {
    $hklm=[Microsoft.Win32.RegistryKey]::OpenBaseKey(
      [Microsoft.Win32.RegistryHive]::LocalMachine,
      [Microsoft.Win32.RegistryView]::Registry64)
    try {
      $readable=$hklm.OpenSubKey($report.workloadRecordHKLMPath,$false)
      if($null -eq $readable){
        $report.workloadRecordKeyPresent=$false
        $report.workloadRecordProbeResult='ABSENT_IN_THIS_RUNNER_NO_CONCLUSION'
      } else {
        $report.workloadRecordKeyPresent=$true
        $readable.Dispose()
        try {
          $writable=$hklm.OpenSubKey($report.workloadRecordHKLMPath,$true)
          $report.workloadRecordWritableByLowUser=($null -ne $writable)
          if($writable){$writable.Dispose()}
        } catch [UnauthorizedAccessException]{$report.workloadRecordWritableByLowUser=$false}
        catch [Security.SecurityException]{$report.workloadRecordWritableByLowUser=$false}
        $report.workloadRecordProbeResult='EXISTING_ROOT_OPENED_NO_MUTATIONS'
      }
    } finally {$hklm.Dispose()}
  }catch{$report.workloadRecordProbeResult='REGISTRY_QUERY_ERROR: '+$_.Exception.GetType().Name}
  if(!$report.protectedReadDenied -or !$report.protectedWriteDenied -or
      !$report.linkedProtectedReadDenied -or !$report.dataJunctionCreated -or
      !$report.narrowTempMatches -or !$report.broadTempMatches -or
      !$report.lowOwnExtractCreated -or $report.workloadListExitCode -ne 0){
    throw 'A baseline negative control or read-only normal client test failed'
  }
  $report.status='COMPLETED'
  Write-Host ('NORMAL_CLIENT_READ_ONLY_EXIT='+$report.workloadListExitCode)
  Write-Host ('NORMAL_SHAPED_DATA_JUNCTION='+$report.dataJunctionCreated)
  Write-Host ('WORKLOAD_RECORD_QUERY='+$report.workloadRecordProbeResult)
} catch {
  $report.status='ERROR'
  $report.errors+=$_.Exception.ToString()
  Write-Host ('LOW_USER_ERROR='+$_.Exception)
} finally {
  $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $Output -Encoding utf8
  Write-Host ('LOW_PROBE_EVIDENCE='+$Output)
  Write-Host ('LOW_PROBE_STATUS='+$report.status)
}
if($report.status -ne 'COMPLETED'){exit 1}
