# Genuine Windows ShellExecute "runas" gate probe from a separately-created standard user.
# The test supplies no administrator credentials and DOES NOT auto-approve any UAC prompt.
# It does not connect to an elevated broker or modify any MSI, registry or protected file.
# The attempt can fail or time out on an unattended Windows GitHub-hosted runner.
param(
  [Parameter(Mandatory=$true)][string]$SdkVersion,
  [Parameter(Mandatory=$true)][string]$DotnetExe,
  [Parameter(Mandatory=$true)][string]$ClientTemp,
  [Parameter(Mandatory=$true)][string]$SdkPinnedCwd,
  [Parameter(Mandatory=$true)][string]$EvidencePath
)
$ErrorActionPreference="Stop"
$summary=[ordered]@{
  timestampUtc=(Get-Date).ToUniversalTime().ToString('o')
  sdkVersion=$SdkVersion
  experiment="actual standard-user ProcessStartInfo(Verb=runas, UseShellExecute=true), no consent automation"
  status="STARTING"
  interactiveAdminConsentProvided=$false
  syntheticParentProcessUsed=$false
  lowUserSid=$null
  lowUserAccount=$null
  lowUserIsAdministrator=$null
  lowUserSessionId=$null
  parentDotnetExecutable=$DotnetExe
  cliArguments=('workload elevate --client-temp "{0}"' -f $ClientTemp)
  requestedClientTemp=$ClientTemp
  sourceParity="InstallClientElevationContext.Elevate uses same runas+UseShellExecute+CLI arguments"
  operatingSystem=$env:OS
  uacEnableLUA=$null
  consentPromptBehaviorUser=$null
  promptOnSecureDesktop=$null
  ordinaryDirectBrokerExitCode=$null
  ordinaryDirectBrokerOutput=$null
  actualRunasStartCalled=$false
  actualRunasReturnedProcessId=$null
  actualRunasWin32Code=$null
  actualRunasException=$null
  actualRunasStartedProcessExit=$null
  actualRunasCalledAtUtc=$null
  observations=@()
  errors=@()
}
function Save {
  $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidencePath -Encoding utf8
}
try {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $summary.lowUserSid=$identity.User.Value
  $summary.lowUserAccount=$identity.Name
  $summary.lowUserIsAdministrator=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $summary.lowUserSessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId
  if($summary.lowUserIsAdministrator){ throw "This probe must execute as a non-administrator." }
  $regPath='HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  foreach($item in @(@('EnableLUA','uacEnableLUA'),@('ConsentPromptBehaviorUser','consentPromptBehaviorUser'),@('PromptOnSecureDesktop','promptOnSecureDesktop'))){
    try {
      $value=[Microsoft.Win32.Registry]::GetValue($regPath,$item[0],$null)
      $summary[$item[1]]=$value
    } catch { $summary.observations+=('Could not read UAC registry policy '+$item[0]+': '+$_.Exception.GetType().Name) }
  }
  if(!(Test-Path -LiteralPath $DotnetExe)){throw "Pinned dotnet.exe not found"}
  if(!(Test-Path -LiteralPath $SdkPinnedCwd)){throw "Pinned SDK test cwd not found"}
  $summary.status="DIRECT_NEGATIVE_CONTROL"
  Save
  # Direct low-privilege launch must be denied; this is distinct from UAC.
  $pinfo=[Diagnostics.ProcessStartInfo]::new($DotnetExe)
  $pinfo.Arguments=$summary.cliArguments
  $pinfo.WorkingDirectory=$SdkPinnedCwd
  $pinfo.UseShellExecute=$false
  $pinfo.CreateNoWindow=$true
  $pinfo.RedirectStandardOutput=$true
  $pinfo.RedirectStandardError=$true
  $direct=[Diagnostics.Process]::new()
  $direct.StartInfo=$pinfo
  if(!$direct.Start()){ throw "Direct control did not start child" }
  if(!$direct.WaitForExit(13000)){
    $direct.Kill($true)
    $summary.observations+="Direct launch timed out; killed only probe's own child."
  } else {
    $summary.ordinaryDirectBrokerExitCode=$direct.ExitCode
  }
  $directOutput=$direct.StandardOutput.ReadToEnd()+$direct.StandardError.ReadToEnd()
  $summary.ordinaryDirectBrokerOutput=$directOutput.Substring(0,[Math]::Min($directOutput.Length,1000))
  $direct.Dispose()
  # Precisely replicate .NET SDK's ShellExecute-based UAC request, with no admin creds.
  $summary.actualRunasStartCalled=$true
  $summary.actualRunasCalledAtUtc=(Get-Date).ToUniversalTime().ToString('o')
  $summary.status="RUNAS_CALLING"
  Save
  $start=[Diagnostics.ProcessStartInfo]::new($DotnetExe)
  $start.Arguments=$summary.cliArguments
  $start.WorkingDirectory=$SdkPinnedCwd
  $start.Verb="runas"
  $start.UseShellExecute=$true
  $start.CreateNoWindow=$true
  $start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
  try {
    $child=[Diagnostics.Process]::Start($start)
    if($null -eq $child){ $summary.status="RUNAS_RETURNED_NO_PROCESS" }
    else {
      $summary.actualRunasReturnedProcessId=$child.Id
      # Do not permit a headless runner to leave any broker running. No IPC is sent.
      if(!$child.WaitForExit(3000)){
        $child.Kill($true)
        $summary.observations+="RunAs unexpectedly returned a child process; killed only this newly created child."
      } else {
        $summary.actualRunasStartedProcessExit=$child.ExitCode
      }
      $summary.status="RUNAS_RETURNED_CHILD_WITHOUT_TRACKED_CONSENT"
    }
    if($null -ne $child){$child.Dispose()}
  } catch [ComponentModel.Win32Exception] {
    $summary.actualRunasWin32Code=$_.Exception.NativeErrorCode
    $summary.actualRunasException=$_.Exception.Message
    $summary.status="RUNAS_SHELLEXECUTE_REJECTED"
  } catch {
    $summary.actualRunasException=$_.Exception.ToString()
    $summary.status="RUNAS_EXCEPTION"
  }
} catch {
  $summary.errors+=$_.Exception.ToString()
  $summary.status="LAB_ERROR"
} finally {
  Save
  Write-Host ("REAL_UAC_GATE="+$summary.status)
  Write-Host ("DIRECT_NONADMIN_EXIT="+$summary.ordinaryDirectBrokerExitCode)
  Write-Host ("RUNAS_NATIVE_ERROR="+$summary.actualRunasWin32Code)
  Write-Host ("EVIDENCE_FILE="+$EvidencePath)
}
# A clean negative result is a completed test, not evidence of privilege escalation.
if($summary.status -in @("RUNAS_SHELLEXECUTE_REJECTED","RUNAS_EXCEPTION","RUNAS_RETURNED_NO_PROCESS","RUNAS_RETURNED_CHILD_WITHOUT_TRACKED_CONSENT")){exit 0}
exit 1
