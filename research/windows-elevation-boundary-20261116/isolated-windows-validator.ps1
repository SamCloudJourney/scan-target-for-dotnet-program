# Windows workload broker: isolated path-validation regression harness.
# Only disposable folders under RUNNER_TEMP are modified.
# This executes SDK path-validator methods, NOT the workload elevation broker.
param([Parameter(Mandatory=$true)][string]$SdkVersion)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$timestamp = (Get-Date).ToUniversalTime().ToString("o")
$testRoot = Join-Path $env:RUNNER_TEMP ("workload-boundary-" + [guid]::NewGuid().ToString("N"))
$reportPath = Join-Path $env:RUNNER_TEMP ("windows-elevation-" + $SdkVersion + ".json")
$report = [ordered]@{
  sdkVersion=$SdkVersion; timestamp=$timestamp; runnerOS=$env:RUNNER_OS;
  status="RUNNING"; evidenceType="real SDK validator invoked by reflection, no broker / UAC invocation";
  cases=@(); errors=@(); environment=[ordered]@{}
}
function Add-Case([string]$id,[bool]$passed,[string]$observation,[string]$limitations="") {
  $script:report.cases += [ordered]@{id=$id;passed=$passed;observation=$observation;limitations=$limitations}
  Write-Host ("TEST " + $id + ": " + $(if($passed){"PASS"}else{"FAIL"}) + " " + $observation)
}
function Invoke-SdkValidator($m,[object[]]$argsList) {
  return [string]$m.Invoke($null,$argsList)
}
try {
  New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
  $client = Join-Path $testRoot "client"
  $server = Join-Path $testRoot "server"
  $outside = Join-Path $testRoot "isolated-outside"
  $other = Join-Path $testRoot "other"
  @($client,$server,$outside,$other) | ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }
  $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($ident)
  $report.environment.user = $ident.Name
  $report.environment.sid = $ident.User.Value
  $report.environment.isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $report.environment.uacEnableLUA = try { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA } catch { $null }
  $report.environment.token = (& whoami /all | Out-String)
  $dotnet = (Get-Command dotnet).Source
  $root = if($env:DOTNET_ROOT){$env:DOTNET_ROOT}else{Split-Path $dotnet}
  $dll = Join-Path $root ("sdk\" + $SdkVersion + "\dotnet.dll")
  if(-not(Test-Path -LiteralPath $dll)) { throw "SDK CLI assembly not found at $dll" }
  $report.environment.dotnet = $dotnet
  $report.environment.cliAssembly = $dll
  $report.environment.cliSha256 = (Get-FileHash -Algorithm SHA256 $dll).Hash
  $report.environment.installedSdks = (& dotnet --list-sdks | Out-String)
  $asm = [Reflection.Assembly]::LoadFrom($dll)
  $utils = $asm.GetType("Microsoft.DotNet.Cli.Installer.Windows.WindowsUtils",$true)
  $installer = $asm.GetType("Microsoft.DotNet.Cli.Installer.Windows.InstallerBase",$true)
  $publicStatic = [Reflection.BindingFlags]::Public -bor [Reflection.BindingFlags]::Static
  $logValidate = $utils.GetMethod("ValidateLogFilePath",$publicStatic)
  $manifestValidate = $utils.GetMethod("ValidateManifestPath",$publicStatic)
  $trustedRootProperty = $installer.GetProperty("TrustedClientTempDirectory",$publicStatic)
  if($null -eq $logValidate -or $null -eq $manifestValidate -or $null -eq $trustedRootProperty) {
    throw "Could not resolve actual SDK validator methods and property"
  }
  # #11: ordinary chosen client root; explicit unrelated path must be redirected.
  $trustedRootProperty.SetValue($null,$client)
  $inClient = Join-Path $client "in-client.log"
  $accepted = Invoke-SdkValidator $logValidate @($inClient,$server)
  Add-Case "11-normal-root" ($accepted -eq [IO.Path]::GetFullPath($inClient)) "Trusted client-owned directory accepted"
  $unrelated = Join-Path $outside "unrelated.log"
  $rejected = Invoke-SdkValidator $logValidate @($unrelated,$server)
  $expected = Join-Path $server "unrelated.log"
  Add-Case "11-outside-control" ($rejected -eq $expected) "Unrelated path redirects into disposable server temp"
  # Overbroad trusted root is set in memory (not broker command line); this checks downstream policy.
  $trustedRootProperty.SetValue($null,$testRoot)
  $broadAccepted = Invoke-SdkValidator $logValidate @($unrelated,$server)
  Add-Case "11-overbroad-root" ($broadAccepted -eq [IO.Path]::GetFullPath($unrelated)) "Client trust root can authorize outside intended client temp; no UAC involved" "Does not establish who can set broker root or privilege escalation"
  $manifestBroad = [bool]$manifestValidate.Invoke($null,@($unrelated,$server))
  Add-Case "11-broad-manifest" $manifestBroad "Overbroad trust root affects manifest allow decision" "No manifest file was moved or read"
  # Reset normal client root for reparse tests.
  $trustedRootProperty.SetValue($null,$client)
  $junction = Join-Path $client "junction"
  New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
  $viaJunction = Join-Path $junction "followed.txt"
  $checked = Invoke-SdkValidator $logValidate @($viaJunction,$server)
  $manifestJunction = [bool]$manifestValidate.Invoke($null,@($viaJunction,$server))
  Add-Case "12-lexical-junction-accepted" ($checked -eq [IO.Path]::GetFullPath($viaJunction) -and $manifestJunction) "Real SDK validators accept a lexical client-temp child containing an NTFS junction" "Only same-token validator invoked"
  $marker="disposable-regression-" + [guid]::NewGuid().ToString("N")
  [IO.File]::WriteAllText($checked,$marker)
  $resolved = Join-Path $outside "followed.txt"
  $wasRedirected = (Test-Path -LiteralPath $resolved) -and ([IO.File]::ReadAllText($resolved) -eq $marker)
  $junctionInfo = Get-Item -LiteralPath $junction
  Add-Case "12-junction-final-object" $wasRedirected ("Disposable write landed outside lexical root. junctionTarget=" + ($junctionInfo.Target -join ",")) "Write performed by harness identity, NOT elevated SDK broker"
  # Staged change after validation, intentionally not called a race exploit.
  $swap = Join-Path $client "swap"
  New-Item -ItemType Junction -Path $swap -Target $outside | Out-Null
  $beforeSwap = Join-Path $swap "swapped.txt"
  $acceptedSwap = Invoke-SdkValidator $logValidate @($beforeSwap,$server)
  Remove-Item -LiteralPath $swap -Force
  New-Item -ItemType Junction -Path $swap -Target $other | Out-Null
  [IO.File]::WriteAllText($acceptedSwap,"staged-object-change")
  Add-Case "12-staged-check-use-change" (Test-Path -LiteralPath (Join-Path $other "swapped.txt")) "Changing a junction after validation redirects a later ordinary open" "Staged deterministic change, NOT a timed race and NOT a broker operation"
  # #13: negative control proves Windows Installer rejects a random noninstalled MSI product.
  # This does NOT test the workload broker's request authorization.
  $randomProduct = "{" + [guid]::NewGuid().ToString().ToUpperInvariant() + "}"
  $msi = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/x",$randomProduct,"/qn","/norestart") -PassThru -Wait
  $report.environment.randomMsiExitCode = $msi.ExitCode
  Add-Case "13-msi-missing-product-negative-control" ($msi.ExitCode -ne 0) ("Windows Installer did not uninstall a nonexistent randomly generated product: exitCode=" + $msi.ExitCode) "Does not verify unrelated installed MSI or broker request dispatch"
  $report.status = if(@($report.cases | Where-Object {$_.passed -eq $false}).Count -gt 0){"TEST_FAILURE"}else{"COMPLETED"}
} catch {
  $report.status="ERROR"
  $report.errors += $_.Exception.ToString()
  Write-Host ("ERROR: " + $_.Exception.ToString())
} finally {
  try { if(Test-Path -LiteralPath $testRoot){ Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction Stop }} catch {
    $report.errors += ("Cleanup: " + $_.Exception.ToString())
  }
  $report | ConvertTo-Json -Depth 8 | Set-Content -Path $reportPath -Encoding utf8
  Write-Host ("EVIDENCE_FILE=" + $reportPath)
  Write-Host ("RUN_STATUS=" + $report.status)
}
if($report.status -ne "COMPLETED"){ exit 1 }
