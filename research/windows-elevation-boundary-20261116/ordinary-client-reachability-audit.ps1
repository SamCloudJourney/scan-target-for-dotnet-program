# Source provenance audit of official SDK workload client; no UAC or exploit.
param([Parameter(Mandatory=$true)][string]$SdkSourceRoot)
$ErrorActionPreference="Stop"
$checks=@()
function Check([string]$id,[bool]$passed,[string]$explanation,[string]$limitation) {
  $script:checks+=[pscustomobject]@{id=$id;passed=$passed;explanation=$explanation;limitation=$limitation}
  Write-Host ("CHECK "+$id+" "+$(if($passed){"PASS"}else{"FAIL"})+" "+$explanation)
}
$names=[ordered]@{
  ElevationClient='Installer/Windows/InstallClientElevationContext.cs'
  ElevationEntrypoint='Commands/Workload/Elevate/WorkloadElevateCommand.cs'
  NormalClient='Commands/Workload/Install/NetSdkMsiInstallerClient.cs'
  Cache='Installer/Windows/MsiPackageCache.cs'
  Broker='Commands/Workload/Install/NetSdkMsiInstallerServer.cs'
  Base='Commands/Workload/Install/MsiInstallerBase.cs'
  Validators='Installer/Windows/WindowsUtils.cs'
}
$source=@{};$hash=@{}
foreach($name in @($names.Keys)){
  $path=Join-Path $SdkSourceRoot $names[$name]
  if(!(Test-Path -LiteralPath $path)){throw "Pinned source file not checked out: $path"}
  $source[$name]=Get-Content -Raw -LiteralPath $path
  $hash[$name]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}
$e=$source.ElevationClient;$n=$source.NormalClient;$c=$source.Cache
$b=$source.Broker;$v=$source.Validators;$m=$source.Base;$z=$source.ElevationEntrypoint
Check 'client-runas' ($e.Contains('Verb = "runas"') -and $e.Contains('UseShellExecute = true')) 'Normal client invokes ShellExecute runas' 'Interactive approval not available on GitHub-hosted runners'
Check 'client-env-temp' ($e.Contains('Path.GetFullPath(Path.GetTempPath())')) 'Client obtains trusted-temp argument from effective temporary directory' 'Does not prove client can choose arbitrary manifest'
Check 'client-pipe' ($e.Contains('InitializeDispatcher(new NamedPipeClientStream') -and $e.Contains('Dispatcher.Connect()')) 'Normal client connects to broker pipe' 'Request authorization must be assessed separately'
Check 'trusted-root-accepted' ($z.Contains('TrustedClientTempDirectory = Path.GetFullPath(clientTemp)')) 'Broker normalizes user-supplied root' 'Not a resolved-object validation'
Check 'client-random-extraction' ($n.Contains('Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString())')) 'Normal client uses random extraction folder under temp' 'Root selection does not automatically permit manifest substitution'
Check 'client-manifest-derived' ($n.Contains('Path.Combine(extractedPackageRootPath, "data", "msi.json")')) 'Normal client derives manifest path from unpacked package' 'Normal client does not expose an arbitrary manifest argument in this call'
Check 'client-cache-request' ($n.Contains('Cache.CachePayload(packageId, packageVersion, manifestPath)')) 'Normal client calls cache with derived path' 'No unauthorised root or junction substitution is proven'
Check 'cache-lexical-validator' ($c.Contains('ValidateManifestPath(fullManifestPath)') -and $v.Contains('IsPathUnder(fullManifestPath, clientTemp)')) 'Cache uses lexical containment of allowed path roots' 'Reparse-point path resolution differs from text containment'
Check 'cache-relocation' ($c.Contains('SecurityUtils.MoveAndSecureFile(fullManifestPath, cachedManifestPath') -and $c.Contains('SecurityUtils.MoveAndSecureFile(msiPath, cachedMsiPath')) 'Elevated cache moves manifest and adjacent payload' 'Real client reachability of arbitrary protected source remains unknown'
Check 'client-productcodes-payload' ($n.Contains('RepairMsi(msi.ProductCode, logFile)') -and $n.Contains('UninstallMsi(msi.ProductCode, logFile)')) 'Normal package repair/uninstall derives product GUID from MSI metadata' 'Not arbitrary GUID on normal CLI'
Check 'client-record-mismatch' ($n.Contains('UninstallMsi(record.ProductCode, logFile)')) 'Recorded ProductCode can be used on mismatch path' 'No proof low user can alter protected workload records'
Check 'client-msi-database-validation' ($n.Contains('ValidateMsiDatabase(msi)')) 'Normal client validates MSI database before execution' 'Database validation is not a cryptographic signature check'
Check 'broker-direct-productcode' ($b.Contains('UninstallMsi(request.ProductCode, request.LogFile)') -and $b.Contains('RepairMsi(request.ProductCode, request.LogFile)')) 'Broker directly dispatches supplied ProductCode' 'No authorization bypass demonstrated solely by dispatch'
Check 'broker-msi-signature-check' ($m.Contains('Cache.VerifyPackageSignature(packagePath)')) 'Broker verifies signature on MSI install path' 'Does not cover arbitrary repair/uninstall'
Check 'normal-client-boundary' ($n.Contains('GetCachedMsiPayload(') -and $e.Contains('InitializeDispatcher(')) 'Normal workload client has resolver and IPC path independent from custom harness' 'Custom broker harness must not be described as unmodified workload exploitation'
$failed=@($checks|Where-Object{-not $_.passed})
$result=[ordered]@{
  utc=(Get-Date).ToUniversalTime().ToString('o')
  sourceRoot=$SdkSourceRoot
  sourceVersion='repository scan-target-v11.0.100 source snapshot (not SDK 10 source)'
  sourceSha256=$hash
  results=$checks
  passedCount=($checks.Count-$failed.Count)
  totalChecks=$checks.Count
  status=$(if($failed.Count -eq 0){'COMPLETED'}else{'SOURCE_ASSERTIONS_FAILED'})
  interpretation='Exact source pattern verification only, not real UAC approval or arbitrary MSI/manifest control via unmodified dotnet workload command.'
}
$out=Join-Path $env:RUNNER_TEMP 'ordinary-client-reachability-audit.json'
$result|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $out -Encoding utf8
Write-Host "EVIDENCE_FILE=$out"
Write-Host "RUN_STATUS=$($result.status)"
if($failed.Count -gt 0){exit 1}
