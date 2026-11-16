# Run as administrator after the interactive standard-user test.
# Verify file identity and installed-product effects independently of the low-user client,
# then optionally remove ONLY uniquely generated lab artifacts.
param(
  [Parameter(Mandatory=$true)][string]$FixtureConfig,
  [string]$EvidenceDirectory=(Join-Path $env:USERPROFILE 'DotnetBrokerEvidence'),
  [switch]$Cleanup
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $admin){throw 'Administrator required for independent verification and optional cleanup'}
$config=Get-Content -LiteralPath $FixtureConfig -Raw|ConvertFrom-Json
$root=[IO.Path]::GetFullPath($config.Root)
$public=[IO.Path]::GetFullPath($env:PUBLIC)
if(-not $root.StartsWith(($public+[IO.Path]::DirectorySeparatorChar),[StringComparison]::OrdinalIgnoreCase) -or
  ((Split-Path $root -Leaf) -notmatch '^msrc-windows-elevation-lab-[0-9a-f]{32}$')) {
  throw 'Refusing unsafe fixture root'
}
foreach($id in @($config.JunctionCacheId,$config.BroadCacheId)){
  if($id -notmatch '^Lab(Junction|Broad)\.[0-9a-f]{32}$'){throw ('Refusing unsafe generated cache ID '+$id)}
}
if($config.ProviderName -notmatch '^LabProvider\.[0-9a-f]{32}$'){throw 'Refusing unsafe generated provider'}
New-Item -ItemType Directory -Path $EvidenceDirectory -Force|Out-Null
$junctionSource=Join-Path $config.ProtectedDir 'junction-payload.dat'
$broadSource=Join-Path $config.ProtectedDir 'broad-payload.dat'
$cacheRoot=Join-Path $env:ProgramData 'dotnet\workloads'
$junctionPackage=Join-Path $cacheRoot $config.JunctionCacheId
$broadPackage=Join-Path $cacheRoot $config.BroadCacheId
$cachedJunction=Join-Path (Join-Path $junctionPackage '1.0.0') 'junction-payload.dat'
$cachedBroad=Join-Path (Join-Path $broadPackage '1.0.0') 'broad-payload.dat'
function HashOrNull([string]$path) {
  if(Test-Path -LiteralPath $path){return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
  return $null
}
$providerPath='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Dependencies\'+$config.ProviderName
$providerExists=Test-Path -LiteralPath $providerPath
$msiRemoved=$null
if($config.ProductCode){$msiRemoved=!(Test-Path -LiteralPath $config.ProductMarker)}
$readback=Join-Path $config.ClientDir 'results'
$clientJSON=Join-Path $readback ('interactive-'+$config.SdkVersion+'.json')
$clientStatus=$null
if(Test-Path -LiteralPath $clientJSON){
  Copy-Item -LiteralPath $clientJSON -Destination (Join-Path $EvidenceDirectory 'interactive-client.json') -Force
  $clientStatus=(Get-Content -LiteralPath $clientJSON -Raw|ConvertFrom-Json).status
}
$assessment=[ordered]@{
  utc=(Get-Date).ToUniversalTime().ToString('o')
  sdkVersion=$config.SdkVersion
  source='Independent administrator inspection, after separate actual UAC approval experiment'
  testClientKind='CUSTOM IPC client mirrors official runas invocation; not normal dotnet workload command'
  sourceProtectedJunctionGone=!(Test-Path -LiteralPath $junctionSource)
  sourceProtectedBroadGone=!(Test-Path -LiteralPath $broadSource)
  junctionReadbackMatches=( (HashOrNull $cachedJunction) -eq $config.JunctionSha256 )
  broadReadbackMatches=( (HashOrNull $cachedBroad) -eq $config.BroadSha256 )
  cachedJunctionSha256=(HashOrNull $cachedJunction)
  cachedBroadSha256=(HashOrNull $cachedBroad)
  protectedDirectorySddl=$(if(Test-Path -LiteralPath $config.ProtectedDir){(Get-Acl -LiteralPath $config.ProtectedDir).Sddl}else{$null})
  cachedJunctionSddl=$(if(Test-Path -LiteralPath $cachedJunction){(Get-Acl -LiteralPath $cachedJunction).Sddl}else{$null})
  cachedBroadSddl=$(if(Test-Path -LiteralPath $cachedBroad){(Get-Acl -LiteralPath $cachedBroad).Sddl}else{$null})
  expectedLowUserSid=$config.CreatedBySid
  fixtureSetupAdministratorSid=$config.SetupAdministratorSid
  providerRecordCreated=$providerExists
  unrelatedSelfAuthoredMsiRemoved=$msiRemoved
  clientStatus=$clientStatus
  establishedRegularWorkloadReachability=$false
  trueInteractiveUacApprovalAttestation='Human UAC approval is necessary; tool cannot independently attest approved admin identity.'
  cleanupRequested=[bool]$Cleanup
  cleanupActions=@()
  cleanupErrors=@()
}
$summaryFile=Join-Path $EvidenceDirectory 'administrator-verification.json'
$assessment|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $summaryFile -Encoding utf8
Write-Host ('VERIFICATION_FILE='+$summaryFile)
Write-Host ('JUNCTION_DISCLOSURE='+$assessment.junctionReadbackMatches)
Write-Host ('BROAD_ROOT_DISCLOSURE='+$assessment.broadReadbackMatches)
Write-Host ('HKLM_PROVIDER_CREATED='+$assessment.providerRecordCreated)
Write-Host ('SELF_AUTHORED_MSI_REMOVED='+$assessment.unrelatedSelfAuthoredMsiRemoved)
if($Cleanup){
  # These are NEVER real workloads or third-party products. Exact generated
  # package IDs, registry provider, MSI product code and sandbox names only.
  try{
    if($config.ProductCode -and $config.ProductCode -match '^\{[0-9A-Fa-f-]{36}\}$' -and
        (Test-Path -LiteralPath $config.ProductMarker)) {
      $p=Start-Process msiexec.exe -ArgumentList ('/x {0} /qn /norestart' -f $config.ProductCode) -Wait -PassThru
      $assessment.cleanupActions+=('Uninstalled remaining self-authored fixture MSI: '+$p.ExitCode)
    }
  }catch{$assessment.cleanupErrors+=('MSI cleanup: '+$_.Exception.Message)}
  foreach($package in @($junctionPackage,$broadPackage)){
    try{
      if(Test-Path -LiteralPath $package){
        Remove-Item -LiteralPath $package -Recurse -Force -ErrorAction Stop
        $assessment.cleanupActions+=('Removed exact generated cache package '+$package)
      }
    }catch{$assessment.cleanupErrors+=('Cache cleanup: '+$_.Exception.Message)}
  }
  try{
    if(Test-Path -LiteralPath $providerPath){
      Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction Stop
      $assessment.cleanupActions+='Removed exact generated HKLM provider record'
    }
  }catch{$assessment.cleanupErrors+=('HKLM cleanup: '+$_.Exception.Message)}
  try{
    $link=Join-Path $config.ClientDir 'junction'
    if(Test-Path -LiteralPath $link){
      & cmd.exe /c ('rmdir "'+$link+'"')|Out-Null
      $assessment.cleanupActions+='Removed generated client junction only'
    }
  }catch{$assessment.cleanupErrors+=('Junction cleanup: '+$_.Exception.Message)}
  try{
    if(Test-Path -LiteralPath $root){
      Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
      $assessment.cleanupActions+='Removed generated public scratch directory'
    }
  }catch{$assessment.cleanupErrors+=('Sandbox cleanup: '+$_.Exception.Message)}
  $assessment|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $summaryFile -Encoding utf8
  Write-Host ('CLEANUP_ERRORS='+$assessment.cleanupErrors.Count)
}
