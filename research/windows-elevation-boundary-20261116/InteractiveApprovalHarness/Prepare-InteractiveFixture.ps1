# Run as an administrator in a disposable Windows VM.
# Creates ONLY uniquely named lab files, optional self-authored WiX MSI, and ACLs.
# The standard user used in the test must ALREADY exist; this script does not create users.
param(
  [Parameter(Mandatory=$true)][string]$StandardUser,
  [Parameter(Mandatory=$true)][ValidateSet('10.0.404','11.0.100')][string]$SdkVersion,
  [switch]$SkipMsi
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$uid=[guid]::NewGuid().ToString('N')
$root=Join-Path $env:PUBLIC ("msrc-windows-elevation-lab-"+$uid)
$client=Join-Path $root 'client'
$protected=Join-Path $root 'admin-only'
$pinned=Join-Path $root 'sdk-pinned'
$configFile=Join-Path $client 'fixture.json'
$provider='LabProvider.'+$uid
$junctionId='LabJunction.'+$uid
$broadId='LabBroad.'+$uid
$msiProduct=$null
$msiMarker=$null
$msiPath=$null
$standardSid=([Security.Principal.NTAccount]::new($StandardUser)).Translate([Security.Principal.SecurityIdentifier]).Value
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run fixture preparation from an actual elevated administrator account'
}
$dotnet=(Get-Command dotnet.exe -ErrorAction Stop).Source
$dotnetRoot=Split-Path $dotnet -Parent
if(!(Test-Path (Join-Path $dotnetRoot ("sdk\"+$SdkVersion+"\dotnet.dll")))) {
  throw ("SDK "+$SdkVersion+" not installed at "+$dotnetRoot)
}
if(!(Test-Path (Join-Path $dotnetRoot 'sdk\11.0.100'))) {
  throw 'Interactive harness targets net11.0 and requires SDK 11.0.100 for compilation'
}
$service=(& sc.exe query wuauserv | Out-String)
if($service -match 'STATE\s+:\s+\d+\s+RUNNING') {
  throw 'Windows Update service is active. Stop and assess in this disposable VM before using the workload broker; this setup does not stop services.'
}
New-Item -ItemType Directory -Force -Path $root,$client,$protected,$pinned | Out-Null
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if($LASTEXITCODE -ne 0){throw 'Failed lab root ACL'}
& icacls.exe $protected /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw 'Failed admin-only ACL'}
$grant=('*{0}:(OI)(CI)M' -f $standardSid)
& icacls.exe $client /grant:r $grant | Out-Null
if($LASTEXITCODE -ne 0){throw 'Failed to grant low-user scratch access'}
& icacls.exe $pinned /grant:r ('*{0}:(OI)(CI)RX' -f $standardSid) | Out-Null
if($LASTEXITCODE -ne 0){throw 'Failed to grant low-user pinned-sdk access'}
[IO.File]::WriteAllText((Join-Path $protected 'junction-payload.dat'),'ISOLATED-ADMIN-ONLY-JUNCTION-'+$uid)
[IO.File]::WriteAllText((Join-Path $protected 'broad-payload.dat'),'ISOLATED-ADMIN-ONLY-BROAD-'+$uid)
[IO.File]::WriteAllText((Join-Path $protected 'junction.msi.json'),'{"Payload":"junction-payload.dat"}')
[IO.File]::WriteAllText((Join-Path $protected 'broad.msi.json'),'{"Payload":"broad-payload.dat"}')
@{sdk=@{version=$SdkVersion;rollForward='disable'}}|ConvertTo-Json -Depth 4 -Compress|
  Set-Content -LiteralPath (Join-Path $pinned 'global.json') -Encoding utf8
foreach($id in @($junctionId,$broadId)) {
  $cachePath=Join-Path (Join-Path $env:ProgramData 'dotnet\workloads') $id
  if(Test-Path -LiteralPath $cachePath){throw 'Refuse preexisting package cache fixture collision'}
}
if(-not $SkipMsi) {
  $wixBin=@('C:\Program Files (x86)\WiX Toolset v3.14\bin',
            'C:\Program Files (x86)\WiX Toolset v3.11\bin') |
    Where-Object {(Test-Path (Join-Path $_ 'candle.exe')) -and (Test-Path (Join-Path $_ 'light.exe'))} |
    Select-Object -First 1
  if($wixBin) {
    $msiBuild=Join-Path $root 'msi-build'
    $msiInstall=Join-Path $protected 'msi-install'
    New-Item -ItemType Directory -Force -Path $msiBuild,$msiInstall | Out-Null
    $msiProduct=[guid]::NewGuid().ToString('B').ToUpperInvariant()
    $upgrade=[guid]::NewGuid().ToString('B').ToUpperInvariant()
    $component=[guid]::NewGuid().ToString('B').ToUpperInvariant()
    $file=Join-Path $msiBuild 'marker-input.txt'
    [IO.File]::WriteAllText($file,'ISOLATED-OWNED-MSI-'+$uid)
    $escaped=[Security.SecurityElement]::Escape($file)
    $wxs=Join-Path $msiBuild 'fixture.wxs'
    $obj=Join-Path $msiBuild 'fixture.wixobj'
    $msiPath=Join-Path $msiBuild 'fixture.msi'
    $msiMarker=Join-Path $msiInstall 'marker-input.txt'
    $xml=@"
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="$msiProduct" Name="Owned .NET Broker Validation Fixture" Language="1033"
           Version="1.0.0.0" Manufacturer="PrivateIsolatedLab" UpgradeCode="$upgrade">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" />
    <MediaTemplate EmbedCab="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLDIR" Name="OwnedBrokerFixture">
          <Component Id="MarkerComponent" Guid="$component">
            <File Id="OwnedMarker" Name="marker-input.txt" Source="$escaped" KeyPath="yes" />
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Complete" Title="IsolatedFixture" Level="1">
      <ComponentRef Id="MarkerComponent" />
    </Feature>
  </Product>
</Wix>
"@
    [IO.File]::WriteAllText($wxs,$xml)
    & (Join-Path $wixBin 'candle.exe') -nologo -out $obj $wxs | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Self-authored MSI compile failed'}
    & (Join-Path $wixBin 'light.exe') -nologo -out $msiPath $obj | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Self-authored MSI link failed'}
    $installArgs=('/i "{0}" /qn /norestart ALLUSERS=1 INSTALLDIR="{1}" /L*v "{2}"' -f
      $msiPath,$msiInstall,(Join-Path $msiBuild 'install.log'))
    $process=Start-Process msiexec.exe -ArgumentList $installArgs -Wait -PassThru
    if($process.ExitCode -ne 0 -or !(Test-Path -LiteralPath $msiMarker)) {
      throw ('Self-authored MSI failed to install, error '+$process.ExitCode)
    }
  } else {
    Write-Host 'WiX v3 absent: #13 MSI uninstall will be skipped; registry-provider check will still run.'
  }
}
$config=[ordered]@{
  Root=$root
  ClientDir=$client
  ProtectedDir=$protected
  PinnedCwd=$pinned
  JunctionCacheId=$junctionId
  BroadCacheId=$broadId
  ProviderName=$provider
  ProductCode=$msiProduct
  ProductMarker=$msiMarker
  JunctionSha256=(Get-FileHash -LiteralPath (Join-Path $protected 'junction-payload.dat') -Algorithm SHA256).Hash
  BroadSha256=(Get-FileHash -LiteralPath (Join-Path $protected 'broad-payload.dat') -Algorithm SHA256).Hash
  CreatedBySid=$standardSid
  SdkVersion=$SdkVersion
  SetupAdministratorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  FixtureCreatedUtc=(Get-Date).ToUniversalTime().ToString('O')
}
$config|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $configFile -Encoding utf8
Write-Host ('FIXTURE_CONFIG='+$configFile)
Write-Host ('LOW_USER_SID='+$standardSid)
Write-Host ('DISPOSABLE_MSI_INSTALLED='+[bool]$msiProduct)
Write-Host ('REQUIRES_TWO_REAL_UAC_APPROVALS=True')
Write-Host 'Sign in as the standard user and run Run-InteractiveClient.ps1 with this fixture path. Do not use an administrator PowerShell for the client.'
