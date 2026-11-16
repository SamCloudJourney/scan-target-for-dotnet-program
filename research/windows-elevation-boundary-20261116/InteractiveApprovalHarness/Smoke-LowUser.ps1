# Negative-control fixture ACL verification under a genuine standard-user Windows token.
# Does not use UAC or elevated IPC and does not touch any installed products.
param([Parameter(Mandatory=$true)][string]$FixtureConfig,
      [Parameter(Mandatory=$true)][string]$EvidencePath)
$ErrorActionPreference="Stop"
$fx=Get-Content -Raw -LiteralPath $FixtureConfig|ConvertFrom-Json
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin=[Security.Principal.WindowsPrincipal]::new($id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$rootTest=Join-Path $fx.Root ('low-extraction-'+[guid]::NewGuid().ToString('N'))
$probe=[ordered]@{
  timestampUtc=(Get-Date).ToUniversalTime().ToString('O')
  sid=$id.User.Value
  account=$id.Name
  isAdmin=$isAdmin
  matchedPreparedSid=($id.User.Value -eq $fx.CreatedBySid)
  createdRandomExtractionDirectory=$false
  wroteInsideNewExtractionDirectory=$false
  protectedReadDenied=$false
  protectedWriteDenied=$false
  clientJunctionCreated=$false
  junctionProtectedReadDenied=$false
  rootTempSelectionMatches=$false
  errors=@()
}
try{
  if($isAdmin){throw 'Probe incorrectly started as admin'}
  [IO.Directory]::CreateDirectory($rootTest)|Out-Null
  $probe.createdRandomExtractionDirectory=(Test-Path -LiteralPath $rootTest)
  [IO.File]::WriteAllText((Join-Path $rootTest 'msi.json'),'{"Payload":"low-owned-test"}')
  $probe.wroteInsideNewExtractionDirectory=(Test-Path -LiteralPath (Join-Path $rootTest 'msi.json'))
  $protected=Join-Path $fx.ProtectedDir 'junction-payload.dat'
  try{$null=[IO.File]::ReadAllBytes($protected)}catch{$probe.protectedReadDenied=$true}
  try{[IO.File]::AppendAllText($protected,'UNEXPECTED')}catch{$probe.protectedWriteDenied=$true}
  $link=Join-Path $fx.ClientDir 'smoke-junction'
  $proc=Start-Process cmd.exe -ArgumentList ('/c mklink /J "{0}" "{1}"' -f $link,$fx.ProtectedDir) -Wait -PassThru -NoNewWindow
  $probe.clientJunctionCreated=($proc.ExitCode -eq 0 -and (Test-Path -LiteralPath $link))
  try{$null=[IO.File]::ReadAllBytes((Join-Path $link 'junction-payload.dat'))}catch{$probe.junctionProtectedReadDenied=$true}
  $oldTmp=$env:TMP;$oldTemp=$env:TEMP
  try{
    $env:TMP=$fx.Root;$env:TEMP=$fx.Root
    $probe.rootTempSelectionMatches=([IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') -eq [IO.Path]::GetFullPath($fx.Root).TrimEnd('\'))
  }finally{$env:TMP=$oldTmp;$env:TEMP=$oldTemp}
}catch{$probe.errors+=$_.Exception.ToString()}
finally{
  $probe|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $EvidencePath -Encoding utf8
  Write-Host ('SMOKE_RESULT='+$(if(@($probe.errors).Count -eq 0){'FINISHED'}else{'ERROR'}))
}
if($probe.errors.Count -gt 0 -or $isAdmin -or !$probe.matchedPreparedSid -or
   !$probe.createdRandomExtractionDirectory -or !$probe.wroteInsideNewExtractionDirectory -or
   !$probe.protectedReadDenied -or !$probe.protectedWriteDenied -or
   !$probe.clientJunctionCreated -or !$probe.junctionProtectedReadDenied -or
   !$probe.rootTempSelectionMatches){exit 1}
