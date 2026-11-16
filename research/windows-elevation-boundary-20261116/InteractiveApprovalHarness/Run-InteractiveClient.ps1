# Run from a normal (nonadministrator) PowerShell session in your disposable Windows VM.
# Explicit UAC approval from a separate human administrator is required for each broker.
param([Parameter(Mandatory=$true)][string]$FixtureConfig)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$config=Get-Content -LiteralPath $FixtureConfig -Raw|ConvertFrom-Json
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$admin=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($admin){throw 'Run this script as the actual STANDARD USER, not as administrator'}
if($identity.User.Value -ne $config.CreatedBySid){throw 'Current user SID differs from fixture standard user'}
if($config.SdkVersion -notin @('10.0.404','11.0.100')){throw 'Unknown pinned SDK version'}
$project=Join-Path $PSScriptRoot 'InteractiveApprovalHarness.csproj'
$assembly=Join-Path $PSScriptRoot 'bin\Release\net11.0\InteractiveApprovalHarness.dll'
& dotnet build $project -c Release --nologo
if($LASTEXITCODE -ne 0){throw 'Interactive harness failed to compile'}
if(!(Test-Path -LiteralPath $assembly)){throw 'Missing compiled test DLL'}
$results=Join-Path $config.ClientDir 'results'
New-Item -ItemType Directory -Path $results -Force|Out-Null
$output=Join-Path $results ('interactive-'+$config.SdkVersion+'.json')
Write-Host 'Two real Windows UAC prompts will be requested from a separate administrator.'
Write-Host 'Only accept these prompts in an isolated VM you own and expressly authorize.'
Write-Host 'The requests use a CUSTOM test client; success does NOT prove an unmodified workload command is exploitable.'
Write-Host ('LOW_USER='+$identity.Name+' SID='+$identity.User.Value)
Write-Host ('PINNED_SDK='+$config.SdkVersion)
& dotnet $assembly $FixtureConfig $config.SdkVersion $output
$exit=$LASTEXITCODE
Write-Host ('EVIDENCE_FILE='+$output)
Write-Host ('HARNESS_EXIT='+$exit)
if($exit -ne 0){throw 'A test was declined, blocked, failed, or was incomplete; inspect the JSON and verify no unexpected machine changes'}
