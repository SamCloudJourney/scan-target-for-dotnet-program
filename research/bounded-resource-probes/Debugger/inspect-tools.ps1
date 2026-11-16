$ErrorActionPreference = 'Stop'
$paths = [ordered]@{}
$tools = @('vsdbg.exe','cdb.exe','windbg.exe','devenv.exe','VsDebugConsole.exe','dotnet-dump.exe','dotnet-trace.exe','vswhere.exe')
foreach($name in $tools) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    $paths[$name] = if($null -ne $cmd) { @($cmd.Source) } else { @() }
}
$root = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe'
if(Test-Path $root) {
    $paths['vswhere-installed'] = @(& $root -products * -property installationPath)
}
$vs = $paths['vswhere-installed']
foreach($install in $vs) {
    foreach($relative in @('Common7\IDE\devenv.exe','Common7\IDE\CommonExtensions\Microsoft\IntelliCode','Common7\IDE\CommonExtensions\Microsoft\Debugger','Common7\IDE\VsDebugConsole.exe')) {
        $target = Join-Path $install $relative
        if(Test-Path $target) { $paths[$relative] = @($target) }
    }
}
$frameworks = & dotnet --list-runtimes
$os = [Environment]::OSVersion.VersionString
$results = [ordered]@{test="windows-debugger-inventory";os=$os;dotnetRuntimes=$frameworks;tools=$paths}
$results | ConvertTo-Json -Depth 7 -Compress | Tee-Object -FilePath "debugger-evidence/inventory.jsonl"
