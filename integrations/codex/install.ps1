param([string]$CodexDirectory, [string]$CliPath = 'orphan-guard.exe')

$ErrorActionPreference = 'Stop'
if (-not $CodexDirectory) {
    if ($env:CODEX_HOME) { $CodexDirectory = $env:CODEX_HOME }
    else { $CodexDirectory = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.codex' }
}
$CodexDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CodexDirectory)
$executable = (Get-Command $CliPath -CommandType Application -ErrorAction Stop).Source
$sourceSkill = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../skills/orphan-guard'))
$installedSkill = Join-Path $CodexDirectory 'skills/orphan-guard'
$installedHook = Join-Path $installedSkill 'scripts/session-start.ps1'
$configPath = Join-Path $CodexDirectory 'hooks.json'
$original = $null
if (Test-Path -LiteralPath $configPath) {
    $original = [IO.File]::ReadAllText($configPath)
    $config = $original | ConvertFrom-Json
} else { $config = [pscustomobject]@{} }
if ($config -isnot [pscustomobject]) { throw 'hooks.json must contain a JSON object' }
if (-not $config.PSObject.Properties['hooks']) { $config | Add-Member hooks ([pscustomobject]@{}) }
if ($config.hooks -isnot [pscustomobject]) { throw 'hooks must contain an object' }
if (-not $config.hooks.PSObject.Properties['SessionStart']) { $config.hooks | Add-Member SessionStart @() }
if ($config.hooks.SessionStart -isnot [array]) { throw 'SessionStart must contain an array' }

$marker = 'OrphanGuard: read-only SessionStart scan'
$invocation = "& '" + $installedHook.Replace("'", "''") + "' -CliPath '" + $executable.Replace("'", "''") + "'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($invocation))
$command = 'powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
$owned = @($config.hooks.SessionStart.hooks | Where-Object { $_.statusMessage -eq $marker })
if ($owned.Count -gt 1) { throw 'Multiple OrphanGuard registrations exist; review them in /hooks before reinstalling' }
$changed = $false
if ($owned.Count -eq 1) {
    if ($owned[0].type -ne 'command') { throw 'Existing OrphanGuard handler is not a command hook' }
    if ($owned[0].command -cne $command) { $owned[0].command = $command; $changed = $true }
} else {
    $handler = [pscustomobject]@{
        type = 'command'
        command = $command
        timeout = 10
        additionalContextLimit = 512
        statusMessage = $marker
    }
    $config.hooks.SessionStart = @($config.hooks.SessionStart) + @([pscustomobject]@{ hooks = @($handler) })
    $changed = $true
}

foreach ($relativePath in @('SKILL.md', 'scripts/session-start.ps1')) {
    $sourcePath = Join-Path $sourceSkill $relativePath
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw ('Missing integration asset: ' + $sourcePath) }
}
[void][IO.Directory]::CreateDirectory((Join-Path $installedSkill 'scripts'))
foreach ($relativePath in @('SKILL.md', 'scripts/session-start.ps1')) {
    Copy-Item -LiteralPath (Join-Path $sourceSkill $relativePath) -Destination (Join-Path $installedSkill $relativePath) -Force
}

if ($changed) {
    $temporaryPath = Join-Path $CodexDirectory ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllText($temporaryPath, ($config | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
        if ($null -ne $original) {
            if ([IO.File]::ReadAllText($configPath) -cne $original) { throw 'hooks.json changed during installation; rerun to preserve the concurrent edit' }
            $backupPath = $configPath + '.orphan-guard-' + [guid]::NewGuid().ToString('N') + '.bak'
            [IO.File]::Replace($temporaryPath, $configPath, $backupPath)
            Write-Output ('Original hook configuration: ' + $backupPath)
        } else { [IO.File]::Move($temporaryPath, $configPath) }
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
    }
}
Write-Output ('Installed skill: ' + (Join-Path $installedSkill 'SKILL.md'))
Write-Output ('SessionStart hook: ' + $installedHook)
Write-Output 'Review and trust the new hook in Codex with /hooks. Existing hook trust settings were preserved.'
