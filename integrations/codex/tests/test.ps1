$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$hookScript = Join-Path $repoRoot 'skills/orphan-guard/scripts/session-start.ps1'
$installer = Join-Path $repoRoot 'integrations/codex/install.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('orphan-guard-integration-' + [guid]::NewGuid().ToString('N'))
$testStarted = Get-Date
$fixturePath = Join-Path $testRoot 'Fixture tool/fixture.exe'
$fixtureLog = Join-Path $testRoot 'fixture.jsonl'
$powershellPath = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
$eventJson = '{"hook_event_name":"SessionStart","source":"startup","session_id":"synthetic-test","cwd":"C:/unused & literal"}'
$failures = [Collections.Generic.List[string]]::new()
$assertions = 0
$oldMode = $env:ORPHAN_GUARD_FIXTURE_MODE
$oldLog = $env:ORPHAN_GUARD_FIXTURE_LOG

function Assert-True($condition, [string]$message) {
    $script:assertions++
    if (-not $condition) { throw $message }
}

function Test-Case([string]$name, [scriptblock]$body) {
    try { & $body; Write-Output "PASS $name" }
    catch { $script:failures.Add("${name}: $($_.Exception.Message)"); Write-Output "FAIL ${name}: $($_.Exception.Message)" }
}

function Invoke-Process([string]$arguments, [string]$inputText = '') {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $powershellPath
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ' + $arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $child = [Diagnostics.Process]::new()
    $child.StartInfo = $start
    try {
        [void]$child.Start()
        $stdoutTask = $child.StandardOutput.ReadToEndAsync()
        $stderrTask = $child.StandardError.ReadToEndAsync()
        $child.StandardInput.Write($inputText)
        $child.StandardInput.Close()
        if (-not $child.WaitForExit(12000)) { $child.Kill(); throw 'Test child exceeded twelve seconds' }
        if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), 1000)) { throw 'Test child output did not close' }
        return [pscustomobject]@{ Code = $child.ExitCode; Out = $stdoutTask.Result; Err = $stderrTask.Result }
    } finally { $child.Dispose() }
}

function Invoke-Hook([string]$cli = $fixturePath, [string]$payload = $eventJson) {
    return Invoke-Process ('-File "' + $hookScript + '" -CliPath "' + $cli + '"') $payload
}

function Read-HookResult($result) {
    Assert-True ($result.Code -eq 0) ('Hook blocked the session: ' + $result.Err)
    $output = $result.Out | ConvertFrom-Json
    Assert-True ($output.continue -eq $true) 'Hook must explicitly continue the session'
    Assert-True ($output.hookSpecificOutput.hookEventName -eq 'SessionStart') 'Wrong hook output event'
    Assert-True ($output.hookSpecificOutput.additionalContext.Length -lt 1500) 'Hook context is not bounded'
    return $output.hookSpecificOutput.additionalContext
}

try {
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $fixturePath))
    & go build -o $fixturePath (Join-Path $PSScriptRoot 'fixture.go')
    if ($LASTEXITCODE -ne 0) { throw 'Could not build the disposable scanner fixture' }
    $env:ORPHAN_GUARD_FIXTURE_LOG = $fixtureLog
    $env:ORPHAN_GUARD_FIXTURE_MODE = 'valid'

    Test-Case 'read-only scan and compact context' {
        $context = Read-HookResult (Invoke-Hook)
        Assert-True ($context -match '3 processes' -and $context -match '1 candidate') 'Scan counts were not reported'
        Assert-True ($context -match 'SKILL.md') 'Skill pointer missing'
        $record = Get-Content -LiteralPath $fixtureLog | Select-Object -Last 1 | ConvertFrom-Json
        Assert-True (($record.args -join ' ') -eq 'scan --json') 'Hook ran a command other than the read-only scan'
    }

    foreach ($mode in @('invalid', 'error', 'applied')) {
        $env:ORPHAN_GUARD_FIXTURE_MODE = $mode
        Test-Case "unavailable scanner: $mode" {
            $context = Read-HookResult (Invoke-Hook)
            Assert-True ($context -match 'unavailable') 'Failed scanner presented a normal baseline'
            Assert-True ($context -notmatch 'fixture-secret') 'Scanner output leaked into agent context'
        }
    }

    Test-Case 'missing CLI is nonblocking' {
        $context = Read-HookResult (Invoke-Hook (Join-Path $testRoot 'missing.exe'))
        Assert-True ($context -match 'unavailable') 'Missing CLI was not reported'
    }

    $env:ORPHAN_GUARD_FIXTURE_MODE = 'hang'
    Test-Case 'timeout reaps only the owned scanner' {
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $context = Read-HookResult (Invoke-Hook)
        Assert-True ($watch.Elapsed.TotalSeconds -lt 10 -and $context -match 'unavailable') 'Scanner timeout was not bounded'
        $record = Get-Content -LiteralPath $fixtureLog | Select-Object -Last 1 | ConvertFrom-Json
        $remaining = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
        Assert-True (-not $remaining -or $remaining.Path -ne $fixturePath) 'Owned scanner remained after timeout'
    }

    $env:ORPHAN_GUARD_FIXTURE_MODE = 'valid'
    Test-Case 'other lifecycle events are ignored' {
        $before = 0
        if (Test-Path -LiteralPath $fixtureLog) { $before = @(Get-Content -LiteralPath $fixtureLog).Count }
        $result = Invoke-Hook $fixturePath '{"hook_event_name":"Stop"}'
        Assert-True ($result.Code -eq 0 -and $result.Out.Trim() -eq '') 'Unexpected output for another event'
        $after = 0
        if (Test-Path -LiteralPath $fixtureLog) { $after = @(Get-Content -LiteralPath $fixtureLog).Count }
        Assert-True ($after -eq $before) 'Another event launched the scanner'
    }

    Test-Case 'installer preserves hooks and is idempotent' {
        $codexDirectory = Join-Path $testRoot 'Codex home '' & $literal'
        [void][IO.Directory]::CreateDirectory($codexDirectory)
        $configPath = Join-Path $codexDirectory 'hooks.json'
        $original = '{"description":"preserve me","metadata":{"nested":{"keep":true}},"hooks":{"SessionStart":[{"matcher":"resume","hooks":[{"type":"command","command":"existing-start","timeout":7}]}],"Stop":[{"hooks":[{"type":"command","command":"existing-stop"}]}]}}'
        [IO.File]::WriteAllText($configPath, $original)
        $arguments = '-File "' + $installer + '" -CodexDirectory "' + $codexDirectory + '" -CliPath "' + $fixturePath + '"'
        $result = Invoke-Process $arguments
        Assert-True ($result.Code -eq 0) ('Install failed: ' + $result.Err)
        $installed = [IO.File]::ReadAllText($configPath)
        $config = $installed | ConvertFrom-Json
        Assert-True ($config.description -eq 'preserve me' -and $config.metadata.nested.keep) 'Config metadata lost'
        Assert-True ($config.hooks.Stop[0].hooks[0].command -eq 'existing-stop') 'Unrelated event changed'
        Assert-True ($config.hooks.SessionStart[0].hooks[0].command -eq 'existing-start') 'Existing startup hook changed'
        $owned = @($config.hooks.SessionStart.hooks | Where-Object { $_.statusMessage -eq 'OrphanGuard: read-only SessionStart scan' })
        Assert-True ($owned.Count -eq 1) 'Expected exactly one OrphanGuard registration'
        Assert-True (Test-Path -LiteralPath (Join-Path $codexDirectory 'skills/orphan-guard/SKILL.md')) 'Skill not installed'
        $encodedArguments = $owned[0].command.Substring('powershell.exe '.Length)
        $context = Read-HookResult (Invoke-Process $encodedArguments $eventJson)
        Assert-True ($context.Contains((Join-Path $codexDirectory 'skills/orphan-guard/SKILL.md'))) 'Installed hook points at another skill'
        $result = Invoke-Process $arguments
        Assert-True ($result.Code -eq 0) ('Reinstall failed: ' + $result.Err)
        Assert-True ([IO.File]::ReadAllText($configPath) -eq $installed) 'Reinstall rewrote config or duplicated the hook'
        $backups = @(Get-ChildItem -LiteralPath $codexDirectory -Filter 'hooks.json.orphan-guard-*.bak')
        Assert-True ($backups.Count -eq 1 -and [IO.File]::ReadAllText($backups[0].FullName) -eq $original) 'Original config backup missing or changed'
    }

    Test-Case 'installer repairs case changes in encoded registration' {
        $codexDirectory = Join-Path $testRoot 'Encoded command'
        $arguments = '-File "' + $installer + '" -CodexDirectory "' + $codexDirectory + '" -CliPath "' + $fixturePath + '"'
        $result = Invoke-Process $arguments
        Assert-True ($result.Code -eq 0) ('Initial install failed: ' + $result.Err)
        $configPath = Join-Path $codexDirectory 'hooks.json'
        $config = [IO.File]::ReadAllText($configPath) | ConvertFrom-Json
        $expected = $config.hooks.SessionStart[0].hooks[0].command
        $config.hooks.SessionStart[0].hooks[0].command = $expected.ToUpperInvariant()
        [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 100))
        $result = Invoke-Process $arguments
        Assert-True ($result.Code -eq 0) ('Repair failed: ' + $result.Err)
        $config = [IO.File]::ReadAllText($configPath) | ConvertFrom-Json
        Assert-True ($config.hooks.SessionStart.Count -eq 1 -and $config.hooks.SessionStart[0].hooks[0].command -ceq $expected) 'Encoded command case was not repaired'
    }

    Test-Case 'concurrent case-only config edit is preserved' {
        $codexDirectory = Join-Path $testRoot 'Concurrent config'
        [void][IO.Directory]::CreateDirectory($codexDirectory)
        $configPath = Join-Path $codexDirectory 'hooks.json'
        $original = '{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo ORIGINAL"}]}]}}'
        $edited = $original.Replace('echo ORIGINAL', 'echo original')
        [IO.File]::WriteAllText($configPath, $original)
        function Copy-Item {
            param([string]$LiteralPath, [string]$Destination, [switch]$Force)
            Microsoft.PowerShell.Management\Copy-Item @PSBoundParameters
            [IO.File]::WriteAllText($configPath, $edited)
        }
        $rejected = $false
        try { & $installer -CodexDirectory $codexDirectory -CliPath $fixturePath | Out-Null }
        catch { $rejected = $_.Exception.Message -like 'hooks.json changed during installation*' }
        finally { Remove-Item Function:\Copy-Item }
        Assert-True $rejected 'Concurrent case-only edit was accepted'
        Assert-True ([IO.File]::ReadAllText($configPath) -ceq $edited) 'Concurrent case-only edit was overwritten'
    }

    Test-Case 'relative destination follows the PowerShell location' {
        $processDirectory = Join-Path $testRoot 'Process directory'
        $shellDirectory = Join-Path $testRoot 'Shell directory'
        [void][IO.Directory]::CreateDirectory($processDirectory)
        [void][IO.Directory]::CreateDirectory($shellDirectory)
        $oldLocation = Get-Location
        $oldProcessDirectory = [Environment]::CurrentDirectory
        try {
            [Environment]::CurrentDirectory = $processDirectory
            Set-Location -LiteralPath $shellDirectory
            & $installer -CodexDirectory './Codex home' -CliPath $fixturePath | Out-Null
            Assert-True (Test-Path -LiteralPath (Join-Path $shellDirectory 'Codex home/hooks.json')) 'Relative destination ignored the PowerShell location'
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $processDirectory 'Codex home'))) 'Installed into the process working directory'
        } finally {
            Set-Location -LiteralPath $oldLocation.Path
            [Environment]::CurrentDirectory = $oldProcessDirectory
        }
    }

    Test-Case 'malformed config is preserved' {
        $codexDirectory = Join-Path $testRoot 'Invalid config'
        [void][IO.Directory]::CreateDirectory($codexDirectory)
        $configPath = Join-Path $codexDirectory 'hooks.json'
        [IO.File]::WriteAllText($configPath, '{broken')
        $result = Invoke-Process ('-File "' + $installer + '" -CodexDirectory "' + $codexDirectory + '" -CliPath "' + $fixturePath + '"')
        Assert-True ($result.Code -ne 0) 'Malformed config accepted'
        Assert-True ([IO.File]::ReadAllText($configPath) -eq '{broken') 'Malformed config overwritten'
    }

    Test-Case 'missing CLI leaves setup untouched' {
        $codexDirectory = Join-Path $testRoot 'Missing CLI'
        $result = Invoke-Process ('-File "' + $installer + '" -CodexDirectory "' + $codexDirectory + '" -CliPath "' + (Join-Path $testRoot 'missing.exe') + '"')
        Assert-True ($result.Code -ne 0 -and -not (Test-Path -LiteralPath $codexDirectory)) 'Setup changed without a usable CLI'
    }
} finally {
    $env:ORPHAN_GUARD_FIXTURE_MODE = $oldMode
    $env:ORPHAN_GUARD_FIXTURE_LOG = $oldLog
    if (Test-Path -LiteralPath $fixtureLog) {
        foreach ($line in Get-Content -LiteralPath $fixtureLog) {
            $record = $line | ConvertFrom-Json
            $owned = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
            if ($owned -and $owned.Path -eq $fixturePath -and $owned.StartTime -ge $testStarted) { $owned.Kill(); $owned.WaitForExit(2000) | Out-Null }
        }
    }
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolvedRoot) -notlike 'orphan-guard-integration-*') { throw 'Refusing unsafe test cleanup path' }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
}

Write-Output ("$assertions assertions; $($failures.Count) failed cases")
if ($failures.Count -gt 0) { exit 1 }
