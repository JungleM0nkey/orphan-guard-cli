param([string]$CliPath = 'orphan-guard.exe')

$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$skillPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../SKILL.md'))
$scanner = $null
$context = 'OrphanGuard startup scan unavailable. For Windows process cleanup, load ' + $skillPath + '.'

try {
    $event = [Console]::In.ReadToEnd() | ConvertFrom-Json
    if ($event.hook_event_name -ne 'SessionStart') { exit 0 }

    $executable = (Get-Command $CliPath -CommandType Application -ErrorAction Stop).Source
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $executable
    $start.Arguments = 'scan --json'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $scanner = [Diagnostics.Process]::new()
    $scanner.StartInfo = $start
    [void]$scanner.Start()
    $stdoutTask = $scanner.StandardOutput.ReadToEndAsync()
    $stderrTask = $scanner.StandardError.ReadToEndAsync()
    if (-not $scanner.WaitForExit(5000)) {
        $scanner.Kill()
        [void]$scanner.WaitForExit(1000)
        throw 'Scanner timed out'
    }
    if (-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutTask, $stderrTask), 1000)) { throw 'Scanner output timed out' }
    if ($scanner.ExitCode -ne 0) { throw 'Scanner failed' }
    $scan = $stdoutTask.Result | ConvertFrom-Json
    if ($scan.schema_version -ne 1 -or $scan.command -ne 'scan' -or $scan.mode -ne 'parent' -or $scan.applied -isnot [bool] -or $scan.applied -or $scan.candidates -isnot [array]) { throw 'Invalid scan report' }
    if (($scan.process_count -isnot [int] -and $scan.process_count -isnot [long]) -or $scan.process_count -lt $scan.candidates.Count) { throw 'Invalid scan counts' }
    $context = 'OrphanGuard SessionStart scan (read-only): {0} processes, {1} candidate(s). For Windows process cleanup or buildup, load {2} ($orphan-guard). Candidates require review; this baseline does not authorize cleanup.' -f $scan.process_count, $scan.candidates.Count, $skillPath
} catch {
    # Scanner diagnostics can contain private data; emit only the fixed fallback.
} finally {
    if ($scanner) { $scanner.Dispose() }
}

[Console]::WriteLine((@{
    continue = $true
    hookSpecificOutput = @{
        hookEventName = 'SessionStart'
        additionalContext = $context
    }
} | ConvertTo-Json -Depth 4 -Compress))
