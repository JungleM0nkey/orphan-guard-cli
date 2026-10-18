# OrphanGuard CLI

A standalone Go CLI for inspecting and cleaning up Windows processes from a terminal or coding agent. The original Python system tray application is also included.

## Install the CLI

Requires Windows 10/11 and Go 1.25 or newer. The CLI has no Python or third-party Go dependencies.

```powershell
git clone https://github.com/JungleM0nkey/orphan-guard-cli.git
cd orphan-guard-cli
go install ./cmd/orphan-guard
orphan-guard --help
```

The executable is installed in `GOBIN`, or `%USERPROFILE%\go\bin` by default. Add that directory to your `PATH` if necessary. To build a portable executable instead:

```powershell
go build -trimpath -o bin/orphan-guard.exe ./cmd/orphan-guard
```

## CLI usage

```powershell
# Inspect candidates without changing anything.
orphan-guard scan
orphan-guard scan --json

# Preview cleanup of one candidate. Copy its exact started_at from the scan.
orphan-guard clean --pid 12345 --json
orphan-guard clean --pid 12345 --started-at '2026-10-18T12:00:00.1234567Z' --apply --json

# Create the tray app's default profiles, all disabled.
orphan-guard init --config config.json

# After deliberately enabling a profile in config.json:
orphan-guard scan --config config.json --profile 'Citrix Workspace' --json
orphan-guard clean --config config.json --profile 'Citrix Workspace'
orphan-guard clean --config config.json --profile 'Citrix Workspace' --apply --json
```

Without `--config`, scans report same-session processes whose parent PID is missing or belongs to a newer process. These are **candidates for review**: normal desktop apps, detached servers, and daemons can outlive their parents. A missing parent alone does not mean a process should be stopped.

With `--config`, scans use enabled profiles and the tray app's `window`, `process`, and `blocklist` modes. Window mode requires a visible, titled top-level window owned by the indicator process. An omitted `enabled` value defaults to enabled, matching the tray app. All generated defaults explicitly set it to `false`. The CLI rejects malformed profiles, duplicate names, wildcard/path targets, protected targets, and unknown fields instead of silently rewriting the file. `init` never overwrites an existing file.

The default minimum process age is one minute. Use `--min-age 5m` to restrict scans further, or deliberately use `--min-age 0` for newly created processes. CLI commands are one-shot operations; `auto_kill` and `scan_interval_seconds` never trigger automatic cleanup or monitoring.

`clean` is a dry run unless `--apply` is supplied. Applying requires a named profile or an explicit PID; a PID additionally requires its exact `started_at` timestamp. The CLI rechecks eligibility, then verifies the executable and creation time on the same native process handle used for termination. Critical Windows processes, Herdr, supported coding agents, the CLI, and its ancestors are protected. Other Windows sessions are excluded. Access failures are reported without automatic elevation. Only selected processes are terminated; descendants are not implicitly killed. Termination is forced and can discard unsaved work in a selected application.

## Agent output and exit codes

`scan --json` and `clean --json` write a single report to stdout:

```json
{
  "schema_version": 1,
  "command": "scan",
  "mode": "parent",
  "scanned_at": "2026-10-18T12:05:00Z",
  "process_count": 100,
  "candidates": [
    {
      "pid": 12345,
      "parent_pid": 12344,
      "name": "worker.exe",
      "started_at": "2026-10-18T12:00:00.1234567Z",
      "memory_bytes": 10485760,
      "session_id": 1,
      "reason": "parent_missing"
    }
  ],
  "applied": false,
  "results": []
}
```

Reports expose names and process metadata without command lines or environment variables. `memory_bytes` is the resident working set, or zero if unavailable. Profile matches also include `profile`. Reasons are `parent_missing`, `parent_pid_reused`, `profile_process_missing`, `profile_no_window`, or `profile_blocklist`.

Applied cleanup adds one result per selected PID with `status` set to `terminated`, `exited`, `skipped`, or `failed`; unsuccessful results include `error`. Skipped or failed cleanup returns a nonzero exit code. Preflight errors go to stderr; with `--json`, they use `{"error":"...","exit_code":1}`.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan, preview, initialization, or selected cleanup succeeded; an empty scan is successful. |
| `1` | Runtime/configuration failure, stale or ineligible PID, or incomplete cleanup. |
| `2` | Invalid command, flag, selection, timestamp, or profile selection. |

## Development

```powershell
go test ./...
go vet ./...
go build ./cmd/orphan-guard
```

Tests exercise selection/configuration rules and use disposable test-helper processes for actual Windows snapshots, dry runs, stale PID protection, and termination. Process inspection and cleanup require Windows; other platforms return an explicit unsupported-platform error.

## Python tray application

Some Windows applications sneakily (or lazily) leave processes behind after their parent app has been closed. Consequences range from mild annoyance (memory bloat) to actual workflow problems (Citrix leaves processes behind that interfere with subsequent connection attempts).

This utility makes it easy to detect and clean them up, working directly from your system tray.

### Tray features

- **System tray** monitoring with configurable scan interval
- **Three detection modes**:
  - **Window** — app is "running" only while it has a visible window
  - **Process** — app is "running" while its indicator process exists
  - **Blocklist** — processes are always unwanted (bloatware cleanup)
- **Auto-kill** option per profile for hands-free cleanup
- **Process browser** to discover and add target processes
- **Start with Windows** via registry
- Built-in profiles for Edge, Teams, Zoom, Citrix, and common Windows bloatware

### Tray requirements

- Windows 10/11
- Python 3.10+

### Tray setup

```
git clone https://github.com/JungleM0nkey/orphan-guard-cli.git
cd orphan-guard-cli
```

Run `setup.bat` to create a virtual environment and install dependencies, or manually:

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Tray usage

```
run.bat
```

Or directly:

```
pythonw orphan_guard.py
```

OrphanGuard appears in the system tray. Right-click for options:

- **View Details** — see all detected orphans
- **Kill All / Kill [Profile]** — terminate orphaned processes
- **Scan Now** — run an immediate scan
- **Settings** — manage profiles, scan interval, and auto-kill

### Tray configuration

A `config.json` is created automatically on first run with default profiles (all disabled). Edit it through the Settings UI or directly:

```json
{
  "scan_interval_seconds": 15,
  "profiles": [
    {
      "name": "Microsoft Edge",
      "enabled": false,
      "indicator": { "process": "msedge.exe", "mode": "window" },
      "targets": ["msedge.exe", "msedgewebview2.exe"],
      "auto_kill": false
    }
  ]
}
```

## License

MIT
