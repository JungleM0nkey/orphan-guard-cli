---
name: orphan-guard
description: Use when reviewing OrphanGuard session-start candidates, investigating Windows process buildup, or cleaning up orphaned processes.
---

# OrphanGuard

Inspect Windows process candidates with the installed `orphan-guard` CLI. Use `orphan-guard --help` for current flags. A session-start summary is advisory; act on process cleanup only within the user's task.

When cleanup or investigation is requested:

1. Run a fresh `orphan-guard scan --json`. Default scans find missing or reused parent PIDs; `--config PATH` switches to enabled application profiles. A missing parent also describes legitimate desktop apps and detached servers.
2. Match each selected PID and `started_at` to current ownership and purpose. Check executable and command line with `Get-CimInstance Win32_Process -Filter 'ProcessId = 12345'`, plus active agent/session records. Keep active agent jobs, terminals, services, and unresolved candidates running. Existing cleanup authorization covers confirmed stale jobs.
3. Preview the explicit selection, then apply once its identity and abandonment are established:

   ```powershell
   orphan-guard clean --pid 12345 --started-at '2026-10-18T12:00:00.1234567Z' --json
   orphan-guard clean --pid 12345 --started-at '2026-10-18T12:00:00.1234567Z' --apply --json
   ```

   Substitute the reviewed PID and its exact timestamp from the fresh scan. Profile cleanup requires both `--config` and `--profile`. Selected PIDs are terminated individually; descendant cleanup needs separate selection.
4. Inspect every cleanup result and the exit code, then rescan. Report confirmed removals and unresolved candidates separately. A report can contain partial failures; stale identity or changed eligibility requires fresh evaluation.

With RTK, capture and parse the executable's stdout inside PowerShell before formatting a short summary; direct `rtk proxy orphan-guard ...` can filter or truncate JSON. Check `$LASTEXITCODE` before parsing. Startup hooks run only the read-only scan. Termination uses the explicit cleanup workflow above.
