# OrphanGuard for Codex

The skill guides process review and explicit cleanup. The SessionStart hook runs one read-only scan and supplies process counts plus a pointer to the skill. It runs on session starts, including resumed sessions; it does not poll or clean up candidates.

## Install

Requires Windows PowerShell 5.1, Codex with hooks enabled, and the native `orphan-guard.exe` CLI on PATH. The Go CLI is tracked in [PR #1](https://github.com/JungleM0nkey/orphan-guard-cli/pull/1); the Python tray application does not provide its commands.

From this repository:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File integrations/codex/install.ps1
```

Pass `-CliPath 'C:\path\to\orphan-guard.exe'` if the executable is outside PATH. The installer uses `CODEX_HOME` when set, otherwise `%USERPROFILE%\.codex`; `-CodexDirectory` overrides that destination.

The installer copies `skills/orphan-guard` into the Codex skills directory and appends one handler to `hooks.json`. Existing handlers and other settings are preserved. Reinstallation updates this handler without duplicating it. A changed existing configuration is saved beside the original as `hooks.json.orphan-guard-<id>.bak` before replacement.

In Codex, open `/hooks` to review and trust the new handler. Codex skips untrusted hooks; see [OpenAI's hook trust documentation](https://learn.chatgpt.com/docs/hooks#review-and-trust-hooks). Start a new session after trusting it to receive the scan summary and discover the installed skill.

## Use

Invoke `$orphan-guard` or request orphan-process cleanup. The skill calls for a fresh scan, ownership review, and a dry run before applying an explicit selection. Parentless processes can be legitimate applications or detached servers. The startup summary alone does not authorize termination.

The hook invokes only `scan --json`. It forwards counts rather than process names, command lines, or scanner diagnostics. Failure returns a short unavailable message and allows the session to continue. A scan exceeding five seconds is stopped through the hook's own child-process handle; unrelated processes are untouched.

## Verify changes

With Go installed, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File integrations/codex/tests/test.ps1
```

The tests build a disposable scanner fixture and exercise read-only arguments, failures, timeouts, path escaping, configuration preservation, and repeat installation. They do not terminate user processes. To remove the integration, delete its handler through `/hooks` and remove the installed `skills/orphan-guard` directory.
