<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v4.0.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-cygwin/v4.0.5** was hardened automatically. 3 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): A GitHub Actions expression `${{ runner.os }}` is directly interpolated inside a `run:` shell command string on line 24: `if ('${{ runner.os }}' -ne 'Windows')`. Any `${{ ... }}` expression inside a `run:` block is a script-injection risk because the value is substituted into the shell command string before the shell parses it, allowing template-injected content to alter control flow.

Locations:

- `action.yml:24`

### github-env-injection (severity: high)

Step 2 writes the caller-controlled input `inputs.env` (mapped to env var `ARG_ENV`) directly to `$GITHUB_ENV` without sanitization: `echo "CYGWIN=$env:ARG_ENV" >> $env:GITHUB_ENV`. A newline character in `inputs.env` would allow an attacker to inject arbitrary environment variable definitions into subsequent steps. The required sanitization (stripping newlines before the write) is absent.

Locations:

- `action.yml:32`

### github-env-injection (severity: high)

Step 3 writes the caller-controlled input `inputs.install-dir` (mapped to env var `ARG_INSTALL_DIR`, then read into `$install_dir`) to `$GITHUB_PATH` without sanitization: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH` and `echo (Join-Path $install_dir usr local bin) >> $env:GITHUB_PATH`. A newline character embedded in `inputs.install-dir` would allow an attacker to inject arbitrary entries into `$GITHUB_PATH`, potentially hijacking commands used by subsequent steps. The required sanitization (stripping newlines before the write) is absent.

Locations:

- `action.yml:57`
- `action.yml:58`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed three findings in action.yml:
1. script-injection: Moved `${{ runner.os }}` from inline run: string to env: block as RUNNER_OS_VAL, referenced as `$env:RUNNER_OS_VAL` in PowerShell (correct pwsh syntax).
2. github-env-injection (inputs.env/ARG_ENV): Added `$safe_env = $env:ARG_ENV -replace "`r", "" -replace "`n", ""` before writing to $GITHUB_ENV.
3. github-env-injection (inputs.install-dir/ARG_INSTALL_DIR): Added `-replace "`r", "" -replace "`n", ""` to the $install_dir assignment before it is used in Join-Path calls that write to $GITHUB_PATH.

