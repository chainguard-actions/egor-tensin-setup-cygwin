<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v4.0.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-cygwin/v4.0.4** was hardened automatically. 3 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): A GitHub Actions expression `${{ runner.os }}` is directly interpolated inside a `run:` shell command string on line 24. Any `${{ ... }}` expression inside a `run:` block is a script-injection risk because the value is substituted into the shell command string before the shell parses it. Offending line: `if ('${{ runner.os }}' -ne 'Windows') {`

Locations:

- `action.yml:24`

### github-env-injection (severity: high)

Step 2 writes the untrusted input `inputs.env` (mapped to env var `ARG_ENV`) directly to `$GITHUB_ENV` without sanitization. An attacker-controlled newline in the value can inject arbitrary environment variables into subsequent steps. The required sanitization step (`printf '%s' "$ARG_ENV" | tr -d '\n\r'`) is absent. Offending line: `echo "CYGWIN=$env:ARG_ENV" >> $env:GITHUB_ENV`

Locations:

- `action.yml:32`

### github-env-injection (severity: high)

Step 3 writes the untrusted input `inputs.install-dir` (mapped via `ARG_INSTALL_DIR` into `$install_dir`) to `$GITHUB_PATH` twice without sanitization. An attacker-controlled newline in the install-dir value can inject arbitrary entries into the runner's PATH. The required sanitization step is absent before both writes. Offending lines: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH` and `echo (Join-Path $install_dir usr local bin) >> $env:GITHUB_PATH`

Locations:

- `action.yml:57`
- `action.yml:58`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed three findings in hardened/action/action.yml:
1. script-injection: Moved `${{ runner.os }}` from inline run: string to env: block as RUNNER_OS_VAL, referenced as `$env:RUNNER_OS_VAL` in PowerShell.
2. github-env-injection (step 2): Sanitized `$env:ARG_ENV` with `-replace '[\r\n]', ''` before writing to $GITHUB_ENV.
3. github-env-injection (step 3): Sanitized `$env:ARG_INSTALL_DIR` with `-replace '[\r\n]', ''` when assigning to `$install_dir`, which is then used in both `echo ... >> $env:GITHUB_PATH` writes.

