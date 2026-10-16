<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v4.0.3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-cygwin/v4.0.3** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple `run:` blocks in action.yml directly interpolate GitHub Actions expressions (`${{ ... }}`) inside PowerShell shell commands, violating rule (a). This allows an attacker-controlled value to be injected into the shell command string before the shell ever sees it.

- Line 24: `New-Variable os -Value ('${{ runner.os }}') -Option Constant` — `runner.os` interpolated directly into pwsh run block.
- Line 33: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV` — `inputs.env` (attacker-controlled) interpolated directly into pwsh run block.
- Line 36: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant` — `inputs.install-dir` interpolated directly.
- Line 37: `New-Variable packages -Value '${{ inputs.packages }}' -Option Constant` — `inputs.packages` interpolated directly.
- Line 65: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant` — `inputs.install-dir` interpolated directly.
- Line 66: `New-Variable hardlinks -Value ('${{ inputs.hardlinks }}' -eq '1') -Option Constant` — `inputs.hardlinks` interpolated directly.

All of these should be passed via `env:` variables instead of inline interpolation.

Locations:

- `action.yml:24`
- `action.yml:33`
- `action.yml:36`
- `action.yml:37`
- `action.yml:65`
- `action.yml:66`

### github-env-injection (severity: high)

Multiple `run:` blocks write values derived from untrusted inputs to `$GITHUB_ENV` or `$GITHUB_PATH` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`).

- Line 33: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV` — `inputs.env` is written directly to GITHUB_ENV. An attacker can inject newlines to set arbitrary environment variables.
- Line 57: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH` — `$install_dir` is derived from `${{ inputs.install-dir }}` (line 36) and written to GITHUB_PATH without sanitization.
- Line 58: `echo (Join-Path $install_dir usr local bin) >> $env:GITHUB_PATH` — same issue; `$install_dir` from `inputs.install-dir` written to GITHUB_PATH without sanitization.

Locations:

- `action.yml:33`
- `action.yml:57`
- `action.yml:58`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.env }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:33`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.install-dir }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:37`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.packages }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:38`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.install-dir }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:72`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.hardlinks }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:73`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all findings in hardened/action/action.yml:

1. Step 1 (runner.os check): Moved `${{ runner.os }}` to `env: RUNNER_OS:`, referenced as `$env:RUNNER_OS` in PowerShell.

2. Step 2 (GITHUB_ENV write): Moved `${{ inputs.env }}` to `env: INPUT_ENV:`, sanitized with `-replace '[\r\n]', ''` before writing `CYGWIN=...` to `$env:GITHUB_ENV`.

3. Step 3 (Cygwin install): Moved `${{ inputs.install-dir }}` and `${{ inputs.packages }}` to `env:` block as `INPUT_INSTALL_DIR` and `INPUT_PACKAGES`. `install_dir` is sanitized with `-replace '[\r\n]', ''` before use (including before being written to `$GITHUB_PATH` via `Join-Path`).

4. Step 4 (hardlinks): Moved `${{ inputs.install-dir }}` and `${{ inputs.hardlinks }}` to `env:` block as `INPUT_INSTALL_DIR` and `INPUT_HARDLINKS`. Both are sanitized with `-replace '[\r\n]', ''` before use.

All PowerShell env var references use the correct `$env:VAR_NAME` syntax. Newline sanitization uses PowerShell's `-replace '[\r\n]', ''` which strips both CR and LF characters.

