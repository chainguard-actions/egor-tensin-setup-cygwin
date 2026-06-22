<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v3.0.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--setup-cygwin/v3.0.1** was hardened automatically. 8 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple ${{ ... }} expressions are directly interpolated inside run: blocks in action.yml, violating sub-rule (a). This allows an attacker-controlled value to be injected into the PowerShell script before the shell parses it. Offending lines:
- Line 27: `New-Variable os -Value ('${{ runner.os }}') -Option Constant`
- Line 35: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV`
- Line 39: `New-Variable x64 -Value ('${{ inputs.platform }}' -eq 'x64') -Option Constant`
- Line 40: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant`
- Line 41: `New-Variable packages -Value '${{ inputs.packages }}' -Option Constant`
- Line 84: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant`
- Line 85: `New-Variable hardlinks -Value ('${{ inputs.hardlinks }}' -eq '1') -Option Constant`
All inputs.* and runner.* values should be passed via environment variables and referenced as $env:VAR_NAME inside the run block, never interpolated directly.

Locations:

- `action.yml:27`
- `action.yml:35`
- `action.yml:39`
- `action.yml:40`
- `action.yml:41`
- `action.yml:84`
- `action.yml:85`

### github-env-injection (severity: high)

Untrusted input values are written directly to $GITHUB_ENV and $GITHUB_PATH without sanitization (no `printf '%s' ... | tr -d '\n\r'` step applied before the write).
- Line 35: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV` — the `inputs.env` value is interpolated directly into the GITHUB_ENV write. A newline in the value can inject arbitrary environment variables.
- Line 68-69: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH` and `echo (Join-Path $install_dir usr local bin) >> $env:GITHUB_PATH` — `$install_dir` is derived from `${{ inputs.install-dir }}` (line 40) without sanitization before being written to GITHUB_PATH.

Locations:

- `action.yml:35`
- `action.yml:68`
- `action.yml:69`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.env }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:37`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.platform }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:41`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.install-dir }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:42`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.packages }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:43`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.install-dir }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:85`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.hardlinks }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:86`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all high-severity findings in action.yml by:
1. Moving all ${{ runner.os }}, ${{ inputs.* }} expressions from run: blocks into env: blocks for each step, referencing them as $env:VAR_NAME in PowerShell.
2. Sanitizing inputs.env before writing to GITHUB_ENV using PowerShell's -replace '[\r\n]', '' to strip newlines.
3. Sanitizing the install_dir (derived from inputs.install-dir) before writing to GITHUB_PATH using the same newline-stripping approach.
4. All four steps now have proper env: blocks with the expressions, and the run: blocks only reference environment variables.

