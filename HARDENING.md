<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v4.0.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--setup-cygwin/v4.0.2** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple run: blocks in action.yml directly interpolate ${{ }} expressions inside PowerShell shell commands, violating sub-rule (a). This allows template substitution to inject arbitrary content before the shell parses the command.

- Line 23: `New-Variable os -Value ('${{ runner.os }}') -Option Constant`
- Line 32: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV`
- Line 36: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant`
- Line 37: `New-Variable packages -Value '${{ inputs.packages }}' -Option Constant`
- Line 68: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant`
- Line 69: `New-Variable hardlinks -Value ('${{ inputs.hardlinks }}' -eq '1') -Option Constant`

All of these should be passed via env: variables instead of direct interpolation.

Locations:

- `action.yml:23`
- `action.yml:32`
- `action.yml:36`
- `action.yml:37`
- `action.yml:68`
- `action.yml:69`

### github-env-injection (severity: high)

Untrusted input values are written to special GitHub environment files without sanitization (no `printf '%s' ... | tr -d '\n\r'` step).

- Line 32: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV` — the user-controlled `inputs.env` is directly interpolated and written to GITHUB_ENV. A newline in the value can inject arbitrary environment variables.
- Lines 57-58: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH` and `echo (Join-Path $install_dir usr local bin) >> $env:GITHUB_PATH` — `$install_dir` is derived from `${{ inputs.install-dir }}` (line 36) without sanitization before being written to GITHUB_PATH.

Locations:

- `action.yml:32`
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

Fixed all high-severity findings in action.yml:
1. script-injection (lines 23, 32, 36, 37, 68, 69): Moved all ${{ }} expressions (runner.os, inputs.env, inputs.install-dir, inputs.packages, inputs.hardlinks) from run: blocks to env: blocks. Each step now references values via PowerShell environment variables ($env:RUNNER_OS, $env:INPUT_ENV, $env:INPUT_INSTALL_DIR, $env:INPUT_PACKAGES, $env:INPUT_HARDLINKS).
2. github-env-injection (lines 32, 57, 58): Sanitized user-controlled values before writing to GITHUB_ENV and GITHUB_PATH using PowerShell's -replace '[\r\n]', '' to strip newlines, preventing environment variable injection.
3. static-inline-injection (lines 33, 37, 38, 72, 73): All direct ${{ }} interpolations in run: blocks eliminated by moving to env: maps.

