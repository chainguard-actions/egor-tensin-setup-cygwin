<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v4.0.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--setup-cygwin/v4.0.1** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple run: blocks in action.yml directly interpolate ${{ ... }} expressions inside shell command strings (sub-rule a), which is a script injection risk. Affected lines:
- Line 23: `New-Variable os -Value ('${{ runner.os }}') -Option Constant`
- Line 31: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV`
- Line 34: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant`
- Line 35: `New-Variable packages -Value '${{ inputs.packages }}' -Option Constant`
- Line 66: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant`
- Line 67: `New-Variable hardlinks -Value ('${{ inputs.hardlinks }}' -eq '1') -Option Constant`
All of these embed GitHub Actions expressions directly into the PowerShell run: script before the shell ever sees the value, allowing an attacker to inject arbitrary PowerShell commands via crafted input values.

Locations:

- `action.yml:23`
- `action.yml:31`
- `action.yml:34`
- `action.yml:35`
- `action.yml:66`
- `action.yml:67`

### github-env-injection (severity: high)

Two run: blocks write values derived from untrusted inputs to special GitHub environment files without sanitization:
1. Line 31: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV` — the value of inputs.env is interpolated directly and written to $GITHUB_ENV with no newline stripping, allowing an attacker to inject additional environment variables.
2. Lines 57-58: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH` and `echo (Join-Path $install_dir usr local bin) >> $env:GITHUB_PATH` — $install_dir is derived from `${{ inputs.install-dir }}` (line 34) and written to $GITHUB_PATH without sanitization, allowing path injection.

Locations:

- `action.yml:31`
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

- `action.yml:77`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.hardlinks }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:78`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all script-injection, github-env-injection, and static-inline-injection findings in action.yml by: (1) Moving all ${{ runner.os }}, ${{ inputs.env }}, ${{ inputs.install-dir }}, ${{ inputs.packages }}, and ${{ inputs.hardlinks }} expressions from run: blocks into env: blocks on each step, referencing them via $env:VARIABLE_NAME in PowerShell; (2) Sanitizing values written to $GITHUB_ENV and $GITHUB_PATH by stripping newlines/carriage returns using PowerShell's -replace '[\r\n]', '' before writing to the special environment files. The bash heredoc content in the last step was preserved unchanged as it contains no GitHub Actions expressions.

