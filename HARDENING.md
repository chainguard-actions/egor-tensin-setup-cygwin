<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v4.0.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-cygwin/v4.0.2** was hardened automatically. 9 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple `${{ ... }}` expressions are directly interpolated inside `run:` shell command strings in action.yml, violating sub-rule (a). This allows an attacker-controlled value to be injected into the PowerShell script before the shell ever sees it:
- Line 23: `New-Variable os -Value ('${{ runner.os }}') -Option Constant`
- Line 31: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV`
- Line 35: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant`
- Line 36: `New-Variable packages -Value '${{ inputs.packages }}' -Option Constant`
- Line 62: `New-Variable install_dir -Value '${{ inputs.install-dir }}' -Option Constant`
- Line 63: `New-Variable hardlinks -Value ('${{ inputs.hardlinks }}' -eq '1') -Option Constant`
All inputs should be passed via environment variables and referenced as `$env:VAR_NAME` in the PowerShell script, never interpolated directly.

Locations:

- `action.yml:23`
- `action.yml:31`
- `action.yml:35`
- `action.yml:36`
- `action.yml:62`
- `action.yml:63`

### github-env-injection (severity: high)

Untrusted input values are written to GitHub special environment files without sanitization:
- Line 31: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV` — the `inputs.env` value is interpolated directly into the GITHUB_ENV write. A newline in the input could inject arbitrary environment variables.
- Lines 55–56: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH` and `echo (Join-Path $install_dir usr local bin) >> $env:GITHUB_PATH` — `$install_dir` is derived from `${{ inputs.install-dir }}` (line 35) without sanitization before being written to GITHUB_PATH. A newline in the input could inject arbitrary PATH entries.
The sanitization step (`printf '%s' ... | tr -d '\n\r'`) must be applied before every write to GITHUB_ENV or GITHUB_PATH when the value originates from user-controlled input.

Locations:

- `action.yml:31`
- `action.yml:55`
- `action.yml:56`

### unpinned-uses (severity: high)

The workflow file references external actions using mutable tag refs instead of immutable full 40-character SHA digests. This exposes the workflow to supply-chain attacks if the tag is moved or the repository is compromised:
- `uses: actions/checkout@v6` (appears on lines 35, 73, 87)
- `uses: egor-tensin/cleanup-path@v3` (appears on lines 38, 76, 90)
All `uses:` references should be pinned to a full commit SHA, e.g. `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`.

Locations:

- `.github/workflows/test.yml:35`
- `.github/workflows/test.yml:38`
- `.github/workflows/test.yml:73`
- `.github/workflows/test.yml:76`
- `.github/workflows/test.yml:87`
- `.github/workflows/test.yml:90`

### missing-permissions (severity: medium)

The workflow file `.github/workflows/test.yml` has no top-level `permissions:` key, and none of its three jobs (`test`, `shell_igncr`, `shell_shellopts`) define a job-level `permissions:` block. Without explicit permissions, the workflow inherits the default repository permissions (which may include `contents: write` and other broad scopes depending on repository settings). A minimal `permissions: {}` or specific scopes (e.g. `contents: read`) should be declared at the top level or per job.

Locations:

- `.github/workflows/test.yml:1`

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

**Fixes applied:** script-injection, static-inline-injection, github-env-injection, unpinned-uses, missing-permissions

**Notes:**

Fixed action.yml: moved all ${{ }} expressions from run: blocks to env: maps, referencing them as $env:VAR_NAME in PowerShell. Sanitized values written to GITHUB_ENV and GITHUB_PATH using PowerShell -replace '[\r\n]', '' to strip newlines. Fixed .github/workflows/test.yml: pinned actions/checkout@v6 to SHA df4cb1c069e1874edd31b4311f1884172cec0e10 and egor-tensin/cleanup-path@v3 to SHA 8469525c8ee3eddabbd3487658621a6235b3c581 (all 6 occurrences), and added top-level permissions: {} block.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in the 'Check CYGWIN environment variable' step of .github/workflows/test.yml. Moved `${{ matrix.env }}` out of the run: shell string into an env: block as MATRIX_ENV, and updated the PowerShell comparison from `'${{ matrix.env }}'` to `$env:MATRIX_ENV`. This prevents the matrix-controlled value from being interpolated directly into the shell command string.

