<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v4.0.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-cygwin/v4.0.1** was hardened automatically. 9 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### unpinned-uses (severity: high)

The workflow file references actions by mutable tag rather than a pinned 40-character commit SHA. This exposes the workflow to supply-chain attacks if the tag is moved. Failing references: `actions/checkout@v3` (used in all three jobs) and `egor-tensin/cleanup-path@v3` (used in all three jobs). These should be pinned to their full SHA digests, e.g. `actions/checkout@<40-char-sha> # v3`.

Locations:

- `.github/workflows/test.yml:30`
- `.github/workflows/test.yml:33`
- `.github/workflows/test.yml:63`
- `.github/workflows/test.yml:66`
- `.github/workflows/test.yml:83`
- `.github/workflows/test.yml:86`

### script-injection (severity: high)

Multiple `${{ ... }}` expressions are interpolated directly inside `run:` shell (PowerShell) blocks in action.yml, violating rule (a). This means the template value is substituted into the shell command string before PowerShell ever parses it, allowing an attacker-controlled value to inject arbitrary PowerShell commands. Offending lines:
- Step 1: `New-Variable os -Value ('${{ runner.os }}')` — runner context injected into pwsh
- Step 2: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV` — attacker-controlled input injected into pwsh
- Step 3: `New-Variable install_dir -Value '${{ inputs.install-dir }}'` and `New-Variable packages -Value '${{ inputs.packages }}'` — attacker-controlled inputs injected into pwsh
- Step 4: `New-Variable install_dir -Value '${{ inputs.install-dir }}'` and `New-Variable hardlinks -Value ('${{ inputs.hardlinks }}' -eq '1')` — attacker-controlled inputs injected into pwsh
All these expressions should be passed via `env:` variables and referenced as `$env:VAR_NAME` in the shell script.

Locations:

- `action.yml:22`
- `action.yml:28`
- `action.yml:31`
- `action.yml:32`
- `action.yml:68`
- `action.yml:69`

### github-env-injection (severity: high)

Untrusted input values are written to GitHub special environment files without sanitization.

(1) Step 2 writes `inputs.env` directly to `$GITHUB_ENV`: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV`. An attacker can inject newlines into `inputs.env` to set arbitrary environment variables for subsequent steps.

(2) Step 3 writes `$install_dir` (set from `${{ inputs.install-dir }}`) to `$GITHUB_PATH`: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH`. An attacker-controlled `inputs.install-dir` containing newlines can inject arbitrary entries into GITHUB_PATH.

The required sanitization (`printf '%s' "$VAR" | tr -d '\n\r'`) is absent before both writes.

Locations:

- `action.yml:28`
- `action.yml:56`

### permissions (severity: medium)

The workflow file `.github/workflows/test.yml` has no top-level `permissions:` key and none of its three jobs (`test`, `shell_igncr`, `shell_shellopts`) define a `permissions:` block. Without explicit permissions, the workflow inherits the repository's default token permissions, which may be overly broad (e.g. `write` on contents). A minimal `permissions: {}` or specific scopes should be declared.

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

- `action.yml:77`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.hardlinks }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:78`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, script-injection, github-env-injection, permissions, static-inline-injection

**Notes:**

Fixed all findings in action.yml and .github/workflows/test.yml:

1. **unpinned-uses**: Pinned actions/checkout@v3 → @a37ce9120846195fa4ece8f58b268e6043cb2f26 and egor-tensin/cleanup-path@v3 → @8469525c8ee3eddabbd3487658621a6235b3c581 in all 6 locations in test.yml.

2. **permissions**: Added `permissions: {}` at the top level of test.yml.

3. **script-injection / static-inline-injection**: Moved all ${{ }} expressions in action.yml run: blocks into env: maps and referenced them as $env:VAR_NAME in PowerShell. Affected: runner.os (step 1), inputs.env (step 2), inputs.install-dir and inputs.packages (step 3), inputs.install-dir and inputs.hardlinks (step 4).

4. **github-env-injection**: Added newline sanitization before writing to GITHUB_ENV (step 2: `$safe_env = $env:INPUT_ENV -replace '[\r\n]', ''`) and GITHUB_PATH (step 3: `$safe_bin = ($install_dir -replace '[\r\n]', '')`).

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in the 'Check CYGWIN environment variable' step of .github/workflows/test.yml. Moved `${{ matrix.env }}` out of the run: shell string into an env: block as MATRIX_ENV, and updated the PowerShell comparison from `'${{ matrix.env }}'` to `"$env:MATRIX_ENV"`. This prevents the matrix value from being interpolated directly into the shell command string before execution.

