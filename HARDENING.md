<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v3.0.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-cygwin/v3.0.1** was hardened automatically. 10 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple ${{ }} expressions are directly interpolated inside run: blocks in action.yml (sub-rule a). This allows an attacker-controlled value to be injected into the PowerShell script before the shell parses it. Affected expressions:
- Line 27: `'${{ runner.os }}'` in a pwsh run block
- Line 35: `echo 'CYGWIN=${{ inputs.env }}'` written to $GITHUB_ENV
- Line 39: `'${{ inputs.platform }}'`
- Line 40: `'${{ inputs.install-dir }}'`
- Line 41: `'${{ inputs.packages }}'`
- Line 64: `'${{ inputs.install-dir }}'`
- Line 65: `'${{ inputs.hardlinks }}'`
All of these should be passed via env: variables and then referenced as PowerShell env vars (e.g. $env:INPUT_PLATFORM) instead of being interpolated directly into the script string.

Locations:

- `action.yml:27`
- `action.yml:35`
- `action.yml:39`
- `action.yml:40`
- `action.yml:41`
- `action.yml:64`
- `action.yml:65`

### github-env-injection (severity: high)

Unsanitized user-controlled values are written to GitHub special environment files without the required sanitization step (printf '%s' ... | tr -d '\n\r'):
1. Line 35: `echo 'CYGWIN=${{ inputs.env }}' >> $env:GITHUB_ENV` — the value of inputs.env is interpolated directly into the GITHUB_ENV write, allowing newline injection to set arbitrary environment variables.
2. Lines 57-58: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH` and `echo (Join-Path $install_dir usr local bin) >> $env:GITHUB_PATH` — $install_dir is derived from `${{ inputs.install-dir }}` (line 40) and written to GITHUB_PATH without sanitization, allowing path injection via embedded newlines.

Locations:

- `action.yml:35`
- `action.yml:57`
- `action.yml:58`

### unpinned-uses (severity: high)

The workflow file uses action references pinned to mutable tags rather than immutable full-length SHA commit hashes. This exposes the workflow to supply-chain attacks if the tag is moved or the upstream repository is compromised. Failing references:
- `uses: actions/checkout@v3` (appears 3 times)
- `uses: egor-tensin/cleanup-path@v3` (appears 3 times)
All should be pinned to a full 40-character hex SHA, e.g. `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`.

Locations:

- `.github/workflows/test.yml:31`
- `.github/workflows/test.yml:34`
- `.github/workflows/test.yml:72`
- `.github/workflows/test.yml:75`
- `.github/workflows/test.yml:92`
- `.github/workflows/test.yml:95`

### missing-permissions (severity: medium)

The workflow file .github/workflows/test.yml has no top-level `permissions:` key and none of its three jobs (test, shell_igncr, shell_shellopts) define a `permissions:` block. Without explicit permissions, the GITHUB_TOKEN is granted its default permissions (which may include write access to repository contents, packages, etc.), violating the principle of least privilege. A `permissions: {}` or minimal scoped block should be added at the top level or to each job.

Locations:

- `.github/workflows/test.yml:1`

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

**Fixes applied:** script-injection, static-inline-injection, github-env-injection, unpinned-uses, missing-permissions

**Notes:**

Fixed action.yml: moved all ${{ }} expressions from run: blocks into env: blocks, referencing them as PowerShell $env:VAR_NAME variables. Sanitized inputs.env before writing to GITHUB_ENV (using -replace '[\r\n]', ''), and sanitized install_dir-derived paths before writing to GITHUB_PATH. Fixed test.yml: added top-level 'permissions: {}' block, and pinned all action references to full SHAs (actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744 # v3, egor-tensin/cleanup-path@8469525c8ee3eddabbd3487658621a6235b3c581 # v3).

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in .github/workflows/test.yml at the 'Check CYGWIN environment variable' step. Moved `${{ matrix.env }}` from the `run:` shell string into an `env:` block as `MATRIX_ENV: ${{ matrix.env }}`, and updated the PowerShell comparison from `$($env:CYGWIN -eq '${{ matrix.env }}')` to `$($env:CYGWIN -eq $env:MATRIX_ENV)`. This ensures the matrix value is passed as an environment variable rather than being directly interpolated into the shell command string.

