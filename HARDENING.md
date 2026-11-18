<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-cygwin/v4.0.5

> This file was generated automatically by the hardening agent.

**Policy SHA:** `374911c4be584df24e6da57af2d990570ef0f859`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-cygwin/v4.0.5** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): a GitHub Actions expression is placed straight into a pwsh run: script: `if ('${{ runner.os }}' -ne 'Windows') {`. Read the built-in $env:RUNNER_OS environment variable instead.

Locations:

- `action.yml:24`

### github-env-injection (severity: high)

The value of inputs.env is written to $GITHUB_ENV without sanitization: `echo "CYGWIN=$env:ARG_ENV" >> $env:GITHUB_ENV`. Passing it through an env: variable does not make it safe. A newline in the input would inject extra environment variables, such as LD_PRELOAD or NODE_OPTIONS, into later steps. Strip CR/LF characters from the value before writing it.

Locations:

- `action.yml:32`

### github-env-injection (severity: high)

A path built from inputs.install-dir (ARG_INSTALL_DIR -> $install_dir) is written to $GITHUB_PATH without stripping newlines: `echo (Join-Path $install_dir bin) >> $env:GITHUB_PATH` and `echo (Join-Path $install_dir usr local bin) >> $env:GITHUB_PATH`. A newline in the input would add arbitrary entries to PATH. Strip CR/LF characters before writing.

Locations:

- `action.yml:64`
- `action.yml:65`

### prior-fix (severity: high)

Carried forward from this version's previous harden, which fixed it; fix it again unless the code no longer has the problem. The previous harden changed action.yml without recording a finding for it, and this analysis reported nothing there. Re-apply its security changes unless the code no longer needs them. The previous patch:
```diff
diff --git a/action.yml b/action.yml
index 0acbbe4..ca244fa 100644
--- a/action.yml
+++ b/action.yml
@@ -20,23 +20,43 @@ inputs:
 runs:
   using: composite
   steps:
-    - run: |
-        if ('${{ runner.os }}' -ne 'Windows') {
-            throw "Sorry, installing Cygwin is unsupported on $os"
+    - env:
+        RUNNER_OS_VAL: ${{ runner.os }}
+      run: |
+        if ($env:RUNNER_OS_VAL -ne 'Windows') {
+            throw "Sorry, installing Cygwin is unsupported on $env:RUNNER_OS_VAL"
         }
       shell: pwsh
 
     - env:
         ARG_ENV: ${{ inputs.env }}
       run: |
-        echo "CYGWIN=$env:ARG_ENV" >> $env:GITHUB_ENV
+        $safe_env = $env:ARG_ENV -replace "`r", "" -replace "`n", ""
+        echo "CYGWIN=$safe_env" >> $env:GITHUB_ENV
       shell: pwsh
 
     - env:
         ARG_INSTALL_DIR: ${{ inputs.install-dir }}
         ARG_PACKAGES: ${{ inputs.packages }}
       run: |
-        $install_dir = (Get-ChildItem env:ARG_INSTALL_DIR).Value
+        $install_dir = ((Get-ChildItem env:ARG_INSTALL_DIR).Value) -replace "`r", "" -replace "`n", ""
         $packages = (Get-ChildItem env:ARG_PACKAGES).Value
 
         function Locate-Choco {

```

Locations:

- `action.yml`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, prior-fix

**Notes:**

I fixed all the findings in action.yml. I haven't run the action, and the new PowerShell lines weren't executed.

- **script-injection:** The OS check now reads the built-in `$env:RUNNER_OS` instead of inserting `${{ runner.os }}` into the script. The error message used to name an undefined `$os`, so it would have shown no OS name. It now shows the real one.
- **`inputs.env` written to `$GITHUB_ENV`:** CR and LF characters are removed before the value is written as `CYGWIN=`.
- **`inputs.install-dir` written to `$GITHUB_PATH`:** CR and LF are removed when `$install_dir` is first set, so the choco install folder is cleaned as well. Both PATH lines are also cleaned again at the point they're written.
- **prior-fix:** This covers everything the previous harden changed. The one difference is that I didn't add its extra `RUNNER_OS_VAL` variable, because the runner already sets `RUNNER_OS`.

