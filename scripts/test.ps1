param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $PytestArgs
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
$codexPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"

if (Test-Path $venvPython) {
    $python = $venvPython
} elseif (Test-Path $codexPython) {
    $python = $codexPython
} else {
    throw "No supported CPython 3.12 runtime found. Create .venv or install the Codex primary runtime."
}

$depsPath = Join-Path $repoRoot ".codex_deps"
if (Test-Path $depsPath) {
    $env:PYTHONPATH = "$depsPath;$repoRoot"
} else {
    $env:PYTHONPATH = "$repoRoot"
}

Push-Location $repoRoot
try {
    & $python -m app.toolchain check
    if ($PytestArgs.Count -eq 0) {
        & $python -m pytest tests -v
    } else {
        & $python -m pytest @PytestArgs
    }
} finally {
    Pop-Location
}
