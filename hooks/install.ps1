# WAF++ PASS — pre-commit hook installer for Windows (PowerShell)
#
# Usage (from repo root):
#   .\hooks\install.ps1           # install (copy, since symlinks need elevation)
#   .\hooks\install.ps1 -Symlink  # symlink (requires admin or Developer Mode)

param(
    [switch]$Symlink
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Ok($msg)   { Write-Host "✔ $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "▸ $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "! $msg" -ForegroundColor Yellow }
function Write-Abort($msg){ Write-Host "✘ $msg" -ForegroundColor Red; exit 1 }

# ── Find git root ─────────────────────────────────────────────────────────────
try {
    $GitRoot = (git rev-parse --show-toplevel 2>$null).Trim()
} catch {
    Write-Abort "Not inside a git repository."
}
if (-not $GitRoot) { Write-Abort "Not inside a git repository." }

$HooksDir  = Join-Path $GitRoot ".git\hooks"
$HookSrc   = Join-Path $GitRoot "hooks\pre-commit"
$HookDst   = Join-Path $HooksDir "pre-commit"

if (-not (Test-Path $HookSrc)) { Write-Abort "Source hook not found: $HookSrc" }

# ── Handle existing hook ──────────────────────────────────────────────────────
if (Test-Path $HookDst) {
    $Backup = "$HookDst.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
    Write-Warn "Existing hook found — backing up to $([System.IO.Path]::GetFileName($Backup))"
    Move-Item $HookDst $Backup
}

# ── Install ───────────────────────────────────────────────────────────────────
if ($Symlink) {
    New-Item -ItemType SymbolicLink -Path $HookDst -Target $HookSrc | Out-Null
    Write-Ok "Linked hook  →  .git\hooks\pre-commit  (→  hooks\pre-commit)"
} else {
    Copy-Item $HookSrc $HookDst
    Write-Ok "Copied hook  →  .git\hooks\pre-commit"
}

# ── IDE notes ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "IDE notes" -ForegroundColor White
Write-Host "  VS Code        Git integration runs .git\hooks automatically — no extra setup." -ForegroundColor Cyan
Write-Host "  IntelliJ/IDEA  Settings → Version Control → Git → 'Run Git hooks' must be enabled." -ForegroundColor Cyan
Write-Host "                 If wafpass is not on PATH, add its install dir to the system PATH" -ForegroundColor Cyan
Write-Host "                 or set WAFPASS_STRICT=0 to warn instead of block." -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration (set as environment variables or in .env)" -ForegroundColor White
Write-Host "  WAFPASS_CONTROLS_DIR   path to controls dir   (default: controls)"
Write-Host "  WAFPASS_SEVERITY       minimum severity        (default: high)"
Write-Host "  WAFPASS_FAIL_ON        fail|skip|any           (default: fail)"
Write-Host "  WAFPASS_STRICT         1 = abort if wafpass is missing (default: 0 = warn)"
Write-Host ""
Write-Ok "Pre-commit hook installed. It will run on your next 'git commit'."
