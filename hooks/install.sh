#!/usr/bin/env bash
# WAF++ PASS — pre-commit hook installer
# Works on macOS, Linux, and Git Bash on Windows.
#
# Usage:
#   bash hooks/install.sh           # install (symlink by default)
#   bash hooks/install.sh --copy    # copy instead of symlink

set -euo pipefail

COPY_MODE=0
for arg in "$@"; do
    [[ "$arg" == "--copy" ]] && COPY_MODE=1
done

# ── Colours ───────────────────────────────────────────────────────────────────
if [ -t 1 ] && command -v tput &>/dev/null && tput colors &>/dev/null 2>&1; then
    RED=$(tput setaf 1); YELLOW=$(tput setaf 3); GREEN=$(tput setaf 2)
    CYAN=$(tput setaf 6); BOLD=$(tput bold); RESET=$(tput sgr0)
else
    RED=""; YELLOW=""; GREEN=""; CYAN=""; BOLD=""; RESET=""
fi

info()  { echo "${CYAN}▸${RESET} $*"; }
ok()    { echo "${GREEN}✔${RESET} $*"; }
warn()  { echo "${YELLOW}!${RESET} $*"; }
abort() { echo "${RED}${BOLD}✘${RESET} $*"; exit 1; }

# ── Find git root ─────────────────────────────────────────────────────────────
GIT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) \
    || abort "Not inside a git repository. Run this from within the repo."

HOOKS_DIR="$GIT_ROOT/.git/hooks"
HOOK_SOURCE="$GIT_ROOT/hooks/pre-commit"
HOOK_TARGET="$HOOKS_DIR/pre-commit"

[[ -f "$HOOK_SOURCE" ]] || abort "Source hook not found: $HOOK_SOURCE"

# ── Handle an already-existing hook ──────────────────────────────────────────
if [[ -e "$HOOK_TARGET" && ! -L "$HOOK_TARGET" ]]; then
    BACKUP="${HOOK_TARGET}.bak.$(date +%Y%m%d%H%M%S)"
    warn "Existing pre-commit hook found — backing up to $(basename "$BACKUP")"
    mv "$HOOK_TARGET" "$BACKUP"
elif [[ -L "$HOOK_TARGET" ]]; then
    info "Replacing existing symlink."
    rm "$HOOK_TARGET"
fi

# ── Install ───────────────────────────────────────────────────────────────────
chmod +x "$HOOK_SOURCE"

if [[ $COPY_MODE -eq 1 ]]; then
    cp "$HOOK_SOURCE" "$HOOK_TARGET"
    chmod +x "$HOOK_TARGET"
    ok "Copied hook  →  .git/hooks/pre-commit"
else
    ln -s "$HOOK_SOURCE" "$HOOK_TARGET"
    ok "Linked hook  →  .git/hooks/pre-commit  (→  hooks/pre-commit)"
fi

# ── Smoke-test ────────────────────────────────────────────────────────────────
if bash -n "$HOOK_TARGET" 2>/dev/null; then
    ok "Hook syntax check passed."
else
    warn "Hook syntax check failed — verify the script manually."
fi

# ── IDE notes ─────────────────────────────────────────────────────────────────
echo ""
echo "${BOLD}IDE notes${RESET}"
echo "  ${CYAN}VS Code${RESET}        Git integration runs .git/hooks automatically — no extra setup."
echo "  ${CYAN}IntelliJ/IDEA${RESET}  Settings → Version Control → Git → 'Run Git hooks' must be enabled (it is by default)."
echo "                 If hooks are skipped, go to Settings → Tools → Terminal and set 'Shell path' to your login shell."
echo ""
echo "  ${CYAN}PATH issues${RESET}    If wafpass is not found in IDE commits, set WAFPASS_STRICT=0 in .env"
echo "                 or add the install prefix to Settings → Build → Python Interpreter."
echo ""
echo "${BOLD}Configuration (optional .env or shell exports)${RESET}"
echo "  WAFPASS_CONTROLS_DIR   path to controls dir   (default: controls)"
echo "  WAFPASS_SEVERITY       minimum severity        (default: high)"
echo "  WAFPASS_FAIL_ON        fail|skip|any           (default: fail)"
echo "  WAFPASS_STRICT         1 = abort if wafpass is missing (default: 0 = warn only)"
echo ""
ok "Pre-commit hook installed. It will run on your next \`git commit\`."
