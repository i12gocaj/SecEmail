#!/usr/bin/env bash
# SecEmail — automatic all-in-one installer.
#
# Usage:
#   ./install.sh           # creates a local venv and leaves the tool ready
#   ./install.sh --global  # installs into the system Python (not recommended)
#   ./install.sh --no-qr   # skips the optional qrcode dependency (faster)
#
# After installing:
#   source .venv/bin/activate   # local mode only
#   secemail                     # launches the interactive menu

set -e

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; CYAN=''; BOLD=''; NC=''
fi

info()  { printf "${CYAN}▸${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}✓${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}!${NC} %s\n" "$*"; }
fail()  { printf "${RED}✗${NC} %s\n" "$*" >&2; exit 1; }

# Clean Ctrl+C
trap 'printf "\n${YELLOW}Installation cancelled.${NC}\n"; exit 130' INT

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

MODE="local"
SKIP_QR=0
for arg in "$@"; do
  case "$arg" in
    --global) MODE="global" ;;
    --no-qr)  SKIP_QR=1 ;;
    --help|-h)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) warn "Unknown argument ignored: $arg" ;;
  esac
done

printf "\n${BOLD}SecEmail · installer${NC}\n"
printf "Mode: ${BOLD}%s${NC}\n\n" "$MODE"

# ---------------------------------------------------------------------------
# Python 3.10+ detection
# ---------------------------------------------------------------------------
PYTHON=""
for cand in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$cand" >/dev/null 2>&1; then
    ver=$("$cand" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "0.0")
    major=${ver%%.*}
    minor=${ver##*.}
    if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
      PYTHON="$cand"
      break
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  printf "${RED}✗${NC} Python ≥ 3.10 is required.\n\n"
  printf "Install it like this:\n"
  printf "  macOS:  ${BOLD}brew install python@3.12${NC}\n"
  printf "  Ubuntu: ${BOLD}sudo apt install python3.12 python3.12-venv${NC}\n"
  printf "  Fedora: ${BOLD}sudo dnf install python3.12${NC}\n\n"
  exit 1
fi

PY_VER=$($PYTHON --version)
ok "Python found: $PY_VER at $(command -v $PYTHON)"

# ---------------------------------------------------------------------------
# venv setup (local mode)
# ---------------------------------------------------------------------------
if [ "$MODE" = "local" ]; then
  if [ ! -d ".venv" ]; then
    info "Creating virtual environment at .venv/ ..."
    if ! "$PYTHON" -m venv .venv 2>/dev/null; then
      fail "Could not create the venv. On Ubuntu/Debian install: sudo apt install python3-venv"
    fi
    ok "venv created"
  else
    ok "venv already exists at .venv/"
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  PIP="pip"
else
  PIP="$PYTHON -m pip"
fi

# ---------------------------------------------------------------------------
# Dependency installation
# ---------------------------------------------------------------------------
info "Upgrading pip..."
$PIP install --upgrade pip --quiet 2>/dev/null || warn "pip upgrade emitted a warning, continuing"

info "Installing SecEmail and dependencies (≈30 seconds)..."
if ! $PIP install --upgrade -e . --quiet 2>/tmp/secemail_install.log; then
  printf "${RED}✗${NC} Installation failed. Details:\n"
  tail -20 /tmp/secemail_install.log >&2
  fail "Review the log and retry."
fi
ok "SecEmail installed"

# Optional dep for quishing (non-critical)
if [ "$SKIP_QR" -eq 0 ]; then
  info "Installing QR support (quishing template, optional)..."
  if $PIP install "qrcode[pil]>=7" --quiet 2>/dev/null; then
    ok "QR support installed"
  else
    warn "Optional QR not installed (the quishing template will use an SVG placeholder)"
  fi
fi

# ---------------------------------------------------------------------------
# Final verification
# ---------------------------------------------------------------------------
if command -v secemail >/dev/null 2>&1; then
  VER=$(secemail --version 2>&1 | head -1)
  ok "Verification: $VER"
  ENTRY="secemail"
else
  VER=$($PYTHON -m secemail --version 2>&1 | head -1)
  ok "Verification: $VER"
  ENTRY="$PYTHON -m secemail"
fi

# ---------------------------------------------------------------------------
# Final summary with the key commands
# ---------------------------------------------------------------------------
printf "\n${BOLD}${GREEN}Installation complete.${NC}\n\n"

if [ "$MODE" = "local" ]; then
  printf "To use SecEmail in a new terminal:\n"
  printf "  ${CYAN}cd $(pwd)${NC}\n"
  printf "  ${CYAN}source .venv/bin/activate${NC}\n\n"
fi

printf "Get started:\n"
printf "  ${BOLD}${ENTRY}${NC}                         # interactive menu (recommended)\n"
printf "  ${BOLD}${ENTRY} audit company.com${NC}        # quick audit\n"
printf "  ${BOLD}${ENTRY} audit company.com --full${NC} # full audit\n"
printf "  ${BOLD}${ENTRY} --help${NC}                   # detailed help\n\n"
