#!/usr/bin/env bash
# CloudSecure CLI - Standalone Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/carlosinfantes/cloudsecure/main/install.sh | bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}▸${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
fail()  { echo -e "${RED}✗${NC} $*"; exit 1; }

echo ""
echo -e "${BOLD}CloudSecure CLI Installer${NC}"
echo ""

# Check Python 3.9+
if ! command -v python3 >/dev/null 2>&1; then
  fail "Python 3 not found. Install from https://www.python.org/downloads/"
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]; }; then
  fail "Python 3.9+ required (found $PY_VERSION)"
fi

ok "Python $PY_VERSION"

# Install via pipx (preferred) or pip
if command -v pipx >/dev/null 2>&1; then
  info "Installing with pipx..."
  pipx install cloudsecure
elif command -v pip3 >/dev/null 2>&1; then
  info "Installing with pip (consider using pipx for isolated installs)..."
  pip3 install --user cloudsecure
elif python3 -m pip --version >/dev/null 2>&1; then
  info "Installing with pip..."
  python3 -m pip install --user cloudsecure
else
  fail "Neither pipx nor pip found. Install pip: https://pip.pypa.io/en/stable/installation/"
fi

# Verify
echo ""
if command -v cloudsecure >/dev/null 2>&1; then
  ok "Installed: $(cloudsecure --version)"
else
  echo -e "${CYAN}Note:${NC} You may need to add ~/.local/bin to your PATH:"
  echo '  export PATH="$HOME/.local/bin:$PATH"'
  echo ""
fi

echo ""
echo -e "${BOLD}Next steps:${NC}"
echo "  cloudsecure --help                    # See all commands"
echo "  cloudsecure assess --help             # Start an assessment"
echo "  cloudsecure status                    # List assessments"
echo ""
