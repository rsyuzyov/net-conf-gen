#!/usr/bin/env bash
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
    echo "install.sh currently supports Debian/Ubuntu via apt-get." >&2
    echo "Install Python 3, pip and venv manually, then run: python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt pytest" >&2
    exit 1
fi

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    SUDO="sudo"
else
    SUDO=""
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

$SUDO apt-get update
$SUDO apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    gcc \
    libkrb5-dev

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt pytest

cat <<'EOF'

Installation complete.

Activate the environment:
  source .venv/bin/activate

Quick check:
  python -m pytest tests/test_models_storage.py tests/test_enrichment.py tests/test_reporting.py

Notes:
  - Discovery/report work on Linux directly.
  - WinRM with username/password works through pywinrm.
  - Kerberos/SSO for WinRM may require extra krb5 configuration in your environment.
EOF
