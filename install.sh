#!/usr/bin/env bash
set -euo pipefail

echo "========================================"
echo "              HORCRUX"
echo "        Installation Wizard"
echo "========================================"
echo

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Python 3 is required."
    exit 1
fi

echo "[+] Python found: $(command -v python3)"

if [ ! -d ".venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv .venv
fi

echo "[+] Upgrading pip..."
.venv/bin/python -m pip install --upgrade pip

echo "[+] Installing Horcrux dependencies..."
.venv/bin/python -m pip install -r requirements.txt

echo "[+] Installing Horcrux..."
.venv/bin/python -m pip install -e .

echo
echo "[+] HORCRUX installation complete."
echo
echo "Run:"
echo "    source .venv/bin/activate"
echo "    horcrux"
echo
echo "Check your environment with:"
echo "    horcrux doctor"
echo
