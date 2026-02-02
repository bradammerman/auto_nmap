#!/bin/bash
#
# Auto Nmap v3.0 - Quick Launcher
# ================================
# Automatically activates venv and runs the scanner with sudo
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
PYTHON="$VENV_DIR/bin/python"

# Check if venv exists
if [ ! -f "$PYTHON" ]; then
    echo "[!] Virtual environment not found!"
    echo ""
    echo "Run setup first:"
    echo "  bash $SCRIPT_DIR/setup.sh"
    echo ""
    exit 1
fi

# Run with sudo, passing all arguments
sudo "$PYTHON" "$SCRIPT_DIR/auto_nmap_v3.py" "$@"
