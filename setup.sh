#!/bin/bash
#
# Auto Nmap v3.0 - Setup Script for Kali Linux
# =============================================
# This script sets up a virtual environment and installs dependencies.
# Run this ONCE before using auto_nmap_v3.py
#

set -e

echo "=============================================="
echo "  Auto Nmap v3.0 - Setup Script"
echo "=============================================="
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed!"
    echo "Install with: sudo apt install python3 python3-venv"
    exit 1
fi

echo "[*] Python 3 found: $(python3 --version)"

# Check for nmap
if ! command -v nmap &> /dev/null; then
    echo "[!] nmap command not found. Installing..."
    sudo apt install -y nmap
fi
echo "[*] nmap found: $(nmap --version | head -1)"

# Check for python3-venv
if ! python3 -m venv --help &> /dev/null; then
    echo "[!] python3-venv not installed. Installing..."
    sudo apt install -y python3-venv
fi

# Create virtual environment
echo ""
echo "[*] Creating virtual environment in $VENV_DIR..."
if [ -d "$VENV_DIR" ]; then
    echo "    Removing old virtual environment..."
    rm -rf "$VENV_DIR"
fi

python3 -m venv "$VENV_DIR"
echo "[+] Virtual environment created!"

# Activate and install
echo ""
echo "[*] Installing python-nmap..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip > /dev/null 2>&1
pip install python-nmap

echo ""
echo "=============================================="
echo "  Setup Complete!"
echo "=============================================="
echo ""
echo "To use Auto Nmap, run:"
echo ""
echo "  source $VENV_DIR/bin/activate"
echo "  sudo $VENV_DIR/bin/python $SCRIPT_DIR/auto_nmap_v3.py -t <target> --full"
echo ""
echo "Or use the quick launcher:"
echo ""
echo "  sudo $SCRIPT_DIR/run.sh -t <target> --full"
echo ""
