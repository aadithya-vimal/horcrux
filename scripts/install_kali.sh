#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install -y \
  nmap rustscan masscan curl wget dnsutils openssl \
  whatweb wafw00f nikto gobuster ffuf feroxbuster dirsearch \
  nuclei seclists \
  smbclient rpcclient enum4linux-ng ldap-utils snmp \
  hydra medusa john hashcat sqlmap exploitdb \
  netcat-openbsd docker.io

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .

echo
echo "HORCRUX installed."
echo "Run: horcrux"
echo "Then: horcrux doctor"
