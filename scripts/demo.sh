#!/usr/bin/env bash
# Authorized scan targets only:
#   example.com  -> IANA-owned, explicitly allows scanning
#   scanme.sh    -> projectdiscovery's sanctioned test host
set -e
cd "$(dirname "$0")/.."
pip install -r requirements.txt
python scripts/install_engines.py
export PATH="$PWD/bin:$PATH"
python -m sentinel.cli example.com scanme.sh --stages recon scan --json --out findings.json
echo "Wrote findings.json"
