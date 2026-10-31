#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Use the local virtual environment only when the project dependencies exist.
# On Google Colab, setup.sh installs into the notebook's own Python environment.
if [[ -x .venv/bin/python ]] && .venv/bin/python -c 'import httpx, playwright' >/dev/null 2>&1; then
  source .venv/bin/activate
elif [[ -d .venv ]]; then
  echo "[INFO] Ignoring incomplete .venv and using python3 from the current environment." >&2
fi

if ! python3 -c 'import httpx, playwright' >/dev/null 2>&1; then
  echo "[ERROR] Dependencies missing. Run ./setup.sh (or ./setup.sh --no-venv for Colab)." >&2
  exit 1
fi

mode="${1:-passive}"
case "$mode" in
  passive)
    python3 scopeforge.py --scope inputs/xiaomi_scope.csv --out results/xiaomi-passive --project 'Xiaomi Passive Inventory' --passive-only
    ;;
  active)
    echo "[!] Active probing only when currently authorized under the bug bounty program policy."
    python3 scopeforge.py --scope inputs/xiaomi_scope.csv --out results/xiaomi --project 'Xiaomi Surface Intelligence' --authorized --workers 5 --max-hosts 500 --max-screenshots 150
    ;;
  *) echo "Usage: $0 [passive|active]" >&2; exit 2;;
esac
