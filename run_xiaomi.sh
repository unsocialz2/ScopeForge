#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ -f .venv/bin/activate ]; then source .venv/bin/activate; fi
mode="${1:-passive}"
case "$mode" in
  passive)
    python scopeforge.py --scope inputs/xiaomi_scope.csv --out results/xiaomi-passive --project 'Xiaomi Passive Inventory' --passive-only
    ;;
  active)
    echo "[!] Active probing only when currently authorized under the bug bounty program policy."
    python scopeforge.py --scope inputs/xiaomi_scope.csv --out results/xiaomi --project 'Xiaomi Surface Intelligence' --authorized --workers 5 --max-hosts 500 --max-screenshots 150
    ;;
  *) echo "Usage: $0 [passive|active]" >&2; exit 2;;
esac
