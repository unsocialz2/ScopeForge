#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$PWD/.tools:$PATH"

if [[ -x .venv/bin/python ]] && .venv/bin/python -c 'import httpx, playwright' >/dev/null 2>&1; then
  source .venv/bin/activate
elif [[ -d .venv ]]; then
  echo "[INFO] Ignoring incomplete .venv; using current Python." >&2
fi
if ! python3 -c 'import httpx, playwright' >/dev/null 2>&1; then
  echo "[ERROR] Dependencies missing; run ./setup.sh --no-venv on Colab." >&2
  exit 1
fi

# Zero count caps mean all discovered, in-scope assets. Respect program rate limits.
RECON_WORKERS="${RECON_WORKERS:-20}"
SOURCE_WORKERS="${SOURCE_WORKERS:-4}"
DISCOVERY_SOURCES="${DISCOVERY_SOURCES:-crtsh,otx,subfinder}"
SCREENSHOT_WORKERS="${SCREENSHOT_WORKERS:-3}"
MAX_HOSTS="${MAX_HOSTS:-0}"
MAX_SCREENSHOTS="${MAX_SCREENSHOTS:-0}"
SCREENSHOT_TIMEOUT="${SCREENSHOT_TIMEOUT:-25}"

mode="${1:-passive}"
case "$mode" in
  passive)
    python3 scopeforge.py --scope inputs/xiaomi_scope.csv --out results/xiaomi-passive \
      --project 'Xiaomi Passive Inventory' --sources "$DISCOVERY_SOURCES" --source-workers "$SOURCE_WORKERS" --passive-only
    ;;
  active)
    echo "[!] Active probing only when currently authorized by the program policy."
    python3 scopeforge.py --scope inputs/xiaomi_scope.csv --out results/xiaomi \
      --project 'Xiaomi Surface Intelligence' --authorized \
      --workers "$RECON_WORKERS" --sources "$DISCOVERY_SOURCES" --source-workers "$SOURCE_WORKERS" \
      --max-hosts "$MAX_HOSTS" --max-screenshots "$MAX_SCREENSHOTS" \
      --screenshot-workers "$SCREENSHOT_WORKERS" --screenshot-timeout "$SCREENSHOT_TIMEOUT"
    ;;
  screenshots)
    echo "[!] Browser navigation only when currently authorized by the program policy."
    python3 scopeforge.py --scope inputs/xiaomi_scope.csv --out results/xiaomi \
      --authorized --screenshots-only --max-screenshots "$MAX_SCREENSHOTS" \
      --screenshot-workers "$SCREENSHOT_WORKERS" --screenshot-timeout "$SCREENSHOT_TIMEOUT"
    ;;
  *) echo "Usage: $0 [passive|active|screenshots]" >&2; exit 2;;
esac
