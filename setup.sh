#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install chromium
printf '\n[READY] Run: ./run_xiaomi.sh passive\nOr, after rechecking authorization: ./run_xiaomi.sh active\n'
