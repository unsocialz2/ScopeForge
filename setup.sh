#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Google Colab is already an isolated runtime and often lacks ensurepip support.
is_colab=false
if [[ -n "${COLAB_RELEASE_TAG:-}" || -n "${COLAB_JUPYTER_IP:-}" ]] || python3 -c 'import google.colab' >/dev/null 2>&1; then
  is_colab=true
fi

if [[ "$is_colab" == true || "${1:-}" == "--no-venv" ]]; then
  echo "[INFO] Installing into the current Python environment (Colab/no-venv mode)."
  # An interrupted venv creation may have left an unusable .venv directory.
  if [[ -e .venv/bin/activate ]]; then
    echo "[INFO] This setup does not use .venv; run_xiaomi.sh will ignore invalid venvs."
  fi
  python3 -m pip install -r requirements.txt
  if [[ "$is_colab" == true ]]; then
    echo "[INFO] Installing Chromium and Linux dependencies for Colab."
    python3 -m playwright install --with-deps chromium
  else
    python3 -m playwright install chromium
  fi
else
  echo "[INFO] Creating the local virtual environment."
  if ! python3 -m venv .venv; then
    cat >&2 <<'EOF'
[ERROR] Python couldn't create the virtual environment (ensurepip failed).
On Debian/Ubuntu/Kali, install the version-matched venv package:
  sudo apt update && sudo apt install -y python3-venv
Then retry:
  ./setup.sh
On Google Colab or another isolated runtime that already has pip:
  ./setup.sh --no-venv
EOF
    exit 1
  fi
  .venv/bin/python -m pip install -r requirements.txt
  .venv/bin/python -m playwright install chromium
fi

# On Colab, add the official passive Subfinder binary where possible.
# Failure is not fatal: crt.sh and OTX still work without it.
if [[ "$is_colab" == true ]]; then
  echo "[INFO] Checking optional Subfinder passive discovery tool."
  if ! bash scripts/install_subfinder.sh; then
    echo "[WARN] Subfinder install failed; passive discovery will use available public sources." >&2
  fi
fi

printf '\n[READY] Run: ./run_xiaomi.sh passive\nOr, after rechecking authorization: ./run_xiaomi.sh active\n'
