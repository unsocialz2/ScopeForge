#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v subfinder >/dev/null 2>&1 || [[ -x .tools/subfinder ]]; then
  echo "[subfinder] already installed"
  exit 0
fi

# Pinned official ProjectDiscovery release, checksum verified before extraction.
version=2.17.0
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "[subfinder] unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
filename="subfinder_${version}_linux_${arch}.zip"
base="https://github.com/projectdiscovery/subfinder/releases/download/v${version}"
mkdir -p .tools
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
curl --fail --location --silent --show-error --retry 2 --max-time 90 "$base/$filename" -o "$scratch/$filename"
curl --fail --location --silent --show-error --retry 2 --max-time 30 "$base/subfinder_${version}_checksums.txt" -o "$scratch/checksums.txt"
expected="$(awk -v f="$filename" '$2==f {print $1}' "$scratch/checksums.txt")"
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "[subfinder] checksum entry missing" >&2; exit 1; }
actual="$(sha256sum "$scratch/$filename" | cut -d' ' -f1)"
[[ "$actual" == "$expected" ]] || { echo "[subfinder] checksum mismatch" >&2; exit 1; }
python3 - "$scratch/$filename" ".tools/subfinder" <<'PY'
from pathlib import Path
import sys, zipfile
source, destination = sys.argv[1:]
with zipfile.ZipFile(source) as archive:
    members = [name for name in archive.namelist() if name.rsplit('/', 1)[-1] == 'subfinder']
    if len(members) != 1:
        raise ValueError('Expected exactly one subfinder executable in the verified archive')
    Path(destination).write_bytes(archive.read(members[0]))
PY
chmod 755 .tools/subfinder
.tools/subfinder -version 2>&1 | head -n 3
echo "[subfinder] installed verified v${version} under .tools/"
