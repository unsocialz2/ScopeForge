# ScopeForge — Visual Bug Bounty Asset Intelligence

**Input:** HackerOne-format CSV scope. **Output:** standalone offline HTML dashboard + screenshots named after hosts + CSV/JSON + priority lists. Runs without a paid Shodan account or any API keys.

> For **authorized scope only**. No vulnerability exploitation, credentials testing, mass port scanning, or scanning beyond scope. Manual verification remains necessary. A priority score is not a finding or a bounty severity.

## Install — Kali Linux / WSL

```bash
cd ScopeForge
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install chromium
```

If Chromium reports missing Linux libraries, run `python -m playwright install --with-deps chromium` on a system where you can install packages. `subfinder` is **optional**; install from [ProjectDiscovery](https://github.com/projectdiscovery/subfinder) to improve free coverage. Without subfinder, the tool still uses public sources `crt.sh` and AlienVault OTX. These may impose rate limits/outages. Wayback is opt-in.

## Google Colab / hosted notebook

In Colab, install into the notebook's Python instead of creating a virtual environment:

```bash
cd /content/ScopeForge
git pull
./setup.sh
./run_xiaomi.sh passive
```

`setup.sh` detects Colab and skips `venv`, which may fail with `ensurepip` in managed notebook images. If Colab is not detected, run `./setup.sh --no-venv`. A partial `.venv` from an earlier failed installation is ignored by `run_xiaomi.sh`.

## Run your uploaded Xiaomi scope

**First: discovery only (no direct traffic to Xiaomi hosts):**

```bash
python scopeforge.py \
  --scope inputs/xiaomi_scope.csv \
  --out results/xiaomi-passive \
  --project 'Xiaomi Passive Inventory' \
  --passive-only
```

**Then: authorized web probing + screenshot capture + tech fingerprints:**

```bash
python scopeforge.py \
  --scope inputs/xiaomi_scope.csv \
  --out results/xiaomi \
  --project 'Xiaomi Surface Intelligence' \
  --authorized \
  --workers 5 \
  --max-hosts 500 \
  --max-screenshots 150
```

Open `results/xiaomi/report.html` in Chrome/Firefox. Windows: open the WSL folder in Explorer and double-click `report.html`. **Do not run the active command unless you have checked the program's current policy and scope.** The bundled scope CSV reflects the uploaded export, not a live revalidation of program rules.

## Advanced examples

```bash
# More discovery sources, at a modest concurrency
python scopeforge.py --scope inputs/xiaomi_scope.csv --out results/full \
  --sources crtsh,otx,subfinder,wayback \
  --source-workers 3 --workers 4 --max-hosts 0 --max-screenshots 0 --authorized

# Skip screenshots for quick inventories
python scopeforge.py --scope inputs/xiaomi_scope.csv --out results/fast \
  --no-screenshots --authorized --max-hosts 300

# Include previously discovered hostnames (still scope-checked)
python scopeforge.py --scope inputs/xiaomi_scope.csv --seeds old_subdomains.txt \
  --out results/combined --authorized
```

`--max-hosts 0` probes all *discovered* hosts, **not every possible DNS name**. Wildcard scopes are infinite in practice, and passive sources cannot guarantee 100% coverage. Be considerate of the target program's restrictions and server load.

## How it works

1. **Scope Guard:** parses `WILDCARD` entries and explicit web assets only. Ignores phone hardware, APK packages, and out-of-scope rows. `*.mi.com` does not authorize `mi.com` apex.
2. **Passive Discovery:** optional Subfinder plus `crt.sh` and AlienVault OTX, optional Wayback. Every discovered host is rechecked against the supplied scope. Supports additional seed files.
3. **Bounded HTTP Probe:** one root request per hostname (HTTPS first, HTTP fallback), up to three in-scope redirects, small response body limit, request timeout and worker cap. Doesn't follow out-of-scope redirects.
4. **Classification:** `200–399` = live/redirect; `401/403` = restricted (still alive); `404/410` = dead *at the root URL only*; `500–599` = server error (separate review bucket); network failures = unreachable.
5. **Technology Fingerprint:** server and `X-Powered-By` headers, generator meta tags, explicit framework signatures and JS src hints. Only lists version numbers that actually appear in observed evidence. No guessing CVEs.
6. **Screenshots:** Chromium navigates each eligible site, saves compressed `.webp` as `screenshots/HOST_HASH.webp`. Browser navigation to out-of-scope hosts is blocked. It does not click anything, submit forms, or authenticate.
7. **Triage:** explainable additive scoring from hostname/title categories, authentication endpoints, explicit versions and error messages. `HIGH/MEDIUM/LOW` are **review priorities**, not vulnerability severity.
8. **Offline Dashboard:** responsive, sortable, searchable assets, screenshot cards, root/source visibility, click-to-inspect evidence, notes and review stars saved in browser `localStorage` where supported, export filtered CSV or review JSON.

## Outputs

```text
results/xiaomi/
├── report.html                 Interactive self-contained dashboard
├── results.json                Detailed structured results
├── assets.csv                  Complete inventory
├── discovered.txt              Every passively collected in-scope name
├── discovery_sources.csv       Provenance for every name
├── live_assets.txt             Live/restricted/redirected web sites
├── high_priority.txt           Highest priority non-dead hostnames
├── server_errors.txt           5xx separate from dead
├── dead_or_unreachable.txt     404/410 or connection failures
└── screenshots/
    └── HOST_HASH.webp          One named image per captured site
```

`assets.csv` includes dead/unreachable hosts for auditing, while the dashboard's default Asset Explorer view hides dead and server-error hosts. Use state filters to inspect them separately. HTTP 404 on `/` does **not** prove there are no other pages.

### Security and operations

- No secret harvesting, account login, brute force, or vulnerability proof-of-concepts.
- Some sites require browser authentication or disallow screenshots. Treat those failures as expected; don't try to bypass controls.
- Screenshots can contain sensitive data. Store output privately; don't publish real asset data without permission.
- A browser may load third-party CSS/JS/images used by the scanned site. The tool blocks out-of-scope **top-level navigation**, not all third-party asset loads.
- Public-source outages are logged in `results.json`. TLS verification is **on**; invalid TLS falls back to HTTP only when available.
- The report is generated from raw public page titles/headers with HTML-safe serialization.
- For huge scopes, start with conservative limits and review program rate limits before expanding.

## Demo and tests (zero target traffic)

```bash
python demo/build_demo.py
python -m pytest tests -q    # pytest installed only for testing
```

Open `demo/report.html`: **every hostname and every screenshot is fictional**, exclusively to preview the UI. It is not a Xiaomi assessment.

### Optional next improvements

- Wappalyzer-style detection via a well-maintained fingerprint database (higher coverage than built-in heuristics).
- External JSONL imports from httpx ProjectDiscovery (if you have it) and Shodan exports (if available).
- Incremental snapshots with diffs across days, wildcard DNS noise suppression, and resumable runs.

---

Made for reproducible, policy-compliant reconnaissance. v1.0.0.