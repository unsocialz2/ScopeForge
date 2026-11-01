#!/usr/bin/env python3
"""Show per-provider discovery results from the existing ScopeForge report."""
from collections import Counter
from pathlib import Path
import json
import sys

path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results/xiaomi/results.json")
if not path.is_file():
    raise SystemExit(f"[diagnose] Report not found: {path}")
data = json.loads(path.read_text(encoding="utf-8"))
meta = data.get("meta", {})
rows = data.get("rows", [])
print(f"[diagnose] discovered={meta.get('discovered', '?')} probed={meta.get('probed', '?')} screenshots={sum(bool(r.get('screen')) for r in rows)}")
health = meta.get("health", {})
if not health:
    print("[diagnose] This report has no per-source health details")
for source in sorted(health):
    checks = health[source]
    if not isinstance(checks, dict):
        continue
    total = sum(x.get("returned", 0) for x in checks.values() if isinstance(x, dict))
    errors = [(domain, str(x.get("result", ""))) for domain, x in checks.items()
              if isinstance(x, dict) and x.get("result") != "ok"]
    if source == "subfinder":
        overall = checks.get("all", {})
        if isinstance(overall, dict):
            print(f"  {source}: returned={overall.get('returned', 0)} result={overall.get('result', '?')}")
            continue
    print(f"  {source}: returned_raw={total} failed_roots={len(errors)}/{len(checks)}")
    summary = Counter(msg.split(":", 1)[0] for _, msg in errors)
    if summary:
        print(f"    error types: {dict(summary)}")
    for domain, error in errors[:5]:
        print(f"    {domain}: {error}")
