#!/usr/bin/env python3
"""ScopeForge — scope-aware passive discovery, bounded web triage and offline reporting.

Only scan assets for which you have explicit authorization. No vulnerability exploitation.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import httpx

ROOT = Path(__file__).resolve().parent
APP_VERSION = "1.0.0"
USER_AGENT = f"ScopeForge/{APP_VERSION} (authorized asset inventory)"
VALID_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
INTERESTING = [
    (r"(?:^|[.\-_])(admin|administrator|manage|management|console|dashboard|portal|backoffice)(?:[.\-_]|$)", 23, "Admin/management hostname"),
    (r"(?:^|[.\-_])(dev|development|staging|stage|uat|qa|preprod|preview|sandbox)(?:[.\-_]|$)", 18, "Non-production environment keyword"),
    (r"(?:^|[.\-_])(old|legacy|archive|backup|bak|deprecated|retired)(?:[.\-_]|$)", 19, "Legacy/backup keyword"),
    (r"(?:^|[.\-_])(auth|login|sso|idp|oauth|account|payment|billing|wallet)(?:[.\-_]|$)", 15, "Identity/payment-related hostname"),
    (r"(?:^|[.\-_])(api|graphql|gateway|swagger|docs)(?:[.\-_]|$)", 12, "API/documentation keyword"),
    (r"(?:^|[.\-_])(vpn|git|jenkins|grafana|kibana|prometheus|sonar|registry|nexus)(?:[.\-_]|$)", 22, "Infrastructure/tooling keyword"),
]


def stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_host(value: str) -> str | None:
    value = (value or "").strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if "://" in value:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return None
    value = value.split("/")[0]
    # Reject IPv4/6 and malformed names; no broad IP scanning.
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    return value if VALID_DOMAIN.fullmatch(value) else None


class Scope:
    def __init__(self, wildcards: list[str], exact: list[str], excluded: list[str], ignored: list[str]):
        self.wildcards = sorted(set(wildcards))
        self.exact = sorted(set(exact))
        self.excluded = sorted(set(excluded))
        self.ignored = ignored

    def includes(self, host: str) -> bool:
        host = normalize_host(host)
        if not host:
            return False
        allowed = host in self.exact or any(host.endswith("." + d) for d in self.wildcards)
        blocked = any(host == d or host.endswith("." + d) for d in self.excluded)
        return allowed and not blocked

    def domain_of(self, host: str) -> str:
        matches = [d for d in self.wildcards if host.endswith("." + d)]
        return max(matches, key=len) if matches else host

    @classmethod
    def from_csv(cls, filename: Path) -> "Scope":
        wildcards, exact, excluded, ignored = [], [], [], []
        with filename.open(encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        if not rows or "identifier" not in rows[0]:
            raise ValueError("Expected HackerOne scope CSV with 'identifier' column")
        for row in rows:
            identifier = (row.get("identifier") or "").strip()
            asset_type = (row.get("asset_type") or "").upper()
            submission = (row.get("eligible_for_submission") or "true").strip().lower()
            # Use ONLY explicit web/domain scope rows. APK and hardware excluded.
            if asset_type not in ("WILDCARD", "DOMAIN", "URL"):
                ignored.append(identifier)
                continue
            host = normalize_host(identifier)
            if not host:
                ignored.append(identifier)
                continue
            if submission in ("false", "no", "0"):
                excluded.append(host)
            elif asset_type == "WILDCARD" or identifier.startswith("*."):
                wildcards.append(host)
            else:
                exact.append(host)
        if not wildcards and not exact:
            raise ValueError("No in-scope web assets found")
        return cls(wildcards, exact, excluded, ignored)


def record_source(found: dict[str, set[str]], scope: Scope, host: str, source: str) -> None:
    h = normalize_host(host)
    if h and scope.includes(h):
        found.setdefault(h, set()).add(source)


def extract_crt_names(payload) -> set[str]:
    names = set()
    if not isinstance(payload, list):
        return names
    for item in payload:
        if isinstance(item, dict):
            for field in ("name_value", "common_name"):
                for value in str(item.get(field) or "").splitlines():
                    names.add(value.strip())
    return names


async def source_request(client: httpx.AsyncClient, url: str, *, params=None, timeout=25, retries=2) -> httpx.Response:
    """Retry transient public data-source failures without retrying permanent 4xx responses."""
    for attempt in range(retries + 1):
        try:
            response = await client.get(url, params=params, timeout=timeout)
            response.raise_for_status()
            return response
        except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
            status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
            if attempt >= retries or (status is not None and status not in (429, 500, 502, 503, 504)):
                raise
            delay = min(8, 2 ** attempt)
            if isinstance(exc, httpx.HTTPStatusError):
                try:
                    delay = max(delay, min(15, int(exc.response.headers.get("retry-after", "0"))))
                except ValueError:
                    pass
            await asyncio.sleep(delay)
    raise RuntimeError("unreachable retry state")


async def gather_crt(client: httpx.AsyncClient, domain: str, sem: asyncio.Semaphore) -> tuple[str, set[str], str]:
    async with sem:
        try:
            r = await source_request(client, "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=25)
            return domain, extract_crt_names(r.json()), "ok"
        except Exception as exc:
            return domain, set(), f"{type(exc).__name__}: {str(exc)[:100]}"


async def gather_otx(client: httpx.AsyncClient, domain: str, sem: asyncio.Semaphore) -> tuple[str, set[str], str]:
    async with sem:
        try:
            r = await source_request(client, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=20)
            data = r.json()
            items = data.get("passive_dns", [])
            hosts = {x.get("hostname", "") for x in items if isinstance(x, dict)}
            return domain, hosts, "ok"
        except Exception as exc:
            return domain, set(), f"{type(exc).__name__}: {str(exc)[:100]}"


async def gather_wayback(client: httpx.AsyncClient, domain: str, sem: asyncio.Semaphore) -> tuple[str, set[str], str]:
    async with sem:
        try:
            r = await source_request(client, "https://web.archive.org/cdx/search/cdx", params={
                "url": f"*.{domain}/*", "output": "json", "fl": "original", "collapse": "urlkey", "limit": "2000"
            }, timeout=35)
            data = r.json()
            hosts = set()
            for item in data[1:] if isinstance(data, list) else []:
                try:
                    host = urlsplit(item[0]).hostname
                    if host:
                        hosts.add(host)
                except (TypeError, ValueError, IndexError):
                    pass
            return domain, hosts, "ok"
        except Exception as exc:
            return domain, set(), f"{type(exc).__name__}: {str(exc)[:100]}"


async def run_subfinder(domains: list[str]) -> tuple[set[str], str]:
    """Pass the domain list using Subfinder's documented -dL flag."""
    if not shutil.which("subfinder"):
        return set(), "not installed (optional; install Subfinder for wider coverage)"
    if not domains:
        return set(), "no wildcard roots"
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", prefix="scopeforge_domains_", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(domains) + "\n")
            temp_name = tmp.name
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-silent", "-dL", temp_name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=360)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return set(), "timeout (360 seconds)"
        result = {line.strip() for line in out.decode("utf-8", "replace").splitlines() if line.strip()}
        return result, "ok" if proc.returncode == 0 else f"exit {proc.returncode}: {err.decode('utf-8','replace')[-150:]}"
    except Exception as exc:
        return set(), f"{type(exc).__name__}: {str(exc)[:100]}"
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


async def discover(scope: Scope, sources: set[str], seeds: Path | None, source_jobs: int) -> tuple[dict[str, set[str]], dict]:
    found: dict[str, set[str]] = {}
    health: dict[str, dict] = defaultdict(dict)
    if seeds:
        with seeds.open(encoding="utf-8-sig") as f:
            for line in f:
                # Supports plain host lines and URLs; CSV one host per first column.
                value = line.strip().split(",")[0].strip('"')
                record_source(found, scope, value, "seed")
        health["seed"]["input"] = "ok"

    domains = scope.wildcards
    sem = asyncio.Semaphore(max(1, source_jobs))
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, follow_redirects=False, timeout=25) as client:
        jobs = []
        if "crtsh" in sources:
            jobs += [("crtsh", gather_crt(client, d, sem)) for d in domains]
        if "otx" in sources:
            jobs += [("otx", gather_otx(client, d, sem)) for d in domains]
        if "wayback" in sources:
            jobs += [("wayback", gather_wayback(client, d, sem)) for d in domains]
        if jobs:
            print(f"[discovery] {len(jobs)} public-source requests across {len(domains)} wildcard roots")
            results = await asyncio.gather(*(coro for _, coro in jobs))
            for (name, _), (domain, hosts, outcome) in zip(jobs, results):
                health[name][domain] = {"result": outcome, "returned": len(hosts)}
                for host in hosts:
                    record_source(found, scope, host, name)
    if "subfinder" in sources:
        print("[discovery] subfinder passive enumeration")
        hosts, outcome = await run_subfinder(domains)
        health["subfinder"]["all"] = {"result": outcome, "returned": len(hosts)}
        for host in hosts:
            record_source(found, scope, host, "subfinder")
    for hostname in scope.exact:
        record_source(found, scope, hostname, "explicit_scope")
    for name in sorted(health):
        checks = health[name]
        successes = sum(1 for v in checks.values() if isinstance(v, dict) and v.get("result") == "ok")
        failures = [(domain, v.get("result")) for domain, v in checks.items()
                    if isinstance(v, dict) and v.get("result") != "ok"]
        count = sum(v.get("returned", 0) for v in checks.values() if isinstance(v, dict))
        print(f"[source:{name}] ok={successes}/{len(checks)} raw_names={count} failures={len(failures)}")
        for domain, error in failures[:3]:
            print(f"[source:{name}] {domain}: {error}")
    return found, dict(health)


class PageSignals(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title = ""
        self.meta: dict[str, str] = {}
        self.scripts: list[str] = []

    def handle_starttag(self, tag, attrs):
        props = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag == "meta":
            key = (props.get("name") or props.get("property") or "").lower()
            if key in ("generator", "application-name"):
                self.meta[key] = props.get("content") or ""
        if tag == "script" and props.get("src"):
            self.scripts.append(props["src"])

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title and len(self.title) < 240:
            self.title += data


def fingerprint(headers: dict[str, str], body: str) -> tuple[list[dict], str]:
    h = {k.lower(): v for k, v in headers.items()}
    parser = PageSignals()
    try:
        parser.feed(body[:180000])
    except Exception:
        pass
    tech: dict[str, dict] = {}

    def add(name: str, version: str = "", evidence: str = ""):
        current = tech.get(name)
        # Keep explicit version evidence instead of a generic heuristic.
        if not current or (version and not current["version"]):
            tech[name] = {"name": name, "version": version[:60], "evidence": evidence[:180]}

    for hdr, name in (("server", "Server"), ("x-powered-by", "X-Powered-By")):
        value = h.get(hdr, "")
        if value:
            for match_name in ("nginx", "Apache", "Caddy", "LiteSpeed", "Microsoft-IIS", "PHP", "Express", "ASP.NET"):
                m = re.search(rf"(?<![a-z]){re.escape(match_name)}(?:/([\w.\-]+))?", value, re.I)
                if m:
                    add(match_name, m.group(1) or "", f"{hdr}: {value}")
    if "cf-ray" in h or h.get("server", "").lower() == "cloudflare":
        add("Cloudflare", evidence="cf-ray/server response header")
    if "x-vercel-id" in h:
        add("Vercel", evidence="x-vercel-id response header")
    if "x-amz-cf-id" in h:
        add("AWS CloudFront", evidence="x-amz-cf-id response header")
    if "x-generator" in h:
        gen = h["x-generator"]
        m = re.search(r"(Drupal|WordPress|Joomla)\s*([\d.]+)?", gen, re.I)
        if m:
            add(m.group(1).title(), m.group(2) or "", f"x-generator: {gen}")
    if "laravel_session" in h.get("set-cookie", ""):
        add("Laravel", evidence="laravel_session cookie")
    if "csrftoken" in h.get("set-cookie", ""):
        add("Django (possible)", evidence="csrftoken cookie (not conclusive)")
    generator = parser.meta.get("generator", "")
    for name in ("WordPress", "Drupal", "Joomla", "Ghost"):
        m = re.search(rf"\b{re.escape(name)}\b\s*([\d.]+)?", generator, re.I)
        if m:
            add(name, m.group(1) or "", f"meta generator: {generator}")
    if "/wp-content/" in body or "/wp-includes/" in body:
        add("WordPress", evidence="wp-content/wp-includes path")
    if "__NEXT_DATA__" in body or "/_next/static/" in body:
        add("Next.js", evidence="__NEXT_DATA__ or /_next/static/ HTML signature")
    if "__NUXT__" in body or "/_nuxt/" in body:
        add("Nuxt", evidence="Nuxt HTML signature")
    if "ng-version=" in body:
        m = re.search(r'ng-version=["\']([^"\']+)', body)
        add("Angular", m.group(1) if m else "", "ng-version DOM attribute")
    if 'data-reactroot' in body or 'id="__next"' in body:
        add("React", evidence="React root signature")
    if "__VIEWSTATE" in body:
        add("ASP.NET Web Forms", evidence="__VIEWSTATE hidden field")
    for script in parser.scripts[:80]:
        for name, pattern in (("jQuery", r"jquery(?:[.-]min)?[-.]([\d.]+)"),
                              ("Bootstrap", r"bootstrap(?:[.-]bundle)?(?:[.-]min)?[-.]([\d.]+)")):
            m = re.search(pattern, script, re.I)
            if m:
                add(name, m.group(1).rstrip('.'), f"script src: {script[:130]}")
    return sorted(tech.values(), key=lambda x: x["name"].lower()), html.unescape(parser.title.strip())[:150]


def status_bucket(status: int | None, err: str = "") -> str:
    if status is None:
        return "unreachable"
    if status in (404, 410):
        return "dead"
    if status >= 500:
        return "server_error"
    if status in (401, 403, 407, 429):
        return "restricted"
    if status in (301, 302, 303, 307, 308):
        return "redirect"
    if 200 <= status < 400:
        return "live"
    if 400 <= status < 500:
        return "client_error"
    return "other"


def scoring(host: str, status: int | None, title: str, tech: list[dict], headers: dict[str, str], body: str, redirect_external: bool) -> tuple[int, list[str], str]:
    score, reasons = 5, []
    test = f"{host} {title}".lower()
    for pattern, weight, reason in INTERESTING:
        if re.search(pattern, host, re.I):
            score += weight
            reasons.append(reason)
    if any(x in test for x in ("swagger ui", "api documentation", "graphql playground", "openapi", "api explorer")):
        score += 24
        reasons.append("API documentation/console title")
    if any(x in test for x in ("jenkins", "grafana", "kibana", "gitlab", "sonarqube", "prometheus")):
        score += 19
        reasons.append("Infrastructure product title")
    if status in (401, 403):
        score += 7
        reasons.append("Access-controlled endpoint")
    if status and status >= 500:
        score += 7
        reasons.append("Server-side error: manual review")
    if redirect_external:
        reasons.append("Redirect target outside supplied scope")
    if any(t.get("version") for t in tech):
        score += 8
        reasons.append("Explicit technology version visible")
    if re.search(r"(?:traceback \(most recent|stack trace|exception in thread|debug mode|django debug|whoops! there was an error)", body, re.I):
        score += 22
        reasons.append("Possible debug/error detail in public response")
    if not reasons:
        reasons.append("No elevated triage indicators")
    score = min(100, score)
    bucket = "high" if score >= 35 else "medium" if score >= 20 else "low"
    return score, reasons, bucket


async def _fetch_limited(client: httpx.AsyncClient, url: str) -> tuple[httpx.Response, str]:
    async with client.stream("GET", url, follow_redirects=False) as r:
        chunks, length = [], 0
        async for block in r.aiter_bytes():
            chunks.append(block)
            length += len(block)
            if length >= 180000:
                break
        data = b"".join(chunks)[:180000]
        return r, data.decode(r.encoding or "utf-8", errors="replace")


async def probe_host(client: httpx.AsyncClient, scope: Scope, host: str, sem: asyncio.Semaphore) -> dict:
    start = time.monotonic()
    state = {"host": host, "root": scope.domain_of(host), "url": "", "status": None, "bucket": "unreachable", "title": "", "tech": [], "headers": {}, "redirect": "", "external_redirect": False, "error": "", "latency_ms": 0, "screen": ""}
    async with sem:
        last_error = ""
        fallback_response = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            redirects = 0
            while redirects <= 3:
                try:
                    response, body = await _fetch_limited(client, url)
                except (httpx.RequestError, httpx.HTTPStatusError, ValueError, UnicodeError) as exc:
                    last_error = f"{type(exc).__name__}: {str(exc)[:120]}"
                    break
                status = response.status_code
                headers = dict(response.headers)
                location = headers.get("location", "")
                # Explicit no-out-of-scope redirect rule, even for http -> https.
                if status in (301,302,303,307,308) and location:
                    target = urljoin(url, location)
                    parts = urlsplit(target)
                    if not scope.includes(parts.hostname or "") or parts.scheme not in ("http", "https"):
                        state.update(url=url, status=status, headers=headers, redirect=target[:350], external_redirect=True)
                        break
                    redirects += 1
                    if redirects > 3:
                        state.update(url=url, status=status, headers=headers, redirect=target[:350])
                        break
                    url = target
                    continue
                if scheme == "https" and status in (404, 410):
                    # Keep HTTPS 404/410 if HTTP fallback cannot connect.
                    fallback_response = (url, status, headers, body)
                    break
                state.update(url=url, status=status, headers=headers, redirect=location[:350])
                tech, title = fingerprint(headers, body)
                state.update(tech=tech, title=title)
                break
            if state["status"] is not None:
                break
        if state["status"] is None and fallback_response is not None:
            url, code, headers, body = fallback_response
            tech, title = fingerprint(headers, body)
            state.update(url=url, status=code, headers=headers, tech=tech, title=title)
        state["error"] = last_error if state["status"] is None else ""
        state["latency_ms"] = round((time.monotonic() - start) * 1000)
        state["bucket"] = status_bucket(state["status"], last_error)
        # No raw page bodies/secrets saved. Use only response signals in report.
        score, reasons, priority = scoring(host, state["status"], state["title"], state["tech"], state["headers"], body if state["status"] is not None else "", state["external_redirect"])
        state.update(score=score, reasons=reasons, priority=priority)
        state["headers"] = {k: v[:180] for k, v in state["headers"].items() if k.lower() in ("server", "x-powered-by", "content-type", "location", "x-generator", "x-frame-options")}
        return state


async def capture_screenshots(rows: list[dict], scope: Scope, output: Path, max_screenshots: int, screenshot_workers: int, screenshot_timeout: int) -> str:
    """Capture web previews; retry Chromium flavors, save logs, resume existing images."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return "Playwright package missing; install playwright"

    eligible = [r for r in rows if r.get("url") and r.get("bucket") in
                ("live", "restricted", "client_error", "redirect")
                and not r.get("external_redirect")
                and scope.includes(urlsplit(r["url"]).hostname or "")]
    eligible.sort(key=lambda r: (-r.get("score", 0), r["host"]))
    if max_screenshots > 0:
        eligible = eligible[:max_screenshots]
    if not eligible:
        return "No screenshot-eligible hosts"

    image_dir = output / "screenshots"
    image_dir.mkdir(parents=True, exist_ok=True)
    candidates = [
        ("new-headless Chromium", {"channel": "chromium", "headless": True,
                                    "args": ["--no-sandbox", "--disable-dev-shm-usage"]}),
        ("Chromium headless shell", {"headless": True,
                                     "args": ["--no-sandbox", "--disable-dev-shm-usage"]}),
    ]
    launch_errors = []
    sem = asyncio.Semaphore(max(1, screenshot_workers))
    captured = failed = reused = 0
    async with async_playwright() as playwright:
        browser = None
        selected = ""
        for name, options in candidates:
            probe_browser = None
            try:
                probe_browser = await playwright.chromium.launch(**options)
                # Some hosted runtimes launch a browser and immediately crash.
                check_page = await probe_browser.new_page()
                try:
                    await check_page.goto("data:text/html,<title>ScopeForge check</title>", timeout=10000)
                    await check_page.screenshot(timeout=10000)
                finally:
                    await check_page.close()
                browser = probe_browser
                selected = name
                break
            except Exception as exc:
                launch_errors.append(f"[{name}] {type(exc).__name__}: {exc}")
                if probe_browser is not None:
                    try:
                        await probe_browser.close()
                    except Exception:
                        pass

        if browser is None:
            logfile = image_dir / "browser_launch_error.log"
            logfile.write_text("\n\n".join(launch_errors), encoding="utf-8")
            return ("Chromium could not start; full diagnostic saved to "
                    f"{logfile}. Run: python3 -m playwright install --with-deps chromium")

        async def capture_one(row):
            nonlocal captured, failed, reused
            digest = hashlib.sha256(row["host"].encode()).hexdigest()[:8]
            name = re.sub(r"[^a-z0-9._-]", "_", row["host"])[:110]
            filename = f"{name}_{digest}.webp"
            target = image_dir / filename
            if target.is_file() and target.stat().st_size > 0:
                row["screen"] = f"screenshots/{filename}"
                row.pop("screenshot_error", None)
                reused += 1
                return

            async with sem:
                page = None
                try:
                    page = await browser.new_page(viewport={"width": 1365, "height": 810},
                                                  device_scale_factor=1, ignore_https_errors=False)

                    async def guard(route):
                        request = route.request
                        if request.is_navigation_request() and request.frame == page.main_frame:
                            parsed = urlsplit(request.url)
                            if parsed.scheme not in ("http", "https") or not scope.includes(parsed.hostname or ""):
                                return await route.abort()
                        return await route.continue_()

                    await page.route("**/*", guard)
                    await page.goto(row["url"], wait_until="domcontentloaded",
                                    timeout=screenshot_timeout * 1000)
                    final = urlsplit(page.url)
                    if final.scheme not in ("http", "https") or not scope.includes(final.hostname or ""):
                        raise ValueError("Browser navigation left authorized scope")
                    await page.screenshot(path=str(target), type="webp", quality=72,
                                          animations="disabled", full_page=False,
                                          timeout=max(12000, screenshot_timeout * 1000))
                    row["screen"] = f"screenshots/{filename}"
                    row.pop("screenshot_error", None)
                    captured += 1
                except Exception as exc:
                    row["screenshot_error"] = f"{type(exc).__name__}: {str(exc)[:350]}"
                    failed += 1
                finally:
                    if page is not None:
                        try:
                            await page.close()
                        except Exception:
                            pass

        try:
            await asyncio.gather(*(capture_one(row) for row in eligible))
        finally:
            try:
                await browser.close()
            except Exception:
                pass

    return (f"{captured} captured, {reused} reused, {failed} failed, "
            f"{len(eligible)} eligible; engine={selected}")


def render_report(results: list[dict], meta: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    results.sort(key=lambda x: (-x.get("score", 0), x["host"]))
    payload = {"meta": meta, "rows": results}
    (output / "results.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    subsets = {
        "live_assets.txt": [r for r in results if r.get("bucket") in ("live", "restricted", "redirect", "client_error")],
        "server_errors.txt": [r for r in results if r.get("bucket") == "server_error"],
        "dead_or_unreachable.txt": [r for r in results if r.get("bucket") in ("dead", "unreachable")],
        "high_priority.txt": [r for r in results if r.get("priority") == "high" and r.get("bucket") not in ("dead", "unreachable")],
    }
    for filename, subset in subsets.items():
        (output / filename).write_text("\n".join(r["host"] for r in subset) + ("\n" if subset else ""), encoding="utf-8")
    with (output / "assets.csv").open("w", encoding="utf-8-sig", newline="") as f:
        cols = ["host", "root", "url", "status", "bucket", "priority", "score", "title", "tech", "versions", "sources", "reasons", "screen"]
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        for row in results:
            writer.writerow({k: (", ".join(f"{t['name']} {t['version']}".strip() for t in row.get("tech", [])) if k == "tech"
                                 else ", ".join(f"{t['name']} {t['version']}" for t in row.get("tech", []) if t.get("version")) if k == "versions"
                                 else ", ".join(row.get(k, [])) if k in ("sources", "reasons")
                                 else row.get(k, "")) for k in cols})
    # HTML-safe serialized data to prevent an untrusted page title from injecting markup/scripts.
    js = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    js = js.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = (ROOT / "dashboard.html").read_text(encoding="utf-8")
    (output / "report.html").write_text(template.replace("__SCOPEFORGE_PAYLOAD__", js), encoding="utf-8")


async def execute(args):
    scope = Scope.from_csv(args.scope)
    print(f"[scope] {len(scope.wildcards)} wildcard roots, {len(scope.exact)} exact web assets, {len(scope.ignored)} non-web ignored")
    if args.screenshots_only:
        previous = args.out / "results.json"
        if not previous.is_file():
            raise ValueError(f"No previous scan results at {previous}; run active mode first")
        payload = json.loads(previous.read_text(encoding="utf-8"))
        rows = [r for r in payload["rows"] if scope.includes(r["host"])]
        print(f"[screenshots] reusing {len(rows)} previously probed in-scope assets (no discovery/probing)")
        shots = await capture_screenshots(rows, scope, args.out, args.max_screenshots,
                                           args.screenshot_workers, args.screenshot_timeout)
        metadata = payload["meta"]
        metadata["screenshots"] = shots
        metadata["generated"] = stamp()
        render_report(rows, metadata, args.out)
        print("[screenshots]", shots)
        print(f"[complete] {args.out/'report.html'}")
        return
    sources = {x.strip() for x in args.sources.split(",") if x.strip()}
    invalid = sources - {"crtsh", "otx", "subfinder", "wayback"}
    if invalid:
        raise ValueError(f"Unsupported sources: {sorted(invalid)}")
    found, health = await discover(scope, sources, args.seeds, args.source_workers)
    # Preserve previous discoveries even when a public-source API is temporarily down.
    # All names are rechecked against scope and actively probed on active runs.
    previous_discovery = args.out / "discovered.txt"
    if previous_discovery.is_file():
        previous_hosts = 0
        for value in previous_discovery.read_text(encoding="utf-8", errors="replace").splitlines():
            host = normalize_host(value)
            if host and scope.includes(host):
                record_source(found, scope, host, "previous_run")
                previous_hosts += 1
        if previous_hosts:
            print(f"[discovery] merged {previous_hosts} previously discovered hostnames (scope-checked)")
    print(f"[discovery] {len(found)} unique in-scope names collected")
    if len(found) < max(50, len(scope.wildcards) * 3):
        print("[WARN] Sparse discovery for this scope. Check results.json -> meta.health for source errors.")
        print("[WARN] A low discovery count is NOT evidence that other subdomains do not exist.")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "discovered.txt").write_text("\n".join(sorted(found)) + "\n", encoding="utf-8")
    with (args.out / "discovery_sources.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "root", "sources"])
        for host in sorted(found):
            writer.writerow([host, scope.domain_of(host), ",".join(sorted(found[host]))])
    selected = sorted(found, key=lambda host: (-sum(w for p, w, _ in INTERESTING if re.search(p, host, re.I)), -len(found[host]), host))
    if args.max_hosts > 0:
        selected = selected[:args.max_hosts]
    if args.passive_only:
        rows = []
        for host in selected:
            score, reasons, priority = scoring(host, None, "", [], {}, "", False)
            rows.append({"host": host, "root": scope.domain_of(host), "url": "", "status": None, "bucket": "unprobed", "priority": priority, "score": score, "title": "", "tech": [], "sources": sorted(found[host]), "reasons": reasons, "screen": "", "latency_ms": 0})
        shots = "not requested (passive-only)"
    else:
        print(f"[probe] checking {len(selected)} scoped hosts; workers={args.workers}, timeout={args.timeout}s")
        sem = asyncio.Semaphore(args.workers)
        async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.4"}, verify=True, follow_redirects=False,
                                     timeout=httpx.Timeout(args.timeout), limits=httpx.Limits(max_connections=args.workers, max_keepalive_connections=args.workers)) as client:
            rows = await asyncio.gather(*(probe_host(client, scope, h, sem) for h in selected))
        for row in rows:
            row["sources"] = sorted(found[row["host"]])
        print(f"[probe] buckets: {dict(Counter(x['bucket'] for x in rows))}")
        shots = "disabled"
        if args.screenshots:
            print("[screenshots] launching Chromium for eligible in-scope web pages")
            shots = await capture_screenshots(rows, scope, args.out, args.max_screenshots, args.screenshot_workers, args.screenshot_timeout)
            print("[screenshots]", shots)
    metadata = {
        "name": args.project, "version": APP_VERSION, "generated": stamp(),
        "scope_file": args.scope.name, "scope_roots": scope.wildcards,
        "scope_wildcards": len(scope.wildcards), "ignored_non_web": len(scope.ignored),
        "discovered": len(found), "probed": len(selected) if not args.passive_only else 0,
        "sources": sorted(sources), "health": health,
        "screenshots": shots, "passive_only": args.passive_only,
        "notice": "Triage scores are prioritization hints, NOT confirmed vulnerabilities or severity ratings. Source discoveries may be incomplete."
    }
    render_report(rows, metadata, args.out)
    print(f"[complete] {args.out/'report.html'}")


def get_args():
    parser = argparse.ArgumentParser(description="ScopeForge | passive-first, scope-aware reconnaissance dashboard", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--scope", type=Path, required=True, help="HackerOne scope CSV (identifier, asset_type columns)")
    parser.add_argument("--out", type=Path, default=Path("./output"), help="Output folder (report.html, screenshots, CSV, JSON)")
    parser.add_argument("--project", default="Authorized Asset Intelligence", help="Dashboard display title")
    parser.add_argument("--sources", default="crtsh,otx,subfinder", help="Comma list of: crtsh,otx,subfinder,wayback")
    parser.add_argument("--seeds", type=Path, help="Optional additional user-collected host/URL list; always scope-filtered")
    parser.add_argument("--source-workers", type=int, default=4, help="Parallel passive-source requests")
    parser.add_argument("--workers", type=int, default=20, help="Parallel HTTP probes (bounded)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout per request")
    parser.add_argument("--max-hosts", type=int, default=0, help="Max hosts actively probed; 0 = no cap")
    parser.add_argument("--max-screenshots", type=int, default=0, help="Max screenshots; 0 = all eligible")
    parser.add_argument("--screenshot-workers", type=int, default=3, help="Concurrent Chromium pages")
    parser.add_argument("--screenshot-timeout", type=int, default=25, help="Browser navigation timeout per host")
    parser.add_argument("--passive-only", action="store_true", help="No requests to target hosts, no screenshots")
    parser.add_argument("--screenshots-only", action="store_true", help="Resume from existing results.json; no discovery/probes")
    parser.add_argument("--no-screenshots", dest="screenshots", action="store_false", help="Skip Chromium screenshots")
    parser.add_argument("--authorized", action="store_true", help="Acknowledge authorization for active probing of supplied scope")
    args = parser.parse_args()
    if args.screenshots_only and args.passive_only:
        parser.error("--screenshots-only and --passive-only cannot be combined")
    if not args.passive_only and not args.authorized:
        parser.error("Active HTTP probing requires --authorized (or choose --passive-only)")
    for attr in ("workers", "source_workers", "screenshot_workers", "timeout", "screenshot_timeout"):
        if getattr(args, attr) < 1:
            parser.error(f"--{attr.replace('_', '-')} must be >= 1")
    if args.max_hosts < 0 or args.max_screenshots < 0:
        parser.error("max-hosts/max-screenshots must be >= 0")
    if args.seeds and not args.seeds.is_file():
        parser.error("--seeds file not found")
    if not args.scope.is_file():
        parser.error("--scope file not found")
    return args


if __name__ == "__main__":
    try:
        asyncio.run(execute(get_args()))
    except KeyboardInterrupt:
        print("\n[interrupted]")
        sys.exit(130)
    except (ValueError, OSError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        sys.exit(1)
