"""Optional component CVE lookup + pre-scan SPA/API check.

Component detection loads the target in a headless browser (the tool is
SPA-focused, and SPAs only expose framework versions at runtime — Angular's
ng-version, jQuery's version, etc.). Detected product+versions are looked up in
the NVD by CPE. This does NOT map the scanner's behavioural findings (BOLA,
etc.) to CVEs — those are weakness types (CWE), not product CVEs.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_FINGERPRINT_HEADERS = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache",
)
# product/version tokens in banners, keeping letter releases (OpenSSL 1.0.2k)
# and distribution suffixes (PHP/7.4.3-4ubuntu2.19) so matching can judge them.
_PRODUCT_VERSION = re.compile(
    r"([A-Za-z][A-Za-z0-9._+\-]*?)[/ ]v?"
    r"(\d+(?:\.\d+){1,3}[a-z]{0,2}(?:[-~+][A-Za-z0-9.~+]+)?)")

# Runtime probe: read framework/library versions the SPA sets on the live page.
_RUNTIME_JS = """() => {
  const out = {scripts: [], hasRoot: false, framework: null};
  try {
    const ng = document.querySelector('[ng-version]');
    if (ng) { out.angular = ng.getAttribute('ng-version'); out.framework = 'Angular'; }
    if (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) out.jquery = window.jQuery.fn.jquery;
    if (window.React && window.React.version) { out.react = window.React.version; out.framework = out.framework || 'React'; }
    if (window.Vue && window.Vue.version) { out.vue = window.Vue.version; out.framework = out.framework || 'Vue'; }
    if (window.bootstrap && window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION) out.bootstrap = window.bootstrap.Tooltip.VERSION;
    if (window.angular && window.angular.version && window.angular.version.full) out.angularjs = window.angular.version.full;
    if (!out.framework) {
      if (document.querySelector('[data-reactroot]') || window.__NEXT_DATA__) out.framework = 'React';
      else if (window.__NUXT__ || window.$nuxt) out.framework = 'Vue';
      else if (document.querySelector('app-root')) out.framework = 'Angular';
    }
    out.hasRoot = !!document.querySelector('#root, #app, app-root, [data-reactroot], [ng-version]');
    out.scripts = [...document.scripts].map(s => s.src).filter(Boolean).slice(0, 25);
  } catch (e) { out.error = String(e); }
  return out;
}"""

_FRAMEWORK_KEYS = {
    "angular": "angular", "angularjs": "angularjs", "react": "react",
    "vue": "vue", "jquery": "jquery", "bootstrap": "bootstrap",
}


async def _browser_probe(url: str) -> tuple[dict[str, str], dict[str, Any], Optional[str]]:
    """Load the target in headless Chromium; return (headers, runtime, error)."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {}, {}, "Playwright is not installed."
    headers: dict[str, str] = {}
    runtime: dict[str, Any] = {}
    error: Optional[str] = None
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            try:
                page = await browser.new_page(ignore_https_errors=True)
                resp = await page.goto(url, wait_until="networkidle",
                                       timeout=25000)
                if resp is not None:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                await page.wait_for_timeout(1200)
                runtime = await page.evaluate(_RUNTIME_JS)
            finally:
                await browser.close()
    except Exception as exc:  # unreachable / timeout / navigation error
        error = str(exc).splitlines()[0]
    return headers, runtime, error


def _parse_header(header: str, value: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for token in re.split(r"[;,]", value):
        token = token.strip()
        for m in (_PRODUCT_VERSION.finditer(token) if token else ()):
            out.append({"header": header, "product": m.group(1).lower(),
                        "version": m.group(2)})
    return out


_DISTRO_HINT = re.compile(
    r"\b(ubuntu|debian|centos|red ?hat|rhel|fedora|suse|amazon linux|amzn|"
    r"alpine|oracle linux|win(?:32|64)|el\d)\b", re.IGNORECASE)
_RUNTIME_EVIDENCE = {
    "angular": "[ng-version] attribute", "angularjs": "window.angular.version.full",
    "jquery": "window.jQuery.fn.jquery", "react": "window.React.version",
    "vue": "window.Vue.version", "bootstrap": "window.bootstrap.Tooltip.VERSION",
}


def _script_name(src: str) -> str:
    """Filename of a script URL without query/fragment (no host is kept)."""
    return src.split("#", 1)[0].split("?", 1)[0].rsplit("/", 1)[-1][:120]


async def fingerprint(target_url: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Identify product/version evidence on the live target.

    Each component records where its version came from (``source`` and a short
    ``evidence`` string), when it was observed (``observed_at``) and any
    distribution hint seen in a server banner (back-port risk)."""
    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    headers, runtime, error = await _browser_probe(target_url)
    notes: list[str] = []
    if error:
        notes.append(f"Could not load the target to fingerprint it: {error}")
    seen: set[tuple[str, str]] = set()
    components: list[dict[str, Any]] = []

    def add(product: str, version: Optional[str], source: str, evidence: str,
            hint: Optional[str] = None) -> None:
        if not version or not re.match(r"^\d+(?:\.\d+)+", str(version)):
            return
        key = (product.lower(), str(version))
        if key not in seen:
            seen.add(key)
            components.append({"header": source, "source": source,
                               "product": product.lower(), "version": str(version),
                               "evidence": evidence[:200], "observed_at": observed_at,
                               "distribution_hint": hint})

    # 1) Runtime framework/library versions (the reliable source for SPAs).
    for key, product in _FRAMEWORK_KEYS.items():
        add(product, runtime.get(key), "runtime", _RUNTIME_EVIDENCE.get(key, key))
    # 2) Response headers.
    for h in _FINGERPRINT_HEADERS:
        if h in headers:
            hint_m = _DISTRO_HINT.search(headers[h])
            for comp in _parse_header(h, headers[h]):
                add(comp["product"], comp["version"], h,
                    f"{h}: {headers[h]}", hint_m.group(0) if hint_m else None)
    # 3) Versioned filenames in loaded scripts (e.g. jquery-3.6.0.min.js).
    for src in (runtime.get("scripts") or []):
        name = _script_name(src)
        m = re.search(r"([A-Za-z][A-Za-z0-9]+)[-.@]v?(\d+\.\d+(?:\.\d+)?)", name)
        if m:
            add(m.group(1), m.group(2), "bundle", f"script file {name}")

    if not components and not error:
        notes.append("No component versions could be identified from the "
                     "target (framework globals, headers, and script names "
                     "were all unversioned). Nothing to look up.")
    return components, notes


def _cve_summary(cve: dict[str, Any]) -> dict[str, Any]:
    text = next((d.get("value", "") for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), "")
    score = None
    severity = ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity") or ""
            break
    cid = cve.get("id", "")
    return {"id": cid, "score": score, "severity": (severity or "").title(),
            "summary": (text[:280] + "…") if len(text) > 280 else text,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}" if cid else ""}


async def lookup(components: list[dict[str, Any]], per_component: int = 5
                 ) -> tuple[list[dict[str, Any]], list[str]]:
    notes: list[str] = []
    grouped: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=25.0) as client:
        for comp in components:
            cpe = f"cpe:2.3:a:*:{comp['product']}:{comp['version']}"
            try:
                resp = await client.get(NVD_API, params={
                    "virtualMatchString": cpe, "resultsPerPage": per_component})
            except Exception as exc:
                notes.append(f"CVE lookup for {comp['product']} "
                             f"{comp['version']} failed (network?): {exc}")
                continue
            if resp.status_code in (403, 429):
                notes.append("NVD rate limit reached — wait a minute and "
                             "re-check (or configure an NVD API key).")
                break
            if resp.status_code != 200:
                notes.append(f"NVD returned HTTP {resp.status_code} for "
                             f"{comp['product']} {comp['version']}.")
                continue
            items = resp.json().get("vulnerabilities", [])
            cves = [_cve_summary(i.get("cve", {})) for i in items]
            cves = [c for c in cves if c["id"]]
            cves.sort(key=lambda c: c["score"] or 0, reverse=True)
            grouped.append({
                "component": f"{comp['product']} {comp['version']}",
                "source": comp["header"], "cve_count": len(cves), "cves": cves})
    return grouped, notes


async def check_target(target_url: str) -> dict[str, Any]:
    components, fp_notes = await fingerprint(target_url)
    results, cve_notes = await lookup(components)
    return {
        "target_url": target_url,
        "components": [{"product": c["product"], "version": c["version"],
                        "source": c["header"]} for c in components],
        "results": results,
        "notes": fp_notes + cve_notes,
        "disclaimer": ("Version-based lookup is best-effort: banners/globals "
                       "can be wrong or spoofed, and a listed CVE may not apply "
                       "to your exact build. Verify before acting."),
    }


# -- pre-scan SPA / API check ---------------------------------------------

_API_HINTS = ("/api/", "/rest/", "/graphql", "fetch(", "axios",
              "xmlhttprequest", "httpclient")


async def precheck(target_url: str) -> dict[str, Any]:
    """Quickly decide whether the target looks like a SPA and/or uses APIs,
    so the user can confirm before scanning. Uses a headless browser so that
    runtime framework detection and real API calls are observed."""
    api_calls: list[str] = []
    headers, runtime, error = {}, {}, None
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            try:
                page = await browser.new_page(ignore_https_errors=True)

                def on_request(req):
                    u = req.url
                    if req.resource_type in ("xhr", "fetch") or any(
                            k in u.lower() for k in ("/api/", "/rest/", "/graphql")):
                        api_calls.append(f"{req.method} {u}")

                page.on("request", on_request)
                resp = await page.goto(target_url, wait_until="networkidle",
                                       timeout=25000)
                if resp is not None:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                await page.wait_for_timeout(1500)
                runtime = await page.evaluate(_RUNTIME_JS)
            finally:
                await browser.close()
    except ImportError:
        error = "Playwright is not installed."
    except Exception as exc:
        error = str(exc).splitlines()[0]

    if error:
        return {"reachable": False, "error": error, "is_spa": False,
                "uses_api": False, "framework": None, "recommended": False,
                "verdict": f"Could not load the target: {error}"}

    framework = runtime.get("framework")
    is_spa = bool(runtime.get("hasRoot") or framework)
    uses_api = bool(api_calls)
    recommended = is_spa or uses_api

    if is_spa and uses_api:
        verdict = (f"Looks like a Single-Page Application"
                   f"{f' ({framework})' if framework else ''} that calls APIs "
                   f"({len(api_calls)} API request(s) seen on load). Good fit "
                   f"for this scanner.")
    elif is_spa:
        verdict = (f"Looks like a Single-Page Application"
                   f"{f' ({framework})' if framework else ''}. SPAs are the "
                   f"scanner's focus; API calls will surface during the scan.")
    elif uses_api:
        verdict = (f"Not a classic SPA, but it makes API calls "
                   f"({len(api_calls)} seen). The scanner can still discover "
                   f"its APIs.")
    else:
        verdict = ("This does not look like a Single-Page Application or an "
                   "API-driven app. The scanner is specialised for those and "
                   "may find little here.")

    return {"reachable": True, "error": None, "is_spa": is_spa,
            "uses_api": uses_api, "framework": framework,
            "api_call_sample": api_calls[:5], "recommended": recommended,
            "verdict": verdict}
