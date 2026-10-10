"""Shape scan reports for the two audiences, and export to CSV / PDF.

The technical view passes the scanner's own (already redaction-safe) JSON
straight through. The summary view derives plain-language findings and the
chart series an IT-literate reader needs.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Optional

from app import findings as findings_mod

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

_PLAIN_CATEGORY = {
    "API1": "Broken object-level authorization (users can reach other users' data)",
    "API2": "Broken authentication (login/session weaknesses)",
    "API3": "Excessive data exposure (the API returns more sensitive data than needed)",
    "API4": "No rate limiting (the API can be overused or abused)",
    "API5": "Broken function-level authorization (users can reach admin-only actions)",
    "API8": "Security misconfiguration (unsafe default settings exposed)",
}


def load_report(json_path: Path) -> dict[str, Any]:
    return json.loads(json_path.read_text(encoding="utf-8"))


def _severity_counts(vulns: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for v in vulns:
        sev = str(v.get("severity", "Info")).title()
        counts[sev] = counts.get(sev, 0) + 1
    return {k: c for k, c in counts.items() if c or k != "Info"}


def _category_counts(vulns: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for v in vulns:
        cat = v.get("owasp_category") or "Other"
        counts[cat] = counts.get(cat, 0) + 1
    return dict(sorted(counts.items()))


def summary_view(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {}) or {}
    vulns = report.get("vulnerabilities", []) or []
    risk_score = float(summary.get("overall_risk_score") or 0.0)
    risk_level = summary.get("overall_risk_level") or "Info"

    classified = findings_mod.summarize(report)
    by_id = {c["finding_id"]: c for c in classified["items"]}
    order = {"confirmed": 0, "potential": 1, "unknown": 2, "dismissed": 3}
    findings = []
    for v in sorted(vulns, key=lambda x: x.get("risk_score", 0), reverse=True):
        cat = v.get("owasp_category", "")
        c = by_id.get(str(v.get("id") or "")) or findings_mod.classify_vulnerability(v)
        findings.append({
            "finding_id": c["finding_id"],
            "title": v.get("title") or v.get("owasp_name") or "Finding",
            "severity": str(v.get("severity", "Info")).title(),
            "risk_score": v.get("risk_score"),
            # Scanner values preserved verbatim:
            "status": v.get("status"),
            "confidence": v.get("confidence"),
            # Evidence-based display category (additive):
            "evidence_category": c["evidence_category"],
            "evidence_category_label": c["evidence_category_label"],
            "evidence_basis": c["evidence_basis"],
            "plain_meaning": _PLAIN_CATEGORY.get(cat, v.get("owasp_name", "")),
            "what_to_do": v.get("remediation") or "Review this finding with your security team.",
            "endpoint_id": v.get("endpoint_id"),
        })
    findings.sort(key=lambda f: order.get(f["evidence_category"], 9))
    counts = classified["counts"]
    active = [v for v in vulns
              if findings_mod.classify_vulnerability(v)["evidence_category"] != "dismissed"]

    endpoints = report.get("endpoints", {}) or {}
    shadow_eps = endpoints.get("shadow") or endpoints.get("unmanaged") or []
    shadow_list = [
        {"method": e.get("method", ""),
         "url": _short_path(e.get("url", ""))}
        for e in shadow_eps
    ]
    inventory = {
        "Documented": summary.get("documented_endpoints", 0),
        "Shadow / unmanaged": summary.get("shadow_unmanaged_endpoints", 0),
        "Unknown": summary.get("unknown_documentation_status", 0),
    }

    return {
        "target_url": report.get("target_url"),
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "headline": _headline(risk_level, counts,
                              summary.get("shadow_unmanaged_endpoints", 0),
                              classified["security_testing_ran"]),
        "stats": {
            "endpoints_discovered": summary.get("total_endpoints_discovered", 0),
            "shadow_unmanaged": summary.get("shadow_unmanaged_endpoints", 0),
            "documented": summary.get("documented_endpoints", 0),
            # Total scanner entries of every status (kept for compatibility).
            "vulnerabilities": summary.get("vulnerabilities_found", len(vulns)),
            "confirmed_findings": counts["confirmed"],
            "potential_findings": counts["potential"],
            "unknown_findings": counts["unknown"],
            "dismissed_findings": counts["dismissed"],
        },
        "finding_counts": counts,
        "checks": classified["checks"],
        "charts": {
            # All non-dismissed entries; see severity_by_status for the split.
            "severity": _severity_counts(active),
            "severity_by_status": {
                cat: _severity_counts([v for v in vulns if
                                       findings_mod.classify_vulnerability(v)["evidence_category"] == cat])
                for cat in ("confirmed", "potential")},
            "owasp_category": _category_counts(active),
            "inventory": {k: v for k, v in inventory.items() if v},
            "risk_gauge": {"score": round(risk_score, 1), "level": risk_level},
        },
        "shadow_endpoints": shadow_list,
        "findings": findings,
    }


def _short_path(url: str) -> str:
    import re
    return re.sub(r"^https?://[^/]+", "", url) or url


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n != 1 else ''}"


def _headline(risk_level: str, counts: dict, shadow_count: int,
              security_ran: bool = True) -> str:
    confirmed, potential = counts.get("confirmed", 0), counts.get("potential", 0)
    unknown = counts.get("unknown", 0)
    parts = []
    if shadow_count:
        parts.append(_plural(shadow_count, "shadow / unmanaged API"))
    if confirmed:
        parts.append(_plural(confirmed, "confirmed security finding"))
    if potential:
        parts.append(_plural(potential, "potential finding") + " needing validation")
    if unknown:
        parts.append(_plural(unknown, "untested item"))
    if not parts:
        base = "No shadow APIs or security findings were reported."
        if not security_ran:
            base += " Security validation did not run at this scan level."
        return base
    return f"Overall risk: {risk_level}. Found " + ", ".join(parts) + "."


def technical_view(report: dict[str, Any]) -> dict[str, Any]:
    """Pass the scanner's own report through, trimmed to what the UI renders."""
    return {
        "target_url": report.get("target_url"),
        "started_at": report.get("started_at"),
        "completed_at": report.get("completed_at"),
        "summary": report.get("summary", {}),
        "endpoints": report.get("endpoints", {}),
        # Scanner entries unchanged plus an additive evidence classification.
        "vulnerabilities": [
            {**v, "evidence": findings_mod.classify_vulnerability(v)}
            for v in report.get("vulnerabilities", []) or []],
        "validation_results": report.get("validation_results", []),
        "warnings": report.get("warnings", []),
    }


LEGACY_CSV_COLUMNS = [
    "owasp_category", "owasp_name", "title", "severity", "status",
    "risk_score", "confidence", "cwe_id", "affected_methods",
    "poc_status_code", "remediation",
]
# Additive columns (appended after the legacy ones; documented in
# docs/ENRICHMENT.md). Legacy columns keep their meaning for behavioural rows.
ADDITIVE_CSV_COLUMNS = [
    "record_type", "record_id", "evidence_category", "component",
    "observed_version", "detection_source", "identity_confidence",
    "cve_id", "affected_range", "cvss_score", "cvss_version", "cvss_vector",
    "match_rationale", "references", "observed_at",
]
_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in text cells."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIX):
        return "'" + value
    return value


def export_csv(report: dict[str, Any], enrichment: Optional[dict] = None) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(LEGACY_CSV_COLUMNS + ADDITIVE_CSV_COLUMNS)

    def row(values: list) -> None:
        writer.writerow([csv_cell(v) for v in values])

    for v in report.get("vulnerabilities", []) or []:
        c = findings_mod.classify_vulnerability(v)
        row([
            v.get("owasp_category", ""), v.get("owasp_name", ""),
            v.get("title", ""), v.get("severity", ""), v.get("status", ""),
            v.get("risk_score", ""), v.get("confidence", ""),
            v.get("cwe_id", ""),
            ";".join(v.get("affected_methods", []) or []),
            v.get("poc_status_code", ""), v.get("remediation", ""),
            "behavioral_finding", v.get("id", ""), c["evidence_category"],
            "", "", "", "", "", "", "", "", "", c["evidence_basis"],
            ";".join(str(r) for r in v.get("references", []) or []), v.get("found_at", ""),
        ])
    cm = (enrichment or {}).get("cve_matching") or {}
    for comp in cm.get("components", []):
        ident = comp.get("identity", {})
        base = [comp.get("identity", {}).get("display", ""), comp.get("observed_version", ""),
                f"{comp.get('detection_source', '')}: {comp.get('evidence', '')}",
                ident.get("confidence", "")]
        if not comp.get("matches"):
            # One row per detected component so unknown coverage is visible.
            row(["", "", f"Component {base[0]} {base[1]}", "", comp.get("lookup_status", ""),
                 "", "", "", "", "", "",
                 "component", comp.get("component_id", ""), comp.get("lookup_status", ""),
                 *base, "", "", "", "", "", "; ".join(comp.get("limitations", [])), "",
                 comp.get("observed_at", "")])
            continue
        for m in comp["matches"]:
            rem = ("Upgrade to a vendor-supported release outside the affected range; "
                   "confirm the fixed version in the vendor advisory.")
            row(["", "", f"{m['cve_id']} in {base[0]} {base[1]}", m.get("severity") or "",
                 {"version_match": "Version match (not confirmed exploitable)",
                  "potential": "Potential (needs validation)",
                  "unknown": "Unknown"}.get(m["category"], m["category"]),
                 "", "", ";".join(m.get("cwe_ids", [])), "", "", rem,
                 "component_cve_match", m["match_id"], m["category"], *base,
                 m["cve_id"], "; ".join(f"{r['cpe']} {r['range']}" for r in m["affected_ranges"]),
                 m.get("cvss_score") if m.get("cvss_score") is not None else "",
                 m.get("cvss_version") or "", m.get("cvss_vector") or "",
                 m.get("rationale", ""),
                 ";".join([m["nvd_url"]] + [r["url"] for r in m.get("references", [])[:5]]),
                 comp.get("observed_at", "")])
    return buf.getvalue()


def export_json(report: dict[str, Any], enrichment: Optional[dict]) -> dict[str, Any]:
    """The scanner's report unchanged, plus an additive ``enrichment`` key."""
    out = dict(report)
    out["enrichment"] = enrichment
    out["webapp_export_schema"] = 1
    return out


async def export_pdf(html_path: Path) -> bytes:
    """Render the scanner's HTML report to PDF using Playwright (already a dep)."""
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        page = await browser.new_page()
        await page.goto(html_path.resolve().as_uri(),
                        wait_until="networkidle")
        pdf = await page.pdf(format="A4", print_background=True,
                             margin={"top": "12mm", "bottom": "12mm",
                                     "left": "10mm", "right": "10mm"})
        await browser.close()
        return pdf
