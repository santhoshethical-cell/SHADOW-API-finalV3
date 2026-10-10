"""Evidence-based classification of the scanner's behavioural results.

The scanner's own ``status`` and ``confidence`` values are preserved verbatim;
this module only adds an ``evidence_category`` used for display and counting:

``confirmed``  scanner status "Confirmed" AND proof-of-concept evidence is
               attached (request, response evidence or status code).
``potential``  scanner status "Potential", or "Confirmed" without attached
               evidence (flagged so a reviewer can check it).
``dismissed``  scanner status "False Positive" (listed, never counted).
``unknown``    scanner status "Not Tested" or anything unrecognised.

Validator check outcomes (``validation_results``) are summarised as
passed / vulnerable / inconclusive / skipped / failed so the report can say
which checks did not complete instead of implying "nothing found".

Component CVE matches are produced elsewhere (matching.py) and are never
merged into these behavioural findings.
"""

from __future__ import annotations

from typing import Any

CATEGORY_LABELS = {
    "confirmed": "Confirmed (scanner evidence)",
    "potential": "Potential — needs validation",
    "dismissed": "Dismissed (false positive)",
    "unknown": "Unknown / not tested",
}


def classify_vulnerability(v: dict) -> dict[str, Any]:
    status = str(v.get("status") or "").strip()
    s = status.lower()
    has_evidence = bool(v.get("poc_request") or v.get("poc_evidence")
                        or v.get("poc_status_code") is not None)
    if s == "confirmed" and has_evidence:
        cat, why = "confirmed", "Scanner confirmed the behaviour and attached proof-of-concept evidence."
    elif s == "confirmed":
        cat, why = "potential", ("Scanner marked this confirmed but no proof-of-concept "
                                 "evidence is attached; verify manually.")
    elif s == "potential":
        cat, why = "potential", "Scanner reported an indicator that needs validation."
    elif s == "false positive":
        cat, why = "dismissed", "Scanner classified this result as a false positive."
    else:
        cat, why = "unknown", f"Scanner status '{status or 'none'}' does not establish a finding."
    return {"finding_id": str(v.get("id") or ""), "scanner_status": status,
            "scanner_confidence": v.get("confidence"), "evidence_category": cat,
            "evidence_category_label": CATEGORY_LABELS[cat], "evidence_basis": why,
            "has_poc_evidence": has_evidence}


_CHECK_MAP = {"protected": "passed", "vulnerable": "vulnerable",
              "inconclusive": "inconclusive", "skipped": "skipped", "error": "failed"}


def summarize(report: dict) -> dict[str, Any]:
    vulns = report.get("vulnerabilities") or []
    items = []
    counts = {k: 0 for k in CATEGORY_LABELS}
    for v in vulns:
        c = classify_vulnerability(v)
        counts[c["evidence_category"]] += 1
        items.append({**c, "title": v.get("title") or v.get("owasp_name") or "Finding",
                      "severity": str(v.get("severity") or "Info").title(),
                      "owasp_category": v.get("owasp_category"),
                      "owasp_name": v.get("owasp_name"), "cwe_id": v.get("cwe_id"),
                      "risk_score": v.get("risk_score"),
                      "endpoint_id": v.get("endpoint_id")})
    checks = {k: 0 for k in ("passed", "vulnerable", "inconclusive", "skipped", "failed")}
    incomplete = []
    for r in report.get("validation_results") or []:
        outcome = _CHECK_MAP.get(str(r.get("result") or "").lower(), "inconclusive")
        checks[outcome] += 1
        if outcome in ("inconclusive", "skipped", "failed"):
            incomplete.append({"check_id": r.get("id"), "validator": r.get("validator"),
                               "method": r.get("method"), "outcome": outcome,
                               "category": r.get("vulnerability_category")})
    return {"counts": counts, "items": items, "checks": checks,
            "incomplete_checks": incomplete[:200],
            "security_testing_ran": bool(report.get("validation_results"))
            or bool(vulns) or bool((report.get("summary") or {}).get("tests_executed"))}
