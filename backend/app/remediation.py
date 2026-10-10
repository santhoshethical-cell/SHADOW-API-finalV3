"""Deterministic remediation guidance (always available, AI or not).

Rules this module follows:
- Reuse the scanner's own remediation text first; add category guidance.
- Never invent a patched version. An upgrade target is reported as
  *verified* only when a source explicitly documents a fixed version
  (``fixed_version``). NVD range end-points are shown as range boundaries
  ("NVD lists versions before X as affected") with an instruction to confirm
  the fixed release in the vendor advisory.
- Workarounds are only listed when a reference is tagged "Mitigation" by NVD.
- Every item carries verification steps and an explicit uncertainty list.
- Wording is advisory ("Recommended…"); nothing claims a fix was applied.
"""

from __future__ import annotations

from typing import Any

from app.cvedb import safe_reference_url

_OWASP_2023 = {
    "API1": ("Broken Object Level Authorization", "0xa1-broken-object-level-authorization"),
    "API2": ("Broken Authentication", "0xa2-broken-authentication"),
    "API3": ("Broken Object Property Level Authorization",
             "0xa3-broken-object-property-level-authorization"),
    "API4": ("Unrestricted Resource Consumption", "0xa4-unrestricted-resource-consumption"),
    "API5": ("Broken Function Level Authorization", "0xa5-broken-function-level-authorization"),
    "API6": ("Unrestricted Access to Sensitive Business Flows",
             "0xa6-unrestricted-access-to-sensitive-business-flows"),
    "API7": ("Server Side Request Forgery", "0xa7-server-side-request-forgery"),
    "API8": ("Security Misconfiguration", "0xa8-security-misconfiguration"),
    "API9": ("Improper Inventory Management", "0xa9-improper-inventory-management"),
    "API10": ("Unsafe Consumption of APIs", "0xaa-unsafe-consumption-of-apis"),
}

_ACTIONS = {
    "API1": ["Enforce an object-level authorization check on every request that uses a "
             "client-supplied object ID, comparing the object's owner/tenant with the "
             "authenticated principal.",
             "Prefer non-enumerable identifiers (e.g. random UUIDs) as defence in depth, "
             "not as the control."],
    "API2": ["Require valid, unexpired credentials on every protected operation and "
             "reject tampered, expired or unsigned tokens.",
             "Apply rate limiting and lockout to authentication endpoints."],
    "API3": ["Return only the properties the caller is entitled to (explicit response "
             "schemas / allow-lists rather than serialising whole objects).",
             "Reject or ignore client-supplied properties that must not be writable "
             "(mass assignment)."],
    "API4": ["Set per-client rate limits, request size limits and pagination maximums.",
             "Return 429 with Retry-After when limits are exceeded."],
    "API5": ["Deny administrative and privileged functions by default and check the "
             "caller's role on the server for each one."],
    "API8": ["Harden configuration: disable verbose errors/debug endpoints, restrict "
             "methods and CORS, and send security headers."],
    "API9": ["Inventory this endpoint: document it in the API specification with an owner, "
             "or retire it if it is no longer needed.",
             "Route it through the managed gateway so authentication, logging and rate "
             "limits apply consistently."],
    "API10": ["Validate and sanitise data received from third-party APIs before use."],
}
_VERIFY = {
    "API1": ["Repeat the request for another user's object with a different user's "
             "token; expect 403/404 and no object data.",
             "Re-run this scanner's BOLA validation for the same endpoint."],
    "API2": ["Call the operation with no token, an expired token and a tampered token; "
             "each must be rejected with 401."],
    "API3": ["Inspect the response body for removed properties; attempt to set a "
             "protected property and confirm it is rejected or ignored."],
    "API4": ["Send requests above the configured limit and confirm 429 responses."],
    "API5": ["Call the privileged function with a low-privilege account; expect 403."],
    "API8": ["Re-request the affected resource and confirm the misconfiguration is gone."],
    "API9": ["Confirm the endpoint appears in the published specification or no "
             "longer responds; re-run discovery and check it is no longer flagged."],
}
_GENERIC_VERIFY = ["Re-run the scan at the same level and confirm the finding no longer "
                   "appears or is reported as protected."]


def owasp_reference(cat: str) -> str | None:
    entry = _OWASP_2023.get((cat or "").upper())
    if not entry:
        return None
    return f"https://owasp.org/API-Security/editions/2023/en/{entry[1]}/"


def cwe_reference(cwe: str | None) -> str | None:
    import re
    m = re.fullmatch(r"CWE-(\d{1,5})", str(cwe or "").strip(), re.IGNORECASE)
    return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html" if m else None


def for_behavioral(finding: dict, classification: dict) -> dict[str, Any]:
    cat = str(finding.get("owasp_category") or "").upper()
    refs = [u for u in [owasp_reference(cat), cwe_reference(finding.get("cwe_id"))] if u]
    for r in finding.get("references") or []:
        u = safe_reference_url(r)
        if u and u not in refs:
            refs.append(u)
    actions = []
    if finding.get("remediation"):
        actions.append(f"Scanner recommendation: {finding['remediation']}")
    actions.extend(_ACTIONS.get(cat, ["Review the affected operation with the owning team "
                                      "and apply the control described in the references."]))
    uncertainty = []
    if classification["evidence_category"] != "confirmed":
        uncertainty.append("This finding is not confirmed by scanner evidence; validate it "
                           "before prioritising a fix.")
    return {"ref": f"B:{classification['finding_id']}", "kind": "behavioral",
            "finding_id": classification["finding_id"],
            "title": finding.get("title") or finding.get("owasp_name") or "Finding",
            "evidence_category": classification["evidence_category"],
            "actions": actions, "upgrade": None, "workarounds": [],
            "verification": _VERIFY.get(cat, []) + _GENERIC_VERIFY,
            "references": refs[:8], "uncertainty": uncertainty}


def for_component(comp: dict) -> dict[str, Any] | None:
    """One consolidated remediation entry per component with CVE matches."""
    matches = [m for m in comp.get("matches", []) if m["category"] in ("version_match", "potential")]
    if not matches:
        return None
    name = comp["identity"]["display"]
    version = comp.get("observed_version")
    fixed = sorted({r["fixed_version"] for m in matches for r in m["affected_ranges"]
                    if r.get("fixed_version")})
    boundaries = sorted({r["end_excluding"] for m in matches for r in m["affected_ranges"]
                         if r.get("end_excluding")})
    open_ended = sorted({m["cve_id"] for m in matches for r in m["affected_ranges"]
                         if not r.get("end_excluding") and not r.get("end_including")
                         and not r.get("exact_version")})
    incl_ends = sorted({r["end_including"] for m in matches for r in m["affected_ranges"]
                        if r.get("end_including")})
    if fixed:
        upgrade = {"verified": True, "versions": fixed,
                   "basis": "Fixed version(s) explicitly documented by the data source."}
    else:
        upgrade = {"verified": False, "versions": [],
                   "basis": ("No source in the local database documents a fixed version. "
                             + (f"NVD lists versions before {', '.join(boundaries)} as affected "
                                "for the matched ranges (exclusive upper bounds). " if boundaries else "")
                             + (f"Ranges ending at and including {', '.join(incl_ends)} are also "
                                "affected. " if incl_ends else "")
                             + "Confirm the fixed release in the vendor advisory before upgrading.")}
    actions = [f"Recommended: upgrade {name} from {version} to a vendor-supported release that "
               f"is outside every affected range listed for "
               f"{', '.join(sorted({m['cve_id'] for m in matches}))}."]
    if open_ended:
        actions.append(f"No upper bound is given for {', '.join(open_ended)}; check the "
                       "vendor advisory to see whether any release is fixed.")
    workarounds, refs = [], []
    for m in matches:
        for r in m.get("references", []):
            url = safe_reference_url(r.get("url"))
            if not url:
                continue
            tags = [str(t).lower() for t in r.get("tags", [])]
            if "mitigation" in tags and url not in [w["url"] for w in workarounds]:
                workarounds.append({"cve_id": m["cve_id"], "url": url,
                                    "note": "Reference tagged 'Mitigation' by NVD."})
            if any(t in tags for t in ("vendor advisory", "patch", "release notes",
                                       "mitigation")) and url not in refs:
                refs.append(url)
        if m["nvd_url"] not in refs:
            refs.append(m["nvd_url"])
    uncertainty = sorted({u for m in matches for u in m.get("uncertainty", [])})
    uncertainty.extend(comp.get("limitations", []))
    uncertainty.append("A version match does not prove the vulnerable code path is used or "
                       "exploitable on this target.")
    verification = [
        f"After upgrading, use 'Re-check components' and confirm {name} reports the new "
        "version and no matching affected range.",
        "Confirm in the deployed asset (not only the source repository) that the old "
        "version is no longer served, including cached or CDN copies.",
        "Where the vendor advisory describes a test or configuration check, perform it.",
    ]
    return {"ref": f"C:{comp['component_id']}", "kind": "component",
            "component_id": comp["component_id"], "title": f"{name} {version}",
            "evidence_category": ("version_match" if any(m["category"] == "version_match"
                                                         for m in matches) else "potential"),
            "actions": actions, "upgrade": upgrade, "workarounds": workarounds[:6],
            "verification": verification, "references": refs[:12],
            "uncertainty": list(dict.fromkeys(uncertainty))}


def build(report: dict, classified: dict, cve_block: dict | None) -> list[dict]:
    by_id = {str(v.get("id")): v for v in report.get("vulnerabilities") or []}
    out = []
    for item in classified["items"]:
        if item["evidence_category"] == "dismissed":
            continue
        out.append(for_behavioral(by_id.get(item["finding_id"], {}), item))
    for comp in (cve_block or {}).get("components", []):
        rem = for_component(comp)
        if rem:
            out.append(rem)
    return out
