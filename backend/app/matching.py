"""Deterministic offline matching of detected components against the local CVE DB.

For each detected component:
1. Resolve its identity through the component catalog (high / medium /
   ambiguous / unrecognized).
2. Parse the observed version with the product's own version scheme.
3. Check database coverage for that product (complete / partial / stale /
   missing). Missing coverage => "unknown", never "no vulnerabilities".
4. Evaluate every vulnerable NVD range row for the product with real version
   comparison (inclusive/exclusive start and end bounds, exact versions,
   CPE update/pre-release qualifiers).

Each affected CVE becomes one match with a category:
``version_match``  identity is certain, version parsed cleanly and lies in an
                   explicit affected range, no configuration prerequisite.
                   This is version evidence only — NOT confirmed exploitability.
``potential``      in range, but something weakens the evidence (ambiguous or
                   indirect identity, pre-release, distribution build with
                   possible back-ports, configuration prerequisites,
                   unanalysed NVD record, unspecified range).
``unknown``        could not be evaluated (unparseable bound, etc.).

Behavioural scanner findings are never passed through this module, so CVEs
can never be attached to BOLA/authentication/injection findings via CWE.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app import cvedb
from app.component_catalog import CATALOG, resolve
from app.versioning import ParsedVersion, VersionParseError, compare, parse_version

UNANALYSED = {"received", "awaiting analysis", "undergoing analysis", "deferred"}


def _range_text(row: dict) -> str:
    v = row.get("cpe_version") or "*"
    if v not in ("*", "-", ""):
        upd = row.get("cpe_update")
        return f"= {v}" + (f" ({upd})" if upd and upd not in ("*", "-") else "")
    parts = []
    if row.get("start_incl"):
        parts.append(f">= {row['start_incl']}")
    if row.get("start_excl"):
        parts.append(f"> {row['start_excl']}")
    if row.get("end_incl"):
        parts.append(f"<= {row['end_incl']}")
    if row.get("end_excl"):
        parts.append(f"< {row['end_excl']}")
    if v == "-":
        return "version not applicable / not specified by NVD"
    return ", ".join(parts) if parts else "all versions (no bounds given by NVD)"


def evaluate_range(observed: ParsedVersion, row: dict, scheme: str
                   ) -> tuple[str, str]:
    """Return (outcome, detail). outcome: affected | not_affected |
    unspecified | unknown."""
    v = (row.get("cpe_version") or "*").strip()
    upd = (row.get("cpe_update") or "*").strip()
    try:
        if v == "-":
            return "unspecified", "NVD gives no version for this entry."
        if v not in ("*", ""):
            if upd == "*":
                # Any update of this exact release: compare releases only.
                ref = parse_version(v, scheme)
                bare = ParsedVersion(observed.raw, observed.scheme, observed.release,
                                     (), observed.letter)
                return (("affected", "exact release match (any update qualifier)")
                        if compare(bare, ref) == 0 else ("not_affected", "different release"))
            ref = parse_version(v, scheme, update=upd)
            return (("affected", "exact version match")
                    if compare(observed, ref) == 0 else ("not_affected", "different version"))
        bounds = [(k, row.get(k)) for k in ("start_incl", "start_excl", "end_incl", "end_excl")
                  if row.get(k)]
        if not bounds:
            return "unspecified", "NVD lists all versions without bounds."
        for k, raw in bounds:
            b = parse_version(raw, scheme)
            c = compare(observed, b)
            ok = {"start_incl": c >= 0, "start_excl": c > 0,
                  "end_incl": c <= 0, "end_excl": c < 0}[k]
            if not ok:
                return "not_affected", f"outside bound {k}={raw}"
        return "affected", "within all range bounds"
    except VersionParseError as exc:
        return "unknown", f"cannot compare: {exc}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def match_components(components: list[dict], db_path: Optional[Path] = None,
                     matched_at: Optional[str] = None) -> dict:
    """Match fingerprinted components; returns the ``cve_matching`` block."""
    db_path = Path(db_path or cvedb.default_path())
    matched_at = matched_at or _now_iso()
    db_state = cvedb.status(db_path)
    results = []
    for idx, comp in enumerate(components, start=1):
        results.append(_match_one(f"comp-{idx}", comp, db_path, db_state))
    return {"matched_at": matched_at, "database": {
        "state": db_state["state"], "last_update_at": db_state.get("last_update_at"),
        "cve_count": db_state.get("cve_count", 0), "message": db_state.get("message", ""),
    }, "components": results}


def _match_one(cid: str, comp: dict, db_path: Path, db_state: dict) -> dict:
    product = comp.get("product", "")
    version = comp.get("version")
    source = comp.get("source", "")
    identity = resolve(product, version, source)
    out: dict[str, Any] = {
        "component_id": cid, "product_token": product, "observed_version": version,
        "detection_source": source, "evidence": comp.get("evidence"),
        "observed_at": comp.get("observed_at"),
        "distribution_hint": comp.get("distribution_hint"),
        "identity": {"key": identity.key, "candidates": identity.candidates,
                     "display": " / ".join(CATALOG[k].display for k in identity.candidates)
                     or product,
                     "confidence": identity.confidence, "rationale": identity.rationale},
        "version": None, "coverage": None, "lookup_status": None,
        "matches": [], "not_affected_count": 0, "rejected_skipped": 0,
        "limitations": [],
    }
    if not identity.candidates:
        out["lookup_status"] = "unrecognized"
        out["limitations"].append("Component is not in the catalog; CVE status unknown.")
        return out
    if db_state["state"] == "missing":
        out["lookup_status"] = "db_missing"
        out["limitations"].append("Local CVE database not populated; CVE status unknown.")
        return out

    for key in identity.candidates:
        out["limitations"].extend(CATALOG[key].notes)
    primary_key = identity.candidates[0]
    scheme = CATALOG[primary_key].scheme
    try:
        pv = parse_version(version or "", scheme)
        out["version"] = {"ok": True, "scheme": scheme, "normalized": pv.upstream(),
                          "prerelease": pv.is_prerelease,
                          "vendor_suffix": pv.vendor_suffix}
    except VersionParseError as exc:
        out["version"] = {"ok": False, "scheme": scheme, "error": str(exc)}
        out["lookup_status"] = "version_unparseable"
        out["limitations"].append(
            f"Version '{version}' cannot be compared under the {scheme} scheme; "
            "CVE status unknown.")
        return out

    coverages = [cvedb.coverage_for(k, db_path) for k in identity.candidates]
    states = [c["coverage"] for c in coverages]
    if all(s == "missing" for s in states):
        worst = "missing"
    else:
        # Some candidate identities lack data: matching proceeds for the rest,
        # but coverage for this component is only partial.
        worst = _worst_coverage(["partial" if s == "missing" else s for s in states])
    out["coverage"] = {"state": worst, "per_identity": coverages}
    if worst == "missing":
        out["lookup_status"] = "coverage_missing"
        out["limitations"].append(
            "The local database has no data for this product; CVE status unknown.")
        return out

    uncertain_global = []
    if identity.confidence != "high":
        uncertain_global.append(f"identity {identity.confidence}: {identity.rationale}")
    if pv.vendor_suffix:
        uncertain_global.append(
            f"distribution/vendor build '{pv.vendor_suffix}': fixes may be back-ported "
            "without changing the upstream version")
    if comp.get("distribution_hint"):
        uncertain_global.append(
            f"server banner indicates a distribution build ({comp['distribution_hint']}); "
            "fixes may be back-ported")
    if pv.is_prerelease:
        uncertain_global.append("pre-release version: NVD ranges usually describe "
                                "final releases")

    by_cve: dict[str, dict] = {}
    for key in identity.candidates:
        k_scheme = CATALOG[key].scheme
        try:
            k_pv = pv if k_scheme == scheme else parse_version(version or "", k_scheme)
        except VersionParseError:
            continue
        for row in cvedb.candidate_ranges(key, db_path):
            status_l = (row.get("vuln_status") or "").lower()
            entry = by_cve.setdefault(row["cve_id"], {"rows": [], "rejected": False})
            if status_l == "rejected":
                entry["rejected"] = True
                continue
            outcome, detail = evaluate_range(k_pv, row, k_scheme)
            entry["rows"].append((outcome, detail, row, key))

    for cve_id, entry in sorted(by_cve.items()):
        if entry["rejected"] and not entry["rows"]:
            out["rejected_skipped"] += 1
            continue
        outcomes = [r[0] for r in entry["rows"]]
        hits = [r for r in entry["rows"] if r[0] in ("affected", "unspecified")]
        if not hits:
            if "unknown" in outcomes:
                row = next(r for r in entry["rows"] if r[0] == "unknown")
                out["matches"].append(_match_record(cid, cve_id, "unknown", [row], identity,
                                                  comp, pv, [row[1]]))
            else:
                out["not_affected_count"] += 1
            continue
        reasons = list(uncertain_global)
        for outcome, detail, row, key in hits:
            if outcome == "unspecified":
                reasons.append("NVD does not state which versions are affected")
            if row.get("requires_config"):
                reasons.append("configuration prerequisite: "
                               + (row.get("config_note") or "see NVD configuration"))
        status_l = (hits[0][2].get("vuln_status") or "").lower()
        if status_l in UNANALYSED:
            reasons.append(f"NVD record status is '{hits[0][2].get('vuln_status')}'")
        category = "version_match" if not reasons else "potential"
        out["matches"].append(_match_record(cid, cve_id, category, hits, identity, comp,
                                          pv, sorted(set(reasons))))

    n_match = sum(1 for m in out["matches"] if m["category"] != "unknown")
    if n_match:
        out["lookup_status"] = "matched"
    elif out["matches"]:
        out["lookup_status"] = "unknown"
    else:
        out["lookup_status"] = "no_match_in_available_data"
    if worst in ("partial", "stale"):
        out["limitations"].append(
            f"Database coverage for this product is {worst}; results may be incomplete.")
    out["matches"].sort(key=lambda m: (-(m.get("cvss_score") or 0), m["cve_id"]))
    out["limitations"] = list(dict.fromkeys(out["limitations"]))
    return out


def _worst_coverage(states: list[str]) -> str:
    for s in ("missing", "partial", "stale"):
        if s in states:
            return s
    return "complete"


def _match_record(cid: str, cve_id: str, category: str, hits: list, identity, comp: dict,
                  pv: ParsedVersion, reasons: list[str]) -> dict:
    row = hits[0][2]
    ranges = [{"cpe": f"{h[2]['vendor']}:{h[2]['product']}",
               "range": _range_text(h[2]), "outcome": h[0], "detail": h[1],
               "start_including": h[2].get("start_incl"),
               "start_excluding": h[2].get("start_excl"),
               "end_including": h[2].get("end_incl"),
               "end_excluding": h[2].get("end_excl"),
               "exact_version": (h[2].get("cpe_version")
                                 if h[2].get("cpe_version") not in ("*", "-", None) else None),
               "fixed_version": h[2].get("fixed_version"),
               "requires_configuration": bool(h[2].get("requires_config")),
               "configuration_note": h[2].get("config_note"),
               "target_software": (h[2].get("target_sw")
                                   if h[2].get("target_sw") not in ("*", "-") else None)}
              for h in hits]
    display = " / ".join(CATALOG[k].display for k in identity.candidates)
    range_list = "; ".join(f"{r['cpe']} {r['range']}" for r in ranges)
    if category == "unknown":
        rationale = (f"{display} {comp.get('version')} could not be evaluated against "
                     f"{cve_id}: {reasons[0] if reasons else 'unknown reason'}.")
    else:
        rationale = (f"Observed {display} {comp.get('version')} (from {comp.get('source')}) "
                     f"lies within the NVD affected range(s) {range_list}. "
                     "This is version evidence only; exploitability was not tested.")
        if reasons:
            rationale += " Requires validation: " + "; ".join(reasons) + "."
    return {
        "match_id": f"{cid}:{cve_id}", "cve_id": cve_id, "category": category,
        "component_id": cid, "component": display, "observed_version": comp.get("version"),
        "description": (row.get("description") or "")[:600],
        "severity": row.get("severity"), "cvss_score": row.get("cvss_score"),
        "cvss_version": row.get("cvss_version"), "cvss_vector": row.get("cvss_vector"),
        "cvss_source": row.get("cvss_source"), "nvd_status": row.get("vuln_status"),
        "published": row.get("published"), "last_modified": row.get("last_modified"),
        "record_source": row.get("record_source"), "cwe_ids": row.get("cwe_ids", []),
        "affected_ranges": ranges,
        "references": [r for r in row.get("references", [])
                       if cvedb.safe_reference_url(r.get("url"))][:12],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "rationale": rationale, "uncertainty": reasons,
    }
