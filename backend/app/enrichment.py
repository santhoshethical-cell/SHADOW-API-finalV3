"""Post-scan enrichment: components, CVE matches, finding statuses, remediation, AI.

Runs *after* a scan completes and is completely separate from the scanner's
four phases: the scan's "done" event and completed status are emitted first,
and nothing here can turn a successful scan into a failed one.

Persistence (per scan, survives restarts):
    data/reports/<scan_id>/enrichment.json          current result (versioned)
    data/reports/<scan_id>/enrichment_history/*.json previous results on re-check
    data/reports/<scan_id>/enriched_report.html     scanner HTML + enrichment
                                                     section (used by PDF export)
Reopening or exporting a report reads these files; it never contacts the
target. Only an explicit re-check fingerprints the target again, and it records
its own observation timestamp.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from jinja2 import Environment

from app import ai_analysis, cve, cvedb, db, findings, matching, remediation
from app.secrets_guard import scrub

logger = logging.getLogger("sas.webapp")

SCHEMA_VERSION = 1
ENRICHMENT_FILE = "enrichment.json"
ENRICHED_HTML = "enriched_report.html"
_locks: dict[str, asyncio.Lock] = {}

FingerprintFn = Callable[[str], Awaitable[tuple[list[dict], list[str]]]]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

def load(scan_dir: Path) -> Optional[dict]:
    p = Path(scan_dir) / ENRICHMENT_FILE
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"schema_version": SCHEMA_VERSION, "status": "failed",
                "error": "Stored enrichment file is unreadable."}
    return upgrade(data)


def upgrade(data: dict) -> dict:
    """Bring older enrichment documents to the current schema (additive)."""
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("stages", {})
    data.setdefault("history", [])
    data.setdefault("counts", {})
    return data


def save(scan_dir: Path, data: dict) -> None:
    p = Path(scan_dir) / ENRICHMENT_FILE
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, p)


def latest_report(scan_dir: Path) -> tuple[Optional[dict], Optional[Path], Optional[Path]]:
    scan_dir = Path(scan_dir)
    jsons = sorted(scan_dir.glob("scan_report_*.json"))
    htmls = sorted(scan_dir.glob("scan_report_*.html"))
    report = None
    if jsons:
        try:
            report = json.loads(jsons[-1].read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = None
    return report, (jsons[-1] if jsons else None), (htmls[-1] if htmls else None)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def compute_counts(data: dict) -> dict:
    f = data.get("findings") or {}
    c = f.get("counts", {})
    comps = (data.get("cve_matching") or {}).get("components", [])
    matches = [m for comp in comps for m in comp.get("matches", [])]
    return {
        "behavioral_confirmed": c.get("confirmed", 0),
        "behavioral_potential": c.get("potential", 0),
        "behavioral_unknown": c.get("unknown", 0),
        "behavioral_dismissed": c.get("dismissed", 0),
        "checks_incomplete": sum((f.get("checks") or {}).get(k, 0)
                                 for k in ("inconclusive", "skipped", "failed")),
        "components_detected": len(comps),
        "components_unknown_status": sum(
            1 for comp in comps if comp.get("lookup_status") in
            ("unrecognized", "db_missing", "coverage_missing", "version_unparseable", "unknown")),
        "cve_version_matches": sum(1 for m in matches if m["category"] == "version_match"),
        "cve_potential_matches": sum(1 for m in matches if m["category"] == "potential"),
        "cve_unknown": sum(1 for m in matches if m["category"] == "unknown"),
    }


def _overall(stages: dict) -> str:
    sts = []
    for name, s in stages.items():
        st = s.get("status")
        # AI is optional: disabled/not-configured/nothing-to-analyse is not a gap.
        if name == "ai_analysis" and st in ("disabled", "skipped"):
            st = "completed"
        sts.append(st)
    if all(s in ("completed", "disabled") for s in sts):
        return "completed"
    if all(s in ("failed",) for s in sts if s):
        return "failed"
    return "partial"


async def run(scan_id: str, scan_dir: Path, *, trigger: str = "scan",
              refingerprint: bool = True,
              fingerprint_fn: Optional[FingerprintFn] = None,
              ai_client=None, db_path: Optional[Path] = None) -> dict:
    """Run (or re-run) enrichment for a scan and persist the result."""
    lock = _locks.setdefault(scan_id, asyncio.Lock())
    async with lock:
        return await _run_locked(scan_id, Path(scan_dir), trigger, refingerprint,
                                 fingerprint_fn or cve.fingerprint, ai_client, db_path)


async def _run_locked(scan_id, scan_dir, trigger, refingerprint, fingerprint_fn,
                      ai_client, db_path) -> dict:
    previous = load(scan_dir)
    report, _, html_path = latest_report(scan_dir)
    history = list((previous or {}).get("history", []))
    if previous and previous.get("status") not in (None, "running", "pending"):
        hdir = scan_dir / "enrichment_history"
        hdir.mkdir(exist_ok=True)
        stamp = (previous.get("completed_at") or _now()).replace(":", "").replace("+", "_")
        name = f"enrichment_{stamp}.json"
        (hdir / name).write_text(json.dumps(previous, indent=2, default=str), encoding="utf-8")
        history.append({"archived": name, "trigger": previous.get("trigger"),
                        "completed_at": previous.get("completed_at"),
                        "components_observed_at": previous.get("components_observed_at")})
    data: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "scan_id": scan_id, "status": "running",
        "trigger": trigger, "started_at": _now(), "completed_at": None,
        "target_url": (report or {}).get("target_url"), "stages": {},
        "history": history[-20:],
    }
    save(scan_dir, data)
    db.set_enrichment_status(scan_id, "running")
    try:
        if report is None:
            raise RuntimeError("The scan report is not available, so enrichment cannot run.")
        target = report.get("target_url") or ""

        # 1. Components (live fingerprint, or reuse for an offline re-match).
        st = {"started_at": _now()}
        if refingerprint or not previous or not previous.get("components"):
            try:
                comps, notes = await fingerprint_fn(target)
                st.update(status="completed", notes=notes,
                          source="live fingerprint of the target")
                if notes and not comps and any("Could not load" in n for n in notes):
                    st["status"] = "failed"
                    st["error"] = notes[0]
            except Exception as exc:
                comps = []
                st.update(status="failed", error=scrub(f"Fingerprinting failed: {exc}")[:300])
            data["components_observed_at"] = _now() if st["status"] == "completed" else None
        else:
            comps = previous.get("components", [])
            data["components_observed_at"] = previous.get("components_observed_at")
            st.update(status="completed", source="reused components from the previous "
                      "observation (offline re-match; target not contacted)")
        for c in comps:
            c.setdefault("observed_at", data.get("components_observed_at"))
        st["completed_at"] = _now()
        data["components"] = comps
        data["stages"]["fingerprint"] = st

        # 2. Local CVE matching (offline).
        st = {"started_at": _now()}
        try:
            block = matching.match_components(comps, db_path)
            data["cve_matching"] = block
            dbstate = block["database"]["state"]
            if dbstate == "missing":
                st.update(status="skipped", reason="Local CVE database not populated; "
                          "component CVE status is unknown (not 'no vulnerabilities').")
            elif any(c.get("lookup_status") in ("coverage_missing", "db_missing")
                     or (c.get("coverage") or {}).get("state") in ("partial", "stale")
                     for c in block["components"]):
                # Judge coverage for the components actually detected, not
                # for every catalog product.
                st.update(status="partial", reason="Some detected components have "
                          "missing, partial or stale CVE database coverage.")
            else:
                st["status"] = "completed"
        except Exception as exc:
            data["cve_matching"] = None
            st.update(status="failed", error=scrub(f"CVE matching failed: {exc}")[:300])
        st["completed_at"] = _now()
        data["stages"]["cve_matching"] = st

        # 3. Evidence-based classification of behavioural findings.
        data["findings"] = findings.summarize(report)
        data["stages"]["classification"] = {"status": "completed", "completed_at": _now()}

        # 4. Deterministic remediation.
        data["remediation"] = remediation.build(report, data["findings"], data.get("cve_matching"))
        data["stages"]["remediation"] = {"status": "completed", "completed_at": _now()}

        # 5. Optional AI analysis (never raises).
        save(scan_dir, {**data, "counts": compute_counts(data)})
        ai = await ai_analysis.analyze(data["findings"], data.get("cve_matching"),
                                       target, client=ai_client)
        data["ai_analysis"] = ai
        data["stages"]["ai_analysis"] = {
            "status": {"completed": "completed", "partial": "partial",
                       "disabled": "disabled"}.get(ai["status"],
                                                   "skipped" if ai["status"] == "skipped" else "failed"),
            "reason": ai.get("error"), "completed_at": _now()}
    except Exception as exc:
        logger.exception("Enrichment failed for scan %s", scan_id)
        data["stages"].setdefault("pipeline", {})
        data["stages"]["pipeline"] = {"status": "failed",
                                      "error": scrub(str(exc))[:300]}
    data["counts"] = compute_counts(data)
    data["status"] = _overall(data["stages"])
    data["completed_at"] = _now()
    save(scan_dir, data)
    db.set_enrichment_status(scan_id, data["status"])
    try:
        if report is not None and html_path is not None:
            write_enriched_html(scan_dir, html_path, data)
    except Exception:
        logger.exception("Could not write enriched HTML for scan %s", scan_id)
    return data


def mark_interrupted(scan_dir: Path) -> None:
    """On startup: a 'running' enrichment from a previous process is stale."""
    data = load(scan_dir)
    if data and data.get("status") in ("running", "pending"):
        data["status"] = "failed"
        data["stages"]["pipeline"] = {"status": "failed",
                                      "error": "Interrupted by an application restart; "
                                               "use Re-check to run it again."}
        save(scan_dir, data)


# --------------------------------------------------------------------------- #
# Enriched HTML (same content as the UI; used for PDF export)
# --------------------------------------------------------------------------- #

_LABEL = {"version_match": "Version match — not confirmed exploitable",
          "potential": "Potential — needs validation",
          "unknown": "Unknown — could not evaluate",
          "confirmed": "Confirmed (scanner evidence)", "dismissed": "Dismissed"}

ENRICHMENT_TEMPLATE = """
<section id="sas-enrichment" style="max-width:1200px;margin:0 auto;padding:0 2rem 2rem">
<h2>Enrichment: finding status, components and CVEs</h2>
<p class="muted" style="color:#94a3b8;font-size:.85rem">Added by the Shadow API Scanner web app after the
scan. Enrichment status: <strong>{{ e.status }}</strong>{% if e.completed_at %} · completed {{ e.completed_at }}{% endif %}
{% if e.components_observed_at %} · components observed {{ e.components_observed_at }}{% endif %}.
Behavioural findings and component CVE matches are separate and never counted together.</p>

<h3>Behavioural findings by evidence status</h3>
<div class="grid">
<div class="card"><div class="label">Confirmed (evidence)</div><div class="value high">{{ c.behavioral_confirmed or 0 }}</div></div>
<div class="card"><div class="label">Potential</div><div class="value medium">{{ c.behavioral_potential or 0 }}</div></div>
<div class="card"><div class="label">Unknown / not tested</div><div class="value info">{{ c.behavioral_unknown or 0 }}</div></div>
<div class="card"><div class="label">Checks incomplete</div><div class="value info">{{ c.checks_incomplete or 0 }}</div></div>
</div>
{% if f and f["items"] %}<div class="table-scroll"><table>
<thead><tr><th>Finding</th><th>Severity</th><th>Scanner status</th><th>Confidence</th><th>Evidence status</th><th>Basis</th></tr></thead>
<tbody>{% for i in f["items"] %}<tr><td>{{ i.title }}</td><td>{{ i.severity }}</td><td>{{ i.scanner_status }}</td>
<td>{{ i.scanner_confidence }}</td><td>{{ i.evidence_category_label }}</td><td>{{ i.evidence_basis }}</td></tr>{% endfor %}</tbody>
</table></div>{% endif %}

<h3>Detected components</h3>
{% set cm = e.cve_matching %}
{% if cm %}<p>Local CVE database: <strong>{{ cm.database.state }}</strong>{% if cm.database.last_update_at %}, updated {{ cm.database.last_update_at }}{% endif %}. {{ cm.database.message }}</p>{% else %}<p>CVE matching did not run: {{ (e.stages.cve_matching or {}).error or 'not available' }}</p>{% endif %}
{% if e.stages.fingerprint and e.stages.fingerprint.status == 'failed' %}<p style="color:#facc15">Component detection failed: {{ e.stages.fingerprint.error }}. Component CVE status is unknown.</p>{% endif %}
{% if cm and cm.components %}<div class="table-scroll"><table>
<thead><tr><th>Component</th><th>Observed version</th><th>Evidence</th><th>Identity</th><th>Coverage</th><th>Result</th></tr></thead>
<tbody>{% for comp in cm.components %}<tr>
<td>{{ comp.identity.display }}</td><td>{{ comp.observed_version }}</td>
<td>{{ comp.detection_source }}: {{ comp.evidence }}<br><small>observed {{ comp.observed_at }}</small></td>
<td>{{ comp.identity.confidence }}</td><td>{{ (comp.coverage or {}).state or '—' }}</td>
<td>{{ lookup[comp.lookup_status] or comp.lookup_status }}</td></tr>{% endfor %}</tbody>
</table></div>{% elif cm %}<p>No versioned components were identified.</p>{% endif %}

{% if cm %}{% for comp in cm.components %}{% for m in comp.matches %}
<div class="vuln-card {{ m.severity or 'Info' }}">
<div style="display:flex;justify-content:space-between"><h3>{{ m.cve_id }} — {{ comp.identity.display }} {{ comp.observed_version }}</h3>
<span class="badge {{ m.severity or 'Info' }}">{{ m.severity or 'n/a' }}{% if m.cvss_score is not none %} · CVSS {{ m.cvss_version }} {{ m.cvss_score }}{% endif %}</span></div>
<p><strong>{{ label[m.category] }}</strong></p>
<p>{{ m.description }}</p>
<p><strong>Affected ranges:</strong> {% for r in m.affected_ranges %}{{ r.cpe }} {{ r.range }}{% if not loop.last %}; {% endif %}{% endfor %}</p>
{% if m.cvss_vector %}<p><small>Vector {{ m.cvss_vector }} (source {{ m.cvss_source }})</small></p>{% endif %}
<p><strong>Rationale:</strong> {{ m.rationale }}</p>
<p><small>References: <a href="{{ m.nvd_url | safe_url }}">{{ m.nvd_url }}</a>{% for r in m.references[:5] %}{% if r.url | safe_url %} · <a href="{{ r.url | safe_url }}">{{ r.url }}</a>{% endif %}{% endfor %}</small></p>
</div>{% endfor %}{% endfor %}{% endif %}

<h3>Remediation</h3>
{% for r in e.remediation or [] %}<div class="vuln-card">
<h3>{{ r.title }} <small>({{ label[r.evidence_category] or r.evidence_category }})</small></h3>
<ul>{% for a in r.actions %}<li>{{ a }}</li>{% endfor %}</ul>
{% if r.upgrade %}<p><strong>Upgrade target:</strong> {% if r.upgrade.verified %}{{ r.upgrade.versions | join(', ') }} (documented){% else %}not verified — {{ r.upgrade.basis }}{% endif %}</p>{% endif %}
{% if r.workarounds %}<p><strong>Documented workarounds:</strong> {% for w in r.workarounds %}<a href="{{ w.url | safe_url }}">{{ w.url }}</a> ({{ w.cve_id }}){% if not loop.last %}; {% endif %}{% endfor %}</p>{% endif %}
<p><strong>Verify after remediation:</strong></p><ul>{% for v in r.verification %}<li>{{ v }}</li>{% endfor %}</ul>
{% if r.uncertainty %}<p><strong>Remaining uncertainty:</strong> {{ r.uncertainty | join(' ') }}</p>{% endif %}
</div>{% else %}<p>No remediation items.</p>{% endfor %}

{% set ai = e.ai_analysis %}
<h3>AI analysis</h3>
{% if not ai or ai.status in ('disabled', 'skipped') %}<p>AI analysis was not run ({{ (ai or {}).error or 'not configured' }}). Deterministic remediation above applies.</p>
{% elif ai.status == 'failed' %}<p>AI analysis failed ({{ ai.error }}). Scan results and deterministic remediation are unaffected.</p>
{% else %}<p><small>Generated by {{ ai.provider }} / {{ ai.model }} at {{ ai.completed_at }}. {{ ai.disclosure }}
Statements that could not be verified against the evidence were removed ({{ ai.validation.rejected_fields }} field(s)).</small></p>
{% if ai.overview %}<p>{{ ai.overview }}</p>{% endif %}
{% for ref, it in ai["items"].items() %}<div class="vuln-card"><h3>{{ ref }}</h3>
{% if it.explanation %}<p>{{ it.explanation }}</p>{% endif %}{% if it.potential_impact %}<p><strong>Potential impact:</strong> {{ it.potential_impact }}</p>{% endif %}
{% if it.remediation_steps %}<ul>{% for s in it.remediation_steps %}<li>{{ s }}</li>{% endfor %}</ul>{% endif %}
{% if it.verification_steps %}<p><strong>Verify:</strong></p><ul>{% for s in it.verification_steps %}<li>{{ s }}</li>{% endfor %}</ul>{% endif %}
</div>{% endfor %}{% endif %}
</section>
"""

LOOKUP_LABELS = {
    "matched": "CVE match(es) found", "no_match_in_available_data":
    "No affected range matched in available data", "unrecognized":
    "Not in catalog — CVE status unknown", "db_missing": "Database missing — unknown",
    "coverage_missing": "No database coverage — unknown",
    "version_unparseable": "Version not comparable — unknown", "unknown": "Unknown",
}


def render_section(data: dict) -> str:
    env = Environment(autoescape=True)
    env.filters["safe_url"] = lambda u: cvedb.safe_reference_url(u) or "#"
    tpl = env.from_string(ENRICHMENT_TEMPLATE)
    return tpl.render(e=data, c=data.get("counts") or {}, f=data.get("findings"),
                      label=_LABEL, lookup=LOOKUP_LABELS)


def write_enriched_html(scan_dir: Path, html_path: Path, data: dict) -> Path:
    html = Path(html_path).read_text(encoding="utf-8")
    section = render_section(data)
    idx = html.lower().rfind("</body>")
    out = html[:idx] + section + html[idx:] if idx != -1 else html + section
    dest = Path(scan_dir) / ENRICHED_HTML
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_text(out, encoding="utf-8")
    os.replace(tmp, dest)
    return dest
