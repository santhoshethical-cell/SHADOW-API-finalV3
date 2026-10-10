"""
Phase 4: Report Generator

Produces JSON and HTML reports from scan results.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment

from shadow_api_scanner import __version__
from shadow_api_scanner.core.config import ScanConfig
from shadow_api_scanner.core.models import ScanResult
from shadow_api_scanner.utils.helpers import ensure_dir
from shadow_api_scanner.utils.redaction import redact_body, redact_url

logger = logging.getLogger("shadow_api_scanner")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shadow / Unmanaged API Scan Report - {{ scan.target_url | redact_url }}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:2rem}
h1{font-size:1.8rem;background:linear-gradient(135deg,#6366f1,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem}
h2{font-size:1.3rem;color:#94a3b8;margin:2rem 0 1rem;border-bottom:1px solid #1e293b;padding-bottom:.5rem}
h3{font-size:1.1rem;color:#cbd5e1;margin:.5rem 0}
.header{background:linear-gradient(135deg,#1e1b4b,#312e81);border-radius:12px;padding:2rem;margin-bottom:2rem;border:1px solid #3730a3}
.subtitle{color:#a5b4fc;font-size:.9rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin:1rem 0}
.card{background:#1e293b;border-radius:10px;padding:1.5rem;border:1px solid #334155}
.card .label{color:#64748b;font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}
.card .value{font-size:2rem;font-weight:700;margin-top:.3rem}
.critical{color:#ef4444}.high{color:#f97316}.medium{color:#eab308}.low{color:#22c55e}.info{color:#3b82f6}
.badge{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:.75rem;font-weight:600}
.badge.Critical{background:#7f1d1d;color:#fca5a5}
.badge.High{background:#7c2d12;color:#fdba74}
.badge.Medium{background:#713f12;color:#fde047}
.badge.Low{background:#14532d;color:#86efac}
.badge.Info{background:#1e3a5f;color:#93c5fd}
.badge.Zombie{background:#4c1d95;color:#ddd6fe}
.badge.Rogue{background:#7c2d12;color:#fdba74}
.badge.Ghost{background:#312e81;color:#c4b5fd}
.badge.Orphaned{background:#713f12;color:#fde047}
table{width:100%;border-collapse:collapse;margin:1rem 0;font-size:.85rem}
.table-scroll{width:100%;overflow-x:auto}
th{background:#1e293b;color:#94a3b8;text-align:left;padding:10px 12px;border-bottom:2px solid #334155}
td{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:top}
tr:hover{background:#1e293b80}
.vuln-card{background:#1e293b;border-radius:10px;padding:1.5rem;margin:1rem 0;border-left:4px solid #334155}
.vuln-card.Critical{border-left-color:#ef4444}
.vuln-card.High{border-left-color:#f97316}
.vuln-card.Medium{border-left-color:#eab308}
.vuln-card.Low{border-left-color:#22c55e}
pre{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:1rem;overflow-x:auto;font-size:.8rem;margin:.5rem 0;color:#94a3b8}
.muted{color:#64748b;font-size:.75rem}
.remediation{background:#14532d20;border:1px solid #16a34a30;border-radius:6px;padding:.8rem;margin-top:.8rem;font-size:.85rem}
.footer{text-align:center;color:#475569;margin-top:3rem;padding-top:1rem;border-top:1px solid #1e293b;font-size:.8rem}
.score-ring{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:700;margin:0 auto}
.risk-note{background:#450a0a;border:1px solid #991b1b;border-radius:6px;padding:.8rem 1rem;margin:1rem 0;color:#fecaca;font-size:.85rem}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>Shadow / Unmanaged API Scanner Report</h1>
<p class="subtitle">Target: {{ scan.target_url | redact_url }} &nbsp;|&nbsp; Scan ID: {{ scan.scan_id }} &nbsp;|&nbsp; {{ scan.started_at }}</p>
</div>
{% set api_counts = scan.api_classification_counts() %}
{% set unified = scan.unified_findings() %}
<div class="risk-note">
<strong>Shadow API and Unmanaged API are the same category.</strong>
An active production endpoint is Shadow / Unmanaged when it is invisible to IT
security, lacks central management and official documentation, and has no active
security monitoring. Shared risks include missing authentication, data leakage,
and zero security visibility. External discovery confirms live operation and
baseline absence; internal gateway ownership and monitoring status still
require organizational validation.
</div>

<h2>Discovery Findings</h2>
<div class="grid">
<div class="card"><div class="label">Documented API</div><div class="value low">{{ unified.discovery.documented_api|length }}</div></div>
<div class="card"><div class="label">Shadow API</div><div class="value critical">{{ unified.discovery.shadow_api|length }}</div></div>
<div class="card"><div class="label">Undocumented Parameters</div><div class="value medium">{{ unified.discovery.undocumented_parameter|length }}</div></div>
<div class="card"><div class="label">Runtime-only API</div><div class="value high">{{ unified.discovery.runtime_only_api|length }}</div></div>
<div class="card"><div class="label">Static-only API</div><div class="value info">{{ unified.discovery.static_only_api|length }}</div></div>
</div>

<div class="grid">
<div class="card"><div class="label">Risk Level</div>
<div class="value {{ scan.overall_risk_level.value | lower }}">{{ scan.overall_risk_level.value }}</div></div>
<div class="card"><div class="label">Risk Score</div>
<div class="value">{{ "%.1f"|format(scan.overall_risk_score) }}/10</div></div>
<div class="card"><div class="label">API Operations</div>
<div class="value">{{ scan.all_endpoints|length }}</div></div>
<div class="card"><div class="label">Method Candidates</div>
<div class="value info">{{ scan.candidate_endpoints|length }}</div></div>
<div class="card"><div class="label">Endpoint Observations</div>
<div class="value info">{{ scan.raw_endpoints_discovered or scan.all_endpoints | sum(attribute='observed_count') }}</div></div>
<div class="card"><div class="label">Shadow / Unmanaged APIs</div>
<div class="value critical">{{ api_counts['Shadow / Unmanaged API'] }}</div></div>
<div class="card"><div class="label">Unverified API References</div>
<div class="value info">{{ api_counts['Unknown API'] }}</div></div>
<div class="card"><div class="label">Documented APIs</div>
<div class="value low">{{ scan.documented_endpoints|length }}</div></div>
<div class="card"><div class="label">Vulnerabilities</div>
<div class="value high">{{ scan.vulnerabilities|length }}</div></div>
<div class="card"><div class="label">JS Files Analyzed</div>
<div class="value info">{{ scan.js_files_analyzed }}</div></div>
<div class="card"><div class="label">Templates Resolved</div>
<div class="value info">{{ scan.template_endpoints_resolved }}</div></div>
<div class="card"><div class="label">Imported Traffic</div>
<div class="value info">{{ scan.imported_traffic_requests }}</div></div>
<div class="card"><div class="label">Security-Discovered Operations</div>
<div class="value info">{{ scan.security_operations_discovered }}</div></div>
</div>

<div class="grid">
<div class="card"><div class="label">Critical</div><div class="value critical">{{ scan.critical_count }}</div></div>
<div class="card"><div class="label">High</div><div class="value high">{{ scan.high_count }}</div></div>
<div class="card"><div class="label">Medium</div><div class="value medium">{{ scan.medium_count }}</div></div>
<div class="card"><div class="label">Low</div><div class="value low">{{ scan.low_count }}</div></div>
</div>

{% if scan.accuracy_metrics %}
<h2>Accuracy Benchmark</h2>
<div class="grid">
<div class="card"><div class="label">Discovery Precision</div>
<div class="value">{{ 'N/A' if scan.accuracy_metrics.discovery_precision is none else '%.1f%%'|format(scan.accuracy_metrics.discovery_precision * 100) }}</div></div>
<div class="card"><div class="label">Discovery Recall</div>
<div class="value">{{ 'N/A' if scan.accuracy_metrics.discovery_recall is none else '%.1f%%'|format(scan.accuracy_metrics.discovery_recall * 100) }}</div></div>
<div class="card"><div class="label">Discovery F1</div>
<div class="value">{{ 'N/A' if scan.accuracy_metrics.discovery_f1 is none else '%.1f%%'|format(scan.accuracy_metrics.discovery_f1 * 100) }}</div></div>
<div class="card"><div class="label">Shadow / Unmanaged Precision</div>
<div class="value">{{ 'N/A' if scan.accuracy_metrics.shadow_precision is none else '%.1f%%'|format(scan.accuracy_metrics.shadow_precision * 100) }}</div></div>
<div class="card"><div class="label">Shadow / Unmanaged Recall</div>
<div class="value">{{ 'N/A' if scan.accuracy_metrics.shadow_recall is none else '%.1f%%'|format(scan.accuracy_metrics.shadow_recall * 100) }}</div></div>
<div class="card"><div class="label">Shadow / Unmanaged F1</div>
<div class="value">{{ 'N/A' if scan.accuracy_metrics.shadow_f1 is none else '%.1f%%'|format(scan.accuracy_metrics.shadow_f1 * 100) }}</div></div>
<div class="card"><div class="label">Documentation Macro F1</div>
<div class="value">{{ 'N/A' if scan.accuracy_metrics.documentation_macro_f1 is none else '%.1f%%'|format(scan.accuracy_metrics.documentation_macro_f1 * 100) }}</div></div>
<div class="card"><div class="label">API Classification Macro F1</div>
<div class="value">{{ 'N/A' if scan.accuracy_metrics.api_classification_macro_f1 is none else '%.1f%%'|format(scan.accuracy_metrics.api_classification_macro_f1 * 100) }}</div></div>
</div>
<table>
<thead><tr><th>Discovery TP</th><th>Discovery FP</th><th>Discovery FN</th><th>90% Target</th></tr></thead>
<tbody><tr>
<td>{{ scan.accuracy_metrics.discovery_true_positives }}</td>
<td>{{ scan.accuracy_metrics.discovery_false_positives }}</td>
<td>{{ scan.accuracy_metrics.discovery_false_negatives }}</td>
<td>{{ 'Met' if scan.accuracy_metrics.meets_90_percent_target else 'Not met' }}</td>
</tr></tbody>
</table>
{% if scan.accuracy_metrics.api_classification_expected_operations %}
<h3>API Classification Confusion Matrix</h3>
<div class="table-scroll">
<table>
<thead><tr><th>Expected / Predicted</th>{% for label in scan.accuracy_metrics.api_classification_labels %}<th>{{ label }}</th>{% endfor %}</tr></thead>
<tbody>
{% for expected_label in scan.accuracy_metrics.api_classification_labels %}
<tr><td><strong>{{ expected_label }}</strong></td>{% for predicted_label in scan.accuracy_metrics.api_classification_labels %}<td>{{ scan.accuracy_metrics.api_classification_confusion_matrix[expected_label][predicted_label] }}</td>{% endfor %}</tr>
{% endfor %}
</tbody>
</table>
</div>
{% endif %}
{% endif %}

<h2>Discovered API Operations ({{ scan.all_endpoints|length }})</h2>
<table>
<thead><tr><th>Method</th><th>Route</th><th>Observed</th><th>Evidence</th><th>Type</th><th>Source</th><th>Owner</th><th>Lifecycle</th><th>API Status</th><th>Status</th></tr></thead>
<tbody>
{% for ep in scan.all_endpoints %}
{% set api_classification = scan.api_classification_for(ep) %}
<tr>
<td><strong>{{ ep.method }}</strong></td>
<td style="word-break:break-all">
{{ (ep.route_pattern or ep.url) | redact_url }}
{% if ep.route_pattern %}<div class="muted">Representative: {{ ep.url | redact_url }}</div>{% endif %}
</td>
<td>{{ ep.observed_count }}</td>
<td>{{ ep.operation_evidence | join(', ') if ep.operation_evidence else ep.source.value }}</td>
<td>{{ ep.endpoint_type.value }}</td>
<td>{{ ep.source.value }}</td>
<td>{{ ep.owner or '-' }}</td>
<td>{{ ep.lifecycle or '-' }}</td>
<td title="{{ scan.api_classification_reason_for(ep) }}">{% if api_classification == 'Shadow / Unmanaged API' %}<span class="badge Critical">Shadow / Unmanaged API</span>{% elif api_classification == 'Documented API' %}<span class="badge Low">Documented API</span>{% else %}<span class="badge Info">Unknown API</span>{% endif %}</td>
<td>{{ ep.status_code or '-' }}</td>
</tr>
{% endfor %}
</tbody>
</table>

{% if scan.candidate_endpoints %}
<h2>Unverified Method Candidates ({{ scan.candidate_endpoints|length }})</h2>
<table>
<thead><tr><th>Method</th><th>Route</th><th>Evidence</th><th>Source</th><th>Status</th></tr></thead>
<tbody>
{% for ep in scan.candidate_endpoints %}
<tr>
<td><strong>{{ ep.method }}</strong></td>
<td style="word-break:break-all">{{ (ep.route_pattern or ep.url) | redact_url }}</td>
<td>{{ ep.operation_evidence | join(', ') }}</td>
<td>{{ ep.source.value }}</td>
<td>Candidate, not confirmed active</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}

{% if scan.inventory_diff and scan.inventory_diff.summary %}
<h2>Inventory Diff</h2>
<div class="grid">
<div class="card"><div class="label">Added</div><div class="value high">{{ scan.inventory_diff.summary.added }}</div></div>
<div class="card"><div class="label">Removed</div><div class="value medium">{{ scan.inventory_diff.summary.removed }}</div></div>
<div class="card"><div class="label">Status Changes</div><div class="value info">{{ scan.inventory_diff.summary.status_changed }}</div></div>
<div class="card"><div class="label">Method Changes</div><div class="value info">{{ scan.inventory_diff.summary.method_changes }}</div></div>
</div>
{% if scan.inventory_diff.added %}
<h3>Added Endpoints</h3>
<table>
<thead><tr><th>Method</th><th>URL</th><th>Status</th></tr></thead>
<tbody>
{% for ep in scan.inventory_diff.added[:25] %}
<tr><td><strong>{{ ep.method }}</strong></td><td style="word-break:break-all">{{ ep.url | redact_url }}</td><td>{{ ep.documentation_status }}</td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}
{% if scan.inventory_diff.removed %}
<h3>Removed Endpoints</h3>
<table>
<thead><tr><th>Method</th><th>URL</th><th>Status</th></tr></thead>
<tbody>
{% for ep in scan.inventory_diff.removed[:25] %}
<tr><td><strong>{{ ep.method }}</strong></td><td style="word-break:break-all">{{ ep.url | redact_url }}</td><td>{{ ep.documentation_status }}</td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}
{% endif %}

<h2>Security Findings</h2>
<div class="grid">
<div class="card"><div class="label">BOLA / IDOR</div><div class="value">{{ unified.security.bola_idor|length }}</div></div>
<div class="card"><div class="label">Authentication</div><div class="value">{{ unified.security.authentication_issue|length }}</div></div>
<div class="card"><div class="label">Data Exposure</div><div class="value">{{ unified.security.excessive_data_exposure|length }}</div></div>
<div class="card"><div class="label">Parameter Manipulation</div><div class="value">{{ unified.security.parameter_manipulation|length }}</div></div>
<div class="card"><div class="label">Rate-limit Weakness</div><div class="value">{{ unified.security.rate_limit_weakness|length }}</div></div>
<div class="card"><div class="label">Injection Indicator</div><div class="value">{{ unified.security.injection_indicator|length }}</div></div>
<div class="card"><div class="label">Session / Access Control</div><div class="value">{{ unified.security.session_access_control|length }}</div></div>
</div>

{% if scan.validation_results %}
<h3>Validation Evidence ({{ scan.validation_results|length }})</h3>
<div class="table-scroll"><table>
<thead><tr><th>Result</th><th>Validator</th><th>Method</th><th>Endpoint</th><th>Severity</th><th>Confidence</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{% for finding in scan.validation_results %}<tr>
<td>{{ finding.result.value }}</td><td>{{ finding.validator }}</td><td>{{ finding.method }}</td>
<td style="word-break:break-all">{{ (finding.normalized_route or finding.endpoint) | redact_url }}</td>
<td><span class="badge {{ finding.severity.value }}">{{ finding.severity.value }}</span></td>
<td>{{ '%.0f%%'|format(finding.confidence * 100) }}</td>
<td>{{ (finding.evidence.reason or '-') | redact_body }}</td><td>{{ finding.remediation or '-' }}</td>
</tr>{% endfor %}</tbody>
</table></div>
{% endif %}

<h2>Vulnerabilities ({{ scan.vulnerabilities|length }})</h2>
{% for vuln in scan.vulnerabilities %}
<div class="vuln-card {{ vuln.severity.value }}">
<div style="display:flex;justify-content:space-between;align-items:start">
<h3>{{ vuln.title }}</h3>
<span class="badge {{ vuln.severity.value }}">{{ vuln.severity.value }} ({{ "%.1f"|format(vuln.risk_score) }})</span>
</div>
<p style="color:#94a3b8;font-size:.85rem;margin:.5rem 0">{{ vuln.owasp_category }}: {{ vuln.owasp_name }}</p>
{% if vuln.affected_methods %}<p class="muted"><strong>Affected operation:</strong> {{ vuln.affected_methods | join(', ') }}</p>{% endif %}
<p>{{ vuln.description }}</p>
{% if vuln.report_poc_request %}<h4 style="margin-top:1rem;color:#64748b">Proof of Concept - Request</h4><pre>{{ vuln.report_poc_request }}</pre>{% endif %}
{% if vuln.report_poc_response %}<h4 style="color:#64748b">Response</h4><pre>{{ vuln.report_poc_response[:800] }}</pre>{% endif %}
{% if vuln.remediation %}<div class="remediation"><strong>Remediation:</strong> {{ vuln.remediation }}</div>{% endif %}
{% if vuln.cwe_id %}<p style="margin-top:.5rem;font-size:.8rem;color:#64748b">CWE: {{ vuln.cwe_id }}</p>{% endif %}
</div>
{% endfor %}

{% if scan.warnings %}
<h2>Warnings</h2>
<ul>{% for warning in scan.warnings %}<li style="color:#facc15">{{ warning | redact_body }}</li>{% endfor %}</ul>
{% endif %}

{% if scan.errors %}
<h2>Errors</h2>
<ul>{% for e in scan.errors %}<li style="color:#f87171">{{ e | redact_body }}</li>{% endfor %}</ul>
{% endif %}

<div class="footer">
<p>Generated by Shadow / Unmanaged API Scanner v{{ version }} &nbsp;|&nbsp; {{ scan.completed_at }}</p>
</div>
</div>
</body>
</html>"""


class ReportGenerator:
    """Generate JSON and HTML reports from scan results."""

    def __init__(self, config: ScanConfig):
        self.config = config

    def generate(self, result: ScanResult) -> dict[str, str]:
        """
        Generate reports in all configured formats.

        Returns:
            Dict mapping format name -> output file path.
        """
        logger.info("=" * 60)
        logger.info("PHASE 4: Report Generation")
        logger.info("=" * 60)

        output_dir = Path(ensure_dir(self.config.output_dir))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        generated: dict[str, str] = {}

        # JSON report
        if "json" in self.config.report_formats:
            json_path = output_dir / f"scan_report_{timestamp}.json"
            with json_path.open("w", encoding="utf-8", newline="\n") as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            generated["json"] = str(json_path)
            logger.info(f"  JSON report: {json_path}")

        # HTML report
        if "html" in self.config.report_formats:
            html_path = output_dir / f"scan_report_{timestamp}.html"
            environment = Environment(autoescape=True)
            environment.filters["redact_body"] = redact_body
            environment.filters["redact_url"] = redact_url
            template = environment.from_string(HTML_TEMPLATE)
            html_content = template.render(scan=result, version=__version__)
            with html_path.open("w", encoding="utf-8", newline="\n") as f:
                f.write(html_content)
            generated["html"] = str(html_path)
            logger.info(f"  HTML report: {html_path}")

        return generated
