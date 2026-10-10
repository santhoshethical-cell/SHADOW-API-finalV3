"""Evaluate a saved scanner report against labeled operation ground truth."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from shadow_api_scanner.core.models import (
    APIEndpoint,
    DocumentationStatus,
    EndpointSource,
    EndpointType,
    SHADOW_UNMANAGED_API_LABEL,
)
from shadow_api_scanner.evaluation.metrics import (
    API_CLASSIFICATION_LABELS,
    DOCUMENTATION_LABELS,
    AccuracyEvaluator,
)


def evaluate_scan_report(
    report_file: str,
    ground_truth_file: str,
) -> dict[str, object]:
    """Return benchmark metrics for a previously generated JSON report."""
    report_path = Path(report_file)
    with report_path.open("r", encoding="utf-8") as file_handle:
        report = json.load(file_handle)
    with open(ground_truth_file, "r", encoding="utf-8") as file_handle:
        ground_truth = json.load(file_handle)

    if not isinstance(report, dict) or not report.get("target_url"):
        raise ValueError("Scan report must contain target_url")
    endpoint_section = report.get("endpoints", {})
    records = (
        endpoint_section.get("all", [])
        if isinstance(endpoint_section, dict)
        else []
    )
    if not isinstance(records, list):
        raise ValueError("Scan report endpoints.all must be a list")

    endpoints: list[APIEndpoint] = []
    classifications: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict) or not record.get("url"):
            raise ValueError("Each report endpoint must contain a url")
        endpoint = _endpoint_from_record(record)
        endpoints.append(endpoint)
        if record.get("api_classification"):
            classifications[endpoint.id] = str(
                record["api_classification"]
            )

    def classification_for(endpoint: APIEndpoint) -> str:
        explicit = classifications.get(endpoint.id)
        if explicit:
            return explicit
        if endpoint.documentation_status == DocumentationStatus.DOCUMENTED:
            return "Documented API"
        if (
            endpoint.documentation_status == DocumentationStatus.SHADOW
            or endpoint.is_shadow
        ):
            return SHADOW_UNMANAGED_API_LABEL
        return "Unknown API"

    metrics = AccuracyEvaluator(str(report["target_url"])).evaluate_file(
        ground_truth_file,
        endpoints,
        classification_for,
    )
    finding_metrics = _evaluate_required_findings(
        ground_truth,
        report,
    )
    metrics.update(finding_metrics)
    security_metrics = _evaluate_security_findings(ground_truth, report)
    metrics.update(security_metrics)
    metrics["execution_time_seconds"] = _execution_time_seconds(report)
    if finding_metrics["required_findings"]:
        metrics["target_metrics"]["required_findings_recall"] = (
            finding_metrics["required_findings_recall"]
        )
        metrics["meets_90_percent_target"] = all(
            value is not None and value >= 0.9
            for value in metrics["target_metrics"].values()
        )
    if security_metrics["security_expected_findings"]:
        metrics["target_metrics"]["security_validation_f1"] = (
            security_metrics["security_validation_f1"]
        )
        metrics["meets_90_percent_target"] = all(
            value is not None and value >= 0.9
            for value in metrics["target_metrics"].values()
        )
    return metrics


def evaluate_benchmark_manifest(
    manifest_file: str,
) -> dict[str, object]:
    """Evaluate and aggregate all saved-report cases in a manifest."""
    manifest_path = Path(manifest_file).resolve()
    with manifest_path.open("r", encoding="utf-8") as file_handle:
        manifest = json.load(file_handle)

    entries = manifest.get("cases", []) if isinstance(manifest, dict) else []
    if not isinstance(entries, list) or not entries:
        raise ValueError("Benchmark manifest must contain a non-empty cases list")

    case_results = []
    used_names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each benchmark case must be an object")
        name = str(entry.get("name", "")).strip()
        report = entry.get("report")
        ground_truth = entry.get("ground_truth")
        if not name or not report or not ground_truth:
            raise ValueError(
                "Each benchmark case requires name, report, and ground_truth"
            )
        if name in used_names:
            raise ValueError(f"Duplicate benchmark case name: {name}")
        used_names.add(name)

        report_path = _resolve_manifest_path(manifest_path, str(report))
        ground_truth_path = _resolve_manifest_path(
            manifest_path,
            str(ground_truth),
        )
        metrics = evaluate_scan_report(
            str(report_path),
            str(ground_truth_path),
        )
        case_results.append({
            "name": name,
            "kind": str(entry.get("kind", "unspecified")),
            "report": str(report_path),
            "ground_truth": str(ground_truth_path),
            "metrics": metrics,
        })

    return {
        "manifest": str(manifest_path),
        "case_count": len(case_results),
        "cases": case_results,
        "aggregate": _aggregate_case_metrics(case_results),
    }


def _aggregate_case_metrics(
    cases: list[dict],
) -> dict[str, object]:
    metrics_list = [case["metrics"] for case in cases]
    discovery_tp = sum(
        int(metrics["discovery_true_positives"])
        for metrics in metrics_list
    )
    discovery_fp = sum(
        int(metrics["discovery_false_positives"])
        for metrics in metrics_list
    )
    discovery_fn = sum(
        int(metrics["discovery_false_negatives"])
        for metrics in metrics_list
    )
    micro_discovery = _binary_metrics(
        discovery_tp,
        discovery_fp,
        discovery_fn,
    )

    macro_discovery_f1 = _mean_metric(metrics_list, "discovery_f1")
    macro_documentation_f1 = _mean_metric(
        metrics_list,
        "documentation_macro_f1",
    )
    macro_api_classification_f1 = _mean_metric(
        metrics_list,
        "api_classification_macro_f1",
    )
    total_required_findings = sum(
        int(metrics["required_findings"])
        for metrics in metrics_list
    )
    matched_required_findings = sum(
        int(metrics["matched_required_findings"])
        for metrics in metrics_list
    )
    required_findings_recall = _ratio(
        matched_required_findings,
        total_required_findings,
    )
    macro_required_findings_recall = _mean_metric(
        metrics_list,
        "required_findings_recall",
    )
    security_tp = sum(int(metrics["security_true_positives"]) for metrics in metrics_list)
    security_fp = sum(int(metrics["security_false_positives"]) for metrics in metrics_list)
    security_tn = sum(int(metrics["security_true_negatives"]) for metrics in metrics_list)
    security_fn = sum(int(metrics["security_false_negatives"]) for metrics in metrics_list)
    security_expected = sum(int(metrics["security_expected_findings"]) for metrics in metrics_list)
    security_binary = _binary_metrics(security_tp, security_fp, security_fn)
    target_metrics = {
        "micro_discovery_precision": micro_discovery["precision"],
        "micro_discovery_recall": micro_discovery["recall"],
        "micro_discovery_f1": micro_discovery["f1"],
        "macro_documentation_f1": macro_documentation_f1,
        "macro_api_classification_f1": (
            macro_api_classification_f1
        ),
    }
    if total_required_findings:
        target_metrics["required_findings_recall"] = (
            required_findings_recall
        )
    if security_expected:
        target_metrics["security_validation_f1"] = security_binary["f1"]
    failed_cases = [
        case["name"]
        for case in cases
        if not case["metrics"]["meets_90_percent_target"]
    ]

    return {
        "total_ground_truth_operations": sum(
            int(metrics["ground_truth_endpoints"])
            for metrics in metrics_list
        ),
        "total_discovered_operations": sum(
            int(metrics["discovered_endpoints"])
            for metrics in metrics_list
        ),
        "discovery_true_positives": discovery_tp,
        "discovery_false_positives": discovery_fp,
        "discovery_false_negatives": discovery_fn,
        "micro_discovery_precision": micro_discovery["precision"],
        "micro_discovery_recall": micro_discovery["recall"],
        "micro_discovery_f1": micro_discovery["f1"],
        "macro_discovery_f1": macro_discovery_f1,
        "macro_documentation_f1": macro_documentation_f1,
        "macro_api_classification_f1": (
            macro_api_classification_f1
        ),
        "total_required_findings": total_required_findings,
        "matched_required_findings": matched_required_findings,
        "missing_required_findings": (
            total_required_findings - matched_required_findings
        ),
        "required_findings_recall": required_findings_recall,
        "macro_required_findings_recall": (
            macro_required_findings_recall
        ),
        "security_expected_findings": security_expected,
        "security_true_positives": security_tp,
        "security_false_positives": security_fp,
        "security_true_negatives": security_tn,
        "security_false_negatives": security_fn,
        "security_validation_precision": security_binary["precision"],
        "security_validation_recall": security_binary["recall"],
        "security_validation_f1": security_binary["f1"],
        "security_validation_accuracy": _ratio(
            security_tp + security_tn,
            security_tp + security_fp + security_tn + security_fn,
        ),
        "total_execution_time_seconds": sum(
            float(metrics["execution_time_seconds"] or 0)
            for metrics in metrics_list
        ),
        "mean_execution_time_seconds": _mean_metric(
            metrics_list, "execution_time_seconds"
        ),
        "documentation_per_class": _aggregate_per_class(
            metrics_list,
            "documentation_per_class",
            DOCUMENTATION_LABELS,
        ),
        "api_classification_per_class": _aggregate_per_class(
            metrics_list,
            "api_classification_per_class",
            API_CLASSIFICATION_LABELS,
        ),
        "cases_meeting_90_percent_target": (
            len(cases) - len(failed_cases)
        ),
        "failed_cases": failed_cases,
        "target_metrics": target_metrics,
        "meets_90_percent_target": all(
            value is not None and value >= 0.9
            for value in target_metrics.values()
        ),
    }


def _aggregate_per_class(
    metrics_list: list[dict],
    metrics_key: str,
    labels: tuple[str, ...],
) -> dict[str, dict[str, object]]:
    aggregated = {}
    for label in labels:
        support = sum(
            int(metrics[metrics_key][label]["support"])
            for metrics in metrics_list
        )
        predicted = sum(
            int(metrics[metrics_key][label]["predicted"])
            for metrics in metrics_list
        )
        true_positives = sum(
            int(metrics[metrics_key][label]["true_positives"])
            for metrics in metrics_list
        )
        false_positives = predicted - true_positives
        false_negatives = support - true_positives
        aggregated[label] = {
            "support": support,
            "predicted": predicted,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            **_binary_metrics(
                true_positives,
                false_positives,
                false_negatives,
            ),
        }
    return aggregated


def _evaluate_required_findings(
    ground_truth: object,
    report: object,
) -> dict[str, object]:
    requirements = (
        ground_truth.get("required_findings", [])
        if isinstance(ground_truth, dict)
        else []
    )
    if not isinstance(requirements, list):
        raise ValueError("required_findings must be a list")
    findings = (
        report.get("vulnerabilities", [])
        if isinstance(report, dict)
        else []
    )
    if not isinstance(findings, list):
        raise ValueError("Scan report vulnerabilities must be a list")

    unmatched_findings = set(range(len(findings)))
    matched = []
    missing = []
    for requirement in requirements:
        if not isinstance(requirement, dict):
            raise ValueError("Each required finding must be an object")
        match_index = next(
            (
                index
                for index in sorted(unmatched_findings)
                if _finding_matches(requirement, findings[index])
            ),
            None,
        )
        label = _required_finding_label(requirement)
        if match_index is None:
            missing.append(label)
            continue
        unmatched_findings.remove(match_index)
        matched.append(label)

    return {
        "required_findings": len(requirements),
        "matched_required_findings": len(matched),
        "missing_required_findings": missing,
        "required_findings_recall": _ratio(
            len(matched),
            len(requirements),
        ),
        "required_findings_met": not missing,
    }


def _evaluate_security_findings(
    ground_truth: object,
    report: object,
) -> dict[str, object]:
    expected = (
        ground_truth.get("security_findings", [])
        if isinstance(ground_truth, dict)
        else []
    )
    actual = (
        report.get("validation_results", [])
        if isinstance(report, dict)
        else []
    )
    if not isinstance(expected, list):
        raise ValueError("security_findings must be a list")
    if not isinstance(actual, list):
        raise ValueError("Scan report validation_results must be a list")

    scored_validators = (
        ground_truth.get("security_scored_validators")
        if isinstance(ground_truth, dict)
        else None
    )
    if scored_validators is not None:
        if not isinstance(scored_validators, list) or not all(
            isinstance(item, str) and item.strip()
            for item in scored_validators
        ):
            raise ValueError(
                "security_scored_validators must be a list of validator names"
            )
        scored = {item.strip().lower() for item in scored_validators}
        actual = [
            item for item in actual
            if (
                isinstance(item, dict)
                and str(item.get("validator", "")).lower() in scored
            )
        ]

    confusion = _security_confusion(expected, actual)
    validators = sorted({
        str(item.get("validator", "")).strip()
        for item in expected
        if isinstance(item, dict) and item.get("validator")
    })
    per_validator = {}
    for validator in validators:
        expected_cases = [
            item for item in expected
            if (
                isinstance(item, dict)
                and str(item.get("validator", "")).lower()
                == validator.lower()
            )
        ]
        actual_cases = [
            item for item in actual
            if (
                isinstance(item, dict)
                and str(item.get("validator", "")).lower()
                == validator.lower()
            )
        ]
        per_validator[validator] = _security_confusion(
            expected_cases,
            actual_cases,
        )

    return {
        **confusion,
        "security_scored_validators": validators,
        "security_per_validator": per_validator,
        "security_outcome_counts": {
            outcome: sum(
                isinstance(item, dict)
                and str(item.get("result", "")).lower() == outcome
                for item in actual
            )
            for outcome in (
                "vulnerable",
                "protected",
                "inconclusive",
                "skipped",
                "error",
            )
        },
    }


def _security_confusion(
    expected: list,
    actual: list,
) -> dict[str, object]:
    """Score one independently labeled security-validation population."""

    unmatched_actual = set(range(len(actual)))
    tp = fp = tn = fn = unclassified = 0
    missing = []
    for item in expected:
        if not isinstance(item, dict):
            raise ValueError("Each security finding must be an object")
        expected_result = str(item.get("expected_result", "")).lower()
        if expected_result not in {"vulnerable", "protected"}:
            raise ValueError(
                "security_findings expected_result must be vulnerable or protected"
            )
        match_index = next((
            index for index in sorted(unmatched_actual)
            if _security_identity_matches(item, actual[index])
        ), None)
        if match_index is None:
            if expected_result == "vulnerable":
                fn += 1
            else:
                unclassified += 1
            missing.append(_required_finding_label(item))
            continue
        unmatched_actual.remove(match_index)
        predicted = str(actual[match_index].get("result", "")).lower()
        if expected_result == "vulnerable":
            if predicted == "vulnerable":
                tp += 1
            else:
                fn += 1
        elif predicted == "vulnerable":
            fp += 1
        elif predicted == "protected":
            tn += 1
        else:
            unclassified += 1

    fp += sum(
        1 for index in unmatched_actual
        if isinstance(actual[index], dict)
        and str(actual[index].get("result", "")).lower() == "vulnerable"
    )
    binary = _binary_metrics(tp, fp, fn)
    return {
        "security_expected_findings": len(expected),
        "security_expected_vulnerable": sum(
            str(item.get("expected_result", "")).lower() == "vulnerable"
            for item in expected if isinstance(item, dict)
        ),
        "security_expected_protected": sum(
            str(item.get("expected_result", "")).lower() == "protected"
            for item in expected if isinstance(item, dict)
        ),
        "security_true_positives": tp,
        "security_false_positives": fp,
        "security_true_negatives": tn,
        "security_false_negatives": fn,
        "security_unclassified": unclassified,
        "security_validation_precision": binary["precision"],
        "security_validation_recall": binary["recall"],
        "security_validation_f1": binary["f1"],
        "security_validation_accuracy": _ratio(tp + tn, tp + fp + tn + fn),
        "missing_security_findings": missing,
    }


def _security_identity_matches(expected: dict, actual: object) -> bool:
    if not isinstance(actual, dict):
        return False
    for expected_key, actual_key in (
        ("validator", "validator"),
        ("vulnerability_category", "vulnerability_category"),
        ("method", "method"),
        ("affected_parameter", "affected_parameter"),
    ):
        if expected.get(expected_key) and str(actual.get(actual_key, "")).lower() != str(
            expected[expected_key]
        ).lower():
            return False
    if expected.get("endpoint"):
        expected_path = str(expected["endpoint"]).rstrip("/")
        actual_endpoint = str(
            actual.get("normalized_route") or actual.get("endpoint", "")
        ).rstrip("/")
        if not (
            actual_endpoint == expected_path
            or actual_endpoint.endswith(expected_path)
        ):
            return False
    return True


def _execution_time_seconds(report: object) -> Optional[float]:
    if not isinstance(report, dict):
        return None
    try:
        started = datetime.fromisoformat(str(report["started_at"]))
        completed = datetime.fromisoformat(str(report["completed_at"]))
    except (KeyError, TypeError, ValueError):
        return None
    return max(0.0, (completed - started).total_seconds())


def _finding_matches(requirement: dict, finding: object) -> bool:
    if not isinstance(finding, dict):
        return False
    title = str(finding.get("title", ""))
    if requirement.get("title") and title != str(requirement["title"]):
        return False
    if (
        requirement.get("title_prefix")
        and not title.startswith(str(requirement["title_prefix"]))
    ):
        return False
    if (
        requirement.get("owasp_category")
        and str(finding.get("owasp_category", "")).upper()
        != str(requirement["owasp_category"]).upper()
    ):
        return False
    if (
        requirement.get("status")
        and str(finding.get("status", "")).lower()
        != str(requirement["status"]).lower()
    ):
        return False
    if requirement.get("affected_method"):
        affected_methods = {
            str(method).upper()
            for method in finding.get("affected_methods", [])
        }
        if str(requirement["affected_method"]).upper() not in affected_methods:
            return False
    return True


def _required_finding_label(requirement: dict) -> str:
    return str(
        requirement.get("name")
        or requirement.get("title")
        or requirement.get("title_prefix")
        or requirement.get("owasp_category")
        or "unnamed finding"
    )


def _mean_metric(
    metrics_list: list[dict],
    key: str,
) -> Optional[float]:
    values = [
        float(metrics[key])
        for metrics in metrics_list
        if metrics.get(key) is not None
    ]
    return sum(values) / len(values) if values else None


def _binary_metrics(
    true_positives: int,
    false_positives: int,
    false_negatives: int,
) -> dict[str, Optional[float]]:
    precision = _ratio(
        true_positives,
        true_positives + false_positives,
    )
    recall = _ratio(
        true_positives,
        true_positives + false_negatives,
    )
    denominator = (
        (2 * true_positives)
        + false_positives
        + false_negatives
    )
    return {
        "precision": precision,
        "recall": recall,
        "f1": (
            (2 * true_positives) / denominator
            if denominator
            else None
        ),
    }


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return numerator / denominator if denominator else None


def _resolve_manifest_path(
    manifest_path: Path,
    configured_path: str,
) -> Path:
    path = Path(configured_path)
    if not path.is_absolute():
        path = manifest_path.parent / path
    return path.resolve()


def _endpoint_from_record(record: dict) -> APIEndpoint:
    source = _enum_value(
        EndpointSource,
        record.get("source"),
        EndpointSource.MANUAL,
    )
    endpoint_type = _enum_value(
        EndpointType,
        record.get("type"),
        EndpointType.UNKNOWN,
    )
    documentation_status = _enum_value(
        DocumentationStatus,
        record.get("documentation_status"),
        DocumentationStatus.UNKNOWN,
    )
    endpoint = APIEndpoint(
        url=str(record.get("representative_url") or record["url"]),
        method=str(record.get("method", "GET")).upper(),
        endpoint_type=endpoint_type,
        source=source,
        is_shadow=bool(record.get("is_shadow", False)),
        documentation_status=documentation_status,
        documentation_reason=str(
            record.get("documentation_reason", "")
        ),
        status_code=record.get("status_code"),
        confidence=float(record.get("confidence", 1.0)),
        route_pattern=record.get("route_pattern"),
        observed_urls=list(record.get("observed_urls", [])),
        observed_sources=list(record.get("observed_sources", [])),
        operation_evidence=list(record.get("operation_evidence", [])),
        parent_endpoint_id=record.get("parent_endpoint_id"),
    )
    if record.get("id"):
        endpoint.id = str(record["id"])
    return endpoint


def _enum_value(enum_type, value, default):
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        return default


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate one saved report or aggregate a benchmark manifest."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--report", help="Scanner JSON report")
    source.add_argument(
        "--manifest",
        help="Benchmark manifest containing multiple cases",
    )
    parser.add_argument(
        "--ground-truth",
        help="Labeled ground-truth JSON",
    )
    parser.add_argument(
        "--output",
        help="Optional path for benchmark metrics JSON",
    )
    args = parser.parse_args(argv)

    if args.report:
        if not args.ground_truth:
            parser.error("--ground-truth is required with --report")
        metrics = evaluate_scan_report(args.report, args.ground_truth)
    else:
        if args.ground_truth:
            parser.error("--ground-truth cannot be used with --manifest")
        metrics = evaluate_benchmark_manifest(args.manifest)
    rendered = json.dumps(metrics, indent=2)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
