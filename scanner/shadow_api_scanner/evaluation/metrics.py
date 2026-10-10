"""Evaluate operation discovery and classification against labeled truth."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

from shadow_api_scanner.core.models import (
    APIEndpoint,
    DocumentationStatus,
    SHADOW_UNMANAGED_API_LABEL,
)


PARAMETER_SEGMENT = re.compile(r"^(?:\{[^/{}]+\}|:[A-Za-z_$][\w$]*)$")
AKTO_PARAMETER_SEGMENTS = {
    "INTEGER",
    "FLOAT",
    "UUID",
    "BOOLEAN",
    "AKTO_TEMPLATE_STR",
}
DOCUMENTATION_LABELS = tuple(status.value for status in DocumentationStatus)
API_CLASSIFICATION_LABELS = (
    "Documented API",
    SHADOW_UNMANAGED_API_LABEL,
    "Unknown API",
)
API_CLASSIFICATION_ALIASES = {
    label.lower(): label for label in API_CLASSIFICATION_LABELS
}
API_CLASSIFICATION_ALIASES.update({
    label.removesuffix(" API").lower(): label
    for label in API_CLASSIFICATION_LABELS
})
API_CLASSIFICATION_ALIASES.update({
    "shadow api": SHADOW_UNMANAGED_API_LABEL,
    "shadow": SHADOW_UNMANAGED_API_LABEL,
    "unmanaged api": SHADOW_UNMANAGED_API_LABEL,
    "unmanaged": SHADOW_UNMANAGED_API_LABEL,
    "known unmanaged api": SHADOW_UNMANAGED_API_LABEL,
    "unknown shadow api": SHADOW_UNMANAGED_API_LABEL,
    # Read historical benchmark artifacts without preserving their old
    # user-facing taxonomy.
    "zombie api": SHADOW_UNMANAGED_API_LABEL,
    "rogue api": SHADOW_UNMANAGED_API_LABEL,
    "orphaned api": SHADOW_UNMANAGED_API_LABEL,
    "ghost api": "Unknown API",
})


@dataclass(frozen=True)
class ExpectedEndpoint:
    method: str
    url: str
    documentation_status: DocumentationStatus
    api_classification: Optional[str] = None


class AccuracyEvaluator:
    """Compute one-to-one operation discovery and classification metrics."""

    def __init__(self, target_url: str):
        self.target_url = target_url

    def evaluate_file(
        self,
        ground_truth_file: str,
        discovered: list[APIEndpoint],
        classification_for: Optional[
            Callable[[APIEndpoint], str]
        ] = None,
    ) -> dict[str, object]:
        with open(ground_truth_file, "r", encoding="utf-8") as file_handle:
            payload = json.load(file_handle)
        return self.evaluate(
            self._parse_expected(payload),
            discovered,
            classification_for,
        )

    def evaluate(
        self,
        expected: list[ExpectedEndpoint],
        discovered: list[APIEndpoint],
        classification_for: Optional[
            Callable[[APIEndpoint], str]
        ] = None,
    ) -> dict[str, object]:
        matched_pairs = self._match_pairs(expected, discovered)
        matched_expected = {expected_index for expected_index, _ in matched_pairs}
        matched_actual = {actual_index for _, actual_index in matched_pairs}

        discovery_tp = len(matched_pairs)
        discovery_fp = len(discovered) - discovery_tp
        discovery_fn = len(expected) - discovery_tp
        discovery_metrics = self._binary_metrics(
            discovery_tp,
            discovery_fp,
            discovery_fn,
        )

        documentation_expected = {
            index: item.documentation_status.value
            for index, item in enumerate(expected)
        }
        documentation_predicted = {
            index: endpoint.documentation_status.value
            for index, endpoint in enumerate(discovered)
        }
        documentation_metrics = self._classification_metrics(
            DOCUMENTATION_LABELS,
            documentation_expected,
            documentation_predicted,
            matched_pairs,
        )
        shadow_metrics = documentation_metrics["per_class"]["shadow"]

        expected_api_classifications = {
            index: label
            for index, item in enumerate(expected)
            if (
                label := self._expected_api_classification(item)
            ) is not None
        }
        api_pairs = [
            (expected_index, actual_index)
            for expected_index, actual_index in matched_pairs
            if expected_index in expected_api_classifications
        ]
        api_predictions = {
            actual_index: self._actual_api_classification(
                discovered[actual_index],
                classification_for,
            )
            for _, actual_index in api_pairs
        }
        api_metrics = self._classification_metrics(
            API_CLASSIFICATION_LABELS,
            expected_api_classifications,
            api_predictions,
            api_pairs,
        )

        target_metrics = {
            "discovery_precision": discovery_metrics["precision"],
            "discovery_recall": discovery_metrics["recall"],
            "discovery_f1": discovery_metrics["f1"],
            "documentation_macro_f1": documentation_metrics["macro_f1"],
        }
        if (
            shadow_metrics["support"]
            or shadow_metrics["predicted"]
        ):
            target_metrics["shadow_f1"] = shadow_metrics["f1"]
        if expected_api_classifications:
            target_metrics["api_classification_macro_f1"] = (
                api_metrics["macro_f1"]
            )

        return {
            "ground_truth_endpoints": len(expected),
            "discovered_endpoints": len(discovered),
            "matched_ground_truth_endpoints": discovery_tp,
            "discovery_true_positives": discovery_tp,
            "discovery_false_positives": discovery_fp,
            "discovery_false_negatives": discovery_fn,
            "false_positive_operations": [
                self._actual_operation_label(discovered[index])
                for index in range(len(discovered))
                if index not in matched_actual
            ],
            "false_negative_operations": [
                self._expected_operation_label(expected[index])
                for index in range(len(expected))
                if index not in matched_expected
            ],
            "discovery_precision": discovery_metrics["precision"],
            "discovery_recall": discovery_metrics["recall"],
            "discovery_f1": discovery_metrics["f1"],
            "expected_shadow_endpoints": shadow_metrics["support"],
            "predicted_shadow_endpoints": shadow_metrics["predicted"],
            "shadow_precision": shadow_metrics["precision"],
            "shadow_recall": shadow_metrics["recall"],
            "shadow_f1": shadow_metrics["f1"],
            "unmanaged_precision": shadow_metrics["precision"],
            "unmanaged_recall": shadow_metrics["recall"],
            "unmanaged_f1": shadow_metrics["f1"],
            "shadow_unmanaged_precision": shadow_metrics["precision"],
            "shadow_unmanaged_recall": shadow_metrics["recall"],
            "shadow_unmanaged_f1": shadow_metrics["f1"],
            "documentation_classification_accuracy": (
                documentation_metrics["accuracy"]
            ),
            "documentation_classification_coverage": (
                documentation_metrics["coverage"]
            ),
            "documentation_macro_f1": documentation_metrics["macro_f1"],
            "documentation_labels": list(DOCUMENTATION_LABELS),
            "documentation_confusion_matrix": (
                documentation_metrics["confusion_matrix"]
            ),
            "documentation_per_class": documentation_metrics["per_class"],
            "api_classification_expected_operations": len(
                expected_api_classifications
            ),
            "api_classification_matched_operations": api_metrics["matched"],
            "api_classification_correct_operations": api_metrics["correct"],
            "api_classification_accuracy": api_metrics["accuracy"],
            "api_classification_coverage": api_metrics["coverage"],
            "api_classification_macro_f1": api_metrics["macro_f1"],
            "api_classification_labels": list(API_CLASSIFICATION_LABELS),
            "api_classification_confusion_matrix": (
                api_metrics["confusion_matrix"]
            ),
            "api_classification_per_class": api_metrics["per_class"],
            "target_metrics": target_metrics,
            "meets_90_percent_target": bool(target_metrics) and all(
                metric is not None and metric >= 0.9
                for metric in target_metrics.values()
            ),
        }

    def _parse_expected(self, payload: object) -> list[ExpectedEndpoint]:
        entries = payload.get("endpoints", []) if isinstance(payload, dict) else payload
        if not isinstance(entries, list):
            raise ValueError("Ground truth must be a list or an object with endpoints")

        expected: list[ExpectedEndpoint] = []
        for entry in entries:
            if not isinstance(entry, dict) or "url" not in entry:
                raise ValueError("Each ground-truth endpoint must contain a url")
            raw_status = entry.get(
                "documentation_status",
                "shadow" if entry.get("is_shadow") else "documented",
            )
            try:
                status = DocumentationStatus(str(raw_status).lower())
            except ValueError as error:
                raise ValueError(
                    f"Unsupported documentation_status: {raw_status}"
                ) from error
            raw_api_classification = entry.get("api_classification")
            api_classification = None
            if raw_api_classification is not None:
                api_classification = self._normalize_api_classification(
                    raw_api_classification
                )
            expected.append(ExpectedEndpoint(
                method=str(entry.get("method", "GET")).upper(),
                url=urljoin(self.target_url.rstrip("/") + "/", str(entry["url"])),
                documentation_status=status,
                api_classification=api_classification,
            ))
        return expected

    def _match_pairs(
        self,
        expected: list[ExpectedEndpoint],
        discovered: list[APIEndpoint],
    ) -> list[tuple[int, int]]:
        adjacency = {
            expected_index: [
                actual_index
                for actual_index, endpoint in enumerate(discovered)
                if self._matches(item, endpoint)
            ]
            for expected_index, item in enumerate(expected)
        }
        actual_to_expected: dict[int, int] = {}

        def assign(expected_index: int, seen: set[int]) -> bool:
            for actual_index in adjacency[expected_index]:
                if actual_index in seen:
                    continue
                seen.add(actual_index)
                previous = actual_to_expected.get(actual_index)
                if previous is None or assign(previous, seen):
                    actual_to_expected[actual_index] = expected_index
                    return True
            return False

        ordered_expected = sorted(
            range(len(expected)),
            key=lambda index: self._specificity(expected[index]),
            reverse=True,
        )
        for expected_index in ordered_expected:
            assign(expected_index, set())

        return sorted(
            (
                expected_index,
                actual_index,
            )
            for actual_index, expected_index in actual_to_expected.items()
        )

    def _matches(self, expected: ExpectedEndpoint, actual: APIEndpoint) -> bool:
        if expected.method != actual.method.upper():
            return False

        expected_parsed = urlparse(expected.url)
        actual_parsed = urlparse(actual.url)
        if (
            expected_parsed.hostname
            and actual_parsed.hostname
            and expected_parsed.netloc.lower() != actual_parsed.netloc.lower()
        ):
            return False

        expected_segments = self._segments(expected_parsed.path)
        actual_segments = self._segments(actual_parsed.path)
        if len(expected_segments) != len(actual_segments):
            return False
        return all(
            self._segment_matches(pattern, value)
            for pattern, value in zip(expected_segments, actual_segments)
        )

    @staticmethod
    def _specificity(expected: ExpectedEndpoint) -> tuple[int, int]:
        segments = AccuracyEvaluator._segments(urlparse(expected.url).path)
        static_segments = sum(
            1 for segment in segments
            if (
                not PARAMETER_SEGMENT.fullmatch(segment)
                and segment not in AKTO_PARAMETER_SEGMENTS
            )
        )
        return static_segments, len(segments)

    def _segment_matches(self, pattern: str, value: str) -> bool:
        if pattern == value:
            return True
        if PARAMETER_SEGMENT.fullmatch(pattern):
            return bool(value)
        if pattern in AKTO_PARAMETER_SEGMENTS:
            if pattern == "INTEGER":
                return bool(re.fullmatch(r"-?\d+", value))
            if pattern == "FLOAT":
                return bool(re.fullmatch(r"-?(?:\d+\.\d+|\d+)", value))
            if pattern == "BOOLEAN":
                return value.lower() in {"true", "false"}
            if pattern == "UUID":
                return bool(re.fullmatch(
                    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
                    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
                    value,
                ))
            return bool(value)
        return False

    @staticmethod
    def _segments(path: str) -> list[str]:
        return [segment for segment in path.strip("/").split("/") if segment]

    def _expected_api_classification(
        self,
        expected: ExpectedEndpoint,
    ) -> Optional[str]:
        if expected.api_classification:
            return self._normalize_api_classification(
                expected.api_classification
            )
        if expected.documentation_status == DocumentationStatus.DOCUMENTED:
            return "Documented API"
        if expected.documentation_status == DocumentationStatus.SHADOW:
            return SHADOW_UNMANAGED_API_LABEL
        return None

    def _actual_api_classification(
        self,
        endpoint: APIEndpoint,
        classification_for: Optional[Callable[[APIEndpoint], str]],
    ) -> str:
        if classification_for:
            return self._normalize_api_classification(
                classification_for(endpoint)
            )
        if endpoint.documentation_status == DocumentationStatus.DOCUMENTED:
            return "Documented API"
        if (
            endpoint.documentation_status == DocumentationStatus.SHADOW
            or endpoint.is_shadow
        ):
            return SHADOW_UNMANAGED_API_LABEL
        return "Unknown API"

    @staticmethod
    def _normalize_api_classification(value: object) -> str:
        normalized = str(value).strip().lower()
        classification = API_CLASSIFICATION_ALIASES.get(normalized)
        if classification is None:
            supported = ", ".join(API_CLASSIFICATION_LABELS)
            raise ValueError(
                f"Unsupported api_classification: {value}. "
                f"Expected one of: {supported}"
            )
        return classification

    @staticmethod
    def _classification_metrics(
        labels: tuple[str, ...],
        expected: dict[int, str],
        predicted: dict[int, str],
        matched_pairs: list[tuple[int, int]],
    ) -> dict[str, object]:
        confusion_matrix = {
            expected_label: {
                predicted_label: 0 for predicted_label in labels
            }
            for expected_label in labels
        }
        correct = 0
        relevant_pairs = []
        for expected_index, actual_index in matched_pairs:
            if (
                expected_index not in expected
                or actual_index not in predicted
            ):
                continue
            expected_label = expected[expected_index]
            predicted_label = predicted[actual_index]
            confusion_matrix[expected_label][predicted_label] += 1
            relevant_pairs.append((expected_index, actual_index))
            if expected_label == predicted_label:
                correct += 1

        per_class = {}
        for label in labels:
            true_positives = sum(
                1
                for expected_index, actual_index in relevant_pairs
                if (
                    expected[expected_index] == label
                    and predicted[actual_index] == label
                )
            )
            expected_count = sum(
                1 for value in expected.values() if value == label
            )
            predicted_count = sum(
                1 for value in predicted.values() if value == label
            )
            class_metrics = AccuracyEvaluator._binary_metrics(
                true_positives,
                predicted_count - true_positives,
                expected_count - true_positives,
            )
            per_class[label] = {
                "support": expected_count,
                "predicted": predicted_count,
                "true_positives": true_positives,
                "false_positives": predicted_count - true_positives,
                "false_negatives": expected_count - true_positives,
                **class_metrics,
            }

        active_f1_scores = [
            metrics["f1"]
            for metrics in per_class.values()
            if (
                metrics["support"]
                or metrics["predicted"]
            )
            and metrics["f1"] is not None
        ]
        return {
            "matched": len(relevant_pairs),
            "correct": correct,
            "accuracy": AccuracyEvaluator._ratio(
                correct, len(relevant_pairs)
            ),
            "coverage": AccuracyEvaluator._ratio(
                len(relevant_pairs), len(expected)
            ),
            "macro_f1": (
                sum(active_f1_scores) / len(active_f1_scores)
                if active_f1_scores
                else None
            ),
            "confusion_matrix": confusion_matrix,
            "per_class": per_class,
        }

    @staticmethod
    def _binary_metrics(
        true_positives: int,
        false_positives: int,
        false_negatives: int,
    ) -> dict[str, Optional[float]]:
        precision = AccuracyEvaluator._ratio(
            true_positives,
            true_positives + false_positives,
        )
        recall = AccuracyEvaluator._ratio(
            true_positives,
            true_positives + false_negatives,
        )
        f1_denominator = (
            (2 * true_positives)
            + false_positives
            + false_negatives
        )
        f1 = (
            (2 * true_positives) / f1_denominator
            if f1_denominator
            else None
        )
        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    @staticmethod
    def _expected_operation_label(endpoint: ExpectedEndpoint) -> str:
        return f"{endpoint.method.upper()} {endpoint.url}"

    @staticmethod
    def _actual_operation_label(endpoint: APIEndpoint) -> str:
        return f"{endpoint.method.upper()} {endpoint.inventory_url}"

    @staticmethod
    def _ratio(numerator: int, denominator: int) -> Optional[float]:
        if denominator == 0:
            return None
        return numerator / denominator
