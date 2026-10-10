"""Automatic local evidence and per-target history discovery.

The default CLI is intentionally useful without specialist API knowledge.
This module finds optional traffic and inventory files in conventional input
directories and maintains a target-specific inventory history file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from shadow_api_scanner.core.config import ScanConfig


@dataclass
class AutoEvidence:
    """Evidence selected for a zero-configuration scan."""

    har_files: list[str] = field(default_factory=list)
    traffic_log_files: list[str] = field(default_factory=list)
    api_inventory_file: str | None = None
    compare_baseline: str | None = None
    save_baseline: str | None = None
    sources: list[str] = field(default_factory=list)


class EvidenceFinder:
    """Find target-relevant evidence without requiring CLI options."""

    INPUT_DIRS = (
        "evidence",
        "inputs",
        "traffic",
        "logs",
        "har",
        "inventory",
    )
    INVENTORY_WORDS = ("inventory", "catalog", "approved", "routes", "endpoints")
    TRAFFIC_WORDS = ("traffic", "access", "gateway", "proxy", "requests")
    INVENTORY_SUFFIXES = {".json", ".yaml", ".yml", ".csv"}
    TRAFFIC_SUFFIXES = {".json", ".jsonl", ".log", ".txt", ".csv"}
    GENERIC_STEMS = {
        "api_inventory",
        "approved_routes",
        "endpoint_catalog",
        "traffic",
        "access",
        "gateway",
        "proxy",
        "requests",
        "capture",
    }

    def __init__(
        self,
        config: ScanConfig,
        search_roots: list[Path] | None = None,
    ):
        self.config = config
        self.host = (urlparse(config.target_url).hostname or "target").lower()
        self.host_slug = self._slug(self.host)
        self.host_label = self.host.split(".", 1)[0]
        self.search_roots = search_roots or self._default_search_roots()

    def discover(self) -> AutoEvidence:
        """Return local evidence and automatic history paths for the target."""
        evidence = AutoEvidence()

        if self.config.auto_evidence:
            files = self._candidate_files()
            inventory_candidates: list[tuple[int, Path]] = []
            for path in files:
                score = self._relevance_score(path)
                if score <= 0:
                    continue

                name = path.name.lower()
                suffix = path.suffix.lower()
                if suffix == ".har":
                    evidence.har_files.append(str(path))
                    continue

                if (
                    suffix in self.INVENTORY_SUFFIXES
                    and any(word in name for word in self.INVENTORY_WORDS)
                ):
                    inventory_candidates.append((score, path))
                    continue

                if (
                    suffix in self.TRAFFIC_SUFFIXES
                    and any(word in name for word in self.TRAFFIC_WORDS)
                ):
                    evidence.traffic_log_files.append(str(path))

            evidence.har_files = sorted(set(evidence.har_files))
            evidence.traffic_log_files = sorted(set(evidence.traffic_log_files))
            if inventory_candidates:
                inventory_candidates.sort(
                    key=lambda item: (-item[0], str(item[1]))
                )
                evidence.api_inventory_file = str(inventory_candidates[0][1])

        if self.config.auto_history:
            history_path = (
                Path(self.config.output_dir)
                / "baselines"
                / f"{self.host_slug}.json"
            )
            evidence.save_baseline = str(history_path)
            if history_path.is_file():
                evidence.compare_baseline = str(history_path)

        evidence.sources.extend(f"har:{path}" for path in evidence.har_files)
        evidence.sources.extend(
            f"traffic_log:{path}" for path in evidence.traffic_log_files
        )
        if evidence.api_inventory_file:
            evidence.sources.append(
                f"api_inventory:{evidence.api_inventory_file}"
            )
        if evidence.compare_baseline:
            evidence.sources.append(
                f"history_baseline:{evidence.compare_baseline}"
            )
        return evidence

    def _default_search_roots(self) -> list[Path]:
        project_root = Path(__file__).resolve().parents[2]
        bases = [Path.cwd(), project_root]
        roots: list[Path] = []
        seen: set[Path] = set()
        for base in bases:
            for dirname in self.INPUT_DIRS:
                path = (base / dirname).resolve()
                if path in seen or not path.is_dir():
                    continue
                seen.add(path)
                roots.append(path)
        return roots

    def _candidate_files(self) -> list[Path]:
        files: list[Path] = []
        for root in self.search_roots:
            if not root.is_dir():
                continue
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in (
                    self.INVENTORY_SUFFIXES | self.TRAFFIC_SUFFIXES | {".har"}
                ):
                    files.append(path.resolve())
        return sorted(set(files))

    def _relevance_score(self, path: Path) -> int:
        """Prefer target-scoped evidence while allowing conventional names."""
        searchable = self._slug(str(path).lower())
        name = path.name.lower()
        score = 0
        if self.host_slug in searchable:
            score += 100
        if len(self.host_label) >= 6 and self.host_label in searchable:
            score += 80
        if path.stem.lower() in self.GENERIC_STEMS:
            score += 10
        return score

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "target"
