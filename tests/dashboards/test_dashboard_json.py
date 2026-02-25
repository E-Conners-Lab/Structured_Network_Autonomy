"""Tests for Grafana dashboard JSON files."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

DASHBOARDS_DIR = Path(__file__).parent.parent.parent / "dashboards"


def _load_dashboard_files() -> list[tuple[str, dict]]:
    """Load all JSON files from the dashboards directory."""
    results = []
    for json_file in sorted(DASHBOARDS_DIR.glob("*.json")):
        with open(json_file) as f:
            data = json.load(f)
        results.append((json_file.name, data))
    return results


def _get_known_metrics() -> set[str]:
    """Extract metric names from metrics.py."""
    metrics_file = (
        Path(__file__).parent.parent.parent / "src" / "sna" / "observability" / "metrics.py"
    )
    content = metrics_file.read_text()
    # Match Counter/Gauge/Histogram name arguments
    pattern = re.compile(r'(?:Counter|Gauge|Histogram)\(\s*"([^"]+)"')
    return set(pattern.findall(content))


class TestDashboardFiles:
    """Dashboard JSON validation tests."""

    @pytest.fixture
    def dashboard_files(self) -> list[tuple[str, dict]]:
        return _load_dashboard_files()

    def test_dashboard_files_valid_json(self) -> None:
        """All JSON files in dashboards/ should parse without error."""
        json_files = list(DASHBOARDS_DIR.glob("*.json"))
        assert len(json_files) >= 2, "Expected at least 2 dashboard files"

        for json_file in json_files:
            with open(json_file) as f:
                data = json.load(f)
            assert isinstance(data, dict), f"{json_file.name} is not a JSON object"

    def test_dashboard_has_required_fields(
        self, dashboard_files: list[tuple[str, dict]]
    ) -> None:
        """Each dashboard must have title, panels, and templating."""
        for name, data in dashboard_files:
            assert "title" in data, f"{name} missing 'title'"
            assert "panels" in data, f"{name} missing 'panels'"
            assert isinstance(data["panels"], list), f"{name} 'panels' is not a list"
            assert len(data["panels"]) > 0, f"{name} has no panels"
            assert "templating" in data, f"{name} missing 'templating'"

    def test_panel_targets_reference_valid_metrics(
        self, dashboard_files: list[tuple[str, dict]]
    ) -> None:
        """Panel queries should reference metrics that exist in metrics.py."""
        known_metrics = _get_known_metrics()
        assert len(known_metrics) > 0, "No metrics found in metrics.py"

        for name, data in dashboard_files:
            for panel in data.get("panels", []):
                for target in panel.get("targets", []):
                    expr = target.get("expr", "")
                    # Extract metric names from PromQL expressions
                    # Match metric_name at start of expression or after functions
                    metric_refs = re.findall(r"\b(sna_\w+)", expr)
                    for metric_ref in metric_refs:
                        # Try the exact name first; only strip Prometheus
                        # histogram suffixes (_bucket, _count, _sum) if the
                        # exact name isn't a known metric.
                        if metric_ref in known_metrics:
                            base_metric = metric_ref
                        else:
                            base_metric = re.sub(
                                r"_(bucket|count|sum)$", "", metric_ref
                            )
                        assert base_metric in known_metrics, (
                            f"{name}: panel '{panel.get('title')}' references "
                            f"unknown metric '{base_metric}' in expr '{expr}'. "
                            f"Known metrics: {sorted(known_metrics)}"
                        )

    def test_panels_have_titles(
        self, dashboard_files: list[tuple[str, dict]]
    ) -> None:
        """Every panel should have a title."""
        for name, data in dashboard_files:
            for i, panel in enumerate(data.get("panels", [])):
                assert "title" in panel, (
                    f"{name}: panel {i} missing 'title'"
                )
                assert panel["title"], f"{name}: panel {i} has empty title"

    def test_dashboard_uids_unique(
        self, dashboard_files: list[tuple[str, dict]]
    ) -> None:
        """Dashboard UIDs should be unique."""
        uids = [data.get("uid") for _, data in dashboard_files]
        assert len(uids) == len(set(uids)), f"Duplicate UIDs: {uids}"
