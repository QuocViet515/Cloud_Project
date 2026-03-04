"""Tests for pipeline metrics computation."""
import pytest
from datetime import datetime, timezone, timedelta
from pipeline.metrics import MetricsCollector


class TestMetricsCollector:
    def setup_method(self):
        self.collector = MetricsCollector()

    def test_detection_coverage(self):
        findings = [
            {"cis_controls": ["CIS 3.2", "CIS 3.7"], "severity": "HIGH"},
            {"cis_controls": ["CIS 6.1"], "severity": "CRITICAL"},
        ]
        result = self.collector.detection_coverage(findings)
        assert result["covered_checks"] == 3
        assert result["coverage_percent"] > 0
        assert "CIS 3.2" in result["covered"]

    def test_remediation_rate(self):
        results = [
            {"action": "auto_remediate", "success": True},
            {"action": "auto_remediate", "success": False},
            {"action": "create_ticket", "success": True},
        ]
        rate = self.collector.remediation_rate(results)
        assert rate["auto_attempted"] == 2
        assert rate["auto_success"] == 1
        assert rate["rate_percent"] > 0

    def test_mttr(self):
        start = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = start + timedelta(minutes=5)
        mttr = self.collector.mttr(start, end)
        assert mttr == 300.0

    def test_false_positive_rate(self):
        findings = [
            {"action": "ignore", "severity": "LOW"},
            {"action": "auto_remediate", "severity": "HIGH"},
        ]
        results = [
            {"details": "rollback applied"},
            {"details": "success"},
        ]
        fp = self.collector.false_positive_rate(findings, results)
        assert fp["ignored"] == 1
        assert fp["reverted"] == 1
        assert fp["false_positives"] == 2

    def test_compliance_score(self):
        findings = [
            {"severity": "HIGH", "cis_controls": ["CIS 3.2"]},
            {"severity": "LOW", "cis_controls": ["CIS 9.1"]},
        ]
        score = self.collector.compliance_score(findings)
        assert score["failing"] >= 1
        assert score["score_percent"] < 100

    def test_severity_breakdown(self):
        findings = [
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "LOW"},
        ]
        breakdown = self.collector.severity_breakdown(findings)
        assert breakdown["HIGH"] == 2
        assert breakdown["LOW"] == 1

    def test_compute_all(self):
        findings = [
            {"id": "f1", "cis_controls": ["CIS 3.2"], "severity": "HIGH",
             "scanner": "checkov", "action": "auto_remediate"},
        ]
        results = [
            {"action": "auto_remediate", "success": True, "details": "ok"},
        ]
        start = datetime.now(timezone.utc) - timedelta(seconds=60)
        end = datetime.now(timezone.utc)
        metrics = self.collector.compute_all(findings, results, start, end)
        assert "detection_coverage" in metrics
        assert "remediation_rate" in metrics
        assert "compliance_score" in metrics
        assert metrics["total_findings"] == 1
