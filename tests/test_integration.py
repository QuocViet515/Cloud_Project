"""Integration test — end-to-end pipeline with mocked external services."""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone


class TestPipelineIntegration:
    """Tests the full scan → normalize → dedup → triage → dispatch flow."""

    def _make_raw_findings(self):
        """Simulated scanner output."""
        return [
            {
                "provider": "azure",
                "resource_type": "StorageAccount",
                "resource_id": "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
                "finding_code": "STORAGE_PUBLIC_ACCESS",
                "severity": "HIGH",
                "details": "Container public access enabled",
                "scanner": "checkov",
                "region": "eastus",
            },
            {
                "provider": "azure",
                "resource_type": "StorageAccount",
                "resource_id": "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
                "finding_code": "STORAGE_PUBLIC_ACCESS",
                "severity": "MEDIUM",
                "details": "Blob public access",
                "scanner": "tfsec",
                "region": "eastus",
            },
            {
                "provider": "azure",
                "resource_type": "NSG",
                "resource_id": "/subscriptions/abc/resourceGroups/rg1/providers/Microsoft.Network/networkSecurityGroups/nsg1",
                "finding_code": "NSG_OPEN_SSH",
                "severity": "CRITICAL",
                "details": "SSH open to 0.0.0.0/0",
                "scanner": "checkov",
                "region": "westus",
            },
        ]

    def test_normalize_and_dedup(self):
        from pipeline.normalizer import normalize_batch
        from pipeline.deduplicator import deduplicate

        raw = self._make_raw_findings()
        normalized = normalize_batch(raw)
        assert len(normalized) == 3

        deduped = deduplicate(normalized)
        # Two STORAGE_PUBLIC_ACCESS for same resource should merge → expect 2 unique
        assert len(deduped) == 2

    def test_triage_all_findings(self):
        from pipeline.normalizer import normalize_batch
        from pipeline.deduplicator import deduplicate
        from triage.engine import TriageEngine

        raw = self._make_raw_findings()
        normalized = normalize_batch(raw)
        deduped = deduplicate(normalized)

        engine = TriageEngine()
        triaged = engine.triage_batch(deduped)
        assert len(triaged) == 2
        assert all("action" in t for t in triaged)

    def test_metrics_on_results(self):
        from pipeline.normalizer import normalize_batch
        from pipeline.deduplicator import deduplicate
        from triage.engine import TriageEngine
        from pipeline.metrics import MetricsCollector

        raw = self._make_raw_findings()
        normalized = normalize_batch(raw)
        deduped = deduplicate(normalized)

        engine = TriageEngine()
        triaged = engine.triage_batch(deduped)

        # Simulate remediation results
        results = [
            {"action": t["action"], "success": True, "details": "simulated"} for t in triaged
        ]

        collector = MetricsCollector()
        start = datetime.now(timezone.utc)
        end = datetime.now(timezone.utc)
        metrics = collector.compute_all(deduped, results, start, end)

        assert metrics["total_findings"] == 2
        assert "detection_coverage" in metrics
        assert "compliance_score" in metrics
