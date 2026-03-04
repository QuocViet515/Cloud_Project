"""Tests for pipeline.deduplicator — cross-scanner deduplication."""
import pytest
from pipeline.deduplicator import deduplicate


class TestDeduplicate:
    def test_removes_exact_duplicates(self):
        findings = [
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "STORAGE_PUBLIC_ACCESS",
             "severity": "HIGH", "scanner": "checkov", "id": "f1"},
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "STORAGE_PUBLIC_ACCESS",
             "severity": "HIGH", "scanner": "tfsec", "id": "f2"},
        ]
        result = deduplicate(findings)
        assert len(result) == 1

    def test_keeps_highest_severity(self):
        findings = [
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "STORAGE_PUBLIC_ACCESS",
             "severity": "MEDIUM", "scanner": "checkov", "id": "f1"},
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "STORAGE_PUBLIC_ACCESS",
             "severity": "HIGH", "scanner": "tfsec", "id": "f2"},
        ]
        result = deduplicate(findings)
        assert len(result) == 1
        assert result[0]["severity"] == "HIGH"

    def test_different_resources_not_deduped(self):
        findings = [
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "STORAGE_PUBLIC_ACCESS",
             "severity": "HIGH", "scanner": "checkov", "id": "f1"},
            {"provider": "azure", "resource_id": "/sub/sa2", "finding_code": "STORAGE_PUBLIC_ACCESS",
             "severity": "HIGH", "scanner": "checkov", "id": "f2"},
        ]
        result = deduplicate(findings)
        assert len(result) == 2

    def test_different_finding_codes_not_deduped(self):
        findings = [
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "STORAGE_PUBLIC_ACCESS",
             "severity": "HIGH", "scanner": "checkov", "id": "f1"},
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "STORAGE_ENCRYPTION",
             "severity": "HIGH", "scanner": "checkov", "id": "f2"},
        ]
        result = deduplicate(findings)
        assert len(result) == 2

    def test_merges_scanner_names(self):
        findings = [
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "STORAGE_PUBLIC_ACCESS",
             "severity": "HIGH", "scanner": "checkov", "id": "f1"},
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "STORAGE_PUBLIC_ACCESS",
             "severity": "HIGH", "scanner": "tfsec", "id": "f2"},
        ]
        result = deduplicate(findings)
        scanner_field = result[0].get("scanner", "")
        # Should contain both scanner names
        assert "checkov" in scanner_field or "tfsec" in scanner_field

    def test_empty_input(self):
        assert deduplicate([]) == []

    def test_single_finding(self):
        findings = [
            {"provider": "azure", "resource_id": "/sub/sa1", "finding_code": "X",
             "severity": "LOW", "scanner": "s", "id": "f1"},
        ]
        result = deduplicate(findings)
        assert len(result) == 1
