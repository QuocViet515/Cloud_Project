"""Tests for triage.engine and triage.rules — decision logic."""
import pytest
from unittest.mock import patch, MagicMock
from triage.engine import TriageEngine
from triage.rules import StaticTriageRules


# ---------- StaticTriageRules ----------
class TestStaticTriageRules:
    def setup_method(self):
        self.rules = StaticTriageRules()

    def test_critical_production_quarantine(self):
        finding = {
            "severity": "CRITICAL",
            "environment": "production",
            "resource_type": "StorageAccount",
            "finding_code": "STORAGE_PUBLIC_ACCESS",
        }
        action = self.rules.evaluate(finding)
        assert action in ("quarantine", "auto_remediate", "create_ticket")

    def test_low_severity_ticket(self):
        finding = {
            "severity": "LOW",
            "environment": "development",
            "resource_type": "VM",
            "finding_code": "VM_BOOT_DIAGNOSTICS",
        }
        action = self.rules.evaluate(finding)
        assert action in ("create_ticket", "ignore", "auto_remediate")

    def test_high_dev_auto_remediate(self):
        finding = {
            "severity": "HIGH",
            "environment": "development",
            "resource_type": "StorageAccount",
            "finding_code": "STORAGE_ENCRYPTION",
        }
        action = self.rules.evaluate(finding)
        assert action in ("auto_remediate", "create_pr", "create_ticket")


# ---------- TriageEngine ----------
class TestTriageEngine:
    def setup_method(self):
        self.engine = TriageEngine()

    def test_triage_single_returns_action(self):
        finding = {
            "id": "f1",
            "severity": "HIGH",
            "environment": "production",
            "resource_type": "StorageAccount",
            "finding_code": "STORAGE_PUBLIC_ACCESS",
            "cis_controls": ["CIS 3.7"],
        }
        result = self.engine.triage_single(finding)
        assert "action" in result
        assert result["action"] in (
            "auto_remediate", "create_pr", "create_ticket", "quarantine", "ignore"
        )

    def test_triage_batch(self):
        findings = [
            {"id": "f1", "severity": "HIGH", "environment": "prod",
             "resource_type": "NSG", "finding_code": "NSG_OPEN_SSH", "cis_controls": []},
            {"id": "f2", "severity": "LOW", "environment": "dev",
             "resource_type": "VM", "finding_code": "VM_BOOT_DIAGNOSTICS", "cis_controls": []},
        ]
        results = self.engine.triage_batch(findings)
        assert len(results) == 2
        assert all("action" in r for r in results)

    def test_suppressed_finding_ignored(self):
        engine = TriageEngine(suppression_list=["STORAGE_PUBLIC_ACCESS"])
        finding = {
            "id": "f1",
            "severity": "CRITICAL",
            "environment": "production",
            "resource_type": "StorageAccount",
            "finding_code": "STORAGE_PUBLIC_ACCESS",
            "cis_controls": [],
        }
        result = engine.triage_single(finding)
        assert result["action"] == "ignore"
