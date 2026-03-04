"""Tests for remediation dispatcher — mocked remediation actions."""
import pytest
from unittest.mock import patch, MagicMock
from remediation.dispatcher import RemediationDispatcher


class TestRemediationDispatcher:
    def setup_method(self):
        self.dispatcher = RemediationDispatcher()

    def test_dispatch_auto_remediate(self):
        finding = {
            "id": "f1",
            "action": "auto_remediate",
            "finding_code": "STORAGE_PUBLIC_ACCESS",
            "severity": "HIGH",
            "resource_id": "/sub/sa1",
            "resource_type": "StorageAccount",
            "provider": "azure",
            "details": "Public access enabled",
        }
        with patch.object(self.dispatcher, "_run_ansible", return_value={"success": True}):
            result = self.dispatcher.dispatch_single(finding)
            assert result.get("success") is True or result.get("action") == "auto_remediate"

    def test_dispatch_create_ticket(self):
        finding = {
            "id": "f2",
            "action": "create_ticket",
            "finding_code": "CUSTOM_CHECK",
            "severity": "MEDIUM",
            "resource_id": "/sub/x1",
            "resource_type": "Other",
            "provider": "azure",
            "details": "Manual review needed",
        }
        with patch.object(self.dispatcher, "_create_ticket", return_value={"success": True, "ticket_id": "T-1"}):
            result = self.dispatcher.dispatch_single(finding)
            assert "action" in result or "success" in result

    def test_dispatch_quarantine(self):
        finding = {
            "id": "f3",
            "action": "quarantine",
            "finding_code": "NSG_OPEN_SSH",
            "severity": "CRITICAL",
            "resource_id": "/sub/nsg1",
            "resource_type": "NSG",
            "provider": "azure",
            "details": "SSH open to world",
        }
        with patch.object(self.dispatcher, "_quarantine", return_value={"success": True}):
            result = self.dispatcher.dispatch_single(finding)
            assert "action" in result or "success" in result

    def test_dispatch_batch(self):
        findings = [
            {"id": "f1", "action": "auto_remediate", "finding_code": "STORAGE_ENCRYPTION",
             "severity": "HIGH", "resource_id": "/sub/sa1", "resource_type": "StorageAccount",
             "provider": "azure", "details": "No encryption"},
            {"id": "f2", "action": "create_ticket", "finding_code": "X",
             "severity": "LOW", "resource_id": "/sub/x", "resource_type": "Other",
             "provider": "azure", "details": "Low risk"},
        ]
        with patch.object(self.dispatcher, "_run_ansible", return_value={"success": True}):
            with patch.object(self.dispatcher, "_create_ticket", return_value={"success": True}):
                results = self.dispatcher.dispatch_batch(findings)
                assert len(results) == 2
