"""Tests for pipeline.normalizer — canonical finding normalization."""
import pytest
from pipeline.normalizer import (
    normalize_finding,
    normalize_batch,
    parse_checkov,
    parse_tfsec,
    parse_trivy,
)


# ---------- normalize_finding ----------
class TestNormalizeFinding:
    def test_minimal_finding(self):
        raw = {
            "provider": "azure",
            "resource_type": "StorageAccount",
            "resource_id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1",
            "finding_code": "STORAGE_PUBLIC_ACCESS",
            "severity": "HIGH",
            "details": "Public access enabled",
        }
        result = normalize_finding(raw)
        assert result["provider"] == "azure"
        assert result["severity"] == "HIGH"
        assert result["finding_code"] == "STORAGE_PUBLIC_ACCESS"
        assert "id" in result
        assert "timestamp" in result

    def test_severity_normalization(self):
        raw = {
            "provider": "azure",
            "resource_type": "VM",
            "resource_id": "/sub/vm1",
            "finding_code": "VM_PUBLIC_IP",
            "severity": "warning",
            "details": "test",
        }
        result = normalize_finding(raw)
        assert result["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_cis_mapping_applied(self):
        raw = {
            "provider": "azure",
            "resource_type": "StorageAccount",
            "resource_id": "/sub/sa1",
            "finding_code": "STORAGE_ENCRYPTION",
            "severity": "HIGH",
            "details": "No encryption",
        }
        result = normalize_finding(raw)
        assert isinstance(result.get("cis_controls"), list)


class TestNormalizeBatch:
    def test_batch_produces_list(self):
        raw_list = [
            {"provider": "azure", "resource_type": "NSG", "resource_id": "/sub/nsg1",
             "finding_code": "NSG_OPEN_SSH", "severity": "HIGH", "details": "SSH open"},
            {"provider": "azure", "resource_type": "NSG", "resource_id": "/sub/nsg2",
             "finding_code": "NSG_OPEN_RDP", "severity": "CRITICAL", "details": "RDP open"},
        ]
        results = normalize_batch(raw_list)
        assert len(results) == 2
        assert all("id" in r for r in results)


# ---------- parse_checkov ----------
class TestParseCheckov:
    def test_parse_checkov_results(self):
        mock_output = {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AZURE_35",
                        "check_result": {"result": "FAILED"},
                        "resource": "azurerm_storage_account.example",
                        "file_path": "/main.tf",
                        "guideline": "Enable encryption",
                    }
                ]
            }
        }
        findings = parse_checkov(mock_output)
        assert len(findings) >= 1
        assert findings[0]["scanner"] == "checkov"

    def test_empty_checkov(self):
        findings = parse_checkov({"results": {"failed_checks": []}})
        assert findings == []


# ---------- parse_tfsec ----------
class TestParseTfsec:
    def test_parse_tfsec_results(self):
        mock_output = {
            "results": [
                {
                    "rule_id": "azure-storage-no-public-access",
                    "severity": "HIGH",
                    "description": "Storage has public access",
                    "location": {"filename": "main.tf", "start_line": 10},
                    "resource": "azurerm_storage_account.example",
                }
            ]
        }
        findings = parse_tfsec(mock_output)
        assert len(findings) == 1
        assert findings[0]["scanner"] == "tfsec"

    def test_empty_tfsec(self):
        findings = parse_tfsec({"results": []})
        assert findings == []


# ---------- parse_trivy ----------
class TestParseTrivy:
    def test_parse_trivy_results(self):
        mock_output = {
            "Results": [
                {
                    "Target": "main.tf",
                    "Misconfigurations": [
                        {
                            "ID": "AVD-AZU-0001",
                            "Title": "Storage public access",
                            "Severity": "HIGH",
                            "Description": "Public access is enabled",
                            "Resolution": "Disable public access",
                        }
                    ],
                }
            ]
        }
        findings = parse_trivy(mock_output)
        assert len(findings) == 1
        assert findings[0]["scanner"] == "trivy"

    def test_empty_trivy(self):
        findings = parse_trivy({"Results": []})
        assert findings == []
