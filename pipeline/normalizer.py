"""
Normalizer: converts scanner outputs to a canonical JSON schema.

Canonical schema:
{
    "id": str (uuid),
    "provider": str ("azure", "aws", "openstack"),
    "resource_type": str,
    "resource_id": str,
    "finding_code": str (rule_id),
    "severity": str ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
    "details": str,
    "region": str,
    "timestamp": str (ISO 8601),
    "scanner": str ("custom", "scoutsuite", "cloudsploit", "checkov", "tfsec", "trivy"),
    "title": str,
    "evidence": dict,
    "remediation": list[str],
    "cis_controls": list[str],
    "asset_owner": str,
    "environment": str ("prod", "staging", "dev"),
    "iac_file_path": str | None
}
"""
import uuid
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ---------- CIS control mapping ----------
CIS_MAPPING = {
    "AZ-Storage-PublicBlob-001": ["CIS 3.7", "CIS 3.8"],
    "AZ-Storage-Encryption-001": ["CIS 3.2"],
    "AZ-NSG-OPEN-001": ["CIS 6.1", "CIS 6.2"],
    "AZ-VM-PUBIP-001": ["CIS 6.3"],
    "AZ-FunctionApp-Anonymous-001": ["CIS 9.1"],
    "AZST001": ["CIS 3.7"],
    "AZST002": ["CIS 3.6"],
    "AZKV001": ["CIS 8.4"],
    "AZKV002": ["CIS 8.4"],
    "AZKV003": ["CIS 8.5"],
    "AZAS001": ["CIS 9.3"],
    "AZAS002": ["CIS 9.3"],
    "AZ-VM-IPFWD-001": ["CIS 6.4"],
    "AZ-VM-MULTIPIP-001": ["CIS 6.3"],
    "AZ-VM-BOOTDIAG-001": ["CIS 7.5"],
    "AZ-RES-TAGS-001": ["CIS 1.3"],
}

# ---------- Severity normalization ----------
SEVERITY_MAP = {
    # Generic
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "LOW",
    "informational": "LOW",
    "warning": "MEDIUM",
    # ScoutSuite
    "danger": "HIGH",
    "warning": "MEDIUM",
    # Checkov
    "failed": "HIGH",
    "passed": "LOW",
    # Trivy
    "unknown": "LOW",
}


def normalize_severity(raw: str) -> str:
    """Map any vendor severity to unified CRITICAL/HIGH/MEDIUM/LOW."""
    if not raw:
        return "LOW"
    return SEVERITY_MAP.get(raw.strip().lower(), raw.upper())


def _safe_str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    return json.dumps(val, ensure_ascii=False)


def normalize_finding(
    finding: Dict[str, Any],
    scanner: str = "custom",
    provider: str = "azure",
    environment: str = "dev",
    asset_owner: str = "",
) -> Dict[str, Any]:
    """Convert a raw finding dict from any scanner to canonical schema."""
    rule_id = finding.get("rule_id") or finding.get("finding_code") or finding.get("id") or ""
    resource_id = finding.get("resource_id") or finding.get("resourceId") or ""
    resource_type = finding.get("service") or finding.get("resource_type") or ""

    severity_raw = finding.get("severity") or ""
    severity = normalize_severity(severity_raw)

    evidence = finding.get("evidence") or {}
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            evidence = {"raw": evidence}

    remediation = finding.get("remediation") or []
    if isinstance(remediation, str):
        remediation = [remediation]

    cis = CIS_MAPPING.get(rule_id, [])

    return {
        "id": str(uuid.uuid4()),
        "provider": provider,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "finding_code": rule_id,
        "severity": severity,
        "details": finding.get("title") or finding.get("description") or "",
        "region": finding.get("region") or finding.get("location") or "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scanner": scanner,
        "title": finding.get("title") or "",
        "evidence": evidence,
        "remediation": remediation,
        "cis_controls": cis,
        "asset_owner": asset_owner,
        "environment": environment,
        "iac_file_path": finding.get("iac_file_path") or finding.get("file_path"),
    }


def normalize_batch(
    findings: List[Dict[str, Any]],
    scanner: str = "custom",
    provider: str = "azure",
    environment: str = "dev",
    asset_owner: str = "",
) -> List[Dict[str, Any]]:
    """Normalize a list of findings."""
    return [
        normalize_finding(f, scanner=scanner, provider=provider,
                          environment=environment, asset_owner=asset_owner)
        for f in findings
    ]


# ---- ScoutSuite output parser ----
def parse_scoutsuite(report_path: str, provider: str = "azure") -> List[Dict[str, Any]]:
    """Parse ScoutSuite JSON report into raw findings list."""
    findings = []
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception:
        return []

    services = report.get("services", {})
    for svc_name, svc_data in services.items():
        for finding_key, finding_data in svc_data.get("findings", {}).items():
            flagged = finding_data.get("flagged_items", 0)
            if flagged > 0:
                for item in finding_data.get("items", []):
                    findings.append({
                        "rule_id": f"SS-{svc_name}-{finding_key}",
                        "service": svc_name,
                        "title": finding_data.get("description", finding_key),
                        "severity": finding_data.get("level", "warning"),
                        "resource_id": item,
                        "evidence": {
                            "flagged_items": flagged,
                            "checked_items": finding_data.get("checked_items", 0),
                        },
                        "remediation": [finding_data.get("remediation", "Review ScoutSuite documentation.")],
                    })
    return normalize_batch(findings, scanner="scoutsuite", provider=provider)


# ---- CloudSploit output parser ----
def parse_cloudsploit(report_path: str, provider: str = "azure") -> List[Dict[str, Any]]:
    """Parse CloudSploit JSON output."""
    findings = []
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    for item in data if isinstance(data, list) else []:
        status = (item.get("status") or "").upper()
        if status in ("FAIL", "WARN"):
            findings.append({
                "rule_id": f"CS-{item.get('plugin', 'unknown')}",
                "service": item.get("category", ""),
                "title": item.get("message", ""),
                "severity": "HIGH" if status == "FAIL" else "MEDIUM",
                "resource_id": item.get("resource", ""),
                "region": item.get("region", ""),
                "evidence": {"status": status, "plugin": item.get("plugin")},
                "remediation": [item.get("remediation", "See CloudSploit docs.")],
            })
    return normalize_batch(findings, scanner="cloudsploit", provider=provider)


# ---- Checkov output parser ----
def parse_checkov(report_path: str) -> List[Dict[str, Any]]:
    """Parse Checkov JSON output (IaC findings)."""
    findings = []
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    checks = []
    if isinstance(data, list):
        for entry in data:
            checks.extend(entry.get("results", {}).get("failed_checks", []))
    elif isinstance(data, dict):
        checks = data.get("results", {}).get("failed_checks", [])

    for chk in checks:
        findings.append({
            "rule_id": chk.get("check_id", ""),
            "service": chk.get("check_type", "IaC"),
            "title": chk.get("check_result", {}).get("name", chk.get("name", "")),
            "severity": chk.get("severity", "HIGH"),
            "resource_id": chk.get("resource", ""),
            "iac_file_path": chk.get("file_path", ""),
            "evidence": {
                "file_path": chk.get("file_path"),
                "file_line_range": chk.get("file_line_range"),
                "guideline": chk.get("guideline", ""),
            },
            "remediation": [chk.get("guideline", "Fix the IaC resource.")],
        })
    return normalize_batch(findings, scanner="checkov", provider="iac")


# ---- tfsec output parser ----
def parse_tfsec(report_path: str) -> List[Dict[str, Any]]:
    """Parse tfsec JSON output."""
    findings = []
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    for result in data.get("results", []) if isinstance(data, dict) else []:
        findings.append({
            "rule_id": result.get("rule_id") or result.get("long_id", ""),
            "service": result.get("rule_provider", "terraform"),
            "title": result.get("rule_description", ""),
            "severity": result.get("severity", "HIGH"),
            "resource_id": result.get("resource", ""),
            "iac_file_path": result.get("location", {}).get("filename", ""),
            "evidence": {
                "filename": result.get("location", {}).get("filename"),
                "start_line": result.get("location", {}).get("start_line"),
                "end_line": result.get("location", {}).get("end_line"),
            },
            "remediation": [result.get("resolution", "Review tfsec documentation.")],
        })
    return normalize_batch(findings, scanner="tfsec", provider="iac")


# ---- Trivy output parser ----
def parse_trivy(report_path: str) -> List[Dict[str, Any]]:
    """Parse Trivy JSON output (container/image scanning)."""
    findings = []
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    for result in data.get("Results", []) if isinstance(data, dict) else []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "rule_id": vuln.get("VulnerabilityID", ""),
                "service": "container",
                "title": vuln.get("Title", vuln.get("VulnerabilityID", "")),
                "severity": vuln.get("Severity", "MEDIUM"),
                "resource_id": target,
                "evidence": {
                    "pkg_name": vuln.get("PkgName"),
                    "installed_version": vuln.get("InstalledVersion"),
                    "fixed_version": vuln.get("FixedVersion"),
                },
                "remediation": [f"Update {vuln.get('PkgName', '')} to {vuln.get('FixedVersion', 'latest')}"],
            })
        for misconfig in result.get("Misconfigurations", []) or []:
            findings.append({
                "rule_id": misconfig.get("ID", ""),
                "service": misconfig.get("Type", "config"),
                "title": misconfig.get("Title", ""),
                "severity": misconfig.get("Severity", "MEDIUM"),
                "resource_id": target,
                "evidence": {"message": misconfig.get("Message", "")},
                "remediation": [misconfig.get("Resolution", "See Trivy docs.")],
            })
    return normalize_batch(findings, scanner="trivy", provider="container")
