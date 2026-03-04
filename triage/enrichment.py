"""
Enrichment: adds contextual metadata to findings before triage.

Enrichments:
  - CIS control mapping
  - Asset owner (from CMDB or tag)
  - Environment (prod/staging/dev)
  - Exposure score
  - Resource sensitivity
"""
from typing import Any, Dict

from pipeline.normalizer import CIS_MAPPING

# ---- Sensitivity classification ----
SENSITIVE_RESOURCE_PATTERNS = [
    "database", "sql", "cosmos", "keyvault", "key-vault",
    "secret", "certificate", "identity", "ad", "iam",
]

# ---- Asset owner simulation (would come from CMDB in prod) ----
_MOCK_OWNERS = {
    "rg-production": "security-team@company.com",
    "rg-staging": "devops-team@company.com",
    "rg-dev": "dev-team@company.com",
}


def _guess_environment(finding: Dict[str, Any]) -> str:
    """Infer environment from resource ID / tags / explicit field."""
    if finding.get("environment"):
        return finding["environment"]
    rid = (finding.get("resource_id") or "").lower()
    if "prod" in rid:
        return "prod"
    if "staging" in rid or "stag" in rid:
        return "staging"
    return "dev"


def _guess_owner(finding: Dict[str, Any]) -> str:
    """Lookup asset owner from resource group or tags."""
    if finding.get("asset_owner"):
        return finding["asset_owner"]
    rid = (finding.get("resource_id") or "").lower()
    for rg_pattern, owner in _MOCK_OWNERS.items():
        if rg_pattern in rid:
            return owner
    return ""


def _is_sensitive(finding: Dict[str, Any]) -> bool:
    """Check if the resource is considered sensitive."""
    rtype = (finding.get("resource_type") or "").lower()
    rid = (finding.get("resource_id") or "").lower()
    combined = f"{rtype} {rid}"
    return any(p in combined for p in SENSITIVE_RESOURCE_PATTERNS)


def _exposure_score(finding: Dict[str, Any]) -> int:
    """
    Compute an exposure score (0-100) based on:
    - severity
    - environment
    - sensitivity
    - whether it's public-facing
    """
    score = 0
    sev = (finding.get("severity") or "LOW").upper()
    if sev == "CRITICAL":
        score += 40
    elif sev == "HIGH":
        score += 30
    elif sev == "MEDIUM":
        score += 20
    else:
        score += 10

    env = _guess_environment(finding)
    if env == "prod":
        score += 30
    elif env == "staging":
        score += 15

    if _is_sensitive(finding):
        score += 20

    # Check for public-facing indicators
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict):
        for key, val in evidence.items():
            val_str = str(val).lower()
            if any(x in val_str for x in ["0.0.0.0", "public", "*", "internet", "true"]):
                score += 10
                break

    return min(score, 100)


def enrich_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Add enrichment metadata to a finding."""
    # CIS controls
    code = finding.get("finding_code", "")
    if not finding.get("cis_controls"):
        finding["cis_controls"] = CIS_MAPPING.get(code, [])

    # Environment
    finding["environment"] = _guess_environment(finding)

    # Asset owner
    finding["asset_owner"] = _guess_owner(finding)

    # Sensitivity
    finding["is_sensitive"] = _is_sensitive(finding)

    # Exposure score
    finding["exposure_score"] = _exposure_score(finding)

    return finding
