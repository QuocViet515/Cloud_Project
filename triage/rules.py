"""
Static triage rules: determines action based on severity, environment,
resource type, and scanner source.

Policy:
  - LOW severity in non-prod → auto_remediate
  - MEDIUM severity in non-prod → auto_remediate
  - MEDIUM severity in prod → create_ticket
  - HIGH severity → create_ticket (needs approval)
  - CRITICAL severity → quarantine + create_ticket
  - IaC findings (scanner=checkov/tfsec) → create_pr
  - Container findings (scanner=trivy) → create_ticket
"""
from typing import Any, Dict, Tuple


# Rule IDs that are safe for auto-remediation
AUTO_REMEDIATE_SAFE = {
    "AZ-RES-TAGS-001",       # Missing tags (low risk)
    "AZ-Storage-PublicBlob-001",  # Block public access
    "AZST001",                # Block public access (alt scanner)
    "AZ-Storage-Encryption-001",  # Enable encryption
    "AZ-VM-BOOTDIAG-001",    # Enable boot diagnostics
}

# Rule IDs that always require human review
ALWAYS_MANUAL = {
    "AZKV003",   # Overly-broad Key Vault access
    "AZ-VM-MULTIPIP-001",  # Multiple public IPs - needs review
}


class StaticTriageRules:
    """Evaluate findings using static decision rules."""

    def evaluate(self, finding: Dict[str, Any]) -> Tuple[str, str]:
        """
        Returns (action, reason) tuple.
        """
        severity = (finding.get("severity") or "LOW").upper()
        environment = (finding.get("environment") or "dev").lower()
        scanner = (finding.get("scanner") or "custom").lower()
        finding_code = finding.get("finding_code", "")
        is_prod = environment in ("prod", "production")

        # IaC findings → create PR
        if scanner in ("checkov", "tfsec"):
            return "create_pr", f"IaC finding from {scanner} — generate fix PR"

        # Container findings → ticket
        if scanner == "trivy":
            return "create_ticket", "Container/image finding — manual review"

        # Always-manual rules
        if finding_code in ALWAYS_MANUAL:
            return "create_ticket", f"Rule {finding_code} requires human review"

        # CRITICAL → quarantine
        if severity == "CRITICAL":
            return "quarantine", "CRITICAL severity — quarantine and create ticket"

        # HIGH in prod → ticket
        if severity == "HIGH" and is_prod:
            return "create_ticket", "HIGH severity in production — requires approval"

        # HIGH in non-prod with safe rule → auto
        if severity == "HIGH" and not is_prod and finding_code in AUTO_REMEDIATE_SAFE:
            return "auto_remediate", f"HIGH in non-prod, safe rule {finding_code}"

        # HIGH in non-prod general → ticket
        if severity == "HIGH" and not is_prod:
            return "create_ticket", "HIGH severity — needs review even in non-prod"

        # MEDIUM in prod → ticket
        if severity == "MEDIUM" and is_prod:
            return "create_ticket", "MEDIUM severity in production — create ticket"

        # MEDIUM/LOW in non-prod → auto
        if severity in ("MEDIUM", "LOW") and not is_prod:
            return "auto_remediate", f"{severity} in {environment} — safe to auto-fix"

        # LOW in prod → auto (if safe rule)
        if severity == "LOW" and is_prod and finding_code in AUTO_REMEDIATE_SAFE:
            return "auto_remediate", f"LOW in prod, safe rule {finding_code}"

        # Default: create ticket
        return "create_ticket", "Default policy — manual review"
