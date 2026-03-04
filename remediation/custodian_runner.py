"""
Cloud Custodian Remediator: runs c7n policies for auto-remediation.

Uses custodian CLI (`custodian run`) with pre-defined policy YAML files.
"""
import subprocess
import os
import logging
import json
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Map finding codes to custodian policy files
CUSTODIAN_POLICY_MAP = {
    "AZ-Storage-PublicBlob-001": "storage-block-public-access.yml",
    "AZST001": "storage-block-public-access.yml",
    "AZST002": "storage-deny-network-acl.yml",
    "AZ-NSG-OPEN-001": "nsg-restrict-open-ports.yml",
    "AZ-Storage-Encryption-001": "storage-enable-encryption.yml",
}

POLICIES_DIR = os.path.join(os.path.dirname(__file__), "..", "custodian", "policies")


class CustodianRemediator:
    """Execute Cloud Custodian policies for auto-remediation."""

    def __init__(self, policies_dir: str = None):
        self.policies_dir = policies_dir or POLICIES_DIR

    def has_policy(self, finding_code: str) -> bool:
        """Check if a custodian policy exists for the finding."""
        policy_name = CUSTODIAN_POLICY_MAP.get(finding_code)
        if not policy_name:
            return False
        return os.path.exists(os.path.join(self.policies_dir, policy_name))

    def remediate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Run the custodian policy for the given finding."""
        finding_code = finding.get("finding_code", "")
        policy_name = CUSTODIAN_POLICY_MAP.get(finding_code)

        if not policy_name:
            return {
                "action": "auto_remediate",
                "success": False,
                "details": f"No Custodian policy for {finding_code}",
            }

        policy_path = os.path.join(self.policies_dir, policy_name)
        if not os.path.exists(policy_path):
            return {
                "action": "auto_remediate",
                "success": False,
                "details": f"Custodian policy file not found: {policy_path}",
            }

        output_dir = os.path.join(self.policies_dir, "..", "output", finding_code)
        os.makedirs(output_dir, exist_ok=True)

        cmd = [
            "custodian", "run",
            "--output-dir", output_dir,
            policy_path,
        ]

        logger.info(f"Running Custodian: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                return {
                    "action": "auto_remediate",
                    "success": True,
                    "details": f"Custodian policy {policy_name} applied",
                    "output": result.stdout[-500:] if result.stdout else "",
                }
            else:
                return {
                    "action": "auto_remediate",
                    "success": False,
                    "details": f"Custodian failed (rc={result.returncode}): {result.stderr[-500:]}",
                }
        except FileNotFoundError:
            logger.error("custodian CLI not found. Install: pip install c7n")
            return {
                "action": "auto_remediate",
                "success": False,
                "details": "custodian not installed",
            }
        except subprocess.TimeoutExpired:
            return {
                "action": "auto_remediate",
                "success": False,
                "details": "Custodian policy timed out",
            }
