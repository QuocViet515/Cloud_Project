"""
Ansible Remediator: runs Ansible playbooks to fix runtime misconfigurations.

Maps finding_code → playbook path, then executes via ansible-runner or subprocess.
"""
import subprocess
import os
import json
import logging
from typing import Any, Dict

from remediation.rollback import RollbackManager

logger = logging.getLogger(__name__)

# Mapping from finding codes to Ansible playbook names
PLAYBOOK_MAP = {
    "AZ-Storage-PublicBlob-001": "remediate_storage_public_access.yml",
    "AZST001": "remediate_storage_public_access.yml",
    "AZST002": "remediate_storage_network_acl.yml",
    "AZ-Storage-Encryption-001": "remediate_storage_encryption.yml",
    "AZ-NSG-OPEN-001": "remediate_nsg_open_rules.yml",
    "AZ-VM-PUBIP-001": "remediate_vm_public_ip.yml",
    "AZ-VM-IPFWD-001": "remediate_vm_ip_forwarding.yml",
    "AZ-VM-BOOTDIAG-001": "remediate_vm_boot_diagnostics.yml",
    "AZKV001": "remediate_keyvault_softdelete.yml",
    "AZKV002": "remediate_keyvault_purge_protection.yml",
    "AZ-FunctionApp-Anonymous-001": "remediate_functionapp_auth.yml",
    "AZ-RES-TAGS-001": "remediate_resource_tags.yml",
}

PLAYBOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "ansible", "playbooks")


class AnsibleRemediator:
    """Execute Ansible playbooks for auto-remediation."""

    def __init__(self, playbooks_dir: str = None, inventory: str = None):
        self.playbooks_dir = playbooks_dir or PLAYBOOKS_DIR
        self.inventory = inventory or os.path.join(
            os.path.dirname(__file__), "..", "ansible", "inventory.yml"
        )
        self.rollback = RollbackManager()

    def has_playbook(self, finding_code: str) -> bool:
        """Check if a playbook exists for this finding code."""
        pb_name = PLAYBOOK_MAP.get(finding_code)
        if not pb_name:
            return False
        return os.path.exists(os.path.join(self.playbooks_dir, pb_name))

    def remediate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Run the Ansible playbook for the given finding."""
        finding_code = finding.get("finding_code", "")
        pb_name = PLAYBOOK_MAP.get(finding_code)

        if not pb_name:
            return {
                "action": "auto_remediate",
                "success": False,
                "details": f"No Ansible playbook mapped for {finding_code}",
            }

        pb_path = os.path.join(self.playbooks_dir, pb_name)
        if not os.path.exists(pb_path):
            return {
                "action": "auto_remediate",
                "success": False,
                "details": f"Playbook not found: {pb_path}",
            }

        # Save snapshot for rollback
        self.rollback.save_snapshot(finding)

        # Build extra vars from finding
        extra_vars = self._build_extra_vars(finding)

        cmd = [
            "ansible-playbook",
            pb_path,
            "-i", self.inventory,
            "--extra-vars", json.dumps(extra_vars),
        ]

        logger.info(f"Running Ansible: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                return {
                    "action": "auto_remediate",
                    "success": True,
                    "details": f"Ansible playbook {pb_name} succeeded",
                    "output": result.stdout[-500:] if result.stdout else "",
                }
            else:
                # Attempt rollback
                self.rollback.rollback(finding)
                return {
                    "action": "auto_remediate",
                    "success": False,
                    "details": f"Ansible failed (rc={result.returncode}): {result.stderr[-500:]}",
                }
        except FileNotFoundError:
            logger.error("ansible-playbook not found. Install Ansible.")
            return {
                "action": "auto_remediate",
                "success": False,
                "details": "ansible-playbook not installed",
            }
        except subprocess.TimeoutExpired:
            return {
                "action": "auto_remediate",
                "success": False,
                "details": "Ansible playbook timed out",
            }

    def _build_extra_vars(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant variables from finding for Ansible."""
        evidence = finding.get("evidence", {})
        if isinstance(evidence, str):
            try:
                evidence = json.loads(evidence)
            except Exception:
                evidence = {}

        resource_id = finding.get("resource_id", "")
        # Parse Azure resource ID components
        parts = resource_id.split("/") if resource_id else []
        resource_group = ""
        resource_name = ""
        subscription_id = ""
        if len(parts) >= 5:
            subscription_id = parts[2] if len(parts) > 2 else ""
            resource_group = parts[4] if len(parts) > 4 else ""
            resource_name = parts[-1] if parts else ""

        return {
            "resource_id": resource_id,
            "resource_group": resource_group,
            "resource_name": resource_name or evidence.get("storage_account", ""),
            "subscription_id": subscription_id,
            "finding_code": finding.get("finding_code", ""),
            "nsg_name": evidence.get("nsg_name", ""),
            "rule_name": evidence.get("rule_name", ""),
            "vm_name": evidence.get("vm_name", ""),
            "nic_name": evidence.get("nic_name", ""),
        }
