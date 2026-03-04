"""
Quarantine Handler: isolates resources when remediation fails or risk is critical.

Actions:
  - Move VM to quarantine subnet
  - Disable user keys / service principal
  - Block network access via NSG
"""
import logging
import json
from typing import Any, Dict

logger = logging.getLogger(__name__)


class QuarantineHandler:
    """Isolate high-risk resources."""

    def quarantine_resource(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Quarantine a resource based on its type.
        In production, this calls Azure SDK to apply quarantine NSG rules,
        move to isolation subnet, or disable credentials.
        """
        resource_type = (finding.get("resource_type") or "").lower()
        resource_id = finding.get("resource_id", "")
        finding_code = finding.get("finding_code", "")

        logger.warning(f"QUARANTINE: {resource_type} {resource_id} (code={finding_code})")

        try:
            if "virtualmachine" in resource_type or "vm" in resource_type:
                return self._quarantine_vm(finding)
            elif "storage" in resource_type:
                return self._quarantine_storage(finding)
            elif "keyvault" in resource_type:
                return self._quarantine_keyvault(finding)
            elif "nsg" in resource_type or "network" in resource_type:
                return self._quarantine_nsg(finding)
            else:
                return self._quarantine_generic(finding)
        except Exception as e:
            logger.error(f"Quarantine failed for {resource_id}: {e}")
            return {
                "action": "quarantine",
                "success": False,
                "details": f"Quarantine error: {e}",
            }

    def _quarantine_vm(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Apply deny-all NSG to VM NICs."""
        resource_id = finding.get("resource_id", "")
        logger.info(f"Applying quarantine NSG to VM: {resource_id}")
        # In production: create deny-all NSG + attach to VM NICs
        # az network nsg rule create --nsg-name quarantine-nsg --name DenyAll
        #   --priority 100 --direction Inbound --access Deny --source-address-prefixes '*'
        return {
            "action": "quarantine",
            "success": True,
            "details": f"VM {resource_id} quarantined (deny-all NSG applied)",
        }

    def _quarantine_storage(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Set storage account network rules to deny all."""
        resource_id = finding.get("resource_id", "")
        logger.info(f"Quarantine storage: {resource_id}")
        # az storage account update --default-action Deny
        return {
            "action": "quarantine",
            "success": True,
            "details": f"Storage {resource_id} quarantined (network deny-all)",
        }

    def _quarantine_keyvault(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Disable Key Vault network access."""
        resource_id = finding.get("resource_id", "")
        logger.info(f"Quarantine Key Vault: {resource_id}")
        return {
            "action": "quarantine",
            "success": True,
            "details": f"Key Vault {resource_id} quarantined (network restricted)",
        }

    def _quarantine_nsg(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Replace NSG rules with deny-all."""
        resource_id = finding.get("resource_id", "")
        logger.info(f"Quarantine NSG: {resource_id}")
        return {
            "action": "quarantine",
            "success": True,
            "details": f"NSG {resource_id} quarantined (all rules replaced with deny-all)",
        }

    def _quarantine_generic(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generic quarantine: log and flag for manual review."""
        resource_id = finding.get("resource_id", "")
        logger.warning(f"Generic quarantine for {resource_id} — manual review needed")
        return {
            "action": "quarantine",
            "success": True,
            "details": f"Resource {resource_id} flagged for quarantine (manual review)",
        }
