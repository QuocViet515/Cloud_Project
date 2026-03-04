"""
Remediation Dispatcher: routes triaged findings to the appropriate
remediation handler based on the 'action' field.

Actions:
  - auto_remediate → AnsibleRemediator or CustodianRemediator
  - create_pr      → IaCPRCreator
  - create_ticket  → TicketCreator
  - quarantine     → QuarantineHandler
  - ignore         → skip
"""
import logging
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class RemediationDispatcher:
    """Route each finding to its remediation handler."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.audit_log: List[Dict[str, Any]] = []

        # Lazy-load handlers
        self._ansible = None
        self._custodian = None
        self._pr_creator = None
        self._ticket_creator = None
        self._quarantine = None

    def _get_ansible(self):
        if self._ansible is None:
            from remediation.ansible_runner import AnsibleRemediator
            self._ansible = AnsibleRemediator()
        return self._ansible

    def _get_custodian(self):
        if self._custodian is None:
            from remediation.custodian_runner import CustodianRemediator
            self._custodian = CustodianRemediator()
        return self._custodian

    def _get_pr_creator(self):
        if self._pr_creator is None:
            from iac_pr.pr_creator import IaCPRCreator
            self._pr_creator = IaCPRCreator()
        return self._pr_creator

    def _get_ticket_creator(self):
        if self._ticket_creator is None:
            from notifications.ticket_creator import TicketCreator
            self._ticket_creator = TicketCreator()
        return self._ticket_creator

    def _get_quarantine(self):
        if self._quarantine is None:
            from remediation.quarantine import QuarantineHandler
            self._quarantine = QuarantineHandler()
        return self._quarantine

    def _log_action(self, finding: Dict, action: str, success: bool, details: str = ""):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "finding_code": finding.get("finding_code", ""),
            "resource_id": finding.get("resource_id", ""),
            "action": action,
            "success": success,
            "details": details,
        }
        self.audit_log.append(entry)
        logger.info(f"AUDIT: {json.dumps(entry)}")

    def dispatch_single(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a single triaged finding."""
        action = finding.get("action", "create_ticket")
        result = {"action": action, "success": False, "details": ""}

        try:
            if action == "auto_remediate":
                result = self._handle_auto_remediate(finding)
            elif action == "create_pr":
                result = self._handle_create_pr(finding)
            elif action == "create_ticket":
                result = self._handle_create_ticket(finding)
            elif action == "quarantine":
                result = self._handle_quarantine(finding)
            elif action == "ignore":
                result = {"action": "ignore", "success": True, "details": "Suppressed finding"}
            else:
                result = {"action": action, "success": False, "details": f"Unknown action: {action}"}
        except Exception as e:
            result = {"action": action, "success": False, "details": str(e)}
            logger.error(f"Dispatch error for {action}: {e}")

        self._log_action(finding, action, result.get("success", False), result.get("details", ""))
        return result

    def dispatch_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Dispatch remediation for a batch of triaged findings."""
        results = []
        for f in findings:
            results.append(self.dispatch_single(f))
        return results

    def _handle_auto_remediate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Try Cloud Custodian first, fall back to Ansible."""
        finding_code = finding.get("finding_code", "")

        # Try Custodian
        try:
            custodian = self._get_custodian()
            if custodian.has_policy(finding_code):
                return custodian.remediate(finding)
        except Exception as e:
            logger.warning(f"Custodian failed: {e}")

        # Fall back to Ansible
        try:
            ansible = self._get_ansible()
            return ansible.remediate(finding)
        except Exception as e:
            logger.error(f"Ansible remediation failed: {e}")
            # Fall back to ticket
            return self._handle_create_ticket(finding)

    def _handle_create_pr(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate an IaC fix PR."""
        try:
            pr_creator = self._get_pr_creator()
            return pr_creator.create_fix_pr(finding)
        except Exception as e:
            logger.error(f"PR creation failed: {e}")
            return {"action": "create_pr", "success": False, "details": str(e)}

    def _handle_create_ticket(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create a ticket for manual review."""
        try:
            ticket = self._get_ticket_creator()
            return ticket.create_ticket(finding)
        except Exception as e:
            logger.warning(f"Ticket creation failed: {e}")
            return {"action": "create_ticket", "success": False, "details": str(e)}

    def _handle_quarantine(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine a resource and create a ticket."""
        try:
            quarantine = self._get_quarantine()
            q_result = quarantine.quarantine_resource(finding)
            # Also create a ticket
            try:
                self._handle_create_ticket(finding)
            except Exception:
                pass
            return q_result
        except Exception as e:
            logger.error(f"Quarantine failed: {e}")
            return {"action": "quarantine", "success": False, "details": str(e)}

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Return the audit log of all remediation actions."""
        return self.audit_log
