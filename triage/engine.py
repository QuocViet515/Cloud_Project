"""
Triage Engine: determines remediation action for each finding.

Actions:
  - "auto_remediate"  → dispatcher runs Ansible/Custodian fix automatically
  - "create_pr"       → IaC fix PR is generated
  - "create_ticket"   → JIRA/ServiceNow ticket + notify approver
  - "quarantine"      → isolate the resource
  - "ignore"          → known exception / suppressed

Decision flow:
  1. Check suppression list (known false positives)
  2. Apply OPA policy (if available)
  3. Fall back to static rules based on severity + environment + resource sensitivity
"""
import logging
from typing import Any, Dict, List, Optional

from triage.rules import StaticTriageRules
from triage.opa_client import OPAClient
from triage.enrichment import enrich_finding

logger = logging.getLogger(__name__)


class TriageEngine:
    """Determine action for each finding."""

    def __init__(self, opa_url: str = None, suppression_list: List[str] = None):
        self.rules = StaticTriageRules()
        self.opa = OPAClient(url=opa_url) if opa_url else None
        self.suppression_list = set(suppression_list or [])

    def triage_single(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single finding and add 'action' + 'triage_reason' fields."""
        finding_code = finding.get("finding_code", "")

        # 1. Suppression check
        resource_key = f"{finding.get('resource_id')}:{finding_code}"
        if resource_key in self.suppression_list or finding_code in self.suppression_list:
            finding["action"] = "ignore"
            finding["triage_reason"] = "suppressed"
            return finding

        # 2. Enrich context
        finding = enrich_finding(finding)

        # 3. Try OPA policy
        if self.opa:
            try:
                decision = self.opa.evaluate(finding)
                if decision:
                    finding["action"] = decision.get("action", "create_ticket")
                    finding["triage_reason"] = f"opa_policy: {decision.get('reason', '')}"
                    return finding
            except Exception as e:
                logger.warning(f"OPA evaluation failed: {e}")

        # 4. Static rules fallback
        action, reason = self.rules.evaluate(finding)
        finding["action"] = action
        finding["triage_reason"] = reason
        return finding

    def triage_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Triage a batch of findings."""
        triaged = []
        for f in findings:
            triaged.append(self.triage_single(f))

        # Log summary
        actions = {}
        for f in triaged:
            a = f.get("action", "unknown")
            actions[a] = actions.get(a, 0) + 1
        logger.info(f"Triage summary: {actions}")

        return triaged
