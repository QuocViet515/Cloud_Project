"""
Ticket Creator: integrates with JIRA / ServiceNow to create
tickets for findings that require manual review.
"""
import os
import json
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

TICKET_LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "tickets")


class TicketCreator:
    """Create tickets in JIRA or ServiceNow for manual-review findings."""

    def __init__(self):
        self.jira_url = os.getenv("JIRA_URL", "")
        self.jira_user = os.getenv("JIRA_USER", "")
        self.jira_token = os.getenv("JIRA_API_TOKEN", "")
        self.jira_project = os.getenv("JIRA_PROJECT", "SEC")
        os.makedirs(TICKET_LOG_DIR, exist_ok=True)

    def create_ticket(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create a JIRA ticket or log locally if JIRA is not configured."""
        if self.jira_url and self.jira_token:
            return self._create_jira_ticket(finding)
        else:
            return self._create_local_ticket(finding)

    def _create_jira_ticket(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create a JIRA issue via REST API."""
        if not HAS_REQUESTS:
            return self._create_local_ticket(finding)

        severity = finding.get("severity", "MEDIUM")
        priority_map = {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        }

        issue_data = {
            "fields": {
                "project": {"key": self.jira_project},
                "summary": f"[CloudSec] {finding.get('finding_code', '')}: {finding.get('title', '')[:100]}",
                "description": self._format_description(finding),
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority_map.get(severity, "Medium")},
                "labels": ["cloud-security", "auto-scanner", finding.get("provider", "azure")],
            }
        }

        try:
            resp = requests.post(
                f"{self.jira_url}/rest/api/2/issue",
                json=issue_data,
                auth=(self.jira_user, self.jira_token),
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            if resp.status_code == 201:
                issue_key = resp.json().get("key", "")
                logger.info(f"JIRA ticket created: {issue_key}")
                return {
                    "action": "create_ticket",
                    "success": True,
                    "details": f"JIRA ticket: {issue_key}",
                    "ticket_key": issue_key,
                }
            else:
                logger.error(f"JIRA API error: {resp.status_code} {resp.text[:300]}")
                return self._create_local_ticket(finding)
        except Exception as e:
            logger.error(f"JIRA error: {e}")
            return self._create_local_ticket(finding)

    def _create_local_ticket(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create a local ticket file when JIRA is not available."""
        ticket_id = f"LOCAL-{finding.get('finding_code', 'UNK')}-{hash(finding.get('resource_id', '')) % 10000:04d}"
        ticket = {
            "ticket_id": ticket_id,
            "finding_code": finding.get("finding_code", ""),
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "resource_id": finding.get("resource_id", ""),
            "resource_type": finding.get("resource_type", ""),
            "environment": finding.get("environment", ""),
            "asset_owner": finding.get("asset_owner", ""),
            "remediation": finding.get("remediation", []),
            "status": "open",
        }

        filepath = os.path.join(TICKET_LOG_DIR, f"{ticket_id}.json")
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(ticket, f, indent=2, ensure_ascii=False)
            logger.info(f"Local ticket created: {ticket_id}")
        except Exception as e:
            logger.error(f"Ticket file creation failed: {e}")

        return {
            "action": "create_ticket",
            "success": True,
            "details": f"Local ticket: {ticket_id}",
            "ticket_key": ticket_id,
        }

    def _format_description(self, finding: Dict[str, Any]) -> str:
        """Format JIRA issue description."""
        remediation = finding.get("remediation", [])
        rem_text = "\n".join(f"* {r}" for r in remediation) if isinstance(remediation, list) else str(remediation)
        cis = ", ".join(finding.get("cis_controls", []))

        return (
            f"h3. Cloud Security Finding\n\n"
            f"||Field||Value||\n"
            f"|Finding Code|{finding.get('finding_code', '')}|\n"
            f"|Severity|{finding.get('severity', '')}|\n"
            f"|Provider|{finding.get('provider', '')}|\n"
            f"|Resource Type|{finding.get('resource_type', '')}|\n"
            f"|Resource ID|{finding.get('resource_id', '')}|\n"
            f"|Environment|{finding.get('environment', '')}|\n"
            f"|Scanner|{finding.get('scanner', '')}|\n"
            f"|CIS Controls|{cis}|\n"
            f"|Exposure Score|{finding.get('exposure_score', 'N/A')}|\n\n"
            f"h3. Remediation Steps\n"
            f"{rem_text}\n\n"
            f"h3. Evidence\n"
            f"{{code:json}}\n{json.dumps(finding.get('evidence', {}), indent=2)}\n{{code}}\n\n"
            f"_Auto-generated by Cloud Misconfiguration Scanner_"
        )
