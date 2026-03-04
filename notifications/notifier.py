"""
Notification Manager: sends alerts via Slack, Microsoft Teams, and email.
"""
import json
import os
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class NotificationManager:
    """Send notifications for findings and remediation results."""

    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        self.teams_webhook = os.getenv("TEAMS_WEBHOOK_URL", "")
        self.email_enabled = os.getenv("EMAIL_NOTIFICATIONS", "false").lower() == "true"

    def notify_batch(
        self,
        findings: List[Dict[str, Any]],
        results: List[Dict[str, Any]],
    ):
        """Send summary notification for a scan run."""
        total = len(findings)
        auto_fixed = sum(1 for r in results if r.get("action") == "auto_remediate" and r.get("success"))
        tickets = sum(1 for r in results if r.get("action") == "create_ticket")
        prs = sum(1 for r in results if r.get("action") == "create_pr" and r.get("success"))
        quarantined = sum(1 for r in results if r.get("action") == "quarantine")
        failed = sum(1 for r in results if not r.get("success") and r.get("action") != "ignore")

        # Severity breakdown
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "LOW")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        message = self._format_message(total, severity_counts, auto_fixed, prs, tickets, quarantined, failed)

        if self.slack_webhook:
            self._send_slack(message)
        if self.teams_webhook:
            self._send_teams(message, total, severity_counts, auto_fixed, prs, tickets, quarantined)

        # Always log
        logger.info(f"NOTIFICATION: {message}")

    def notify_single(self, finding: Dict[str, Any], result: Dict[str, Any]):
        """Send alert for a single high-priority finding."""
        severity = finding.get("severity", "")
        if severity not in ("CRITICAL", "HIGH"):
            return

        message = (
            f"🚨 *{severity} Finding*\n"
            f"*Rule:* {finding.get('finding_code', '')}\n"
            f"*Title:* {finding.get('title', '')}\n"
            f"*Resource:* {finding.get('resource_id', '')}\n"
            f"*Action:* {result.get('action', '')} — {'✅ Success' if result.get('success') else '❌ Failed'}\n"
        )

        if self.slack_webhook:
            self._send_slack(message)
        if self.teams_webhook:
            self._send_teams_simple(message)

    def _format_message(self, total, severity_counts, auto_fixed, prs, tickets, quarantined, failed):
        """Format a summary message."""
        sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))
        return (
            f"☁️ *Cloud Scan Complete*\n"
            f"📊 Total Findings: {total} ({sev_str})\n"
            f"✅ Auto-remediated: {auto_fixed}\n"
            f"🔀 PRs Created: {prs}\n"
            f"🎫 Tickets Created: {tickets}\n"
            f"🔒 Quarantined: {quarantined}\n"
            f"❌ Failed: {failed}\n"
        )

    def _send_slack(self, message: str):
        """Send message to Slack webhook."""
        if not HAS_REQUESTS:
            return
        try:
            payload = {"text": message}
            resp = requests.post(self.slack_webhook, json=payload, timeout=10)
            if resp.status_code != 200:
                logger.warning(f"Slack notification failed: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Slack error: {e}")

    def _send_teams(self, message, total, severity_counts, auto_fixed, prs, tickets, quarantined):
        """Send adaptive card to Microsoft Teams."""
        if not HAS_REQUESTS:
            return
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if severity_counts.get("CRITICAL", 0) > 0 else "FFA500",
            "summary": f"Cloud Scan: {total} findings",
            "sections": [
                {
                    "activityTitle": "☁️ Cloud Misconfiguration Scan Results",
                    "facts": [
                        {"name": "Total Findings", "value": str(total)},
                        {"name": "Auto-Remediated", "value": str(auto_fixed)},
                        {"name": "PRs Created", "value": str(prs)},
                        {"name": "Tickets", "value": str(tickets)},
                        {"name": "Quarantined", "value": str(quarantined)},
                    ],
                    "markdown": True,
                }
            ],
        }
        try:
            resp = requests.post(self.teams_webhook, json=card, timeout=10)
            if resp.status_code != 200:
                logger.warning(f"Teams notification failed: {resp.status_code}")
        except Exception as e:
            logger.warning(f"Teams error: {e}")

    def _send_teams_simple(self, message: str):
        """Send simple text to Teams."""
        if not HAS_REQUESTS:
            return
        try:
            payload = {"text": message}
            requests.post(self.teams_webhook, json=payload, timeout=10)
        except Exception as e:
            logger.warning(f"Teams error: {e}")
