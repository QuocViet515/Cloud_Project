"""
IaC PR Creator: automatically generates fix branches and pull requests
for IaC misconfigurations detected by Checkov/tfsec.

Flow:
  1. Parse finding to identify the IaC file and issue
  2. Generate a fix (using fix templates or Checkov remediation suggestions)
  3. Create a new git branch
  4. Commit the fix
  5. Push and create a PR via GitHub API
"""
import os
import json
import logging
import subprocess
import re
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ---- Fix templates for common IaC issues ----
FIX_TEMPLATES = {
    # Checkov checks
    "CKV_AZURE_35": {
        "description": "Enable storage account network rules",
        "search": r'network_rules\s*\{[^}]*default_action\s*=\s*"Allow"',
        "replace": 'network_rules {\n    default_action = "Deny"',
    },
    "CKV_AZURE_33": {
        "description": "Enable storage encryption",
        "search": r'(resource\s+"azurerm_storage_account"\s+"[^"]*"\s*\{)',
        "replace_append": '\n  enable_https_traffic_only = true\n  min_tls_version          = "TLS1_2"',
    },
    "CKV_AZURE_3": {
        "description": "Enable storage account secure transfer",
        "search": r'enable_https_traffic_only\s*=\s*false',
        "replace": 'enable_https_traffic_only = true',
    },
}


class IaCPRCreator:
    """Create fix PRs for IaC misconfigurations."""

    def __init__(self, repo_path: str = ".", github_token: str = None, repo_name: str = None):
        self.repo_path = repo_path
        self.github_token = github_token or os.getenv("GITHUB_TOKEN", "")
        self.repo_name = repo_name or os.getenv("GITHUB_REPOSITORY", "")

    def create_fix_pr(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a fix and create a PR for an IaC finding.
        """
        finding_code = finding.get("finding_code", "")
        iac_file = finding.get("iac_file_path") or finding.get("evidence", {}).get("file_path", "")

        if not iac_file:
            return {
                "action": "create_pr",
                "success": False,
                "details": "No IaC file path in finding",
            }

        # Generate branch name
        branch_name = f"fix/{finding_code.lower()}-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        try:
            # 1. Try to apply fix
            fix_applied = self._apply_fix(finding_code, iac_file, finding)

            if not fix_applied:
                # Generate a placeholder fix comment
                fix_applied = self._add_fix_comment(iac_file, finding)

            if not fix_applied:
                return {
                    "action": "create_pr",
                    "success": False,
                    "details": f"Could not generate fix for {finding_code}",
                }

            # 2. Create branch, commit, push
            self._git_create_branch(branch_name)
            self._git_commit(branch_name, finding)
            self._git_push(branch_name)

            # 3. Create PR via GitHub API
            pr_url = self._create_github_pr(branch_name, finding)

            return {
                "action": "create_pr",
                "success": True,
                "details": f"PR created: {pr_url or branch_name}",
                "branch": branch_name,
                "pr_url": pr_url,
            }
        except Exception as e:
            logger.error(f"PR creation failed: {e}")
            return {
                "action": "create_pr",
                "success": False,
                "details": str(e),
            }

    def _apply_fix(self, finding_code: str, file_path: str, finding: Dict) -> bool:
        """Apply an automated fix based on fix templates."""
        template = FIX_TEMPLATES.get(finding_code)
        if not template:
            return False

        full_path = os.path.join(self.repo_path, file_path)
        if not os.path.exists(full_path):
            return False

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()

            if "search" in template and "replace" in template:
                new_content = re.sub(template["search"], template["replace"], content)
                if new_content != content:
                    with open(full_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    return True

            if "replace_append" in template and "search" in template:
                match = re.search(template["search"], content)
                if match:
                    insert_pos = match.end()
                    new_content = content[:insert_pos] + template["replace_append"] + content[insert_pos:]
                    with open(full_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    return True
        except Exception as e:
            logger.error(f"Fix application failed: {e}")
        return False

    def _add_fix_comment(self, file_path: str, finding: Dict) -> bool:
        """Add a TODO comment in the IaC file as a placeholder fix."""
        full_path = os.path.join(self.repo_path, file_path)
        if not os.path.exists(full_path):
            return False

        try:
            evidence = finding.get("evidence", {})
            line_range = evidence.get("file_line_range", [])
            remediation = finding.get("remediation", [])
            rem_text = remediation[0] if remediation else "Review and fix this resource"

            with open(full_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            insert_line = line_range[0] - 1 if line_range else 0
            comment = f"# TODO [AUTO-FIX]: {finding.get('finding_code', '')} - {rem_text}\n"
            lines.insert(insert_line, comment)

            with open(full_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
            return True
        except Exception as e:
            logger.error(f"Comment insertion failed: {e}")
            return False

    def _git_create_branch(self, branch_name: str):
        """Create a new git branch."""
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=self.repo_path, check=True, capture_output=True,
        )

    def _git_commit(self, branch_name: str, finding: Dict):
        """Stage and commit changes."""
        subprocess.run(
            ["git", "add", "-A"],
            cwd=self.repo_path, check=True, capture_output=True,
        )
        msg = f"fix: auto-remediate {finding.get('finding_code', '')}\n\n{finding.get('title', '')}"
        subprocess.run(
            ["git", "commit", "-m", msg],
            cwd=self.repo_path, check=True, capture_output=True,
        )

    def _git_push(self, branch_name: str):
        """Push branch to remote."""
        subprocess.run(
            ["git", "push", "origin", branch_name],
            cwd=self.repo_path, check=True, capture_output=True,
        )

    def _create_github_pr(self, branch_name: str, finding: Dict) -> Optional[str]:
        """Create a Pull Request via GitHub API."""
        if not self.github_token or not self.repo_name or not HAS_REQUESTS:
            logger.warning("GitHub token or repo not configured, skipping PR creation.")
            return None

        url = f"https://api.github.com/repos/{self.repo_name}/pulls"
        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json",
        }
        body = (
            f"## Auto-fix: {finding.get('finding_code', '')}\n\n"
            f"**Title:** {finding.get('title', '')}\n"
            f"**Severity:** {finding.get('severity', '')}\n"
            f"**Scanner:** {finding.get('scanner', '')}\n\n"
            f"### Remediation\n"
            f"{chr(10).join(finding.get('remediation', []))}\n\n"
            f"---\n"
            f"*This PR was auto-generated by the Cloud Misconfiguration Scanner pipeline.*"
        )

        data = {
            "title": f"[Auto-Fix] {finding.get('finding_code', '')}: {finding.get('title', '')[:80]}",
            "body": body,
            "head": branch_name,
            "base": "main",
        }

        try:
            resp = requests.post(url, json=data, headers=headers, timeout=30)
            if resp.status_code == 201:
                pr_url = resp.json().get("html_url", "")
                logger.info(f"PR created: {pr_url}")
                return pr_url
            else:
                logger.error(f"GitHub PR creation failed: {resp.status_code} {resp.text[:500]}")
                return None
        except Exception as e:
            logger.error(f"GitHub API error: {e}")
            return None
