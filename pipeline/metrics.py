"""
Evaluation Metrics: computes KPIs for the scan/remediation pipeline.

Metrics:
  - Detection coverage: % of CIS checks covered by scanners
  - Remediation rate: % of findings successfully auto-remediated
  - MTTR (Mean Time to Remediate): avg time from detection → fix
  - False positive rate: % of findings suppressed or reverted
  - Compliance score: % of CIS benchmarks passing
  - Operational cost: API calls, runtime overhead
"""
import json
import os
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------- CIS Azure Benchmark Checks (subset) ----------
CIS_AZURE_CHECKS = {
    "CIS 1.3": "Ensure resource tags are applied",
    "CIS 3.2": "Ensure storage encryption is enabled",
    "CIS 3.6": "Ensure default network ACL denies access",
    "CIS 3.7": "Ensure public blob access is disabled",
    "CIS 3.8": "Ensure storage account public access is blocked",
    "CIS 6.1": "Ensure NSG does not allow SSH from 0.0.0.0/0",
    "CIS 6.2": "Ensure NSG does not allow RDP from 0.0.0.0/0",
    "CIS 6.3": "Ensure no public IPs on VMs",
    "CIS 6.4": "Ensure IP forwarding is disabled",
    "CIS 7.5": "Ensure VM boot diagnostics is enabled",
    "CIS 8.4": "Ensure Key Vault soft-delete and purge protection",
    "CIS 8.5": "Ensure Key Vault access policies are restricted",
    "CIS 9.1": "Ensure Function Apps have authentication",
    "CIS 9.3": "Ensure App Service secrets in Key Vault",
}

METRICS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "metrics")


class MetricsCollector:
    """Collect and compute pipeline evaluation metrics."""

    def __init__(self):
        os.makedirs(METRICS_DIR, exist_ok=True)

    def compute_all(
        self,
        findings: List[Dict[str, Any]],
        remediation_results: List[Dict[str, Any]],
        run_start: Optional[datetime] = None,
        run_end: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Compute all KPIs and return a metrics report."""
        metrics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
            "detection_coverage": self.detection_coverage(findings),
            "remediation_rate": self.remediation_rate(remediation_results),
            "mttr_seconds": self.mttr(run_start, run_end),
            "false_positive_rate": self.false_positive_rate(findings, remediation_results),
            "compliance_score": self.compliance_score(findings),
            "severity_breakdown": self.severity_breakdown(findings),
            "action_breakdown": self.action_breakdown(remediation_results),
            "scanner_breakdown": self.scanner_breakdown(findings),
        }

        # Persist metrics
        self._save_metrics(metrics)
        return metrics

    def detection_coverage(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compute what % of CIS checks are covered by the scanner findings.
        """
        covered_cis = set()
        for f in findings:
            for cis in f.get("cis_controls", []):
                covered_cis.add(cis)

        total_cis = len(CIS_AZURE_CHECKS)
        covered_count = len(covered_cis & set(CIS_AZURE_CHECKS.keys()))

        return {
            "total_cis_checks": total_cis,
            "covered_checks": covered_count,
            "coverage_percent": round((covered_count / total_cis) * 100, 1) if total_cis > 0 else 0,
            "covered": list(covered_cis & set(CIS_AZURE_CHECKS.keys())),
            "uncovered": list(set(CIS_AZURE_CHECKS.keys()) - covered_cis),
        }

    def remediation_rate(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        % of findings successfully remediated automatically.
        """
        total = len(results)
        if total == 0:
            return {"total": 0, "success": 0, "rate_percent": 0}

        auto_attempts = [r for r in results if r.get("action") == "auto_remediate"]
        auto_success = [r for r in auto_attempts if r.get("success")]

        return {
            "total_findings": total,
            "auto_attempted": len(auto_attempts),
            "auto_success": len(auto_success),
            "rate_percent": round((len(auto_success) / total) * 100, 1) if total > 0 else 0,
        }

    def mttr(
        self,
        run_start: Optional[datetime] = None,
        run_end: Optional[datetime] = None,
    ) -> float:
        """
        Mean Time to Remediate in seconds.
        Measures time from scan start to scan + remediation completion.
        """
        if run_start and run_end:
            delta = (run_end - run_start).total_seconds()
            return round(delta, 2)
        return 0.0

    def false_positive_rate(
        self,
        findings: List[Dict[str, Any]],
        results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        % of findings that were suppressed (ignore) or whose remediation was reverted.
        """
        total = len(findings)
        if total == 0:
            return {"total": 0, "false_positives": 0, "rate_percent": 0}

        ignored = sum(1 for f in findings if f.get("action") == "ignore")
        reverted = sum(1 for r in results if "rollback" in str(r.get("details", "")).lower())

        fp = ignored + reverted
        return {
            "total": total,
            "false_positives": fp,
            "ignored": ignored,
            "reverted": reverted,
            "rate_percent": round((fp / total) * 100, 1) if total > 0 else 0,
        }

    def compliance_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        % of CIS benchmarks satisfied (no findings for that check).
        """
        failing_cis = set()
        for f in findings:
            severity = (f.get("severity") or "").upper()
            if severity in ("CRITICAL", "HIGH", "MEDIUM"):
                for cis in f.get("cis_controls", []):
                    failing_cis.add(cis)

        total_cis = len(CIS_AZURE_CHECKS)
        passing = total_cis - len(failing_cis & set(CIS_AZURE_CHECKS.keys()))

        return {
            "total_cis_checks": total_cis,
            "passing": passing,
            "failing": total_cis - passing,
            "score_percent": round((passing / total_cis) * 100, 1) if total_cis > 0 else 0,
            "failing_controls": list(failing_cis & set(CIS_AZURE_CHECKS.keys())),
        }

    def severity_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = (f.get("severity") or "LOW").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def action_breakdown(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count actions taken."""
        counts = {}
        for r in results:
            action = r.get("action", "unknown")
            success = "success" if r.get("success") else "failed"
            key = f"{action}_{success}"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def scanner_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by scanner source."""
        counts = {}
        for f in findings:
            scanner = f.get("scanner", "unknown")
            counts[scanner] = counts.get(scanner, 0) + 1
        return counts

    def _save_metrics(self, metrics: Dict[str, Any]):
        """Save metrics to a JSON file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(METRICS_DIR, f"metrics_{timestamp}.json")
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(metrics, f, indent=2, ensure_ascii=False)
            logger.info(f"Metrics saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save metrics: {e}")

    def load_latest_metrics(self) -> Optional[Dict[str, Any]]:
        """Load the most recent metrics file."""
        files = [f for f in os.listdir(METRICS_DIR) if f.endswith(".json")]
        if not files:
            return None
        latest = sorted(files)[-1]
        try:
            with open(os.path.join(METRICS_DIR, latest), "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def load_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Load metrics history for trend analysis."""
        files = sorted([f for f in os.listdir(METRICS_DIR) if f.endswith(".json")])
        files = files[-limit:]
        history = []
        for fname in files:
            try:
                with open(os.path.join(METRICS_DIR, fname), "r", encoding="utf-8") as f:
                    history.append(json.load(f))
            except Exception:
                pass
        return history
