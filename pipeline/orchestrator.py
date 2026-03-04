"""
Orchestrator: end-to-end pipeline
Scheduler → Scanner runners → Normalizer → Dedup → SIEM → Triage → Dispatcher → Notify → Audit
"""
import logging
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pipeline.normalizer import normalize_batch, parse_scoutsuite, parse_cloudsploit, parse_checkov, parse_tfsec, parse_trivy
from pipeline.deduplicator import deduplicate

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """
    Orchestrates the full scan → triage → remediate pipeline.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.findings: List[Dict[str, Any]] = []
        self.run_id: Optional[int] = None

        # Lazy imports to avoid circular dependencies
        self._dao = None
        self._triage_engine = None
        self._dispatcher = None
        self._siem = None
        self._notifier = None

    def _get_dao(self):
        if self._dao is None:
            from db import dao
            self._dao = dao
        return self._dao

    def _get_triage(self):
        if self._triage_engine is None:
            from triage.engine import TriageEngine
            self._triage_engine = TriageEngine()
        return self._triage_engine

    def _get_dispatcher(self):
        if self._dispatcher is None:
            from remediation.dispatcher import RemediationDispatcher
            self._dispatcher = RemediationDispatcher()
        return self._dispatcher

    def _get_siem(self):
        if self._siem is None:
            try:
                from siem.elastic_client import ElasticSIEM
                self._siem = ElasticSIEM()
            except Exception:
                logger.warning("SIEM client not available, logging to file.")
                self._siem = None
        return self._siem

    # ---------- Phase 1: Scan ----------
    def run_custom_scanner(self) -> List[Dict[str, Any]]:
        """Run the existing custom Azure scanner."""
        from run_scan import run as custom_run
        raw = custom_run() or []
        return normalize_batch(raw, scanner="custom", provider="azure",
                               environment=self.config.get("environment", "dev"))

    def run_scoutsuite(self, report_dir: str = "./reports/scoutsuite") -> List[Dict[str, Any]]:
        """Run ScoutSuite and parse results."""
        from scanner.runner_scoutsuite import run_scoutsuite
        report_path = run_scoutsuite(report_dir=report_dir, provider=self.config.get("provider", "azure"))
        if report_path:
            return parse_scoutsuite(report_path, provider=self.config.get("provider", "azure"))
        return []

    def run_cloudsploit(self, report_dir: str = "./reports/cloudsploit") -> List[Dict[str, Any]]:
        """Run CloudSploit and parse results."""
        from scanner.runner_cloudsploit import run_cloudsploit
        report_path = run_cloudsploit(output_dir=report_dir)
        if report_path:
            return parse_cloudsploit(report_path, provider=self.config.get("provider", "azure"))
        return []

    def run_checkov(self, target_dir: str = "./terraform") -> List[Dict[str, Any]]:
        """Run Checkov IaC scanner and parse results."""
        from scanner.runner_checkov import run_checkov
        report_path = run_checkov(target_dir=target_dir)
        if report_path:
            return parse_checkov(report_path)
        return []

    def run_tfsec(self, target_dir: str = "./terraform") -> List[Dict[str, Any]]:
        """Run tfsec IaC scanner."""
        from scanner.runner_tfsec import run_tfsec
        report_path = run_tfsec(target_dir=target_dir)
        if report_path:
            return parse_tfsec(report_path)
        return []

    def run_trivy(self, target: str = ".") -> List[Dict[str, Any]]:
        """Run Trivy container/config scanner."""
        from scanner.runner_trivy import run_trivy
        report_path = run_trivy(target=target)
        if report_path:
            return parse_trivy(report_path)
        return []

    # ---------- Phase 2: Normalize & Dedup ----------
    def collect_and_normalize(self, scanners: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Run selected scanners, normalize and deduplicate."""
        all_findings = []
        active_scanners = scanners or self.config.get("scanners", ["custom"])

        for scanner_name in active_scanners:
            try:
                logger.info(f"Running scanner: {scanner_name}")
                if scanner_name == "custom":
                    all_findings.extend(self.run_custom_scanner())
                elif scanner_name == "scoutsuite":
                    all_findings.extend(self.run_scoutsuite())
                elif scanner_name == "cloudsploit":
                    all_findings.extend(self.run_cloudsploit())
                elif scanner_name == "checkov":
                    all_findings.extend(self.run_checkov())
                elif scanner_name == "tfsec":
                    all_findings.extend(self.run_tfsec())
                elif scanner_name == "trivy":
                    all_findings.extend(self.run_trivy())
            except Exception as e:
                logger.error(f"Scanner {scanner_name} failed: {e}")

        # Deduplicate
        deduped = deduplicate(all_findings)
        logger.info(f"Total findings: {len(all_findings)}, after dedup: {len(deduped)}")
        self.findings = deduped
        return deduped

    # ---------- Phase 3: Persist & SIEM ----------
    def persist_findings(self, findings: List[Dict[str, Any]]):
        """Save findings to DB and push to SIEM."""
        dao = self._get_dao()
        self.run_id = dao.start_run()

        # Convert normalized findings back to dao-compatible format
        dao_findings = []
        for f in findings:
            dao_findings.append({
                "rule_id": f.get("finding_code", ""),
                "service": f.get("resource_type", ""),
                "resource_id": f.get("resource_id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "evidence": f.get("evidence", {}),
                "remediation": f.get("remediation", []),
            })
        dao.save_findings(self.run_id, dao_findings)
        dao.finish_run(self.run_id)

        # Push to SIEM
        siem = self._get_siem()
        if siem:
            try:
                siem.push_findings(findings)
                logger.info(f"Pushed {len(findings)} findings to SIEM.")
            except Exception as e:
                logger.warning(f"SIEM push failed: {e}")

    # ---------- Phase 4: Triage ----------
    def triage_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run triage engine on findings, adds 'action' field."""
        engine = self._get_triage()
        triaged = engine.triage_batch(findings)
        return triaged

    # ---------- Phase 5: Dispatch Remediation ----------
    def dispatch_remediations(self, triaged_findings: List[Dict[str, Any]]):
        """Execute remediation actions based on triage decisions."""
        dispatcher = self._get_dispatcher()
        results = dispatcher.dispatch_batch(triaged_findings)

        # Notify
        try:
            from notifications.notifier import NotificationManager
            notifier = NotificationManager()
            notifier.notify_batch(triaged_findings, results)
        except Exception as e:
            logger.warning(f"Notification failed: {e}")

        return results

    # ---------- Full Pipeline ----------
    def run_pipeline(self, scanners: Optional[List[str]] = None):
        """Execute the full pipeline end-to-end."""
        logger.info("=" * 60)
        logger.info("PIPELINE START")
        logger.info("=" * 60)

        # 1. Scan & normalize
        findings = self.collect_and_normalize(scanners)

        # 2. Persist & SIEM
        self.persist_findings(findings)

        # 3. Triage
        triaged = self.triage_findings(findings)

        # 4. Remediate
        results = self.dispatch_remediations(triaged)

        logger.info(f"PIPELINE COMPLETE: {len(findings)} findings, "
                     f"{sum(1 for r in results if r.get('success'))} remediated")
        return {
            "run_id": self.run_id,
            "total_findings": len(findings),
            "triaged": triaged,
            "remediation_results": results,
        }
