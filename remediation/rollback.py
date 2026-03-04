"""
Rollback Manager: saves resource state before remediation and
can revert if remediation causes issues.
"""
import json
import os
import logging
from datetime import datetime, timezone
from typing import Any, Dict

logger = logging.getLogger(__name__)

SNAPSHOT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "rollback_snapshots")


class RollbackManager:
    """Save and restore resource configuration snapshots."""

    def __init__(self, snapshot_dir: str = None):
        self.snapshot_dir = snapshot_dir or SNAPSHOT_DIR
        os.makedirs(self.snapshot_dir, exist_ok=True)

    def _snapshot_path(self, finding: Dict[str, Any]) -> str:
        """Generate a snapshot file path for a finding."""
        resource_id = finding.get("resource_id", "unknown")
        # Sanitize for filename
        safe_id = resource_id.replace("/", "_").replace("\\", "_").replace(":", "_")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.snapshot_dir, f"{safe_id}_{timestamp}.json")

    def save_snapshot(self, finding: Dict[str, Any]) -> str:
        """
        Save current resource state before remediation.
        Returns the snapshot file path.
        """
        snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "finding_code": finding.get("finding_code", ""),
            "resource_id": finding.get("resource_id", ""),
            "resource_type": finding.get("resource_type", ""),
            "evidence_before": finding.get("evidence", {}),
            "provider": finding.get("provider", ""),
        }

        path = self._snapshot_path(finding)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, ensure_ascii=False)
            logger.info(f"Snapshot saved: {path}")
            return path
        except Exception as e:
            logger.error(f"Failed to save snapshot: {e}")
            return ""

    def rollback(self, finding: Dict[str, Any]) -> bool:
        """
        Attempt to rollback a remediation using the saved snapshot.
        In production, this would call Azure/AWS APIs to restore the previous config.
        """
        resource_id = finding.get("resource_id", "")
        logger.warning(f"ROLLBACK requested for {resource_id}")

        # Find the latest snapshot for this resource
        safe_id = resource_id.replace("/", "_").replace("\\", "_").replace(":", "_")
        snapshots = [
            f for f in os.listdir(self.snapshot_dir)
            if f.startswith(safe_id) and f.endswith(".json")
        ]

        if not snapshots:
            logger.error(f"No snapshot found for rollback: {resource_id}")
            return False

        latest = sorted(snapshots)[-1]
        snapshot_path = os.path.join(self.snapshot_dir, latest)

        try:
            with open(snapshot_path, "r", encoding="utf-8") as f:
                snapshot = json.load(f)

            # Log the rollback attempt
            logger.info(f"Rolling back to snapshot: {snapshot_path}")
            logger.info(f"Previous state: {json.dumps(snapshot.get('evidence_before', {}))}")

            # TODO: In production, call Azure SDK to restore previous configuration
            # For now, log the intent
            logger.warning(
                f"ROLLBACK: Would restore {resource_id} to state from "
                f"{snapshot.get('timestamp', 'unknown')}"
            )
            return True
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False

    def list_snapshots(self, resource_id: str = None) -> list:
        """List all available rollback snapshots."""
        files = os.listdir(self.snapshot_dir)
        if resource_id:
            safe_id = resource_id.replace("/", "_").replace("\\", "_").replace(":", "_")
            files = [f for f in files if f.startswith(safe_id)]
        return sorted(files)
