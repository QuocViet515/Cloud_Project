"""
Scheduler: manages periodic and on-demand scan scheduling.

Uses APScheduler for cron-based scheduling and exposes
functions for on-demand trigger.
"""
import logging
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    HAS_APSCHEDULER = True
except ImportError:
    HAS_APSCHEDULER = False


class ScanScheduler:
    """Schedule scan jobs periodically or on-demand."""

    def __init__(self):
        self._scheduler = None
        self._lock = threading.Lock()
        if HAS_APSCHEDULER:
            self._scheduler = BackgroundScheduler()
        else:
            logger.warning("apscheduler not installed; periodic scheduling disabled.")

    def add_periodic_scan(
        self,
        scan_func: Callable,
        cron_expr: str = "0 */6 * * *",
        job_id: str = "periodic_scan",
    ):
        """
        Schedule a scan function using a cron expression.
        Default: every 6 hours.
        """
        if not self._scheduler:
            logger.error("Scheduler unavailable (apscheduler not installed).")
            return
        hour, minute = 0, 0
        parts = cron_expr.split()
        if len(parts) >= 2:
            minute = parts[0]
            hour = parts[1]

        self._scheduler.add_job(
            scan_func,
            CronTrigger.from_crontab(cron_expr),
            id=job_id,
            replace_existing=True,
        )
        logger.info(f"Periodic scan scheduled: {cron_expr} (job_id={job_id})")

    def start(self):
        if self._scheduler:
            self._scheduler.start()
            logger.info("Scheduler started.")

    def stop(self):
        if self._scheduler:
            self._scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped.")

    def trigger_now(self, scan_func: Callable, **kwargs):
        """Run a scan immediately in a separate thread."""
        t = threading.Thread(target=scan_func, kwargs=kwargs, daemon=True)
        t.start()
        logger.info("On-demand scan triggered.")
        return t
