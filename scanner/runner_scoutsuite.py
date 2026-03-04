"""
ScoutSuite runner: wraps the ScoutSuite CLI to scan cloud environments.
"""
import subprocess
import os
import json
import logging
import glob

logger = logging.getLogger(__name__)


def run_scoutsuite(
    provider: str = "azure",
    report_dir: str = "./reports/scoutsuite",
    extra_args: list = None,
) -> str:
    """
    Execute ScoutSuite and return path to the JSON report.

    Args:
        provider: cloud provider (azure, aws, gcp)
        report_dir: directory to store reports
        extra_args: additional CLI arguments

    Returns:
        Path to the generated JSON report, or empty string on failure.
    """
    os.makedirs(report_dir, exist_ok=True)

    cmd = [
        "scout",
        provider,
        "--report-dir", report_dir,
        "--no-browser",
    ]
    if extra_args:
        cmd.extend(extra_args)

    logger.info(f"Running ScoutSuite: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            logger.error(f"ScoutSuite failed: {result.stderr}")
            return ""
        logger.info("ScoutSuite scan completed.")
    except FileNotFoundError:
        logger.error("ScoutSuite not installed. Install with: pip install scoutsuite")
        return ""
    except subprocess.TimeoutExpired:
        logger.error("ScoutSuite timed out after 600s.")
        return ""

    # Find the latest report JSON
    pattern = os.path.join(report_dir, "scoutsuite-results", "scoutsuite_results_*.js")
    files = glob.glob(pattern)
    if not files:
        # Try alternate location
        pattern = os.path.join(report_dir, "**", "*.json")
        files = glob.glob(pattern, recursive=True)

    if files:
        latest = max(files, key=os.path.getmtime)
        # ScoutSuite .js files start with "scoutsuite_results ="
        if latest.endswith(".js"):
            json_path = latest.replace(".js", ".json")
            try:
                with open(latest, "r", encoding="utf-8") as f:
                    content = f.read()
                # Strip JS variable assignment
                if "=" in content:
                    content = content.split("=", 1)[1].strip().rstrip(";")
                data = json.loads(content)
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                return json_path
            except Exception as e:
                logger.error(f"Failed to parse ScoutSuite JS: {e}")
                return latest
        return latest
    return ""
