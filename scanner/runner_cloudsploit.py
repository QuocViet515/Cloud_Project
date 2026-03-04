"""
CloudSploit runner: wraps CloudSploit CLI (Docker or local) to scan cloud resources.
"""
import subprocess
import os
import json
import logging

logger = logging.getLogger(__name__)


def run_cloudsploit(
    output_dir: str = "./reports/cloudsploit",
    config_path: str = "./config/cloudsploit_config.yml",
    use_docker: bool = True,
) -> str:
    """
    Execute CloudSploit and return the JSON report path.

    Args:
        output_dir: directory for output reports
        config_path: path to CloudSploit config file
        use_docker: whether to use Docker (True) or local install

    Returns:
        Path to JSON report or empty string.
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "cloudsploit_results.json")

    if use_docker:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.path.abspath(output_dir)}:/reports",
        ]
        if os.path.exists(config_path):
            cmd.extend(["-v", f"{os.path.abspath(config_path)}:/config.yml"])
            cmd.extend(["cloudsploit/scans", "--config", "/config.yml"])
        else:
            cmd.extend(["cloudsploit/scans"])
        cmd.extend(["--json", "/reports/cloudsploit_results.json"])
    else:
        cmd = [
            "cloudsploit-scan",
            "--json", output_path,
        ]
        if os.path.exists(config_path):
            cmd.extend(["--config", config_path])

    logger.info(f"Running CloudSploit: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            logger.error(f"CloudSploit failed: {result.stderr}")
            # Still check if partial output was created
        logger.info("CloudSploit scan completed.")
    except FileNotFoundError:
        logger.error("CloudSploit not found. Install Docker or cloudsploit-scan.")
        return ""
    except subprocess.TimeoutExpired:
        logger.error("CloudSploit timed out after 600s.")
        return ""

    if os.path.exists(output_path):
        return output_path
    return ""
