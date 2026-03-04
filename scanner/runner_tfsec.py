"""
tfsec runner: wraps tfsec CLI for Terraform security scanning.
"""
import subprocess
import os
import logging

logger = logging.getLogger(__name__)


def run_tfsec(
    target_dir: str = "./terraform",
    output_dir: str = "./reports/tfsec",
) -> str:
    """
    Execute tfsec on a Terraform directory and return JSON report path.
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "tfsec_results.json")

    cmd = [
        "tfsec",
        target_dir,
        "--format", "json",
    ]

    logger.info(f"Running tfsec: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )
        if result.stdout:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            return output_path
        if result.returncode not in (0, 1):
            logger.error(f"tfsec error: {result.stderr}")
    except FileNotFoundError:
        logger.error("tfsec not installed. See: https://github.com/aquasecurity/tfsec")
        return ""
    except subprocess.TimeoutExpired:
        logger.error("tfsec timed out after 300s.")
        return ""
    return ""
