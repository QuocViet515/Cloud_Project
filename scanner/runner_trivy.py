"""
Trivy runner: wraps Trivy CLI for container image & config scanning.
"""
import subprocess
import os
import logging

logger = logging.getLogger(__name__)


def run_trivy(
    target: str = ".",
    scan_type: str = "config",
    output_dir: str = "./reports/trivy",
) -> str:
    """
    Execute Trivy and return JSON report path.

    Args:
        target: image name or directory to scan
        scan_type: 'image', 'config', 'fs', 'repo'
        output_dir: directory for output

    Returns:
        Path to JSON report or empty string.
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "trivy_results.json")

    cmd = [
        "trivy",
        scan_type,
        target,
        "--format", "json",
        "--output", output_path,
    ]

    logger.info(f"Running Trivy: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            logger.warning(f"Trivy exit code {result.returncode}: {result.stderr[:500]}")
        if os.path.exists(output_path):
            return output_path
    except FileNotFoundError:
        logger.error("Trivy not installed. See: https://github.com/aquasecurity/trivy")
        return ""
    except subprocess.TimeoutExpired:
        logger.error("Trivy timed out after 600s.")
        return ""
    return ""
