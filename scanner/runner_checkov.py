"""
Checkov runner: wraps Checkov CLI for IaC static analysis.
"""
import subprocess
import os
import logging

logger = logging.getLogger(__name__)


def run_checkov(
    target_dir: str = "./terraform",
    output_dir: str = "./reports/checkov",
    framework: str = None,
) -> str:
    """
    Execute Checkov on a directory and return JSON report path.

    Args:
        target_dir: directory containing IaC files (Terraform, CloudFormation, etc.)
        output_dir: directory for output report
        framework: specific framework to scan (terraform, cloudformation, etc.)

    Returns:
        Path to JSON report or empty string.
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "checkov_results.json")

    cmd = [
        "checkov",
        "-d", target_dir,
        "--output", "json",
        "--output-file-path", output_dir,
    ]
    if framework:
        cmd.extend(["--framework", framework])

    logger.info(f"Running Checkov: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )
        logger.info(f"Checkov exit code: {result.returncode}")
        # Checkov exits with 1 if findings are found, which is normal
        if result.returncode not in (0, 1):
            logger.error(f"Checkov error: {result.stderr}")
    except FileNotFoundError:
        logger.error("Checkov not installed. Install with: pip install checkov")
        return ""
    except subprocess.TimeoutExpired:
        logger.error("Checkov timed out after 300s.")
        return ""

    # Checkov outputs to results_json.json in the output dir
    for candidate in [
        os.path.join(output_dir, "results_json.json"),
        output_path,
    ]:
        if os.path.exists(candidate):
            return candidate

    # If file mode output didn't work, try parsing stdout
    if result.stdout:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            return output_path
        except Exception:
            pass
    return ""
