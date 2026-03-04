"""
OPA Client: evaluates findings against Open Policy Agent policies.

Requires OPA server running (e.g., `opa run --server policies/`).
"""
import logging
import json
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class OPAClient:
    """Client for OPA REST API."""

    def __init__(self, url: str = None):
        self.base_url = url or "http://localhost:8181"
        self.policy_path = "/v1/data/triage/decision"

    def evaluate(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send finding to OPA and get back a decision.

        Expected OPA response:
        {
            "result": {
                "action": "auto_remediate" | "create_ticket" | "create_pr" | "quarantine" | "ignore",
                "reason": "explanation string"
            }
        }
        """
        if not HAS_REQUESTS:
            logger.warning("requests library not available for OPA client.")
            return None

        endpoint = f"{self.base_url}{self.policy_path}"
        payload = {"input": finding}

        try:
            resp = requests.post(endpoint, json=payload, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                result = data.get("result", {})
                if result and result.get("action"):
                    return result
                logger.debug(f"OPA returned no decision: {data}")
                return None
            else:
                logger.warning(f"OPA returned status {resp.status_code}")
                return None
        except requests.exceptions.ConnectionError:
            logger.debug("OPA server not reachable — falling back to static rules.")
            return None
        except Exception as e:
            logger.warning(f"OPA evaluation error: {e}")
            return None

    def health_check(self) -> bool:
        """Check if OPA server is reachable."""
        if not HAS_REQUESTS:
            return False
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False
