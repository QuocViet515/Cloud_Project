"""
Elasticsearch SIEM Client: pushes normalized findings to Elasticsearch
for Kibana visualization and audit trail.

Falls back to file-based logging if Elasticsearch is unavailable.
"""
import json
import os
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

try:
    from elasticsearch import Elasticsearch, helpers
    HAS_ELASTIC = True
except ImportError:
    HAS_ELASTIC = False

FINDINGS_INDEX = "cloud-misconfig-findings"
AUDIT_INDEX = "cloud-misconfig-audit"
FALLBACK_LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "siem_logs")


class ElasticSIEM:
    """Push findings and audit events to Elasticsearch."""

    def __init__(
        self,
        es_url: str = None,
        es_user: str = None,
        es_password: str = None,
        use_fallback: bool = True,
    ):
        self.es_url = es_url or os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
        self.es_user = es_user or os.getenv("ELASTICSEARCH_USER", "")
        self.es_password = es_password or os.getenv("ELASTICSEARCH_PASSWORD", "")
        self.use_fallback = use_fallback
        self.client = None

        if HAS_ELASTIC:
            try:
                kwargs = {"hosts": [self.es_url]}
                if self.es_user:
                    kwargs["basic_auth"] = (self.es_user, self.es_password)
                self.client = Elasticsearch(**kwargs)
                if self.client.ping():
                    logger.info(f"Connected to Elasticsearch at {self.es_url}")
                    self._ensure_index()
                else:
                    logger.warning("Elasticsearch ping failed, using fallback.")
                    self.client = None
            except Exception as e:
                logger.warning(f"Elasticsearch connection failed: {e}")
                self.client = None
        else:
            logger.info("elasticsearch-py not installed, using file-based SIEM logging.")

    def _ensure_index(self):
        """Create index with mapping if it doesn't exist."""
        if not self.client:
            return
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "provider": {"type": "keyword"},
                    "resource_type": {"type": "keyword"},
                    "resource_id": {"type": "text"},
                    "finding_code": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "scanner": {"type": "keyword"},
                    "title": {"type": "text"},
                    "environment": {"type": "keyword"},
                    "asset_owner": {"type": "keyword"},
                    "cis_controls": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "exposure_score": {"type": "integer"},
                }
            }
        }
        for idx in [FINDINGS_INDEX, AUDIT_INDEX]:
            try:
                if not self.client.indices.exists(index=idx):
                    self.client.indices.create(index=idx, body=mapping)
                    logger.info(f"Created index: {idx}")
            except Exception as e:
                logger.warning(f"Index creation failed for {idx}: {e}")

    def push_findings(self, findings: List[Dict[str, Any]]):
        """Push a batch of findings to Elasticsearch or fallback log."""
        if self.client:
            self._push_to_elastic(findings, FINDINGS_INDEX)
        elif self.use_fallback:
            self._push_to_file(findings, "findings")

    def push_audit_events(self, events: List[Dict[str, Any]]):
        """Push audit/remediation events."""
        if self.client:
            self._push_to_elastic(events, AUDIT_INDEX)
        elif self.use_fallback:
            self._push_to_file(events, "audit")

    def _push_to_elastic(self, docs: List[Dict[str, Any]], index: str):
        """Bulk index documents to Elasticsearch."""
        actions = []
        for doc in docs:
            action = {
                "_index": index,
                "_source": doc,
            }
            actions.append(action)

        try:
            success, errors = helpers.bulk(self.client, actions, raise_on_error=False)
            logger.info(f"Indexed {success} docs to {index}, {len(errors)} errors")
        except Exception as e:
            logger.error(f"Bulk indexing failed: {e}")
            if self.use_fallback:
                self._push_to_file(docs, index.split("-")[-1])

    def _push_to_file(self, docs: List[Dict[str, Any]], prefix: str):
        """Fallback: write findings to JSONL file."""
        os.makedirs(FALLBACK_LOG_DIR, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(FALLBACK_LOG_DIR, f"{prefix}_{timestamp}.jsonl")

        try:
            with open(filepath, "a", encoding="utf-8") as f:
                for doc in docs:
                    f.write(json.dumps(doc, ensure_ascii=False) + "\n")
            logger.info(f"Logged {len(docs)} docs to {filepath}")
        except Exception as e:
            logger.error(f"File logging failed: {e}")

    def search_findings(
        self, severity: str = None, scanner: str = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search findings in Elasticsearch."""
        if not self.client:
            return []

        query = {"bool": {"must": []}}
        if severity:
            query["bool"]["must"].append({"term": {"severity": severity.upper()}})
        if scanner:
            query["bool"]["must"].append({"term": {"scanner": scanner.lower()}})
        if not query["bool"]["must"]:
            query = {"match_all": {}}

        try:
            resp = self.client.search(index=FINDINGS_INDEX, query=query, size=limit)
            return [hit["_source"] for hit in resp["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
