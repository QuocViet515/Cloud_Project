"""
Deduplicator: removes duplicate findings across multiple scanners.

Dedup key = (provider, resource_id, finding_code) — if same resource
flagged by multiple scanners, keep the one with highest severity and
merge scanner names.
"""
from typing import Dict, List, Any


def _dedup_key(finding: Dict[str, Any]) -> str:
    """Generate a deduplication key from a normalized finding."""
    provider = (finding.get("provider") or "").lower()
    resource_id = (finding.get("resource_id") or "").lower()
    finding_code = (finding.get("finding_code") or "").lower()
    # Fallback: use title if finding_code is empty
    title = (finding.get("title") or "").lower()
    return f"{provider}|{resource_id}|{finding_code or title}"


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate findings.
    When the same resource+finding is reported by multiple scanners,
    keep the entry with the highest severity and record all scanner names.
    """
    seen: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        key = _dedup_key(f)
        if key in seen:
            existing = seen[key]
            # Keep higher severity
            existing_sev = SEVERITY_ORDER.get(existing.get("severity", "LOW"), 0)
            new_sev = SEVERITY_ORDER.get(f.get("severity", "LOW"), 0)
            if new_sev > existing_sev:
                scanner_list = existing.get("scanners", [existing.get("scanner", "unknown")])
                scanner_list.append(f.get("scanner", "unknown"))
                f["scanners"] = list(set(scanner_list))
                seen[key] = f
            else:
                scanners = existing.get("scanners", [existing.get("scanner", "unknown")])
                scanners.append(f.get("scanner", "unknown"))
                existing["scanners"] = list(set(scanners))
        else:
            f["scanners"] = [f.get("scanner", "unknown")]
            seen[key] = f

    return list(seen.values())
