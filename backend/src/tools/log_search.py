import logging
import httpx
from src.tools.base import Tool
from src.config import INDEXER_URL, INDEXER_USER, INDEXER_PASS

logger = logging.getLogger(__name__)

# Fallback sample data when the indexer is unreachable
LOG_DB = {
    "WIN-PC": [
        {"timestamp": "2024-01-15T10:02:00Z", "event_id": 4688, "message": "New process created: powershell.exe by winword.exe", "level": "warning"},
        {"timestamp": "2024-01-15T10:02:05Z", "event_id": 3, "message": "Network connection: powershell.exe -> 185.199.1.20:443", "level": "alert"},
    ],
}


class LogSearchTool(Tool):
    name = "log_search"
    description = "Search recent security logs for a host. Input: {\"hostname\": \"WIN-PC\"}"

    def run(self, input: dict) -> dict:
        hostname = input.get("hostname", "")
        logs = self._indexer_search(hostname)
        if logs is not None:
            return {"hostname": hostname, "source": "wazuh-indexer", "log_count": len(logs), "logs": logs}
        mock = LOG_DB.get(hostname, [])
        return {"hostname": hostname, "source": "mock", "log_count": len(mock), "logs": mock}

    def _indexer_search(self, hostname: str):
        """Query the Wazuh indexer for the host's recent alerts; None on failure."""
        if not hostname:
            return None
        query = {
            "size": 8,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"match": {"agent.name": hostname}},
            "_source": ["timestamp", "rule.description", "rule.level", "rule.id"],
        }
        try:
            r = httpx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search", json=query,
                           auth=(INDEXER_USER, INDEXER_PASS), verify=False, timeout=6.0)
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
        except Exception as exc:
            logger.warning("Indexer log search failed for %s: %s", hostname, exc)
            return None
        logs = []
        for h in hits:
            s = h.get("_source", {})
            rule = s.get("rule", {})
            logs.append({"timestamp": s.get("timestamp"), "rule_id": rule.get("id"),
                         "level": rule.get("level"), "message": rule.get("description")})
        return logs
