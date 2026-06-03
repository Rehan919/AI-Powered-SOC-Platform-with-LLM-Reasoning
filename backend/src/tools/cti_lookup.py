import logging
import httpx
from src.tools.base import Tool
from src.config import ABUSEIPDB_KEY

logger = logging.getLogger(__name__)

THREAT_DB = {
    "185.199.1.20": {"malicious": True, "family": "RedLine", "confidence": 92, "source": "ThreatFox"},
    "45.89.10.2": {"malicious": True, "family": "AgentTesla", "confidence": 88, "source": "MalwareBazaar"},
    "91.215.85.100": {"malicious": True, "family": "Cobalt Strike", "confidence": 95, "source": "VirusTotal"},
    "8.8.8.8": {"malicious": False, "family": None, "confidence": 99, "source": "VirusTotal"},
}


class CTILookupTool(Tool):
    name = "cti_lookup"
    description = "Look up an IP address or file hash in threat intelligence databases. Input: {\"indicator\": \"<ip_or_hash>\"}"

    def run(self, input: dict) -> dict:
        indicator = input.get("indicator", "")
        if ABUSEIPDB_KEY and indicator:
            real = self._abuseipdb(indicator)
            if real is not None:
                return real
        if indicator in THREAT_DB:
            return THREAT_DB[indicator]
        return {"malicious": False, "family": None, "confidence": 50, "source": "No match found"}

    def _abuseipdb(self, ip: str):
        try:
            r = httpx.get("https://api.abuseipdb.com/api/v2/check",
                          params={"ipAddress": ip, "maxAgeInDays": 90},
                          headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}, timeout=6.0)
            r.raise_for_status()
            d = r.json().get("data", {})
        except Exception as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None
        score = d.get("abuseConfidenceScore", 0)
        return {"malicious": score >= 50, "family": None, "confidence": score,
                "source": "AbuseIPDB", "country": d.get("countryCode"), "total_reports": d.get("totalReports")}
