from src.models.schemas import AlertInput


def _severity(raw: dict) -> int:
    value = raw.get("severity", raw.get("level", 5))
    try:
        return int(value)
    except (TypeError, ValueError):
        return 5


def normalize_alert(raw: dict) -> AlertInput:
    """Normalize varying Wazuh alert formats into a standard AlertInput."""
    return AlertInput(
        hostname=raw.get("agent") or raw.get("hostname") or raw.get("agent_name"),
        username=raw.get("username") or raw.get("user") or raw.get("account_name"),
        process=raw.get("process") or raw.get("process_name") or raw.get("image"),
        destination_ip=raw.get("destination_ip") or raw.get("dest_ip") or raw.get("dst"),
        source_ip=raw.get("source_ip") or raw.get("src_ip") or raw.get("src"),
        rule=raw.get("rule") or raw.get("rule_description") or raw.get("title"),
        mitre=raw.get("mitre") or raw.get("mitre_id") or raw.get("technique_id"),
        severity=_severity(raw),
        raw_json=raw,
    )
