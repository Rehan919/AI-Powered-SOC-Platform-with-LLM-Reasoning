import logging
import httpx
from src.config import WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS

logger = logging.getLogger(__name__)

# SentinelForge action -> Wazuh active-response command (must exist in ossec.conf)
AR_COMMANDS = {
    "block_ip": "netsh",            # Windows firewall block (firewall-drop on Linux agents)
    "isolate_host": "netsh",
    "disable_account": "disable-account",
    "mitigate_threat": "mitigate-threat", # Custom mitigation script
}


async def trigger_active_response(action_type: str, hostname: str, src_ip: str | None = None, custom_args: list[str] = None) -> dict | None:
    """Best-effort real containment via the Wazuh API. Returns None if this
    action has no real AR mapping; a status dict otherwise (caller falls back)."""
    command = AR_COMMANDS.get(action_type)
    if not command:
        return None
    try:
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            auth = await client.post(f"{WAZUH_API_URL}/security/user/authenticate",
                                     auth=(WAZUH_API_USER, WAZUH_API_PASS))
            auth.raise_for_status()
            token = auth.json()["data"]["token"]
            headers = {"Authorization": f"Bearer {token}"}
            ag = await client.get(f"{WAZUH_API_URL}/agents", headers=headers,
                                  params={"q": f"name={hostname}", "select": "id"})
            ag.raise_for_status()
            items = ag.json().get("data", {}).get("affected_items", [])
            if not items:
                return {"status": "no_agent", "command": command}
            agent_id = items[0]["id"]
            
            args = []
            if src_ip:
                args.append(src_ip)
            if custom_args:
                args.extend(custom_args)
                
            body = {"command": command, "arguments": args}
            resp = await client.put(f"{WAZUH_API_URL}/active-response", headers=headers,
                                    params={"agents_list": agent_id}, json=body)
            resp.raise_for_status()
            return {"status": "active_response_sent", "command": command, "agent_id": agent_id}
    except Exception as exc:
        logger.warning("Wazuh active-response failed for %s: %s", action_type, exc)
        return {"status": "active_response_failed", "command": command, "error": str(exc)}

