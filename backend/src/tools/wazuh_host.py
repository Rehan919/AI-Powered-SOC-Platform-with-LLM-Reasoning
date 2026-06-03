from src.tools.base import Tool

HOST_DB = {
    "WIN-PC": {
        "processes": [
            {"name": "powershell.exe", "pid": 4812, "parent": "winword.exe", "parent_pid": 3200, "user": "jdoe"},
            {"name": "winword.exe", "pid": 3200, "parent": "explorer.exe", "parent_pid": 1024, "user": "jdoe"},
        ],
        "users_logged_in": ["jdoe", "SYSTEM"],
        "recent_connections": [
            {"dest_ip": "185.199.1.20", "dest_port": 443, "process": "powershell.exe"},
            {"dest_ip": "10.0.0.5", "dest_port": 445, "process": "svchost.exe"},
        ],
    },
    "WIN-01": {
        "processes": [
            {"name": "cmd.exe", "pid": 5501, "parent": "svchost.exe", "parent_pid": 800, "user": "SYSTEM"},
        ],
        "users_logged_in": ["admin"],
        "recent_connections": [
            {"dest_ip": "91.215.85.100", "dest_port": 8080, "process": "cmd.exe"},
        ],
    },
}


class WazuhHostTool(Tool):
    name = "wazuh_host"
    description = "Investigate a host via Wazuh — returns process tree, logged-in users, and recent connections. Input: {\"hostname\": \"WIN-PC\"}"

    def run(self, input: dict) -> dict:
        hostname = input.get("hostname", "")
        if hostname in HOST_DB:
            return HOST_DB[hostname]
        return {"processes": [], "users_logged_in": [], "recent_connections": []}
