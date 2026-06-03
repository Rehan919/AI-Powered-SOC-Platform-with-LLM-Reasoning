from src.tools.base import Tool

MITRE_DB = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries may abuse command and script interpreters to execute commands.", "detection": "Monitor process creation for cmd.exe, powershell.exe, bash spawned by unusual parents."},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "description": "Adversaries may communicate using application layer protocols to avoid detection.", "detection": "Analyze network data for uncommon data flows and beaconing patterns."},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "description": "Adversaries may inject code into processes to evade defenses.", "detection": "Monitor for API calls such as WriteProcessMemory, CreateRemoteThread."},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "description": "Adversaries may attempt to dump credentials from the OS.", "detection": "Monitor for access to LSASS process and SAM registry hive."},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Adversaries may encrypt data on target systems to interrupt availability.", "detection": "Monitor for mass file rename/modification events and known ransomware extensions."},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "description": "Adversaries may use valid accounts to log into remote services.", "detection": "Monitor for unusual RDP, SSH, or SMB authentication events."},
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "description": "Adversaries may send phishing messages to gain access.", "detection": "Monitor email attachments and links from external sources."},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence", "description": "Adversaries may abuse task scheduling to execute malicious code.", "detection": "Monitor scheduled task creation via schtasks or at commands."},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries may use repeated password guesses to obtain valid credentials.", "detection": "Monitor for many failed logons (Windows 4625) from a single source in a short window."},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence", "description": "Adversaries may manipulate accounts (create, enable, modify, add to groups) to maintain access.", "detection": "Monitor account-management events (4720/4722/4738) and group changes."},
    "T1136": {"name": "Create Account", "tactic": "Persistence", "description": "Adversaries may create accounts to maintain access to victim systems.", "detection": "Monitor for new local/domain account creation (Windows 4720)."},
    "T1484": {"name": "Domain or Tenant Policy Modification", "tactic": "Privilege Escalation", "description": "Adversaries may modify domain/group policy or privileged group membership to escalate.", "detection": "Monitor changes to privileged groups such as Administrators (Windows 4732)."},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence", "description": "Adversaries may create or modify system-level services for persistence.", "detection": "Monitor for new service installation (Windows 7045)."},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion", "description": "Adversaries may delete or clear logs to remove evidence of activity.", "detection": "Monitor for security event log clears (Windows 1102)."},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion", "description": "Adversaries may use valid credentials to access systems.", "detection": "Monitor for explicit-credential logons (Windows 4648) and anomalous logon times."},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion", "description": "Adversaries may disable security tools, firewalls, or audit policy.", "detection": "Monitor for firewall/audit-policy changes (Windows 4719) and AV tampering."},
}


class MITRELookupTool(Tool):
    name = "mitre_lookup"
    description = "Look up a MITRE ATT&CK technique by ID. Input: {\"technique_id\": \"T1059\"}"

    def run(self, input: dict) -> dict:
        tid = input.get("technique_id", "")
        entry = MITRE_DB.get(tid) or MITRE_DB.get(tid.split(".")[0])  # sub-technique -> parent
        if entry:
            return {"technique_id": tid, **entry}
        return {"name": "Unknown", "tactic": "Unknown", "description": "Technique not found.", "detection": "N/A"}
