import logging
import os
import concurrent.futures

import chromadb
from src.config import CHROMA_HOST, CHROMA_PORT

logger = logging.getLogger(__name__)

# Seed data
MITRE_KNOWLEDGE = [
    {"id": "T1059", "text": "T1059 Command and Scripting Interpreter - Execution tactic. Adversaries use cmd, PowerShell, bash to execute commands. Detect unusual parent-child process relationships."},
    {"id": "T1071", "text": "T1071 Application Layer Protocol - C2 tactic. Adversaries use HTTP/HTTPS/DNS for command and control. Look for beaconing patterns and unusual destinations."},
    {"id": "T1055", "text": "T1055 Process Injection - Defense Evasion. Adversaries inject code into legitimate processes. Monitor WriteProcessMemory and CreateRemoteThread API calls."},
    {"id": "T1003", "text": "T1003 OS Credential Dumping - Credential Access. Adversaries dump LSASS or SAM for credentials. Monitor access to lsass.exe and registry hives."},
    {"id": "T1486", "text": "T1486 Data Encrypted for Impact - Ransomware. Mass file encryption activity. Monitor bulk file renames and known ransomware extensions."},
    {"id": "T1021", "text": "T1021 Remote Services - Lateral Movement. Adversaries use RDP, SSH, SMB to move laterally. Detect unusual remote logon events."},
    {"id": "T1566", "text": "T1566 Phishing - Initial Access. Spearphishing emails with malicious attachments or links. Monitor email gateway and user click behavior."},
    {"id": "T1053", "text": "T1053 Scheduled Task - Persistence. Adversaries create scheduled tasks for persistence. Monitor schtasks.exe and at.exe usage."},
    {"id": "T1048", "text": "T1048 Exfiltration Over Alternative Protocol - Exfiltration. Data theft via DNS, ICMP, or cloud storage. Monitor unusual outbound data volumes."},
    {"id": "T1078", "text": "T1078 Valid Accounts - Persistence/Initial Access. Compromised credentials used for access. Detect impossible travel and unusual login times."},
]

DETECTION_RULES = [
    {"id": "rule_ps_encoded", "text": "Rule: PowerShell Encoded Command - Detects powershell.exe with -enc or -encodedcommand parameter. Severity: High. MITRE: T1059.001"},
    {"id": "rule_lsass_access", "text": "Rule: LSASS Memory Access - Detects processes accessing lsass.exe memory. Severity: Critical. MITRE: T1003.001"},
    {"id": "rule_suspicious_parent", "text": "Rule: Suspicious Parent Process - Detects cmd/powershell spawned by office applications (word, excel). Severity: High. MITRE: T1059"},
    {"id": "rule_c2_beacon", "text": "Rule: C2 Beaconing Pattern - Detects regular interval connections to external IPs. Severity: High. MITRE: T1071"},
    {"id": "rule_mass_rename", "text": "Rule: Mass File Rename - Detects bulk file extension changes indicating ransomware. Severity: Critical. MITRE: T1486"},
]

RESPONSE_PLAYBOOKS = [
    {"id": "pb_malware", "text": "Playbook: Malware Infection - 1. Isolate host from network. 2. Kill malicious process. 3. Collect memory dump. 4. Block C2 IP at firewall. 5. Scan for lateral movement. 6. Reset user credentials."},
    {"id": "pb_phishing", "text": "Playbook: Phishing Response - 1. Block sender domain. 2. Delete email from all mailboxes. 3. Check for clicks/downloads. 4. Scan endpoint for malware. 5. Reset compromised credentials."},
    {"id": "pb_ransomware", "text": "Playbook: Ransomware - 1. Immediately isolate host. 2. Disconnect from network shares. 3. Identify ransomware family. 4. Check backup integrity. 5. Report to management. 6. Do NOT pay ransom."},
    {"id": "pb_credential_theft", "text": "Playbook: Credential Theft - 1. Disable compromised accounts. 2. Force password reset. 3. Revoke active sessions. 4. Check for unauthorized access. 5. Enable MFA. 6. Monitor for reuse."},
    {"id": "pb_lateral_movement", "text": "Playbook: Lateral Movement - 1. Identify all accessed hosts. 2. Isolate compromised systems. 3. Block attacker IP ranges. 4. Check for persistence mechanisms. 5. Rotate service account passwords."},
]

# Local persistent storage path (used when ChromaDB HTTP server is unavailable)
_LOCAL_CHROMA_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "chroma_data")


def _try_http_client(timeout: float = 3.0):
    """Attempt to connect to the ChromaDB HTTP server. Returns client or None."""
    def _connect():
        client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        client.heartbeat()  # force an actual connection
        return client

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_connect)
        try:
            return fut.result(timeout=timeout)
        except Exception as exc:
            logger.warning(
                "ChromaDB HTTP server at %s:%s unavailable (%s); using local PersistentClient.",
                CHROMA_HOST, CHROMA_PORT, exc,
            )
            return None


class SecurityMemory:
    def __init__(self):
        client = _try_http_client()
        if client is None:
            os.makedirs(_LOCAL_CHROMA_PATH, exist_ok=True)
            client = chromadb.PersistentClient(path=_LOCAL_CHROMA_PATH)
            logger.info("Using local ChromaDB PersistentClient at %s", _LOCAL_CHROMA_PATH)
        self.client = client
        self.collections = {}

    def init_collections(self):
        self.collections["mitre"] = self.client.get_or_create_collection("mitre_attack")
        self.collections["incidents"] = self.client.get_or_create_collection("past_incidents")
        self.collections["rules"] = self.client.get_or_create_collection("detection_rules")
        self.collections["playbooks"] = self.client.get_or_create_collection("response_playbooks")

    def seed_knowledge(self):
        self.init_collections()
        self._seed_collection("mitre", MITRE_KNOWLEDGE)
        self._seed_collection("rules", DETECTION_RULES)
        self._seed_collection("playbooks", RESPONSE_PLAYBOOKS)

    def _seed_collection(self, name: str, data: list[dict]):
        col = self.collections[name]
        if col.count() > 0:
            return  # Already seeded
        col.add(
            ids=[d["id"] for d in data],
            documents=[d["text"] for d in data],
        )

    def store_incident(self, incident_id: int, summary: str, mitre: list[str]):
        col = self.collections.get("incidents")
        if not col:
            self.init_collections()
            col = self.collections["incidents"]
        text = f"Incident {incident_id}: {summary}. MITRE: {', '.join(mitre)}"
        col.add(ids=[f"inc_{incident_id}"], documents=[text])

    def similar_incidents(self, query: str, exclude_id: int = None, top_k: int = 3) -> list[dict]:
        """Return the most similar past incidents (excludes the current one)."""
        col = self.collections.get("incidents")
        if not col:
            try:
                self.init_collections()
                col = self.collections["incidents"]
            except Exception:
                return []
        if col.count() == 0:
            return []
        try:
            res = col.query(query_texts=[query], n_results=min(top_k + 1, col.count()))
        except Exception:
            return []
        out = []
        for cid, doc in zip(res.get("ids", [[]])[0], res.get("documents", [[]])[0]):
            if exclude_id and cid == f"inc_{exclude_id}":
                continue
            out.append({"id": cid, "text": doc})
        return out[:top_k]

    def query_context(self, query: str, top_k: int = 3) -> list[str]:
        results = []
        for col in self.collections.values():
            try:
                res = col.query(query_texts=[query], n_results=min(top_k, col.count()) if col.count() > 0 else 1)
                if res["documents"] and res["documents"][0]:
                    results.extend(res["documents"][0])
            except Exception as exc:
                logger.warning("Skipping Chroma collection '%s' after query failure: %s", col.name, exc)
                continue
        return results[:top_k * 2]
