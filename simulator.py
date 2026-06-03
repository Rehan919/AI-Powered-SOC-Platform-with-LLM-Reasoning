import time
import json
import random
import urllib.request

WEBHOOK_URL = "http://localhost:9090/webhook/wazuh"

ALERTS = [
    {
        "agent": {"name": "WIN-SERVER-01"},
        "rule": {"description": "Suspicious PowerShell Command", "level": 8, "mitre": {"id": ["T1059.001"]}},
        "data": {"process_name": "powershell.exe", "dstip": "185.199.1.20", "srcip": "10.0.0.5", "dstuser": "Administrator"}
    },
    {
        "agent": {"name": "UBUNTU-WEB-02"},
        "rule": {"description": "Multiple Failed SSH Logins", "level": 10, "mitre": {"id": ["T1110.001"]}},
        "data": {"process_name": "sshd", "dstip": "192.168.1.100", "srcip": "103.45.67.89", "dstuser": "root"}
    },
    {
        "agent": {"name": "MAC-DEV-05"},
        "rule": {"description": "Malware detected: Ransomware behavior", "level": 12, "mitre": {"id": ["T1486"]}},
        "data": {"process_name": "unknown_encryptor.app", "dstip": "12.34.56.78", "srcip": "192.168.1.20", "dstuser": "jdoe"}
    }
]

print(f"Starting Wazuh Simulator... streaming alerts to {WEBHOOK_URL}")

while True:
    # Pick a random alert
    alert = random.choice(ALERTS)
    
    # Send it to SentinelForge webhook
    try:
        data = json.dumps(alert).encode('utf-8')
        req = urllib.request.Request(WEBHOOK_URL, data=data, headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req)
        print(f"[{time.strftime('%H:%M:%S')}] Fired alert: {alert['rule']['description']} on {alert['agent']['name']}")
    except Exception as e:
        print(f"Failed to send alert: {e}")

    # Wait 30 seconds before sending the next one
    time.sleep(30)
