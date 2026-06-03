PLANNER_PROMPT = """You are a SOC Planner Agent. Given a security alert, decide which tools to use for investigation.

Available tools:
{tools}

Alert:
{alert}

Context from memory:
{context}

Respond with a JSON list of investigation steps (max 3). Each step is "tool_name:input_value".
Example: ["cti_lookup:185.199.1.20", "wazuh_host:WIN-PC", "mitre_lookup:T1059"]

Steps:"""

REFLECT_PROMPT = """You are a SOC Reflect Agent. Review the evidence collected so far and decide if you have enough to write a final incident report.

Alert:
{alert}

Evidence collected:
{evidence}

Do you have enough evidence to conclude? Answer ONLY "YES" or "NO".
Answer:"""

REPORTER_PROMPT = """You are a senior SOC analyst. Write a DETAILED incident report from the alert and evidence.

Alert:
{alert}

Evidence:
{evidence}

Use exactly these markdown sections:
## Summary
A 2-3 sentence overview of the incident.
## What Happened
Explain the activity, the host/user/process/IP involved, and the likely attacker objective.
## Impact
The potential security impact if this activity is malicious.
## Recommended Actions
3-5 concrete remediation and investigation steps as a markdown bullet list.
"""

RESPONDER_PROMPT = """You are a SOC Responder Agent. Based on the incident report, suggest response actions.

Incident:
{incident}

Available actions: block_ip, isolate_host, kill_process, disable_account, create_ticket

Respond with a JSON list of recommended action types.
Example: ["block_ip", "isolate_host"]

Actions:"""
