import sys, json
from collections import Counter

event_types = Counter()
files_dropped = set()
network_conns = set()
registry_mods = set()
dlls_loaded = set()
dns_queries = set()
processes = set()
rules_fired = Counter()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        a = json.loads(line)
        r = a.get('rule', {})
        d = a.get('data', {}).get('win', {})
        ed = d.get('eventdata', {})
        sd = d.get('system', {})
        eid = sd.get('eventID', '?')

        rules_fired[f"Rule {r.get('id','?')} (L{r.get('level','?')}) - {r.get('description','?')}"] += 1

        # Sysmon Event ID classification
        if eid == '1':  # Process Create
            event_types['Process Created (EID 1)'] += 1
            img = ed.get('image', '')
            cmd = ed.get('commandLine', '')
            if img:
                processes.add(f"{img} | cmd: {cmd[:120]}")
        elif eid == '3':  # Network Connection
            event_types['Network Connection (EID 3)'] += 1
            dst = ed.get('destinationIp', '') + ':' + ed.get('destinationPort', '')
            network_conns.add(f"{ed.get('image','')} -> {dst}")
        elif eid == '7':  # Image Loaded (DLL)
            event_types['DLL Loaded (EID 7)'] += 1
            dlls_loaded.add(ed.get('imageLoaded', ed.get('image', '')))
        elif eid == '11':  # File Created
            event_types['File Created (EID 11)'] += 1
            files_dropped.add(ed.get('targetFilename', ''))
        elif eid == '12' or eid == '13':  # Registry
            event_types[f'Registry (EID {eid})'] += 1
            registry_mods.add(ed.get('targetObject', ''))
        elif eid == '22':  # DNS Query
            event_types['DNS Query (EID 22)'] += 1
            dns_queries.add(ed.get('queryName', ''))
        else:
            event_types[f'Other (EID {eid})'] += 1

    except Exception as e:
        pass

print("=" * 70)
print("FORENSIC ANALYSIS: LightningDrops_v2")
print("=" * 70)

print(f"\n--- EVENT SUMMARY ({sum(event_types.values())} total events) ---")
for k, v in event_types.most_common():
    print(f"  {k}: {v}")

print(f"\n--- RULES TRIGGERED ({len(rules_fired)} unique) ---")
for k, v in rules_fired.most_common():
    print(f"  [{v}x] {k}")

if processes:
    print(f"\n--- PROCESSES SPAWNED ({len(processes)}) ---")
    for p in sorted(processes):
        print(f"  {p[:200]}")

if files_dropped:
    print(f"\n--- FILES CREATED ({len(files_dropped)}) ---")
    for f in sorted(files_dropped):
        print(f"  {f}")

if network_conns:
    print(f"\n--- NETWORK CONNECTIONS ({len(network_conns)}) ---")
    for n in sorted(network_conns):
        print(f"  {n}")

if dns_queries:
    print(f"\n--- DNS QUERIES ({len(dns_queries)}) ---")
    for d in sorted(dns_queries):
        print(f"  {d}")

if dlls_loaded:
    print(f"\n--- DLLS LOADED ({len(dlls_loaded)}) ---")
    for d in sorted(dlls_loaded):
        print(f"  {d}")

if registry_mods:
    print(f"\n--- REGISTRY MODIFICATIONS ({len(registry_mods)}) ---")
    for r in sorted(registry_mods):
        print(f"  {r}")

if not any([processes, files_dropped, network_conns, dns_queries, dlls_loaded, registry_mods]):
    print("\n(No detailed Sysmon eventdata found - alerts may be rule-only)")
