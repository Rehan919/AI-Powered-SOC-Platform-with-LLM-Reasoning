import sys, json

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        a = json.loads(line)
        r = a.get('rule', {})
        d = a.get('data', {}).get('win', {}).get('eventdata', {})
        mitre = r.get('mitre', {})
        desc = r.get('description', '?')
        level = r.get('level', '?')
        rid = r.get('id', '?')
        groups = r.get('groups', [])
        print(f"Level {level} | Rule {rid} | {desc}")
        if mitre:
            print(f"  MITRE: {mitre.get('technique',[])} / {mitre.get('tactic',[])}")
        print(f"  Groups: {groups}")
        img = d.get('image', '')
        tgt = d.get('targetFilename', '')
        if img:
            print(f"  Image: {img[:150]}")
        if tgt:
            print(f"  Target: {tgt[:150]}")
        print()
    except Exception as e:
        pass
