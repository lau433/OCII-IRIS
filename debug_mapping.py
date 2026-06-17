import requests
import warnings
import json
warnings.filterwarnings('ignore')

# Chercher les alertes récentes et voir la structure exacte
r = requests.post(
    'https://192.168.0.95:9200/wazuh-alerts-*/_search',
    auth=('admin', 'OciiAdmin2026'),
    verify=False,
    timeout=30,
    json={
        "size": 3,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": 5}}}
    }
)
data = r.json()
print("Status:", r.status_code)
hits = data.get('hits', {}).get('hits', [])
print(f"Hits: {len(hits)}")
for h in hits:
    src = h.get('_source', {})
    agent = src.get('agent', {})
    rule = src.get('rule', {})
    print(f"\n_id: {h.get('_id')}")
    print(f"  agent: {json.dumps(agent)}")
    print(f"  rule.level: {rule.get('level')} | {rule.get('description','')[:60]}")
