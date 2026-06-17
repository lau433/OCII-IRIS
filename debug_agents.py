import requests
import warnings
import json
warnings.filterwarnings('ignore')

r = requests.post(
    'https://192.168.0.95:9200/wazuh-alerts-*/_search',
    auth=('admin', 'OciiAdmin2026'),
    verify=False,
    timeout=30,
    json={
        "size": 0,
        "aggs": {
            "agents": {
                "terms": {
                    "field": "agent.name.keyword",
                    "size": 30
                }
            }
        }
    }
)
data = r.json()
print("Status:", r.status_code)
buckets = data.get('aggregations', {}).get('agents', {}).get('buckets', [])
print(f"Agents trouvés : {len(buckets)}")
for b in buckets:
    print(f"  {b['key']} — {b['doc_count']} alertes")
