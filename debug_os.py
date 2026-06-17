import requests, warnings
warnings.filterwarnings('ignore')
r = requests.post(
    'https://192.168.0.95:9200/wazuh-alerts-*/_search',
    auth=('admin', 'OciiAdmin2026'),
    json={
        'size': 0,
        'aggs': {'agents': {'terms': {'field': 'agent.name', 'size': 20}}}
    },
    verify=False, timeout=10
)
print('Status:', r.status_code)
buckets = r.json().get('aggregations', {}).get('agents', {}).get('buckets', [])
for b in buckets:
    print(b['key'], '--', b['doc_count'], 'alertes')
