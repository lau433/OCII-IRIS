import requests, warnings, json
warnings.filterwarnings('ignore')
r = requests.post('https://192.168.0.95:9200/wazuh-alerts-*/_search', auth=('admin', 'OciiAdmin2026'), verify=False, timeout=30, json={'size':3,'query':{'match_all':{}},'_source':['agent.name','rule.level','rule.description']})
data = r.json()
print('Status:', r.status_code)
print('Total alertes:', data.get('hits',{}).get('total',{}).get('value',0))
for h in data.get('hits',{}).get('hits',[]):
    print(h.get('_id'), '-', h.get('_source'))
