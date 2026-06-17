warnings.filterwarnings('ignore')
r = requests.post('https://192.168.0.95:9200/wazuh-alerts-*/_search', auth=('admin', 'OciiAdmin2026'), verify=False, timeout=30, json={'size':5,'query':{'wildcard':{'agent.name':{'value':'*JACKSON*'}}},'_source':['agent.name','rule.level']})
data = r.json()
print('Total:', data.get('hits',{}).get('total',{}).get('value',0))
for h in data.get('hits',{}).get('hits',[]):
    print(h.get('_id'), '-', h.get('_source'))
