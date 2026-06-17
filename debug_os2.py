import requests, warnings, json
warnings.filterwarnings('ignore')
r = requests.get('https://192.168.0.95:9200', auth=('admin', 'OciiAdmin2026'), verify=False, timeout=30)
print('Status:', r.status_code)
print(r.text[:500])
