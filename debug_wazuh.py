import requests
import warnings
import json
warnings.filterwarnings('ignore')

# Token Wazuh
auth = requests.post(
    'https://192.168.0.95:55000/security/user/authenticate',
    auth=('wazuh-wui', '09fB4oB*SqUk3nr5X3kWFpAxFNQ*3MlQ'),
    verify=False, timeout=10
)
token = auth.json().get('data', {}).get('token', '')
print("Auth status:", auth.status_code)

# Liste des agents
r = requests.get(
    'https://192.168.0.95:55000/agents',
    headers={'Authorization': f'Bearer {token}'},
    verify=False, timeout=10
)
agents = r.json().get('data', {}).get('affected_items', [])
print(f"\nAgents Wazuh ({len(agents)}) :")
for a in agents:
    print(f"  [{a.get('status')}] {a.get('name')} — IP: {a.get('ip')} — ID: {a.get('id')}")
