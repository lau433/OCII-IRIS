"""Debug: test OpenSearch _id lookup vs get_recent_alerts"""
import requests, urllib3, json
urllib3.disable_warnings()

OS = "https://192.168.0.95:9200"
AUTH = ("admin", "OciiAdmin2026")

# 1. Get a few recent alerts with their _id
print("=== STEP 1: Get recent alerts ===")
r = requests.post(f"{OS}/wazuh-alerts-*/_search", auth=AUTH, verify=False, timeout=10,
    json={"size": 3, "sort": [{"@timestamp": {"order": "desc"}}],
          "query": {"range": {"rule.level": {"gte": 10}}}})
hits = r.json().get("hits", {}).get("hits", [])
print(f"Found {len(hits)} alerts")

for h in hits:
    doc_id = h["_id"]
    index = h["_index"]
    level = h["_source"].get("rule", {}).get("level")
    desc = h["_source"].get("rule", {}).get("description", "")[:60]
    print(f"  _id={doc_id}  _index={index}  level={level}  {desc}")

if not hits:
    print("No alerts found!")
    exit()

# 2. Try to fetch the first one back using ids query (same as get_alert_by_id)
test_id = hits[0]["_id"]
test_index = hits[0]["_index"]
print(f"\n=== STEP 2: Lookup by ids query (wildcard index) ===")
print(f"Looking for _id={test_id}")

r2 = requests.post(f"{OS}/wazuh-alerts-*/_search", auth=AUTH, verify=False, timeout=10,
    json={"size": 1, "query": {"ids": {"values": [test_id]}}})
hits2 = r2.json().get("hits", {}).get("hits", [])
print(f"Result: {len(hits2)} hits")
if hits2:
    print(f"  Found: _id={hits2[0]['_id']}")
else:
    print("  FAILED - ids query returned nothing on wildcard index")

# 3. Try on specific index
print(f"\n=== STEP 3: Lookup by ids on specific index {test_index} ===")
r3 = requests.post(f"{OS}/{test_index}/_search", auth=AUTH, verify=False, timeout=10,
    json={"size": 1, "query": {"ids": {"values": [test_id]}}})
hits3 = r3.json().get("hits", {}).get("hits", [])
print(f"Result: {len(hits3)} hits")
if hits3:
    print(f"  Found: _id={hits3[0]['_id']}")

# 4. Try term query on _id
print(f"\n=== STEP 4: Lookup by term _id ===")
r4 = requests.post(f"{OS}/wazuh-alerts-*/_search", auth=AUTH, verify=False, timeout=10,
    json={"size": 1, "query": {"term": {"_id": test_id}}})
hits4 = r4.json().get("hits", {}).get("hits", [])
print(f"Result: {len(hits4)} hits")

# 5. Try GET by doc ID
print(f"\n=== STEP 5: GET /{test_index}/_doc/{test_id} ===")
r5 = requests.get(f"{OS}/{test_index}/_doc/{test_id}", auth=AUTH, verify=False, timeout=10)
print(f"Status: {r5.status_code}")
if r5.status_code == 200:
    d = r5.json()
    print(f"  found={d.get('found')}  _id={d.get('_id')}")
