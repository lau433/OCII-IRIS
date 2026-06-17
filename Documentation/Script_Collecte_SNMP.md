# Script_Collecte_SNMP

**Date :** 2026-06-03
**État :** 🔧 En cours — SNMP v2 codé, à tester sur VM
**Lié à :** [[DOC_DEVELOPPEMENT_OCII_IRIS]] | [[Configuration_Docker_Compose]] | [[Architecture_VM_Specs]]

---

## Vue d'ensemble

Le module SNMP v2 d'OCII-IRIS permet de recevoir des **traps SNMP** (alertes réseau) directement depuis les équipements (firewalls Sophos XG, switches Cisco, routeurs…) et de les injecter automatiquement dans le pipeline d'investigation IA.

```
Équipement réseau
  │  trap SNMP v2c (UDP:162)
  ▼
snmp_receiver.py ──► format_trap_as_alert()
  │
  │  POST /api/snmp_trap (X-SNMP-Token)
  ▼
app.py (Flask) ──► extract_alert_context()
  │
  ▼
run_ai_analysis() ──► Groq / Ollama
  │
  ▼
Rapport SOC affiché
```

---

## Fichiers créés

| Fichier | Rôle |
|---------|------|
| `snmp_receiver.py` | Daemon Python — écoute UDP:162, formate les traps, pousse vers Flask |
| `Dockerfile.snmp` | Image Docker dédiée au receiver SNMP |
| `requirements.snmp.txt` | Dépendances : `pysnmp==4.4.12`, `requests` |

---

## snmp_receiver.py — Architecture

### Mapping OID → Catégorie

```python
OID_CATEGORY_MAP = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.4.1.2604.5":  "sophos_firewall",
    "1.3.6.1.4.1.9.9.41.2":"cisco_syslog",
}
```

### Format d'alerte produit

```json
{
  "_id": "snmp-192.168.1.1-1748908800",
  "_source": {
    "rule": {
      "level": 12,
      "groups": ["snmp", "authenticationFailure"],
      "mitre": { "tactic": ["Credential Access"], "technique": ["T1110 - Brute Force"] }
    },
    "agent": { "name": "192.168.1.1", "ip": "192.168.1.1" },
    "data": { "srcip": "192.168.1.1", "trap_oid": "...", "category": "authenticationFailure" }
  }
}
```

---

## app.py — Route /api/snmp_trap

```python
@app.route("/api/snmp_trap", methods=["POST"])
def receive_snmp_trap():
    # 1. Vérification token X-SNMP-Token
    # 2. Validation payload (_id + _source)
    # 3. Déduplication via analysis_cache
    # 4. extract_alert_context(alert)
    # 5. Enrichissement IP AbuseIPDB + VirusTotal (si IP publique)
    # 6. run_ai_analysis() en thread daemon
    # 7. Retour {"status": "investigation_started", "poll_url": "/api/ai_status/{id}"}
```

---

## Variables d'environnement à ajouter dans .env

```bash
SNMP_COMMUNITY=public
OCII_API_TOKEN=changez-moi-en-token-aleatoire-32-chars

# Générer :
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## Configuration équipements

### Sophos XG
```
System > Administration > SNMP
  Version : SNMPv2c
  Community : public
  Trap Destination : [IP_VM]:162
```

### Cisco IOS
```
snmp-server host [IP_VM] version 2c public
snmp-server enable traps
```

---

## Commandes de déploiement et test

```bash
# Build et démarrage
docker-compose up -d --build

# Logs du receiver SNMP
docker logs ocii-iris-snmp -f

# Test trap manuel depuis la VM (paquet snmp-utils requis)
snmptrap -v2c -c public localhost:162 '' 1.3.6.1.6.3.1.1.5.3

# Test endpoint Flask directement
curl -s -X POST http://localhost:5000/api/snmp_trap \
  -H "Content-Type: application/json" \
  -H "X-SNMP-Token: snmp-internal-token" \
  -d '{
    "_id": "test-snmp-001",
    "_source": {
      "timestamp": "2026-06-03T12:00:00Z",
      "rule": {"id":"snmp-test","description":"Test trap","level":8,"groups":["snmp","linkDown"],"mitre":{"tactic":["Impact"],"technique":["T1499"],"id":["T1499"]}},
      "agent": {"name":"192.168.1.1","ip":"192.168.1.1"},
      "data": {"srcip":"192.168.1.1","trap_oid":"1.3.6.1.6.3.1.1.5.3","category":"linkDown","var_binds":[]},
      "location": "snmp-trap-receiver:162"
    }
  }' | python3 -m json.tool
```

---

## Roadmap

| Étape | Statut |
|-------|--------|
| `snmp_receiver.py` daemon | ✅ Codé |
| `Dockerfile.snmp` | ✅ Codé |
| `app.py /api/snmp_trap` | ✅ Codé |
| `docker-compose.yml` service snmp | ✅ Codé |
| Test sur VM réelle | 🔧 À faire |
| Configuration Sophos XG | 📋 Planifié |
| OIDs custom par équipement | 📋 Planifié |
| Migration SNMPv3 (auth/priv) | 📋 Planifié |
