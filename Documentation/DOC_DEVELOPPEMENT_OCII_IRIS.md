# DOC_DEVELOPPEMENT_OCII_IRIS

> Fichier de synthèse technique — mis à jour à chaque session de développement  
> Voir sous-notes : [[Architecture_VM_Specs]] · [[Configuration_Docker_Compose]] · [[Integration_IA_Groq]] · [[Script_Collecte_SNMP]]

---

## SESSION 2026-06-16 — SOC Platform V2

**État :** ✅ Validé — prêt pour rebuild Docker  
**Développeur :** Laurent VIDOT — OCII La Réunion

---

### Objectif de la session

Transformer OCII-IRIS d'un outil d'investigation ponctuel en une **plateforme SOC complète** avec :
- Dashboard temps réel (alertes + agents)
- Page Agents — liste des 29 machines Wazuh cliquables
- Page Alertes — flux OpenSearch filtrable en temps réel
- Page Historique — toutes les investigations IA de la session
- Navigation unifiée entre les pages

---

### Structure de fichiers (arborescence mise à jour)

```
C:\ocii-iris\
├── app.py                          ← Application Flask (~800 lignes)
├── docker-compose.yml              ← Stack 3 services
├── Dockerfile                      ← Image Flask
├── Dockerfile.snmp                 ← Image SNMP receiver
├── .env                            ← Secrets (NE PAS COMMITTER)
├── requirements.txt
├── requirements.snmp.txt
├── snmp_receiver.py                ← Receiver SNMP v2c (pure UDP)
├── templates/
│   ├── base.html                   ← Layout + navigation (MAJ nav links)
│   ├── login.html
│   ├── index.html                  ← Dashboard SOC temps réel (RÉÉCRIT)
│   ├── investigate.html            ← Rapport IA (existant)
│   ├── agents.html                 ← NEW — liste 29 agents cliquables
│   ├── alerts.html                 ← NEW — flux alertes OpenSearch
│   ├── history.html                ← NEW — historique investigations
│   └── error.html
├── static/
└── Documentation/
    ├── DOC_DEVELOPPEMENT_OCII_IRIS.md  ← CE FICHIER
    ├── RESUME_PROJET_OCII_IRIS.md
    ├── Architecture_VM_Specs.md
    ├── Configuration_Docker_Compose.md
    ├── Integration_IA_Groq.md
    └── Script_Collecte_SNMP.md
```

---

### Code Clé — app.py (nouveautés session 2026-06-16)

#### Historique des investigations

```python
investigation_history = []   # Historique des investigations complètes
MAX_HISTORY = 200

# Dans run_ai_analysis(), quand une analyse IA réussit :
investigation_history.insert(0, {
    "alert_id":      alert_id,
    "timestamp":     result["_timestamp"],
    "agent_name":    result["_agent_name"],
    "rule_level":    result["_rule_level"],
    "src_ip":        result["_src_ip"],
    "niveau_danger": result.get("niveau_danger"),
    "score_risque":  result.get("score_risque"),
    "type_attaque":  result.get("type_attaque"),
    "resume_executif": result.get("resume_executif"),
})
```

#### Wazuh API — récupération des agents

```python
_wazuh_token_cache = {"token": None, "expires": 0}

def get_wazuh_token():
    # Cache JWT 13 min (Wazuh le valide 15 min)
    ...

def get_wazuh_agents():
    # GET /agents — retourne liste avec : name, id, status, ip, os, lastKeepAlive, version
    ...
```

#### OpenSearch — query étendu

```python
def os_query(body, timeout=15):
    """Lance une requête OpenSearch complète (body libre)."""
    ...

def get_recent_alerts(size=50, min_level=5):
    """Alertes triées par timestamp desc."""
    ...

def get_dashboard_stats():
    """3 comptages OS : total / critiques (≥12) / élevées (9-11)."""
    ...
```

#### Nouvelles routes Flask

```python
# Pages
@app.route("/agents")   → render agents.html
@app.route("/alerts")   → render alerts.html
@app.route("/history")  → render history.html

# API JSON (appelées par JS frontend)
@app.route("/api/dashboard")  → stats + critical_feed + agents counts
@app.route("/api/agents")     → liste Wazuh (JSON brut)
@app.route("/api/alerts")     → alertes OS (params: min_level, size)
@app.route("/api/history")    → investigation_history list

# Webhook Grafana (compatibilité)
@app.route("/api/grafana_webhook", methods=["POST"])
```

---

### Code Clé — base.html (navigation)

```html
<div class="nav-links">
  <a href="/"        class="nav-link {% if request.path == '/' %}active{% endif %}">DASHBOARD</a>
  <a href="/agents"  class="nav-link ...">AGENTS</a>
  <a href="/alerts"  class="nav-link ...">ALERTES</a>
  <a href="/history" class="nav-link ...">HISTORIQUE</a>
</div>
```

---

### Auto-refresh des pages

| Page       | Alertes/Stats | Agents |
|------------|--------------|--------|
| Dashboard  | 30 s         | 60 s   |
| Alertes    | 30 s         | —      |
| Agents     | —            | 60 s   |
| Historique | 15 s         | —      |

---

### Bugs corrigés (session précédente — en prod)

| Bug | Fix |
|-----|-----|
| `get_alert_by_id` cherchait `_source.id` | `{"ids": {"values": [alert_id]}}` ✅ |
| `investigate_agent` timeout 10s | 20s + 3 stratégies fallback ✅ |
| `VIRUSTOTAL_KEY` mal nommée | Corrigé docker-compose.yml ✅ |
| pysnmp incompatible Python 3.11 | Rewrite pure UDP socket ✅ |

---

### Commandes — Rebuild et déploiement

```powershell
# Sur NUC-ALT (192.168.0.183) — PowerShell

# Rebuild uniquement Flask (le plus rapide)
docker-compose up -d --build ocii-iris

# Rebuild complet
docker-compose up -d --build

# Logs en direct
docker logs -f ocii-iris-app

# Tests rapides
curl http://localhost:5000/api/status
curl http://localhost:5000/api/dashboard
curl http://localhost:5000/api/agents
```

---

### Accès LAN

| Service | URL |
|---------|-----|
| Dashboard | http://192.168.0.183:5000/ |
| Agents | http://192.168.0.183:5000/agents |
| Alertes | http://192.168.0.183:5000/alerts |
| Historique | http://192.168.0.183:5000/history |

> **Firewall Windows :** règle "OCII-IRIS Flask" TCP 5000 créée (session précédente) ✅

---

### Prochaines étapes (backlog)

- [ ] Export PDF des rapports d'investigation
- [ ] Moteur auto-investigation background (toutes les 5 min, max 10/heure)
- [ ] Auth SQLite + bcrypt (remplacer dict hardcodé)
- [ ] Cache Redis (remplacer analysis_cache mémoire)
- [ ] CI/CD GitHub Actions
- [ ] SSL OpenSearch
- [ ] Migration SNMPv3

---

## SESSION PRÉCÉDENTE — 2026-06-03 à 2026-06-15

**État :** ✅ En production

### Ce qui a été livré

- Infrastructure Docker : 3 containers (Flask + Ollama + SNMP receiver)
- Fix `get_alert_by_id` — requête `ids` OpenSearch
- Fix `investigate_agent` — 3 stratégies fallback + timeout 20s
- Receiver SNMP v2c (pure UDP socket, zero dépendance pysnmp)
- Endpoint `/api/snmp_trap` avec auth token
- Enrichissement IP : AbuseIPDB + VirusTotal
- Analyse IA : Groq (llama-3.3-70b) + Ollama fallback
- Cartographie MITRE ATT&CK (10 tactiques)
- Présentation Canva ASRC (10 slides, non-technique)
- Kanban Notion synchronisé
- Accès LAN : règle firewall Windows port 5000

---

*Généré automatiquement — OCII-IRIS Dev — 2026-06-16*
