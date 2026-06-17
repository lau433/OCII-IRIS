# [[Integration_IA_Groq]]

> **Projet :** OCII-IRIS
> **Date :** 2026-05-28
> **État :** ✅ Validé

---

## 1. Vue d'ensemble des moteurs IA

| Moteur | Type | Modèle par défaut | Latence | Coût | Usage |
|---|---|---|---|---|---|
| **Groq** | Cloud API | `llama-3.3-70b-versatile` | ~2-5 s | Pay-per-token | **Production** |
| **Ollama** | Local Docker | `llama3.1:8b` | ~10-30 s | Gratuit | Test / fallback hors-ligne |

### Flux de décision IA

```
/investigate?alert_id=XXXX
        │
        ▼
GROQ_API_KEY présente ?
    ├── OUI → call_groq()  → api.groq.com (cloud)
    └── NON → [dégradé] analyse indisponible (Ollama non branché en v1)
```

> En v1, Ollama est disponible mais non intégré dans le flux principal.
> Il sert de test de connectivité (`test_ollama.py`) et de fallback manuel.

---

## 2. Configuration (app.py)

```python
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
```

### Modèles Groq disponibles (mai 2026)

| Modèle | Contexte | Vitesse | Usage recommandé |
|---|---|---|---|
| `llama-3.3-70b-versatile` | 128k tokens | Rapide | **Production OCII-IRIS** |
| `llama3-70b-8192` | 8k tokens | Très rapide | Analyse simple |
| `llama3-8b-8192` | 8k tokens | Ultra rapide | Test / fallback rapide |
| `mixtral-8x7b-32768` | 32k tokens | Rapide | Contexte long |

---

## 3. Prompt système complet

```python
system_prompt = """Tu es un analyste SOC niveau 3 certifié CISSP, spécialisé en
threat intelligence et réponse aux incidents.
Tu travailles pour OCII (Océan Indien Informatique) à La Réunion, une société
informatique qui gère l'infrastructure IT de clients locaux.
Tu dois produire des analyses de sécurité précises, actionnables et adaptées
au contexte d'une PME réunionnaise.
Réponds UNIQUEMENT avec du JSON valide, sans texte avant ou après."""
```

---

## 4. Prompt utilisateur complet (build_expert_prompt)

Le prompt est construit dynamiquement à partir du contexte de l'alerte :

```python
user_prompt = f"""Analyse cette alerte de sécurité Wazuh et produis un rapport
d'investigation complet.

=== ALERTE ===
Règle: {rule.get('description')} (ID: {rule.get('id')}, niveau {rule.get('level')}/15)
Agent: {agent.get('name')} (ID: {agent.get('id')})
Groupes: {', '.join(ctx['groups'])}
Fois déclenchée au total: {ctx['firedtimes']}
Timestamp: {alert.get('timestamp')}

=== RÉSEAU ===
IP source: {ctx['src_ip']} (port {ctx['src_port']})
IP destination: {ctx['dst_ip']} (port {ctx['dst_port']} → {ctx['port_service']})
Protocole: {ctx['protocol']} | Action: {ctx['log_subtype']}
Géolocalisation source: {ctx['city']}, {ctx['region']}, {ctx['country']}
[Détails Sophos si présents : composant, interface, app, bytes, severity]

=== THREAT INTELLIGENCE ===
AbuseIPDB: Score {abuse_score}/100, {nb_reports} signalements, Pays: {pays},
           Type: {usage_type}, ISP: {isp}, Domaine: {domain}
VirusTotal: {malicious} moteurs malveillants, {suspicious} suspects,
            réputation: {reputation}, ASN: {as_owner}, réseau: {network}

=== HISTORIQUE IP SOURCE ===
[N] alertes pour cette IP (5 dernières affichées) :
  [timestamp] description (niveau X)
  ...

=== HISTORIQUE AGENT ===
[N] alertes récentes sur cet agent :
  [timestamp] description (niveau X)
  ...

=== FORMAT DE RÉPONSE REQUIS ===
Réponds avec ce JSON exactement (tous les champs obligatoires) :
{
  "niveau_danger": "CRITIQUE|ELEVE|MOYEN|FAIBLE",
  "score_risque": <0-100>,
  "confiance_analyse": <0-100>,
  "type_attaque": "classification précise",
  "resume_executif": "3 phrases pour un directeur non-technique",
  "analyse_technique": "analyse SOC détaillée",
  "analyse_port": "signification du port ciblé et pourquoi les attaquants le ciblent",
  "analyse_geographique": "provenance vs contexte OCII/Réunion",
  "correlation": "analyse des patterns de déclenchement",
  "mitre_analyse": "tactique + technique MITRE ATT&CK précises",
  "faux_positif": "probabilité % + justification",
  "ioc": ["liste des IOC détectés"],
  "recommandations": {
    "immediat_P1": "action dans les 15 prochaines minutes",
    "court_terme_P2": "action dans les 24h",
    "moyen_terme_P3": "action dans la semaine",
    "long_terme_P4": "recommandation structurelle"
  },
  "commandes_utiles": ["commandes shell concrètes pour investiguer"],
  "references": ["CVE, MITRE, ou autres sources"]
}"""
```

---

## 5. Appel API Groq (call_groq)

```python
def call_groq(system_prompt, user_prompt):
    if not GROQ_API_KEY:
        print("[GROQ] Clé API manquante")
        return None
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt}
                ],
                "temperature": 0.1,       # Déterministe — essentiel pour SOC
                "max_tokens": 2000,       # JSON de réponse complet
                "response_format": {"type": "json_object"}  # Force du JSON valide
            },
            timeout=30   # 30s max — au-delà, l'analyse échoue proprement
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        else:
            print(f"[GROQ] Erreur HTTP {r.status_code}: {r.text[:300]}")
    except requests.exceptions.Timeout:
        print("[GROQ] Timeout après 30s")
    except Exception as e:
        print(f"[GROQ] Exception: {e}")
    return None
```

### Paramètres clés expliqués

| Paramètre | Valeur | Raison |
|---|---|---|
| `temperature` | `0.1` | Analyse reproductible, pas de créativité hasardeuse |
| `max_tokens` | `2000` | Suffisant pour le JSON complet (~1500 tokens typiquement) |
| `response_format` | `json_object` | Évite le texte parasite autour du JSON |
| `timeout` | `30s` | L'API Groq répond généralement en 2-5s |

---

## 6. Extraction et validation du JSON (extract_json)

```python
def extract_json(text):
    # Tentative 1 : JSON direct
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass

    # Tentative 2 : JSON dans un bloc ```json ... ```
    m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass

    # Tentative 3 : Extraction brute du premier { ... }
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except Exception:
            pass

    return None   # Toutes les tentatives ont échoué
```

> Les 3 tentatives couvrent les cas où le LLM insère du texte avant/après le JSON
> malgré `response_format: json_object`. La robustesse est critique en production.

---

## 7. Flux asynchrone complet

```
Requête HTTP GET /investigate?alert_id=XXXX
    │
    ▼
[Thread principal Flask]
    ├── get_alert_by_id(alert_id)          → OpenSearch
    ├── extract_alert_context(alert)        → contexte réseau, Sophos, MITRE
    ├── check_abuseipdb(src_ip)            → API cloud (si IP publique)
    ├── check_virustotal(src_ip)           → API cloud (si IP publique)
    ├── reverse_dns(src_ip)                → DNS
    ├── get_agent_history(agent_name)      → OpenSearch (15 alertes)
    ├── get_ip_history(src_ip)             → OpenSearch (10 alertes)
    │
    ├── analysis_cache[alert_id] existe ?
    │       ├── OUI (status=done/running) → pas de nouveau thread
    │       └── NON → démarrage Thread daemon :
    │               run_ai_analysis(alert_id, alert, ctx, ...)
    │                   ├── build_expert_prompt(...)
    │                   ├── call_groq(system, user)     → api.groq.com
    │                   ├── extract_json(raw_response)
    │                   └── analysis_cache[alert_id] = result  (status=done)
    │
    └── render_template("investigate.html", ...)
            │
            ▼ (front-end JavaScript)
        Poll toutes les 2s → GET /api/ai_status/<alert_id>
            ├── {"status": "running"} → spinner
            ├── {"status": "done", ...} → affichage verdict
            └── {"status": "error"} → message d'erreur
```

---

## 8. Cache des analyses

```python
# Dictionnaire en mémoire (global)
analysis_cache = {}

# Structure d'une entrée
analysis_cache["alert-id-xxxx"] = {
    "status": "done",           # running | done | error
    "niveau_danger": "ELEVE",
    "score_risque": 75,
    "confiance_analyse": 88,
    "type_attaque": "...",
    # ... tous les champs JSON de la réponse Groq
}
```

> **Limitation actuelle :** Le cache est en RAM — perdu au redémarrage du container.
> **Évolution prévue :** Migrer vers Redis ou SQLite pour la persistance.

---

## 9. Mapping MITRE ATT&CK complet

```python
MITRE_MAP = {
    "authentication_failed": {
        "tactic": "Credential Access",
        "technique": "T1110 - Brute Force",
        "description": "Tentatives répétées d'authentification"
    },
    "authentication_success": {
        "tactic": "Initial Access",
        "technique": "T1078 - Valid Accounts",
        "description": "Connexion réussie potentiellement compromise"
    },
    "ssh": {
        "tactic": "Lateral Movement",
        "technique": "T1021.004 - SSH",
        "description": "Connexion SSH distante"
    },
    "web": {
        "tactic": "Initial Access",
        "technique": "T1190 - Exploit Public-Facing Application",
        "description": "Attaque applicative web"
    },
    "sophos": {
        "tactic": "Defense Evasion / Command & Control",
        "technique": "T1071 - Application Layer Protocol",
        "description": "Trafic réseau suspect détecté par le firewall"
    },
    "firewall": {
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Discovery",
        "description": "Scan ou sondage réseau"
    },
    "malware": {
        "tactic": "Execution",
        "technique": "T1204 - User Execution",
        "description": "Exécution de code malveillant potentielle"
    },
    "windows": {
        "tactic": "Execution",
        "technique": "T1059 - Command and Scripting Interpreter",
        "description": "Activité système Windows suspecte"
    },
    "syslog": {
        "tactic": "Discovery",
        "technique": "T1082 - System Information Discovery",
        "description": "Collecte d'informations système"
    },
    "rootcheck": {
        "tactic": "Persistence",
        "technique": "T1547 - Boot or Logon Autostart Execution",
        "description": "Modification système persistante"
    },
}
```

### Logique de sélection du mapping

```python
# Parcours des groupes Wazuh de l'alerte → premier match MITRE_MAP
groups = rule.get("groups", [])
mitre = None
for g in groups:
    for key, val in MITRE_MAP.items():
        if key in g.lower():
            mitre = val
            break
    if mitre:
        break

# Cas particulier : groupe "sophos" détecté directement
if not mitre and "sophos" in [g.lower() for g in groups]:
    mitre = MITRE_MAP.get("sophos")
```

---

## 10. Tuning et optimisation

### Améliorer la qualité des analyses

```python
# Augmenter la taille du contexte historique
agent_history = get_agent_history(agent_name, limit=30)  # au lieu de 15
ip_history    = get_ip_history(src_ip, limit=20)         # au lieu de 10

# Réduire la température pour plus de cohérence
"temperature": 0.05

# Augmenter max_tokens si la réponse est tronquée
"max_tokens": 3000
```

### Ajouter un retry automatique en cas d'échec Groq

```python
def call_groq_with_retry(system_prompt, user_prompt, max_retries=3):
    for attempt in range(max_retries):
        result = call_groq(system_prompt, user_prompt)
        if result:
            return result
        print(f"[GROQ] Tentative {attempt+1}/{max_retries} échouée, retry dans 5s")
        time.sleep(5)
    return None
```

---

## 11. Test & debug

```bash
# Tester l'API Groq directement depuis le container
docker exec -it ocii-iris-app python3 -c "
import requests, os
r = requests.post(
    'https://api.groq.com/openai/v1/chat/completions',
    headers={'Authorization': f'Bearer {os.environ[\"GROQ_API_KEY\"]}'},
    json={'model': 'llama-3.3-70b-versatile',
          'messages': [{'role': 'user', 'content': 'Dis juste OK'}],
          'max_tokens': 10},
    timeout=15
)
print(r.status_code, r.json())
"

# Tester Ollama local
docker exec -it ocii-iris-app python test_ollama.py

# Voir les analyses en cache (debug Flask)
docker exec -it ocii-iris-app python3 -c "
import app; print(list(app.analysis_cache.keys()))
"
```

---

## Liens

- [[Architecture_VM_Specs]]
- [[Configuration_Docker_Compose]]
- [[Script_Collecte_SNMP]]
- [[DOC_DEVELOPPEMENT_OCII_IRIS]]
