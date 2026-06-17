# RÉSUMÉ PROJET OCII-IRIS
**Auteur :** Laurent VIDOT — Licence ASRC, OCII La Réunion
**Date :** 2026-06-03
**Statut :** 🚀 En production — évolution vers plateforme SOC complète

---

## 🎯 C'est quoi OCII-IRIS ?

OCII-IRIS est une **plateforme SOC (Security Operations Center) propulsée par l'IA**, développée en interne pour OCII — Océan Indien Informatique, La Réunion.

L'idée de départ : quand une alerte de sécurité arrive, un analyste passe 20 à 30 minutes à collecter les informations, croiser les sources et rédiger un rapport. OCII-IRIS réduit ce temps à **moins de 5 secondes** en automatisant toute l'investigation grâce à l'intelligence artificielle.

---

## 🏗️ Ce qui a été construit

### Infrastructure
- **VM Ubuntu 22.04** hébergeant Wazuh SIEM + OpenSearch (192.168.0.95)
- **Docker Desktop** sur NUC-ALT (192.168.0.183) faisant tourner 3 containers :
  - `ocii-iris-app` — application Flask sur le port 5000
  - `ocii-iris-ollama` — LLM local (llama3.1:8b) sur le port 11434
  - `ocii-iris-snmp` — receiver SNMP v2c sur le port 162/UDP

### Application Flask (app.py ~600 lignes)
- **Authentification** par session Flask-Login
- **Connexion Wazuh** — API REST sur le port 55000
- **Connexion OpenSearch** — requêtes sur `wazuh-alerts-*` (10 000+ alertes, 29 agents)
- **Enrichissement IP** — AbuseIPDB + VirusTotal pour la réputation des IPs
- **Cartographie MITRE ATT&CK** — 10 tactiques/techniques mappées automatiquement
- **Analyse IA** — Groq API (llama-3.3-70b-versatile) en mode SOC niveau 3 / CISSP
- **Fallback local** — Ollama si Groq indisponible
- **Analyse asynchrone** — threading pour ne pas bloquer l'interface
- **Receiver SNMP** — les traps réseau déclenchent aussi des investigations

### Agents Wazuh surveillés (29 au total)
| Statut | Nombre | Exemples |
|--------|--------|---------|
| ✅ Actif | 22 | PCDOMI24, PCNICO, OCII-NOEUD1, NUC-ALT, SRV-SAVE-MATRIX... |
| ❌ Déconnecté | 7 | PCJACKSON, PC-FOLIO, 1471-PIERRE, Portable-Nicolas... |

### Documentation Obsidian (4 sous-notes)
- `Architecture_VM_Specs.md` — specs VM, réseau, ports, UFW
- `Configuration_Docker_Compose.md` — docker-compose, .env, Nginx, rollback
- `Integration_IA_Groq.md` — prompts SOC, MITRE, cache, retry
- `Script_Collecte_SNMP.md` — pipeline SNMP, receiver, routes Flask

### Présentation ASRC
- 10 diapositives Canva en langage accessible pour jury non technique
- Chiffres clés : 20-30 min → < 5 secondes par investigation

---

## ⚙️ Comment ça marche aujourd'hui

```
Équipement réseau / Wazuh
        │
        │  Alerte (alert_id) ou Trap SNMP
        ▼
   OCII-IRIS Flask
        │
        ├── Récupère l'alerte dans OpenSearch
        ├── Enrichit l'IP (AbuseIPDB + VirusTotal)
        ├── Mappe sur MITRE ATT&CK
        ├── Construit le prompt SOC expert
        ├── Envoie à Groq (ou Ollama en fallback)
        │
        ▼
   Rapport d'investigation complet
        ├── Niveau de sévérité (ROUGE/ORANGE/JAUNE/VERT)
        ├── Tactique MITRE + technique
        ├── Score de réputation IP
        ├── Recommandations SOC
        └── Historique de l'agent
```

---

## 🚀 Vision pour la suite — OCII-IRIS SOC Platform

### Objectif : remplacer Grafana pour la sécurité

Aujourd'hui OCII-IRIS attend qu'on lui envoie un `alert_id` depuis Grafana. La vision est d'en faire une **plateforme SOC autonome et complète** qui rende Grafana optionnel pour la partie sécurité.

### Architecture cible

```
OCII-IRIS SOC Platform
│
├── /  Dashboard temps réel
│   ├── 29 agents — statuts actif/déconnecté
│   ├── Alertes critiques en cours
│   ├── Investigations récentes
│   ├── Stats : Sophos XGS, Windows, SSH, SNMP
│   └── Carte des origines d'attaques
│
├── /agents  Vue par machine
│   ├── Liste des 29 agents avec statut Wazuh
│   ├── Niveau de risque par agent
│   └── Clic → investigation immédiate
│
├── /alerts  Flux temps réel
│   ├── Toutes les alertes OpenSearch
│   ├── Filtres : niveau, agent, type, date
│   └── Bouton "Investiguer" sur chaque alerte
│
├── /investigate  Rapport IA (existant, amélioré)
│
├── /history  Historique investigations
│   ├── Toutes les analyses IA effectuées
│   ├── Filtres par agent, date, sévérité
│   └── Export PDF des rapports
│
└── /api/*  Endpoints internes
    ├── /api/grafana_webhook  (compatibilité)
    ├── /api/snmp_trap        (SNMP v2)
    └── /api/ai_status/<id>   (polling IA)
```

### Moteur autonome (background)
- Scan OpenSearch toutes les 5 minutes
- Détection automatique des nouvelles alertes critiques (niveau ≥ 12)
- Investigation IA automatique avec quota tokens (max 10/heure)
- Anti-doublon : une même IP ne réinvestiguée qu'après 2h

### Règles de déclenchement automatique
| Condition | Action | Quota |
|-----------|--------|-------|
| Alerte niveau ≥ 12 (Critique) | Investigation immédiate | Prioritaire |
| Agent déconnecté | Alerte dashboard | Aucun token |
| IP AbuseIPDB score > 80 | Investigation immédiate | Prioritaire |
| Alerte niveau 9-11 (Élevé) | Proposition investigation | Sur demande |
| Sophos XGS masse (> 1000) | Regroupement par IP | 1 token/groupe |

---

## 📋 Backlog priorisé

### 🔴 Cette semaine (démo équipe OCII)
- [ ] Fix `get_alert_by_id` — requête `ids` OpenSearch *(en cours)*
- [ ] Dashboard principal avec agents + alertes temps réel
- [ ] Page `/agents` — liste cliquable des 29 agents
- [ ] Page `/history` — historique des investigations
- [ ] Test démo complet PCDOMI24 → rapport IA

### 🟠 Semaine prochaine
- [ ] Webhook Grafana → OCII-IRIS (compatibilité)
- [ ] Moteur auto-investigation background
- [ ] Page `/alerts` — flux temps réel OpenSearch
- [ ] Export PDF des rapports d'investigation

### 🟡 Moyen terme
- [ ] CI/CD GitHub Actions (tests + Trivy + deploy SSH)
- [ ] Auth SQLite + bcrypt (remplacer dict hardcodé)
- [ ] Cache Redis (remplacer analysis_cache mémoire)
- [ ] SSL OpenSearch activé
- [ ] Migration SNMPv3 (auth + chiffrement)
- [ ] OIDs SNMP custom par équipement réseau

---

## 🐛 Bugs connus

| Bug | Impact | Priorité |
|-----|--------|----------|
| `VIRUSTOTAL_KEY` mal nommée dans docker-compose | VirusTotal ne fonctionne pas | 🔴 Haute |
| `get_alert_by_id` cherchait `_source.id` au lieu de `_id` | Investigation impossible | 🔴 Corrigé |
| SSL désactivé OpenSearch (`verify=False`) | Risque MITM | 🟠 Moyenne |
| Auth hardcodée (`admin/OciiIris2026!`) | Sécurité | 🟠 Moyenne |
| `analysis_cache` en mémoire | Perdu au redémarrage | 🟡 Faible |

---

## 🔗 Liens

- **Application :** http://192.168.0.183:5000
- **Présentation Canva :** https://www.canva.com/d/RllpQdZzbQ36k0S
- **Kanban Notion :** https://app.notion.com/p/c6fb76f4e77f471994e5d6da618312da
- **Wazuh / OpenSearch :** https://192.168.0.95 (LAN)
- **Groq Console :** https://console.groq.com
