# [[Architecture_VM_Specs]]

> **Projet :** OCII-IRIS — Intelligence & Response Investigation System
> **Date :** 2026-05-28
> **État :** ✅ Validé
> **Version :** v1.0.0

---

## 1. Matériel recommandé

| Ressource | Minimum | Recommandé | Justification |
|---|---|---|---|
| **RAM** | 32 Go | **64 Go** | Ollama llama3.1:8b ≈ 8 Go + OS + Flask + buffers OpenSearch |
| **CPU** | 4 cœurs | **8-16 cœurs** | Inférence LLM locale multi-thread, Flask threaded=True |
| **GPU** | — | Optionnel (CUDA) | Accélère Ollama ×5-10 (NVIDIA RTX 3080+ ou A4000) |
| **Stockage SSD** | 50 Go | **≥ 100 Go** | OS (20 Go) + Docker images (10 Go) + modèles Ollama (5 Go/modèle) + logs |
| **Réseau** | 100 Mbps | **1 Gbps** | Flux Wazuh + APIs cloud (Groq, AbuseIPDB, VirusTotal) |
| **OS** | Ubuntu 20.04 | **Ubuntu 22.04 LTS** | Support long terme, Docker Engine stable |

### Estimation consommation RAM par composant

```
OS Ubuntu 22.04          →   1-2 Go
Docker Engine daemon     →   0.5 Go
ocii-iris-app (Flask)    →   0.2-0.5 Go
ocii-iris-ollama         →   6-10 Go  (llama3.1:8b en mémoire)
Buffers système / cache  →   2-4 Go
─────────────────────────────────────
TOTAL estimé             →  ~10-17 Go actif
Recommandé avec marge    →  64 Go (headroom pour modèles plus grands)
```

---

## 2. Schéma d'architecture réseau

```
                        INTERNET
                            │
                    ┌───────▼────────┐
                    │  Groq API      │  api.groq.com:443
                    │  AbuseIPDB     │  api.abuseipdb.com:443
                    │  VirusTotal    │  virustotal.com:443
                    └───────┬────────┘
                            │ HTTPS sortant
                            │
          ┌─────────────────▼──────────────────────────────┐
          │               RÉSEAU LAN  192.168.0.0/24        │
          │                                                  │
          │   ┌──────────────────────────────────────────┐  │
          │   │          VM SERVEUR OCII-IRIS            │  │
          │   │         (192.168.0.XX — 64 Go RAM)       │  │
          │   │                                          │  │
          │   │  ┌─────────────────┐  ┌───────────────┐ │  │
          │   │  │ ocii-iris-app   │  │ ocii-iris-    │ │  │
          │   │  │ :5000 (Flask)   │◄►│ ollama :11434 │ │  │
          │   │  └────────┬────────┘  └───────────────┘ │  │
          │   │           │  réseau interne Docker       │  │
          │   └───────────┼──────────────────────────────┘  │
          │               │                                  │
          │   ┌───────────▼──────────────────────────────┐  │
          │   │       SERVEUR WAZUH  192.168.0.95        │  │
          │   │                                          │  │
          │   │  ┌──────────────┐   ┌─────────────────┐ │  │
          │   │  │ Wazuh API    │   │  OpenSearch     │ │  │
          │   │  │ :55000 HTTPS │   │  :9200  HTTPS   │ │  │
          │   │  └──────────────┘   └─────────────────┘ │  │
          │   └──────────────────────────────────────────┘  │
          │                                                  │
          │   ┌──────────────────────────────────────────┐  │
          │   │       POSTES ANALYSTES / GRAFANA         │  │
          │   │       → http://192.168.0.XX:5000         │  │
          │   └──────────────────────────────────────────┘  │
          └──────────────────────────────────────────────────┘
```

---

## 3. Tableau des ports

### Ports exposés par la VM OCII-IRIS

| Port | Protocole | Service | Container | Accès |
|---|---|---|---|---|
| **5000** | HTTP | Interface web Flask | `ocii-iris-app` | LAN interne (analystes + Grafana) |
| **11434** | HTTP | API Ollama LLM | `ocii-iris-ollama` | LAN interne (inter-containers) |

### Connexions sortantes depuis la VM

| Destination | Port | Protocole | Service |
|---|---|---|---|
| `192.168.0.95` | **55000** | HTTPS | Wazuh Manager API REST |
| `192.168.0.95` | **9200** | HTTPS | OpenSearch (index `wazuh-alerts-*`) |
| `api.groq.com` | **443** | HTTPS | Groq LLM API (cloud) |
| `api.abuseipdb.com` | **443** | HTTPS | AbuseIPDB Threat Intel |
| `www.virustotal.com` | **443** | HTTPS | VirusTotal Threat Intel |

### Règles firewall recommandées (UFW)

```bash
# Autoriser SSH pour administration
sudo ufw allow 22/tcp

# Autoriser l'accès à l'interface OCII-IRIS depuis le LAN uniquement
sudo ufw allow from 192.168.0.0/24 to any port 5000

# Bloquer le port 11434 Ollama depuis l'extérieur (interne Docker uniquement)
sudo ufw deny 11434

# Autoriser les connexions sortantes vers Wazuh
sudo ufw allow out to 192.168.0.95 port 55000
sudo ufw allow out to 192.168.0.95 port 9200

# Autoriser HTTPS sortant (APIs cloud)
sudo ufw allow out 443/tcp

# Activer le pare-feu
sudo ufw enable
sudo ufw status verbose
```

---

## 4. Arborescence complète du projet

```
/opt/ocii-iris/                       ← Répertoire de déploiement recommandé
│
├── app.py                            # Application Flask principale (~540 lignes)
│   ├── Auth           (login/logout/login_required)
│   ├── OpenSearch     (os_search, get_alert_by_id, get_agent_history, get_ip_history)
│   ├── IP Enrichment  (check_abuseipdb, check_virustotal, reverse_dns, is_private)
│   ├── Context        (extract_alert_context → src/dst IP, ports, géo, Sophos, MITRE)
│   └── IA Groq        (build_expert_prompt, call_groq, run_ai_analysis, extract_json)
│
├── Dockerfile                        # Image Python 3.11-slim, EXPOSE 5000
├── docker-compose.yml                # Services : ollama + ocii-iris, volumes
├── .env                              # ⚠️ Secrets (NON versionné)
├── .gitignore                        # Doit contenir : .env, __pycache__, *.pyc
├── requirements.txt                  # flask, requests, python-dotenv, werkzeug
├── test_ollama.py                    # Test connectivité Ollama local
├── architecture-OCII-IRIS.html       # Diagramme d'architecture interactif
│
├── templates/
│   ├── base.html                     # Layout global, CSS variables (--cyan, --hot…)
│   ├── index.html                    # Page d'accueil — statut système
│   ├── investigate.html              # Page investigation (~800 lignes CSS+JS+HTML)
│   │   ├── Verdict panel            (niveau_danger, score_risque, confiance)
│   │   ├── Network panel            (src/dst IP, ports, géo, Sophos)
│   │   ├── Threat Intel panel       (AbuseIPDB, VirusTotal, rDNS)
│   │   ├── MITRE panel              (tactique, technique, description)
│   │   ├── History panel            (alertes IP + alertes agent)
│   │   ├── AI Analysis panel        (analyse technique, IOC, recommandations)
│   │   └── Commands panel           (commandes shell d'investigation)
│   ├── login.html                    # Formulaire auth + remember me
│   └── error.html                    # Affichage erreurs avec message
│
└── static/                           # Assets CSS/JS (à compléter)
```

---

## 5. Prérequis d'installation sur la VM

### 5.1 Installer Docker Engine (Ubuntu 22.04)

```bash
# Désinstaller les anciennes versions
sudo apt remove docker docker-engine docker.io containerd runc

# Installer les dépendances
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release

# Ajouter le dépôt Docker officiel
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Installer Docker Engine + Compose plugin
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Ajouter l'utilisateur courant au groupe docker (évite sudo)
sudo usermod -aG docker $USER
newgrp docker

# Vérifier
docker --version
docker compose version
```

### 5.2 Cloner et configurer le projet

```bash
# Créer le répertoire de déploiement
sudo mkdir -p /opt/ocii-iris
sudo chown $USER:$USER /opt/ocii-iris

# Copier les fichiers du projet
cp -r /chemin/vers/sources/* /opt/ocii-iris/
cd /opt/ocii-iris

# Créer le fichier .env (à partir du template)
cp .env.example .env
nano .env   # Renseigner toutes les clés API et mots de passe

# Vérifier que .env est dans .gitignore
echo ".env" >> .gitignore
```

### 5.3 Premier démarrage

```bash
cd /opt/ocii-iris

# Build et démarrage
docker compose up -d --build

# Attendre ~30 secondes, puis vérifier
docker compose ps
docker logs ocii-iris-app --tail=20
docker logs ocii-iris-ollama --tail=20

# Télécharger le modèle Ollama (5 Go — à faire une seule fois)
docker exec -it ocii-iris-ollama ollama pull llama3.1:8b

# Test de sanité
curl http://localhost:5000/api/status
```

---

## 6. Intégration Grafana

### Lien cliquable depuis un panneau d'alerte Grafana

```
URL : http://192.168.0.XX:5000/investigate?alert_id=${__data.fields.id}
```

Variables Grafana utiles :
- `${__data.fields.id}` → ID de l'alerte Wazuh dans OpenSearch
- `${__data.fields["agent.name"]}` → Nom de la machine (pour `/investigate/agent?name=...`)

### Data source Grafana → OpenSearch

```
URL        : https://192.168.0.95:9200
Auth       : Basic auth (admin / <OS_PASSWORD>)
Index      : wazuh-alerts-*
Time field : @timestamp
SSL        : Skip TLS verify (en attendant les certificats)
```

---

## 7. Monitoring de la VM

```bash
# Ressources Docker en temps réel
docker stats ocii-iris-app ocii-iris-ollama

# Espace disque utilisé par Docker
docker system df

# Espace occupé par les modèles Ollama
docker exec ocii-iris-ollama du -sh /root/.ollama/models/

# Logs applicatifs des dernières 24h
docker logs ocii-iris-app --since 24h

# Processus système
htop
```

---

## 8. Checklist de déploiement

- [ ] Docker Engine installé et fonctionnel (`docker --version`)
- [ ] Fichier `.env` renseigné avec toutes les clés API
- [ ] `.env` absent du dépôt Git (`.gitignore`)
- [ ] `docker compose up -d --build` sans erreur
- [ ] `curl http://localhost:5000/api/status` retourne `{"status": "ok"}`
- [ ] Modèle Ollama téléchargé (`ollama pull llama3.1:8b`)
- [ ] Test Ollama OK (`docker exec -it ocii-iris-app python test_ollama.py`)
- [ ] Accès à Wazuh API testé (port 55000)
- [ ] Accès à OpenSearch testé (port 9200)
- [ ] Lien Grafana → `/investigate?alert_id=` configuré
- [ ] Règles UFW activées
- [ ] Restart automatique vérifié (`restart: unless-stopped`)

---

## Liens

- [[Configuration_Docker_Compose]]
- [[Integration_IA_Groq]]
- [[Script_Collecte_SNMP]]
- [[DOC_DEVELOPPEMENT_OCII_IRIS]]
