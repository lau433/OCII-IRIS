<<<<<<< HEAD
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
import requests
import os
import json
import re
import socket
import threading
import time
import secrets
import urllib3
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
=======
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
import os
import json
import urllib3
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
<<<<<<< HEAD
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── Security: Cookie hardening ──
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ── Security: Rate limiting (brute-force protection) ──
_login_attempts = defaultdict(list)   # {ip: [timestamp, ...]}
RATE_LIMIT_WINDOW = 300   # 5 minutes
RATE_LIMIT_MAX    = 5     # max attempts per window

def _is_rate_limited(ip):
    """Check if IP has exceeded login attempt limit."""
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < RATE_LIMIT_WINDOW]
    return len(_login_attempts[ip]) >= RATE_LIMIT_MAX

def _record_attempt(ip):
    _login_attempts[ip].append(time.time())
=======
app.secret_key = os.environ.get("SECRET_KEY", "ocii-iris-secret")
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e

WAZUH_HOST     = os.environ.get("WAZUH_HOST", "192.168.0.95")
WAZUH_PORT     = os.environ.get("WAZUH_PORT", "55000")
WAZUH_USER     = os.environ.get("WAZUH_USER", "wazuh-wui")
WAZUH_PASSWORD = os.environ.get("WAZUH_PASSWORD", "")
<<<<<<< HEAD
GROQ_API_KEY   = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL     = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
=======
OLLAMA_HOST    = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
OLLAMA_MODEL   = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e
ABUSEIPDB_KEY  = os.environ.get("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_KEY", "")
OS_HOST        = WAZUH_HOST
OS_PORT        = "9200"
OS_USER        = "admin"
OS_PASS        = os.environ.get("OS_PASSWORD", "")

<<<<<<< HEAD
# Utilisateurs — mots de passe via variables d'environnement
USERS = {
    "admin": os.environ.get("ADMIN_PASSWORD", "changeme"),
}

# ── Security: HTTP headers ──
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    # Remove server header
    response.headers.pop("Server", None)
    return response
analysis_cache = {}
investigation_history = []   # Historique des investigations complètes
MAX_HISTORY = 200

# Cache token Wazuh (expire toutes les 13 minutes)
_wazuh_token_cache = {"token": None, "expires": 0}

# Cache dashboard (TTL 10s — évite les re-calculs sur refresh rapide)
_dashboard_cache = {"data": None, "key": None, "expires": 0}

# Cache agent details — Syscollector OS + hardware (TTL 120s)
_agent_details_cache = {}  # {agent_id: {"data": ..., "expires": ...}}

# ══════════════════════════════════════════════
# MAPPING MITRE ATT&CK
# ══════════════════════════════════════════════

MITRE_MAP = {
    "authentication_failed": {"tactic": "Credential Access", "technique": "T1110 - Brute Force", "description": "Tentatives répétées d'authentification"},
    "authentication_success": {"tactic": "Initial Access", "technique": "T1078 - Valid Accounts", "description": "Connexion réussie potentiellement compromise"},
    "ssh": {"tactic": "Lateral Movement", "technique": "T1021.004 - SSH", "description": "Connexion SSH distante"},
    "web": {"tactic": "Initial Access", "technique": "T1190 - Exploit Public-Facing Application", "description": "Attaque applicative web"},
    "sophos": {"tactic": "Defense Evasion / Command & Control", "technique": "T1071 - Application Layer Protocol", "description": "Trafic réseau suspect détecté par le firewall"},
    "firewall": {"tactic": "Discovery", "technique": "T1046 - Network Service Discovery", "description": "Scan ou sondage réseau"},
    "malware": {"tactic": "Execution", "technique": "T1204 - User Execution", "description": "Exécution de code malveillant potentielle"},
    "windows": {"tactic": "Execution", "technique": "T1059 - Command and Scripting Interpreter", "description": "Activité système Windows suspecte"},
    "syslog": {"tactic": "Discovery", "technique": "T1082 - System Information Discovery", "description": "Collecte d'informations système"},
    "rootcheck": {"tactic": "Persistence", "technique": "T1547 - Boot or Logon Autostart Execution", "description": "Modification système persistante"},
}

PORT_MAP = {
    "21": "FTP — Transfert de fichiers",
    "22": "SSH — Accès distant sécurisé",
    "23": "Telnet — Accès distant non chiffré (obsolète)",
    "25": "SMTP — Envoi de mails",
    "53": "DNS — Résolution de noms",
    "80": "HTTP — Web non chiffré",
    "110": "POP3 — Réception de mails",
    "143": "IMAP — Accès messagerie (lecture emails à distance)",
    "443": "HTTPS — Web chiffré",
    "445": "SMB — Partage de fichiers Windows",
    "993": "IMAPS — IMAP chiffré",
    "995": "POP3S — POP3 chiffré",
    "1433": "MSSQL — Base de données Microsoft SQL",
    "3306": "MySQL — Base de données",
    "3389": "RDP — Bureau à distance Windows",
    "5432": "PostgreSQL — Base de données",
    "8080": "HTTP alternatif",
    "8443": "HTTPS alternatif",
    "27017": "MongoDB — Base de données NoSQL",
}
=======
USERS = {"admin": "OciiIris2026!"}
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e

# ══════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════

<<<<<<< HEAD
def _generate_csrf():
    """Generate and store a CSRF token in the session."""
    token = secrets.token_hex(32)
    session["_csrf"] = token
    return token

def _validate_csrf():
    """Validate CSRF token from form against session."""
    form_token = request.form.get("_csrf", "")
    session_token = session.pop("_csrf", None)
    return form_token and session_token and secrets.compare_digest(form_token, session_token)


=======
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
<<<<<<< HEAD
        client_ip = request.remote_addr or "unknown"

        # Rate limiting check
        if _is_rate_limited(client_ip):
            error = "Trop de tentatives. Réessayez dans quelques minutes."
            return render_template("login.html", error=error, csrf_token=_generate_csrf())

        # CSRF validation
        if not _validate_csrf():
            error = "Session expirée. Veuillez réessayer."
            return render_template("login.html", error=error, csrf_token=_generate_csrf())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember")

        if USERS.get(username) == password:
            # Regenerate session to prevent fixation
            session.clear()
=======
        username = request.form.get("username")
        password = request.form.get("password")
        remember = request.form.get("remember")
        if USERS.get(username) == password:
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e
            session.permanent = bool(remember)
            session["user"] = username
            return redirect(url_for("index"))
        else:
<<<<<<< HEAD
            _record_attempt(client_ip)
            error = "Identifiants incorrects."
    return render_template("login.html", error=error, csrf_token=_generate_csrf())
=======
            error = "Identifiants incorrects."
    return render_template("login.html", error=error)
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════
# OPENSEARCH
# ══════════════════════════════════════════════

def os_search(query, size=1):
    url = f"https://{OS_HOST}:{OS_PORT}/wazuh-alerts-*/_search"
    try:
<<<<<<< HEAD
        r = requests.post(url, auth=(OS_USER, OS_PASS),
            json={"size": size, "query": query}, verify=False, timeout=15)
        if r.status_code == 200:
            return r.json().get("hits", {}).get("hits", [])
        print(f"[OS] {r.status_code}: {r.text[:100]}")
    except Exception as e:
        print(f"[OS] {e}")
    return []

def get_alert_by_id(alert_id, index=None):
    """Cherche une alerte par _id OpenSearch.
    Stratégie : GET _doc sur l'index exact (rapide) → deviner les indices récents."""
    from datetime import datetime, timedelta
    url_base = f"https://{OS_HOST}:{OS_PORT}"

    def _try_get_doc(idx):
        """Tente GET /{index}/_doc/{id} — accès direct, pas de search."""
        try:
            r = requests.get(
                f"{url_base}/{idx}/_doc/{alert_id}",
                auth=(OS_USER, OS_PASS), verify=False, timeout=8)
            if r.status_code == 200:
                data = r.json()
                if data.get("found"):
                    src = data.get("_source", {})
                    src["_id"] = data.get("_id", alert_id)
                    return src
        except Exception as e:
            print(f"[OS] GET _doc {idx} failed: {e}")
        return None

    # 1. Si l'index exact est fourni, accès direct (< 100ms)
    if index:
        result = _try_get_doc(index)
        if result:
            return result

    # 2. Fallback : essayer les indices des 7 derniers jours
    today = datetime.utcnow().date()
    for days_back in range(8):
        d = today - timedelta(days=days_back)
        idx = f"wazuh-alerts-4.x-{d.strftime('%Y.%m.%d')}"
        result = _try_get_doc(idx)
        if result:
            return result

    print(f"[OS] Alert {alert_id} introuvable dans les indices récents")
    return None

def get_agent_history(agent_name, limit=20):
    """Historique agent : alertes ≥ niveau 5, 7 derniers jours, triées par date desc."""
    url = f"https://{OS_HOST}:{OS_PORT}/wazuh-alerts-*/_search"
    query = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"match_phrase": {"agent.name": agent_name}},
                    {"range": {"rule.level": {"gte": 5}}},
                    {"range": {"@timestamp": {"gte": "now-7d"}}}
                ]
            }
        },
        "_source": ["timestamp", "@timestamp", "rule.id", "rule.description",
                     "rule.level", "rule.groups", "data.srcip", "agent.name"]
    }
    try:
        r = requests.post(url, auth=(OS_USER, OS_PASS), json=query, verify=False, timeout=10)
        if r.status_code == 200:
            return [h.get("_source", {}) for h in r.json().get("hits", {}).get("hits", [])]
    except Exception as e:
        print(f"[OS] agent_history: {e}")
    return []

def get_ip_history(ip, limit=15):
    if not ip:
        return []
    url = f"https://{OS_HOST}:{OS_PORT}/wazuh-alerts-*/_search"
    query = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"match": {"data.srcip": ip}},
                    {"range": {"@timestamp": {"gte": "now-7d"}}}
                ]
            }
        },
        "_source": ["timestamp", "@timestamp", "rule.id", "rule.description",
                     "rule.level", "rule.groups", "data.srcip", "agent.name"]
    }
    try:
        r = requests.post(url, auth=(OS_USER, OS_PASS), json=query, verify=False, timeout=10)
        if r.status_code == 200:
            return [h.get("_source", {}) for h in r.json().get("hits", {}).get("hits", [])]
    except Exception as e:
        print(f"[OS] ip_history: {e}")
    return []
=======
        r = requests.post(
            url,
            auth=(OS_USER, OS_PASS),
            json={"size": size, "query": query},
            verify=False, timeout=10
        )
        if r.status_code == 200:
            return r.json().get("hits", {}).get("hits", [])
        else:
            print(f"[OS] Status {r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"[OS] Erreur : {e}")
    return []

def get_alert_by_id(alert_id):
    hits = os_search({"term": {"id": alert_id}}, size=1)
    if hits:
        return hits[0].get("_source", {})
    return None

def get_agent_history(agent_name, limit=10):
    hits = os_search({"match": {"agent.name": agent_name}}, size=limit)
    return [h.get("_source", {}) for h in hits]
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e

# ══════════════════════════════════════════════
# ENRICHISSEMENT IP
# ══════════════════════════════════════════════

def is_private(ip):
    if not ip:
        return True
<<<<<<< HEAD
    return ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.") or ip == "127.0.0.1"
=======
    return (ip.startswith("192.168") or ip.startswith("10.")
            or ip.startswith("172.") or ip == "127.0.0.1")
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e

def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY or is_private(ip):
        return None
    try:
<<<<<<< HEAD
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}, timeout=10)
        if r.status_code == 200:
            return r.json().get("data", {})
    except Exception as e:
        print(f"[ABUSEIPDB] {e}")
=======
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if r.status_code == 200:
            return r.json().get("data", {})
    except Exception as e:
        print(f"[ABUSEIPDB] Erreur : {e}")
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e
    return None

def check_virustotal(ip):
    if not VIRUSTOTAL_KEY or is_private(ip):
        return None
    try:
<<<<<<< HEAD
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY}, timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            return {
                "stats": data.get("last_analysis_stats", {}),
                "reputation": data.get("reputation", 0),
                "asn": data.get("asn", ""),
                "as_owner": data.get("as_owner", ""),
                "network": data.get("network", ""),
            }
    except Exception as e:
        print(f"[VIRUSTOTAL] {e}")
    return None

def reverse_dns(ip):
    if not ip or is_private(ip):
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# ══════════════════════════════════════════════
# EXTRACTION CONTEXTE
# ══════════════════════════════════════════════

def extract_alert_context(alert):
    data = alert.get("data", {})
    rule = alert.get("rule", {})
    geo  = alert.get("GeoLocation", {})

    src_ip   = data.get("srcip") or data.get("src_ip") or ""
    dst_ip   = data.get("dstip") or data.get("dst_ip") or ""
    src_port = data.get("srcport") or data.get("src_port") or ""
    dst_port = data.get("dstport") or data.get("dst_port") or ""
    protocol = data.get("protocol") or "N/A"
    dst_port_str = str(dst_port)
    port_service = PORT_MAP.get(dst_port_str, f"Port {dst_port_str} — service inconnu")

    full_log = alert.get("full_log", "")
    sophos = {}
    if full_log:
        patterns = {
            "fw_rule_id":    r'fw_rule_id="?([^"\s]+)"?',
            "fw_rule_name":  r'fw_rule_name="([^"]+)"',
            "fw_rule_type":  r'fw_rule_type="([^"]+)"',
            "app_name":      r'app_name="([^"]+)"',
            "app_risk":      r'app_risk=([^\s]+)',
            "app_category":  r'app_category="([^"]+)"',
            "in_interface":  r'in_interface="([^"]+)"',
            "src_mac":       r'src_mac="([^"]+)"',
            "log_subtype":   r'log_subtype="([^"]+)"',
            "log_component": r'log_component="([^"]+)"',
            "severity":      r'severity="([^"]+)"',
            "bytes_sent":    r'bytes_sent=([^\s]+)',
            "bytes_received":r'bytes_received=([^\s]+)',
            "device_model":  r'device_model="([^"]+)"',
            "log_id":        r'log_id="([^"]+)"',
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, full_log)
            if m:
                sophos[key] = m.group(1)

    groups = rule.get("groups", [])
    mitre = None
    for g in groups:
        g_lower = g.lower()
        for key, val in MITRE_MAP.items():
            if key in g_lower:
                mitre = val
                break
        if mitre:
            break
    if not mitre and "sophos" in [g.lower() for g in groups]:
        mitre = MITRE_MAP.get("sophos")

    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "dst_port_str": dst_port_str, "port_service": port_service,
        "protocol": protocol,
        "city": geo.get("city_name", ""),
        "country": geo.get("country_name", ""),
        "region": geo.get("region_name", ""),
        "lat": geo.get("location", {}).get("lat", ""),
        "lon": geo.get("location", {}).get("lon", ""),
        "src_country": data.get("src_country") or "",
        "dst_country": data.get("dst_country") or "",
        "log_subtype": data.get("log_subtype") or sophos.get("log_subtype") or "",
        "sophos": sophos, "mitre": mitre, "groups": groups,
        "firedtimes": rule.get("firedtimes", 0),
        "full_log": full_log,
    }

# ══════════════════════════════════════════════
# ANALYSE IA — GROQ
# ══════════════════════════════════════════════

def build_expert_prompt(alert, ctx, abuse_data, vt_data, ip_history, agent_history):
    rule  = alert.get("rule", {})
    agent = alert.get("agent", {})

    abuse_str = "Non disponible"
    if abuse_data:
        abuse_str = (
            f"Score abus: {abuse_data.get('abuseConfidenceScore', 0)}/100, "
            f"{abuse_data.get('totalReports', 0)} signalements, "
            f"Pays: {abuse_data.get('countryCode', '?')}, "
            f"Type: {abuse_data.get('usageType', '?')}, "
            f"ISP: {abuse_data.get('isp', '?')}, "
            f"Domaine: {abuse_data.get('domain', '?')}"
        )

    vt_str = "Non disponible"
    if vt_data:
        stats = vt_data.get("stats", {})
        vt_str = (
            f"{stats.get('malicious', 0)} moteurs malveillants, "
            f"{stats.get('suspicious', 0)} suspects, "
            f"réputation: {vt_data.get('reputation', 0)}, "
            f"ASN: {vt_data.get('as_owner', '?')}, "
            f"réseau: {vt_data.get('network', '?')}"
        )

    ip_hist_str = "Aucune alerte précédente pour cette IP"
    if ip_history:
        lines = [
            f"[{h.get('timestamp','')[:16]}] {h.get('rule',{}).get('description','?')} (niveau {h.get('rule',{}).get('level','?')}) agent: {h.get('agent',{}).get('name','?')}"
            for h in ip_history[:10]
        ]
        ip_hist_str = f"{len(ip_history)} alertes pour cette IP sur 7 jours:\n" + "\n".join(lines)

    agent_hist_str = "Aucune alerte récente sur cet agent"
    if agent_history:
        # Compter les niveaux pour résumé
        level_counts = {}
        for h in agent_history:
            lvl = h.get('rule', {}).get('level', 0)
            level_counts[lvl] = level_counts.get(lvl, 0) + 1
        level_summary = ", ".join(f"niveau {k}: {v}" for k, v in sorted(level_counts.items(), reverse=True))
        lines = [
            f"[{h.get('timestamp','')[:16]}] {h.get('rule',{}).get('description','?')} (niveau {h.get('rule',{}).get('level','?')}, groupes: {', '.join(h.get('rule',{}).get('groups',[])[:])})"
            for h in agent_history[:10]
        ]
        agent_hist_str = f"{len(agent_history)} alertes sur 7 jours (répartition: {level_summary}):\n" + "\n".join(lines)

    sophos_str = ""
    if ctx["sophos"]:
        s = ctx["sophos"]
        parts = []
        if s.get("log_component"): parts.append(f"Composant: {s['log_component']}")
        if s.get("in_interface"):  parts.append(f"Interface entrante: {s['in_interface']}")
        if s.get("fw_rule_name"):  parts.append(f"Règle firewall: {s['fw_rule_name']} (ID: {s.get('fw_rule_id','?')}, type: {s.get('fw_rule_type','?')})")
        if s.get("app_name"):      parts.append(f"Application: {s['app_name']} (risque={s.get('app_risk','?')}, catégorie={s.get('app_category','?')})")
        if s.get("severity"):      parts.append(f"Sévérité Sophos: {s['severity']}")
        if s.get("src_mac"):       parts.append(f"MAC source: {s['src_mac']}")
        if s.get("bytes_sent"):    parts.append(f"Bytes envoyés: {s['bytes_sent']}")
        if s.get("bytes_received"):parts.append(f"Bytes reçus: {s['bytes_received']}")
        if s.get("device_model"):  parts.append(f"Modèle firewall: {s['device_model']}")
        if s.get("log_id"):        parts.append(f"Log ID: {s['log_id']}")
        if s.get("log_subtype"):   parts.append(f"Action: {s['log_subtype']}")
        if parts:
            sophos_str = "\n\n=== DÉTAILS SOPHOS FIREWALL ===\n" + "\n".join(parts)

    # ── Pattern analysis : contexte firedtimes ──
    firedtimes = ctx.get('firedtimes', 0)
    pattern_str = ""
    if firedtimes > 100:
        pattern_str = f"\n\n=== ANALYSE DE PATTERN ===\nATTENTION : Cette règle a été déclenchée {firedtimes} fois. Cela indique un comportement automatisé/répétitif (scan, brute force, ou flood). Analyse l'intensité et recommande des actions de blocage spécifiques (IP, MAC, interface)."
    elif firedtimes > 10:
        pattern_str = f"\n\n=== ANALYSE DE PATTERN ===\nLa règle a été déclenchée {firedtimes} fois — fréquence modérée. Évalue si c'est un comportement normal récurrent ou une tentative persistante."

    # ── Extraire infos OS de l'agent si disponibles ──
    agent_os = alert.get("agent", {}).get("os", {})
    os_info = ""
    if agent_os:
        os_info = f"\nOS agent: {agent_os.get('name', '')} {agent_os.get('version', '')} ({agent_os.get('platform', '')} {agent_os.get('arch', '')})"

    # ── Log brut (tronqué à 1500 chars pour rester dans les limites) ──
    raw_log = ctx.get("full_log", "")[:1500]
    log_section = f"\n=== LOG BRUT ===\n{raw_log}" if raw_log else ""

    # ── Références CVE depuis la description de la règle ──
    cve_refs = re.findall(r'CVE-\d{4}-\d{4,7}', rule.get('description', '') + ' ' + raw_log)
    cve_str = ", ".join(set(cve_refs)) if cve_refs else "Aucun CVE détecté dans l'alerte"

    system_prompt = f"""Tu es un analyste SOC niveau 3 expert en cybersécurité, certifié CISSP et GIAC, spécialisé en threat hunting et réponse aux incidents.
Tu travailles pour OCII (Océan Indien Informatique) à La Réunion, une société qui gère l'infrastructure IT de PME et collectivités locales.

MÉTHODOLOGIE OBLIGATOIRE — Suis ces étapes dans l'ordre pour chaque analyse :
1. IDENTIFICATION : Quel est l'événement exact ? Extrais les faits du log brut.
2. CONTEXTUALISATION : Qui est l'agent affecté ? Quel est son rôle probable ? L'IP source est-elle interne/externe ?
3. CORRÉLATION : Croise avec l'historique agent ({len(agent_history)} alertes récentes) et l'historique IP. Détecte les patterns.
4. ÉVALUATION : Score le risque réel (pas théorique). Une CVE critique sur un poste isolé ≠ une CVE critique sur un serveur exposé.
5. RECOMMANDATIONS : Des actions SPÉCIFIQUES avec les commandes exactes. Pas de généralités.

RÈGLES :
- Adapte le niveau de menace au contexte OCII (PME réunionnaise, réseau local, pas un datacenter critique)
- Si c'est un faux positif probable, dis-le clairement avec la justification
- Les commandes doivent être exécutables sur l'OS de l'agent ({agent_os.get('platform', 'inconnu')})
- Cite les CVE exacts quand pertinent, avec le score CVSS si tu le connais
- Réponds UNIQUEMENT avec du JSON valide, sans texte avant ou après."""

    user_prompt = f"""Analyse cette alerte Wazuh et produis un rapport d'investigation expert.

=== ALERTE ===
Règle: {rule.get('description', 'N/A')} (ID: {rule.get('id', 'N/A')}, niveau {rule.get('level', 0)}/15)
Groupes: {', '.join(ctx['groups'])}
Fois déclenchée: {ctx['firedtimes']}
Timestamp: {alert.get('timestamp', 'N/A')}
CVE détectés: {cve_str}

=== AGENT ===
Nom: {agent.get('name', 'N/A')} (ID: {agent.get('id', 'N/A')}){os_info}

=== RÉSEAU ===
IP source: {ctx['src_ip']} (port {ctx['src_port']})
IP destination: {ctx['dst_ip']} (port {ctx['dst_port']} → {ctx['port_service']})
Protocole: {ctx['protocol']} | Action: {ctx['log_subtype']}
Géolocalisation: {ctx['city']}, {ctx['region']}, {ctx['country']} ({ctx['src_country']}){sophos_str}
{log_section}
=== THREAT INTELLIGENCE ===
AbuseIPDB: {abuse_str}
VirusTotal: {vt_str}

=== HISTORIQUE IP SOURCE (7 derniers jours) ===
{ip_hist_str}

=== HISTORIQUE AGENT (7 derniers jours, alertes ≥ niveau 5) ===
{agent_hist_str}{pattern_str}

=== FORMAT JSON REQUIS ===
{{
  "niveau_danger": "CRITIQUE | ELEVE | MOYEN | FAIBLE",
  "score_risque": 85,
  "confiance_analyse": 90,
  "type_attaque": "classification précise (ex: CVE exploitation, brute force SSH, port scan, malware execution...)",
  "resume_executif": "3-4 phrases pour un directeur non-technique. Quoi, impact business, urgence.",
  "analyse_technique": "Analyse SOC détaillée : vecteur d'attaque identifié dans le log brut, chaîne d'attaque probable, intentions de l'attaquant, surface d'exposition de l'agent. Minimum 5 phrases.",
  "analyse_port": "Rôle du port {ctx['dst_port']} ({ctx['port_service']}), pourquoi il est ciblé, risque spécifique",
  "analyse_geographique": "Provenance {ctx['country']}/{ctx['city']} — normal ou suspect pour le réseau OCII à La Réunion",
  "correlation": "Patterns détectés en croisant historique agent + historique IP. La règle déclenchée {ctx['firedtimes']} fois indique quoi ? Tendance en hausse/baisse ?",
  "mitre_analyse": "Tactique et technique MITRE ATT&CK (ID + nom). Phase dans la kill chain. Prochaine étape probable de l'attaquant si non bloqué.",
  "faux_positif": "Probabilité en % + justification détaillée basée sur le contexte agent et le log brut",
  "cve_details": "Pour chaque CVE détecté : score CVSS, vecteur, exploitabilité, patch disponible. Si aucun CVE : 'N/A'",
  "ioc": ["IP:x.x.x.x", "CVE-XXXX-XXXXX", "hash:...", "domaine:...", "fichier:...", "port:X"],
  "recommandations": {{
    "immediat_P1": "Action dans les 15 min avec la commande exacte à exécuter",
    "court_terme_P2": "Action dans les 24h — patch, isolation, ou investigation complémentaire",
    "moyen_terme_P3": "Action dans la semaine — hardening, monitoring, règle firewall",
    "long_terme_P4": "Recommandation structurelle — architecture, politique, formation"
  }},
  "commandes_investigation": [
    "commande 1 — ce qu'elle fait",
    "commande 2 — ce qu'elle fait"
  ],
  "references": ["CVE-XXXX-XXXXX (CVSS X.X)", "MITRE TXXXX", "URL NVD ou advisory"]
}}"""

    return system_prompt, user_prompt


def extract_json(text):
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except Exception:
            pass
    return None


def call_groq(system_prompt, user_prompt):
    if not GROQ_API_KEY:
        print("[GROQ] Clé API manquante")
        return None
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt}
                ],
                "temperature": 0.15,
                "max_tokens": 4096,
                "response_format": {"type": "json_object"}
            },
            timeout=30
        )
        print(f"[GROQ] HTTP {r.status_code}")
        if r.status_code == 200:
            content = r.json()["choices"][0]["message"]["content"]
            print(f"[GROQ] Réponse: {content[:300]}")
            return content
        else:
            print(f"[GROQ] Erreur: {r.text[:300]}")
    except Exception as e:
        print(f"[GROQ] Exception: {e}")
    return None


def run_ai_analysis(alert_id, alert, ctx, abuse_data, vt_data, ip_history, agent_history):
    analysis_cache[alert_id] = {"status": "running"}
    print(f"[ASYNC] Démarrage analyse {alert_id} avec {GROQ_MODEL}")
    system_prompt, user_prompt = build_expert_prompt(alert, ctx, abuse_data, vt_data, ip_history, agent_history)
    raw = call_groq(system_prompt, user_prompt)
    if raw:
        result = extract_json(raw)
        if result:
            result["status"] = "done"
            result["alert_id"]    = alert_id
            result["_timestamp"]  = alert.get("timestamp", "")
            result["_agent_name"] = alert.get("agent", {}).get("name", "")
            result["_rule_desc"]  = alert.get("rule", {}).get("description", "")
            result["_rule_level"] = alert.get("rule", {}).get("level", 0)
            result["_src_ip"]     = ctx.get("src_ip", "")
            analysis_cache[alert_id] = result
            # ── Enregistrement dans l'historique ──
            investigation_history.insert(0, {
                "alert_id":    alert_id,
                "timestamp":   result["_timestamp"],
                "agent_name":  result["_agent_name"],
                "rule_desc":   result["_rule_desc"],
                "rule_level":  result["_rule_level"],
                "src_ip":      result["_src_ip"],
                "niveau_danger": result.get("niveau_danger", ""),
                "score_risque":  result.get("score_risque", 0),
                "type_attaque":  result.get("type_attaque", ""),
                "resume_executif": result.get("resume_executif", ""),
            })
            if len(investigation_history) > MAX_HISTORY:
                investigation_history.pop()
            print(f"[ASYNC] OK — niveau={result.get('niveau_danger')}")
            return
    analysis_cache[alert_id] = {"status": "error", "message": "Groq n'a pas retourné de réponse valide"}
=======
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10
        )
        if r.status_code == 200:
            return r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except Exception as e:
        print(f"[VIRUSTOTAL] Erreur : {e}")
    return None

# ══════════════════════════════════════════════
# ANALYSE IA
# ══════════════════════════════════════════════

def build_prompt(alert_data, abuse_data, vt_data, history):
    src_ip   = (alert_data.get("data", {}).get("srcip")
                or alert_data.get("data", {}).get("src_ip") or "N/A")
    agent    = alert_data.get("agent", {}).get("name", "N/A")
    rule     = alert_data.get("rule", {}).get("description", "N/A")
    rule_id  = alert_data.get("rule", {}).get("id", "N/A")
    level    = alert_data.get("rule", {}).get("level", 0)
    groups   = alert_data.get("rule", {}).get("groups", [])
    ts       = alert_data.get("timestamp", "N/A")
    full_log = alert_data.get("full_log", "")
    if full_log:
        full_log = full_log[:400]
    else:
        full_log = "Non disponible"

    if abuse_data:
        abuse_str = (
            "Score " + str(abuse_data.get("abuseConfidenceScore", 0)) + "/100 | "
            + str(abuse_data.get("totalReports", 0)) + " signalements | "
            + "Pays: " + str(abuse_data.get("countryCode", "?")) + " | "
            + "Type: " + str(abuse_data.get("usageType", "?")) + " | "
            + "ISP: " + str(abuse_data.get("isp", "?"))
        )
    else:
        abuse_str = "Indisponible (IP privee ou cle non configuree)"

    if vt_data:
        vt_str = (
            "Malveillant: " + str(vt_data.get("malicious", 0)) + " | "
            + "Suspect: " + str(vt_data.get("suspicious", 0)) + " | "
            + "Inoffensif: " + str(vt_data.get("harmless", 0))
        )
    else:
        vt_str = "Indisponible (IP privee ou cle non configuree)"

    if history:
        hist_lines = []
        for h in history[:5]:
            hist_lines.append(
                "- [" + h.get("timestamp", "")[:19] + "] "
                + "Regle " + h.get("rule", {}).get("id", "?")
                + " (niv." + str(h.get("rule", {}).get("level", "?")) + ") : "
                + h.get("rule", {}).get("description", "?")
            )
        hist_str = "\n".join(hist_lines)
    else:
        hist_str = "Aucun historique disponible."

    groups_str = ", ".join(groups) if groups else "N/A"

    prompt = (
        "Tu es un analyste SOC niveau 2 expert en cybersecurite. "
        "Analyse cette alerte et produis un verdict precis.\n\n"
        "ALERTE:\n"
        "Timestamp: " + ts + "\n"
        "Agent: " + agent + "\n"
        "Regle: " + rule + "\n"
        "ID Regle: " + str(rule_id) + "\n"
        "Niveau: " + str(level) + "/15\n"
        "Groupes: " + groups_str + "\n"
        "IP source: " + src_ip + "\n"
        "Log: " + full_log + "\n\n"
        "REPUTATION IP:\n"
        "AbuseIPDB: " + abuse_str + "\n"
        "VirusTotal: " + vt_str + "\n\n"
        "HISTORIQUE:\n"
        + hist_str + "\n\n"
        "Reponds avec ce JSON et rien d autre:\n"
        '{"niveau_danger": "CRITIQUE ou ELEVE ou MOYEN ou FAIBLE", "score": 0, "resume": "analyse en 2 phrases", "action": "action concrete"}'
    )
    return prompt


def analyze_with_ollama(alert_data, abuse_data, vt_data, history):
    prompt = build_prompt(alert_data, abuse_data, vt_data, history)
    print(f"[OLLAMA] Envoi prompt ({len(prompt)} chars) au modele {OLLAMA_MODEL}")
    try:
        r = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                    "num_predict": 300
                }
            },
            timeout=300
        )
        print(f"[OLLAMA] Status: {r.status_code}")
        if r.status_code == 200:
            raw = r.json().get("response", "")
            print(f"[OLLAMA RAW] {raw[:500]}")
            start = raw.find("{")
            end   = raw.rfind("}") + 1
            if start != -1 and end > start:
                result = json.loads(raw[start:end])
                print(f"[OLLAMA] Resultat parse: {result}")
                return result
            else:
                print("[OLLAMA] Pas de JSON trouve dans la reponse")
        else:
            print(f"[OLLAMA] Erreur HTTP: {r.text[:200]}")
    except Exception as e:
        print(f"[OLLAMA] Erreur : {e}")

    return {
        "niveau_danger": "INCONNU",
        "score": 0,
        "resume": "Analyse IA indisponible.",
        "action": "Investiguer manuellement."
    }
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e

# ══════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════

@app.route("/")
@login_required
def index():
    return render_template("index.html")

<<<<<<< HEAD

=======
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e
@app.route("/investigate")
@login_required
def investigate():
    alert_id = request.args.get("alert_id")
<<<<<<< HEAD
    alert_index = request.args.get("_index")  # index OpenSearch (optionnel, accélère la recherche)
    if not alert_id or not re.match(r'^[\w\-]{1,128}$', alert_id):
        return render_template("error.html", message="Identifiant d'alerte invalide ou manquant."), 400

    # Validate _index — reject invalid OpenSearch index names with 400
    if alert_index:
        if not re.match(r'^[\w\-\.]{1,256}$', alert_index):
            return render_template("error.html", message="Paramètre d'index invalide."), 400

    alert = get_alert_by_id(alert_id, index=alert_index)
    if not alert:
        return render_template("error.html", message="Alerte introuvable dans les indices récents.")

    ctx           = extract_alert_context(alert)
    src_ip        = ctx["src_ip"]
    abuse_data    = check_abuseipdb(src_ip) if not is_private(src_ip) else None
    vt_data       = check_virustotal(src_ip) if not is_private(src_ip) else None
    rdns          = reverse_dns(src_ip) if not is_private(src_ip) else None
    agent_name    = alert.get("agent", {}).get("name", "")
    agent_history = get_agent_history(agent_name) if agent_name else []
    ip_history    = get_ip_history(src_ip) if src_ip else []

    if alert_id not in analysis_cache or analysis_cache[alert_id].get("status") == "error":
        t = threading.Thread(
            target=run_ai_analysis,
            args=(alert_id, alert, ctx, abuse_data, vt_data, ip_history, agent_history),
            daemon=True
        )
        t.start()

    return render_template("investigate.html",
        alert=alert, ctx=ctx, src_ip=src_ip, rdns=rdns,
        abuse_data=abuse_data, vt_data=vt_data,
        agent_history=agent_history, ip_history=ip_history,
        alert_id=alert_id
    )


@app.route("/investigate/agent")
@login_required
def investigate_agent():
    """Récupère la dernière alerte critique d'un agent et redirige vers investigate."""
    agent_name = request.args.get("name", "").strip()
    if not agent_name or len(agent_name) > 128 or not re.match(r'^[\w\-\.]+$', agent_name):
        return render_template("error.html", message="Nom de machine invalide ou manquant.")

    print(f"[AGENT] Investigation machine: {agent_name}")

    url = f"https://{OS_HOST}:{OS_PORT}/wazuh-alerts-*/_search"

    # Stratégie : essai exact → puis partiel → puis toutes alertes récentes
    queries = [
        # 1. Correspondance exacte sur le nom
        {"bool": {"must": [{"match_phrase": {"agent.name": agent_name}}, {"range": {"rule.level": {"gte": 5}}}]}},
        # 2. Recherche partielle (wildcard)
        {"bool": {"must": [{"wildcard": {"agent.name": {"value": f"*{agent_name.lower()}*"}}}, {"range": {"rule.level": {"gte": 5}}}]}},
        # 3. Dernière alerte disponible (niveau ≥ 5) — fallback démo
        {"range": {"rule.level": {"gte": 5}}},
    ]

    for i, query in enumerate(queries):
        try:
            r = requests.post(
                url, auth=(OS_USER, OS_PASS),
                json={"size": 1, "query": query, "sort": [{"@timestamp": {"order": "desc"}}]},
                verify=False, timeout=20
            )
            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                if hits:
                    alert_id = hits[0].get("_id")
                    alert_index = hits[0].get("_index", "")
                    if alert_id:
                        strategy = ["exact", "partiel", "fallback"][i]
                        print(f"[AGENT] Alerte trouvée ({strategy}) → {alert_id}")
                        return redirect(url_for("investigate", alert_id=alert_id, _index=alert_index))
        except Exception as e:
            print(f"[AGENT] Erreur stratégie {i}: {e}")

    return render_template("error.html",
        message=f"Aucune alerte trouvée pour la machine {agent_name}.")


@app.route("/api/ai_status/<alert_id>")
@login_required
def ai_status(alert_id):
    result = analysis_cache.get(alert_id, {"status": "pending"})
    return jsonify(result)


@app.route("/api/status")
@login_required
def status():
    return jsonify({"status": "ok", "app": "OCII-IRIS"})


# ══════════════════════════════════════════════
# SNMP TRAP RECEIVER — Endpoint interne
# ══════════════════════════════════════════════
SNMP_API_TOKEN = os.environ.get("OCII_API_TOKEN", "snmp-internal-token")

@app.route("/api/snmp_trap", methods=["POST"])
def receive_snmp_trap():
    """
    Endpoint interne appelé par snmp_receiver.py.
    Reçoit un trap SNMP formaté, l'injecte dans le pipeline d'investigation IA.
    Authentification par token X-SNMP-Token (non exposé publiquement).
    """
    # Vérification du token interne
    token = request.headers.get("X-SNMP-Token", "")
    if token != SNMP_API_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    alert = request.get_json(silent=True)
    if not alert or "_id" not in alert or "_source" not in alert:
        return jsonify({"error": "Payload invalide — champs _id et _source requis"}), 400

    alert_id = alert["_id"]

    # Éviter les doublons si le trap arrive plusieurs fois
    if alert_id in analysis_cache:
        return jsonify({"status": "already_processing", "alert_id": alert_id}), 200

    analysis_cache[alert_id] = {"status": "pending", "source": "snmp_trap"}

    # Extraire le contexte depuis l'alerte SNMP
    ctx = extract_alert_context(alert)

    # Enrichissement IP si disponible
    src_ip = alert.get("_source", {}).get("data", {}).get("srcip", "")
    abuse_data, vt_data, ip_history, agent_history = {}, {}, [], []

    if src_ip and not is_private(src_ip):
        abuse_data   = check_abuseipdb(src_ip)
        vt_data      = check_virustotal(src_ip)
        ip_history   = get_ip_history(src_ip)

    agent_name = alert.get("_source", {}).get("agent", {}).get("name", "")
    if agent_name:
        agent_history = get_agent_history(agent_name)

    # Lancement de l'analyse IA en arrière-plan
    thread = threading.Thread(
        target=run_ai_analysis,
        args=(alert_id, alert, ctx, abuse_data, vt_data, ip_history, agent_history),
        daemon=True
    )
    thread.start()

    return jsonify({
        "status":   "investigation_started",
        "alert_id": alert_id,
        "source":   "snmp_trap",
        "poll_url": f"/api/ai_status/{alert_id}"
    }), 200


# ══════════════════════════════════════════════
# WAZUH API — agents
# ══════════════════════════════════════════════

def get_wazuh_token():
    now = time.time()
    if _wazuh_token_cache["token"] and now < _wazuh_token_cache["expires"]:
        return _wazuh_token_cache["token"]
    try:
        r = requests.post(
            f"https://{WAZUH_HOST}:{WAZUH_PORT}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASSWORD),
            verify=False, timeout=10
        )
        if r.status_code == 200:
            token = r.json().get("data", {}).get("token", "")
            _wazuh_token_cache["token"]   = token
            _wazuh_token_cache["expires"] = now + 780
            return token
    except Exception as e:
        print(f"[WAZUH] Auth error: {e}")
    return None


def get_wazuh_agents():
    token = get_wazuh_token()
    if not token:
        return []
    try:
        r = requests.get(
            f"https://{WAZUH_HOST}:{WAZUH_PORT}/agents",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 100, "sort": "-dateAdd"},
            verify=False, timeout=10
        )
        if r.status_code == 200:
            return r.json().get("data", {}).get("affected_items", [])
    except Exception as e:
        print(f"[WAZUH] Agents error: {e}")
    return []


# ══════════════════════════════════════════════
# OPENSEARCH — helpers étendus
# ══════════════════════════════════════════════

def os_query(body, timeout=15):
    """Lance une requête OpenSearch complète (body libre)."""
    url = f"https://{OS_HOST}:{OS_PORT}/wazuh-alerts-*/_search"
    try:
        r = requests.post(url, auth=(OS_USER, OS_PASS),
            json=body, verify=False, timeout=timeout)
        if r.status_code == 200:
            return r.json()
        print(f"[OS] {r.status_code}: {r.text[:100]}")
    except Exception as e:
        print(f"[OS] {e}")
    return {}


# ── Plages temporelles OpenSearch ──
_OS_RANGES = {
    '15m': 'now-15m', '1h':  'now-1h',  '6h':  'now-6h',
    '24h': 'now-24h', '7d':  'now-7d', '30d': 'now-30d',
}

def build_time_filter(range_str, from_ts=None, to_ts=None):
    """Construit le filtre OpenSearch @timestamp selon la plage choisie.
    Retourne un dict de type query, ou None si plage = 'all'."""
    if range_str == 'custom' and from_ts:
        rng = {"gte": from_ts}
        if to_ts:
            rng["lte"] = to_ts
        return {"range": {"@timestamp": rng}}
    gte = _OS_RANGES.get(range_str)
    if gte:
        return {"range": {"@timestamp": {"gte": gte, "lte": "now"}}}
    return None   # 'all' → pas de filtre temporel


def _with_time(base_query, time_filter):
    """Combine une query de base et un filtre temporel en bool must."""
    if not time_filter:
        return base_query
    return {"bool": {"must": [base_query, time_filter]}}


def get_recent_alerts(size=50, min_level=5, time_filter=None):
    """Retourne les <size> alertes les plus récentes (niveau >= min_level)."""
    level_q = {"range": {"rule.level": {"gte": min_level}}}
    query   = _with_time(level_q, time_filter)
    data    = os_query({
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": query,
        "_source": ["timestamp", "@timestamp", "agent.name", "agent.id",
                     "rule.level", "rule.id", "rule.description", "rule.groups",
                     "data.srcip", "data.src_ip"],
    })
    hits   = data.get("hits", {}).get("hits", [])
    result = []
    for h in hits:
        src = h.get("_source", {})
        result.append({
            "_id":         h.get("_id"),
            "_index":      h.get("_index", ""),
            "timestamp":   src.get("timestamp", src.get("@timestamp", "")),
            "agent_name":  src.get("agent", {}).get("name", ""),
            "agent_id":    src.get("agent", {}).get("id", ""),
            "level":       src.get("rule", {}).get("level", 0),
            "rule_id":     src.get("rule", {}).get("id", ""),
            "description": src.get("rule", {}).get("description", ""),
            "groups":      src.get("rule", {}).get("groups", []),
            "src_ip":      src.get("data", {}).get("srcip") or src.get("data", {}).get("src_ip") or "",
        })
    return result


def get_dashboard_stats(time_filter=None):
    """Stats dashboard — UNE SEULE requête OS avec aggregations."""
    base  = time_filter if time_filter else {"match_all": {}}
    data  = os_query({
        "size": 0,
        "track_total_hits": True,
        "query": base,
        "aggs": {
            "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
            "elevated":  {"filter": {"range": {"rule.level": {"gte": 9, "lte": 11}}}},
        },
    }, timeout=8)

    total_obj   = data.get("hits", {}).get("total", {})
    total_count = total_obj.get("value", 0) if isinstance(total_obj, dict) else (total_obj or 0)
    aggs        = data.get("aggregations", {})

    return {
        "alerts": {
            "total":    total_count,
            "critical": aggs.get("critical", {}).get("doc_count", 0),
            "elevated": aggs.get("elevated",  {}).get("doc_count", 0),
        },
        "investigations": {
            "total":  len(investigation_history),
            "cached": len(analysis_cache),
        },
    }


# ══════════════════════════════════════════════
# NOUVELLES ROUTES — SOC Platform
# ══════════════════════════════════════════════

@app.route("/agents")
@login_required
def agents_page():
    return render_template("agents.html")


@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html")


@app.route("/history")
@login_required
def history_page():
    return render_template("history.html")


# ── API endpoints ──

@app.route("/api/dashboard")
@login_required
def api_dashboard():
    """Dashboard data — plage temporelle + appels parallèles. Cache TTL 10s."""
    range_str, from_ts, to_ts = _sanitize_range_params()

    # ── Cache check ──
    cache_key = f"{range_str}|{from_ts}|{to_ts}"
    now = time.time()
    if _dashboard_cache["data"] and _dashboard_cache["key"] == cache_key and now < _dashboard_cache["expires"]:
        return jsonify(_dashboard_cache["data"])

    time_filter = build_time_filter(range_str, from_ts, to_ts)

    with ThreadPoolExecutor(max_workers=3) as ex:
        f_stats  = ex.submit(get_dashboard_stats, time_filter)
        f_agents = ex.submit(get_wazuh_agents)
        f_feed   = ex.submit(get_recent_alerts, 15, 9, time_filter)

    stats  = f_stats.result()
    agents = f_agents.result()
    feed   = f_feed.result()

    active  = sum(1 for a in agents if a.get("status") == "active")
    disconn = sum(1 for a in agents if a.get("status") != "active")
    stats["agents"]       = {"total": len(agents), "active": active, "disconnected": disconn}
    stats["critical_feed"]= feed
    stats["range"]        = range_str

    # ── Store in cache ──
    _dashboard_cache["data"]    = stats
    _dashboard_cache["key"]     = cache_key
    _dashboard_cache["expires"] = now + 10

    return jsonify(stats)


@app.route("/api/agents")
@login_required
def api_agents():
    agents = get_wazuh_agents()
    # Restrict exposed fields — don't leak full Wazuh agent metadata
    ALLOWED_FIELDS = {"id", "name", "ip", "status", "os", "version", "dateAdd", "lastKeepAlive"}
    safe_agents = [
        {k: v for k, v in a.items() if k in ALLOWED_FIELDS}
        for a in agents
    ]
    return jsonify(safe_agents)


_VALID_RANGES = {'15m', '1h', '6h', '24h', '7d', '30d', 'all', 'custom'}
_ISO_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}')

def _sanitize_range_params():
    """Validate and return (range_str, from_ts, to_ts) from request args."""
    range_str = request.args.get("range", "24h")
    if range_str not in _VALID_RANGES:
        range_str = "24h"
    from_ts = request.args.get("from_ts", None)
    to_ts   = request.args.get("to_ts", None)
    # Validate ISO timestamps
    if from_ts and not _ISO_RE.match(from_ts):
        from_ts = None
    if to_ts and not _ISO_RE.match(to_ts):
        to_ts = None
    return range_str, from_ts, to_ts


@app.route("/api/alerts")
@login_required
def api_alerts():
    try:
        min_level = max(0, min(int(request.args.get("min_level", 5)), 15))
        size      = max(1, min(int(request.args.get("size", 200)), 500))
    except (ValueError, TypeError):
        min_level, size = 5, 200
    range_str, from_ts, to_ts = _sanitize_range_params()
    time_filter = build_time_filter(range_str, from_ts, to_ts)
    alerts      = get_recent_alerts(size=size, min_level=min_level, time_filter=time_filter)
    return jsonify({"alerts": alerts, "count": len(alerts), "range": range_str})


@app.route("/api/history")
@login_required
def api_history():
    return jsonify(investigation_history)


@app.route("/api/agent_details/<agent_id>")
@login_required
def api_agent_details(agent_id):
    """Détails agent : info Wazuh + OS + hardware (Syscollector). Cache 120s."""
    # Validate agent_id (numeric, max 3 digits)
    if not re.match(r'^\d{1,3}$', str(agent_id)):
        return jsonify({"error": "Agent ID invalide"}), 400
    now = time.time()
    cached = _agent_details_cache.get(agent_id)
    if cached and now < cached["expires"]:
        return jsonify(cached["data"])

    token = get_wazuh_token()
    if not token:
        return jsonify({"error": "Wazuh auth failed"}), 502

    headers = {"Authorization": f"Bearer {token}"}
    base    = f"https://{WAZUH_HOST}:{WAZUH_PORT}"

    def _wazuh_get(path):
        try:
            r = requests.get(f"{base}{path}", headers=headers,
                             verify=False, timeout=10)
            if r.status_code == 200:
                items = r.json().get("data", {}).get("affected_items", [])
                return items[0] if items else {}
        except Exception as e:
            print(f"[WAZUH] {path} error: {e}")
        return {}

    # Appels parallèles : agent info + OS + hardware
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_agent = ex.submit(_wazuh_get, f"/agents?agents_list={agent_id}")
        f_os    = ex.submit(_wazuh_get, f"/syscollector/{agent_id}/os")
        f_hw    = ex.submit(_wazuh_get, f"/syscollector/{agent_id}/hardware")

    agent_info = f_agent.result()
    os_info    = f_os.result()
    hw_info    = f_hw.result()

    # Formatage RAM
    ram_total = hw_info.get("ram", {}).get("total", 0)
    ram_free  = hw_info.get("ram", {}).get("free", 0)
    ram_total_gb = round(ram_total / (1024 * 1024), 1) if ram_total else 0
    ram_free_gb  = round(ram_free / (1024 * 1024), 1) if ram_free else 0

    result = {
        "agent": {
            "id":          agent_info.get("id", agent_id),
            "name":        agent_info.get("name", ""),
            "ip":          agent_info.get("ip", ""),
            "status":      agent_info.get("status", ""),
            "os_name":     agent_info.get("os", {}).get("name", ""),
            "os_version":  agent_info.get("os", {}).get("version", ""),
            "group":       agent_info.get("group", []),
            "last_keep_alive": agent_info.get("lastKeepAlive", ""),
            "date_add":    agent_info.get("dateAdd", ""),
        },
        "os": {
            "hostname":     os_info.get("hostname", ""),
            "os_name":      os_info.get("os_name", ""),
            "os_version":   os_info.get("os_version", ""),
            "architecture": os_info.get("architecture", ""),
            "os_release":   os_info.get("os_release", ""),
        },
        "hardware": {
            "cpu_name":    hw_info.get("cpu", {}).get("name", ""),
            "cpu_cores":   hw_info.get("cpu", {}).get("cores", 0),
            "cpu_mhz":     hw_info.get("cpu", {}).get("mhz", 0),
            "ram_total_gb": ram_total_gb,
            "ram_free_gb":  ram_free_gb,
            "ram_usage_pct": round((1 - ram_free / ram_total) * 100, 1) if ram_total else 0,
            "board_serial": hw_info.get("board_serial", ""),
        },
    }

    # Store in cache (120s)
    _agent_details_cache[agent_id] = {"data": result, "expires": now + 120}
    return jsonify(result)


# ── Grafana Webhook (compatibilité) ──

@app.route("/api/grafana_webhook", methods=["POST"])
def grafana_webhook():
    """Reçoit les alertes Grafana et redirige vers une investigation."""
    payload = request.get_json(silent=True) or {}
    alert_id = (
        payload.get("alert_id") or
        payload.get("alertId") or
        (payload.get("alerts", [{}])[0].get("fingerprint") if payload.get("alerts") else None)
    )
    if alert_id:
        return jsonify({"status": "received", "alert_id": alert_id,
                        "investigate_url": f"/investigate?alert_id={alert_id}"}), 200
    return jsonify({"status": "received", "message": "Pas d'alert_id dans le payload"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
=======
    print(f"[DEBUG] alert_id recu: {alert_id}")

    if not alert_id:
        return render_template("error.html", message="Aucun identifiant d'alerte fourni.")

    alert = get_alert_by_id(alert_id)
    print(f"[DEBUG] alerte recuperee: {bool(alert)}")

    if not alert:
        return render_template("error.html", message=f"Alerte {alert_id} introuvable dans OpenSearch.")

    src_ip = (alert.get("data", {}).get("srcip")
              or alert.get("data", {}).get("src_ip") or "")
    print(f"[DEBUG] src_ip: {src_ip}")

    abuse_data = check_abuseipdb(src_ip) if not is_private(src_ip) else None
    vt_data    = check_virustotal(src_ip) if not is_private(src_ip) else None
    print(f"[DEBUG] abuse: {bool(abuse_data)} | vt: {bool(vt_data)}")

    agent_name = alert.get("agent", {}).get("name", "")
    history    = get_agent_history(agent_name) if agent_name else []
    print(f"[DEBUG] historique: {len(history)} alertes")

    print("[DEBUG] lancement analyse IA...")
    ai_result = analyze_with_ollama(alert, abuse_data, vt_data, history)
    print(f"[DEBUG] resultat IA: {ai_result}")

    return render_template("investigate.html",
        alert=alert, src_ip=src_ip,
        abuse_data=abuse_data, vt_data=vt_data,
        history=history, ai=ai_result, alert_id=alert_id
    )

@app.route("/api/status")
def status():
    return jsonify({"status": "ok", "app": "OCII-IRIS"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
>>>>>>> d720f2b6649172b6438eed3b49b13a24f226495e
