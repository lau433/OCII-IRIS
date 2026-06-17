#!/usr/bin/env python3
"""
OCII-IRIS — SNMP Trap Receiver v2.0 (pure socket, no pysnmp)
=============================================================
Daemon UDP qui écoute les traps SNMP v2c sur le port 162.
Parse les paquets BER/ASN.1 manuellement — aucune dépendance externe.

Auteur : Laurent VIDOT — OCII, La Réunion
"""

import os
import socket
import struct
import time
import logging
import threading
import requests
from datetime import datetime, timezone

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
LISTEN_ADDRESS = os.environ.get("SNMP_LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT    = int(os.environ.get("SNMP_LISTEN_PORT", "162"))
COMMUNITY      = os.environ.get("SNMP_COMMUNITY", "public")
OCII_IRIS_URL  = os.environ.get("OCII_IRIS_URL", "http://ocii-iris:5000")
OCII_API_TOKEN = os.environ.get("OCII_API_TOKEN", "snmp-internal-token")
LOG_LEVEL      = os.environ.get("LOG_LEVEL", "INFO")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [SNMP-RCV] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("snmp_receiver")

# ──────────────────────────────────────────────
# Mapping OID → Catégorie
# ──────────────────────────────────────────────
OID_CATEGORY_MAP = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
    "1.3.6.1.4.1.2604.5":  "sophos_firewall",
    "1.3.6.1.4.1.9.9.41.2":"cisco_syslog",
}

SEVERITY_MAP = {
    "coldStart":             "low",
    "warmStart":             "low",
    "linkDown":              "medium",
    "linkUp":                "low",
    "authenticationFailure": "high",
    "egpNeighborLoss":       "medium",
    "sophos_firewall":       "high",
    "cisco_syslog":          "medium",
    "snmp_generic":          "medium",
}

MITRE_MAP = {
    "authenticationFailure": {"tactic": "Credential Access",  "technique": "T1110 - Brute Force"},
    "linkDown":              {"tactic": "Impact",              "technique": "T1499 - Endpoint Denial of Service"},
    "sophos_firewall":       {"tactic": "Defense Evasion",     "technique": "T1071 - Application Layer Protocol"},
    "cisco_syslog":          {"tactic": "Discovery",           "technique": "T1046 - Network Service Discovery"},
    "default":               {"tactic": "Discovery",           "technique": "T1082 - System Information Discovery"},
}

# ──────────────────────────────────────────────
# Parser BER/ASN.1 minimal
# ──────────────────────────────────────────────
def _read_length(data, pos):
    """Lit la longueur BER à la position pos. Retourne (longueur, nouvelle_pos)."""
    if pos >= len(data):
        return 0, pos
    b = data[pos]
    pos += 1
    if b & 0x80 == 0:
        return b, pos
    num_bytes = b & 0x7F
    length = 0
    for _ in range(num_bytes):
        if pos >= len(data):
            return 0, pos
        length = (length << 8) | data[pos]
        pos += 1
    return length, pos


def _read_oid(data, pos, length):
    """Décode un OID BER en notation pointée."""
    if length == 0:
        return ""
    end = pos + length
    components = []
    first = data[pos]
    components.append(str(first // 40))
    components.append(str(first % 40))
    pos += 1
    value = 0
    while pos < end:
        b = data[pos]
        pos += 1
        value = (value << 7) | (b & 0x7F)
        if (b & 0x80) == 0:
            components.append(str(value))
            value = 0
    return ".".join(components)


def parse_snmp_trap(raw_data):
    """
    Parse minimale d'un paquet SNMP v2c.
    Retourne (community, trap_oid, varbinds_text).
    En cas d'échec, retourne des valeurs par défaut.
    """
    community  = "unknown"
    trap_oid   = "unknown"
    varbinds   = []

    try:
        pos = 0
        # Tag SEQUENCE (0x30)
        if raw_data[pos] != 0x30:
            return community, trap_oid, varbinds
        pos += 1
        _, pos = _read_length(raw_data, pos)

        # Version (INTEGER)
        if raw_data[pos] != 0x02:
            return community, trap_oid, varbinds
        pos += 1
        vlen, pos = _read_length(raw_data, pos)
        pos += vlen  # skip version value

        # Community (OCTET STRING 0x04)
        if pos < len(raw_data) and raw_data[pos] == 0x04:
            pos += 1
            clen, pos = _read_length(raw_data, pos)
            community = raw_data[pos:pos+clen].decode("latin-1", errors="replace")
            pos += clen

        # PDU (Trap-PDU = 0xa7 pour v2c)
        if pos < len(raw_data) and raw_data[pos] in (0xa7, 0xa4):
            pos += 1
            _, pos = _read_length(raw_data, pos)
            # Sauter request-id, error-status, error-index (3 INTEGER)
            for _ in range(3):
                if pos < len(raw_data) and raw_data[pos] == 0x02:
                    pos += 1
                    vlen, pos = _read_length(raw_data, pos)
                    pos += vlen

            # VarBindList (SEQUENCE)
            if pos < len(raw_data) and raw_data[pos] == 0x30:
                pos += 1
                _, pos = _read_length(raw_data, pos)

                while pos < len(raw_data):
                    # Chaque VarBind est une SEQUENCE
                    if raw_data[pos] != 0x30:
                        break
                    pos += 1
                    vblen, pos = _read_length(raw_data, pos)
                    vb_end = pos + vblen

                    # OID du varbind
                    if pos < len(raw_data) and raw_data[pos] == 0x06:
                        pos += 1
                        olen, pos = _read_length(raw_data, pos)
                        oid_val = _read_oid(raw_data, pos, olen)
                        pos += olen

                        # Valeur associée
                        val_tag = raw_data[pos] if pos < len(raw_data) else 0
                        pos += 1
                        val_len, pos = _read_length(raw_data, pos)
                        val_raw = raw_data[pos:pos+val_len]
                        pos += val_len

                        # Si c'est snmpTrapOID.0 → extraire l'OID cible
                        if oid_val == "1.3.6.1.6.3.1.1.4.1.0" and val_tag == 0x06:
                            trap_oid = _read_oid(val_raw, 0, len(val_raw))
                        else:
                            try:
                                val_str = val_raw.decode("latin-1", errors="replace")
                            except Exception:
                                val_str = val_raw.hex()
                            varbinds.append(f"{oid_val} = {val_str}")

                    pos = vb_end  # passer au varbind suivant

    except Exception as e:
        log.debug(f"Erreur parsing BER : {e}")

    return community, trap_oid, varbinds


# ──────────────────────────────────────────────
# Formatage alerte OCII-IRIS
# ──────────────────────────────────────────────
def _severity_to_level(severity):
    return {"high": 12, "medium": 8, "low": 4}.get(severity, 6)


def format_trap_as_alert(source_ip, community, trap_oid, varbinds):
    category = OID_CATEGORY_MAP.get(trap_oid, "snmp_generic")
    severity = SEVERITY_MAP.get(category, "medium")
    mitre    = MITRE_MAP.get(category, MITRE_MAP["default"])
    ts       = datetime.now(timezone.utc).isoformat()
    alert_id = f"snmp-{source_ip.replace('.', '-')}-{int(time.time())}"

    description = (
        f"SNMP Trap [{category}] depuis {source_ip} "
        f"(community: {community}) | OID: {trap_oid}"
    )
    if varbinds:
        description += "\n" + "\n".join(varbinds[:10])

    return {
        "_id": alert_id,
        "_source": {
            "timestamp": ts,
            "rule": {
                "id":          f"snmp-{category}",
                "description": description,
                "level":       _severity_to_level(severity),
                "groups":      ["snmp", category],
                "mitre": {
                    "tactic":    [mitre["tactic"]],
                    "technique": [mitre["technique"]],
                    "id":        [mitre["technique"].split(" ")[0]],
                },
            },
            "agent": {"name": source_ip, "ip": source_ip},
            "data": {
                "srcip":    source_ip,
                "trap_oid": trap_oid,
                "category": category,
                "community": community,
                "var_binds": varbinds,
            },
            "location": f"snmp-trap-receiver:{LISTEN_PORT}",
        },
    }


# ──────────────────────────────────────────────
# Envoi vers OCII-IRIS (avec retry)
# ──────────────────────────────────────────────
def push_to_ocii_iris(alert):
    url     = f"{OCII_IRIS_URL}/api/snmp_trap"
    headers = {"Content-Type": "application/json", "X-SNMP-Token": OCII_API_TOKEN}

    for attempt in range(1, 4):
        try:
            r = requests.post(url, json=alert, headers=headers, timeout=10)
            if r.status_code == 200:
                log.info(f"✅ Trap transmis → OCII-IRIS | alert_id={alert['_id']}")
                return
            log.warning(f"OCII-IRIS réponse {r.status_code} (tentative {attempt}/3)")
        except requests.exceptions.ConnectionError:
            log.warning(f"OCII-IRIS injoignable (tentative {attempt}/3) — retry 5s")
            time.sleep(5)
        except Exception as e:
            log.error(f"Erreur envoi : {e}")
            break

    log.error(f"❌ Échec transmission trap {alert['_id']} après 3 tentatives")


# ──────────────────────────────────────────────
# Listener UDP principal
# ──────────────────────────────────────────────
def start_snmp_listener():
    log.info(f"🚀 SNMP Receiver v2.0 démarré — {LISTEN_ADDRESS}:{LISTEN_PORT}/UDP")
    log.info(f"   Community attendue : {COMMUNITY}")
    log.info(f"   OCII-IRIS cible    : {OCII_IRIS_URL}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_ADDRESS, LISTEN_PORT))

    log.info("✅ Socket UDP lié — en attente de traps…")

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            source_ip  = addr[0]
            log.debug(f"Paquet reçu depuis {source_ip} ({len(data)} octets)")

            community, trap_oid, varbinds = parse_snmp_trap(data)
            log.info(f"Trap | src={source_ip} | oid={trap_oid} | category={OID_CATEGORY_MAP.get(trap_oid, 'snmp_generic')}")

            alert = format_trap_as_alert(source_ip, community, trap_oid, varbinds)

            threading.Thread(
                target=push_to_ocii_iris,
                args=(alert,),
                daemon=True
            ).start()

        except KeyboardInterrupt:
            log.info("⏹ Arrêt du SNMP Receiver")
            break
        except Exception as e:
            log.error(f"Erreur boucle principale : {e}")


# ──────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────
if __name__ == "__main__":
    delay = int(os.environ.get("SNMP_STARTUP_DELAY", "5"))
    if delay > 0:
        log.info(f"Attente {delay}s (démarrage Flask)…")
        time.sleep(delay)

    start_snmp_listener()
