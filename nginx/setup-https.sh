#!/bin/bash
# ═══════════════════════════════════════════════════════════
# OCII-IRIS — Installation Nginx HTTPS (certificat auto-signé)
# À exécuter sur la machine hébergeant OCII-IRIS
# ═══════════════════════════════════════════════════════════

set -e

echo "══════════════════════════════════════"
echo " OCII-IRIS — Setup HTTPS Nginx"
echo "══════════════════════════════════════"

# ── Vérification root ──
if [ "$EUID" -ne 0 ]; then
  echo "❌ Ce script doit être exécuté en root (sudo)"
  exit 1
fi

# ── Détection IP LAN ──
LAN_IP=$(hostname -I | awk '{print $1}')
echo "→ IP LAN détectée : $LAN_IP"
echo ""

# ── Installation nginx ──
echo "[1/5] Installation de nginx..."
apt-get update -qq && apt-get install -y -qq nginx openssl > /dev/null 2>&1
echo "  ✓ nginx installé"

# ── Génération certificat auto-signé (valide 2 ans) ──
echo "[2/5] Génération du certificat SSL auto-signé..."
CERT_DIR="/etc/nginx/ssl"
mkdir -p "$CERT_DIR"

openssl req -x509 -nodes -days 730 \
  -newkey rsa:2048 \
  -keyout "$CERT_DIR/ocii-iris.key" \
  -out "$CERT_DIR/ocii-iris.crt" \
  -subj "/C=FR/ST=La Reunion/L=Saint-Denis/O=OCII/OU=SOC/CN=$LAN_IP" \
  -addext "subjectAltName=IP:$LAN_IP,IP:127.0.0.1,DNS:localhost" \
  2>/dev/null

chmod 600 "$CERT_DIR/ocii-iris.key"
echo "  ✓ Certificat généré : $CERT_DIR/ocii-iris.crt (valide 2 ans)"

# ── Configuration nginx ──
echo "[3/5] Configuration nginx..."
cat > /etc/nginx/sites-available/ocii-iris << 'NGINX_CONF'
# ═══════════════════════════════════════════════
# OCII-IRIS — Reverse Proxy HTTPS
# ═══════════════════════════════════════════════

# Redirection HTTP → HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 301 https://$host$request_uri;
}

# HTTPS
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;

    # ── Certificat SSL ──
    ssl_certificate     /etc/nginx/ssl/ocii-iris.crt;
    ssl_certificate_key /etc/nginx/ssl/ocii-iris.key;

    # ── Protocoles et ciphers sécurisés ──
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # ── Headers sécurité (complète ceux de Flask) ──
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # ── Masquer le header Server ──
    server_tokens off;
    more_set_headers "Server: OCII-IRIS";

    # ── Proxy vers Flask ──
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts pour les investigations IA (longues)
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 8k;
        proxy_buffers 8 8k;
    }

    # ── Bloquer l'accès direct aux fichiers sensibles ──
    location ~ /\. { deny all; }
    location ~ \.env$ { deny all; }

    # ── Logs ──
    access_log /var/log/nginx/ocii-iris-access.log;
    error_log  /var/log/nginx/ocii-iris-error.log;
}
NGINX_CONF

# Vérifier si le module headers-more est disponible
if ! nginx -V 2>&1 | grep -q "headers-more"; then
  echo "  ⚠ Module headers-more non installé — installation..."
  apt-get install -y -qq libnginx-mod-http-headers-more-filter > /dev/null 2>&1 || {
    echo "  ⚠ Module headers-more indisponible. Le header 'Server' utilisera server_tokens off."
    # Remplacer more_set_headers par un commentaire
    sed -i 's/more_set_headers "Server: OCII-IRIS";/# more_set_headers non disponible — server_tokens off suffit/' \
      /etc/nginx/sites-available/ocii-iris
  }
fi

# Activer le site
ln -sf /etc/nginx/sites-available/ocii-iris /etc/nginx/sites-enabled/ocii-iris
rm -f /etc/nginx/sites-enabled/default

echo "  ✓ Configuration nginx créée"

# ── Test config ──
echo "[4/5] Test de la configuration..."
nginx -t
echo "  ✓ Configuration valide"

# ── Firewall ──
echo "[5/5] Configuration firewall..."
if command -v ufw &> /dev/null; then
  ufw allow 80/tcp  > /dev/null 2>&1 || true
  ufw allow 443/tcp > /dev/null 2>&1 || true
  echo "  ✓ Ports 80 et 443 ouverts (ufw)"
else
  echo "  ⚠ ufw non installé — vérifier manuellement que les ports 80/443 sont ouverts"
fi

# ── Redémarrage nginx ──
systemctl restart nginx
systemctl enable nginx

echo ""
echo "══════════════════════════════════════════════════"
echo " ✅ OCII-IRIS HTTPS OPÉRATIONNEL"
echo "══════════════════════════════════════════════════"
echo ""
echo " Accès : https://$LAN_IP"
echo ""
echo " ⚠ Le navigateur affichera un avertissement"
echo "   'certificat non reconnu' — c'est normal pour"
echo "   un certificat auto-signé. Cliquer 'Avancé'"
echo "   puis 'Continuer vers le site'."
echo ""
echo " Pour les opérateurs : installer le certificat"
echo " $CERT_DIR/ocii-iris.crt dans les"
echo " certificats de confiance du navigateur supprime"
echo " cet avertissement."
echo ""
echo "══════════════════════════════════════════════════"
