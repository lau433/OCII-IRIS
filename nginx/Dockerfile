FROM nginx:alpine

# Supprime la config par défaut
RUN rm /etc/nginx/conf.d/default.conf

# Copie notre config
COPY nginx.conf /etc/nginx/conf.d/ocii-iris.conf

# Génère le certificat auto-signé au build
RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 730 \
      -newkey rsa:2048 \
      -keyout /etc/nginx/ssl/ocii-iris.key \
      -out /etc/nginx/ssl/ocii-iris.crt \
      -subj "/C=FR/ST=La Reunion/L=Saint-Denis/O=OCII/OU=SOC/CN=ocii-iris" \
      -addext "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:ocii-iris" && \
    chmod 600 /etc/nginx/ssl/ocii-iris.key

EXPOSE 80 443
