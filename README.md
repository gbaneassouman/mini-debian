### 5. Démarrage et activation des services
```bash
sudo systemctl daemon-reload
sudo systemctl enable minio
sudo systemctl start minio
sudo systemctl status minio

# Vérification des logs avec journald
sudo journalctl -u minio -f --since "10 minutes ago"
```# Installation MinIO sur Debian 13 avec Cloudflare Tunnel et Let's Encrypt

## Installation de MinIO sur Debian 13

### 1. Mise à jour du système
```bash
sudo apt update && sudo apt upgrade -y

# Vérification de la version (Debian 13 "Trixie")
cat /etc/os-release
```

### 2. Création d'un utilisateur dédié
```bash
sudo useradd -r -s /bin/false -d /opt/minio minio
sudo mkdir -p /opt/minio/{bin,data,certs}
sudo chown -R minio:minio /opt/minio
```

### 3. Téléchargement et installation de MinIO
```bash
# Télécharger MinIO
wget https://dl.min.io/server/minio/release/linux-amd64/minio
sudo chmod +x minio
sudo mv minio /opt/minio/bin/

# Télécharger MinIO Client (optionnel mais utile)
wget https://dl.min.io/client/mc/release/linux-amd64/mc
sudo chmod +x mc
sudo mv mc /usr/local/bin/
```

## Installation et configuration de Let's Encrypt

### 1. Installation de Certbot
```bash
# Debian 13 inclut les dernières versions de Certbot
sudo apt install certbot python3-certbot-dns-cloudflare python3-pip -y

# Vérification de la version
certbot --version
```

### 2. Configuration des credentials Cloudflare
Créez le fichier d'authentification Cloudflare :
```bash
sudo mkdir -p /etc/letsencrypt
sudo nano /etc/letsencrypt/cloudflare.ini
```

Contenu du fichier (remplacez par vos vraies valeurs) :
```ini
# Cloudflare API credentials
dns_cloudflare_email = votre-email@example.com
dns_cloudflare_api_key = votre_api_key_globale_cloudflare
# OU utilisez un token API (recommandé)
# dns_cloudflare_api_token = votre_api_token
```

Sécurisez le fichier :
```bash
sudo chmod 600 /etc/letsencrypt/cloudflare.ini
```

### 3. Génération des certificats
```bash
# Pour les deux domaines MinIO
sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 60 \
  -d minio-api.votre-domaine.com \
  -d minio-console.votre-domaine.com \
  --email votre-email@example.com \
  --agree-tos \
  --non-interactive
```

### 4. Script de déploiement des certificats pour MinIO
Créez un script pour copier les certificats dans le dossier MinIO :
```bash
sudo nano /etc/letsencrypt/renewal-hooks/deploy/minio-certs.sh
```

Contenu du script :
```bash
#!/bin/bash

DOMAIN="minio-api.votre-domaine.com"
MINIO_CERT_DIR="/opt/minio/certs"

# Copier les certificats
cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $MINIO_CERT_DIR/public.crt
cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $MINIO_CERT_DIR/private.key

# Changer les permissions
chown minio:minio $MINIO_CERT_DIR/public.crt $MINIO_CERT_DIR/private.key
chmod 644 $MINIO_CERT_DIR/public.crt
chmod 600 $MINIO_CERT_DIR/private.key

# Redémarrer MinIO
systemctl restart minio
```

Rendre le script exécutable :
```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/minio-certs.sh
```

### 5. Exécution initiale du script
```bash
sudo /etc/letsencrypt/renewal-hooks/deploy/minio-certs.sh
```

## Configuration de MinIO avec SSL

### 1. Configuration de MinIO
```bash
sudo mkdir -p /etc/minio
sudo nano /etc/minio/minio.conf
```

Contenu avec SSL activé :
```bash
# Variables d'environnement MinIO
MINIO_ROOT_USER="votre_utilisateur_admin"
MINIO_ROOT_PASSWORD="votre_mot_de_passe_fort"
MINIO_VOLUMES="/opt/minio/data"
MINIO_OPTS="--console-address :9001 --certs-dir /opt/minio/certs"
```

## Spécificités Debian 13

### 1. Nouvelles fonctionnalités système
```bash
# Debian 13 utilise systemd 256+ avec de nouvelles fonctionnalités
systemctl --version

# Support amélioré pour les conteneurs et la sécurité
sudo apt install apparmor-utils -y
```

### 2. Configuration AppArmor pour MinIO (optionnel mais recommandé)
```bash
# Créer un profil AppArmor basique pour MinIO
sudo nano /etc/apparmor.d/minio
```

Contenu du profil AppArmor :
```apparmor
# AppArmor profile for MinIO
#include <tunables/global>

/opt/minio/bin/minio {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability dac_override,
  capability setuid,
  capability setgid,
  capability net_bind_service,

  /opt/minio/bin/minio mr,
  /opt/minio/data/ rw,
  /opt/minio/data/** rw,
  /opt/minio/certs/ r,
  /opt/minio/certs/** r,
  /etc/minio/ r,
  /etc/minio/** r,
  /proc/sys/net/core/somaxconn r,
  
  # Permettre l'accès aux sockets réseau
  network inet stream,
  network inet6 stream,
  
  # Logs
  /var/log/minio.log w,
}
```

Activation du profil :
```bash
sudo apparmor_parser -r /etc/apparmor.d/minio
sudo systemctl reload apparmor
```

### 3. Configuration systemd améliorée pour Debian 13
```bash
sudo nano /etc/systemd/system/minio.service
```

Version optimisée pour Debian 13 :
```ini
[Unit]
Description=MinIO Object Storage
Documentation=https://docs.min.io
Wants=network-online.target
After=network-online.target
AssertFileIsExecutable=/opt/minio/bin/minio
ConditionPathExists=/opt/minio/data

[Service]
WorkingDirectory=/opt/minio
User=minio
Group=minio
EnvironmentFile=/etc/minio/minio.conf

# Sécurité renforcée pour systemd 256+
ExecStartPre=/bin/bash -c "if [ -z \"${MINIO_VOLUMES}\" ]; then echo \"Variable MINIO_VOLUMES not set in /etc/minio/minio.conf\"; exit 1; fi"
ExecStart=/opt/minio/bin/minio server $MINIO_OPTS $MINIO_VOLUMES
ExecReload=/bin/kill -HUP $MAINPID

Restart=always
RestartSec=5
LimitNOFILE=65536
TasksMax=infinity
TimeoutStartSec=infinity
TimeoutStopSec=infinity
SendSIGKILL=no

# Sécurité systemd avancée (Debian 13)
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/minio/data /var/log
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

### 4. Optimisations pour Debian 13

#### Configuration réseau avancée
```bash
# Optimisations réseau pour MinIO sur Debian 13
sudo nano /etc/sysctl.d/99-minio.conf
```

Contenu des optimisations :
```bash
# Optimisations réseau pour MinIO
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 30000
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
```

Appliquer les optimisations :
```bash
sudo sysctl -p /etc/sysctl.d/99-minio.conf
```

#### Configuration des limites système
```bash
# Limites pour l'utilisateur minio
sudo nano /etc/security/limits.d/minio.conf
```

```bash
minio soft nofile 65536
minio hard nofile 65536
minio soft nproc 65536
minio hard nproc 65536
```

## Configuration du tunnel Cloudflare

### 1. Installation de cloudflared
```bash
# Pour Debian 13, utiliser la dernière version
wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared-linux-amd64.deb

# Alternative: Installation via le repository officiel
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared trixie main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt update && sudo apt install cloudflared
```

### 2. Authentification avec Cloudflare
```bash
cloudflared tunnel login
```

### 3. Création du tunnel
```bash
cloudflared tunnel create minio-tunnel
cloudflared tunnel list
```

### 4. Configuration du tunnel avec SSL
```bash
sudo mkdir -p /etc/cloudflared
sudo nano /etc/cloudflared/config.yml
```

Configuration avec SSL activé :
```yaml
tunnel: minio-tunnel
credentials-file: /root/.cloudflared/TUNNEL_ID.json

ingress:
  # Interface web MinIO (console) - HTTPS
  - hostname: minio-console.votre-domaine.com
    service: https://localhost:9001
    originRequest:
      noTLSVerify: true
  # API MinIO - HTTPS
  - hostname: minio-api.votre-domaine.com
    service: https://localhost:9000
    originRequest:
      noTLSVerify: true
  # Règle par défaut
  - service: http_status:404
```

### 5. Configuration DNS et service
```bash
# DNS
cloudflared tunnel route dns minio-tunnel minio-console.votre-domaine.com
cloudflared tunnel route dns minio-tunnel minio-api.votre-domaine.com

# Service
sudo cloudflared service install
sudo systemctl start cloudflared
sudo systemctl enable cloudflared
```

## Automatisation du renouvellement

### 1. Configuration de l'auto-renouvellement
Le renouvellement automatique est déjà configuré via le hook de déploiement.

### 2. Test du renouvellement
```bash
sudo certbot renew --dry-run
```

### 3. Script de monitoring (optionnel)
Créez un script pour vérifier l'expiration des certificats :
```bash
sudo nano /usr/local/bin/check-certs.sh
```

```bash
#!/bin/bash

DOMAIN="minio-api.votre-domaine.com"
EXPIRY_DATE=$(openssl x509 -enddate -noout -in /etc/letsencrypt/live/$DOMAIN/cert.pem | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_EPOCH=$(date +%s)
DAYS_LEFT=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))

echo "Certificat expire dans $DAYS_LEFT jours"

if [ $DAYS_LEFT -lt 30 ]; then
    echo "ATTENTION: Le certificat expire bientôt!"
    # Optionnel: envoyer une notification
fi
```

```bash
sudo chmod +x /usr/local/bin/check-certs.sh
```

### 4. Service de monitoring systemd (Debian 13)
Créez un service de monitoring dédié :
```bash
sudo nano /etc/systemd/system/minio-cert-check.service
```

```ini
[Unit]
Description=MinIO Certificate Check
After=minio.service
Wants=minio.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/check-certs.sh
User=root
StandardOutput=journal
StandardError=journal
```

Timer pour automatiser :
```bash
sudo nano /etc/systemd/system/minio-cert-check.timer
```

```ini
[Unit]
Description=Run MinIO Certificate Check daily
Requires=minio-cert-check.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Activation :
```bash
sudo systemctl enable minio-cert-check.timer
sudo systemctl start minio-cert-check.timer
sudo systemctl status minio-cert-check.timer
```

## Configuration iptables pour MinIO

### 1. Sauvegarde des règles actuelles
```bash
# Sauvegarder les règles existantes
sudo iptables-save > /tmp/iptables-backup.rules
sudo ip6tables-save > /tmp/ip6tables-backup.rules
```

### 2. Installation des outils iptables
```bash
# Installation des outils de persistance
sudo apt install iptables-persistent netfilter-persistent -y
```

### 3. Configuration iptables de base
```bash
sudo nano /etc/iptables/rules.v4
```

Configuration IPv4 complète :
```iptables
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Loopback autorisé
-A INPUT -i lo -j ACCEPT

# Connexions établies et reliées
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH (port 22) - Ajustez selon votre port SSH
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 5/min --limit-burst 3 -j ACCEPT

# Protection contre les attaques
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -p tcp --tcp-flags ALL NONE -j DROP
-A INPUT -p tcp --tcp-flags ALL ALL -j DROP
-A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
-A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
-A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
-A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# Protection contre les scans de ports
-A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
-A INPUT -m recent --name portscan --remove
-A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
-A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

# ICMP limité (ping)
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# MinIO - Ports locaux uniquement (via Cloudflare Tunnel)
# Port 9000 (API) et 9001 (Console) - ACCÈS LOCAL UNIQUEMENT
-A INPUT -p tcp -s 127.0.0.1 --dport 9000 -j ACCEPT
-A INPUT -p tcp -s 127.0.0.1 --dport 9001 -j ACCEPT

# Cloudflared - Port pour les connexions sortantes uniquement
# Pas de ports entrants nécessaires pour les tunnels Cloudflare

# DNS (nécessaire pour les résolutions)
-A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# NTP (synchronisation de l'heure)
-A INPUT -p udp --sport 123 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# HTTP/HTTPS sortant (pour les mises à jour, Let's Encrypt, etc.)
-A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Let's Encrypt - Défi DNS uniquement (pas de ports entrants HTTP/HTTPS nécessaires)

# Logging des connexions refusées (optionnel)
-A INPUT -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "iptables INPUT denied: " --log-level 7

COMMIT
```

### 4. Configuration IPv6
```bash
sudo nano /etc/iptables/rules.v6
```

Configuration IPv6 :
```iptables
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Loopback
-A INPUT -i lo -j ACCEPT

# Connexions établies
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH IPv6
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 5/min --limit-burst 3 -j ACCEPT

# ICMPv6 essentiel
-A INPUT -p ipv6-icmp --icmpv6-type destination-unreachable -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type packet-too-big -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type time-exceeded -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type parameter-problem -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type router-advertisement -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type neighbor-solicitation -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type neighbor-advertisement -j ACCEPT

# MinIO - Accès local uniquement IPv6
-A INPUT -p tcp -s ::1 --dport 9000 -j ACCEPT
-A INPUT -p tcp -s ::1 --dport 9001 -j ACCEPT

# Logging
-A INPUT -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "ip6tables INPUT denied: " --log-level 7

COMMIT
```

### 5. Script de gestion iptables personnalisé
```bash
sudo nano /usr/local/bin/minio-firewall.sh
```

Script de gestion complet :
```bash
#!/bin/bash

# Script de gestion du firewall MinIO pour Debian 13

IPTABLES="/usr/sbin/iptables"
IP6TABLES="/usr/sbin/ip6tables"

case "$1" in
  start)
    echo "Démarrage du firewall MinIO..."
    
    # Charger les règles
    if [ -f /etc/iptables/rules.v4 ]; then
        $IPTABLES-restore < /etc/iptables/rules.v4
        echo "Règles IPv4 chargées"
    fi
    
    if [ -f /etc/iptables/rules.v6 ]; then
        $IP6TABLES-restore < /etc/iptables/rules.v6
        echo "Règles IPv6 chargées"
    fi
    ;;
    
  stop)
    echo "Arrêt du firewall..."
    $IPTABLES -F
    $IPTABLES -X
    $IPTABLES -P INPUT ACCEPT
    $IPTABLES -P OUTPUT ACCEPT
    $IPTABLES -P FORWARD ACCEPT
    
    $IP6TABLES -F
    $IP6TABLES -X
    $IP6TABLES -P INPUT ACCEPT
    $IP6TABLES -P OUTPUT ACCEPT
    $IP6TABLES -P FORWARD ACCEPT
    ;;
    
  restart)
    $0 stop
    sleep 2
    $0 start
    ;;
    
  save)
    echo "Sauvegarde des règles..."
    $IPTABLES-save > /etc/iptables/rules.v4
    $IP6TABLES-save > /etc/iptables/rules.v6
    echo "Règles sauvegardées"
    ;;
    
  status)
    echo "=== Règles IPv4 ==="
    $IPTABLES -L -n -v
    echo
    echo "=== Règles IPv6 ==="
    $IP6TABLES -L -n -v
    ;;
    
  test-ssh)
    echo "Test de connectivité SSH..."
    # Ajouter une règle temporaire pour tester
    $IPTABLES -I INPUT -p tcp --dport 22 -j ACCEPT
    echo "Règle SSH temporaire ajoutée. Testez votre connexion."
    echo "Si ça fonctionne, exécutez: $0 save"
    echo "Sinon, la règle sera supprimée au redémarrage."
    ;;
    
  block-ip)
    if [ -z "$2" ]; then
        echo "Usage: $0 block-ip <IP_ADDRESS>"
        exit 1
    fi
    echo "Blocage de l'IP: $2"
    $IPTABLES -I INPUT -s $2 -j DROP
    echo "IP $2 bloquée. Utilisez '$0 save' pour rendre permanent."
    ;;
    
  unblock-ip)
    if [ -z "$2" ]; then
        echo "Usage: $0 unblock-ip <IP_ADDRESS>"
        exit 1
    fi
    echo "Déblocage de l'IP: $2"
    $IPTABLES -D INPUT -s $2 -j DROP 2>/dev/null
    echo "IP $2 débloquée."
    ;;
    
  logs)
    echo "Logs du firewall (dernières 20 entrées):"
    dmesg | grep -E "(iptables|ip6tables)" | tail -20
    ;;
    
  *)
    echo "Usage: $0 {start|stop|restart|save|status|test-ssh|block-ip|unblock-ip|logs}"
    echo
    echo "Commandes:"
    echo "  start     - Charger les règles du firewall"
    echo "  stop      - Arrêter le firewall (DANGEREUX)"
    echo "  restart   - Redémarrer le firewall"
    echo "  save      - Sauvegarder les règles actuelles"
    echo "  status    - Afficher les règles actives"
    echo "  test-ssh  - Tester la règle SSH"
    echo "  block-ip  - Bloquer une adresse IP"
    echo "  unblock-ip- Débloquer une adresse IP"
    echo "  logs      - Afficher les logs du firewall"
    exit 1
    ;;
esac

exit 0
```

```bash
sudo chmod +x /usr/local/bin/minio-firewall.sh
```

### 6. Application des règles
```bash
# Appliquer les règles
sudo /usr/local/bin/minio-firewall.sh start

# Sauvegarder pour la persistance
sudo /usr/local/bin/minio-firewall.sh save

# Activer la persistance au démarrage
sudo systemctl enable netfilter-persistent
```

### 7. Configuration avancée - Fail2ban pour MinIO
```bash
# Installation de Fail2ban
sudo apt install fail2ban -y

# Configuration pour MinIO
sudo nano /etc/fail2ban/jail.d/minio.conf
```

Configuration Fail2ban :
```ini
[minio-auth]
enabled = true
port = 9000,9001
filter = minio-auth
logpath = /var/log/minio/*.log
maxretry = 5
findtime = 600
bantime = 3600
action = iptables-allports[name=minio-auth]

[cloudflared]
enabled = true
port = all
filter = cloudflared
logpath = /var/log/cloudflared.log
maxretry = 3
findtime = 300
bantime = 1800
```

Filtre pour MinIO :
```bash
sudo nano /etc/fail2ban/filter.d/minio-auth.conf
```

```ini
[Definition]
failregex = ^.*API: SYSTEM.*Invalid login attempt.*<HOST>.*$
            ^.*API: AUTH.*Authentication failed.*<HOST>.*$
            ^.*Console: AUTH.*Invalid credentials.*<HOST>.*$

ignoreregex =
```

Filtre pour Cloudflared :
```bash
sudo nano /etc/fail2ban/filter.d/cloudflared.conf
```

```ini
[Definition]
failregex = ^.*cloudflared.*connection failed.*<HOST>.*$
            ^.*cloudflared.*authentication failed.*<HOST>.*$

ignoreregex =
```

### 8. Monitoring et alertes iptables
```bash
sudo nano /usr/local/bin/firewall-monitor.sh
```

Script de monitoring :
```bash
#!/bin/bash

# Monitoring des règles iptables pour MinIO

LOG_FILE="/var/log/firewall-monitor.log"
ALERT_THRESHOLD=10

# Compter les tentatives bloquées dans les dernières 5 minutes
BLOCKED_COUNT=$(dmesg | grep "iptables INPUT denied" | grep "$(date '+%b %d %H:%M' -d '5 minutes ago')" | wc -l)

if [ $BLOCKED_COUNT -gt $ALERT_THRESHOLD ]; then
    echo "$(date): ALERTE - $BLOCKED_COUNT tentatives bloquées" >> $LOG_FILE
    logger -t firewall-monitor "ALERT: $BLOCKED_COUNT blocked attempts in last 5 minutes"
    
    # Notification systemd
    systemd-notify --status="High firewall activity: $BLOCKED_COUNT blocked attempts"
fi

# Vérifier si MinIO est accessible localement
if ! curl -k https://localhost:9000/minio/health/live >/dev/null 2>&1; then
    echo "$(date): ERREUR - MinIO non accessible" >> $LOG_FILE
    logger -p user.crit -t firewall-monitor "MinIO health check failed"
fi

# Statistiques quotidiennes
if [ "$(date '+%H:%M')" = "23:59" ]; then
    DAILY_BLOCKS=$(dmesg | grep "iptables INPUT denied" | grep "$(date '+%b %d')" | wc -l)
    echo "$(date): Rapport quotidien - $DAILY_BLOCKS tentatives bloquées" >> $LOG_FILE
fi
```

```bash
sudo chmod +x /usr/local/bin/firewall-monitor.sh
```

### 9. Service systemd pour le monitoring
```bash
sudo nano /etc/systemd/system/firewall-monitor.timer
```

```ini
[Unit]
Description=Firewall Monitoring Timer
Requires=firewall-monitor.service

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo nano /etc/systemd/system/firewall-monitor.service
```

```ini
[Unit]
Description=Firewall Monitoring Service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/firewall-monitor.sh
User=root
StandardOutput=journal
StandardError=journal
```

### 10. Activation des services
```bash
# Démarrer Fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Activer le monitoring
sudo systemctl enable firewall-monitor.timer
sudo systemctl start firewall-monitor.timer

# Vérifier le statut
sudo systemctl status fail2ban firewall-monitor.timer
```

### 11. Tests de sécurité
```bash
# Test des règles
sudo /usr/local/bin/minio-firewall.sh status

# Test de connectivité locale MinIO
curl -k https://localhost:9000/minio/health/live

# Vérifier Fail2ban
sudo fail2ban-client status

# Test des logs
sudo /usr/local/bin/minio-firewall.sh logs
```

### 12. Script de sauvegarde de la configuration
```bash
sudo nano /usr/local/bin/backup-firewall-config.sh
```

```bash
#!/bin/bash

BACKUP_DIR="/backup/firewall-$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Sauvegarder les règles iptables
iptables-save > $BACKUP_DIR/iptables-rules.txt
ip6tables-save > $BACKUP_DIR/ip6tables-rules.txt

# Sauvegarder la configuration Fail2ban
cp -r /etc/fail2ban/ $BACKUP_DIR/fail2ban/

# Sauvegarder les scripts personnalisés
cp /usr/local/bin/minio-firewall.sh $BACKUP_DIR/
cp /usr/local/bin/firewall-monitor.sh $BACKUP_DIR/

# Créer un archive
tar -czf /backup/firewall-config-$(date +%Y%m%d).tar.gz -C /backup firewall-$(date +%Y%m%d)

echo "Sauvegarde firewall créée: /backup/firewall-config-$(date +%Y%m%d).tar.gz"
```

```bash
sudo chmod +x /usr/local/bin/backup-firewall-config.sh
```

## Configuration de sécurité Cloudflare

### 1. SSL/TLS Settings
Dans votre dashboard Cloudflare :
- SSL/TLS → Overview → Choisir "Full (strict)"
- SSL/TLS → Edge Certificates → Activer "Always Use HTTPS"
- SSL/TLS → Edge Certificates → Activer "HTTP Strict Transport Security (HSTS)"

### 2. Security Settings
- Security → WAF → Activer les règles de protection
- Security → Bot Fight Mode → Activer
- Speed → Auto Minify → Activer pour CSS, JS, HTML

## Test et validation

### 1. Test des certificats
```bash
# Vérifier les certificats MinIO
openssl x509 -in /opt/minio/certs/public.crt -text -noout | grep -A 2 "Subject:"

# Test de connexion SSL
openssl s_client -connect localhost:9000 -servername minio-api.votre-domaine.com
```

## Test et validation avec iptables

### 1. Tests de sécurité complets
```bash
# Vérifier que MinIO n'est pas accessible depuis l'extérieur
sudo nmap -p 9000,9001 localhost
sudo nmap -p 9000,9001 votre-ip-publique

# Test de connectivité locale
curl -k https://localhost:9000/minio/health/live
curl -k https://localhost:9001

# Vérifier les règles actives
sudo /usr/local/bin/minio-firewall.sh status
```

### 2. Test des accès web avec tunnel
- **Console MinIO** : https://minio-console.votre-domaine.com
- **API MinIO** : https://minio-api.votre-domaine.com

### 3. Test de sécurité iptables
```bash
# Simuler une attaque (depuis un autre serveur)
# Ceci devrait être bloqué
nmap -p 9000,9001 votre-serveur-ip

# Vérifier les logs de blocage
sudo dmesg | grep "iptables INPUT denied" | tail -10
```

### 4. Configuration du client mc avec tunnel sécurisé
```bash
mc alias set myminio https://minio-api.votre-domaine.com votre_utilisateur_admin votre_mot_de_passe_fort
mc admin info myminio
```

## Logs et monitoring

## Logs et monitoring avec iptables

### 1. Monitoring complet des services
```bash
# Status de tous les services
sudo systemctl status minio cloudflared fail2ban netfilter-persistent

# Logs combinés en temps réel
sudo journalctl -u minio -u cloudflared -u fail2ban -f

# Logs spécifiques au firewall
sudo dmesg | grep -E "(iptables|ip6tables)" | tail -20
sudo fail2ban-client status
```

### 2. Logs Let's Encrypt et certificats
```bash
# Logs de renouvellement
sudo cat /var/log/letsencrypt/letsencrypt.log

# Test de renouvellement avec iptables actif
sudo certbot renew --dry-run -v
```

### 3. Monitoring iptables avancé
```bash
# Script de surveillance des connexions
sudo nano /usr/local/bin/connection-monitor.sh
```

Script de surveillance :
```bash
#!/bin/bash

echo "=== Connexions actives MinIO ==="
sudo netstat -tlnp | grep -E ":(9000|9001)"

echo -e "\n=== Tentatives bloquées (dernière heure) ==="
dmesg | grep "iptables INPUT denied" | grep "$(date '+%b %d %H')" | wc -l

echo -e "\n=== Top 10 IPs bloquées ==="
dmesg | grep "iptables INPUT denied" | grep -oE "SRC=[0-9.]+" | cut -d= -f2 | sort | uniq -c | sort -nr | head -10

echo -e "\n=== Status Fail2ban ==="
sudo fail2ban-client status | grep "Jail list" -A 10
```

```bash
sudo chmod +x /usr/local/bin/connection-monitor.sh
```

### 2. Logs Let's Encrypt
```bash
# Logs de renouvellement
sudo cat /var/log/letsencrypt/letsencrypt.log

# Test de renouvellement
sudo certbot renew --dry-run -v
```

### 3. Monitoring SSL
```bash
# Script de vérification SSL
curl -I https://minio-api.votre-domaine.com
curl -I https://minio-console.votre-domaine.com
```

## Maintenance

### 1. Renouvellement manuel des certificats (si nécessaire)
```bash
sudo certbot renew --force-renewal
sudo /etc/letsencrypt/renewal-hooks/deploy/minio-certs.sh
```

## Maintenance avec iptables

### 1. Scripts de maintenance automatisée
```bash
# Script de maintenance complète
sudo nano /usr/local/bin/minio-maintenance.sh
```

Script de maintenance :
```bash
#!/bin/bash

echo "=== Maintenance MinIO avec sécurité iptables ==="

# 1. Vérification de l'état des services
echo "Vérification des services..."
systemctl is-active minio cloudflared fail2ban netfilter-persistent

# 2. Nettoyage des logs anciens
echo "Nettoyage des logs..."
find /var/log -name "*.log" -type f -mtime +30 -delete
journalctl --vacuum-time=30d

# 3. Vérification des règles iptables
echo "Vérification des règles iptables..."
if ! iptables -C INPUT -p tcp -s 127.0.0.1 --dport 9000 -j ACCEPT 2>/dev/null; then
    echo "ERREUR: Règle iptables MinIO manquante!"
    /usr/local/bin/minio-firewall.sh start
fi

# 4. Test de connectivité
echo "Test de connectivité..."
if curl -k https://localhost:9000/minio/health/live >/dev/null 2>&1; then
    echo "✓ MinIO API accessible"
else
    echo "✗ MinIO API non accessible"
    systemctl restart minio
fi

# 5. Sauvegarde des configurations
echo "Sauvegarde des configurations..."
/usr/local/bin/backup-firewall-config.sh

# 6. Statistiques de sécurité
echo "=== Statistiques de sécurité ==="
BLOCKED_TODAY=$(dmesg | grep "iptables INPUT denied" | grep "$(date '+%b %d')" | wc -l)
echo "Tentatives bloquées aujourd'hui: $BLOCKED_TODAY"

FAIL2BAN_BANS=$(fail2ban-client status | grep -c "Currently banned:")
echo "IPs bannies par Fail2ban: $FAIL2BAN_BANS"

# 7. Vérification des certificats
CERT_DAYS=$(/usr/local/bin/check-certs.sh | grep -oE "[0-9]+ jours" | cut -d' ' -f1)
echo "Certificat expire dans: $CERT_DAYS jours"

echo "=== Maintenance terminée ==="
```

```bash
sudo chmod +x /usr/local/bin/minio-maintenance.sh
```

### 2. Service de maintenance automatique
```bash
sudo nano /etc/systemd/system/minio-maintenance.service
```

```ini
[Unit]
Description=MinIO Maintenance Service
After=minio.service cloudflared.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/minio-maintenance.sh
User=root
StandardOutput=journal
StandardError=journal
```

Timer hebdomadaire :
```bash
sudo nano /etc/systemd/system/minio-maintenance.timer
```

```ini
[Unit]
Description=Weekly MinIO Maintenance
Requires=minio-maintenance.service

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
```

### 3. Procédure d'urgence
```bash
sudo nano /usr/local/bin/minio-emergency.sh
```

Script d'urgence :
```bash
#!/bin/bash

echo "=== PROCÉDURE D'URGENCE MinIO ==="

case "$1" in
  firewall-off)
    echo "DÉSACTIVATION DU FIREWALL (DANGEREUX!)"
    /usr/local/bin/minio-firewall.sh stop
    echo "Firewall désactivé - N'oubliez pas de le réactiver!"
    ;;
    
  firewall-on)
    echo "Réactivation du firewall..."
    /usr/local/bin/minio-firewall.sh start
    ;;
    
  reset-fail2ban)
    echo "Reset de Fail2ban..."
    systemctl stop fail2ban
    rm -f /var/lib/fail2ban/fail2ban.sqlite3
    systemctl start fail2ban
    ;;
    
  tunnel-restart)
    echo "Redémarrage du tunnel Cloudflare..."
    systemctl restart cloudflared
    sleep 5
    systemctl status cloudflared
    ;;
    
  full-restart)
    echo "Redémarrage complet des services..."
    systemctl restart netfilter-persistent
    systemctl restart fail2ban
    systemctl restart minio
    systemctl restart cloudflared
    ;;
    
  status)
    echo "=== STATUS COMPLET ==="
    /usr/local/bin/minio-firewall.sh status
    echo -e "\n=== SERVICES ==="
    systemctl status minio cloudflared fail2ban --no-pager -l
    echo -e "\n=== CONNECTIVITÉ ==="
    curl -k https://localhost:9000/minio/health/live
    ;;
    
  *)
    echo "Usage: $0 {firewall-off|firewall-on|reset-fail2ban|tunnel-restart|full-restart|status}"
    echo
    echo "COMMANDES D'URGENCE:"
    echo "  firewall-off  - Désactive le firewall (DANGEREUX)"
    echo "  firewall-on   - Réactive le firewall"
    echo "  reset-fail2ban- Reset Fail2ban"
    echo "  tunnel-restart- Redémarre le tunnel Cloudflare"
    echo "  full-restart  - Redémarre tous les services"
    echo "  status        - Affiche le statut complet"
    ;;
esac
```

```bash
sudo chmod +x /usr/local/bin/minio-emergency.sh
```

### 4. Activation des services de maintenance
```bash
# Activer la maintenance automatique
sudo systemctl enable minio-maintenance.timer
sudo systemctl start minio-maintenance.timer

# Test de la maintenance
sudo /usr/local/bin/minio-maintenance.sh

# Vérifier les timers actifs
sudo systemctl list-timers | grep minio
```

### 5. Documentation des procédures d'urgence
```bash
sudo nano /etc/minio/procedures-urgence.md
```

```markdown
# PROCÉDURES D'URGENCE MinIO

## En cas de perte d'accès

1. **Vérification rapide:**
   ```bash
   sudo /usr/local/bin/minio-emergency.sh status
   ```

2. **MinIO inaccessible via tunnel:**
   ```bash
   sudo /usr/local/bin/minio-emergency.sh tunnel-restart
   ```

3. **Problème de certificats:**
   ```bash
   sudo certbot renew --force-renewal
   sudo systemctl restart minio
   ```

4. **Trop de blocages iptables:**
   ```bash
   sudo /usr/local/bin/minio-emergency.sh reset-fail2ban
   ```

5. **URGENCE ABSOLUE (désactive la sécurité):**
   ```bash
   sudo /usr/local/bin/minio-emergency.sh firewall-off
   # RÉACTIVER IMMÉDIATEMENT APRÈS INTERVENTION
   sudo /usr/local/bin/minio-emergency.sh firewall-on
   ```

## Contacts et ressources
- Logs: /var/log/minio/
- Config: /etc/minio/
- Scripts: /usr/local/bin/minio-*
```

### 6. Sauvegarde complète automatisée
```bash
# Ajouter au script de maintenance
echo "# Sauvegarde complète hebdomadaire" >> /etc/crontab
echo "0 2 * * 0 root /usr/local/bin/backup-firewall-config.sh" >> /etc/crontab
```
```bash
# Script de mise à jour automatisée
sudo nano /usr/local/bin/update-minio.sh
```

```bash
#!/bin/bash

# Script de mise à jour MinIO pour Debian 13
CURRENT_VERSION=$(minio --version 2>/dev/null | head -n1 | awk '{print $3}' || echo "unknown")
MINIO_BIN="/opt/minio/bin/minio"
BACKUP_DIR="/opt/minio/backup"

echo "Version actuelle: $CURRENT_VERSION"

# Créer un backup
sudo -u minio mkdir -p $BACKUP_DIR
sudo -u minio cp $MINIO_BIN $BACKUP_DIR/minio-$(date +%Y%m%d)

# Télécharger la nouvelle version
wget -q https://dl.min.io/server/minio/release/linux-amd64/minio -O /tmp/minio
NEW_VERSION=$(/tmp/minio --version 2>/dev/null | head -n1 | awk '{print $3}')

echo "Nouvelle version: $NEW_VERSION"

if [ "$CURRENT_VERSION" != "$NEW_VERSION" ]; then
    echo "Mise à jour détectée, installation..."
    
    # Arrêter le service
    sudo systemctl stop minio
    
    # Remplacer le binaire
    sudo chmod +x /tmp/minio
    sudo mv /tmp/minio $MINIO_BIN
    sudo chown minio:minio $MINIO_BIN
    
    # Redémarrer
    sudo systemctl start minio
    
    # Vérifier le statut
    sleep 5
    sudo systemctl is-active minio
    
    echo "Mise à jour terminée: $CURRENT_VERSION -> $NEW_VERSION"
    logger -t minio-update "MinIO updated from $CURRENT_VERSION to $NEW_VERSION"
else
    echo "Aucune mise à jour disponible"
fi
```

```bash
sudo chmod +x /usr/local/bin/update-minio.sh
```

### 3. Sauvegarde des certificats
```bash
sudo tar -czf /backup/letsencrypt-$(date +%Y%m%d).tar.gz /etc/letsencrypt/
```

Votre installation MinIO est maintenant complètement sécurisée avec :
- Certificats SSL Let's Encrypt avec renouvellement automatique
- Tunnel Cloudflare pour l'accès sécurisé
- Configuration SSL end-to-end
- Monitoring et maintenance automatisés
