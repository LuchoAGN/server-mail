#!/bin/bash

# Servidor de Correo - Script de Inicialización
# Este script configura Postfix, Dovecot, Certbot y OpenDKIM

set -e  # Salir en caso de error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Array para almacenar respaldos
BACKUPS=()

# Configuración inicial
EMAIL_ADMIN="garcialuis783@gmail.com"
MAIN_DOMAIN="media-lagn.ink"
SECONDARY_DOMAIN="luchoagn.com"
MAIL_SUBDOMAIN_MAIN="mail.${MAIN_DOMAIN}"
MAIL_SUBDOMAIN_SECONDARY="mail.${SECONDARY_DOMAIN}"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Función para verificar si el comando se ejecutó correctamente
check_command() {
    if [ $? -eq 0 ]; then
        log_info "$1 - Completado exitosamente"
    else
        log_error "$1 - Falló"
        exit 1
    fi
}

# Función para crear un respaldo
create_backup() {
    local original_file="$1"
    local backup_file="${original_file}.$(date +%Y%m%d%H%M%S).bak"
    if [ -f "${original_file}" ]; then
        cp "${original_file}" "${backup_file}"
        log_info "Respaldo creado: ${backup_file}"
        BACKUPS+=("${backup_file}")
    fi
}

# Función para restaurar el último respaldo
restore_last_backup() {
    if [ ${#BACKUPS[@]} -gt 0 ]; then
        local last_backup="${BACKUPS[-1]}"
        log_warning "Restaurando el último respaldo: ${last_backup}"
        cp "${last_backup}" "${last_backup%.*}" # Restaura al nombre original
    fi
}

# Función para configurar Certbot
configure_certbot() {
    log_info "Configurando Certbot..."
    
    pkg install -y security/py-certbot
    check_command "Instalación de Certbot"
    
    echo "weekly_certbot_enable=\"YES\"" >> /usr/local/etc/periodic/weekly/500.certbot-3.11
    
    # Obtener certificados para ambos dominios
    certbot certonly --standalone \
        --agree-tos \
        --no-eff-email \
        -m ${EMAIL_ADMIN} \
        -d ${MAIL_SUBDOMAIN_MAIN}
    check_command "Certificado para ${MAIL_SUBDOMAIN_MAIN}"
    
    certbot certonly --standalone \
        --agree-tos \
        --no-eff-email \
        -m ${EMAIL_ADMIN} \
        -d ${MAIL_SUBDOMAIN_SECONDARY}
    check_command "Certificado para ${MAIL_SUBDOMAIN_SECONDARY}"
}

# Función para configurar Postfix
configure_postfix() {
    log_info "Configurando Postfix..."
    
    pkg update
    pkg install -y postfix
    check_command "Instalación de Postfix"
    
    # Habilitar servicios
    sysrc postfix_enable="YES"
    sysrc sendmail_enable="NONE"
    
    # Configurar mailer
    install -d /usr/local/etc/mail
    install -m 0644 /usr/local/share/postfix/mailer.conf.postfix /usr/local/etc/mail/mailer.conf
    
    # Configurar periodic
    cat >> /etc/periodic.conf << EOF
daily_clean_hoststat_enable="NO"
daily_status_mail_rejects_enable="NO"
daily_status_include_submit_mailq="NO"
daily_submit_queuerun="NO"
EOF
    
    # Crear usuario vpostfix
    pw groupadd -g 1002 -n vpostfix 2>/dev/null || true
    pw useradd -d /nonexistent -s /sbin/nologin -u 1002 -n vpostfix 2>/dev/null || true
    
    # Crear directorios
    cd /var/mail
    mkdir -p vhosts
    chown -R vpostfix:vpostfix vhosts/
    
    # Configurar main.cf
    cd /usr/local/etc/postfix/
    create_backup "/usr/local/etc/postfix/main.cf"
    
    sed -i.bak \
        -e "s/^#myhostname = host\.domain\.ltd/myhostname = ${MAIL_SUBDOMAIN_MAIN}/" \
        -e "s/^#mydomain = domain\.ltd/mydomain = ${MAIN_DOMAIN}/" \
        -e 's/^#myorigin = \$mydomain/myorigin = \$mydomain/' \
        -e '/^smtp_tls_CApath/s/^/#/' \
        /usr/local/etc/postfix/main.cf
    
    # Agregar configuración virtual
    cat >> /usr/local/etc/postfix/main.cf << EOF

# Virtual Domain config
virtual_mailbox_base = /var/mail/vhosts
virtual_mailbox_domains = /usr/local/etc/postfix/virtual_domains
virtual_mailbox_maps = hash:/usr/local/etc/postfix/vmailbox
virtual_alias_maps = hash:/usr/local/etc/postfix/virtual

# vpostfix user configuration
virtual_minimum_uid = 1002
virtual_uid_maps = static:1002
virtual_gid_maps = static:1002

# TLS Configuration
smtpd_tls_cert_file = /usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/fullchain.pem
smtpd_tls_key_file = /usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/privkey.pem

# SASL Configuration
smtpd_sasl_type = dovecot
broken_sasl_auth_clients = yes
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous

# Security restrictions
smtpd_sender_restrictions = reject_unknown_sender_domain,
                           reject_non_fqdn_sender,
                           reject_unlisted_sender,
                           permit_mynetworks,
                           permit_sasl_authenticated

smtpd_recipient_restrictions = permit_sasl_authenticated,
                              permit_mynetworks,
                              reject_unauth_destination,
                              check_sender_access hash:/usr/local/etc/postfix/sender_access

smtpd_relay_restrictions = permit_sasl_authenticated,
                          permit_mynetworks,
                          reject_unauth_destination

# DKIM Configuration
smtpd_milters = inet:localhost:8891
non_smtpd_milters = \$smtpd_milters
milter_default_action = accept

# Spam protection
disable_vrfy_command = yes
smtpd_helo_required = yes
unverified_sender_reject_reason = Access verification failed

# SNI support for multiple domains
tls_server_sni_maps = hash:/usr/local/etc/postfix/sni_maps
EOF
    
    check_command "Configuración de Postfix"
}

# Función para configurar Dovecot
configure_dovecot() {
    log_info "Configurando Dovecot..."
    
    pkg install -y dovecot
    check_command "Instalación de Dovecot"
    
    sysrc dovecot_enable="YES"
    
    cd /usr/local/etc/dovecot/
    cp -R example-config/* .
    rm -rf example-config/
    
    # Configurar autenticación
    create_backup "/usr/local/etc/dovecot/conf.d/10-auth.conf"
    sed -i '' \
        -e 's/^#disable_plaintext_auth = yes/disable_plaintext_auth = yes/' \
        -e 's/^!include auth-system.conf.ext/#!include auth-system.conf.ext/' \
        -e 's/^#!include auth-passwdfile.conf.ext/!include auth-passwdfile.conf.ext/' \
        /usr/local/etc/dovecot/conf.d/10-auth.conf
    
    # Configurar mail
    cat >> /usr/local/etc/dovecot/conf.d/10-mail.conf << EOF
mail_home = /var/mail/vhosts/%d/%n
mail_location = maildir:~
EOF
    create_backup "/usr/local/etc/dovecot/conf.d/10-mail.conf"
    
    sed -i '' \
        -e 's/^#mail_uid =.*/mail_uid = 1002/' \
        -e 's/^#mail_gid =.*/mail_gid = 1002/' \
        -e 's/^#mail_privileged_group =.*/mail_privileged_group = vpostfix/' \
        /usr/local/etc/dovecot/conf.d/10-mail.conf
    
    # Configurar master
    create_backup "/usr/local/etc/dovecot/conf.d/10-master.conf"
    sed -i '' \
        -e 's/^#port = 993/port = 993/' \
        -e 's/^#ssl = yes/ssl = yes/' \
        -e 's/^#port = 587/port = 587/' \
        -e 's/^#user =.*/user = postfix/' \
        -e 's/^#group =.*/group = postfix/' \
        /usr/local/etc/dovecot/conf.d/10-master.conf
    
    # Configurar SSL
    create_backup "/usr/local/etc/dovecot/conf.d/10-ssl.conf"
    sed -i '' \
        -e 's/^#ssl = yes/ssl = yes/' \
        -e "s|^ssl_cert = </etc/ssl/certs/dovecot.pem|ssl_cert = </usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/fullchain.pem|" \
        -e "s|^ssl_key = </etc/ssl/private/dovecot.pem|ssl_key = </usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/privkey.pem|" \
        /usr/local/etc/dovecot/conf.d/10-ssl.conf
    
    # Agregar configuración SNI para múltiples dominios
    cat >> /usr/local/etc/dovecot/conf.d/10-ssl.conf << EOF

local_name ${MAIL_SUBDOMAIN_MAIN} {
  ssl_cert = </usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/fullchain.pem
  ssl_key = </usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/privkey.pem
}

local_name ${MAIL_SUBDOMAIN_SECONDARY} {
  ssl_cert = </usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_SECONDARY}/fullchain.pem
  ssl_key = </usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_SECONDARY}/privkey.pem
}
EOF
    
    check_command "Configuración de Dovecot"
}

# Función para configurar dominios iniciales
configure_initial_domains() {
    log_info "Configurando dominios iniciales..."
    
    cd /usr/local/etc/postfix/
    
    # Crear archivos de configuración
    cat > sender_access << EOF
${MAIN_DOMAIN} REJECT
${SECONDARY_DOMAIN} REJECT
EOF
    
    cat > virtual_domains << EOF
${MAIN_DOMAIN}
${SECONDARY_DOMAIN}
EOF
    
    cat > vmailbox << EOF
lucho@${MAIN_DOMAIN}    ${MAIN_DOMAIN}/lucho/
lucho@${SECONDARY_DOMAIN}    ${SECONDARY_DOMAIN}/lucho/
EOF
    
    # Crear directorios de correo
    cd /var/mail/vhosts
    mkdir -p ${MAIN_DOMAIN} ${SECONDARY_DOMAIN}
    chown -R vpostfix:vpostfix /var/mail/vhosts/
    
    cd /usr/local/etc/postfix/
    
    # Habilitar submission en master.cf
    sed -i.bak 's/^#submission\s*inet/submission inet/' /usr/local/etc/postfix/master.cf
    
    # Configurar SNI maps
    cat > sni_maps << EOF
${MAIL_SUBDOMAIN_MAIN}     /usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/privkey.pem,/usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/fullchain.pem
.${MAIL_SUBDOMAIN_MAIN}    /usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/privkey.pem,/usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_MAIN}/fullchain.pem
${MAIL_SUBDOMAIN_SECONDARY}     /usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_SECONDARY}/privkey.pem,/usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_SECONDARY}/fullchain.pem
.${MAIL_SUBDOMAIN_SECONDARY}    /usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_SECONDARY}/privkey.pem,/usr/local/etc/letsencrypt/live/${MAIL_SUBDOMAIN_SECONDARY}/fullchain.pem
EOF
    
    # Generar mapas
    postmap vmailbox
    postmap virtual
    postmap sender_access
    postmap sni_maps
    
    check_command "Configuración de dominios iniciales"
}

# Función para configurar OpenDKIM
configure_opendkim() {
    log_info "Configurando OpenDKIM..."
    
    # Crear usuario opendkim
    pw useradd -n opendkim -d /var/db/dkim -g mail -m -s /usr/sbin/nologin -w no 2>/dev/null || true
    
    pkg install -y opendkim
    check_command "Instalación de OpenDKIM"
    
    sysrc milteropendkim_enable="yes"
    sysrc milteropendkim_uid="opendkim"
    
    cd /usr/local/etc/mail/
    rm -f opendkim.conf.sample
    
    # Configurar OpenDKIM
    create_backup "/usr/local/etc/mail/opendkim.conf"
    cat > /usr/local/etc/mail/opendkim.conf << EOF
LogWhy yes
Syslog yes
Syslogsuccess yes
Canonicalization relaxed/simple
Socket inet:8891@localhost
ReportAddress root
SendReports yes
KeyTable refile:/usr/local/etc/mail/KeyTable
SigningTable refile:/usr/local/etc/mail/SigningTable
ExternalIgnoreList refile:/usr/local/etc/mail/TrustedHosts
InternalHosts refile:/usr/local/etc/mail/TrustedHosts
EOF
    
    # Crear archivos de configuración DKIM
    cat > /usr/local/etc/mail/KeyTable << EOF
media-lagn._domainkey.${MAIN_DOMAIN}    ${MAIN_DOMAIN}:media-lagn:/var/db/dkim/MEDIA-LAGN.private
luchoagn._domainkey.${SECONDARY_DOMAIN}    ${SECONDARY_DOMAIN}:luchoagn:/var/db/dkim/LUCHOAGN.private
EOF
    
    cat > /usr/local/etc/mail/SigningTable << EOF
*@${MAIN_DOMAIN}    media-lagn._domainkey.${MAIN_DOMAIN}
*@${SECONDARY_DOMAIN}    luchoagn._domainkey.${SECONDARY_DOMAIN}
EOF
    
    cat > /usr/local/etc/mail/TrustedHosts << EOF
127.0.0.1
localhost
${MAIN_DOMAIN}
${SECONDARY_DOMAIN}
EOF
    
    check_command "Configuración de OpenDKIM"
}

# Función principal
main() {
    log_info "Iniciando configuración del servidor de correo..."

    # Configurar trap para rollback en caso de error
    trap 'log_error "Script interrupted or failed. Attempting rollback..."; restore_last_backup; exit 1' ERR INT TERM

    # Limpiar respaldos al finalizar exitosamente
    trap 'log_info "Script completed successfully. Cleaning up backups..."; rm -f *.bak' EXIT
    
    # Verificar que se ejecuta como root
    if [ "$EUID" -ne 0 ]; then
        log_error "Este script debe ejecutarse como root"
        exit 1
    fi
    
    # Preguntar si desea configurar Certbot
    while true; do
        read -p "Do you want to configure Certbot for SSL certificates? (yes/no): " certbot_choice
        case "$certbot_choice" in
            [Yy][Ee][Ss] ) configure_certbot; break;;
            [Nn][Oo] ) log_info "Skipping Certbot configuration."; break;;
            * ) log_warning "Invalid choice. Please enter 'yes' or 'no'.";;
        esac
    done

    # Ejecutar el resto de las configuraciones
    configure_postfix
    configure_dovecot
    configure_initial_domains
    configure_opendkim
    
    log_info "¡Configuración completada exitosamente!"
    log_warning "Recuerda:"
    log_warning "1. Configurar los registros DNS necesarios"
    log_warning "2. Generar las claves DKIM con el CLI de gestión"
    log_warning "3. Reiniciar los servicios: postfix, dovecot, milter-opendkim"
}

# Ejecutar función principal
main "$@"