#!/usr/bin/env bash
# ==============================================================================
# CCDC General Linux Web Server Hardening Script
# Supports: Debian/Ubuntu & RHEL/CentOS/Rocky/Fedora
# ==============================================================================

set -u

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Error: This script must be run as root."
    exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
VAULT_DIR="/root/.ccdc_vault_${TIMESTAMP}"
QUARANTINE_DIR="${VAULT_DIR}/quarantine"
AUDIT_LOG="${VAULT_DIR}/triage_report.txt"

# Add any usernames that the CCDC scoring engine uses so we don't lock them out
SCORED_USERS=("scoring" "ccdc" "white_team" "whiteteam")
# Set your current emergency admin user (will not be locked out)
ADMIN_USER="${SUDO_USER:-root}"

mkdir -p "$VAULT_DIR" "$QUARANTINE_DIR"
chmod 700 "$VAULT_DIR"

log() {
    echo -e "[+] $1" | tee -a "$AUDIT_LOG"
}

warn() {
    echo -e "[!] $1" | tee -a "$AUDIT_LOG"
}

is_scored_user() {
    local u="$1"
    for su in "${SCORED_USERS[@]}"; do
        [[ "$u" == "$su" ]] && return 0
    done
    return 1
}

# ------------------------------------------------------------------------------
# 1. Rapid Backups (Configs & Web Roots)
# ------------------------------------------------------------------------------
log "1. Backing up /etc and web directories to ${VAULT_DIR}..."
cp -a /etc "${VAULT_DIR}/etc_backup" 2>/dev/null

for webdir in /var/www /usr/share/nginx /srv/http /opt; do
    if [[ -d "$webdir" ]]; then
        tar -czf "${VAULT_DIR}/$(basename "$webdir")_backup.tar.gz" "$webdir" 2>/dev/null
    fi
done

# ------------------------------------------------------------------------------
# 2. Quarantine Red Team Persistence (SSH Keys, Crontabs, LD_PRELOAD)
# ------------------------------------------------------------------------------
log "2. Quarantining SSH keys, crontabs, and checking library hijacks..."

# Check /etc/ld.so.preload for rootkits
if [[ -s /etc/ld.so.preload ]]; then
    warn "CRITICAL: /etc/ld.so.preload is not empty! Quarantining..."
    cp -a /etc/ld.so.preload "${QUARANTINE_DIR}/ld.so.preload.bak"
    > /etc/ld.so.preload
fi

# Quarantine all authorized_keys across the filesystem
mkdir -p "${QUARANTINE_DIR}/ssh_keys"
find / -name "authorized_keys*" -type f 2>/dev/null | while read -r keyfile; do
    warn "Quarantining SSH key file: ${keyfile}"
    safe_name=$(echo "$keyfile" | tr '/' '_')
    chattr -i "$keyfile" 2>/dev/null
    mv "$keyfile" "${QUARANTINE_DIR}/ssh_keys/${safe_name}"
done

# Quarantine user crontabs
mkdir -p "${QUARANTINE_DIR}/crontabs"
for cron_spool in /var/spool/cron/crontabs /var/spool/cron; do
    if [[ -d "$cron_spool" ]]; then
        mv "${cron_spool}"/* "${QUARANTINE_DIR}/crontabs/" 2>/dev/null
    fi
done

# Lock down cron and at access to root only
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow
rm -f /etc/cron.deny /etc/at.deny 2>/dev/null

# ------------------------------------------------------------------------------
# 3. User & Account Auditing / Hardening
# ------------------------------------------------------------------------------
log "3. Auditing and locking down user accounts..."

# Detect non-root UID 0 accounts
awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd | while read -r rogue_root; do
    warn "CRITICAL: Rogue UID 0 account detected: ${rogue_root}"
done

# Lock shells for system/service accounts (UID < 1000 or >= 60000, plus web users)
awk -F: '($3 != 0 && ($3 < 1000 || $3 >= 60000)) {print $1":"$7}' /etc/passwd | while IFS=: read -r user shell; do
    if [[ "$shell" != "/usr/sbin/nologin" && "$shell" != "/sbin/nologin" && "$shell" != "/bin/false" && "$shell" != "/bin/sync" ]]; then
        if ! is_scored_user "$user"; then
            warn "Setting nologin shell for service account: ${user} (was ${shell})"
            usermod -s /sbin/nologin "$user" 2>/dev/null
        fi
    fi
done

# Secure critical auth files
chown root:root /etc/passwd /etc/group
chmod 644 /etc/passwd /etc/group
chown root:root /etc/shadow /etc/gshadow 2>/dev/null
chmod 000 /etc/shadow /etc/gshadow 2>/dev/null

# Audit sudoers for NOPASSWD or wildcards
grep -rnE "NOPASSWD|ALL=\(ALL" /etc/sudoers /etc/sudoers.d/ >> "$AUDIT_LOG" 2>/dev/null

# ------------------------------------------------------------------------------
# 4. CCDC-Safe SSH Hardening
# ------------------------------------------------------------------------------
log "4. Hardening SSH configuration (Keeping PasswordAuthentication for Scoring)..."
SSHD_CFG="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CFG" ]]; then
    chattr -i "$SSHD_CFG" 2>/dev/null
    cp -a "$SSHD_CFG" "${VAULT_DIR}/sshd_config.orig"

    # Remove malicious drop-in configs if any exist
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        mv /etc/ssh/sshd_config.d/*.conf "${QUARANTINE_DIR}/" 2>/dev/null
    fi

    sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CFG"
    sed -i -E 's/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CFG"
    sed -i -E 's/^#?MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CFG"
    sed -i -E 's/^#?X11Forwarding.*/X11Forwarding no/' "$SSHD_CFG"
    sed -i -E 's/^#?AllowTcpForwarding.*/AllowTcpForwarding no/' "$SSHD_CFG"
    sed -i -E 's/^#?PermitUserEnvironment.*/PermitUserEnvironment no/' "$SSHD_CFG"
    sed -i -E 's/^#?ClientAliveInterval.*/ClientAliveInterval 300/' "$SSHD_CFG"
    sed -i -E 's/^#?ClientAliveCountMax.*/ClientAliveCountMax 2/' "$SSHD_CFG"

    # Append explicit overrides at the end of sshd_config to ensure enforcement
    cat << 'EOF' >> "$SSHD_CFG"

# --- CCDC Hardening Overrides ---
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowTcpForwarding no
PermitUserEnvironment no
EOF

    if sshd -t 2>/dev/null; then
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null
        log "SSH reloaded successfully."
    else
        warn "SSH config test failed! Restoring backup..."
        cp -a "${VAULT_DIR}/sshd_config.orig" "$SSHD_CFG"
    fi
fi

# ------------------------------------------------------------------------------
# 5. Kernel & Network Stack Hardening (sysctl)
# ------------------------------------------------------------------------------
log "5. Applying kernel and network stack hardening via sysctl..."
cat << 'EOF' > /etc/sysctl.d/99-ccdc-hardening.conf
# Network Protections
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1

# Kernel & Memory Protections
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

sysctl --system >/dev/null 2>&1

# ------------------------------------------------------------------------------
# 6. Web Server & PHP Hardening (Apache, Nginx, PHP)
# ------------------------------------------------------------------------------
log "6. Hardening Web Server (Apache/Nginx) and PHP configurations..."

# 6a. PHP Hardening (Disable RCE functions & remote file inclusion)
find /etc -name "php.ini" -type f 2>/dev/null | while read -r phpini; do
    log "Hardening PHP config: ${phpini}"
    cp -a "$phpini" "${VAULT_DIR}/$( echo "$phpini" | tr '/' '_' ).bak"
    sed -i -E 's/^;?\s*expose_php\s*=.*/expose_php = Off/' "$phpini"
    sed -i -E 's/^;?\s*display_errors\s*=.*/display_errors = Off/' "$phpini"
    sed -i -E 's/^;?\s*allow_url_fopen\s*=.*/allow_url_fopen = Off/' "$phpini"
    sed -i -E 's/^;?\s*allow_url_include\s*=.*/allow_url_include = Off/' "$phpini"
    sed -i -E 's/^;?\s*session\.cookie_httponly\s*=.*/session.cookie_httponly = 1/' "$phpini"
    sed -i -E 's/^;?\s*disable_functions\s*=.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source,pcntl_exec,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid/' "$phpini"
done

# 6b. Apache Hardening (Debian/Ubuntu & RHEL)
for apache_dir in /etc/apache2 /etc/httpd; do
    if [[ -d "$apache_dir" ]]; then
        log "Hardening Apache in ${apache_dir}..."
        conf_target="${apache_dir}/conf-available/ccdc-security.conf"
        [[ ! -d "${apache_dir}/conf-available" ]] && conf_target="${apache_dir}/conf.d/ccdc-security.conf"

        cat << 'EOF' > "$conf_target"
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None
Header always append X-Frame-Options SAMEORIGIN
Header always set X-Content-Type-Options nosniff
<Directory /var/www/>
    Options -Indexes -Includes -ExecCGI
    AllowOverride None
</Directory>
EOF
        if command -v a2enconf >/dev/null 2>&1; then
            a2enmod headers >/dev/null 2>&1
            a2enconf ccdc-security >/dev/null 2>&1
        fi
        systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null
    fi
done

# 6c. Nginx Hardening
if [[ -f /etc/nginx/nginx.conf ]]; then
    log "Hardening Nginx..."
    sed -i -E 's/#?\s*server_tokens\s+on;/server_tokens off;/' /etc/nginx/nginx.conf
    if ! grep -q "server_tokens off;" /etc/nginx/nginx.conf; then
        sed -i '/http\s*{/a \    server_tokens off;' /etc/nginx/nginx.conf
    fi
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null
fi

# Restart PHP-FPM if running
systemctl list-units --type=service --state=running | awk '/php.*fpm/{print $1}' | while read -r phpsvc; do
    systemctl restart "$phpsvc" 2>/dev/null
done

# 6d. Web Root Permissions & Webshell Scan
if [[ -d /var/www ]]; then
    log "Locking down permissions in /var/www and stripping SUID/SGID bits..."
    find /var/www -type f -perm /6000 -exec chmod a-s {} + 2>/dev/null
    find /var/www -type d -exec chmod 755 {} + 2>/dev/null
    find /var/www -type f -exec chmod 644 {} + 2>/dev/null

    log "Scanning /var/www for suspect PHP webshells (saved to triage report)..."
    echo -e "\n=== SUSPECT WEBSHELL SCAN ===" >> "$AUDIT_LOG"
    grep -rnE "(eval\(|base64_decode\(|gzinflate\(|shell_exec\(|passthru\(|system\(|cmd=|\\\$_REQUEST\[|\\\$_GET\[.*\(|\bexec\()" /var/www/ >> "$AUDIT_LOG" 2>/dev/null
fi

# ------------------------------------------------------------------------------
# 7. Host Firewall Setup (iptables Inbound Lockdown)
# ------------------------------------------------------------------------------
log "7. Applying baseline iptables rules (Allowing SSH/22, HTTP/80, HTTPS/443, ICMP)..."
if command -v iptables >/dev/null 2>&1; then
    # Save current rules before modifying
    iptables-save > "${VAULT_DIR}/iptables.orig" 2>/dev/null

    # Flush existing rules cleanly while keeping defaults ACCEPT during setup
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -F

    # Allow loopback and existing/established connections
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ICMP (Scoring engines frequently ping hosts)
    iptables -A INPUT -p icmp -j ACCEPT

    # Allow SSH, HTTP, HTTPS
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    # Drop invalid packets and unsolicited inbound traffic
    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    log "Firewall rules active (Inbound: 22, 80, 443, ICMP allowed; all else dropped)."
fi

# ------------------------------------------------------------------------------
# 8. Forensic Triage Snapshot
# ------------------------------------------------------------------------------
log "8. Generating forensic triage snapshot in ${AUDIT_LOG}..."
{
    echo -e "\n=== LISTENING PORTS & PROCESSES ==="
    ss -tulpn

    echo -e "\n=== ACTIVE NETWORK CONNECTIONS ==="
    ss -tupn state established

    echo -e "\n=== SUID / SGID BINARIES (Check via GTFOBins) ==="
    find / -path /proc -prune -o -perm /6000 -type f -ls 2>/dev/null

    echo -e "\n=== SYSTEMD TIMERS & CRON DIRECTORIES ==="
    ls -la /etc/cron* /var/spool/cron* 2>/dev/null
    systemctl list-timers --all --no-pager

    echo -e "\n=== RECENTLY MODIFIED FILES IN /var/www (Last 3 Days) ==="
    find /var/www -mtime -3 -ls 2>/dev/null
} >> "$AUDIT_LOG"

log "Hardening complete! Review ${AUDIT_LOG} immediately for anomalies."
