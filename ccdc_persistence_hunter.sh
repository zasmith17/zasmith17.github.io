#!/usr/bin/env bash
# ==============================================================================
# CCDC Advanced Persistence Hunter (Systemd, SUID/Caps, PAM, SSH, Binaries)
# Usage:
#   ./ccdc_persistence_hunter.sh              # Audit and generate report
#   ./ccdc_persistence_hunter.sh --fix-suid   # Also strip rogue SUID & File Caps
# ==============================================================================

set -u

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Error: Run as root."
    exit 1
fi

FIX_SUID=0
[[ "${1:-}" == "--fix-suid" ]] && FIX_SUID=1

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="/root/.ccdc_vault/persistence_hunt_${TIMESTAMP}"
REPORT_FILE="${REPORT_DIR}/persistence_report.txt"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

RED='\033[1;31m'
YEL='\033[1;33m'
GRN='\033[1;32m'
CYN='\033[1;36m'
NC='\033[0m'

header() {
    echo -e "\n${CYN}======================================================================${NC}" | tee -a "$REPORT_FILE"
    echo -e "${CYN}[*] $1${NC}" | tee -a "$REPORT_FILE"
    echo -e "${CYN}======================================================================${NC}" | tee -a "$REPORT_FILE"
}

alert() {
    echo -e "${RED}[CRITICAL] $1${NC}" | tee -a "$REPORT_FILE"
}

warn() {
    echo -e "${YEL}[SUSPICIOUS] $1${NC}" | tee -a "$REPORT_FILE"
}

info() {
    echo -e "${GRN}[INFO] $1${NC}" | tee -a "$REPORT_FILE"
}

# ==============================================================================
# 1. SYSTEMD SERVICES, DROP-IN OVERRIDES, TIMERS & GENERATORS
# ==============================================================================
header "1. HUNTING ROGUE SYSTEMD UNITS, DROP-INS & GENERATORS"

# 1a. Detect Systemd Drop-in Overrides (*.d/*.conf)
# Red Team uses drop-ins to attach ExecStartPost=/bin/sh... to legitimate services
info "Checking for systemd drop-in overrides (*.d/*.conf)..."
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system /run/systemd/system \
    -type d -name "*.d" 2>/dev/null | while read -r dropdir; do
    if ls "$dropdir"/*.conf >/dev/null 2>&1; then
        warn "Drop-in override directory found: ${dropdir}"
        grep -rnE "(ExecStart|ExecStartPre|ExecStartPost|ExecReload|ExecStop)=" "$dropdir" 2>/dev/null | tee -a "$REPORT_FILE"
    fi
done

# 1b. Scan all unit files for suspicious execution paths or inline shells
info "Scanning systemd unit files for suspicious Exec* commands..."
grep -rnE "Exec(Start|StartPre|StartPost|Reload|Stop)=.*(/tmp/|/var/tmp/|/dev/shm/|/home/|/root/|curl |wget |nc |ncat |socat |bash -c|sh -c|python|perl|php|ruby|base64|chmod|chattr|iptables)" \
    /etc/systemd/ /lib/systemd/ /usr/lib/systemd/ /run/systemd/system/ 2>/dev/null | while read -r line; do
    alert "Suspicious Systemd Exec directive: ${line}"
done

# 1c. Identify unpackaged/custom unit files in /etc/systemd/system and /lib/systemd/system
info "Checking for unpackaged (rogue) systemd service/timer files..."
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -maxdepth 2 \
    \( -name "*.service" -o -name "*.timer" -o -name "*.socket" \) -type f 2>/dev/null | while read -r unit; do
    if command -v dpkg >/dev/null 2>&1; then
        if ! dpkg -S "$unit" >/dev/null 2>&1; then
            warn "Unpackaged systemd unit file: ${unit}"
            grep -E "(Description|ExecStart|User)=" "$unit" 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT_FILE"
        fi
    elif command -v rpm >/dev/null 2>&1; then
        if ! rpm -qf "$unit" >/dev/null 2>&1; then
            warn "Unpackaged systemd unit file: ${unit}"
            grep -E "(Description|ExecStart|User)=" "$unit" 2>/dev/null | sed 's/^/    /' | tee -a "$REPORT_FILE"
        fi
    fi
done

# 1d. Systemd Generators (execute arbitrary binaries on every daemon-reload / boot)
info "Auditing systemd system-generators..."
for gendir in /etc/systemd/system-generators /usr/local/lib/systemd/system-generators /run/systemd/system-generators; do
    if [[ -d "$gendir" ]] && [[ -n "$(ls -A "$gendir" 2>/dev/null)" ]]; then
        alert "Files found in non-standard systemd generator directory: ${gendir}"
        ls -la "$gendir" | tee -a "$REPORT_FILE"
    fi
done

# ==============================================================================
# 2. SUID / SGID BACKDOORS & LINUX FILE CAPABILITIES
# ==============================================================================
header "2. HUNTING SUID/SGID GTFOBINS & HIDDEN FILE CAPABILITIES"

# High-risk GTFOBins regex that should NEVER have SUID/SGID or capabilities
GTFOBINS_REGEX="/(bash|sh|dash|zsh|ksh|csh|tcsh|find|vim|vi|nano|emacs|ed|cp|mv|dd|tar|zip|unzip|gzip|bzip2|python[0-9.]*|perl|ruby|php[0-9.]*|lua|node|awk|gawk|mawk|nawk|sed|less|more|man|nmap|nc|ncat|netcat|socat|curl|wget|fetch|env|strace|ltrace|gdb|gcc|make|docker|lxc|ip|systemctl|journalctl|service|apt|apt-get|dpkg|yum|dnf|rpm|tee|xargs|chown|chmod|chattr|base64|xxd|od|tail|head|cat|cut|sort|uniq|rsync|scp|sftp|ssh-keygen|openssl|busybox)$"

info "Scanning filesystem for SUID/SGID binaries..."
find / -path /proc -prune -o -path /sys -prune -o -path /run -prune -o -perm /6000 -type f -print 2>/dev/null | while read -r suid_bin; do
    if [[ "$suid_bin" =~ $GTFOBINS_REGEX ]] || [[ "$suid_bin" =~ ^(/tmp|/var/tmp|/dev/shm|/home|/var/www|/opt) ]]; then
        alert "ROGUE SUID/SGID BINARY DETECTED: ${suid_bin} ($(ls -ld "$suid_bin" | awk '{print $1, $3, $4}'))"
        if [[ "$FIX_SUID" -eq 1 ]]; then
            chattr -i "$suid_bin" 2>/dev/null
            chmod a-s "$suid_bin" 2>/dev/null
            info "  -> [REMEDIATED] Stripped SUID/SGID bit from ${suid_bin}"
        fi
    else
        echo "    [Standard/Other SUID] ${suid_bin}" >> "$REPORT_FILE"
    fi
done

# 2b. Linux File Capabilities (Red Team's favorite SUID alternative: setcap cap_setuid+ep)
info "Scanning filesystem for binaries with elevated Linux Capabilities (getcap)..."
if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null | while read -r cap_line; do
        bin_path=$(echo "$cap_line" | awk '{print $1}')
        cap_val=$(echo "$cap_line" | awk '{print $2, $3}')
        if echo "$cap_val" | grep -qE "(cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace|cap_chown|cap_fowner|=ep)"; then
            alert "DANGEROUS FILE CAPABILITY: ${cap_line}"
            if [[ "$FIX_SUID" -eq 1 ]] && [[ "$bin_path" =~ $GTFOBINS_REGEX ]]; then
                setcap -r "$bin_path" 2>/dev/null
                info "  -> [REMEDIATED] Removed capabilities from ${bin_path}"
            fi
        else
            warn "File Capability present: ${cap_line}"
        fi
    done
fi

# ==============================================================================
# 3. PAM (PLUGGABLE AUTHENTICATION MODULES) BACKDOORS
# ==============================================================================
header "3. HUNTING PAM BACKDOORS (pam_exec, pam_permit, Trojanized .so)"

# 3a. Search /etc/pam.d/ for pam_exec.so (executes arbitrary script with plaintext password)
info "Checking /etc/pam.d/ for pam_exec.so hooks..."
if grep -rn "pam_exec\.so" /etc/pam.d/ 2>/dev/null; then
    alert "pam_exec.so detected in /etc/pam.d/! (Often used to exfiltrate passwords or spawn shells)"
    grep -rn "pam_exec\.so" /etc/pam.d/ 2>/dev/null >> "$REPORT_FILE"
fi

# 3b. Search /etc/pam.d/ for pam_permit.so in auth stacks (allows login with ANY password)
info "Checking /etc/pam.d/ for rogue pam_permit.so or sufficient auth bypasses..."
grep -rnE "^\s*auth\s+.*pam_permit\.so" /etc/pam.d/ 2>/dev/null | while read -r permit_line; do
    alert "PAM AUTH BYPASS (pam_permit.so in auth stack): ${permit_line}"
done

# 3c. Verify PAM shared library integrity (Detects patched pam_unix.so master passwords)
info "Verifying package checksums for PAM modules (detects trojanized pam_unix.so)..."
if command -v dpkg >/dev/null 2>&1; then
    dpkg --verify libpam-modules libpam-modules-bin libpam-runtime 2>/dev/null | while read -r vline; do
        alert "MODIFIED PAM BINARY/CONFIG (dpkg --verify): ${vline}"
    done
elif command -v rpm >/dev/null 2>&1; then
    rpm -Va pam 2>/dev/null | while read -r vline; do
        alert "MODIFIED PAM BINARY/CONFIG (rpm -Va): ${vline}"
    done
fi

# 3d. Check for unpackaged .so files inside PAM security directories
for pam_lib_dir in /lib/security /lib64/security /lib/x86_64-linux-gnu/security /usr/lib/security /usr/lib64/security /usr/lib/x86_64-linux-gnu/security; do
    if [[ -d "$pam_lib_dir" ]]; then
        find "$pam_lib_dir" -name "*.so*" -type f 2>/dev/null | while read -r so_file; do
            if command -v dpkg >/dev/null 2>&1 && ! dpkg -S "$so_file" >/dev/null 2>&1; then
                alert "UNPACKAGED ROGUE PAM MODULE: ${so_file}"
            elif command -v rpm >/dev/null 2>&1 && ! rpm -qf "$so_file" >/dev/null 2>&1; then
                alert "UNPACKAGED ROGUE PAM MODULE: ${so_file}"
            fi
        done
    fi
done

# ==============================================================================
# 4. ADVANCED SSH BACKDOORS
# ==============================================================================
header "4. HUNTING SSH DAEMON & RC BACKDOORS"

# 4a. Check effective sshd configuration via sshd -T
if command -v sshd >/dev/null 2>&1; then
    info "Inspecting active sshd runtime directives (sshd -T)..."
    SSHD_RUNTIME=$(sshd -T 2>/dev/null)

    # AuthorizedKeysCommand dynamically outputs keys even if authorized_keys is empty
    AK_CMD=$(echo "$SSHD_RUNTIME" | grep -i "^authorizedkeyscommand " | awk '{$1=""; print $0}')
    if [[ -n "$AK_CMD" && "$AK_CMD" != " none" ]]; then
        alert "SSH AuthorizedKeysCommand is active: ${AK_CMD}"
    fi

    # TrustedUserCAKeys allows Red Team to sign their own SSH certs for any user
    CA_KEYS=$(echo "$SSHD_RUNTIME" | grep -i "^trustedusercakeys " | awk '{$1=""; print $0}')
    if [[ -n "$CA_KEYS" && "$CA_KEYS" != " none" ]]; then
        alert "SSH TrustedUserCAKeys is active: ${CA_KEYS}"
    fi

    # AuthorizedKeysFile pointing to non-standard hidden paths
    AK_FILE=$(echo "$SSHD_RUNTIME" | grep -i "^authorizedkeysfile ")
    warn "Verify AuthorizedKeysFile paths: ${AK_FILE}"
fi

# 4b. Check for /etc/ssh/sshrc and user ~/.ssh/rc scripts (execute on SSH login)
if [[ -f /etc/ssh/sshrc ]]; then
    alert "Global /etc/ssh/sshrc file exists! Executes commands on every SSH login:"
    cat /etc/ssh/sshrc | tee -a "$REPORT_FILE"
fi

find /root /home -path "*/.ssh/rc" -type f 2>/dev/null | while read -r user_rc; do
    alert "User SSH rc script found: ${user_rc}"
    cat "$user_rc" | tee -a "$REPORT_FILE"
done

# ==============================================================================
# 5. SHELL PROFILES, LD_PRELOAD, & TROJANIZED CORE BINARIES
# ==============================================================================
header "5. HUNTING SHELL HOOKS & TROJANIZED SYSTEM BINARIES"

# 5a. Check shell profiles for PROMPT_COMMAND, alias sudo, or reverse shells
info "Scanning shell initialization files for PROMPT_COMMAND, traps, and aliases..."
grep -rnE "(PROMPT_COMMAND|alias sudo|trap |curl |wget |nc |bash -i|/dev/tcp/)" \
    /etc/profile /etc/profile.d/ /etc/bash.bashrc /etc/bashrc /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null | while read -r sh_line; do
    warn "Suspicious shell profile entry: ${sh_line}"
done

# 5b. Verify integrity of critical system binaries (sudo, sshd, login, ps, ss, netstat)
info "Verifying package checksums for core binaries (sudo, openssh-server, procps, coreutils)..."
if command -v dpkg >/dev/null 2>&1; then
    dpkg --verify sudo openssh-server login passwd procps net-tools iproute2 coreutils util-linux 2>/dev/null | while read -r bin_mod; do
        alert "TROJANIZED SYSTEM BINARY/FILE DETECTED: ${bin_mod}"
    done
elif command -v rpm >/dev/null 2>&1; then
    rpm -Va sudo openssh-server pam procps-ng net-tools iproute coreutils util-linux 2>/dev/null | grep -E "^..5" | while read -r bin_mod; do
        alert "TROJANIZED SYSTEM BINARY MD5 MISMATCH: ${bin_mod}"
    done
fi

echo -e "\n${GRN}[+] Hunt complete! Full report saved to: ${REPORT_FILE}${NC}"

#How to Safely Eradicate What You Find (Without Brick-Locking the Box)Persistence TypeSafe Eradication CommandCCDC Trap to AvoidTrojanized pam_unix.so or pam_permit.soDebian/Ubuntu: apt-get install --reinstall libpam-modules libpam-runtimeRHEL/Rocky: dnf reinstall pamNever delete .so files in /lib/x86_64-linux-gnu/security/ without first removing their reference in /etc/pam.d/, or sudo and sshd will immediately fail open/closed and lock you out of root.Systemd Drop-in Override (ssh.service.d/override.conf)chattr -i /etc/systemd/system/ssh.service.d/override.confrm -f /etc/systemd/system/ssh.service.d/override.confsystemctl daemon-reloadAlways inspect the override file before deleting it. Occasionally White Team puts custom environment variables for scored web apps inside a drop-in file.Hidden File Capability (python3 = cap_setuid+ep)setcap -r /usr/bin/python3.10Do not strip cap_net_raw from /bin/ping or cap_net_bind_service from web server binaries (nginx/apache2/node) if they run as non-root on port 80.SSH AuthorizedKeysCommand or TrustedUserCAKeysComment out both directives in /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*, then run sshd -t && systemctl reload sshd.Red Team often hides these directives inside /etc/ssh/sshd_config.d/50-redhat.conf or at the very bottom of /etc/ssh/sshd_config under a Match block.Trojanized sudo, ps, or ss binarychattr -i /usr/bin/sudoapt-get install --reinstall sudo procps iproute2Red Team sets the immutable bit (chattr +i) on replaced binaries so apt or dnf fails mid-transaction. Always run chattr -i on the flagged binary before reinstalling the package.
