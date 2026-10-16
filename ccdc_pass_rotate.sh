#!/usr/bin/env bash
# ==============================================================================
# CCDC Bulk Password Rotator
# Usage:
#   ./ccdc_pass_rotate.sh                        # Random safe passwords
#   ./ccdc_pass_rotate.sh --secret "TeamKey2026" # Deterministic passwords
#   ./ccdc_pass_rotate.sh --kick                 # Also kill active user sessions
# ==============================================================================

set -u

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Run as root."
    exit 1
fi

# Users that should NEVER have their passwords rotated by this script
# Add your current admin user or specific scoring users here if needed
EXCLUDE_USERS=("scoring" "white_team" "whiteteam" "ccdc" "sync" "halt" "shutdown")

VAULT_DIR="/root/.ccdc_vault"
mkdir -p "$VAULT_DIR"
chmod 700 "$VAULT_DIR"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PASS_FILE="${VAULT_DIR}/passwords_${TIMESTAMP}.csv"

TEAM_SECRET=""
KICK_SESSIONS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --secret)
            TEAM_SECRET="$2"
            shift 2
            ;;
        --kick)
            KICK_SESSIONS=1
            shift
            ;;
        *)
            echo "Usage: $0 [--secret <SEED>] [--kick]"
            exit 1
            ;;
    esac
done

is_excluded() {
    local target="$1"
    for ex in "${EXCLUDE_USERS[@]}"; do
        [[ "$target" == "$ex" ]] && return 0
    done
    return 1
}

generate_password() {
    local user="$1"
    if [[ -n "$TEAM_SECRET" ]]; then
        # Deterministic: First 12 chars of SHA256(user:secret) + fixed complexity suffix
        local hash_part
        hash_part=$(echo -n "${user}:${TEAM_SECRET}" | sha256sum | cut -c1-12)
        echo "${hash_part}Aa9"
    else
        # Random 16-char unambiguous alphanumeric (no 0/O/1/l/I or shell metacharacters)
        tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | head -c 16
        echo ""
    fi
}

echo "username,password" > "$PASS_FILE"
chmod 600 "$PASS_FILE"

echo "========================================================"
printf "%-20s | %-22s | %s\n" "USERNAME" "NEW PASSWORD" "STATUS"
echo "========================================================"

# Select all accounts with valid interactive login shells (plus root)
awk -F: '($7 !~ /(nologin|false|sync|halt|shutdown)$/ || $1 == "root") {print $1}' /etc/passwd | while read -r user; do
    if is_excluded "$user"; then
        printf "%-20s | %-22s | %s\n" "$user" "(SKIPPED)" "Excluded"
        continue
    fi

    NEW_PASS=$(generate_password "$user")

    if echo "${user}:${NEW_PASS}" | chpasswd 2>/dev/null; then
        echo "${user},${NEW_PASS}" >> "$PASS_FILE"
        printf "%-20s | %-22s | %s\n" "$user" "$NEW_PASS" "ROTATED"

        # Unlock account in case Red Team triggered faillock/pam_tally2
        passwd -u "$user" >/dev/null 2>&1
        faillock --user "$user" --reset >/dev/null 2>&1

        # Kill active sessions for this user if --kick is passed (skip root & current sudo user)
        if [[ "$KICK_SESSIONS" -eq 1 && "$user" != "root" && "$user" != "${SUDO_USER:-}" ]]; then
            pkill -KILL -u "$user" 2>/dev/null
        fi
    else
        printf "%-20s | %-22s | %s\n" "$user" "(ERROR)" "Failed"
    fi
done

echo "========================================================"
echo "[+] CSV saved to: ${PASS_FILE}"
