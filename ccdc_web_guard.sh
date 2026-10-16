#!/usr/bin/env bash
# ==============================================================================
# CCDC Real-Time Web Root Monitor & Self-Healer
# Usage:
#   ./ccdc_web_guard.sh /var/www           # Alert + quarantine webshells
#   ./ccdc_web_guard.sh /var/www --heal    # Auto-restore modified/deleted files
#                                          # and auto-delete newly dropped files
# ==============================================================================

set -u

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Run as root."
    exit 1
fi

WATCH_DIR="${1:-/var/www}"
MODE="${2:---alert}"
INTERVAL=2

if [[ ! -d "$WATCH_DIR" ]]; then
    echo "[-] Error: Directory ${WATCH_DIR} does not exist."
    exit 1
fi

VAULT_DIR="/root/.ccdc_vault/web_guard"
GOLDEN_DIR="${VAULT_DIR}/golden_copy"
CAUGHT_DIR="${VAULT_DIR}/caught_payloads"
LOG_FILE="${VAULT_DIR}/web_events.log"
BASELINE_MANIFEST="${VAULT_DIR}/baseline.sha256"
CURRENT_MANIFEST="${VAULT_DIR}/current.sha256"

mkdir -p "$VAULT_DIR" "$GOLDEN_DIR" "$CAUGHT_DIR"
chmod 700 "$VAULT_DIR"

log_alert() {
    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\a\033[1;31m[ALERT ${ts}]\033[0m $1" | tee -a "$LOG_FILE"
}

log_info() {
    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "\033[1;32m[INFO ${ts}]\033[0m $1" | tee -a "$LOG_FILE"
}

build_manifest() {
    local out_file="$1"
    find "$WATCH_DIR" -type f -exec sha256sum {} + 2>/dev/null | sort -k 2 > "$out_file"
}

check_webshell_sig() {
    local file="$1"
    grep -qE "(eval\(|base64_decode\(|gzinflate\(|shell_exec\(|passthru\(|system\(|pcntl_exec\(|\\\$_REQUEST\[|\\\$_GET\[.*\(|\bexec\()" "$file" 2>/dev/null
}

archive_payload() {
    local file="$1"
    local reason="$2"
    local ts
    ts=$(date +"%H%M%S")
    local safe_name
    safe_name=$(echo "$file" | tr '/' '_')
    cp -a "$file" "${CAUGHT_DIR}/${ts}_${reason}_${safe_name}" 2>/dev/null
}

log_info "Creating golden backup of ${WATCH_DIR} in ${GOLDEN_DIR}..."
rm -rf "${GOLDEN_DIR:?}/"*
cp -a "${WATCH_DIR}/." "$GOLDEN_DIR/"

log_info "Building initial SHA-256 baseline..."
build_manifest "$BASELINE_MANIFEST"

log_info "Watching ${WATCH_DIR} every ${INTERVAL}s (Mode: ${MODE}). Press Ctrl+C to stop."

while true; do
    sleep "$INTERVAL"
    build_manifest "$CURRENT_MANIFEST"

    if cmp -s "$BASELINE_MANIFEST" "$CURRENT_MANIFEST"; then
        continue
    fi

    # 1. Detect NEW files (Present in CURRENT, missing in BASELINE)
    comm -13 <(awk '{print $2}' "$BASELINE_MANIFEST") <(awk '{print $2}' "$CURRENT_MANIFEST") | while read -r new_file; do
        [[ -z "$new_file" ]] && continue
        log_alert "NEW FILE DETECTED: ${new_file}"
        archive_payload "$new_file" "NEW"

        if [[ "$MODE" == "--heal" ]]; then
            rm -f "$new_file"
            log_info "HEALED: Removed unauthorized new file ${new_file}"
        elif check_webshell_sig "$new_file"; then
            chmod 000 "$new_file"
            log_alert "WEBSHELL SIGNATURE MATCH! Stripped permissions (chmod 000) on ${new_file}"
        fi
    done

    # 2. Detect DELETED files (Present in BASELINE, missing in CURRENT)
    comm -23 <(awk '{print $2}' "$BASELINE_MANIFEST") <(awk '{print $2}' "$CURRENT_MANIFEST") | while read -r del_file; do
        [[ -z "$del_file" ]] && continue
        log_alert "FILE DELETED: ${del_file}"

        if [[ "$MODE" == "--heal" ]]; then
            rel_path="${del_file#"$WATCH_DIR"/}"
            mkdir -p "$(dirname "$del_file")"
            cp -a "${GOLDEN_DIR}/${rel_path}" "$del_file" 2>/dev/null
            log_info "HEALED: Restored deleted file ${del_file}"
        fi
    done

    # 3. Detect MODIFIED files (Same path, different SHA-256 hash)
    join -j 2 "$BASELINE_MANIFEST" "$CURRENT_MANIFEST" | awk '$2 != $3 {print $1}' | while read -r mod_file; do
        [[ -z "$mod_file" ]] && continue
        log_alert "FILE MODIFIED: ${mod_file}"
        archive_payload "$mod_file" "MODIFIED"

        if [[ "$MODE" == "--heal" ]]; then
            rel_path="${mod_file#"$WATCH_DIR"/}"
            cp -a "${GOLDEN_DIR}/${rel_path}" "$mod_file" 2>/dev/null
            log_info "HEALED: Restored modified file ${mod_file} from golden backup"
        elif check_webshell_sig "$mod_file"; then
            log_alert "WEBSHELL SIGNATURE IN MODIFIED FILE: ${mod_file} (Inspect manually!)"
        fi
    done

    # In --alert mode, update baseline so we don't spam the same alert every 2 seconds.
    # In --heal mode, keep the original golden baseline permanently.
    if [[ "$MODE" != "--heal" ]]; then
        cp -f "$CURRENT_MANIFEST" "$BASELINE_MANIFEST"
    fi
done

#Operational Tips for Competition Day
#Before turning on --heal mode: Make sure you have already cleaned out any pre-planted webshells in /var/www, otherwise the script will treat the pre-existing webshell as part of the "golden" state and diligently restore it if you delete it.
#Watch out for upload/cache folders in --heal mode: If the scored web application writes temporary session files or user uploads inside /var/www/html/uploads, --heal mode will delete them. Either run --alert mode or point --heal specifically at the core code directory (e.g., /var/www/html/includes).
#Free Incident Response Points: Every time Red Team drops a shell or modifies a file, ccdc_web_guard.sh saves an exact copy with a timestamp in /root/.ccdc_vault/web_guard/caught_payloads/. Attach those samples and timestamps directly to your CCDC Incident Response reports for easy points.
