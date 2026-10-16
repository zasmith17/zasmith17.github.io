#!/usr/bin/env bash
# ==============================================================================
# CCDC Day 1 Passive Recon & Day 2 Automated Purge ("Sleeper")
# Recommended Path: /usr/lib/systemd/systemd-journal-flush
#
# Usage:
#   ./systemd-journal-flush --init     # Day 1 Start: Build hidden golden baseline
#   ./systemd-journal-flush --watch &  # Day 1 Loop: Disguised passive note-taker
#   ./systemd-journal-flush --report   # Day 1/2: View attacker notes & kill-list
#   ./systemd-journal-flush --purge    # Day 2 Start: Execute all queued fixes
# ==============================================================================

set -u

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Run as root."
    exit 1
fi

# Inconspicuous hidden storage directory (looks like systemd internal cache)
HIDDEN_DIR="/var/lib/systemd/.coredump-cache"
GOLD_DIR="${HIDDEN_DIR}/gold"
SAMPLES_DIR="${HIDDEN_DIR}/samples"
STATE_DIR="${HIDDEN_DIR}/state"
IR_NOTES="${HIDDEN_DIR}/attacker_notes.log"
KILL_LIST="${HIDDEN_DIR}/day2_killlist.db"

# Directories to monitor passively on Day 1
WATCH_TARGETS=("/etc" "/var/www" "/root" "/home" "/var/spool/cron" "/usr/local/bin" "/lib/systemd/system" "/usr/lib/systemd/system")

# Poll interval in seconds (10s keeps CPU usage near 0% so 'top' looks normal)
POLL_INTERVAL=10

mkdir -p "$GOLD_DIR" "$SAMPLES_DIR" "$STATE_DIR"
chmod 700 "$HIDDEN_DIR"
touch "$IR_NOTES" "$KILL_LIST"

note() {
    local category="$1"
    local msg="$2"
    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[${ts}] [${category}] ${msg}" >> "$IR_NOTES"
}

queue_action() {
    local action_type="$1"
    local target="$2"
    local entry="${action_type}|${target}"
    # Deduplicate entries in the Day 2 kill-list
    if ! grep -Fxq "$entry" "$KILL_LIST" 2>/dev/null; then
        echo "$entry" >> "$KILL_LIST"
    fi
}

save_sample() {
    local filepath="$1"
    local ts
    ts=$(date +"%H%M%S")
    local flat_name
    flat_name=$(echo "$filepath" | tr '/' '_')
    cp -a "$filepath" "${SAMPLES_DIR}/${ts}_${flat_name}" 2>/dev/null
}

build_fs_manifest() {
    local outfile="$1"
    > "$outfile"
    for dir in "${WATCH_TARGETS[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -type f -exec sha256sum {} + 2>/dev/null >> "$outfile"
        fi
    done
    sort -k 2 "$outfile" -o "$outfile"
}

build_suid_manifest() {
    local outfile="$1"
    find / -path /proc -prune -o -path /sys -prune -o -path /run -prune -o -perm /6000 -type f -print 2>/dev/null | sort > "$outfile"
}

build_caps_manifest() {
    local outfile="$1"
    if command -v getcap >/dev/null 2>&1; then
        getcap -r / 2>/dev/null | sort > "$outfile"
    else
        > "$outfile"
    fi
}

# ==============================================================================
# MODE 1: --init (Take Golden Snapshot at Start of Day 1)
# ==============================================================================
do_init() {
    echo "[*] Initializing hidden Day 1 baseline in ${HIDDEN_DIR}..."
    rm -rf "${GOLD_DIR:?}/"* "${STATE_DIR:?}/"*
    > "$IR_NOTES"
    > "$KILL_LIST"

    # Mirror watched directories preserving full path structure (cp --parents)
    for dir in "${WATCH_TARGETS[@]}"; do
        if [[ -d "$dir" ]]; then
            cp -a --parents "$dir" "$GOLD_DIR/" 2>/dev/null
        fi
    done

    build_fs_manifest "${STATE_DIR}/baseline_fs.sha256"
    cp -f "${STATE_DIR}/baseline_fs.sha256" "${STATE_DIR}/last_fs.sha256"

    build_suid_manifest "${STATE_DIR}/baseline_suid.txt"
    cp -f "${STATE_DIR}/baseline_suid.txt" "${STATE_DIR}/last_suid.txt"

    build_caps_manifest "${STATE_DIR}/baseline_caps.txt"
    cp -f "${STATE_DIR}/baseline_caps.txt" "${STATE_DIR}/last_caps.txt"

    ss -tulpn | awk 'NR>1 {print $5}' | sort -u > "${STATE_DIR}/baseline_ports.txt"
    cp -f "${STATE_DIR}/baseline_ports.txt" "${STATE_DIR}/last_ports.txt"

    note "INIT" "Day 1 baseline snapshot completed. Passive monitoring ready."
    echo "[+] Baseline complete. Start stealth watcher with: $0 --watch &"
}

# ==============================================================================
# MODE 2: --watch (Disguised Passive Recon Loop for Day 1)
# ==============================================================================
do_watch() {
    if [[ ! -f "${STATE_DIR}/baseline_fs.sha256" ]]; then
        echo "[-] Run --init first."
        exit 1
    fi

    # Re-exec under a disguised process name [kworker/u4:2-events] if not already disguised
    if [[ "${CCDC_DISGUISED:-0}" != "1" ]]; then
        export CCDC_DISGUISED=1
        exec -a "[kworker/u4:2-events]" "$0" --watch-internal
    fi
}

do_watch_internal() {
    note "WATCHER" "Stealth watcher started under disguised process name (PID $$)."

    while true; do
        sleep "$POLL_INTERVAL"

        # ----------------------------------------------------------------------
        # A. Check Filesystem Additions, Modifications, and Deletions
        # ----------------------------------------------------------------------
        build_fs_manifest "${STATE_DIR}/curr_fs.sha256"

        if ! cmp -s "${STATE_DIR}/last_fs.sha256" "${STATE_DIR}/curr_fs.sha256"; then
            # 1. Newly Created Files
            comm -13 <(awk '{print $2}' "${STATE_DIR}/last_fs.sha256") <(awk '{print $2}' "${STATE_DIR}/curr_fs.sha256") | while read -r newf; do
                [[ -z "$newf" ]] && continue
                owner_perms=$(ls -ld "$newf" 2>/dev/null | awk '{print $1, $3":"$4}')
                note "FILE_CREATED" "${newf} (${owner_perms})"
                save_sample "$newf"
                queue_action "DELETE_FILE" "$newf"

                # If it's a systemd service or timer, also queue stopping/disabling the unit
                if [[ "$newf" =~ \.(service|timer|socket)$ ]]; then
                    unit_name=$(basename "$newf")
                    note "ROGUE_SYSTEMD" "Attacker registered unit ${unit_name} at ${newf}"
                    queue_action "DISABLE_UNIT" "$unit_name"
                fi
            done

            # 2. Modified Files (Compare against previous loop to log each change)
            join -j 2 "${STATE_DIR}/last_fs.sha256" "${STATE_DIR}/curr_fs.sha256" | awk '$2 != $3 {print $1}' | while read -r modf; do
                [[ -z "$modf" ]] && continue
                note "FILE_MODIFIED" "${modf}"
                save_sample "$modf"

                # Record unified diff against golden copy if text file
                if [[ -f "${GOLD_DIR}${modf}" ]]; then
                    diff_out=$(diff -u "${GOLD_DIR}${modf}" "$modf" 2>/dev/null | head -n 30)
                    if [[ -n "$diff_out" ]]; then
                        echo "    --- DIFF FOR ${modf} ---" >> "$IR_NOTES"
                        echo "$diff_out" | sed 's/^/    /' >> "$IR_NOTES"
                    fi
                    queue_action "RESTORE_FILE" "$modf"
                fi
            done

            # 3. Deleted Files
            comm -23 <(awk '{print $2}' "${STATE_DIR}/last_fs.sha256") <(awk '{print $2}' "${STATE_DIR}/curr_fs.sha256") | while read -r delf; do
                [[ -z "$delf" ]] && continue
                note "FILE_DELETED" "${delf}"
                if [[ -f "${GOLD_DIR}${delf}" ]]; then
                    queue_action "RESTORE_FILE" "$delf"
                fi
            done

            cp -f "${STATE_DIR}/curr_fs.sha256" "${STATE_DIR}/last_fs.sha256"
        fi

        # ----------------------------------------------------------------------
        # B. Check for New SUID/SGID Backdoors
        # ----------------------------------------------------------------------
        build_suid_manifest "${STATE_DIR}/curr_suid.txt"
        comm -13 "${STATE_DIR}/last_suid.txt" "${STATE_DIR}/curr_suid.txt" | while read -r new_suid; do
            [[ -z "$new_suid" ]] && continue
            note "SUID_PLANTED" "Attacker added SUID/SGID bit to: ${new_suid}"
            queue_action "STRIP_SUID" "$new_suid"
        done
        cp -f "${STATE_DIR}/curr_suid.txt" "${STATE_DIR}/last_suid.txt"

        # ----------------------------------------------------------------------
        # C. Check for New Linux File Capabilities (e.g., cap_setuid+ep)
        # ----------------------------------------------------------------------
        build_caps_manifest "${STATE_DIR}/curr_caps.txt"
        comm -13 "${STATE_DIR}/last_caps.txt" "${STATE_DIR}/curr_caps.txt" | while read -r new_cap; do
            [[ -z "$new_cap" ]] && continue
            cap_bin=$(echo "$new_cap" | awk '{print $1}')
            note "CAPABILITY_PLANTED" "Attacker set capability: ${new_cap}"
            queue_action "STRIP_CAP" "$cap_bin"
        done
        cp -f "${STATE_DIR}/curr_caps.txt" "${STATE_DIR}/last_caps.txt"

        # ----------------------------------------------------------------------
        # D. Check for New Listening Ports & Suspicious Outbound Shells
        # ----------------------------------------------------------------------
        ss -tulpn | awk 'NR>1 {print $5"|"$7}' | sort -u > "${STATE_DIR}/curr_ports_full.txt"
        awk -F'|' '{print $1}' "${STATE_DIR}/curr_ports_full.txt" | sort -u > "${STATE_DIR}/curr_ports.txt"

        comm -13 "${STATE_DIR}/last_ports.txt" "${STATE_DIR}/curr_ports.txt" | while read -r new_port; do
            [[ -z "$new_port" ]] && continue
            proc_info=$(grep -F "${new_port}|" "${STATE_DIR}/curr_ports_full.txt" | cut -d'|' -f2)
            note "NEW_LISTENER" "Port ${new_port} opened by ${proc_info}"
        done
        cp -f "${STATE_DIR}/curr_ports.txt" "${STATE_DIR}/last_ports.txt"

        # Log processes running out of /tmp, /dev/shm, or /var/tmp
        ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E "(/tmp/|/dev/shm/|/var/tmp/|\(deleted\))" | while read -r rogue_exe; do
            pid=$(echo "$rogue_exe" | awk -F'/' '{print $3}')
            cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null)
            bin_target=$(echo "$rogue_exe" | awk '{print $NF}')
            if ! grep -Fq "PID ${pid} (${cmdline})" "$IR_NOTES" 2>/dev/null; then
                note "SUSPICIOUS_PROC" "PID ${pid} (${cmdline}) running from ${bin_target}"
            fi
        done
    done
}

# ==============================================================================
# MODE 3: --report (View Collected Red Team Intel & Queued Day 2 Fixes)
# ==============================================================================
do_report() {
    echo "======================================================================"
    echo "                 DAY 1 RED TEAM ACTIVITY TIMELINE                     "
    echo "======================================================================"
    if [[ -s "$IR_NOTES" ]]; then
        cat "$IR_NOTES"
    else
        echo "(No events recorded yet)"
    fi

    echo ""
    echo "======================================================================"
    echo "               QUEUED DAY 2 ERADICATION ACTIONS                       "
    echo "======================================================================"
    if [[ -s "$KILL_LIST" ]]; then
        nl -w3 -s'. ' "$KILL_LIST"
    else
        echo "(No remediation actions queued yet)"
    fi
    echo "======================================================================"
    echo "[*] Captured attacker payloads stored in: ${SAMPLES_DIR}"
}

# ==============================================================================
# MODE 4: --purge (Day 2 Morning Instant Eradication)
# ==============================================================================
do_purge() {
    echo "[!] EXECUTING DAY 2 PURGE FROM QUEUED INTELLIGENCE..."

    # 1. Stop the background passive watcher so it doesn't conflict
    pkill -f "watch-internal" 2>/dev/null

    # 2. Process every queued remediation item from Day 1
    while IFS='|' read -r action target; do
        [[ -z "$action" || -z "$target" ]] && continue
        case "$action" in
            DISABLE_UNIT)
                echo "[+] Stopping & disabling rogue systemd unit: ${target}"
                systemctl stop "$target" 2>/dev/null
                systemctl disable "$target" 2>/dev/null
                ;;
            DELETE_FILE)
                if [[ -e "$target" ]]; then
                    echo "[+] Removing attacker-created file: ${target}"
                    chattr -i "$target" 2>/dev/null
                    rm -rf "$target"
                fi
                ;;
            RESTORE_FILE)
                if [[ -e "${GOLD_DIR}${target}" ]]; then
                    echo "[+] Restoring tampered file from Day 1 baseline: ${target}"
                    chattr -i "$target" 2>/dev/null
                    mkdir -p "$(dirname "$target")"
                    cp -a "${GOLD_DIR}${target}" "$target"
                fi
                ;;
            STRIP_SUID)
                if [[ -e "$target" ]]; then
                    echo "[+] Stripping rogue SUID/SGID bit from: ${target}"
                    chattr -i "$target" 2>/dev/null
                    chmod a-s "$target"
                fi
                ;;
            STRIP_CAP)
                if [[ -e "$target" ]] && command -v setcap >/dev/null 2>&1; then
                    echo "[+] Removing rogue file capabilities from: ${target}"
                    setcap -r "$target" 2>/dev/null
                fi
                ;;
        esac
    done < "$KILL_LIST"

    # 3. Kill processes running out of /tmp, /dev/shm, /var/tmp, or deleted binaries
    echo "[+] Terminating processes running from /tmp, /dev/shm, or deleted binaries..."
    ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E "(/tmp/|/dev/shm/|/var/tmp/|\(deleted\))" | awk -F'/' '{print $3}' | while read -r rpid; do
        echo "    -> Killing PID ${rpid} ($(tr '\0' ' ' < /proc/${rpid}/cmdline 2>/dev/null))"
        kill -9 "$rpid" 2>/dev/null
    done

    # 4. Reload systemd & services to apply restored configs cleanly
    systemctl daemon-reload 2>/dev/null
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null
    systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || systemctl reload nginx 2>/dev/null

    note "PURGE_COMPLETE" "Executed Day 2 purge across all queued items."
    echo "[+] Day 2 Purge Complete! Now run your password rotation & hardening scripts."
}

case "${1:-}" in
    --init)           do_init ;;
    --watch)          do_watch ;;
    --watch-internal) do_watch_internal ;;
    --report)         do_report ;;
    --purge)          do_purge ;;
    *)
        echo "Usage: $0 {--init|--watch|--report|--purge}"
        exit 1
        ;;
esac

#Your Day 1 vs. Day 2 GameplanPhaseExact Commands to RunWhy It WorksDay 1: Minute 1chmod 700 /usr/lib/systemd/systemd-journal-flush/usr/lib/systemd/systemd-journal-flush --init/usr/lib/systemd/systemd-journal-flush --watch &history -c && > ~/.bash_historySnapshots the clean state, launches the watcher disguised as [kworker/u4:2-events], and wipes your shell history so Red Team doesn't know they're being recorded.Day 1: Afternoon/usr/lib/systemd/systemd-journal-flush --reportGives you exact timestamps, file paths, and unified diffs of every backdoor Red Team planted so you can write detailed Incident Response reports for massive points on Day 1 without alerting Red Team.Day 2: Minute 1/usr/lib/systemd/systemd-journal-flush --purge./ccdc_web_harden.sh./ccdc_pass_rotate.sh --kick./ccdc_web_guard.sh /var/www --heal &Instantly deletes every Day 1 backdoor, restores every modified config, locks down the firewall/SSH/PHP, rotates all passwords while kicking active sessions, and turns on active self-healing.One Critical Day 1 Precaution: Exfiltrate Your Own BackupEven though Red Team rules usually forbid intentionally bricking servers on Day 1, an aggressive Red Teamer might still stumble across your hidden directory or accidentally break a database. Halfway through Day 1 (and right before Day 1 ends), scp a copy of /var/lib/systemd/.coredump-cache off the server onto your local analyst workstation so your Day 1 intelligence and clean backups survive even if the VM is wiped at the start of Day 2.
