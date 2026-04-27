#!/usr/bin/env bash
# log_monitor.sh — Aldo Pilers
# Watches system auth logs for suspicious activity and alerts to console + alert log.
# Detects: failed SSH logins, brute force patterns, sudo abuse, new user creation.
#
# Usage:
#   chmod +x log_monitor.sh
#   sudo ./log_monitor.sh              # live monitoring
#   ./log_monitor.sh --test            # dry-run against sample log lines

set -euo pipefail

ALERT_LOG="./security_alerts.log"
BRUTE_THRESHOLD=5      # failed logins from same IP before flagging brute force
CHECK_INTERVAL=10      # seconds between log polls (live mode)

# Detect OS log location
if [[ -f /var/log/auth.log ]]; then
    AUTH_LOG="/var/log/auth.log"          # Debian/Ubuntu
elif [[ -f /var/log/secure ]]; then
    AUTH_LOG="/var/log/secure"            # RHEL/CentOS
else
    AUTH_LOG=""
fi

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'

alert() {
    local severity="$1"; local msg="$2"
    local ts; ts=$(date '+%Y-%m-%dT%H:%M:%SZ')
    local line="[$ts] [$severity] $msg"
    echo -e "${RED}⚠  ALERT${NC} $line"
    echo "$line" >> "$ALERT_LOG"
}

info() { echo -e "${GREEN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

# ── Analyse a block of log text ───────────────────────────────────────────────
analyse_lines() {
    local lines="$1"

    # Failed SSH logins
    local failed_ssh
    failed_ssh=$(echo "$lines" | grep -i "Failed password" || true)
    if [[ -n "$failed_ssh" ]]; then
        while IFS= read -r line; do
            local ip; ip=$(echo "$line" | grep -oP '(?<=from )\S+' || echo "unknown")
            alert "HIGH" "Failed SSH login from $ip"
        done <<< "$failed_ssh"
    fi

    # Brute force: count failed attempts per IP
    declare -A ip_counts
    while IFS= read -r line; do
        local ip; ip=$(echo "$line" | grep -oP '(?<=from )\S+' || true)
        [[ -z "$ip" ]] && continue
        ip_counts["$ip"]=$(( ${ip_counts["$ip"]:-0} + 1 ))
    done <<< "$(echo "$lines" | grep -i "Failed password" || true)"

    for ip in "${!ip_counts[@]}"; do
        if (( ip_counts["$ip"] >= BRUTE_THRESHOLD )); then
            alert "CRITICAL" "Possible brute force from $ip — ${ip_counts[$ip]} failed attempts detected"
        fi
    done

    # Successful login after failures (potential credential stuffing success)
    local success_after
    success_after=$(echo "$lines" | grep -i "Accepted password\|Accepted publickey" || true)
    if [[ -n "$success_after" ]]; then
        while IFS= read -r line; do
            local ip; ip=$(echo "$line" | grep -oP '(?<=from )\S+' || echo "unknown")
            local user; user=$(echo "$line" | grep -oP '(?<=for )\S+' || echo "unknown")
            alert "MEDIUM" "Successful SSH login: user=$user ip=$ip"
        done <<< "$success_after"
    fi

    # Sudo usage
    local sudo_use
    sudo_use=$(echo "$lines" | grep -i "sudo:" | grep -v "pam_unix" || true)
    if [[ -n "$sudo_use" ]]; then
        while IFS= read -r line; do
            alert "MEDIUM" "Sudo command executed: $line"
        done <<< "$sudo_use"
    fi

    # New user created
    local new_user
    new_user=$(echo "$lines" | grep -i "new user\|useradd\|adduser" || true)
    if [[ -n "$new_user" ]]; then
        alert "HIGH" "New user account created — verify this was authorized"
    fi

    # Root login
    local root_login
    root_login=$(echo "$lines" | grep -i "session opened for user root" || true)
    if [[ -n "$root_login" ]]; then
        alert "HIGH" "Direct root login session opened"
    fi
}

# ── Test mode with sample data ────────────────────────────────────────────────
run_test() {
    info "Running in TEST MODE with sample log data...\n"
    local sample_lines
    sample_lines=$(cat << 'SAMPLE'
Apr 20 10:01:01 server sshd[1234]: Failed password for admin from 203.0.113.42 port 51234 ssh2
Apr 20 10:01:03 server sshd[1235]: Failed password for root from 203.0.113.42 port 51235 ssh2
Apr 20 10:01:05 server sshd[1236]: Failed password for ubuntu from 203.0.113.42 port 51236 ssh2
Apr 20 10:01:07 server sshd[1237]: Failed password for admin from 203.0.113.42 port 51237 ssh2
Apr 20 10:01:09 server sshd[1238]: Failed password for test from 203.0.113.42 port 51238 ssh2
Apr 20 10:01:11 server sshd[1239]: Failed password for user from 203.0.113.42 port 51239 ssh2
Apr 20 10:05:00 server sshd[1240]: Accepted password for aldo from 10.0.0.5 port 22222 ssh2
Apr 20 10:06:00 server sudo:     aldo : TTY=pts/0 ; PWD=/home/aldo ; USER=root ; COMMAND=/bin/cat /etc/shadow
Apr 20 10:07:00 server useradd[9999]: new user: name=backdoor, UID=0
SAMPLE
)
    analyse_lines "$sample_lines"
    echo ""
    info "Test complete. Check $ALERT_LOG for saved alerts."
}

# ── Live mode ─────────────────────────────────────────────────────────────────
run_live() {
    if [[ -z "$AUTH_LOG" ]]; then
        warn "No auth log found at /var/log/auth.log or /var/log/secure."
        warn "Run with --test to try sample data instead."
        exit 1
    fi

    info "Monitoring $AUTH_LOG for suspicious activity (Ctrl+C to stop)"
    info "Alerts saved to: $ALERT_LOG\n"

    local last_line=0
    while true; do
        local total_lines; total_lines=$(wc -l < "$AUTH_LOG")
        if (( total_lines > last_line )); then
            local new_lines
            new_lines=$(tail -n $(( total_lines - last_line )) "$AUTH_LOG")
            analyse_lines "$new_lines"
            last_line=$total_lines
        fi
        sleep "$CHECK_INTERVAL"
    done
}

# ── Entry point ───────────────────────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║   Log Monitor & Security Alerter     ║"
echo "  ║   Aldo Pilers                        ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

if [[ "${1:-}" == "--test" ]]; then
    run_test
else
    run_live
fi
