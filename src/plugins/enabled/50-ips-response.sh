#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Automated IPS Response Engine
#  ═════════════════════════════════════════════════════════════════════════════
#  Automatically contains CRITICAL-risk services by:
#    1. Adding iptables/nftables DROP rules for unauthorized ports
#    2. Capturing forensic metadata before blocking
#    3. Logging all actions to syslog + SQLite alerts
#    4. Supporting whitelist for known-safe ports/processes
#
#  CLI: --auto-response          → Enable auto-response mode
#       --auto-response-level   → CRITICAL, HIGH, or ALL (default: CRITICAL)
#
#  Config (ports.conf):
#    AUTO_RESPONSE=true
#    AUTO_RESPONSE_LEVEL=CRITICAL
#    WHITELIST_PORTS=22,80,443
#    WHITELIST_PROCESSES=sshd,nginx
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Config (configurable via ports.conf) ───
declare -g AUTO_RESPONSE=false
declare -g AUTO_RESPONSE_LEVEL="${AUTO_RESPONSE_LEVEL:-CRITICAL}"
declare -g WHITELIST_PORTS="${WHITELIST_PORTS:-22,80,443}"
declare -g WHITELIST_PROCESSES="${WHITELIST_PROCESSES:-sshd,nginx,dockerd,containerd}"
declare -g IPS_LOG_DIR="$HOME/.config/port-watcher/ips-logs"
declare -g IPS_ACTIONS_TAKEN=0
declare -g IPS_LAST_ACTION=""

# ─── CLI Flag ───
declare -g SHOW_AUTO_RESPONSE=false
declare -g CLI_AUTO_RESPONSE=false
declare -g CLI_IPS_LEVEL=""

# ─── Plugin Init ───
plugin_init_ips-response() {
  mkdir -p "$IPS_LOG_DIR" 2>/dev/null || true

  # CLI flag overrides config setting
  if $CLI_AUTO_RESPONSE; then
    AUTO_RESPONSE=true
  fi
}

# ─── IPS Actions ───

# Block a port using iptables (both IPv4 and IPv6)
block_port() {
  local port="$1" process="$2" reason="$3"
  local timestamp="$(date +%Y%m%d_%H%M%S)"
  local log_file="${IPS_LOG_DIR}/block-${port}-${timestamp}.log"

  # Check whitelist
  for wp in ${WHITELIST_PORTS//,/ }; do
    [[ "$port" == "$wp" ]] && return 0
  done
  for wp in ${WHITELIST_PROCESSES//,/ }; do
    [[ "$process" == "$wp" ]] && return 0
  done

  # ── Forensic capture before blocking ──
  {
    echo "=== IPS Block Action ==="
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Port: $port"
    echo "Process: $process"
    echo "Reason: $reason"
    echo "Host: ${HOSTNAME:-$(hostname 2>/dev/null || echo 'unknown')}"
    echo ""
    echo "--- lsof output ---"
    lsof -i :"$port" 2>/dev/null || echo "lsof not available"
    echo ""
    echo "--- ps output ---"
    ps aux | grep -E " $process|$port" 2>/dev/null || true
    echo ""
    echo "--- netstat/ss ---"
    ss -tulnp 2>/dev/null | grep ":$port " || true
    echo ""
    echo "--- iptables rules before ---"
    iptables -L INPUT -n 2>/dev/null | head -20 || true
  } > "$log_file"

  # ── Execute block ──
  local blocked=false

  # iptables (IPv4)
  if command -v iptables &>/dev/null; then
    iptables -C INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || {
      iptables -A INPUT -p tcp --dport "$port" -j DROP 2>/dev/null && blocked=true
    }
  fi

  # ip6tables (IPv6)
  if command -v ip6tables &>/dev/null; then
    ip6tables -C INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || {
      ip6tables -A INPUT -p tcp --dport "$port" -j DROP 2>/dev/null
    }
  fi

  # nftables fallback
  if ! command -v iptables &>/dev/null && command -v nft &>/dev/null; then
    nft add rule ip filter INPUT tcp dport "$port" drop 2>/dev/null && blocked=true
  fi

  if $blocked; then
    IPS_ACTIONS_TAKEN=$((IPS_ACTIONS_TAKEN + 1))
    IPS_LAST_ACTION="Blocked port $port ($process)"

    # Log to syslog
    logger -t "port-watcher-ips" "[ACTION] Blocked port $port ($process) — $reason"

    # Record to SQLite if database plugin loaded
    if declare -f record_alert &>/dev/null; then
      record_alert "CRITICAL" "ips_block" "$port" "$process" "IPS blocked $port ($process): $reason" 2>/dev/null || true
    fi

    if $COLOR; then
      echo -e "${C_BOLD_RED}🛡️  IPS blocked port ${port} (${process}) — ${reason}${C_RESET}" >&2
    else
      echo "[IPS] Blocked port $port ($process) — $reason" >&2
    fi
  elif $COLOR; then
    echo -e "${C_YELLOW}⚠️  IPS: Could not block port ${port} — no firewall tool found or permission denied${C_RESET}" >&2
  fi
}

# Check each port and auto-block if needed
run_ips_response() {
  local port_data="$1"

  # Only respond if enabled
  $CLI_AUTO_RESPONSE || return 0
  $AUTO_RESPONSE || return 0

  # Determine minimum risk level for response
  local min_risk="CRITICAL"
  [[ -n "$CLI_IPS_LEVEL" ]] && min_risk="$CLI_IPS_LEVEL"
  [[ -n "$AUTO_RESPONSE_LEVEL" ]] && min_risk="$AUTO_RESPONSE_LEVEL"

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info bind_type score risk
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
    score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
    risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"

    # Check if this risk level triggers a response
    local should_block=false
    case "$min_risk" in
      ALL)       should_block=true ;;
      HIGH)      [[ "$risk" == "CRITICAL" || "$risk" == "HIGH" ]] && should_block=true ;;
      CRITICAL|*) [[ "$risk" == "CRITICAL" ]] && should_block=true ;;
    esac

    $should_block || continue

    # Check whitelist
    local whitelisted=false
    for wp in ${WHITELIST_PORTS//,/ }; do
      [[ "$port" == "$wp" ]] && { whitelisted=true; break; }
    done
    $whitelisted && continue

    local process_lower="$(echo "$process" | tr '[:upper:]' '[:lower:]')"
    for wp in ${WHITELIST_PROCESSES//,/ }; do
      [[ "$process_lower" == "$wp" ]] && { whitelisted=true; break; }
    done
    $whitelisted && continue

    # Block it
    block_port "$port" "$process" "$risk risk — exposed on $bind_type ($bind_addr)"
  done <<< "$port_data"

  if [[ $IPS_ACTIONS_TAKEN -gt 0 && $CLI_AUTO_RESPONSE ]]; then
    echo ""
    echo "  $(cecho "$C_BOLD_RED" "🛡️  IPS Actions Taken: $IPS_ACTIONS_TAKEN")"
    echo "  $(cecho "$C_DIM" "     Last action: $IPS_LAST_ACTION")"
    echo "  $(cecho "$C_DIM" "     Logs: $IPS_LOG_DIR/")"
    echo ""
  fi
}

# ─── Cleanup ───
plugin_cleanup_ips-response() {
  # Report summary of actions taken this session
  if [[ $IPS_ACTIONS_TAKEN -gt 0 ]]; then
    logger -t "port-watcher-ips" "[SUMMARY] $IPS_ACTIONS_TAKEN port(s) blocked this session"
  fi
}
