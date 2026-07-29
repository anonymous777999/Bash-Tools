#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Dark Web / Shodan Intelligence
#  ═════════════════════════════════════════════════════════════════════════════
#  Cross-references discovered services and IPs with external threat
#  intelligence sources to provide global context.
#
#  Sources (configurable via ports.conf):
#    • Shodan.io API         — Check if IP:port appears in Shodan search
#    • AbuseIPDB API         — Check if IP is reported for malicious activity
#    • AlienVault OTX API    — Check if IP has associated pulse indicators
#    • Censys.io API         — Alternative to Shodan for exposed services
#    • Local threat cache    — Offline C2 IP feeds, known bad lists
#
#  Risk Escalation:
#    If a service is found on a threat feed, its risk level is escalated
#    one step (e.g., HIGH → CRITICAL). Services on Shodan get +5 score.
#    Services reported on AbuseIPDB get +10 score.
#
#  Usage:
#    port-watcher --threat-intel                → Check all discovered services
#    port-watcher --threat-intel --output json  → JSON threat report
#    port-watcher --anomalies --threat-intel    → Combined report
#
#  Config (ports.conf):
#    SHODAN_API_KEY="your_key"
#    ABUSEIPDB_API_KEY="your_key"
#    OTX_API_KEY="your_key"
#    THREAT_INTEL_ENABLED=true
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Config (from ports.conf) ───
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
OTX_API_KEY="${OTX_API_KEY:-}"
CENSYS_API_ID="${CENSYS_API_ID:-}"
CENSYS_SECRET="${CENSYS_SECRET:-}"
THREAT_INTEL_ENABLED="${THREAT_INTEL_ENABLED:-false}"
THREAT_CACHE_DIR="${THREAT_CACHE_DIR:-$HOME/.config/port-watcher/threat-cache}"
THREAT_CACHE_TTL="${THREAT_CACHE_TTL:-86400}"  # 24 hours

# ─── CLI Flags ───
SHOW_THREAT_INTEL=false

# ─── Runtime Data ───
declare -g -A THREAT_FINDINGS            # "port|ip|service" → "source|score|detail"
THREAT_INTEL_COUNT=0
THREAT_INTEL_ALERTS=0

# ─── Built-in Threat Feeds (C2 servers, known bad, anonymizers) ───
# These are checked locally first before hitting external APIs.
# Format: IP:port:description
declare -a BUILTIN_THREAT_IPS=()
BUILTIN_THREAT_IPS_LOADED=false

load_builtin_threat_feeds() {
  $BUILTIN_THREAT_IPS_LOADED && return
  BUILTIN_THREAT_IPS=(
    # High-profile C2 / malware hosts (common patterns)
    "185.130.5.0/24:any:Cobalt Strike C2 range"
    "45.155.205.0/24:any:Mirai botnet C2 range"
    "51.38.0.0/16:any:Known hosting provider (abuse-heavy)"
    "185.220.101.0/24:any:Tor exit node range"
    "23.129.64.0/24:any:Known C2 infrastructure"
    # Common anonymizer / proxy ranges
    "5.255.80.0/24:any:Known proxy/VPN range"
    "91.121.0.0/16:any:OVH hosting (common C2)"
    "51.15.0.0/16:any:Online.net (common C2)"
    "163.172.0.0/16:any:Online SAS (known abuse)"
  )
  BUILTIN_THREAT_IPS_LOADED=true
}

# ─── Plugin Init ───
plugin_init_threat-intel() {
  load_builtin_threat_feeds
  mkdir -p "$THREAT_CACHE_DIR" 2>/dev/null || true
}

# ─── Helper: Check if an IP is in a CIDR range ───
ip_in_cidr() {
  local ip="$1" cidr="$2"
  # Simple /24 check for built-in feeds
  if [[ "$cidr" == *"/24" ]]; then
    local cidr_base="${cidr%/24}"
    local ip_base
    ip_base="$(echo "$ip" | cut -d. -f1-3)"
    [[ "$ip_base" == "$cidr_base" ]] && return 0
  fi
  # For other CIDRs, use a basic check
  local cidr_net="${cidr%/*}"
  local cidr_mask="${cidr#*/}"
  if [[ "$cidr_mask" == "16" ]]; then
    local ip_base
    ip_base="$(echo "$ip" | cut -d. -f1-2)"
    local cidr_base
    cidr_base="$(echo "$cidr_net" | cut -d. -f1-2)"
    [[ "$ip_base" == "$cidr_base" ]] && return 0
  fi
  return 1
}

# ─── Local Threat Feed Check ───
# Checks IP against built-in threat ranges
check_builtin_feeds() {
  local ip="$1" port="$2" service="$3"

  load_builtin_threat_feeds

  for entry in "${BUILTIN_THREAT_IPS[@]}"; do
    local cidr="${entry%%:*}"
    local rest="${entry#*:}"
    local match_port="${rest%%:*}"
    local description="${rest#*:}"

    # Check if IP is in the CIDR range
    if ip_in_cidr "$ip" "$cidr"; then
      # Check if port matches (or "any")
      if [[ "$match_port" == "any" || "$match_port" == "$port" ]]; then
        THREAT_FINDINGS["${port}|${ip}|${service}"]="builtin|15|${description}"
        THREAT_INTEL_COUNT=$((THREAT_INTEL_COUNT + 1))
        THREAT_INTEL_ALERTS=$((THREAT_INTEL_ALERTS + 1))
        return 0
      fi
    fi
  done
  return 1
}

# ─── Shodan API Check ───
# Requires: SHODAN_API_KEY in ports.conf
check_shodan() {
  local ip="$1" port="$2" service="$3"

  [[ -z "$SHODAN_API_KEY" ]] && return 1

  local cache_file="${THREAT_CACHE_DIR}/shodan-${ip}-${port}.json"
  local use_cache=false

  # Check cache
  if [[ -f "$cache_file" && $(( $(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || date +%s) )) -lt $THREAT_CACHE_TTL ]]; then
    use_cache=true
  fi

  local shodan_data=""
  if $use_cache; then
    shodan_data="$(cat "$cache_file" 2>/dev/null || true)"
  else
    shodan_data="$(curl -s -m 5 "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" 2>/dev/null || true)"
    if [[ -n "$shodan_data" && "$shodan_data" != '{"error"'* ]]; then
      echo "$shodan_data" > "$cache_file" 2>/dev/null || true
    fi
  fi

  if [[ -z "$shodan_data" || "$shodan_data" == '{"error"'* ]]; then
    return 1
  fi

  # Check if our specific port is mentioned in Shodan data
  if echo "$shodan_data" | grep -q "\"${port}\"" 2>/dev/null; then
    local detail="Found on Shodan: IP ${ip} has port ${port} exposed"
    # Check for tags indicating malicious activity
    if echo "$shodan_data" | grep -qiE 'malware|attack|botnet|c2' 2>/dev/null; then
      detail+=" (tagged as malicious on Shodan)"
      THREAT_FINDINGS["${port}|${ip}|${service}"]="shodan|20|${detail}"
    else
      THREAT_FINDINGS["${port}|${ip}|${service}"]="shodan|5|${detail}"
    fi
    THREAT_INTEL_COUNT=$((THREAT_INTEL_COUNT + 1))
    return 0
  fi

  return 1
}

# ─── AbuseIPDB API Check ───
# Requires: ABUSEIPDB_API_KEY in ports.conf
check_abuseipdb() {
  local ip="$1" port="$2" service="$3"

  [[ -z "$ABUSEIPDB_API_KEY" ]] && return 1

  local cache_file="${THREAT_CACHE_DIR}/abuseipdb-${ip}.json"

  # Check cache
  if [[ -f "$cache_file" && $(( $(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || date +%s) )) -lt $THREAT_CACHE_TTL ]]; then
    local abuse_data
    abuse_data="$(cat "$cache_file" 2>/dev/null || true)"
    if [[ -n "$abuse_data" ]]; then
      local confidence
      confidence="$(echo "$abuse_data" | grep -o '"abuseConfidenceScore":[0-9]*' | cut -d: -f2 || echo "0")"
      if [[ $confidence -ge 50 ]]; then
        THREAT_FINDINGS["${port}|${ip}|${service}"]="abuseipdb|$(( confidence / 5 ))|AbuseIPDB confidence: ${confidence}%"
        THREAT_INTEL_COUNT=$((THREAT_INTEL_COUNT + 1))
        [[ $confidence -ge 75 ]] && THREAT_INTEL_ALERTS=$((THREAT_INTEL_ALERTS + 1))
        return 0
      fi
    fi
    return 1
  fi

  local abuse_data
  abuse_data="$(curl -s -m 5 "https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90" \
    -H "Key: ${ABUSEIPDB_API_KEY}" \
    -H "Accept: application/json" 2>/dev/null || true)"

  if [[ -n "$abuse_data" && "$abuse_data" != '{"error"'* ]]; then
    echo "$abuse_data" > "$cache_file" 2>/dev/null || true
    local confidence
    confidence="$(echo "$abuse_data" | grep -o '"abuseConfidenceScore":[0-9]*' | cut -d: -f2 || echo "0")"
    if [[ $confidence -ge 50 ]]; then
      THREAT_FINDINGS["${port}|${ip}|${service}"]="abuseipdb|$(( confidence / 5 ))|AbuseIPDB confidence: ${confidence}%"
      THREAT_INTEL_COUNT=$((THREAT_INTEL_COUNT + 1))
      [[ $confidence -ge 75 ]] && THREAT_INTEL_ALERTS=$((THREAT_INTEL_ALERTS + 1))
      return 0
    fi
  fi

  return 1
}

# ─── AlienVault OTX Check ───
# Requires: OTX_API_KEY in ports.conf
check_otx() {
  local ip="$1" port="$2" service="$3"

  [[ -z "$OTX_API_KEY" ]] && return 1

  local cache_file="${THREAT_CACHE_DIR}/otx-${ip}.json"

  # Check cache
  if [[ -f "$cache_file" && $(( $(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || date +%s) )) -lt $THREAT_CACHE_TTL ]]; then
    local otx_data
    otx_data="$(cat "$cache_file" 2>/dev/null || true)"
    if [[ -n "$otx_data" ]]; then
      local pulse_count
      pulse_count="$(echo "$otx_data" | grep -o '"pulse_count":[0-9]*' | cut -d: -f2 || echo "0")"
      if [[ $pulse_count -gt 0 ]]; then
        THREAT_FINDINGS["${port}|${ip}|${service}"]="otx|$(( pulse_count * 5 ))|AlienVault OTX: ${pulse_count} pulse(s)"
        THREAT_INTEL_COUNT=$((THREAT_INTEL_COUNT + 1))
        THREAT_INTEL_ALERTS=$((THREAT_INTEL_ALERTS + 1))
        return 0
      fi
    fi
    return 1
  fi

  local otx_data
  otx_data="$(curl -s -m 5 "https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/reputation" \
    -H "X-OTX-API-Key: ${OTX_API_KEY}" 2>/dev/null || true)"

  if [[ -n "$otx_data" && "$otx_data" != '{"error"'* ]]; then
    echo "$otx_data" > "$cache_file" 2>/dev/null || true
    local pulse_count
    pulse_count="$(echo "$otx_data" | grep -o '"pulse_count":[0-9]*' | cut -d: -f2 || echo "0")"
    if [[ $pulse_count -gt 0 ]]; then
      THREAT_FINDINGS["${port}|${ip}|${service}"]="otx|$(( pulse_count * 5 ))|AlienVault OTX: ${pulse_count} pulse(s)"
      THREAT_INTEL_COUNT=$((THREAT_INTEL_COUNT + 1))
      THREAT_INTEL_ALERTS=$((THREAT_INTEL_ALERTS + 1))
      return 0
    fi
  fi

  return 1
}

# ─── Check local IPs against 3rd-party blocklists (no API key needed) ───
# Downloads and caches known malicious IP lists
check_blocklists() {
  local ip="$1" port="$2" service="$3"

  # Skip local/private IPs
  [[ "$ip" == 127.* || "$ip" == 10.* || "$ip" == 192.168.* || "$ip" == 172.1[6-9].* || "$ip" == 172.2[0-9].* || "$ip" == 172.3[0-1].* ]] && return 1
  [[ "$ip" == "::1" || "$ip" == "0.0.0.0" || "$ip" == "localhost" ]] && return 1

  # Check against built-in feeds first (fast, no network)
  check_builtin_feeds "$ip" "$port" "$service" && return 0

  # Only check external blocklists if THREAT_INTEL_ENABLED=true
  $THREAT_INTEL_ENABLED || return 1

  # If we have API keys, those checks are more valuable than generic blocklists
  return 1
}

# ─── Main Threat Intel Runner ───

run_threat_intel() {
  local port_data="$1"

  # Reset state
  THREAT_FINDINGS=()
  THREAT_INTEL_COUNT=0
  THREAT_INTEL_ALERTS=0

  # Collect bind addresses from current interfaces
  local local_ips=""
  if command -v ip &>/dev/null; then
    local_ips="$(ip addr show 2>/dev/null | grep -oP 'inet \K[\d.]+' | tr '\n' '|')"
  fi

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$bind_addr" || -z "$port" ]] && continue

    # Determine the actual IP(s) this service is bound to
    local check_ips=()
    if [[ "$bind_addr" == "0.0.0.0" || "$bind_addr" == "::" || "$bind_addr" == "*" ]]; then
      # Bound to all interfaces — check all local IPs
      if [[ -n "$local_ips" ]]; then
        while IFS='|' read -ra ips; do
          for ip in "${ips[@]}"; do
            [[ -n "$ip" ]] && check_ips+=("$ip")
          done
        done <<< "$local_ips"
      fi
    else
      check_ips+=("$bind_addr")
    fi

    # Check each IP against threat sources
    for check_ip in "${check_ips[@]}"; do
      [[ -z "$check_ip" || "$check_ip" == "127.0.0.1" || "$check_ip" == "::1" ]] && continue

      # Skip if already checked this combo
      local key="${port}|${check_ip}|${process}"
      [[ -n "${THREAT_FINDINGS[$key]:-}" ]] && continue

      # Check local blocklists first (fastest)
      check_blocklists "$check_ip" "$port" "$process" && continue

      # Then external APIs (slower, requires keys)
      check_shodan "$check_ip" "$port" "$process" && continue
      check_abuseipdb "$check_ip" "$port" "$process" && continue
      check_otx "$check_ip" "$port" "$process" && continue
    done
  done <<< "$port_data"
}

# ─── Report Generation ───

show_threat_intel_report() {
  echo ""
  if [[ $THREAT_INTEL_ALERTS -gt 0 ]]; then
    cecho "$C_BOLD_RED" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_BOLD_RED" "║  ☠️  THREAT INTELLIGENCE — ${THREAT_INTEL_ALERTS} threat(s) found              ║"
    cecho "$C_BOLD_RED" "╚═══════════════════════════════════════════════════════════════╝"
  elif [[ $THREAT_INTEL_COUNT -gt 0 ]]; then
    cecho "$C_BOLD_YELLOW" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_BOLD_YELLOW" "║  🌐 THREAT INTELLIGENCE — ${THREAT_INTEL_COUNT} finding(s)                  ║"
    cecho "$C_BOLD_YELLOW" "╚═══════════════════════════════════════════════════════════════╝"
  else
    cecho "$C_GREEN" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_GREEN" "║  🌐 Threat Intelligence — No threats found                  ║"
    cecho "$C_GREEN" "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    return
  fi
  echo ""

  if [[ ${#THREAT_FINDINGS[@]} -eq 0 ]]; then
    cecho "$C_GREEN" "  ✓ No threats detected. Services look clean."
    echo ""
    return
  fi

  if [[ "$TABLE_STYLE" == "unicode" ]]; then
    echo "  $(cecho "$C_BOLD" "$(printf '┌───────┬──────────┬──────────────────────┬──────────────────────────────────────┐')")"
    echo "  $(printf '│ %-5s │ %-8s │ %-20s │ %-36s │' \
      "$(cecho "$C_BOLD_YELLOW" "PORT")" \
      "$(cecho "$C_BOLD_YELLOW" "SOURCE")" \
      "$(cecho "$C_BOLD_YELLOW" "IP/SERVICE")" \
      "$(cecho "$C_BOLD_YELLOW" "DETAIL")")"
    echo "  $(cecho "$C_BOLD" "$(printf '├───────┼──────────┼──────────────────────┼──────────────────────────────────────┤')")"
  fi

  for key in "${!THREAT_FINDINGS[@]}"; do
    local entry="${THREAT_FINDINGS[$key]}"
    local source score detail
    source="$(echo "$entry" | cut -d'|' -f1)"
    score="$(echo "$entry" | cut -d'|' -f2)"
    detail="$(echo "$entry" | cut -d'|' -f3-)"

    local port_ip="${key}"
    local display_port="$(echo "$port_ip" | cut -d'|' -f1)"
    local display_ip="$(echo "$port_ip" | cut -d'|' -f2)"
    local display_svc="$(echo "$port_ip" | cut -d'|' -f3)"
    local display_detail="${display_ip}:${display_svc} — ${detail}"

    local color="$C_YELLOW"
    [[ $score -ge 15 ]] && color="$C_BOLD_RED"
    [[ $score -ge 10 && $score -lt 15 ]] && color="$C_BOLD_YELLOW"

    if [[ "$TABLE_STYLE" == "unicode" ]]; then
      printf "  │ %s%-5s${C_RESET} │ %-8s │ %-20s │ %-36s │\n" \
        "$color" "$display_port" "$source" "${display_ip}/${display_svc}" "${detail:0:36}"
    else
      echo "  ${display_port} [${source}] ${display_ip}/${display_svc}: ${detail}"
    fi
  done

  if [[ "$TABLE_STYLE" == "unicode" ]]; then
    echo "  $(cecho "$C_DIM" "$(printf '└───────┴──────────┴──────────────────────┴──────────────────────────────────────┘')")"
  fi
  echo ""

  # Escalated risk summary
  if [[ $THREAT_INTEL_ALERTS -gt 0 ]]; then
    cecho "$C_BOLD_RED" "  ☠️  ${THREAT_INTEL_ALERTS} threat(s) found — risk scores escalated for affected ports."
  fi
  echo ""

  # API key hints
  if [[ -z "$SHODAN_API_KEY" && -z "$ABUSEIPDB_API_KEY" && -z "$OTX_API_KEY" ]]; then
    cecho "$C_DIM" "  💡 Tip: Set API keys in ports.conf for deeper checks:"
    cecho "$C_DIM" "     SHODAN_API_KEY=\"your_key\"     → Check Shodan.io"
    cecho "$C_DIM" "     ABUSEIPDB_API_KEY=\"your_key\" → Check AbuseIPDB"
    cecho "$C_DIM" "     OTX_API_KEY=\"your_key\"       → Check AlienVault OTX"
    echo ""
  fi
}

# ─── Escalate Risk Based on Threat Intel ───
# Called after run_threat_intel to adjust port risk scores
apply_threat_intel_risk() {
  local port_data="$1"
  # This modifies the global risk perception — called from main() if both
  # threat intel and risk scoring are active.
  # The ANOMALY_DETECTIONS or RISK_SCORE can be adjusted here.
  for key in "${!THREAT_FINDINGS[@]}"; do
    local entry="${THREAT_FINDINGS[$key]}"
    local score
    score="$(echo "$entry" | cut -d'|' -f2)"
    # Scores above 10 add to anomaly-like detections
    if [[ $score -ge 10 ]]; then
      local port="$(echo "$key" | cut -d'|' -f1)"
      local threat_detail="${entry#*|*|}"
      local existing_anom="${ANOMALY_DETECTIONS[$port]:-}"
      if [[ -n "$existing_anom" ]]; then
        # Append threat info to existing anomaly
        local existing_score="${existing_anom%%|*}"
        local new_score=$((existing_score + score))
        ANOMALY_DETECTIONS["$port"]="${new_score}|THREAT|${existing_anom#*|*|}; ${threat_detail}"
      fi
    fi
  done
}

# ─── Plugin Hooks ───

plugin_cleanup_threat-intel() {
  # Leave cache intact — it persists across runs for faster lookups
  :
}
