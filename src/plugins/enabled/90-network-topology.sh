#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Network Topology Mapper
#  ═════════════════════════════════════════════════════════════════════════════
#  Discovers live hosts on the local network, maps service dependencies,
#  and generates an ASCII topology graph showing how services connect.
#
#  Detection methods (auto-detected, in priority order):
#    1. arp-scan (sudo) — fastest, most complete
#    2. ip neigh (kernel ARP cache) — no sudo needed, cached entries only
#    3. avahi-browse (mDNS/Bonjour) — zero-config services on LAN
#    4. nmap ping scan (if installed) — active discovery
#
#  Features:
#    • Live host discovery across subnets
#    • mDNS/Bonjour service discovery (printers, media, smart devices)
#    • Service dependency mapping (which hosts talk to which services)
#    • ASCII topology graph with risk-colored nodes
#    • Dashboard integration via /api/topology JSON endpoint
#    • Configurable subnet via ports.conf (TOPOLOGY_SUBNET)
#
#  Usage:
#    port-watcher --topology              → Show full topology graph
#    port-watcher --topology --output json → JSON topology data
#    port-watcher --dashboard --topology  → Include topology in dashboard
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Config ───
declare -g TOPOLOGY_SUBNET="${TOPOLOGY_SUBNET:-}"           # Auto-detect if empty
declare -g TOPOLOGY_SCAN_TIMEOUT="${TOPOLOGY_SCAN_TIMEOUT:-5}"  # Seconds per scan
declare -g TOPOLOGY_MAX_HOSTS="${TOPOLOGY_MAX_HOSTS:-50}"       # Max hosts to display

# ─── CLI Flag ───
declare -g SHOW_TOPOLOGY=false

# ─── Runtime Data ───
declare -g -A TOPOLOGY_HOSTS        # ip → "hostname|mac|vendor|reachable"
declare -g -A TOPOLOGY_SERVICES     # ip → "service1,service2,..."
declare -g TOPOLOGY_DISCOVERY_METHOD=""


# ─── Plugin Init ───
plugin_init_network-topology() {
  : # Ready when called
}

# ─── ARP Scan (primary method) ───
# Uses arp-scan if available (sudo required), falls back to ip neigh
scan_arp() {
  local subnet="$1"
  local results=()

  if command -v arp-scan &>/dev/null; then
    TOPOLOGY_DISCOVERY_METHOD="arp-scan"
    while IFS=$'\t' read -r ip mac vendor; do
      [[ -z "$ip" || "$ip" == *"Starting"* || "$ip" == *"Interface"* || "$ip" == *"packets"* ]] && continue
      [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
      local hostname=""
      hostname="$(get_hostname "$ip")"
      results+=("$ip|${hostname:-unknown}|${mac:-unknown}|${vendor:-unknown}|true")
    done < <(sudo arp-scan --localnet --timeout="$TOPOLOGY_SCAN_TIMEOUT" 2>/dev/null || true)
  fi

  # Fallback: kernel ARP cache via ip neigh
  if [[ ${#results[@]} -eq 0 ]] && command -v ip &>/dev/null; then
    TOPOLOGY_DISCOVERY_METHOD="ip-neigh"
    while IFS=' ' read -r ip dev mac rest; do
      [[ -z "$ip" || "$ip" == "fe80"* ]] && continue
      ip="${ip%%/*}"
      local state="${rest##* }"
      [[ "$state" != "REACHABLE" && "$state" != "STALE" && "$state" != "DELAY" ]] && continue
      local hostname vendor=""
      hostname="$(get_hostname "$ip")"
      # Try to get vendor from OUI
      vendor="$(get_vendor_from_mac "$mac")"
      results+=("$ip|${hostname:-unknown}|${mac:-unknown}|${vendor:-unknown}|true")
    done < <(ip neigh show 2>/dev/null || true)
  fi

  # Last resort: basic ping sweep on /24
  if [[ ${#results[@]} -eq 0 ]] && command -v ping &>/dev/null; then
    TOPOLOGY_DISCOVERY_METHOD="ping-sweep"
    local base
    base="$(echo "$subnet" | cut -d. -f1-3)"
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
             21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 \
             41 42 43 44 45 46 47 48 49 50; do
      local ip="${base}.${i}"
      ping -c 1 -W 1 "$ip" &>/dev/null && {
        local hostname vendor=""
        hostname="$(get_hostname "$ip")"
        results+=("$ip|${hostname:-unknown}||${vendor}|true")
      } || true
    done
  fi

  printf '%s\n' "${results[@]}"
}

# ─── mDNS / Bonjour Discovery ───
# Discovers zero-config services on the LAN (printers, media, smart devices)
scan_mdns() {
  local results=()

  if command -v avahi-browse &>/dev/null; then
    TOPOLOGY_DISCOVERY_METHOD="${TOPOLOGY_DISCOVERY_METHOD:-avahi-browse}"
    # List all service types, resolve each one
    local services
    services="$(avahi-browse -a -t -p 2>/dev/null | grep '^=' || true)"
    while IFS=';' read -r _ _ iface protocol service_type domain host ip port _; do
      [[ -z "$ip" || -z "$port" ]] && continue
      ip="${ip%[*}"
      ip="${ip#[}"
      local service_name="${service_type%%.*}"
      service_name="${service_name#"$protocol"}"
      results+=("$ip|${host:-unknown}|${port}|${service_name:-unknown}")
    done <<< "$services"
  fi

  # Fallback: dns-sd on macOS
  if [[ ${#results[@]} -eq 0 ]] && command -v dns-sd &>/dev/null; then
    TOPOLOGY_DISCOVERY_METHOD="${TOPOLOGY_DISCOVERY_METHOD:-dns-sd}"
    : # dns-sd requires long-running browse, less practical from CLI
  fi

  printf '%s\n' "${results[@]}"
}

# ─── Helper: Get hostname from IP ───
get_hostname() {
  local ip="$1"
  local name=""
  name="$(host "$ip" 2>/dev/null | head -1 | awk '{print $NF}' | sed 's/\.$//' || true)"
  [[ "$name" == *"NXDOMAIN"* || "$name" == "$ip" || -z "$name" ]] && name=""
  echo "$name"
}

# ─── Helper: Get vendor from MAC OUI ───
get_vendor_from_mac() {
  local mac="$1"
  [[ -z "$mac" || "$mac" == "unknown" || "$mac" == "(incomplete)" ]] && echo "" && return
  local oui="${mac//:/}"
  oui="${oui:0:6}"
  # Built-in common OUI prefixes
  case "${oui^^}" in
    000C29) echo "VMware" ;;
    005056|000569) echo "VMware" ;;
    080027) echo "VirtualBox" ;;
    001C42|002590|001EC2) echo "Parallels/Docker" ;;
    0242AC) echo "Docker" ;;
    00155D) echo "Hyper-V" ;;
    0050B6|00904F|0016E3) echo "Xen" ;;
    ACA12B) echo "QEMU" ;;
    00037F) echo "Intel" ;;
    A8D12B) echo "AMD" ;;
    002590) echo "Raspberry Pi" ;;
    B827EB|DCA632) echo "Raspberry Pi" ;;
    E8ABFA) echo "Apple" ;;
    001B63|0016CB) echo "Cisco" ;;
    *) echo "" ;;
  esac
}

# ─── Auto-detect local subnet ───
detect_local_subnet() {
  if [[ -n "$TOPOLOGY_SUBNET" ]]; then
    echo "$TOPOLOGY_SUBNET"
    return
  fi

  local ip=""
  if command -v ip &>/dev/null; then
    ip="$(ip route get 1 2>/dev/null | head -1 | awk '{print $7}' || true)"
  fi
  if [[ -z "$ip" ]] && command -v ifconfig &>/dev/null; then
    ip="$(ifconfig 2>/dev/null | grep -E 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' || true)"
  fi
  if [[ -z "$ip" ]] && command -v hostname &>/dev/null; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi

  if [[ -n "$ip" ]]; then
    echo "$ip" | awk -F. '{print $1"."$2"."$3".0/24"}'
  else
    echo "192.168.1.0/24"
  fi
}

# ─── Build service dependency mapping ───
# Maps which local services (from port scan) are exposed to which hosts
build_service_dependencies() {
  local port_data="$1"
  local dependencies=""

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info score risk bind_type
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
    score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
    risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"

    # Only show non-LOCAL services in topology (public/exposed services)
    if [[ "$bind_type" != "ALL" && "$bind_type" != "LAN" ]]; then
      continue
    fi

    dependencies+="LOCAL|${process:-unknown}|${port}|${bind_addr}|${bind_type}|${risk}"$'\n'
  done <<< "$port_data"

  echo "$dependencies" | head -c -1
}

# ─── Generate ASCII Topology Graph ───
generate_topology_graph() {
  local hosts="$1" services="$2" dependencies="$3"
  local host_count=0 service_count=0
  local graph=""

  graph+="$(cecho "$C_BOLD_CYAN" "╔═══════════════════════════════════════════════════════════════╗")"$'\n'
  graph+="$(cecho "$C_BOLD_CYAN" "║  🌐 NETWORK TOPOLOGY MAP                                    ║")"$'\n'
  graph+="$(cecho "$C_BOLD_CYAN" "╚═══════════════════════════════════════════════════════════════╝")"$'\n'
  graph+=""$'\n'

  # ── Discovery method ──
  graph+="  $(cecho "$C_DIM" "Discovery: ${TOPOLOGY_DISCOVERY_METHOD:-none}")"$'\n'
  graph+=""$'\n'

  # ── Local Host ──
  graph+="  $(cecho "$C_BOLD" "🖥️  THIS HOST")"$'\n'
  graph+="  ┌─────────────────────────────────────────────────────┐"$'\n'
  graph+="  │ $(cecho "$C_CYAN" "$(hostname 2>/dev/null || echo 'localhost')")"$'\n'

  # List local services
  if [[ -n "$dependencies" ]]; then
    while IFS='|' read -r host process port bind bind_type risk; do
      [[ -z "$port" ]] && continue
      local color="$(risk_color "$risk" 2>/dev/null || echo "$C_DIM")"
      graph+="  │   $(cecho "$color" "◉ ${process:-?}:${port}")$(cecho "$C_DIM" " (${bind}:${bind_type})")"$'\n'
      service_count=$((service_count + 1))
    done <<< "$dependencies"
  else
    graph+="  │   $(cecho "$C_DIM" "No exposed services (all bound to localhost)")"$'\n'
  fi
  graph+="  └─────────────────────────────────────────────────────┘"$'\n'
  graph+=""$'\n'

  # ── Live Hosts ──
  graph+="  $(cecho "$C_BOLD" "📡 LIVE HOSTS (${host_count}))")"$'\n'
  if [[ -n "$hosts" ]]; then
    while IFS='|' read -r ip hostname mac vendor reachable; do
      [[ -z "$ip" ]] && continue
      host_count=$((host_count + 1))
      local mac_display=""
      [[ -n "$mac" && "$mac" != "unknown" ]] && mac_display=" ${mac}"
      local vendor_display=""
      [[ -n "$vendor" && "$vendor" != "" ]] && vendor_display=" ($vendor)"

      graph+="  ├─ $(cecho "$C_GREEN" "${ip}")"$'\n'
      graph+="  │  ├─ Hostname: ${hostname:-<no rDNS>}"$'\n'
      graph+="  │  └─ MAC: ${mac:-<unknown>}${vendor_display}"$'\n'

      # Show mDNS services if available
      local mdns_services
      mdns_services="$(echo "$services" | grep "^${ip}|" || true)"
      if [[ -n "$mdns_services" ]]; then
        while IFS='|' read -r srv_ip srv_host srv_port srv_type; do
          graph+="  │     • $(cecho "$C_YELLOW" "${srv_type}") on port ${srv_port} (${srv_host})"$'\n'
        done <<< "$mdns_services"
      fi

      if [[ $host_count -ge $TOPOLOGY_MAX_HOSTS ]]; then
        graph+="  │"$'\n'
        graph+="  └─ $(cecho "$C_DIM" "... and more (capped at ${TOPOLOGY_MAX_HOSTS} hosts)")"$'\n'
        break
      fi
    done <<< "$hosts"
  else
    graph+="  $(cecho "$C_DIM" "  No live hosts discovered. Try running with sudo for arp-scan.")"$'\n'
  fi

  # ── Connection lines ──
  if [[ $service_count -gt 0 && $host_count -gt 0 ]]; then
    graph+=""$'\n'
    graph+="  $(cecho "$C_BOLD" "🔗 SERVICE DEPENDENCIES")"$'\n'
    graph+=""$'\n'
    while IFS='|' read -r process port bind bind_type risk; do
      [[ -z "$port" ]] && continue
      local color="$(risk_color "$risk" 2>/dev/null || echo "$C_DIM")"
      # Show which hosts this service is exposed to (for ALL = everywhere, LAN = local subnet)
      local exposed_to="all hosts"
      [[ "$bind_type" == "LAN" ]] && exposed_to="local subnet"
      graph+="  ${color}◉${C_RESET} ${process}:${port}  ──→  ${exposed_to}"$'\n'
    done <<< "$dependencies"
  fi

  echo "$graph"
}

# ─── Run Topology Scan ───
run_topology_scan() {
  local port_data="$1"
  local subnet
  subnet="$(detect_local_subnet)"

  # ARP scan for live hosts
  local hosts
  hosts="$(scan_arp "$subnet")"

  # mDNS discovery
  local mdns_services
  mdns_services="$(scan_mdns)"

  # Build service dependencies from port scan data
  local dependencies
  dependencies="$(build_service_dependencies "$port_data")"

  # Store in global arrays for JSON API access
  TOPOLOGY_HOSTS=()
  TOPOLOGY_SERVICES=()

  if [[ -n "$hosts" ]]; then
    while IFS='|' read -r ip hostname mac vendor reachable; do
      [[ -z "$ip" ]] && continue
      TOPOLOGY_HOSTS["$ip"]="${hostname}|${mac}|${vendor}"
    done <<< "$hosts"
  fi

  if [[ -n "$mdns_services" ]]; then
    while IFS='|' read -r ip host port service; do
      [[ -z "$ip" || -z "$service" ]] && continue
      local existing="${TOPOLOGY_SERVICES[$ip]:-}"
      if [[ -n "$existing" ]]; then
        TOPOLOGY_SERVICES["$ip"]="${existing},${service}:${port}"
      else
        TOPOLOGY_SERVICES["$ip"]="${service}:${port}"
      fi
    done <<< "$mdns_services"
  fi

  # Output
  generate_topology_graph "$hosts" "$mdns_services" "$dependencies"
}

# ─── JSON Topology Output ───
render_topology_json() {
  local port_data="$1"
  local subnet
  subnet="$(detect_local_subnet)"
  local first=true

  # Run scan fresh
  local hosts mdns_services
  hosts="$(scan_arp "$subnet")"
  mdns_services="$(scan_mdns)"
  local dependencies
  dependencies="$(build_service_dependencies "$port_data")"

  # Populate global TOPOLOGY_SERVICES array for JSON output
  TOPOLOGY_SERVICES=()
  if [[ -n "$mdns_services" ]]; then
    while IFS='|' read -r ip host port service; do
      [[ -z "$ip" || -z "$service" ]] && continue
      local existing="${TOPOLOGY_SERVICES[$ip]:-}"
      if [[ -n "$existing" ]]; then
        TOPOLOGY_SERVICES["$ip"]="${existing},${service}:${port}"
      else
        TOPOLOGY_SERVICES["$ip"]="${service}:${port}"
      fi
    done <<< "$mdns_services"
  fi

  echo "{"
  echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
  echo "  \"discovery_method\": \"${TOPOLOGY_DISCOVERY_METHOD:-none}\","
  echo "  \"subnet\": \"$subnet\","
  echo "  \"hostname\": \"$(hostname 2>/dev/null || echo 'localhost')\","

  echo "  \"local_services\": ["
  first=true
  if [[ -n "$dependencies" ]]; then
    while IFS='|' read -r host process port bind bind_type risk; do
      [[ -z "$port" ]] && continue
      $first || echo ","
      first=false
      printf '    {"port":%s,"process":"%s","bind":"%s","bind_type":"%s","risk":"%s"}' \
        "$port" "${process:-unknown}" "$bind" "$bind_type" "$risk"
    done <<< "$dependencies"
  fi
  echo ""
  echo "  ],"

  echo "  \"hosts\": ["
  first=true
  if [[ -n "$hosts" ]]; then
    while IFS='|' read -r ip hostname mac vendor reachable; do
      [[ -z "$ip" ]] && continue
      $first || echo ","
      first=false
      printf '    {"ip":"%s","hostname":"%s","mac":"%s","vendor":"%s"}' \
        "$ip" "${hostname:-}" "${mac:-}" "${vendor:-}"
      # Include mDNS services for this host
      local srv="${TOPOLOGY_SERVICES[$ip]:-}"
      if [[ -n "$srv" ]]; then
        printf ',"services":"%s"' "$srv"
      fi
    done <<< "$hosts"
  fi
  echo ""
  echo "  ]"
  echo "}"
}

# ─── Topology Graph → Dashboard integration ───
# Writes topology JSON to temp file for dashboard /api/topology endpoint
render_dashboard_topology() {
  local port_data="$1"
  run_topology_scan "$port_data" > /dev/null 2>&1 || true
  render_topology_json "$port_data" > /tmp/port-watcher-topology.json 2>/dev/null || true
}

# ─── Plugin Cleanup ───
plugin_cleanup_network-topology() {
  rm -f /tmp/port-watcher-topology.json 2>/dev/null || true
}
