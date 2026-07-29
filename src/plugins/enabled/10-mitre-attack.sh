#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — MITRE ATT&CK Mapping Plugin
#  ═════════════════════════════════════════════════════════════════════════════
#  Maps discovered ports/processes to MITRE ATT&CK techniques.
#  Auto-loaded by plugin system when placed in:
#    ~/.config/port-watcher/plugins/enabled/
#
#  MITRE ATT&CK is the industry-standard framework for describing
#  adversary behaviours. This plugin adds a column to every output
#  format showing the relevant technique(s).
# ═══════════════════════════════════════════════════════════════════════════════

# ─── MITRE ATT&CK Mapping Table ───
# Format: technique_id:technique_name:tactic
# Key format: "port:process" or "port:process:bind" or special conditions

declare -A MITRE_ATTACK_MAP=(
  # === Discovery (TA0007) ===
  ["22:ssh"]="T1046:Network Service Discovery:Discovery"
  ["22:sshd"]="T1046:Network Service Discovery:Discovery"
  ["80:http"]="T1046:Network Service Discovery:Discovery"
  ["80:nginx"]="T1046:Network Service Discovery:Discovery"
  ["80:apache"]="T1046:Network Service Discovery:Discovery"
  ["443:http"]="T1046:Network Service Discovery:Discovery"
  ["443:nginx"]="T1046:Network Service Discovery:Discovery"
  ["443:apache"]="T1046:Network Service Discovery:Discovery"
  ["8080:http"]="T1046:Network Service Discovery:Discovery"
  ["8443:http"]="T1046:Network Service Discovery:Discovery"

  # === Persistence (TA0003) ===
  ["22:2222"]="T1098:Account Manipulation:Persistence"
  ["22:sshd:*"]="T1543.002:Systemd Service:Persistence"

  # === Privilege Escalation (TA0004) ===
  ["root:0.0.0.0:*"]="T1548:Abuse Elevation Control Mechanism:PrivilegeEscalation"
  ["root:ALL:CRITICAL"]="T1548:Abuse Elevation Control Mechanism:PrivilegeEscalation"

  # === Credential Access (TA0006) ===
  ["3306:mysql"]="T1552.001:Credentials in Files:CredentialAccess"
  ["3306:mariadb"]="T1552.001:Credentials in Files:CredentialAccess"
  ["5432:postgres"]="T1552.001:Credentials in Files:CredentialAccess"
  ["27017:mongod"]="T1552.001:Credentials in Files:CredentialAccess"
  ["27017:mongodb"]="T1552.001:Credentials in Files:CredentialAccess"
  ["6379:redis"]="T1552.001:Credentials in Files:CredentialAccess"
  ["11211:memcached"]="T1552.001:Credentials in Files:CredentialAccess"

  # === Lateral Movement (TA0008) ===
  ["6379:redis:0.0.0.0"]="T1021.006:Remote Services (Redis — write SSH keys):LateralMovement"
  ["6379:redis-server:0.0.0.0"]="T1021.006:Remote Services (Redis — write SSH keys):LateralMovement"
  ["2375:docker"]="T1611:Escape to Host (Docker API without auth):LateralMovement"
  ["2376:docker"]="T1611:Escape to Host (Docker API with TLS):LateralMovement"
  ["22:ssh"]="T1021.004:Remote SSH Session:LateralMovement"
  ["22:sshd"]="T1021.004:Remote SSH Session:LateralMovement"
  ["445:smb"]="T1021.002:Remote SMB Share Admin:LateralMovement"
  ["135:rpc"]="T1021.003:Remote WMI:LateralMovement"
  ["5985:winrm"]="T1021.006:Windows Remote Management:LateralMovement"
  ["5986:winrm"]="T1021.006:Windows Remote Management:LateralMovement"
  ["3389:rdp"]="T1021.001:Remote Desktop Protocol:LateralMovement"

  # === Defense Evasion (TA0005) ===
  ["*:highport:UNKNOWN"]="T1562.001:Impair Defenses (service on non-standard port):DefenseEvasion"

  # === Collection (TA0009) ===
  ["9200:elasticsearch"]="T1119:Automated Collection:Collection"
  ["9300:elasticsearch"]="T1119:Automated Collection:Collection"

  # === Exfiltration (TA0010) ===
  ["21:ftp"]="T1048:Exfiltration Over Alternative Protocol:Exfiltration"
  ["20:ftp"]="T1048:Exfiltration Over Alternative Protocol:Exfiltration"

  # === Command and Control (TA0011) ===
  ["4444:unknown"]="T1071.001:Application Layer Protocol:CommandAndControl"
  ["6666:unknown"]="T1572:Protocol Tunneling:CommandAndControl"
  ["6667:unknown"]="T1572:Protocol Tunneling:CommandAndControl"
  ["6668:unknown"]="T1572:Protocol Tunneling:CommandAndControl"
  ["6669:unknown"]="T1572:Protocol Tunneling:CommandAndControl"

  # === Container & Resource Escalation ===
  ["10250:kubelet"]="T1611:Escape to Host (Kubelet API):EscapeToHost"
  ["10255:kubelet"]="T1611:Escape to Host (Kubelet read-only):EscapeToHost"
  ["6443:kube"]="T1611:Escape to Host (K8s API):EscapeToHost"
  ["6443:kube-apiserver"]="T1611:Escape to Host (K8s API):EscapeToHost"
  ["8200:vault"]="T1552.001:Credentials in Files (Vault API):CredentialAccess"
  ["8500:consul"]="T1552.001:Credentials in Files (Consul API):CredentialAccess"
)

# ─── Plugin Name ───
# Auto-extracted from filename: "10-mitre-attack.sh" → "mitre-attack"

# ─── Hooks ───

plugin_init_mitre-attack() {
  # Pre-compute lookup patterns for faster matching
  : # No init needed
}

# Return MITRE info for a port/process combination
mitre_lookup() {
  local process="$1" port="$2" bind="$3" risk="$4"

  # Normalize process name (lowercase, strip path)
  process="$(echo "$process" | tr '[:upper:]' '[:lower:]')"
  process="${process##*/}"

  local key="" result=""

  # Try exact match: port:process:bind
  key="${port}:${process}:${bind}"
  result="${MITRE_ATTACK_MAP[$key]:-}"
  [[ -n "$result" ]] && echo "$result" && return

  # Match: port:process
  key="${port}:${process}"
  result="${MITRE_ATTACK_MAP[$key]:-}"
  [[ -n "$result" ]] && echo "$result" && return

  # Match: port:process:*
  key="${port}:${process}:*"
  result="${MITRE_ATTACK_MAP[$key]:-}"
  [[ -n "$result" ]] && echo "$result" && return

  # Match: root:bind:risk
  if [[ "$process" == "root" || "$process" == "toor" ]]; then
    key="root:${bind}:${risk}"
    result="${MITRE_ATTACK_MAP[$key]:-}"
    [[ -n "$result" ]] && echo "$result" && return
  fi

  # Match unknown high port
  if [[ "$risk" == "UNKNOWN" && "$port" -gt 1024 ]]; then
    result="${MITRE_ATTACK_MAP['*:highport:UNKNOWN']:-}"
    [[ -n "$result" ]] && echo "$result" && return
  fi

  echo ""
}

# ─── Render Hooks ───

plugin_render_table_mitre-attack() {
  local arg="$1"
  # Special case: HEADER request returns column header
  if [[ "$arg" == "HEADER" ]]; then
    echo "ATT&CK"
    return
  fi

  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"
  local bind_type risk

  # Determine risk and bind type (may not be available at render time)
  # We pass them as extra params from the main script
  bind_type="${7:-}"
  risk="${8:-}"

  # Fallback: calculate if not provided
  [[ -z "$bind_type" ]] && bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
  [[ -z "$risk" ]] && {
    local risk_info
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    risk="$(echo "$risk_info" | cut -d'|' -f1)"
  }

  local mitre_result
  mitre_result="$(mitre_lookup "$process" "$port" "$bind_type" "$risk")"

  if [[ -n "$mitre_result" ]]; then
    local technique_id technique_name tactic
    technique_id="$(echo "$mitre_result" | cut -d: -f1)"
    technique_name="$(echo "$mitre_result" | cut -d: -f2)"
    # Return ATT&CK ID + short name for table display
    echo "${technique_id}|${C_YELLOW}${technique_id}${C_RESET}"
  else
    echo "|${C_DIM}—${C_RESET}"
  fi
}

plugin_render_json_mitre-attack() {
  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"
  local bind_type="${7:-}" risk="${8:-}"

  [[ -z "$bind_type" ]] && bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
  [[ -z "$risk" ]] && {
    local risk_info
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    risk="$(echo "$risk_info" | cut -d'|' -f1)"
  }

  local mitre_result
  mitre_result="$(mitre_lookup "$process" "$port" "$bind_type" "$risk")"

  if [[ -n "$mitre_result" ]]; then
    local technique_id technique_name tactic
    technique_id="$(echo "$mitre_result" | cut -d: -f1)"
    technique_name="$(echo "$mitre_result" | cut -d: -f2)"
    tactic="$(echo "$mitre_result" | cut -d: -f3)"
    echo "\"mitre_attack_id\": \"$technique_id\", \"mitre_technique\": \"$technique_name\", \"mitre_tactic\": \"$tactic\""
  else
    echo "\"mitre_attack_id\": null, \"mitre_technique\": null, \"mitre_tactic\": null"
  fi
}
