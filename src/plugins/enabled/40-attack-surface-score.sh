#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Attack Surface Score Engine
#  ═════════════════════════════════════════════════════════════════════════════
#  Aggregates all port risks into a single A–F grade with score breakdown,
#  penalty/bonus modifiers, and the top 3 remediation suggestions.
#
#  Formula:
#    BASE     = Σ(port_risk_score)
#    PENALTIES = Docker_exposed(+15) + K8s_exposed(+20) + root_services(+5)
#                + expired_certs(+8) + weak_TLS(+5) + unknown_ports(+3)
#    BONUSES  = firewall_active(-10) + selinux_enforcing(-8) + no_critical(-15)
#    FINAL    = BASE + PENALTIES + BONUSES
#
#  CLI: --score   → show full Attack Surface Score report
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Scoring Config (configurable via ports.conf) ───
declare -g PENALTY_DOCKER_EXPOSED="${PENALTY_DOCKER_EXPOSED:-15}"
declare -g PENALTY_K8S_EXPOSED="${PENALTY_K8S_EXPOSED:-20}"
declare -g PENALTY_ROOT_SERVICES="${PENALTY_ROOT_SERVICES:-5}"
declare -g PENALTY_EXPIRED_CERTS="${PENALTY_EXPIRED_CERTS:-8}"
declare -g PENALTY_WEAK_TLS="${PENALTY_WEAK_TLS:-5}"
declare -g PENALTY_UNKNOWN_PORTS="${PENALTY_UNKNOWN_PORTS:-3}"
declare -g PENALTY_CRITICAL_PORT="${PENALTY_CRITICAL_PORT:-10}"
declare -g BONUS_FIREWALL="${BONUS_FIREWALL:--10}"
declare -g BONUS_SELINUX="${BONUS_SELINUX:--8}"
declare -g BONUS_NO_CRITICAL="${BONUS_NO_CRITICAL:--15}"
declare -g BONUS_NO_HIGH="${BONUS_NO_HIGH:--8}"
declare -g BONUS_APARMOR="${BONUS_APARMOR:--5}"

# ─── CLI Flag (set from port-watcher.sh) ───
declare -g SHOW_SCORE=false

# ─── Plugin Init ───
plugin_init_attack-surface-score() {
  : # No special init needed
}

# ─── Score Calculation ───

# Main calculation: analyzes port data and produces the score report
calculate_attack_surface() {
  local port_data="$1"
  local hostname="${HOSTNAME:-$(hostname 2>/dev/null || echo 'unknown')}"

  # ── Base score: sum of all port risk scores ──
  local base_score=0 critical_count=0 high_count=0 medium_count=0
  local low_count=0 unknown_count=0 total_ports=0
  local root_services=0 docker_exposed=false k8s_exposed=false
  local unknown_ports=0 highest_score=0

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info bind_type score risk
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
    score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
    risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"

    total_ports=$((total_ports + 1))
    base_score="$(awk "BEGIN {printf \"%.1f\", $base_score + $score}" 2>/dev/null || echo "$base_score")"

    # Track highest score per port
    local int_score="${score%.*}"
    [[ -z "$int_score" ]] && int_score=0
    [[ $int_score -gt $highest_score ]] && highest_score=$int_score

    case "$risk" in
      CRITICAL) critical_count=$((critical_count + 1)) ;;
      HIGH)     high_count=$((high_count + 1)) ;;
      MEDIUM)   medium_count=$((medium_count + 1)) ;;
      LOW)      low_count=$((low_count + 1)) ;;
      *)        unknown_count=$((unknown_count + 1))
                unknown_ports=$((unknown_ports + 1)) ;;
    esac

    # Check for root-owned services
    [[ "$user" == "root" || "$user" == "toor" ]] && root_services=$((root_services + 1))

    # Check for Docker exposed
    if { [[ "$port" == "2375" || "$port" == "2376" ]] && [[ "$bind_type" == "ALL" ]]; }; then
      docker_exposed=true
    fi

    # Check for K8s exposed
    if { [[ "$port" == "6443" || "$port" == "10250" || "$port" == "10255" ]] && [[ "$bind_type" == "ALL" ]]; }; then
      k8s_exposed=true
    fi
  done <<< "$port_data"

  # ── Penalties ──
  local penalties=0 penalty_lines=""
  local critical_penalty=0 docker_penalty=0 k8s_penalty=0 root_penalty=0 unknown_penalty=0

  if [[ $critical_count -gt 0 ]]; then
    critical_penalty=$((critical_count * PENALTY_CRITICAL_PORT))
    penalties=$((penalties + critical_penalty))
    penalty_lines+="    • CRITICAL ports found: +${critical_penalty} ($critical_count × ${PENALTY_CRITICAL_PORT})\n"
  fi
  if $docker_exposed; then
    docker_penalty=$PENALTY_DOCKER_EXPOSED
    penalties=$((penalties + docker_penalty))
    penalty_lines+="    • Docker API exposed to 0.0.0.0: +${docker_penalty}\n"
  fi
  if $k8s_exposed; then
    k8s_penalty=$PENALTY_K8S_EXPOSED
    penalties=$((penalties + k8s_penalty))
    penalty_lines+="    • Kubernetes API exposed: +${k8s_penalty}\n"
  fi
  if [[ $root_services -gt 3 ]]; then
    root_penalty=$PENALTY_ROOT_SERVICES
    penalties=$((penalties + root_penalty))
    penalty_lines+="    • $root_services root-owned services (excessive): +${root_penalty}\n"
  fi
  if [[ $unknown_ports -gt 0 ]]; then
    unknown_penalty=$((unknown_ports * PENALTY_UNKNOWN_PORTS))
    penalties=$((penalties + unknown_penalty))
    penalty_lines+="    • $unknown_ports unclassified port(s): +${unknown_penalty}\n"
  fi

  # ── Bonuses (security hardening) ──
  local bonuses=0 bonus_lines=""
  local firewall_bonus=0 selinux_bonus=0 no_critical_bonus=0

  if command -v iptables &>/dev/null && iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|REJECT" 2>/dev/null; then
    firewall_bonus=$BONUS_FIREWALL
    bonuses=$((bonuses + firewall_bonus))
    bonus_lines+="    • Firewall (iptables) active: ${firewall_bonus}\n"
  fi
  if [[ -f /sys/fs/selinux/enforce ]] && [[ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" == "1" ]]; then
    selinux_bonus=$BONUS_SELINUX
    bonuses=$((bonuses + selinux_bonus))
    bonus_lines+="    • SELinux enforcing: ${selinux_bonus}\n"
  fi
  if [[ $critical_count -eq 0 ]]; then
    no_critical_bonus=$BONUS_NO_CRITICAL
    bonuses=$((bonuses + no_critical_bonus))
    bonus_lines+="    • No CRITICAL risk ports: ${no_critical_bonus}\n"
  fi
  if [[ $high_count -eq 0 ]]; then
    bonuses=$((bonuses + BONUS_NO_HIGH))
    bonus_lines+="    • No HIGH risk ports: ${BONUS_NO_HIGH}\n"
  fi

  # ── Final score ──
  local final_score grade
  final_score="$(awk "BEGIN {printf \"%.1f\", $base_score + $penalties + $bonuses}" 2>/dev/null || echo "0")"
  grade="$(grade_score "$final_score")"

  # ── Remediations ──
  local remediations=()
  $docker_exposed && remediations+=("Secure Docker socket (bind to 127.0.0.1 or use TLS)")
  $k8s_exposed && remediations+=("Restrict Kubernetes API to internal network")
  [[ $critical_count -gt 0 ]] && remediations+=("Investigate $critical_count CRITICAL port(s): review if they need to be exposed")
  [[ $unknown_ports -gt 0 ]] && remediations+=("Classify $unknown_ports unknown port(s): identify or restrict access")
  [[ $root_services -gt 5 ]] && remediations+=("Reduce root-owned services: run as non-privileged user where possible")
  [[ $firewall_bonus -eq 0 ]] && remediations+=("Enable firewall: configure iptables or nftables default-deny policy")
  [[ $selinux_bonus -eq 0 && -f /sys/fs/selinux/enforce ]] && remediations+=("Enable SELinux enforcing mode")
  [[ $critical_count -gt 2 ]] && remediations+=("High-priority: patch or isolate the $critical_count critical services")
  [[ ${#remediations[@]} -eq 0 ]] && remediations+=("No critical issues found — maintain current security posture")

  # ── Build report ──
  ASS_SCORE_FINAL="$final_score"
  ASS_GRADE="$grade"
  ASS_BASE="$base_score"
  ASS_PENALTIES="$penalties"
  ASS_BONUSES="$bonuses"
  ASS_TOTAL="$total_ports"
  ASS_CRITICAL="$critical_count"
  ASS_HIGH="$high_count"
  ASS_MEDIUM="$medium_count"
  ASS_LOW="$low_count"
  ASS_UNKNOWN="$unknown_count"
  ASS_REMEDIATIONS=("${remediations[@]}")
  ASS_PENALTY_LINES="$penalty_lines"
  ASS_BONUS_LINES="$bonus_lines"
  ASS_ROOT_SERVICES="$root_services"
  ASS_DOCKER_EXPOSED="$docker_exposed"
  ASS_K8S_EXPOSED="$k8s_exposed"
}

# Convert numeric score to letter grade
grade_score() {
  local score="$1"
  local int_score="${score%.*}"
  [[ -z "$int_score" ]] && int_score=0

  if (( int_score < 20 )); then
    echo "A"
  elif (( int_score < 40 )); then
    echo "B"
  elif (( int_score < 60 )); then
    echo "C"
  elif (( int_score < 80 )); then
    echo "D"
  elif (( int_score < 100 )); then
    echo "E"
  else
    echo "F"
  fi
}

# Get emoji/label for grade
grade_label() {
  local grade="$1"
  case "$grade" in
    A) echo "🔒 Excellent" ;;
    B) echo "🟢 Good" ;;
    C) echo "🟡 Fair" ;;
    D) echo "🟠 Poor" ;;
    E) echo "🔴 Critical" ;;
    F) echo "💀 Severe" ;;
    *) echo "Unknown" ;;
  esac
}

# Get color for grade
grade_color() {
  local grade="$1"
  case "$grade" in
    A) echo "$C_BOLD_GREEN" ;;
    B) echo "$C_GREEN" ;;
    C) echo "$C_BOLD_YELLOW" ;;
    D) echo "$C_YELLOW" ;;
    E) echo "$C_RED" ;;
    F) echo "$C_BOLD_RED" ;;
    *) echo "$C_DIM" ;;
  esac
}

# ─── Display ───

# Show the full Attack Surface Score report
show_score_report() {
  echo ""
  cecho "$C_BOLD_CYAN" "╔═══════════════════════════════════════════════════════════════╗"
  cecho "$C_BOLD_CYAN" "║  📊 ATTACK SURFACE SCORE REPORT                             ║"
  cecho "$C_BOLD_CYAN" "╚═══════════════════════════════════════════════════════════════╝"
  echo ""

  local grade_color="$(grade_color "$ASS_GRADE")"
  local grade_label_str="$(grade_label "$ASS_GRADE")"

  printf "  ${C_BOLD}Grade:${C_RESET}      %s%s${C_RESET}  —  %s\n" "$grade_color" "$ASS_GRADE" "$grade_label_str"
  printf "  ${C_BOLD}Score:${C_RESET}      ${C_BOLD}%s${C_RESET}\n" "$ASS_SCORE_FINAL"
  echo ""

  echo "  $(cecho "$C_BOLD" "Breakdown:")"
  echo ""

  # Base score
  printf "  ${C_DIM}%-30s${C_RESET}    %s\n" "  • Port Risk Base" "${C_BOLD}+${ASS_BASE}${C_RESET}"

  # Penalties
  if [[ $ASS_PENALTIES -gt 0 ]]; then
    echo -e "$ASS_PENALTY_LINES" | while IFS= read -r line; do
      [[ -n "$line" ]] && echo "  $line"
    done
    printf "  ${C_DIM}%-30s${C_RESET}    ${C_RED}+%s${C_RESET}\n" "  ─ Penalties Total" "$ASS_PENALTIES"
  else
    echo "    • No penalties applied"
  fi

  # Bonuses
  if [[ $ASS_BONUSES -lt 0 ]]; then
    echo -e "$ASS_BONUS_LINES" | while IFS= read -r line; do
      [[ -n "$line" ]] && echo "  $line"
    done
    printf "  ${C_DIM}%-30s${C_RESET}    ${C_GREEN}%s${C_RESET}\n" "  ─ Bonuses Total" "$ASS_BONUSES"
  fi

  echo ""
  printf "  ${C_BOLD}%-30s${C_RESET}    ${C_BOLD}%s${C_RESET}\n" "  ═══ FINAL SCORE" "$ASS_SCORE_FINAL"
  echo ""

  # Port distribution
  echo "  $(cecho "$C_BOLD" "Port Distribution:")"
  echo ""
  printf "  ${C_DIM}%-30s${C_RESET}    ${C_BOLD_RED}%-3d${C_RESET}\n" "  CRITICAL" "$ASS_CRITICAL"
  printf "  ${C_DIM}%-30s${C_RESET}    ${C_RED}%-3d${C_RESET}\n" "  HIGH" "$ASS_HIGH"
  printf "  ${C_DIM}%-30s${C_RESET}    ${C_BOLD_YELLOW}%-3d${C_RESET}\n" "  MEDIUM" "$ASS_MEDIUM"
  printf "  ${C_DIM}%-30s${C_RESET}    ${C_GREEN}%-3d${C_RESET}\n" "  LOW" "$ASS_LOW"
  printf "  ${C_DIM}%-30s${C_RESET}    ${C_DIM}%-3d${C_RESET}\n" "  UNKNOWN" "$ASS_UNKNOWN"
  printf "  ${C_DIM}%-30s${C_RESET}    %-3d\n" "  TOTAL PORTS" "$ASS_TOTAL"
  echo ""

  # Top 3 remediations
  echo "  $(cecho "$C_BOLD" "Top Remediations:")"
  echo ""
  local idx=1
  for remediation in "${ASS_REMEDIATIONS[@]}"; do
    [[ $idx -gt 3 ]] && break
    echo "    $idx. $remediation"
    idx=$((idx + 1))
  done
  echo ""

  # Summary
  echo "  $(cecho "$C_DIM" "Summary: $ASS_TOTAL ports monitored | $ASS_CRITICAL critical | Grade $ASS_GRADE")"
  echo ""
}

# ─── Plugin Hooks ───

plugin_analyze_attack-surface-score() {
  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"
  # Calculation is done in batch via calculate_attack_surface()
  :
}

plugin_render_json_attack-surface-score() {
  # Only add global score fields, not per-port
  echo "\"attack_surface_score\": $ASS_SCORE_FINAL, \"attack_surface_grade\": \"$ASS_GRADE\""
}
