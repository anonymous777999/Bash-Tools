#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — AI Anomaly Detection Engine
#  ═════════════════════════════════════════════════════════════════════════════
#  Learns "normal" port behavior over time and detects anomalies using a
#  weighted scoring system. Every change is scored:
#
#    Process changed:   +35  (binary swap = potential backdoor)
#    User changed:      +25  (ownership change = privilege tampering)
#    New port appeared: +30  (new service = unknown attack surface)
#    Port disappeared:  +15  (service killed = possible cleanup)
#    Bind changed:      +20  (exposure changed = network reconfig)
#    Risk jumped:       +10  (score increased = security degredation)
#
#  Thresholds:
#    Score > 50 → 🔴 ANOMALY ALERT
#    Score > 30 → 🟡 WARNING
#    Otherwise  → ℹ️ INFO
#
#  Profile storage (auto-detected):
#    1. SQLite (via database-sqlite plugin) — preferred
#    2. Flat JSON file (~/.config/port-watcher/anomaly-profile.json) — fallback
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Anomaly Scoring Weights (configurable via ports.conf) ───
PROCESS_CHANGED_WEIGHT="${PROCESS_CHANGED_WEIGHT:-35}"
USER_CHANGED_WEIGHT="${USER_CHANGED_WEIGHT:-25}"
NEW_PORT_WEIGHT="${NEW_PORT_WEIGHT:-30}"
PORT_GONE_WEIGHT="${PORT_GONE_WEIGHT:-15}"
BIND_CHANGED_WEIGHT="${BIND_CHANGED_WEIGHT:-20}"
RISK_JUMP_WEIGHT="${RISK_JUMP_WEIGHT:-10}"
PROCESS_COUNT_CHANGED_WEIGHT="${PROCESS_COUNT_CHANGED_WEIGHT:-5}"

# Thresholds
ANOMALY_ALERT_THRESHOLD="${ANOMALY_ALERT_THRESHOLD:-50}"
ANOMALY_WARN_THRESHOLD="${ANOMALY_WARN_THRESHOLD:-30}"

# Profile paths
ANOMALY_PROFILE_DIR="$HOME/.config/port-watcher"
ANOMALY_PROFILE_FILE="${ANOMALY_PROFILE_DIR}/anomaly-profile.json"

# Runtime state
declare -g -A ANOMALY_CURRENT_PROFILE      # key=port:process → "process|user|bind|risk|count"
declare -g -A ANOMALY_DETECTIONS           # key=port → "score|type|detail"
declare -g ANOMALY_TOTAL_SCORE=0
declare -g ANOMALY_COUNT=0
declare -g ANOMALY_USING_SQLITE=false
declare -g ANOMALY_PROFILE_LOADED=false

# ─── Plugin Init ───

plugin_init_anomaly-detection() {
  # Check if SQLite is available (from database plugin)
  if command -v sqlite3 &>/dev/null; then
    ANOMALY_USING_SQLITE=true
    mkdir -p "$ANOMALY_PROFILE_DIR" 2>/dev/null || true
    init_anomaly_schema
  fi
  ANOMALY_PROFILE_LOADED=true
}

# ─── SQLite Schema ───

init_anomaly_schema() {
  local db_path="${DB_PATH:-$ANOMALY_PROFILE_DIR/history.db}"
  sqlite3 "$db_path" 2>/dev/null <<SQL
CREATE TABLE IF NOT EXISTS anomaly_profiles (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  port        INTEGER NOT NULL,
  process     TEXT NOT NULL DEFAULT '',
  user        TEXT NOT NULL DEFAULT '',
  bind_addr   TEXT NOT NULL DEFAULT '',
  risk        TEXT NOT NULL DEFAULT 'UNKNOWN',
  score       REAL DEFAULT 0.0,
  first_seen  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  last_seen   TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  times_seen  INTEGER DEFAULT 1,
  UNIQUE(port, process)
);
CREATE INDEX IF NOT EXISTS idx_anomaly_port ON anomaly_profiles(port);
SQL
}

# ─── Profile Management ───

# Load the anomaly profile from storage
load_anomaly_profile() {
  ANOMALY_CURRENT_PROFILE=()
  local db_path="${DB_PATH:-$ANOMALY_PROFILE_DIR/history.db}"

  if [[ "${ANOMALY_USING_SQLITE:-false}" == "true" ]] && [[ -f "$db_path" ]]; then
    # Load from SQLite
    while IFS='|' read -r port process user bind_addr risk score count; do
      [[ -z "$port" ]] && continue
      local key="${port}|${process}"
      ANOMALY_CURRENT_PROFILE["$key"]="${process}|${user}|${bind_addr}|${risk}|${score}|${count}"
    done < <(sqlite3 "$db_path" "SELECT port, process, user, bind_addr, risk, score, times_seen FROM anomaly_profiles;" 2>/dev/null || true)
  elif [[ -f "${ANOMALY_PROFILE_FILE:-}" ]]; then
    # Load from flat JSON file (fallback)
    while IFS= read -r line; do
      local port process user bind_addr risk score count
      port="$(echo "$line" | cut -d'|' -f1)"
      process="$(echo "$line" | cut -d'|' -f2)"
      user="$(echo "$line" | cut -d'|' -f3)"
      bind_addr="$(echo "$line" | cut -d'|' -f4)"
      risk="$(echo "$line" | cut -d'|' -f5)"
      score="$(echo "$line" | cut -d'|' -f6)"
      count="$(echo "$line" | cut -d'|' -f7)"
      [[ -z "$port" ]] && continue
      local key="${port}|${process}"
      ANOMALY_CURRENT_PROFILE["$key"]="${process}|${user}|${bind_addr}|${risk}|${score}|${count}"
    done < <(grep -E '^\[' "${ANOMALY_PROFILE_FILE:-}" 2>/dev/null && echo "" || cat "${ANOMALY_PROFILE_FILE:-}" 2>/dev/null | tr ',' '\n' | grep -E '"[0-9]+\|' | sed 's/"//g' || true)
  fi
}

# Save a port to the anomaly profile
save_to_anomaly_profile() {
  local port="$1" process="$2" user="$3" bind_addr="$4" risk="$5" score="$6"
  local db_path="${DB_PATH:-$ANOMALY_PROFILE_DIR/history.db}"
  local key="${port}|${process}"

  if [[ "${ANOMALY_USING_SQLITE:-false}" == "true" ]] && [[ -f "$db_path" ]]; then
    # Upsert into SQLite
    local existing_count
    existing_count="$(sqlite3 "$db_path" "SELECT times_seen FROM anomaly_profiles WHERE port=$port AND process='${process//\'/\'\'}' ;" 2>/dev/null || echo "0")"
    if [[ "$existing_count" -gt 0 ]]; then
      sqlite3 "$db_path" "UPDATE anomaly_profiles SET user='${user//\'/\'\'}', bind_addr='${bind_addr//\'/\'\'}', risk='$risk', score=$score, last_seen=datetime('now','localtime'), times_seen=times_seen+1 WHERE port=$port AND process='${process//\'/\'\'}' ;" 2>/dev/null || true
    else
      sqlite3 "$db_path" "INSERT INTO anomaly_profiles (port, process, user, bind_addr, risk, score) VALUES ($port, '${process//\'/\'\'}', '${user//\'/\'\'}', '${bind_addr//\'/\'\'}', '$risk', $score);" 2>/dev/null || true
    fi
  fi

  # Always update in-memory profile
  local count=1
  local existing="${ANOMALY_CURRENT_PROFILE[$key]:-}"
  if [[ -n "$existing" ]]; then
    count="$(echo "$existing" | cut -d'|' -f6)"
    count=$((count + 1))
  fi
  ANOMALY_CURRENT_PROFILE["$key"]="${process}|${user}|${bind_addr}|${risk}|${score}|${count}"
}

# ─── Anomaly Detection ───

# Detect anomalies for a single port by comparing against profile
detect_port_anomaly() {
  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"
  local risk="${7:-}" score="${8:-}"

  # Calculate risk/score inline (don't rely on external functions)
  if [[ -z "$risk" || -z "$score" ]]; then
    local bind_type="ALL"
    case "$bind_addr" in
      127.*|"localhost"|"::1") bind_type="LOCAL" ;;
      10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*) bind_type="LAN" ;;
      [fF][eE]80:*) bind_type="LAN" ;;
      0.0.0.0|"::"|"*"|"") bind_type="ALL" ;;
      *) bind_type="UNKNOWN" ;;
    esac
    local base=3
    for p in 21 22 23 445 3306 3389 5432 6379 27017 1433 1521 5900 5901 4444 6666 6667 6668 6669 2375 2376 6443 10250 10255; do
      [[ "$port" == "$p" ]] && { base=8; break; }
    done
    if [[ $base -eq 3 ]]; then
      for p in 80 443 8080 8443 25 587 993 110 143 465 389 636 161 162 137 138 139 135; do
        [[ "$port" == "$p" ]] && { base=6; break; }
      done
    fi
    score=$(( base * 10 / 10 ))
  fi

  # Normalize process name
  local norm_process="${process##*/}"
  norm_process="$(echo "$norm_process" | tr '[:upper:]' '[:lower:]')"

  # Build lookup key
  local base_key="${port}|${norm_process}"
  local profile_entry="${ANOMALY_CURRENT_PROFILE[$base_key]:-}"
  if [[ -z "$profile_entry" ]]; then
    profile_entry="${ANOMALY_CURRENT_PROFILE[${port}|*]:-}"
  fi

  # No profile entry → NEW PORT
  if [[ -z "$profile_entry" ]]; then
    ANOMALY_DETECTIONS["$port"]="30|NEW|New port appeared: $port ($process)"
    ANOMALY_TOTAL_SCORE=$((ANOMALY_TOTAL_SCORE + 30))
    ANOMALY_COUNT=$((ANOMALY_COUNT + 1))
    return
  fi

  # Parse profile entry: process|user|bind|risk|score|count
  local prof_process prof_user prof_bind prof_risk
  IFS='|' read -r prof_process prof_user prof_bind prof_risk _ _ <<< "$profile_entry"

  local anomaly_score=0
  local anomaly_details=()

  # Check PROCESS change (+35)
  if [[ "$norm_process" != "$prof_process" && "$prof_process" != "*" ]]; then
    anomaly_score=$((anomaly_score + 35))
    anomaly_details+=("Process changed: ${prof_process} -> ${norm_process}")
  fi

  # Check USER change (+25)
  if [[ "$user" != "$prof_user" && "$prof_user" != "*" ]]; then
    anomaly_score=$((anomaly_score + 25))
    anomaly_details+=("User changed: ${prof_user} -> ${user}")
  fi

  # Check BIND change (+20)
  if [[ "$bind_addr" != "$prof_bind" && "$prof_bind" != "*" ]]; then
    anomaly_score=$((anomaly_score + 20))
    anomaly_details+=("Bind changed: ${prof_bind} -> ${bind_addr}")
  fi

  # Record anomaly if detected
  if [[ $anomaly_score -gt 0 ]]; then
    local details_str
    details_str="$(
      IFS='; '
      echo "${anomaly_details[*]}"
    )"
    ANOMALY_DETECTIONS["$port"]="$anomaly_score|CHANGE|${details_str}"
    ANOMALY_TOTAL_SCORE=$((ANOMALY_TOTAL_SCORE + anomaly_score))
    ANOMALY_COUNT=$((ANOMALY_COUNT + 1))
  fi
}


detect_missing_ports() {
  local current_data="$1"
  local current_ports=""

  # Build set of currently-observed (port|process) keys
  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local norm_process="${process##*/}"
    norm_process="$(echo "$norm_process" | tr '[:upper:]' '[:lower:]')"
    current_ports+="${port}|${norm_process}"$'\n'
  done <<< "$current_data"

  # Check each profile entry against current ports
  for key in "${!ANOMALY_CURRENT_PROFILE[@]}"; do
    local port="${key%%|*}"
    local process="${key#*|}"
    [[ "$process" == "*" ]] && continue  # Skip wildcard entries

    # Check if this port+process is in current scan
    if ! grep -q "^${port}|${process}$" <<< "$current_ports" 2>/dev/null; then
      # Port is missing — might be PORT GONE anomaly
      # Only flag if we've seen it at least 2 times (avoid false positives)
      local entry="${ANOMALY_CURRENT_PROFILE[$key]:-}"
      local count="$(echo "$entry" | cut -d'|' -f6)"
      if [[ $count -ge 2 ]]; then
        ANOMALY_DETECTIONS["missing:${port}"]="$PORT_GONE_WEIGHT|GONE|Port $port ($process) is no longer listening"
        ANOMALY_TOTAL_SCORE=$((ANOMALY_TOTAL_SCORE + PORT_GONE_WEIGHT))
        ANOMALY_COUNT=$((ANOMALY_COUNT + 1))

        $USE_SYSLOG && logger -t "port-watcher-anomaly" "[${PORT_GONE_WEIGHT}pts] Port $port ($process) disappeared"
      fi
    fi
  done
}

# ─── Main Detection Runner ───

# Run full anomaly detection on scan data
run_anomaly_detection() {
  local port_data="$1"
  local reset="${2:-false}"

  # Reset state
  ANOMALY_DETECTIONS=()
  ANOMALY_TOTAL_SCORE=0
  ANOMALY_COUNT=0
  # Skip if reset flag; use nounset-safe expansion
  [[ "${reset:-false}" == "true" ]] && return

  # Load profile if not already loaded (nounset-safe)
  [[ "${ANOMALY_PROFILE_LOADED:-false}" != "true" ]] && load_anomaly_profile

  # Detect per-port anomalies
  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    detect_port_anomaly "$process" "$pid" "$user" "$proto" "$bind_addr" "$port" "" ""
  done <<< "$port_data"

  # Detect missing ports
  detect_missing_ports "$port_data"

  # Update profile with current scan data
  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local bind_type="ALL" risk="LOW" score="3"
    case "$bind_addr" in
      127.*|"localhost"|"::1") bind_type="LOCAL" ;;
      10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*) bind_type="LAN" ;;
      [fF][eE]80:*) bind_type="LAN" ;; 0.0.0.0|"::"|"*"|"") bind_type="ALL" ;;
      *) bind_type="UNKNOWN" ;;
    esac
    case "$port" in
      21|22|23|445|3306|3389|5432|6379|27017|1433|1521|5900|5901|4444|6666|6667|6668|6669|2375|2376|6443|10250|10255|9200|9300|11211|27018|27019|1434|1522|9042|9160) score=8; risk="CRITICAL" ;;
      80|443|8080|8443|25|587|993|110|143|465|389|636|161|162|137|138|139|135|502|102|20000|44818|2222|4840) score=6; risk="HIGH" ;;
      53|67|68|69|123|514|179|546|547|548|554|873|2049|111|177|427|631|3283|5353|8612|1124|1900|4500) score=4; risk="MEDIUM" ;;
      *) score=3; risk="LOW" ;;
    esac
    [[ "$bind_type" == "ALL" ]] && score=$((score * 2))
    [[ "$bind_type" == "UNKNOWN" ]] && score=$((score + 1))
    [[ "$risk" == "CRITICAL" && "$bind_type" == "ALL" ]] && risk="CRITICAL"
    [[ "$risk" == "CRITICAL" && "$bind_type" == "LOCAL" ]] && risk="MEDIUM"
    save_to_anomaly_profile "$port" "${process##*/}" "$user" "$bind_addr" "$risk" "$score"
  done <<< "$port_data"

  # Record alerts to SQLite if database plugin loaded
  if [[ $ANOMALY_TOTAL_SCORE -ge $ANOMALY_WARN_THRESHOLD ]] && declare -f record_alert &>/dev/null; then
    local severity="INFO"
    [[ $ANOMALY_TOTAL_SCORE -ge $ANOMALY_ALERT_THRESHOLD ]] && severity="CRITICAL"
    [[ $ANOMALY_TOTAL_SCORE -ge $ANOMALY_WARN_THRESHOLD && $ANOMALY_TOTAL_SCORE -lt $ANOMALY_ALERT_THRESHOLD ]] && severity="HIGH"
    record_alert "$severity" "anomaly" "0" "" "Anomaly score: $ANOMALY_TOTAL_SCORE ($ANOMALY_COUNT detections)" 2>/dev/null || true
  fi
}

# ─── Anomaly Display ───

# Display the anomaly report
show_anomaly_report() {
  echo ""
  if [[ $ANOMALY_TOTAL_SCORE -ge $ANOMALY_ALERT_THRESHOLD ]]; then
    cecho "$C_BOLD_RED" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_BOLD_RED" "║  🚨 ANOMALY DETECTED — Score: ${ANOMALY_TOTAL_SCORE}                          ║"
    cecho "$C_BOLD_RED" "╚═══════════════════════════════════════════════════════════════╝"
  elif [[ $ANOMALY_TOTAL_SCORE -ge $ANOMALY_WARN_THRESHOLD ]]; then
    cecho "$C_BOLD_YELLOW" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_BOLD_YELLOW" "║  ⚠️  ANOMALY WARNING — Score: ${ANOMALY_TOTAL_SCORE}                        ║"
    cecho "$C_BOLD_YELLOW" "╚═══════════════════════════════════════════════════════════════╝"
  else
    cecho "$C_GREEN" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_GREEN" "║  ✅ Anomaly Scan Complete — Score: ${ANOMALY_TOTAL_SCORE}                      ║"
    cecho "$C_GREEN" "╚═══════════════════════════════════════════════════════════════╝"
  fi
  echo ""

  if [[ $ANOMALY_COUNT -eq 0 ]]; then
    cecho "$C_DIM" "  No anomalies detected. System behavior matches expected profile."
    echo ""
    return
  fi

  echo "  $(cecho "$C_BOLD" "Detected ${ANOMALY_COUNT} anomaly/anomalies (Total Score: $ANOMALY_TOTAL_SCORE)")"
  echo ""

  # Per-port anomalies
  if [[ "$TABLE_STYLE" == "unicode" ]]; then
    echo "  $(cecho "$C_BOLD" "$(printf '┌───────┬────────┬────────┬─────────────────────────────────────┐')")"
    echo "  $(printf '│ %-5s │ %-6s │ %-6s │ %-35s │' \
      "$(cecho "$C_BOLD_YELLOW" "PORT")" \
      "$(cecho "$C_BOLD_YELLOW" "SCORE")" \
      "$(cecho "$C_BOLD_YELLOW" "TYPE")" \
      "$(cecho "$C_BOLD_YELLOW" "DETAIL")")"
    echo "  $(cecho "$C_BOLD" "$(printf '├───────┼────────┼────────┼─────────────────────────────────────┤')")"
  fi

  # Sort detections by score descending
  local sorted_ports=()
  for key in "${!ANOMALY_DETECTIONS[@]}"; do
    sorted_ports+=("$key")
  done
  # Simple bubble sort by score (descending)
  for ((i = 0; i < ${#sorted_ports[@]}; i++)); do
    for ((j = i + 1; j < ${#sorted_ports[@]}; j++)); do
      local score_i score_j
      score_i="$(echo "${ANOMALY_DETECTIONS[${sorted_ports[$i]}]:-0}" | cut -d'|' -f1)"
      score_j="$(echo "${ANOMALY_DETECTIONS[${sorted_ports[$j]}]:-0}" | cut -d'|' -f1)"
      if [[ $score_j -gt $score_i ]]; then
        local tmp="${sorted_ports[$i]}"
        sorted_ports[$i]="${sorted_ports[$j]}"
        sorted_ports[$j]="$tmp"
      fi
    done
  done

  for key in "${sorted_ports[@]}"; do
    local entry="${ANOMALY_DETECTIONS[$key]:-}"
    [[ -z "$entry" ]] && continue
    local ascore atype adetail
    ascore="$(echo "$entry" | cut -d'|' -f1)"
    atype="$(echo "$entry" | cut -d'|' -f2)"
    adetail="$(echo "$entry" | cut -d'|' -f3-)"

    local display_port="$key"
    [[ "$key" == missing:* ]] && display_port="${key#missing:}"

    local score_color="$C_DIM"
    [[ $ascore -ge $ANOMALY_ALERT_THRESHOLD ]] && score_color="$C_BOLD_RED"
    [[ $ascore -ge $ANOMALY_WARN_THRESHOLD && $ascore -lt $ANOMALY_ALERT_THRESHOLD ]] && score_color="$C_BOLD_YELLOW"

    local type_display
    case "$atype" in
      NEW)    type_display="$(cecho "$C_BOLD_RED" "NEW  ")" ;;
      GONE)   type_display="$(cecho "$C_BOLD_YELLOW" "GONE ")" ;;
      CHANGE) type_display="$(cecho "$C_YELLOW" "CHG  ")" ;;
      *)      type_display="$atype" ;;
    esac

    if [[ "$TABLE_STYLE" == "unicode" ]]; then
      printf "  │ %-5s │ %s%-5s${C_RESET} │ %s │ %-35s │\\n" \
        "$display_port" "$score_color" "$ascore" "$type_display" "$adetail"
    else
      echo "  $display_port [$ascore] $atype: $adetail"
    fi
  done

  if [[ "$TABLE_STYLE" == "unicode" ]]; then
    echo "  $(cecho "$C_DIM" "$(printf '└───────┴────────┴────────┴─────────────────────────────────────┘')")"
  fi
  echo ""

  # Show threshold summary
  if [[ $ANOMALY_TOTAL_SCORE -ge $ANOMALY_ALERT_THRESHOLD ]]; then
    cecho "$C_BOLD_RED" "  🚨 Score exceeds ALERT threshold ($ANOMALY_ALERT_THRESHOLD) — Investigate immediately!"
  elif [[ $ANOMALY_TOTAL_SCORE -ge $ANOMALY_WARN_THRESHOLD ]]; then
    cecho "$C_BOLD_YELLOW" "  ⚠️  Score exceeds WARNING threshold ($ANOMALY_WARN_THRESHOLD) — Review changes."
  fi
  echo ""
}

# ─── Plugin Hooks ───

# No per-port analyze hook needed — detection runs in batch via
# run_anomaly_detection() which is called directly from main()

# Render table column — shows anomaly status per port
plugin_render_table_anomaly-detection() {
  local arg="$1"
  if [[ "$arg" == "HEADER" ]]; then
    echo "ANOMALY"
    return
  fi

  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"

  # Check if this port has an anomaly
  local entry="${ANOMALY_DETECTIONS[$port]:-}"
  if [[ -z "$entry" ]]; then
    echo "|${C_DIM}✓${C_RESET}"
    return
  fi

  local ascore atype
  ascore="$(echo "$entry" | cut -d'|' -f1)"
  atype="$(echo "$entry" | cut -d'|' -f2)"

  if [[ $ascore -ge $ANOMALY_ALERT_THRESHOLD ]]; then
    echo "!${ascore}|${C_BOLD_RED}!${ascore}${C_RESET}"
  elif [[ $ascore -ge $ANOMALY_WARN_THRESHOLD ]]; then
    echo "!${ascore}|${C_BOLD_YELLOW}!${ascore}${C_RESET}"
  else
    echo "Δ${ascore}|${C_YELLOW}Δ${ascore}${C_RESET}"
  fi
}

# Render JSON hook — adds anomaly fields
plugin_render_json_anomaly-detection() {
  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"

  local entry="${ANOMALY_DETECTIONS[$port]:-}"
  if [[ -z "$entry" ]]; then
    echo "\"anomaly_score\": 0, \"anomaly_type\": null, \"anomaly_detail\": null"
    return
  fi

  local ascore atype adetail
  ascore="$(echo "$entry" | cut -d'|' -f1)"
  atype="$(echo "$entry" | cut -d'|' -f2)"
  adetail="$(echo "$entry" | cut -d'|' -f3-)"

  # Escape quotes in detail for JSON
  adetail="${adetail//\"/\\\"}"

  echo "\"anomaly_score\": $ascore, \"anomaly_type\": \"$atype\", \"anomaly_detail\": \"$adetail\""
}

# ─── Cleanup ───

plugin_cleanup_anomaly-detection() {
  # Save profile to flat file as backup if not using SQLite
  if [[ "${ANOMALY_USING_SQLITE:-false}" != "true" ]] && [[ ${#ANOMALY_CURRENT_PROFILE[@]} -gt 0 ]]; then
    mkdir -p "${ANOMALY_PROFILE_DIR:-$HOME/.config/port-watcher}" 2>/dev/null || true
    echo "{" > "${ANOMALY_PROFILE_FILE:-${ANOMALY_PROFILE_DIR:-$HOME/.config/port-watcher}/anomaly-profile.json}"
    local first=true
    for key in "${!ANOMALY_CURRENT_PROFILE[@]}"; do
      local entry="${ANOMALY_CURRENT_PROFILE[$key]}"
      $first || echo "," >> "$ANOMALY_PROFILE_FILE"
      first=false
      echo "\"${key}\": \"${entry}\"" >> "$ANOMALY_PROFILE_FILE"
    done
    echo "}" >> "$ANOMALY_PROFILE_FILE"
  fi
}
