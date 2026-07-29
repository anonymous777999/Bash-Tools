#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — SQLite Historical Database Plugin
#  ═════════════════════════════════════════════════════════════════════════════
#  Records every scan to a local SQLite database for historical queries,
#  trend analysis, and forensics.
#
#  CLI commands added:
#    --history <port>     Show scan history for a specific port
#    --trend [days]       Show risk trend over N days (default: 7)
#    --timeline           Show alert timeline (new/changed ports)
#    --db <path>          Specify database path (default: ~/.config/port-watcher/history.db)
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Database Path ───
DB_DIR="$HOME/.config/port-watcher"
DB_PATH="${DB_DIR}/history.db"
CLI_DB_COMMAND=""      # Set by --db flag
CLI_HISTORY=""
CLI_TREND=""
CLI_TIMELINE=false
DB_AVAILABLE=false

# ─── Check Dependencies ───
plugin_init_database-sqlite() {
  if command -v sqlite3 &>/dev/null; then
    DB_AVAILABLE=true
    # Override DB path if CLI flag was set
    [[ -n "$CLI_DB_COMMAND" ]] && DB_PATH="$CLI_DB_COMMAND"
    mkdir -p "$(dirname "$DB_PATH")" 2>/dev/null || true
    init_schema
  else
    DB_AVAILABLE=false
  fi
}

# ─── Schema Initialization ───
init_schema() {
  sqlite3 "$DB_PATH" 2>/dev/null <<SQL
CREATE TABLE IF NOT EXISTS scans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp   TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  hostname    TEXT NOT NULL DEFAULT '',
  total_ports INTEGER DEFAULT 0,
  critical    INTEGER DEFAULT 0,
  high        INTEGER DEFAULT 0,
  medium      INTEGER DEFAULT 0,
  low         INTEGER DEFAULT 0,
  unknown     INTEGER DEFAULT 0,
  score_avg   REAL DEFAULT 0.0,
  duration_ms INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ports (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id     INTEGER NOT NULL,
  timestamp   TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  port        INTEGER NOT NULL,
  pid         INTEGER DEFAULT 0,
  user        TEXT DEFAULT 'unknown',
  process     TEXT DEFAULT 'unknown',
  protocol    TEXT DEFAULT 'tcp',
  bind_addr   TEXT DEFAULT '',
  bind_type   TEXT DEFAULT 'UNKNOWN',
  risk        TEXT DEFAULT 'UNKNOWN',
  score       REAL DEFAULT 0.0,
  cve_count   INTEGER DEFAULT 0,
  mitre_id    TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alerts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp   TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  hostname    TEXT NOT NULL DEFAULT '',
  severity    TEXT NOT NULL,
  alert_type  TEXT NOT NULL DEFAULT 'port_change',
  port        INTEGER DEFAULT 0,
  process     TEXT DEFAULT '',
  message     TEXT NOT NULL,
  acknowledged INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);
CREATE INDEX IF NOT EXISTS idx_ports_timestamp ON ports(timestamp);
CREATE INDEX IF NOT EXISTS idx_ports_risk ON ports(risk);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
SQL
}

# ─── Data Recording ───

# Record a completed scan to the database
record_scan() {
  [[ "$DB_AVAILABLE" != "true" ]] && return
  local port_data="$1" total critical high medium low unknown score_avg
  local start_ms end_ms duration_ms

  # Count risk levels
  total=0; critical=0; high=0; medium=0; low=0; unknown=0; score_sum=0
  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info score risk bind_type
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
    score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
    risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"
    ((total++))
    score_sum="$(awk "BEGIN {printf \"%.1f\", $score_sum + $score}" 2>/dev/null || echo "$score_sum")"
    case "$risk" in
      CRITICAL) ((critical++)) ;;
      HIGH)     ((high++)) ;;
      MEDIUM)   ((medium++)) ;;
      LOW)      ((low++)) ;;
      *)        ((unknown++)) ;;
    esac
  done <<< "$port_data"

  [[ $total -eq 0 ]] && return
  score_avg="$(awk "BEGIN {printf \"%.1f\", $score_sum / $total}" 2>/dev/null || echo "0")"

  # Get hostname
  local hostname="${HOSTNAME:-$(hostname 2>/dev/null || echo 'unknown')}"

  # Insert scan record
  local scan_id
  scan_id="$(sqlite3 "$DB_PATH" "INSERT INTO scans (hostname, total_ports, critical, high, medium, low, unknown, score_avg) VALUES ('$hostname', $total, $critical, $high, $medium, $low, $unknown, $score_avg); SELECT last_insert_rowid();" 2>/dev/null || echo "0")"

  [[ "$scan_id" == "0" ]] && return

  # Insert each port record
  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info score risk bind_type
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
    score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
    risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"

    # Escape single quotes in user/process for SQL
    local user_esc="${user//\'/\'\'}"
    local process_esc="${process//\'/\'\'}"
    local bind_addr_esc="${bind_addr//\'/\'\'}"

    sqlite3 "$DB_PATH" "INSERT INTO ports (scan_id, port, pid, user, process, protocol, bind_addr, bind_type, risk, score) VALUES ($scan_id, $port, ${pid:-0}, '$user_esc', '$process_esc', '${proto:-tcp}', '$bind_addr_esc', '$bind_type', '$risk', $score);" 2>/dev/null || true
  done <<< "$port_data"
}

# Record an alert
record_alert() {
  [[ "$DB_AVAILABLE" != "true" ]] && return
  local severity="$1" alert_type="$2" port="$3" process="$4" message="$5"
  local hostname="${HOSTNAME:-$(hostname 2>/dev/null || echo 'unknown')}"

  sqlite3 "$DB_PATH" "INSERT INTO alerts (hostname, severity, alert_type, port, process, message) VALUES ('$hostname', '$severity', '$alert_type', $port, '${process//\'/\'\'}', '${message//\'/\'\'}');" 2>/dev/null || true
}

# ─── Query Commands ───

# Show scan history for a specific port
show_port_history() {
  local port="$1" limit="${2:-20}"
  [[ "$DB_AVAILABLE" != "true" ]] && {
    echo "SQLite3 not available. Install sqlite3 to use --history."
    return 1
  }

  echo ""
  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║  📜 Port History: ${port}                                    ║"
  echo "╚═══════════════════════════════════════════════════════════════╝"
  echo ""

  # Query port history
  sqlite3 -header -column "$DB_PATH" "SELECT timestamp AS 'Timestamp', process AS 'Process', user AS 'User', bind_addr AS 'Bind', risk AS 'Risk', score AS 'Score' FROM ports WHERE port = $port ORDER BY timestamp DESC LIMIT $limit;" 2>/dev/null || echo "No history found for port $port."
  echo ""
}

# Show risk trend over N days
show_risk_trend() {
  local days="${1:-7}"
  [[ "$DB_AVAILABLE" != "true" ]] && {
    echo "SQLite3 not available. Install sqlite3 to use --trend."
    return 1
  }

  echo ""
  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║  📊 Risk Trend — Last ${days} Days                              ║"
  echo "╚═══════════════════════════════════════════════════════════════╝"
  echo ""

  sqlite3 -header -column "$DB_PATH" "SELECT date(timestamp) AS 'Date', total_ports AS 'Ports', critical AS 'Crit', high AS 'High', medium AS 'Med', low AS 'Low', ROUND(score_avg, 1) AS 'Avg Score' FROM scans WHERE date(timestamp) >= date('now', '-${days} days') ORDER BY timestamp DESC;" 2>/dev/null || echo "No trend data available."
  echo ""
}

# Show alert timeline
show_timeline() {
  local limit="${1:-50}"
  [[ "$DB_AVAILABLE" != "true" ]] && {
    echo "SQLite3 not available. Install sqlite3 to use --timeline."
    return 1
  }

  echo ""
  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║  ⏱ Alert Timeline (Last ${limit})                              ║"
  echo "╚═══════════════════════════════════════════════════════════════╝"
  echo ""

  sqlite3 -header -column "$DB_PATH" "SELECT timestamp AS 'Timestamp', severity AS 'Sev', alert_type AS 'Type', port AS 'Port', message AS 'Message' FROM alerts ORDER BY timestamp DESC LIMIT $limit;" 2>/dev/null || echo "No alerts recorded."
  echo ""
}

# Export scan stats
show_db_stats() {
  [[ "$DB_AVAILABLE" != "true" ]] && return

  echo ""
  echo "╔═══════════════════════════════════════════════════════════════╗"
  echo "║  📊 Database Statistics                                       ║"
  echo "╚═══════════════════════════════════════════════════════════════╝"

  local total_scans total_ports total_alerts oldest_scan newest_scan
  total_scans="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM scans;" 2>/dev/null || echo "0")"
  total_ports="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM ports;" 2>/dev/null || echo "0")"
  total_alerts="$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM alerts;" 2>/dev/null || echo "0")"
  oldest_scan="$(sqlite3 "$DB_PATH" "SELECT timestamp FROM scans ORDER BY timestamp ASC LIMIT 1;" 2>/dev/null || echo "N/A")"
  newest_scan="$(sqlite3 "$DB_PATH" "SELECT timestamp FROM scans ORDER BY timestamp DESC LIMIT 1;" 2>/dev/null || echo "N/A")"

  echo ""
  echo "  Database:    $DB_PATH"
  echo "  Total scans: $total_scans"
  echo "  Total ports: $total_ports"
  echo "  Total alerts: $total_alerts"
  echo "  First scan:  $oldest_scan"
  echo "  Latest scan: $newest_scan"
  echo ""
}

# ─── Cleanup ───

plugin_cleanup_database-sqlite() {
  # Vacuum database weekly (optimize storage)
  if [[ "$DB_AVAILABLE" == "true" ]]; then
    sqlite3 "$DB_PATH" "VACUUM;" 2>/dev/null || true
  fi
}
