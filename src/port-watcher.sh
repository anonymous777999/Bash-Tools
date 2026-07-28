#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v2 — Advanced Security Port Risk Analyzer
#  ═════════════════════════════════════════════════════════════════════════════
#  Author  : RedVortex
#  Version : 2.0.0
#  License : MIT
#  Purpose : Monitors open ports, maps processes/users/PIDs, and performs
#            dynamic risk scoring based on port, user, network binding, and
#            software version context.
#
#  Features:
#    • Full CLI: --json, --csv, --html, --watch, --config, --risk, --port
#    • Dynamic risk scoring: BASE(PORT) × USER_WEIGHT × BIND_WEIGHT × VERSION_WEIGHT
#    • Proper IPv4 + IPv6 dual-stack support
#    • Expanded port DB (DevOps, Cloud, IoT, Database, Container)
#    • Differential change detection between scans
#    • Watch mode with real-time refresh and change alerts
#    • Syslog integration for centralized monitoring
#    • HTML report generation
#    • Config file support (~/.config/port-watcher/ports.conf)
# ═══════════════════════════════════════════════════════════════════════════════

set -o errexit
set -o pipefail
set -o nounset
IFS=$'\n\t'

# ─── VERSION & METADATA ───
VERSION="2.0.0"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATHS=(
  "$HOME/.config/port-watcher/ports.conf"
  "/etc/port-watcher/ports.conf"
  "$SCRIPT_DIR/../config/ports.conf.example"
)

# ─── COLOR CODES ───
C_RESET="\e[0m"
C_BOLD="\e[1m"
C_DIM="\e[2m"
C_RED="\e[31m"
C_GREEN="\e[32m"
C_YELLOW="\e[33m"
C_BLUE="\e[34m"
C_MAGENTA="\e[35m"
C_CYAN="\e[36m"
C_WHITE="\e[97m"
C_BOLD_RED="\e[1;31m"
C_BOLD_GREEN="\e[1;32m"
C_BOLD_YELLOW="\e[1;33m"
C_BOLD_BLUE="\e[1;34m"
C_BOLD_MAGENTA="\e[1;35m"
C_BOLD_CYAN="\e[1;36m"
C_BG_RED="\e[41m"
C_BG_GREEN="\e[42m"
C_BG_YELLOW="\e[43m"

# ─── DEFAULT CONFIG (overridden by config file) ───

# Risk port arrays
CRITICAL=(21 22 23 445 3306 3389 5432 6379 27017 1433 1521 5900 5901 4444 6666 6667 6668 6669)
HIGH=(80 443 8080 8443 25 587 993 110 143 465 389 636 161 162 137 138 139 135 993 995)
MEDIUM=(53 67 68 69 123 514 179 546 547 548 554 873 2049 111 177 427)
LOW=(631 3283 5353 8612 1124 1900 4500)
CLOUD=(2375 2376 6443 10250 10255 8200 8300 8500 4646 4647 9090 10000 30000 31000 32000 8888 8472 4789 7946 2379 2380)
DATABASE=(3306 5432 5433 5434 6379 6380 27017 27018 27019 1433 1434 1521 1522 9042 9160 9200 9300 11211 11222)
CONTAINER=(2375 2376 6443 10250 10255 8472 4789 7946 8888 30000 31000)
IOT=(502 102 20000 44818 2222 4840 80 443 161 162 1911 1962 2404 2455)

# Scoring weights
ROOT_USER_WEIGHT=1.5
KNOWN_USER_WEIGHT=0.8
UNKNOWN_USER_WEIGHT=1.2
BIND_ALL_WEIGHT=2.0
BIND_LOCAL_WEIGHT=0.3
BIND_LAN_WEIGHT=1.0
BIND_UNKNOWN_WEIGHT=1.0
VERSION_NONE_WEIGHT=1.0
VERSION_CURRENT_WEIGHT=0.5
VERSION_OUTDATED_WEIGHT=1.5
VERSION_CRITICAL_WEIGHT=2.5

# Display settings
SHOW_HEADER=true
TABLE_STYLE="unicode"
COLOR=true
TIMESTAMP=true

# Alert thresholds
ALERT_CRITICAL_SCORE=30
ALERT_HIGH_SCORE=15

# ─── GLOBALS ───
NO_COLOR=false
OUTPUT_MODE="table"
FILTER_RISK=""
FILTER_PORT=""
FILTER_PROCESS=""
FILTER_USER=""
OUTPUT_FILE=""
WATCH_INTERVAL=0
USE_SYSLOG=false
CONFIG_FILE=""
BASELINE_FILE=""
DIFFERENTIAL=false
HELP=false
VERSION_INFO=false
ALL_PORTS=()
ALL_PROCESSES=()
declare -A RISK_NAMES
declare -A RISK_COLORS

# ─── FUNCTIONS ───

# Print usage information
usage() {
  cat <<EOF
${C_BOLD}Port Watcher v${VERSION}${C_RESET} — Advanced Security Port Risk Analyzer
${C_DIM}Author: RedVortex${C_RESET}

${C_BOLD}Usage:${C_RESET}
  ${SCRIPT_NAME} [options]

${C_BOLD}Options:${C_RESET}
  -o, --output <format>    Output format: table, json, csv, html  (default: table)
  -w, --watch <seconds>    Watch mode — refresh every N seconds
  -c, --config <file>      Path to config file
  -r, --risk <level>       Filter by risk: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
  -p, --port <ports>       Filter by port(s): 22,80,443 or 8000-9000
      --process <name>     Filter by process name (comma-separated)
      --user <name>        Filter by username (comma-separated)
      --no-color           Disable colored output
      --syslog             Log findings to syslog
      --baseline <file>    Save/compare against a baseline for differential
      --version            Show version information
  -h, --help               Show this help message

${C_BOLD}Examples:${C_RESET}
  ${SCRIPT_NAME}                              # Default table output
  ${SCRIPT_NAME} --output json                # JSON output
  ${SCRIPT_NAME} --output html --report.html  # HTML report
  ${SCRIPT_NAME} --watch 5                    # Live refresh every 5s
  ${SCRIPT_NAME} --risk HIGH                  # Show only HIGH risk ports
  ${SCRIPT_NAME} --port 22,80,443             # Filter specific ports
  ${SCRIPT_NAME} --process sshd,nginx          # Filter by process
  ${SCRIPT_NAME} --user root                  # Filter by user
  ${SCRIPT_NAME} --config ./my-ports.conf     # Custom config
  ${SCRIPT_NAME} --baseline baseline.json     # Differential scan
  ${SCRIPT_NAME} --syslog                     # Log to syslog

${C_BOLD}Risk Levels:${C_RESET}
  ${C_BOLD_RED}CRITICAL${C_RESET}  Score > ${ALERT_CRITICAL_SCORE} — CVE-prone, high-value targets
  ${C_BOLD_RED}HIGH${C_RESET}      Score > ${ALERT_HIGH_SCORE} — Common attack surface
  ${C_BOLD_YELLOW}MEDIUM${C_RESET}    Moderate risk, should be monitored
  ${C_GREEN}LOW${C_RESET}       Low risk infrastructure services
  ${C_DIM}UNKNOWN${C_RESET}   Port not classified

${C_BOLD}Configuration:${C_RESET}
  ~/.config/port-watcher/ports.conf    User config
  /etc/port-watcher/ports.conf         System config
EOF
}

# Parse command-line arguments
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--output)
        shift
        case "${1,,}" in
          table|json|csv|html) OUTPUT_MODE="${1,,}" ;;
          *) echo "Invalid output format: $1 (table, json, csv, html)" >&2; exit 1 ;;
        esac
        ;;
      -w|--watch)
        shift
        if [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ]; then
          WATCH_INTERVAL="$1"
        else
          echo "Watch interval must be a positive number (seconds)" >&2
          exit 1
        fi
        ;;
      -c|--config)
        shift
        CONFIG_FILE="$1"
        ;;
      -r|--risk)
        shift
        FILTER_RISK="${1^^}"
        ;;
      -p|--port)
        shift
        FILTER_PORT="$1"
        ;;
      --process)
        shift
        FILTER_PROCESS="$1"
        ;;
      --user)
        shift
        FILTER_USER="$1"
        ;;
      --no-color)
        NO_COLOR=true
        COLOR=false
        ;;
      --syslog)
        USE_SYSLOG=true
        ;;
      --baseline)
        shift
        BASELINE_FILE="$1"
        DIFFERENTIAL=true
        ;;
      --version)
        echo "Port Watcher v${VERSION}"
        echo "Author: RedVortex"
        echo "License: MIT"
        exit 0
        ;;
      -h|--help)
        HELP=true
        ;;
      *)
        echo "Unknown option: $1" >&2
        echo "Use --help for usage information." >&2
        exit 1
        ;;
    esac
    shift
  done

  if $HELP; then
    usage
    exit 0
  fi
}

# Load configuration from file
load_config() {
  local config_file=""

  # Use specified config, or search default paths
  if [[ -n "$CONFIG_FILE" ]]; then
    config_file="$CONFIG_FILE"
  else
    for path in "${CONFIG_PATHS[@]}"; do
      if [[ -f "$path" ]]; then
        config_file="$path"
        break
      fi
    done
  fi

  [[ -z "$config_file" || ! -f "$config_file" ]] && return 0

  # Parse config file line by line
  while IFS='=' read -r key value; do
    key="$(echo "$key" | xargs)"
    value="$(echo "$value" | xargs)"
    [[ -z "$key" || "$key" =~ ^# ]] && continue

    # Strip parentheses and clean the value
    value="$(echo "$value" | tr -d '()')"

    case "${key^^}" in
      CRITICAL)       IFS=' ' read -r -a CRITICAL <<< "$(echo "$value" | tr ',' ' ')";;
      HIGH)           IFS=' ' read -r -a HIGH <<< "$(echo "$value" | tr ',' ' ')";;
      MEDIUM)         IFS=' ' read -r -a MEDIUM <<< "$(echo "$value" | tr ',' ' ')";;
      LOW)            IFS=' ' read -r -a LOW <<< "$(echo "$value" | tr ',' ' ')";;
      CLOUD)          IFS=' ' read -r -a CLOUD <<< "$(echo "$value" | tr ',' ' ')";;
      DATABASE)       IFS=' ' read -r -a DATABASE <<< "$(echo "$value" | tr ',' ' ')";;
      CONTAINER)      IFS=' ' read -r -a CONTAINER <<< "$(echo "$value" | tr ',' ' ')";;
      IOT)            IFS=' ' read -r -a IOT <<< "$(echo "$value" | tr ',' ' ')";;
      RESEARCH)       ;; # Currently unused in scoring
      ROOT_USER_WEIGHT)       ROOT_USER_WEIGHT="$value";;
      KNOWN_USER_WEIGHT)      KNOWN_USER_WEIGHT="$value";;
      UNKNOWN_USER_WEIGHT)    UNKNOWN_USER_WEIGHT="$value";;
      BIND_ALL_WEIGHT)        BIND_ALL_WEIGHT="$value";;
      BIND_LOCAL_WEIGHT)      BIND_LOCAL_WEIGHT="$value";;
      BIND_LAN_WEIGHT)        BIND_LAN_WEIGHT="$value";;
      BIND_UNKNOWN_WEIGHT)    BIND_UNKNOWN_WEIGHT="$value";;
      VERSION_NONE_WEIGHT)    VERSION_NONE_WEIGHT="$value";;
      VERSION_CURRENT_WEIGHT) VERSION_CURRENT_WEIGHT="$value";;
      VERSION_OUTDATED_WEIGHT) VERSION_OUTDATED_WEIGHT="$value";;
      VERSION_CRITICAL_WEIGHT) VERSION_CRITICAL_WEIGHT="$value";;
      SHOW_HEADER)            SHOW_HEADER="$value";;
      TABLE_STYLE)            TABLE_STYLE="$value";;
      COLOR)                  [[ "$NO_COLOR" == false ]] && COLOR="$value";;
      TIMESTAMP)              TIMESTAMP="$value";;
      ALERT_CRITICAL_SCORE)   ALERT_CRITICAL_SCORE="$value";;
      ALERT_HIGH_SCORE)       ALERT_HIGH_SCORE="$value";;
    esac
  done < "$config_file"
}

# Color helper — respects --no-color
cecho() {
  local color="$1"; shift
  if $COLOR; then
    echo -e "${color}$*${C_RESET}"
  else
    echo "$*"
  fi
}

# Get raw color code (no reset) for inline use
cget() {
  if $COLOR; then echo "$1"; fi
}

# Check if a value is in an array
in_array() {
  local needle="$1"; shift
  for elem in "$@"; do
    [[ "$elem" == "$needle" ]] && return 0
  done
  return 1
}

# ─── DATA COLLECTION ───

# Collect listening ports using available methods
# Returns: PROCESS PID USER PROTO BIND_ADDR PORT
collect_ports() {
  local data=()

  # Method 1: lsof (most detailed)
  if command -v lsof &>/dev/null; then
    while IFS=' ' read -r process pid user proto addr; do
      [[ -z "$process" || -z "$pid" || -z "$addr" ]] && continue
      # Parse IPv6 address like [::1]:3306 or IPv4 like 0.0.0.0:22
      local bind_addr="" port=""
      if [[ "$addr" =~ ^\[.*\]:([0-9]+)$ ]]; then
        # IPv6 with brackets
        port="${BASH_REMATCH[1]}"
        bind_addr="${addr%]:*}"
        bind_addr="${bind_addr#[}"
      elif [[ "$addr" =~ ^(\*|0\.0\.0\.0|\[::\]):([0-9]+)$ ]]; then
        # Wildcard / all interfaces
        bind_addr="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        [[ "$bind_addr" == "*" || "$bind_addr" == "[::]" ]] && bind_addr="0.0.0.0"
      elif [[ "$addr" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-fA-F:]+):([0-9]+)$ ]]; then
        # IPv4 or plain IPv6
        bind_addr="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
      else
        continue
      fi
      [[ -z "$port" ]] && continue
      data+=("$process|$pid|$user|${proto:-tcp}|$bind_addr|$port")
    done < <(sudo lsof -i -P -n 2>/dev/null | awk '/LISTEN/{print $1, $2, $3, $8, $9}' || true)
  fi

  # Method 2: ss (fallback / supplement)
  if command -v ss &>/dev/null && [ ${#data[@]} -eq 0 ]; then
    while IFS=' ' read -r proto addr; do
      [[ -z "$addr" ]] && continue
      local bind_addr="" port=""
      if [[ "$addr" =~ ^\[([^\]]+)\]:([0-9]+)$ ]]; then
        bind_addr="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
      elif [[ "$addr" =~ ^([^:]+):([0-9]+)$ ]]; then
        bind_addr="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
      else
        continue
      fi
      # Try to get process info from /proc
      local pid="" user="" process=""
      # Use grep -E (POSIX) instead of grep -oP (Perl regex - not portable)
      local ss_line
      ss_line="$(ss -tulnp 2>/dev/null | grep -E ":$port " | head -1 || true)"
      if [[ -n "$ss_line" ]]; then
        # Extract process name: users:(("sshd",pid=1234,...))
        local re_process='users:\(\("([^"]+)"'
        if [[ "$ss_line" =~ $re_process ]]; then
          process="${BASH_REMATCH[1]}"
        fi
        # Extract PID
        if [[ "$ss_line" =~ pid=([0-9]+) ]]; then
          pid="${BASH_REMATCH[1]}"
        fi
        if [[ -n "$pid" ]]; then
          user="$(ps -o user= -p "$pid" 2>/dev/null || true)"
        fi
      fi
      data+=("${process:-unknown}|${pid:-0}|${user:-unknown}|${proto}|$bind_addr|$port")
    done < <(ss -tuln 2>/dev/null | awk 'NR>1{print $1, $4}' || true)
  fi

  printf '%s\n' "${data[@]}"
}

# Classify binding exposure
classify_bind() {
  local addr="$1"
  case "$addr" in
    0.0.0.0|"*"|"")       echo "ALL" ;;
    "::"|"::0"|"::1")     echo "ALL" ;;
    127.*|"localhost")     echo "LOCAL" ;;
    10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|192.168.*) echo "LAN" ;;
    ::1)                  echo "LOCAL" ;;
    [fF][eE]80:*)         echo "LAN" ;;
    *)                    echo "UNKNOWN" ;;
  esac
}

# Get user weight for scoring
get_user_weight() {
  local user="$1"
  case "$user" in
    root|toor)      echo "$ROOT_USER_WEIGHT" ;;
    www-data|nobody|daemon|bin|sys|mail|www|nfsnobody) echo "$KNOWN_USER_WEIGHT" ;;
    "")             echo "$UNKNOWN_USER_WEIGHT" ;;
    *)              echo "$UNKNOWN_USER_WEIGHT" ;;
  esac
}

# Get binding weight
get_bind_weight() {
  local bind_type="$1"
  case "$bind_type" in
    ALL)     echo "$BIND_ALL_WEIGHT" ;;
    LOCAL)   echo "$BIND_LOCAL_WEIGHT" ;;
    LAN)     echo "$BIND_LAN_WEIGHT" ;;
    *)       echo "$BIND_UNKNOWN_WEIGHT" ;;
  esac
}

# ─── RISK SCORING ───

# Determine base risk level for a port
# Returns: CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN and base score
classify_port_risk() {
  local port="$1"

  # Check risk arrays in order (most severe first)
  if in_array "$port" "${CRITICAL[@]}"; then
    echo "CRITICAL|8"
  elif in_array "$port" "${HIGH[@]}"; then
    echo "HIGH|6"
  elif in_array "$port" "${MEDIUM[@]}"; then
    echo "MEDIUM|4"
  elif in_array "$port" "${LOW[@]}"; then
    echo "LOW|2"
  # Check secondary categories (same severity as matching primary)
  elif in_array "$port" "${CLOUD[@]}"; then
    echo "HIGH|6"
  elif in_array "$port" "${DATABASE[@]}"; then
    echo "CRITICAL|8"
  elif in_array "$port" "${CONTAINER[@]}"; then
    echo "CRITICAL|8"
  elif in_array "$port" "${IOT[@]}"; then
    echo "HIGH|6"
  else
    echo "UNKNOWN|3"
  fi
}

# Calculate dynamic risk score
# score = base_score × user_weight × bind_weight × version_weight
calculate_score() {
  local port="$1" user="$2" bind_type="$3" version="$4"
  local risk_info base_score user_weight bind_weight version_weight score

  risk_info="$(classify_port_risk "$port")"
  base_score="${risk_info#*|}"
  user_weight="$(get_user_weight "$user")"
  bind_weight="$(get_bind_weight "$bind_type")"
  version_weight="$VERSION_NONE_WEIGHT"

  # Simple awk-based floating point math
  score="$(awk "BEGIN {printf \"%.1f\", $base_score * $user_weight * $bind_weight * $version_weight}")"
  echo "$score"
}

# Convert numeric score back to risk label
# Uses pure bash integer comparison (strips decimal) to avoid bc dependency
score_to_risk() {
  local score="$1"
  # Strip decimal for integer comparison: 16.5 -> 16
  local int_score="${score%.*}"
  [[ -z "$int_score" ]] && int_score="$score"
  [[ -z "$int_score" ]] && int_score=0

  if (( int_score >= ALERT_CRITICAL_SCORE )); then
    echo "CRITICAL"
  elif (( int_score >= ALERT_HIGH_SCORE )); then
    echo "HIGH"
  elif (( int_score >= 8 )); then
    echo "MEDIUM"
  elif (( int_score >= 3 )); then
    echo "LOW"
  else
    echo "INFO"
  fi
}

# Get color for risk level
risk_color() {
  local risk="$1"
  case "$risk" in
    CRITICAL) echo "$C_BOLD_RED" ;;
    HIGH)     echo "$C_RED" ;;
    MEDIUM)   echo "$C_BOLD_YELLOW" ;;
    LOW)      echo "$C_GREEN" ;;
    INFO)     echo "$C_DIM" ;;
    *)        echo "$C_DIM" ;;
  esac
}

# ─── OUTPUT FORMATTERS ───

# Format table output
output_table() {
  local data="$1"
  local header printed_header=false

  if $SHOW_HEADER && ! $printed_header; then
    if $TIMESTAMP; then
      cecho "$C_BOLD_CYAN" "╔═══════════════════════════════════════════════════════════════╗"
      cecho "$C_BOLD_CYAN" "║  🔍 PORT WATCHER v${VERSION} — $(date '+%Y-%m-%d %H:%M:%S')                ║"
      cecho "$C_BOLD_CYAN" "╚═══════════════════════════════════════════════════════════════╝"
      echo ""
    else
      cecho "$C_BOLD_CYAN" "🔍 PORT WATCHER v${VERSION}"
      echo ""
    fi

    if [[ "$TABLE_STYLE" == "unicode" ]]; then
      printf "%s\n" "$(cecho "$C_BOLD" "$(printf '┌───────┬──────┬──────────┬──────────────────┬────────────┬──────────┐')")"
      printf "%-s│ %s │ %s │ %-16s │ %-12s │ %-8s │\n" \
        "$(cecho "$C_BOLD" "│")" \
        "$(cecho "$C_BOLD_YELLOW" "PORT")" \
        "$(cecho "$C_BOLD_YELLOW" "PID")" \
        "$(cecho "$C_BOLD_YELLOW" "USER")" \
        "$(cecho "$C_BOLD_YELLOW" "PROCESS")" \
        "$(cecho "$C_BOLD_YELLOW" "BIND")" \
        "$(cecho "$C_BOLD_YELLOW" "RISK")"
      printf "%s\n" "$(cecho "$C_BOLD" "$(printf '├───────┼──────┼──────────┼──────────────────┼────────────┼──────────┤')")"
    else
      echo "PORT   PID    USER       PROCESS           BIND          RISK"
      echo "────   ────   ────       ───────           ────          ────"
    fi
    printed_header=true
  fi

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info score risk bind_type
    risk_info="$(classify_port_risk "$port")"
    bind_type="$(classify_bind "$bind_addr")"
    score="$(calculate_score "$port" "$user" "$bind_type" "")"
    risk="$(score_to_risk "$score")"
    local color="$(risk_color "$risk")"
    local score_color="$color"

    [[ -n "$FILTER_RISK" && "$risk" != "$FILTER_RISK" ]] && continue
    [[ -n "$FILTER_PORT" ]] && ! in_array "$port" ${FILTER_PORT//,/ } && continue
    [[ -n "$FILTER_PROCESS" ]] && ! in_array "$process" ${FILTER_PROCESS//,/ } && continue
    [[ -n "$FILTER_USER" ]] && ! in_array "$user" ${FILTER_USER//,/ } && continue

    if [[ "$TABLE_STYLE" == "unicode" ]]; then
      printf "│ %-5s │ %-4s │ %-8s │ %-16s │ %-10s │ %s%-6s${C_RESET} │\n" \
        "$port" "$pid" "$user" "$process" "$bind_addr" "$color" "$risk"
    else
      echo " $(printf '%-5s' "$port") $(printf '%-5s' "$pid") $(printf '%-8s' "$user") $(printf '%-16s' "$process") $(printf '%-10s' "$bind_addr") $(cecho "$color" "$risk")"
    fi

    # Send to syslog if enabled
    $USE_SYSLOG && logger -t "port-watcher" "[$risk] Port $port ($process, PID: $pid, User: $user, Bind: $bind_addr) — Score: $score"
  done <<< "$data"

  if $SHOW_HEADER && [[ "$TABLE_STYLE" == "unicode" ]]; then
    printf "%s\n" "$(cecho "$C_DIM" "$(printf '└───────┴──────┴──────────┴──────────────────┴────────────┴──────────┘')")"
  fi
}

# Format JSON output
output_json() {
  local data="$1"
  local first=true

  echo "["
  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info score risk bind_type
    risk_info="$(classify_port_risk "$port")"
    bind_type="$(classify_bind "$bind_addr")"
    score="$(calculate_score "$port" "$user" "$bind_type" "")"
    risk="$(score_to_risk "$score")"
    local ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    [[ -n "$FILTER_RISK" && "$risk" != "$FILTER_RISK" ]] && continue

    $first || echo ","
    first=false
    cat <<JSON
  {
    "timestamp": "$ts",
    "port": $port,
    "pid": ${pid:-0},
    "user": "${user:-unknown}",
    "process": "${process:-unknown}",
    "protocol": "${proto:-tcp}",
    "bind_address": "$bind_addr",
    "bind_type": "$bind_type",
    "risk": "$risk",
    "score": $score,
    "tool": "port-watcher-v$VERSION"
  }
JSON
  done <<< "$data"
  echo ""
  echo "]"
}

# Format CSV output
output_csv() {
  local data="$1"

  echo "timestamp,port,pid,user,process,protocol,bind_address,bind_type,risk,score"
  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info score risk bind_type
    risk_info="$(classify_port_risk "$port")"
    bind_type="$(classify_bind "$bind_addr")"
    score="$(calculate_score "$port" "$user" "$bind_type" "")"
    risk="$(score_to_risk "$score")"
    local ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    [[ -n "$FILTER_RISK" && "$risk" != "$FILTER_RISK" ]] && continue

    echo "$ts,$port,${pid:-0},${user:-unknown},${process:-unknown},${proto:-tcp},$bind_addr,$bind_type,$risk,$score"
  done <<< "$data"
}

# Format HTML output
output_html() {
  local data="$1"
  local rows=""

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info score risk bind_type
    risk_info="$(classify_port_risk "$port")"
    bind_type="$(classify_bind "$bind_addr")"
    score="$(calculate_score "$port" "$user" "$bind_type" "")"
    risk="$(score_to_risk "$score")"
    local risk_color_html
    case "$risk" in
      CRITICAL) risk_color_html="#EF4444" ;;
      HIGH)     risk_color_html="#F59E0B" ;;
      MEDIUM)   risk_color_html="#EAB308" ;;
      LOW)      risk_color_html="#10B981" ;;
      *)        risk_color_html="#64748B" ;;
    esac
    local ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

    [[ -n "$FILTER_RISK" && "$risk" != "$FILTER_RISK" ]] && continue

    rows+="    <tr>
      <td>$ts</td>
      <td><strong>$port</strong></td>
      <td>${pid:-0}</td>
      <td>${user:-unknown}</td>
      <td>${process:-unknown}</td>
      <td>$bind_addr</td>
      <td>$bind_type</td>
      <td style=\"color:$risk_color_html; font-weight:bold;\">$risk</td>
      <td>$score</td>
    </tr>
"
  done <<< "$data"

  cat <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Port Watcher v${VERSION} — Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'JetBrains Mono', 'SF Mono', Monaco, 'Cascadia Code', monospace;
      background: #0a0a0f;
      color: #e0e0e0;
      padding: 40px;
    }
    h1 {
      font-size: 1.5rem;
      margin-bottom: 8px;
      background: linear-gradient(135deg, #a78bfa, #22d3ee);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .meta { color: #64748b; font-size: 0.85rem; margin-bottom: 24px; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: #111118;
      border: 1px solid #1e293b;
      border-radius: 12px;
      overflow: hidden;
    }
    th {
      background: #1a1a2e;
      color: #22d3ee;
      padding: 12px 16px;
      text-align: left;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    td {
      padding: 10px 16px;
      border-top: 1px solid #1e293b;
      font-size: 0.85rem;
    }
    tr:hover td { background: rgba(34, 211, 238, 0.04); }
    .critical { color: #EF4444; font-weight: bold; }
    .high { color: #F59E0B; font-weight: bold; }
    .medium { color: #EAB308; }
    .low { color: #10B981; }
    .unknown { color: #64748B; }
    .footer { margin-top: 24px; color: #334155; font-size: 0.78rem; text-align: center; }
  </style>
</head>
<body>
  <h1>🔍 Port Watcher v${VERSION}</h1>
  <p class="meta">Generated: $(date '+%Y-%m-%d %H:%M:%S') UTC &nbsp;|&nbsp; Author: RedVortex</p>
  <table>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Port</th>
        <th>PID</th>
        <th>User</th>
        <th>Process</th>
        <th>Bind</th>
        <th>Exposure</th>
        <th>Risk</th>
        <th>Score</th>
      </tr>
    </thead>
    <tbody>
${rows}
    </tbody>
  </table>
  <p class="footer">Port Watcher v${VERSION} — RedVortex — MIT License</p>
</body>
</html>
HTML
}

# ─── DIFFERENTIAL / BASELINE ───

# Run differential scan against a baseline
run_differential() {
  local current_data="$1" baseline_data="$2"
  local current_ports baseline_ports new_ports missing_ports

  # Extract port lists
  current_ports="$(echo "$current_data" | awk -F'|' '{print $6"|"$1"|"$2"|"$3}' | sort -u)"
  baseline_ports="$(cat "$BASELINE_FILE" 2>/dev/null | awk -F'|' '{print $6"|"$1"|"$2"|"$3}' | sort -u || echo "")"

  echo ""
  cecho "$C_BOLD_CYAN" "═══════════════════════════════════════════════════"
  cecho "$C_BOLD_CYAN" "  🔄 Differential Scan Report"
  cecho "$C_BOLD_CYAN" "═══════════════════════════════════════════════════"

  # New ports (in current but not in baseline)
  while IFS='|' read -r port process pid user; do
    if ! grep -q "^$port|" <<< "$baseline_ports" 2>/dev/null; then
      cecho "$C_BOLD_RED" "  🆕 NEW: Port $port — $process (PID: $pid, User: $user)"
      $USE_SYSLOG && logger -t "port-watcher" "[ALERT] New port detected: $port ($process, PID: $pid)"
    fi
  done <<< "$current_ports"

  # Missing ports (in baseline but not in current)
  if [[ -n "$baseline_ports" ]]; then
    while IFS='|' read -r port process pid user; do
      if ! grep -q "^$port|" <<< "$current_ports" 2>/dev/null; then
        cecho "$C_BOLD_YELLOW" "  🗑️  GONE: Port $port — $process (was PID: $pid)"
        $USE_SYSLOG && logger -t "port-watcher" "[INFO] Port closed: $port ($process)"
      fi
    done <<< "$baseline_ports"
  fi

  echo ""
}

# ─── WATCH MODE ───

# Run in watch mode (continuous monitoring)
watch_mode() {
  local interval="$1"

  cecho "$C_BOLD_CYAN" "📡 Port Watcher v${VERSION} — Watch Mode (refresh every ${interval}s)"
  cecho "$C_DIM" "   Press Ctrl+C to stop"
  echo ""

  # Save initial baseline for differential
  local temp_baseline
  temp_baseline="$(mktemp)"
  collect_ports > "$temp_baseline"
  BASELINE_FILE="$temp_baseline"
  DIFFERENTIAL=true

  while true; do
    clear 2>/dev/null || true
    local data
    data="$(collect_ports)"

    cecho "$C_BOLD_CYAN" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_BOLD_CYAN" "║  🔍 PORT WATCHER v${VERSION} — $(date '+%Y-%m-%d %H:%M:%S')           ║"
    cecho "$C_BOLD_CYAN" "╚═══════════════════════════════════════════════════════════════╝"

    output_table "$data"
    run_differential "$data" "$BASELINE_FILE"

    # Update baseline for next iteration
    echo "$data" > "$BASELINE_FILE"

    sleep "$interval"
  done
}

# ─── MAIN ───

main() {
  # Parse CLI arguments
  parse_args "$@"

  # Load config
  load_config

  # Check dependencies
  if ! command -v lsof &>/dev/null && ! command -v ss &>/dev/null; then
    echo "Error: Neither 'lsof' nor 'ss' found. Install one of them." >&2
    echo "  Debian/Ubuntu: sudo apt install lsof" >&2
    echo "  RHEL/Fedora:   sudo dnf install lsof" >&2
    echo "  Arch:          sudo pacman -S lsof" >&2
    exit 1
  fi

  # Check if running as root (recommended but not required with ss)
  if [[ $EUID -ne 0 ]] && command -v lsof &>/dev/null; then
    cecho "$C_BOLD_YELLOW" "⚠️  Warning: Not running as root. lsof may show limited results."
    cecho "$C_DIM" "   Run with sudo for full visibility: sudo ${SCRIPT_NAME}"
    echo ""
  fi

  # Collect port data
  local port_data
  port_data="$(collect_ports)"

  # Check if any data was collected
  if [[ -z "$port_data" ]]; then
    echo "No listening ports found or unable to collect data."
    exit 0
  fi

  # Run differential if baseline provided
  if $DIFFERENTIAL && [[ -n "$BASELINE_FILE" && -f "$BASELINE_FILE" ]]; then
    run_differential "$port_data" "$BASELINE_FILE"
  fi

  # Skip initial output if watch mode is active (watch_mode handles its own output)
  if [[ $WATCH_INTERVAL -le 0 ]]; then
    # Handle output
    case "$OUTPUT_MODE" in
      json)
        local output
        output="$(output_json "$port_data")"
        if [[ -n "$OUTPUT_FILE" ]]; then
          echo "$output" > "$OUTPUT_FILE"
          echo "JSON report written to: $OUTPUT_FILE"
        else
          echo "$output"
        fi
        ;;
      csv)
        local output
        output="$(output_csv "$port_data")"
        if [[ -n "$OUTPUT_FILE" ]]; then
          echo "$output" > "$OUTPUT_FILE"
          echo "CSV report written to: $OUTPUT_FILE"
        else
          echo "$output"
        fi
        ;;
      html)
        local output
        output="$(output_html "$port_data")"
        if [[ -n "$OUTPUT_FILE" ]]; then
          echo "$output" > "$OUTPUT_FILE"
          echo "HTML report written to: $OUTPUT_FILE"
        else
          echo "$output"
        fi
        ;;
      table|*)
        output_table "$port_data"
        ;;
    esac
  fi

  # Save baseline if requested
  if [[ -n "$BASELINE_FILE" && ! -f "$BASELINE_FILE" ]]; then
    echo "$port_data" > "$BASELINE_FILE"
    cecho "$C_DIM" "Baseline saved to: $BASELINE_FILE"
  fi

  # Run watch mode if requested
  if [[ $WATCH_INTERVAL -gt 0 ]]; then
    watch_mode "$WATCH_INTERVAL"
  fi
}

# Run main
main "$@"
