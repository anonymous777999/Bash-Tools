#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Pluggable Alerting Engine
#  ═════════════════════════════════════════════════════════════════════════════
#  Sends real-time alerts through multiple channels when CRITICAL/HIGH
#  risk ports are detected or anomalies found.
#
#  Supported channels (all optional):
#    • Slack Webhook  (SLACK_WEBHOOK_URL)
#    • Discord Webhook (DISCORD_WEBHOOK_URL)
#    • Email via sendmail (ALERT_EMAIL_TO)
#    • Syslog (built-in, always active)
#
#  Config in ports.conf:
#    ALERT_ENABLED=true
#    ALERT_LEVEL=HIGH          # CRITICAL, HIGH, or ALL
#    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
#    DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
#    ALERT_EMAIL_TO=admin@example.com
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Config (overridable via ports.conf) ───
ALERT_ENABLED="${ALERT_ENABLED:-true}"
ALERT_LEVEL="${ALERT_LEVEL:-HIGH}"
SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK_URL:-}"
ALERT_EMAIL_TO="${ALERT_EMAIL_TO:-}"
ALERTS_SENT=0

# ─── Plugin Init ───
plugin_init_alerting() {
  # Validate webhook URLs look reasonable
  if [[ -n "$SLACK_WEBHOOK" && "$SLACK_WEBHOOK" != https* ]]; then
    echo "[plugin:alerting] Warning: SLACK_WEBHOOK_URL should start with https://" >&2
    SLACK_WEBHOOK=""
  fi
  if [[ -n "$DISCORD_WEBHOOK" && "$DISCORD_WEBHOOK" != https* ]]; then
    echo "[plugin:alerting] Warning: DISCORD_WEBHOOK_URL should start with https://" >&2
    DISCORD_WEBHOOK=""
  fi
}

# ─── Alert Router ───

# Send an alert through all configured channels
send_alert() {
  local severity="$1" alert_type="$2" port="$3" process="$4" message="$5"
  local hostname="${HOSTNAME:-$(hostname 2>/dev/null || echo 'unknown')}"
  local ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  # Check if alerting is enabled and severity meets threshold
  [[ "$ALERT_ENABLED" != "true" ]] && return

  # Check severity threshold
  local should_alert=false
  case "$ALERT_LEVEL" in
    ALL)       should_alert=true ;;
    HIGH)      [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]] && should_alert=true ;;
    CRITICAL|*) [[ "$severity" == "CRITICAL" ]] && should_alert=true ;;
  esac
  $should_alert || return

  ALERTS_SENT=$((ALERTS_SENT + 1))

  # Build the alert payload
  local alert_title="Port Watcher Alert: ${severity}"
  local alert_text="Host: ${hostname}\nType: ${alert_type}\nSeverity: ${severity}"

  # Always log to syslog
  logger -t "port-watcher-alert" "[${severity}] ${message}"

  # ── Slack ──
  if [[ -n "$SLACK_WEBHOOK" ]]; then
    local color
    case "$severity" in
      CRITICAL) color="#EF4444" ;;
      HIGH)     color="#F59E0B" ;;
      MEDIUM)   color="#EAB308" ;;
      *)        color="#64748B" ;;
    esac

    # Build fields
    local fields=""
    [[ -n "$port" ]] && fields+=", {\\\"title\\\": \\\"Port\\\", \\\"value\\\": \\\"$port\\\", \\\"short\\\": true}"
    [[ -n "$process" ]] && fields+=", {\\\"title\\\": \\\"Process\\\", \\\"value\\\": \\\"$process\\\", \\\"short\\\": true}"
    fields+=", {\\\"title\\\": \\\"Host\\\", \\\"value\\\": \\\"$hostname\\\", \\\"short\\\": true}"

    curl -s -X POST -H 'Content-type: application/json' \
      --data "{
        \\\"attachments\\\": [{
          \\\"color\\\": \\\"$color\\\",
          \\\"title\\\": \\\"$alert_title\\\",
          \\\"text\\\": \\\"$message\\\",
          \\\"fields\\\": [$fields],
          \\\"footer\\\": \\\"Port Watcher v$VERSION\\\",
          \\\"ts\\\": $(date +%s)
        }]
      }" "$SLACK_WEBHOOK" &>/dev/null &
  fi

  # ── Discord ──
  if [[ -n "$DISCORD_WEBHOOK" ]]; then
    local color_discord=0
    case "$severity" in
      CRITICAL) color_discord=16711680 ;;
      HIGH)     color_discord=16755200 ;;
      MEDIUM)   color_discord=16099336 ;;
      *)        color_discord=6581670 ;;
    esac

    curl -s -X POST -H 'Content-type: application/json' \
      --data "{
        \\\"embeds\\\": [{
          \\\"color\\\": $color_discord,
          \\\"title\\\": \\\"$alert_title\\\",
          \\\"description\\\": \\\"$message\\\",
          \\\"fields\\\": [
            {\\\"name\\\": \\\"Host\\\", \\\"value\\\": \\\"$hostname\\\", \\\"inline\\\": true},
            {\\\"name\\\": \\\"Port\\\", \\\"value\\\": \\\"$port\\\", \\\"inline\\\": true},
            {\\\"name\\\": \\\"Process\\\", \\\"value\\\": \\\"$process\\\", \\\"inline\\\": true},
            {\\\"name\\\": \\\"Type\\\", \\\"value\\\": \\\"$alert_type\\\", \\\"inline\\\": true},
            {\\\"name\\\": \\\"Severity\\\", \\\"value\\\": \\\"$severity\\\", \\\"inline\\\": true}
          ],
          \\\"footer\\\": {\\\"text\\\": \\\"Port Watcher v$VERSION\\\"},
          \\\"timestamp\\\": \\\"${ts}\\\"
        }]
      }" "$DISCORD_WEBHOOK" &>/dev/null &
  fi

  # ── Email (via sendmail or mail command) ──
  if [[ -n "$ALERT_EMAIL_TO" ]]; then
    local subject="[${severity}] Port Watcher Alert — ${alert_type} on ${hostname}"
    local body=""
    body+="Port Watcher Alert\n"
    body+="══════════════════\n\n"
    body+="Severity: ${severity}\n"
    body+="Type:     ${alert_type}\n"
    body+="Host:     ${hostname}\n"
    body+="Time:     $(date '+%Y-%m-%d %H:%M:%S')\n"
    [[ -n "$port" ]] && body+="Port:     ${port}\n"
    [[ -n "$process" ]] && body+="Process:  ${process}\n"
    body+="\nMessage:  ${message}\n"
    body+="\n---\nPort Watcher v${VERSION}"

    if command -v mail &>/dev/null; then
      echo -e "$body" | mail -s "$subject" "$ALERT_EMAIL_TO" &>/dev/null &
    elif command -v sendmail &>/dev/null; then
      (
        echo "Subject: $subject"
        echo "To: $ALERT_EMAIL_TO"
        echo "Content-Type: text/plain; charset=UTF-8"
        echo ""
        echo -e "$body"
      ) | sendmail -t &>/dev/null &
    fi
  fi
}

# ─── Plugin Hooks ───

# Per-port analysis: send alerts for CRITICAL/HIGH risk ports
plugin_analyze_alerting() {
  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"

  # Determine risk
  local bind_type risk_info risk score
  bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
  risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
  score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
  risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"

  # Build alert message
  local message="Port ${port} (${process}, PID: ${pid}, User: ${user}, Bind: ${bind_addr}) — Risk: ${risk}, Score: ${score}"

  send_alert "$risk" "port_detected" "$port" "$process" "$message"
}

# Cleanup — wait for background curl/mail processes
plugin_cleanup_alerting() {
  wait 2>/dev/null || true
  if [[ $ALERTS_SENT -gt 0 ]]; then
    logger -t "port-watcher-alert" "[SUMMARY] $ALERTS_SENT alert(s) sent this session"
  fi
}
