#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Slack/Discord Alerting Plugin (Example)
#  ═════════════════════════════════════════════════════════════════════════════
#  Sends alerts to Slack, Discord, or any webhook when CRITICAL/HIGH
#  risk ports are detected.
#
#  To use: Copy to ~/.config/port-watcher/plugins/enabled/ and configure
#  the webhook URL in ports.conf:
#    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
#    DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
# ═══════════════════════════════════════════════════════════════════════════════

plugin_init_alert-slack() {
  # Read webhook URLs from config (loaded by port-watcher.conf)
  SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"
  DISCORD_WEBHOOK="${DISCORD_WEBHOOK_URL:-}"
}

plugin_analyze_alert-slack() {
  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"

  # Determine risk
  local bind_type risk_info risk score
  bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
  score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
  risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"

  # Only alert on CRITICAL or HIGH
  [[ "$risk" != "CRITICAL" && "$risk" != "HIGH" ]] && return

  local hostname="${HOSTNAME:-$(hostname 2>/dev/null || echo 'unknown')}"
  local ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  local message="[${risk}] ${hostname}: Port ${port} (${process}, PID: ${pid}, User: ${user}, Bind: ${bind_addr}) — Score: ${score}"

  # Send to Slack
  if [[ -n "$SLACK_WEBHOOK" ]]; then
    local color
    [[ "$risk" == "CRITICAL" ]] && color="#EF4444" || color="#F59E0B"
    curl -s -X POST -H 'Content-type: application/json' \
      --data "{
        \"attachments\": [{
          \"color\": \"$color\",
          \"title\": \"Port Watcher Alert: ${risk}\",
          \"text\": \"Host: ${hostname}\\nPort: ${port}\\nProcess: ${process} (PID: ${pid})\\nUser: ${user}\\nBind: ${bind_addr}\\nScore: ${score}\\nTimestamp: ${ts}\",
          \"footer\": \"Port Watcher v${VERSION}\",
          \"ts\": $(date +%s)
        }]
      }" "$SLACK_WEBHOOK" &>/dev/null &
  fi

  # Send to Discord
  if [[ -n "$DISCORD_WEBHOOK" ]]; then
    local color_discord
    [[ "$risk" == "CRITICAL" ]] && color_discord="16711680" || color_discord="16755200"
    curl -s -X POST -H 'Content-type: application/json' \
      --data "{
        \"embeds\": [{
          \"color\": $color_discord,
          \"title\": \"Port Watcher Alert: ${risk}\",
          \"fields\": [
            {\"name\": \"Host\", \"value\": \"${hostname}\", \"inline\": true},
            {\"name\": \"Port\", \"value\": \"${port}\", \"inline\": true},
            {\"name\": \"Process\", \"value\": \"${process} (PID: ${pid})\", \"inline\": true},
            {\"name\": \"User\", \"value\": \"${user}\", \"inline\": true},
            {\"name\": \"Bind\", \"value\": \"${bind_addr}\", \"inline\": true},
            {\"name\": \"Score\", \"value\": \"${score}\", \"inline\": true}
          ],
          \"footer\": {\"text\": \"Port Watcher v${VERSION}\"},
          \"timestamp\": \"${ts}\"
        }]
      }" "$DISCORD_WEBHOOK" &>/dev/null &
  fi
}

plugin_cleanup_alert-slack() {
  # Wait for background curl requests to finish
  wait 2>/dev/null || true
}
