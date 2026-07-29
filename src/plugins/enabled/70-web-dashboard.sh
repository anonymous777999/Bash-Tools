#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Embedded Web Dashboard
#  ═════════════════════════════════════════════════════════════════════════════
#  Starts a lightweight HTTP server serving a real-time HTML security dashboard.
#
#  Architecture (cached-file serving):
#    1. Background render loop collects data + writes HTML+JSON to /tmp/
#    2. socat/ncat/nc serves the pre-rendered files on each HTTP request
#    3. A small routing script (/tmp/port-watcher-server.sh) handles the
#       path-based routing ( / vs /api/scan ) for socat/ncat
#    4. Browser JS fetches /api/scan.json for live updates without page reload
#
#  Usage:
#    sudo port-watcher --dashboard              → Start server on port 9090
#    sudo port-watcher --dashboard-port 8080    → Custom port
#
#  Endpoints:
#    GET /           → HTML dashboard (JS-powered live updates)
#    GET /api/scan   → JSON scan data
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Config ───
DASHBOARD_PORT="${DASHBOARD_PORT:-9090}"
DASHBOARD_HOST="${DASHBOARD_HOST:-127.0.0.1}"
DASHBOARD_REFRESH_SECONDS="${DASHBOARD_REFRESH_SECONDS:-5}"

# ─── Temp files ───
DASH_HTML_FILE="/tmp/port-watcher-dashboard.html"
DASH_JSON_FILE="/tmp/port-watcher-scan.json"
DASH_SERVER_SCRIPT="/tmp/port-watcher-server.sh"

# ─── CLI Flags (set from port-watcher.sh) ───
CLI_DASHBOARD=false
CLI_DASHBOARD_PORT=""

# ─── Plugin Init ───
plugin_init_web-dashboard() {
  [[ -n "$CLI_DASHBOARD_PORT" ]] && DASHBOARD_PORT="$CLI_DASHBOARD_PORT"
  if $CLI_DASHBOARD; then
    if ! command -v socat &>/dev/null && ! command -v ncat &>/dev/null && ! command -v nc &>/dev/null; then
      cecho "$C_BOLD_RED" "Dashboard requires socat, ncat, or nc."
      cecho "$C_DIM" "  Debian/Ubuntu: sudo apt install netcat-openbsd"
      return 1
    fi
    start_dashboard_server
  fi
}

# ─── Render Functions ───

# Render full state (HTML + JSON) to temp files
render_dashboard_state() {
  local data="$1"
  [[ -z "$data" ]] && data="$(collect_ports 2>/dev/null || true)"

  if declare -f run_anomaly_detection &>/dev/null && [[ -n "$data" ]]; then
    load_anomaly_profile 2>/dev/null || true
    run_anomaly_detection "$data" 2>/dev/null || true
  fi

  render_html "$data" > "$DASH_HTML_FILE"
  render_json_api "$data" > "$DASH_JSON_FILE"
}

# ─── Write the routing script for socat/ncat ───
# This is a standalone shell script that reads HTTP request,
# determines the path, and serves the appropriate cached file.
# It exists as a file because socat's SYSTEM spawns a fresh shell
# that doesn't have access to bash functions.
write_server_script() {
  cat > "$DASH_SERVER_SCRIPT" <<'SRVEOF'
#!/bin/sh
# Port Watcher Dashboard Server — routing script
# Called by socat/ncat for each HTTP request
HTML_FILE="/tmp/port-watcher-dashboard.html"
JSON_FILE="/tmp/port-watcher-scan.json"

# Read HTTP request line
read request_line 2>/dev/null || true

# Extract the path from "GET /path HTTP/1.1"
path="${request_line#* }"
path="${path% HTTP*}"

case "$path" in
  /api/scan)
    echo "HTTP/1.1 200 OK"
    echo "Content-Type: application/json"
    echo "Access-Control-Allow-Origin: *"
    echo "Cache-Control: no-cache, no-store, must-revalidate"
    echo "Connection: close"
    echo ""
    if [ -f "$JSON_FILE" ]; then
      cat "$JSON_FILE"
    else
      echo '{"error":"No data available"}'
    fi
    ;;
  /|/index.html|"")
    echo "HTTP/1.1 200 OK"
    echo "Content-Type: text/html; charset=UTF-8"
    echo "Cache-Control: no-cache, no-store, must-revalidate"
    echo "Connection: close"
    echo ""
    if [ -f "$HTML_FILE" ]; then
      cat "$HTML_FILE"
    else
      echo "<html><body style='background:#0a0a0f;color:#EF4444;font-family:monospace;padding:40px;'><h1>Port Watcher</h1><p>Loading...</p></body></html>"
    fi
    ;;
  *)
    echo "HTTP/1.1 404 Not Found"
    echo "Content-Type: text/plain"
    echo "Connection: close"
    echo ""
    echo "404 - Available: /  /api/scan"
    ;;
esac
SRVEOF
  chmod +x "$DASH_SERVER_SCRIPT"
}

# ─── HTML Generator ───

render_html() {
  local data="$1"
  local hostname="${HOSTNAME:-$(hostname 2>/dev/null || echo 'unknown')}"
  local ts="$(date '+%Y-%m-%d %H:%M:%S')"

  local total=0 critical=0 high=0 medium=0 low=0 unknown=0
  local rows=""
  local anomaly_rows="" anomaly_count=0

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info score risk bind_type
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
    score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
    risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"
    total=$((total + 1))

    local risk_color=""
    case "$risk" in
      CRITICAL) risk_color="#EF4444"; critical=$((critical+1)) ;;
      HIGH)     risk_color="#F59E0B"; high=$((high+1)) ;;
      MEDIUM)   risk_color="#EAB308"; medium=$((medium+1)) ;;
      LOW)      risk_color="#10B981"; low=$((low+1)) ;;
      *)        risk_color="#64748B"; unknown=$((unknown+1)) ;;
    esac

    local mitre_badge=""
    if declare -f mitre_lookup &>/dev/null; then
      local mr
      mr="$(mitre_lookup "$process" "$port" "$bind_type" "$risk" 2>/dev/null || true)"
      [[ -n "$mr" ]] && mitre_badge="<span class=\"badge-mitre\">$(echo "$mr" | cut -d: -f1)</span>"
    fi

    local anomaly_badge="" anom_score=0
    if declare -f run_anomaly_detection &>/dev/null; then
      local ae="${ANOMALY_DETECTIONS[$port]:-}"
      if [[ -n "$ae" ]]; then
        anom_score="$(echo "$ae" | cut -d'|' -f1)"
        local ac="anomaly-info"
        [[ $anom_score -ge 50 ]] && ac="anomaly-alert"
        [[ $anom_score -ge 30 && $anom_score -lt 50 ]] && ac="anomaly-warn"
        anomaly_badge="<span class=\"${ac}\">${anom_score}</span>"
      fi
    fi

    rows+="<tr><td class=\"cell-port\">${port}</td><td>${pid}</td><td class=\"cell-user\">${user}</td><td class=\"cell-process\">${process}</td><td>${bind_addr}</td><td style=\"color:${risk_color};font-weight:600;\">${risk}</td><td>${mitre_badge}</td><td class=\"cell-anomaly\">${anomaly_badge}</td></tr>"

    if [[ $anom_score -gt 0 ]]; then
      local anom_type="$(echo "$ae" | cut -d'|' -f2)"
      local anom_detail="$(echo "$ae" | cut -d'|' -f3-)"
      anom_detail="${anom_detail//\"/\\\"}"
      anomaly_count=$((anomaly_count + 1))
      [[ $anomaly_count -le 5 ]] && anomaly_rows+="<div class=\"ticker-item ticker-${anom_type,,}\"><span class=\"ticker-port\">${port}</span><span class=\"ticker-type\">[${anom_type}]</span><span class=\"ticker-detail\">${anom_detail}</span><span class=\"ticker-score\">${anom_score}</span></div>"
    fi
  done <<< "$data"

  local anomaly_section=""
  if [[ -n "$anomaly_rows" ]]; then
    local more=""
    [[ $anomaly_count -gt 5 ]] && more="<div class=\"ticker-more\">+$((anomaly_count - 5)) more</div>"
    anomaly_section="<div class=\"ticker-section\"><div class=\"ticker-header\">Anomalies</div>${anomaly_rows}${more}</div>"
  fi

  cat <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Port Watcher - ${hostname}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'JetBrains Mono','SF Mono','Cascadia Code','Fira Code',monospace;background:#0a0a0f;color:#e2e8f0;min-height:100vh}
.hdr{background:linear-gradient(135deg,#0f0f1a,#1a1a2e);border-bottom:1px solid #1e293b;padding:16px 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.hdr h1{font-size:1.1rem;background:linear-gradient(135deg,#a78bfa,#22d3ee);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700}
.hdr .m{color:#64748b;font-size:.75rem}
.hdr .m s{color:#22d3ee}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.st{display:flex;gap:12px;padding:16px 24px;background:#0d0d16;border-bottom:1px solid #1e293b;flex-wrap:wrap}
.st>div{flex:1;min-width:100px;background:#111118;border:1px solid #1e293b;border-radius:8px;padding:12px 16px;text-align:center;transition:border-color .2s}
.st>div:hover{border-color:#334155}
.st .v{font-size:1.6rem;font-weight:700;line-height:1.2}
.st .l{font-size:.65rem;text-transform:uppercase;letter-spacing:.08em;color:#64748b;margin-top:3px}
.sc .v{color:#EF4444}
.sh .v{color:#F59E0B}
.sm .v{color:#EAB308}
.sl .v{color:#10B981}
.stt .v{color:#22D3EE}
.cx{display:flex;gap:16px;padding:16px 24px;flex-wrap:wrap}
.tw{flex:1;min-width:300px;overflow-x:auto}
table{width:100%;border-collapse:collapse;background:#111118;border:1px solid #1e293b;border-radius:8px;overflow:hidden}
th{background:#1a1a2e;color:#22d3ee;padding:10px 12px;text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;font-weight:600;white-space:nowrap}
td{padding:8px 12px;border-top:1px solid #1a1a2e;font-size:.8rem;white-space:nowrap}
tr:hover td{background:rgba(34,211,238,.04)}
.cp{font-weight:700;color:#22d3ee}
.cu{color:#94a3b8}
.bm{display:inline-block;background:rgba(167,139,250,.12);color:#a78bfa;padding:1px 6px;border-radius:3px;font-size:.7rem;font-weight:600}
.aa{display:inline-block;background:rgba(239,68,68,.15);color:#EF4444;padding:1px 6px;border-radius:3px;font-weight:700;font-size:.72rem}
.aw{display:inline-block;background:rgba(234,179,8,.15);color:#EAB308;padding:1px 6px;border-radius:3px;font-weight:600;font-size:.72rem}
.ai{display:inline-block;color:#64748B;font-weight:600;font-size:.72rem}
.ts{width:340px;min-width:280px;background:#111118;border:1px solid #1e293b;border-radius:8px;overflow:hidden;align-self:flex-start}
.ts .th{background:#1a1a2e;padding:10px 14px;font-size:.75rem;font-weight:600;color:#22d3ee;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #1e293b}
.ti{padding:10px 14px;border-bottom:1px solid #1a1a2e;font-size:.75rem;line-height:1.5}
.ti:last-child{border-bottom:none}
.tn{color:#22d3ee;font-weight:700;margin-right:6px}
.ty{color:#64748b;margin-right:6px}
.td{color:#94a3b8}
.tsc{float:right;color:#EF4444;font-weight:700}
.tm{padding:8px 14px;text-align:center;color:#64748b;font-size:.7rem}
.ft{padding:12px 24px;color:#334155;font-size:.7rem;text-align:center;border-top:1px solid #1e293b}
.ft a{color:#22d3ee;text-decoration:none}
.ft a:hover{text-decoration:underline}
@media(max-width:768px){.st{gap:8px}.st>div{min-width:calc(50% - 4px)}.cx{flex-direction:column}.ts{width:100%}.hdr{flex-direction:column;text-align:center}}
</style>
</head>
<body>
<div class="hdr">
<div><h1>Port Watcher v${VERSION}</h1><div class="m"><span class="dot"></span>Live - <s id="hn">${hostname}</s></div></div>
<div class="m" style="text-align:right"><div>Last scan: <s id="st">${ts}</s></div><div style="margin-top:3px"><s id="pc">${total}</s> ports</div></div>
</div>

<div class="st">
<div class="sc"><div class="v" id="sc">${critical}</div><div class="l">CRITICAL</div></div>
<div class="sh"><div class="v" id="sh">${high}</div><div class="l">HIGH</div></div>
<div class="sm"><div class="v" id="sm">${medium}</div><div class="l">MEDIUM</div></div>
<div class="sl"><div class="v" id="sl">${low}</div><div class="l">LOW</div></div>
<div class="stt"><div class="v" id="stt">${total}</div><div class="l">TOTAL</div></div>
</div>

<div class="cx">
<div class="tw">
<table><thead><tr><th>Port</th><th>PID</th><th>User</th><th>Process</th><th>Bind</th><th>Risk</th><th>ATT&CK</th><th>Anom</th></tr></thead>
<tbody id="pb">${rows}</tbody></table>
</div>
${anomaly_section}
</div>

<div class="ft">Port Watcher v${VERSION} - <a href="/api/scan">JSON API</a> | Built by RedVortex</div>

<script>
(function p(){fetch('/api/scan').then(r=>r.json()).then(d=>{if(!d||!d.ports)return;const s=d.stats||{};Object.keys(s).forEach(k=>{const id={cr:'sc',hi:'sh',me:'sm',lo:'sl',to:'stt'}[k[0]+k[1]]||k[0]+k[1];const e=document.getElementById(id);if(e)e.textContent=s[k]});document.getElementById('pc').textContent=s.total||'0';document.getElementById('st').textContent=d.timestamp||'?';const tb=document.getElementById('pb');if(!tb)return;tb.innerHTML='';d.ports.forEach(p=>{const r=p.risk;const rc=r==='CRITICAL'?'#EF4444':r==='HIGH'?'#F59E0B':r==='MEDIUM'?'#EAB308':r==='LOW'?'#10B981':'#64748B';const mb=p.mitre_attack_id?'<span class="bm">'+p.mitre_attack_id+'</span>':'';let ab='';if(p.anomaly_score){const ac=p.anomaly_score>=50?'aa':p.anomaly_score>=30?'aw':'ai';ab='<span class="'+ac+'">'+p.anomaly_score+'</span>'}const tr=document.createElement('tr');tr.innerHTML='<td class="cp">'+p.port+'</td><td>'+(p.pid||'')+'</td><td class="cu">'+p.user+'</td><td>'+p.process+'</td><td>'+p.bind_address+'</td><td style="color:'+rc+';font-weight:600">'+r+'</td><td>'+mb+'</td><td>'+ab+'</td>';tb.appendChild(tr)})}).catch(()=>{}).finally(()=>setTimeout(p,5000))})();
</script>
</body>
</html>
HTML
}

# ─── JSON API Generator ───

render_json_api() {
  local data="$1"
  local total=0 critical=0 high=0 medium=0 low=0 unknown=0
  local ports_json="" first=true
  local ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  local hostname="${HOSTNAME:-$(hostname 2>/dev/null || echo 'unknown')}"

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    local risk_info score risk bind_type
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
    score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
    risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"
    total=$((total + 1))
    case "$risk" in
      CRITICAL) critical=$((critical+1)) ;;
      HIGH) high=$((high+1)) ;;
      MEDIUM) medium=$((medium+1)) ;;
      LOW) low=$((low+1)) ;;
      *) unknown=$((unknown+1)) ;;
    esac

    local mid="null" mn="null" mt="null"
    if declare -f mitre_lookup &>/dev/null; then
      local mr
      mr="$(mitre_lookup "$process" "$port" "$bind_type" "$risk" 2>/dev/null || true)"
      if [[ -n "$mr" ]]; then
        mid="\"$(echo "$mr" | cut -d: -f1)\""
        mn="\"$(echo "$mr" | cut -d: -f2)\""
        mt="\"$(echo "$mr" | cut -d: -f3)\""
      fi
    fi

    local anom_score=0 anom_type="null"
    if declare -f run_anomaly_detection &>/dev/null; then
      local ae="${ANOMALY_DETECTIONS[$port]:-}"
      if [[ -n "$ae" ]]; then
        anom_score="$(echo "$ae" | cut -d'|' -f1)"
        anom_type="\"$(echo "$ae" | cut -d'|' -f2)\""
      fi
    fi

    local ue="${user//\"/\\\"}"
    local pe="${process//\"/\\\"}"
    local be="${bind_addr//\"/\\\"}"

    $first || ports_json+=","
    first=false
    ports_json+="{\"port\":$port,\"pid\":${pid:-0},\"user\":\"$ue\",\"process\":\"$pe\",\"protocol\":\"${proto:-tcp}\",\"bind_address\":\"$be\",\"bind_type\":\"$bind_type\",\"risk\":\"$risk\",\"score\":$score,\"mitre_attack_id\":$mid,\"mitre_technique\":$mn,\"mitre_tactic\":$mt,\"anomaly_score\":$anom_score,\"anomaly_type\":$anom_type}"
  done <<< "$data"

  echo "{\"timestamp\":\"$ts\",\"hostname\":\"$hostname\",\"tool\":\"port-watcher-v${VERSION}\",\"stats\":{\"total\":$total,\"critical\":$critical,\"high\":$high,\"medium\":$medium,\"low\":$low,\"unknown\":$unknown},\"ports\":[${ports_json}]}"
}

# ─── HTTP Server ───

start_dashboard_server() {
  local pid_file="$HOME/.config/port-watcher/dashboard.pid"

  if [[ -f "$pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$pid_file" 2>/dev/null || echo "")"
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
      cecho "$C_BOLD_YELLOW" "Dashboard already running (PID ${existing_pid})"
      cecho "$C_DIM" "   http://${DASHBOARD_HOST}:${DASHBOARD_PORT}"
      cecho "$C_DIM" "   Stop: kill ${existing_pid}"
      return 0
    fi
  fi

  # Write the routing script
  write_server_script

  # Render initial state
  local initial_data
  initial_data="$(collect_ports 2>/dev/null || true)"
  render_dashboard_state "$initial_data"

  cecho "$C_BOLD_GREEN" "Dashboard: http://${DASHBOARD_HOST}:${DASHBOARD_PORT}"
  cecho "$C_DIM" "   API: http://${DASHBOARD_HOST}:${DASHBOARD_PORT}/api/scan"
  echo ""

  # Fork the server process (background)
  (
    echo "$$" > "$pid_file"
    trap 'rm -f "$pid_file"; exit' EXIT TERM INT

    if command -v socat &>/dev/null; then
      # socat: best - concurrent connections via fork
      socat TCP-LISTEN:"$DASHBOARD_PORT",bind="$DASHBOARD_HOST",reuseaddr,fork \
        SYSTEM:"$DASH_SERVER_SCRIPT" 2>/dev/null &
    elif command -v ncat &>/dev/null; then
      # ncat: good - handles sequential connections
      while true; do
        ncat -l -p "$DASHBOARD_PORT" -s "$DASHBOARD_HOST" \
          --sh-exec "$DASH_SERVER_SCRIPT" 2>/dev/null || break
      done &
    elif command -v nc &>/dev/null; then
      # nc: basic - one connection at a time via the routing script
      while true; do
        "$DASH_SERVER_SCRIPT" | nc -l -p "$DASHBOARD_PORT" -s "$DASHBOARD_HOST" -q 1 2>/dev/null || break
      done &
    fi

    # Render loop: re-collect data on a timer
    while true; do
      sleep "$DASHBOARD_REFRESH_SECONDS"
      local fresh_data
      fresh_data="$(collect_ports 2>/dev/null || true)"
      [[ -n "$fresh_data" ]] && render_dashboard_state "$fresh_data"
    done
  ) &

  local bg_pid=$!
  disown "$bg_pid" 2>/dev/null || true

  cecho "$C_DIM" "   PID: ${bg_pid} | Refresh: ${DASHBOARD_REFRESH_SECONDS}s"
  echo ""

  # Open browser if possible
  if command -v xdg-open &>/dev/null; then
    (sleep 1 && xdg-open "http://${DASHBOARD_HOST}:${DASHBOARD_PORT}" &>/dev/null) &
  fi
}

# ─── Cleanup ───
plugin_cleanup_web-dashboard() {
  local pid_file="$HOME/.config/port-watcher/dashboard.pid"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || echo "")"
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    rm -f "$pid_file" 2>/dev/null || true
  fi
  rm -f "$DASH_HTML_FILE" "$DASH_JSON_FILE" "$DASH_SERVER_SCRIPT" 2>/dev/null || true
}
