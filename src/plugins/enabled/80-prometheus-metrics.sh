#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Prometheus Metrics Exporter
#  ═════════════════════════════════════════════════════════════════════════════
#  Exposes scan data in Prometheus text format at /metrics endpoint.
#  Integrates with the Embedded Web Dashboard as an additional cached file.
#
#  Usage:
#    sudo port-watcher --dashboard
#    → GET http://127.0.0.1:9090/metrics  (Prometheus text format)
#
#  Metrics:
#    port_watcher_risk_score{port,process,user,risk,bind_address,bind_type}
#    port_watcher_anomaly_score{port,risk,anomaly_type}
#    port_watcher_ports_total{risk_level}
#    port_watcher_attack_surface_grade  (0=A..5=F)
#    port_watcher_attack_surface_score
#    port_watcher_last_scan_timestamp
#    port_watcher_scrape_duration_seconds
#
#  Prometheus config (scrape_configs):
#    - job_name: 'port-watcher'
#      static_configs:
#        - targets: ['localhost:9090']
#      metrics_path: '/metrics'
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Temp file (shared with dashboard) ───
# The dashboard plugin (70-web-dashboard.sh) defines DASH_METRICS_FILE.
# We use the same path so the /metrics endpoint serves our output.
# No plugin_init needed — the dashboard already handles the file path.

# ─── Plugin Analyze hook (called once per port) ───
# We don't need per-port processing; everything is done in render phase.

# ─── Render Prometheus Metrics ───
# Called during render_dashboard_state() to write the cached metrics file.
render_metrics() {
  local data="$1"
  local ts epoch
  [[ -z "$data" ]] && data="$(collect_ports 2>/dev/null || true)"
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)"
  epoch="$(date +%s 2>/dev/null)"
  local start_time="${epoch}"
  local hostname="${HOSTNAME:-$(hostname 2>/dev/null || echo 'unknown')}"

  # ── HELP & TYPE headers ──
  cat <<EOF
# HELP port_watcher_risk_score Dynamic risk score for each listening port (higher = more dangerous)
# TYPE port_watcher_risk_score gauge
# HELP port_watcher_anomaly_score Anomaly detection score for each port (0 = normal, >30 = warning, >50 = alert)
# TYPE port_watcher_anomaly_score gauge
# HELP port_watcher_ports_total Number of ports detected by risk level
# TYPE port_watcher_ports_total gauge
# HELP port_watcher_attack_surface_grade Overall attack surface grade (0=A, 1=B, 2=C, 3=D, 4=E, 5=F)
# TYPE port_watcher_attack_surface_grade gauge
# HELP port_watcher_attack_surface_score Raw attack surface score (higher = worse)
# TYPE port_watcher_attack_surface_score gauge
# HELP port_watcher_last_scan_timestamp Unix timestamp of the most recent scan
# TYPE port_watcher_last_scan_timestamp gauge
# HELP port_watcher_scrape_duration_seconds How long the metrics scrape took in seconds
# TYPE port_watcher_scrape_duration_seconds gauge
# HELP port_watcher_info Static metadata about this port-watcher instance
# TYPE port_watcher_info gauge
EOF

  # ── Instance info (always 1) ──
  printf 'port_watcher_info{version="%s",hostname="%s"} 1\n' \
    "${VERSION:-unknown}" "$hostname"

  # ── Per-port metrics ──
  local critical_count=0 high_count=0 medium_count=0 low_count=0 unknown_count=0

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue

    local risk_info score risk bind_type anom_score anom_type
    risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
    bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
    score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "0")"
    risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"

    # Sanitize label values (escape backslashes, quotes, newlines)
    local pe="${process//\\/\\\\}"; pe="${pe//\"/\\\"}"
    local ue="${user//\\/\\\\}"; ue="${ue//\"/\\\"}"
    local be="${bind_addr//\\/\\\\}"; be="${be//\"/\\\"}"
    local re="${bind_type//\\/\\\\}"; re="${re//\"/\\\"}"
    local rk="${risk//\\/\\\\}"; rk="${rk//\"/\\\"}"

    # Risk score gauge
    printf 'port_watcher_risk_score{port="%s",process="%s",user="%s",risk="%s",bind_address="%s",bind_type="%s"} %s\n' \
      "$port" "$pe" "$ue" "$rk" "$be" "$re" "$score"

    case "$risk" in
      CRITICAL) critical_count=$((critical_count + 1)) ;;
      HIGH)     high_count=$((high_count + 1)) ;;
      MEDIUM)   medium_count=$((medium_count + 1)) ;;
      LOW)      low_count=$((low_count + 1)) ;;
      *)        unknown_count=$((unknown_count + 1)) ;;
    esac

    # Anomaly score gauge (only if anomaly plugin loaded and data exists)
    anom_score=0
    anom_type=""
    if declare -f run_anomaly_detection &>/dev/null; then
      local ae="${ANOMALY_DETECTIONS[$port]:-}"
      if [[ -n "$ae" ]]; then
        anom_score="$(echo "$ae" | cut -d'|' -f1)"
        anom_type="$(echo "$ae" | cut -d'|' -f2)"
        local at="${anom_type//\\/\\\\}"; at="${at//\"/\\\"}"
        printf 'port_watcher_anomaly_score{port="%s",risk="%s",anomaly_type="%s"} %s\n' \
          "$port" "$rk" "$at" "$anom_score"
      fi
    fi
  done <<< "$data"

  # ── Port counts by risk level ──
  printf 'port_watcher_ports_total{risk_level="critical"} %d\n' "$critical_count"
  printf 'port_watcher_ports_total{risk_level="high"} %d\n' "$high_count"
  printf 'port_watcher_ports_total{risk_level="medium"} %d\n' "$medium_count"
  printf 'port_watcher_ports_total{risk_level="low"} %d\n' "$low_count"
  printf 'port_watcher_ports_total{risk_level="unknown"} %d\n' "$unknown_count"
  printf 'port_watcher_ports_total{risk_level="total"} %d\n' \
    $((critical_count + high_count + medium_count + low_count + unknown_count))

  # ── Attack Surface Score (from plugin 40) ──
  if declare -f calculate_attack_surface &>/dev/null; then
    local as_score as_grade_num
    # Recalculate with current data to ensure fresh values
    calculate_attack_surface "$data" 2>/dev/null || true
    # Get the globally stored grade
    as_grade_num=0
    case "${ATTACK_SURFACE_GRADE:-F}" in
      A) as_grade_num=0 ;; B) as_grade_num=1 ;; C) as_grade_num=2 ;;
      D) as_grade_num=3 ;; E) as_grade_num=4 ;; F) as_grade_num=5 ;;
    esac
    printf 'port_watcher_attack_surface_grade{grade="%s"} %d\n' \
      "${ATTACK_SURFACE_GRADE:-F}" "$as_grade_num"
    printf 'port_watcher_attack_surface_score %s\n' \
      "${ATTACK_SURFACE_SCORE:-0}"
  fi

  # ── Timestamp & duration ──
  printf 'port_watcher_last_scan_timestamp %s\n' "$epoch"
  local end_time
  end_time="$(date +%s 2>/dev/null)"
  local duration=$((end_time - start_time))
  [[ $duration -lt 1 ]] && duration=1
  printf 'port_watcher_scrape_duration_seconds %d\n' "$duration"
}

# ─── Cleanup ───
plugin_cleanup_prometheus-metrics() {
  rm -f "${DASH_METRICS_FILE:-/tmp/port-watcher-metrics.prom}" 2>/dev/null || true
}
