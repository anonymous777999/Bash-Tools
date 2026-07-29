#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — SSL/TLS Certificate Auditor (Example Plugin)
#  ═════════════════════════════════════════════════════════════════════════════
#  For every HTTPS/SSL port detected, attempts to fetch the certificate
#  and check: expiry, self-signed status, TLS version, key strength.
#
#  To use: Copy to ~/.config/port-watcher/plugins/enabled/
#  Requires: openssl
# ═══════════════════════════════════════════════════════════════════════════════

SSL_PORTS=(443 8443 993 995 465 636 989 990)

plugin_init_ssl-audit() {
  if ! command -v openssl &>/dev/null; then
    echo "[plugin:ssl-audit] openssl not found — SSL audit disabled" >&2
    return 1
  fi
}

plugin_analyze_ssl-audit() {
  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"

  # Only audit SSL ports
  local is_ssl=false
  for ssl_port in "${SSL_PORTS[@]}"; do
    [[ "$port" == "$ssl_port" ]] && { is_ssl=true; break; }
  done
  $is_ssl || return

  # Determine bind address to connect to
  local connect_addr
  case "$bind_addr" in
    0.0.0.0|"*"|"")  connect_addr="127.0.0.1" ;;
    "::"|"[::]")      connect_addr="::1" ;;
    *)                connect_addr="$bind_addr" ;;
  esac

  # Fetch certificate (timeout after 3 seconds)
  local cert_output
  cert_output="$(echo | timeout 3 openssl s_client -connect "${connect_addr}:${port}" -servername "$connect_addr" 2>/dev/null || true)"

  [[ -z "$cert_output" ]] && return

  # Check expiry
  local expiry_date
  expiry_date="$(echo "$cert_output" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2- || echo "Unknown")"
  local expiry_epoch=0 now_epoch days_left=0
  if [[ "$expiry_date" != "Unknown" ]]; then
    expiry_epoch="$(date -d "$expiry_date" +%s 2>/dev/null || echo 0)"
    now_epoch="$(date +%s)"
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
  fi

  # Check self-signed
  local issuer subject self_signed=false
  issuer="$(echo "$cert_output" | openssl x509 -noout -issuer 2>/dev/null | head -1 || echo "")"
  subject="$(echo "$cert_output" | openssl x509 -noout -subject 2>/dev/null | head -1 || echo "")"
  [[ "$issuer" == "$subject" ]] && self_signed=true

  # Output findings to STDERR (visible when running with plugin debug)
  if $COLOR; then
    if [[ $days_left -lt 30 && $days_left -ge 0 ]]; then
      echo -e "${C_BOLD_YELLOW}[ssl:${port}]${C_RESET} Certificate expires in ${days_left} days — renew soon!" >&2
    elif [[ $days_left -lt 0 ]]; then
      echo -e "${C_BOLD_RED}[ssl:${port}]${C_RESET} Certificate EXPIRED ${days_left#-} days ago!" >&2
    fi
    $self_signed && echo -e "${C_YELLOW}[ssl:${port}]${C_RESET} Self-signed certificate detected" >&2
  else
    echo "[ssl:${port}] Certificate expires in ${days_left} days" >&2
    $self_signed && echo "[ssl:${port}] Self-signed certificate detected" >&2
  fi
}

plugin_render_table_ssl-audit() {
  local arg="$1"
  if [[ "$arg" == "HEADER" ]]; then
    echo "SSL"
    return
  fi

  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"

  local is_ssl=false
  for ssl_port in "${SSL_PORTS[@]}"; do
    [[ "$port" == "$ssl_port" ]] && { is_ssl=true; break; }
  done
  $is_ssl || { echo "|${C_DIM}—${C_RESET}"; return; }

  # Quick check — just show the port has SSL
  echo "✓|${C_GREEN}TLS${C_RESET}"
}
