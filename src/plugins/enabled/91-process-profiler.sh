#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Process Behavior Profiler
#  ═════════════════════════════════════════════════════════════════════════════
#  Profiles running processes associated with listening ports, tracking:
#
#    • CPU usage (%)       — Detect compute spikes (mining, DoS prep)
#    • Memory usage (%)    — Detect memory spraying, heap spraying
#    • File Descriptors    — Detect FD leaks, unusual open files
#    • Thread count        — Detect thread injection, fork bombs
#    • Binary hash (SHA256) — Detect binary replacement (backdoored sshd)
#    • Parent PID          — Detect suspicious parent-child (e.g., browser spawned a listener)
#    • State               — Detect zombie/defunct processes
#    • Uptime              — Detect short-lived/recently started processes
#
#  Detection Rules:
#    • Binary hash changed since last profile snapshot → 🔴 BINARY REPLACEMENT
#    • CPU > 80%                                        → 🟡 CPU SPIKE
#    • Memory > 50%                                     → 🟡 MEMORY SPIKE
#    • Zombie/defunct state                              → 🔴 ZOMBIE PROCESS
#    • Parent PID < 5 (init/systemd)                     → 🟢 Normal (direct daemon)
#    • Parent PID is browser, office, or media player     → 🟠 SUSPICIOUS PARENT
#    • Process running < 60 seconds                      → 🔵 RECENTLY STARTED
#    • Process has no parent (orphaned, pid=1 not init)   → 🔴 ORPHANED
#    • FD count > 500                                    → 🟡 FD LEAK
#    • Thread count > 100                                → 🟡 HIGH THREAD COUNT
#
#  Profile storage:
#    ~/.config/port-watcher/process-profiles.json  — SHA256 hashes per binary path
#
#  Usage:
#    port-watcher --profile              → Show process behavior report
#    port-watcher --profile-snapshot     → Record current binary hashes as baseline
#    port-watcher --anomalies --profile  → Combined anomaly + behavior report
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Config ───
PROFILE_DIR="$HOME/.config/port-watcher"
PROFILE_FILE="${PROFILE_DIR}/process-profiles.json"
PROFILE_CPU_THRESHOLD="${PROFILE_CPU_THRESHOLD:-80}"       # %
PROFILE_MEM_THRESHOLD="${PROFILE_MEM_THRESHOLD:-50}"       # %
PROFILE_FD_THRESHOLD="${PROFILE_FD_THRESHOLD:-500}"        # File descriptors
PROFILE_THREAD_THRESHOLD="${PROFILE_THREAD_THRESHOLD:-100}" # Threads
PROFILE_AGE_THRESHOLD="${PROFILE_AGE_THRESHOLD:-60}"        # Seconds (recently started)

# ─── CLI Flags ───
SHOW_PROFILE=false
PROFILE_SNAPSHOT=false

# ─── Runtime Data ───
declare -A PROCESS_PROFILES         # binary_path → sha256_hash (from profile file)
declare -A PROCESS_BEHAVIOR         # pid → "metric|value|flag|detail"
PROCESS_BEHAVIOR_REPORT=""
PROCESS_BEHAVIOR_COUNT=0
PROCESS_BEHAVIOR_ALERTS=0

# ─── Plugin Init ───
plugin_init_process-profiler() {
  mkdir -p "$PROFILE_DIR" 2>/dev/null || true
  load_process_profiles
}

# ─── Profile Management ───

# Load the saved binary hash profiles
load_process_profiles() {
  PROCESS_PROFILES=()
  if [[ -f "$PROFILE_FILE" ]]; then
    # Parse JSON: {"binary_path": "sha256_hash", ...}
    local in_json=false key="" value=""
    while IFS= read -r line; do
      # Extract "key": "value" pairs
      if [[ "$line" =~ \"([^\"]+)\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
        PROCESS_PROFILES["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
      fi
    done < "$PROFILE_FILE"
  fi
}

# Save binary hashes to profile file
save_process_profiles() {
  mkdir -p "$PROFILE_DIR" 2>/dev/null || true
  echo "{" > "$PROFILE_FILE"
  local first=true
  for key in "${!PROCESS_PROFILES[@]}"; do
    $first || echo "," >> "$PROFILE_FILE"
    first=false
    printf '  "%s": "%s"' "$key" "${PROCESS_PROFILES[$key]}" >> "$PROFILE_FILE"
  done
  echo "" >> "$PROFILE_FILE"
  echo "}" >> "$PROFILE_FILE"
}

# Take a snapshot: record current binary hashes for all running processes
take_process_snapshot() {
  local port_data="$1"
  local count=0

  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$pid" || "$pid" -le 0 ]] && continue
    local binary_path
    binary_path="$(get_process_binary "$pid")"
    [[ -z "$binary_path" || ! -f "$binary_path" ]] && continue
    local hash
    hash="$(sha256sum "$binary_path" 2>/dev/null | cut -d' ' -f1 || true)"
    [[ -z "$hash" ]] && continue
    PROCESS_PROFILES["$binary_path"]="$hash"
    count=$((count + 1))
  done <<< "$port_data"

  save_process_profiles

  cecho "$C_GREEN" "  ✓ Snapshot saved: $count binary hashes recorded"
  cecho "$C_DIM" "    Profile: $PROFILE_FILE"
}

# ─── Process Data Collection ───

# Get the binary path for a PID
get_process_binary() {
  local pid="$1"
  if [[ -f "/proc/${pid}/exe" ]]; then
    readlink "/proc/${pid}/exe" 2>/dev/null || echo ""
  elif command -v lsof &>/dev/null; then
    lsof -p "$pid" -Fn 2>/dev/null | grep '^n/' | head -1 | sed 's/^n//' || echo ""
  else
    echo ""
  fi
}

# Get SHA256 hash of a binary
get_binary_hash() {
  local binary="$1"
  sha256sum "$binary" 2>/dev/null | cut -d' ' -f1 || echo ""
}

# Collect process metrics for a given PID
collect_process_metrics() {
  local pid="$1"
  local metrics=""

  [[ -z "$pid" || "$pid" -le 0 ]] && echo "" && return

  local proc_dir="/proc/${pid}"
  [[ ! -d "$proc_dir" ]] && echo "" && return

  # CPU usage (from /proc/pid/stat — utime+stime over HZ)
  local cpu=0
  if [[ -f "${proc_dir}/stat" ]]; then
    local stat_data
    stat_data="$(cat "${proc_dir}/stat" 2>/dev/null || true)"
    if [[ -n "$stat_data" ]]; then
      # Parse: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime ...
      # Cut past the closing paren of comm field
      local comm_end="${stat_data#*) }"
      local fields
      IFS=' ' read -r -a fields <<< "$comm_end"
      local utime="${fields[11]:-0}"
      local stime="${fields[12]:-0}"
      local total_ticks=$((utime + stime))
      local uptime
      uptime="$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 1)"
      local start_ticks="${fields[19]:-0}"
      local clk_tck
  clk_tck="$(getconf CLK_TCK 2>/dev/null || echo 100)"
      local elapsed=$((uptime - (start_ticks / clk_tck)))
      [[ $elapsed -lt 1 ]] && elapsed=1
      cpu=$(( (total_ticks * 100 / clk_tck) / elapsed ))
    fi
  fi

  # Memory usage (from /proc/pid/status or statm)
  local mem=0
  if [[ -f "${proc_dir}/status" ]]; then
    local vm_rss
    vm_rss="$(grep -i 'VmRSS' "${proc_dir}/status" 2>/dev/null | awk '{print $2}' || echo "0")"
    local total_mem_kb
    total_mem_kb="$(grep -i 'MemTotal' /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "1")"
    [[ $total_mem_kb -gt 0 ]] && mem=$(( (vm_rss * 100) / total_mem_kb ))
  fi

  # File descriptors
  local fd_count=0
  if [[ -d "${proc_dir}/fd" ]]; then
    fd_count="$(ls -1 "${proc_dir}/fd" 2>/dev/null | wc -l || echo 0)"
  fi

  # Thread count
  local thread_count=0
  if [[ -f "${proc_dir}/status" ]]; then
    thread_count="$(grep -i 'Threads' "${proc_dir}/status" 2>/dev/null | awk '{print $2}' || echo 0)"
  fi

  # State
  local state=""
  if [[ -f "${proc_dir}/stat" ]]; then
    state="$(awk '{print $3}' "${proc_dir}/stat" 2>/dev/null || true)"
  fi

  # Parent PID
  local ppid=0
  if [[ -f "${proc_dir}/stat" ]]; then
    ppid="$(awk '{print $4}' "${proc_dir}/stat" 2>/dev/null || echo 0)"
  fi

  # Process start time (uptime seconds when process started)
  local start_time=0
  if [[ -f "${proc_dir}/stat" ]]; then
    local s_comm_end="${stat_data#*) }"
    local s_fields
    IFS=' ' read -r -a s_fields <<< "$s_comm_end"
    start_time="${s_fields[19]:-0}"
  fi

  # Format: cpu|mem|fd_count|threads|state|ppid|start_time
  echo "${cpu}|${mem}|${fd_count}|${thread_count}|${state}|${ppid}|${start_time}"
}

# ─── Behavior Analysis ───

# Analyze a single process for behavioral issues
analyze_process_behavior() {
  local process="$1" pid="$2" user="$3" port="$4"

  [[ -z "$pid" || "$pid" -le 0 ]] && return

  local binary_path
  binary_path="$(get_process_binary "$pid")"

  local metrics
  metrics="$(collect_process_metrics "$pid")"
  [[ -z "$metrics" ]] && return

  local cpu mem fd_count threads state ppid start_time
  cpu="$(echo "$metrics" | cut -d'|' -f1)"
  mem="$(echo "$metrics" | cut -d'|' -f2)"
  fd_count="$(echo "$metrics" | cut -d'|' -f3)"
  threads="$(echo "$metrics" | cut -d'|' -f4)"
  state="$(echo "$metrics" | cut -d'|' -f5)"
  ppid="$(echo "$metrics" | cut -d'|' -f6)"
  start_time="$(echo "$metrics" | cut -d'|' -f7)"

  local findings=()
  local max_severity="INFO"

  # ── 1. Binary hash change detection ──
  if [[ -n "$binary_path" && -f "$binary_path" ]]; then
    local current_hash
    current_hash="$(get_binary_hash "$binary_path")"
    local saved_hash="${PROCESS_PROFILES[$binary_path]:-}"
    if [[ -n "$saved_hash" && "$current_hash" != "$saved_hash" ]]; then
      findings+=("🔴 BINARY REPLACEMENT: ${binary_path} hash changed!")
      max_severity="CRITICAL"
    fi
  fi

  # ── 2. Zombie/defunct process ──
  if [[ "$state" == "Z" ]]; then
    findings+=("🔴 ZOMBIE: Process ${pid} (${process}) is defunct/zombie")
    max_severity="CRITICAL"
  fi

  # ── 3. CPU spike ──
  if [[ $cpu -ge $PROFILE_CPU_THRESHOLD ]]; then
    findings+=("🟡 CPU SPIKE: ${cpu}% CPU usage")
    [[ "$max_severity" != "CRITICAL" ]] && max_severity="HIGH"
  fi

  # ── 4. Memory spike ──
  if [[ $mem -ge $PROFILE_MEM_THRESHOLD ]]; then
    findings+=("🟡 MEMORY SPIKE: ${mem}% memory usage")
    [[ "$max_severity" != "CRITICAL" ]] && max_severity="HIGH"
  fi

  # ── 5. FD leak ──
  if [[ $fd_count -ge $PROFILE_FD_THRESHOLD ]]; then
    findings+=("🟡 FD LEAK: ${fd_count} open file descriptors")
    [[ "$max_severity" == "INFO" ]] && max_severity="MEDIUM"
  fi

  # ── 6. High thread count ──
  if [[ $threads -ge $PROFILE_THREAD_THRESHOLD ]]; then
    findings+=("🟡 THREAD SPIKE: ${threads} threads")
    [[ "$max_severity" == "INFO" ]] && max_severity="MEDIUM"
  fi

  # ── 7. Suspicious parent process ──
  if [[ $ppid -gt 1 ]]; then
    local parent_name=""
    if [[ -f "/proc/${ppid}/comm" ]]; then
      parent_name="$(cat "/proc/${ppid}/comm" 2>/dev/null || true)"
    fi
    # Check if parent is a suspicious category
    if [[ -n "$parent_name" ]]; then
      local suspicious_parents="chrome|firefox|brave|edge|safari|opera|thunderbird|outlook|teams|slack|discord|zoom|vlc|spotify|php"
      if echo "$parent_name" | grep -qiE "^(${suspicious_parents})$" 2>/dev/null; then
        findings+=("🟠 SUSPICIOUS PARENT: ${process} (PID ${pid}) spawned by ${parent_name} (PID ${ppid})")
        [[ "$max_severity" != "CRITICAL" && "$max_severity" != "HIGH" ]] && max_severity="MEDIUM"
      fi
    fi
  fi

  # ── 8. Recently started process ──
  if [[ $start_time -gt 0 ]]; then
    local uptime
    uptime="$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)"
    local clk_tck=100
    local proc_age=$((uptime - (start_time / clk_tck)))
    if [[ $proc_age -lt $PROFILE_AGE_THRESHOLD ]]; then
      findings+=("🔵 RECENTLY STARTED: ${process} started ${proc_age}s ago")
      [[ "$max_severity" == "INFO" ]] && max_severity="LOW"
    fi
  fi

  # Store findings
  if [[ ${#findings[@]} -gt 0 ]]; then
    local finding_str
    finding_str="$(
      IFS='; '
      echo "${findings[*]}"
    )"
    PROCESS_BEHAVIOR["$pid"]="${max_severity}|${finding_str}|${cpu}|${mem}|${fd_count}|${threads}|${binary_path:-unknown}"
    PROCESS_BEHAVIOR_COUNT=$((PROCESS_BEHAVIOR_COUNT + 1))
    if [[ "$max_severity" == "CRITICAL" || "$max_severity" == "HIGH" ]]; then
      PROCESS_BEHAVIOR_ALERTS=$((PROCESS_BEHAVIOR_ALERTS + 1))
    fi
  fi
}

# ─── Main Profiler Runner ───

run_process_profiler() {
  local port_data="$1"

  # Reset state
  PROCESS_BEHAVIOR=()
  PROCESS_BEHAVIOR_COUNT=0
  PROCESS_BEHAVIOR_ALERTS=0

  # If snapshot mode, just record and exit
  if $PROFILE_SNAPSHOT; then
    take_process_snapshot "$port_data"
    return
  fi

  # Load saved profiles if not already loaded
  load_process_profiles

  # Analyze each process
  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$pid" || "$pid" -le 0 ]] && continue
    analyze_process_behavior "$process" "$pid" "$user" "$port"
  done <<< "$port_data"

  # Save updated hashes
  save_process_profiles
}

# ─── Report Generation ───

show_process_profile_report() {
  echo ""
  if [[ $PROCESS_BEHAVIOR_ALERTS -gt 0 ]]; then
    cecho "$C_BOLD_RED" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_BOLD_RED" "║  🧬 PROCESS BEHAVIOR ANALYSIS — ${PROCESS_BEHAVIOR_ALERTS} alert(s)              ║"
    cecho "$C_BOLD_RED" "╚═══════════════════════════════════════════════════════════════╝"
  elif [[ $PROCESS_BEHAVIOR_COUNT -gt 0 ]]; then
    cecho "$C_GREEN" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_GREEN" "║  🧬 PROCESS BEHAVIOR ANALYSIS — ${PROCESS_BEHAVIOR_COUNT} finding(s)             ║"
    cecho "$C_GREEN" "╚═══════════════════════════════════════════════════════════════╝"
  else
    cecho "$C_DIM" "╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_DIM" "║  🧬 Process Behavior Analysis — No issues found             ║"
    cecho "$C_DIM" "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    return
  fi
  echo ""

  if [[ ${#PROCESS_BEHAVIOR[@]} -eq 0 ]]; then
    cecho "$C_GREEN" "  ✓ All processes appear normal."
    echo ""
    return
  fi

  for pid in "${!PROCESS_BEHAVIOR[@]}"; do
    local entry="${PROCESS_BEHAVIOR[$pid]}"
    local severity finding cpu mem fd threads binary
    severity="$(echo "$entry" | cut -d'|' -f1)"
    finding="$(echo "$entry" | cut -d'|' -f2)"
    cpu="$(echo "$entry" | cut -d'|' -f3)"
    mem="$(echo "$entry" | cut -d'|' -f4)"
    fd="$(echo "$entry" | cut -d'|' -f5)"
    threads="$(echo "$entry" | cut -d'|' -f6)"
    binary="$(echo "$entry" | cut -d'|' -f7)"

    local color=""
    case "$severity" in
      CRITICAL) color="$C_BOLD_RED" ;;
      HIGH)     color="$C_BOLD_RED" ;;
      MEDIUM)   color="$C_BOLD_YELLOW" ;;
      LOW)      color="$C_YELLOW" ;;
      INFO)     color="$C_DIM" ;;
    esac

    echo "  ${color}▶ PID ${pid} (${binary##*/})${C_RESET}"
    echo "    ┌─ Metrics: CPU ${cpu}% | MEM ${mem}% | FD ${fd} | Thr ${threads}"

    # Print each finding
    IFS=';' read -ra findings <<< "$finding"
    for f in "${findings[@]}"; do
      f="$(echo "$f" | xargs)"
      echo "    ├─ ${color}${f}${C_RESET}"
    done
    echo "    └─ Severity: ${color}${severity}${C_RESET}"
    echo ""
  done

  # Summary
  if [[ $PROCESS_BEHAVIOR_ALERTS -gt 0 ]]; then
    cecho "$C_BOLD_RED" "  ⚠️  ${PROCESS_BEHAVIOR_ALERTS} process(es) require immediate investigation."
  fi
  echo ""
}

# ─── Plugin Hooks ───

plugin_cleanup_process-profiler() {
  : # Profiles are saved immediately during run
}
