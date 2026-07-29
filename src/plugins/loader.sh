#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — Plugin Loader System
#  ═════════════════════════════════════════════════════════════════════════════
#  Enables drop-in plugin extensibility. Place .sh files in:
#    ~/.config/port-watcher/plugins/enabled/   → auto-loaded at startup
#    /etc/port-watcher/plugins/enabled/        → system-wide plugins
#    <repo>/src/plugins/enabled/               → bundled plugins
#    <repo>/src/plugins/available/             → sample/example plugins
#
#  Plugin Interface (hooks):
#    plugin_init_<name>()       — Called once at startup (setup)
#    plugin_collect_<name>()    — Called during data collection, echoes enriched data
#    plugin_analyze_<name>()    — Called during analysis, receives pipe-delimited data per port
#    plugin_render_table_<name>() — Extra table columns (echoes header|value|color)
#    plugin_render_json_<name>()  — Extra JSON fields (echoes "key": value)
#    plugin_cleanup_<name>()    — Called on exit
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Plugin Paths ───
PLUGIN_DIRS=(
  "$HOME/.config/port-watcher/plugins/enabled"
  "/etc/port-watcher/plugins/enabled"
  "$SCRIPT_DIR/plugins/enabled"
  "$SCRIPT_DIR/../config/plugins"
)

PLUGINS_LOADED=()
PLUGIN_COLLECT_HOOKS=()
PLUGIN_ANALYZE_HOOKS=()
PLUGIN_RENDER_TABLE_HOOKS=()
PLUGIN_RENDER_JSON_HOOKS=()

# ─── Plugin Loader ───

# Discover and load all enabled plugins
load_plugins() {
  local plugin_path=""

  for dir in "${PLUGIN_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
      for plugin in "$dir"/*.sh; do
        [[ -f "$plugin" ]] || continue

        # Get plugin name from filename (strip .sh, strip leading numbers)
        local plugin_name
        plugin_name="$(basename "$plugin" .sh)"
        plugin_name="$(echo "$plugin_name" | sed 's/^[0-9]*-//')"

        # Source the plugin
        if source "$plugin" 2>/dev/null; then
          PLUGINS_LOADED+=("$plugin_name")
          plugin_path="$plugin"

          # Register hooks if they exist
          if declare -f "plugin_init_${plugin_name}" &>/dev/null; then
            plugin_init_$plugin_name 2>/dev/null || true
          fi
          if declare -f "plugin_collect_${plugin_name}" &>/dev/null; then
            PLUGIN_COLLECT_HOOKS+=("plugin_collect_${plugin_name}")
          fi
          if declare -f "plugin_analyze_${plugin_name}" &>/dev/null; then
            PLUGIN_ANALYZE_HOOKS+=("plugin_analyze_${plugin_name}")
          fi
          if declare -f "plugin_render_table_${plugin_name}" &>/dev/null; then
            PLUGIN_RENDER_TABLE_HOOKS+=("plugin_render_table_${plugin_name}")
          fi
          if declare -f "plugin_render_json_${plugin_name}" &>/dev/null; then
            PLUGIN_RENDER_JSON_HOOKS+=("plugin_render_json_${plugin_name}")
          fi

          if $COLOR; then
            echo -e "${C_DIM}[plugin] Loaded: ${plugin_name}${C_RESET}" >&2
          else
            echo "[plugin] Loaded: ${plugin_name}" >&2
          fi
        else
          echo "[plugin] FAILED to load: $(basename "$plugin")" >&2
        fi
      done
    fi
  done

  # Report loaded plugins count
  if $COLOR; then
    echo -e "${C_DIM}[plugin] ${#PLUGINS_LOADED[@]} plugin(s) loaded${C_RESET}" >&2
  else
    echo "[plugin] ${#PLUGINS_LOADED[@]} plugin(s) loaded" >&2
  fi
}

# Run collect hooks — plugins can add enriched data lines
run_collect_hooks() {
  for hook in "${PLUGIN_COLLECT_HOOKS[@]}"; do
    $hook "$@"
  done
}

# Run analyze hooks for each port
run_analyze_hooks() {
  local port_data="$1"
  while IFS='|' read -r process pid user proto bind_addr port; do
    [[ -z "$port" ]] && continue
    for hook in "${PLUGIN_ANALYZE_HOOKS[@]}"; do
      $hook "$process" "$pid" "$user" "$proto" "$bind_addr" "$port"
    done
  done <<< "$port_data"
}

# Run render hooks for extra table columns — must echo: column_name|value|color_code
run_render_table_hooks() {
  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"
  local extra=""
  for hook in "${PLUGIN_RENDER_TABLE_HOOKS[@]}"; do
    local result="$($hook "$process" "$pid" "$user" "$proto" "$bind_addr" "$port" 2>/dev/null || true)"
    if [[ -n "$result" ]]; then
      extra+="$result|"
    fi
  done
  echo "$extra"
}

# Get extra table headers from render hooks
get_plugin_table_headers() {
  local headers=""
  for hook in "${PLUGIN_RENDER_TABLE_HOOKS[@]}"; do
    local result="$($hook "HEADER" 2>/dev/null || true)"
    if [[ -n "$result" ]]; then
      headers+="$result|"
    fi
  done
  echo "$headers"
}

# Run render JSON hooks — must echo: "key": "value"
run_render_json_hooks() {
  local process="$1" pid="$2" user="$3" proto="$4" bind_addr="$5" port="$6"
  local extra=""
  for hook in "${PLUGIN_RENDER_JSON_HOOKS[@]}"; do
    local result="$($hook "$process" "$pid" "$user" "$proto" "$bind_addr" "$port" 2>/dev/null || true)"
    if [[ -n "$result" ]]; then
      extra+=", $result"
    fi
  done
  echo "$extra"
}

# Run cleanup hooks on exit
run_cleanup_hooks() {
  for plugin in "${PLUGINS_LOADED[@]}"; do
    if declare -f "plugin_cleanup_${plugin}" &>/dev/null; then
      plugin_cleanup_$plugin 2>/dev/null || true
    fi
  done
}
