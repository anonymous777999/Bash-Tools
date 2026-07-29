#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Port Watcher v3 — AI Analysis Engine
#  ═════════════════════════════════════════════════════════════════════════════
#  Pipes scan results through LLM APIs for natural-language security briefings,
#  remediation advice, risk explanations, and attack narrative generation.
#
#  Supported providers (all OpenAI-compatible unless noted):
#    • openai     — GPT-4o / GPT-4o-mini          (needs API key with balance)
#    • openrouter — Llama 3, Mistral, DeepSeek etc  (free + paid models)
#    • nvidia     — Llama 3.1 70B, Nemotron etc     (free rate-limited, 40 RPM)
#    • groq       — Llama 3, Mixtral, Gemma         (free tier, TPM-limited)
#    • gemini     — Gemini 2.0 Flash / Pro          (different API format)
#
#  Automatic fallback chain: groq → openrouter → nvidia → gemini → openai
#  If one provider fails, the next available one is tried automatically.
#
#  Config in ports.conf:
#    AI_ANALYSIS_ENABLED=true
#    AI_PROVIDER=openrouter
#    AI_MODEL=auto                    # auto = provider default
#    AI_TEMPERATURE=0.3
#    AI_MAX_TOKENS=2048
#    OPENAI_API_KEY=sk-...            # For OpenAI provider
#    OPENROUTER_API_KEY=sk-or-...     # For OpenRouter provider
#    NVIDIA_API_KEY=nvapi-...         # For NVIDIA NIM provider
#    GROQ_API_KEY=gsk_...             # For Groq provider
#    GEMINI_API_KEY=AIza...           # For Google Gemini provider
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Config (overridable via ports.conf) ───
AI_ANALYSIS_ENABLED="${AI_ANALYSIS_ENABLED:-true}"
AI_PROVIDER="${AI_PROVIDER:-openrouter}"
AI_MODEL="${AI_MODEL:-auto}"
AI_TEMPERATURE="${AI_TEMPERATURE:-0.3}"
AI_MAX_TOKENS="${AI_MAX_TOKENS:-2048}"
AI_CACHE_TTL="${AI_CACHE_TTL:-300}"  # seconds before re-analysis
AI_ANALYSIS_MODE="${AI_ANALYSIS_MODE:-briefing}"  # briefing|remediation|attack|full|auto-fix

# ─── Auto-Fix Config ───
AI_FIX_ENABLED="${AI_FIX_ENABLED:-false}"
AI_FIX_LEVEL="${AI_FIX_LEVEL:-CRITICAL}"  # CRITICAL|HIGH|ALL — minimum risk level to auto-fix
AI_FIX_LOG_DIR="$HOME/.config/port-watcher/ai-fix-logs"
AI_FIX_CONFIRM="${AI_FIX_CONFIRM:-prompt}"  # prompt|yes|dry-run
AI_FIX_ACTIONS_TAKEN=0
AI_FIX_ACTIONS_FAILED=0
AI_FIX_UNDO_FILE="/tmp/port-watcher-ai-undo.txt"

# API Keys (loaded from config or env)
OPENAI_API_KEY="${OPENAI_API_KEY:-}"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
NVIDIA_API_KEY="${NVIDIA_API_KEY:-}"
GROQ_API_KEY="${GROQ_API_KEY:-}"
GEMINI_API_KEY="${GEMINI_API_KEY:-}"

# ─── Provider Endpoints ───
declare -A AI_ENDPOINTS=(
  ["openai"]="https://api.openai.com/v1/chat/completions"
  ["openrouter"]="https://openrouter.ai/api/v1/chat/completions"
  ["nvidia"]="https://integrate.api.nvidia.com/v1/chat/completions"
  ["groq"]="https://api.groq.com/openai/v1/chat/completions"
)

# Gemini uses a different API format
GEMINI_ENDPOINT="https://generativelanguage.googleapis.com/v1beta/models"

# ─── Provider Default Models ───
declare -A AI_DEFAULT_MODELS=(
  ["openai"]="gpt-4o-mini"
  ["openrouter"]="meta-llama/llama-3.1-8b-instruct"
  ["nvidia"]="meta/llama-3.1-70b-instruct"
  ["groq"]="llama-3.3-70b-versatile"
  ["gemini"]="gemini-2.0-flash"
)

# ─── Provider API Key Env Vars ───
declare -A AI_API_KEY_VARS=(
  ["openai"]="OPENAI_API_KEY"
  ["openrouter"]="OPENROUTER_API_KEY"
  ["nvidia"]="NVIDIA_API_KEY"
  ["groq"]="GROQ_API_KEY"
  ["gemini"]="GEMINI_API_KEY"
)

# ─── State ───
AI_ANALYSIS_RESULT=""
AI_ANALYSIS_TIMESTAMP=0
AI_LAST_HASH=""
AI_CACHE_FILE="/tmp/port-watcher-ai-cache.txt"
_PROVIDER_RESPONSE=""
_PROVIDER_ERROR=""

# ─── Fallback Chain (priority order: cheapest/most generous free tier first) ───
AI_FALLBACK_CHAIN=("groq" "openrouter" "nvidia" "gemini" "openai")


# ═══════════════════════════════════════════════════════════════════════════════
#  PROVIDER-SPECIFIC HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

# Get the API key for the configured provider
_get_api_key() {
  local provider="${1:-$AI_PROVIDER}"
  local var_name="${AI_API_KEY_VARS[$provider]:-}"
  [[ -z "$var_name" ]] && { echo ""; return 1; }
  echo "${!var_name:-}"
}

# Get the endpoint URL for the configured provider
_get_endpoint() {
  local provider="${1:-$AI_PROVIDER}"
  if [[ "$provider" == "gemini" ]]; then
    local model="${AI_MODEL:-${AI_DEFAULT_MODELS[$provider]}}"
    echo "${GEMINI_ENDPOINT}/${model}:generateContent?key=$(_get_api_key "$provider")"
  else
    echo "${AI_ENDPOINTS[$provider]:-}"
  fi
}

# Get the model name (user-configured or provider default)
_get_model() {
  local provider="${1:-$AI_PROVIDER}"
  if [[ "$AI_MODEL" == "auto" ]]; then
    echo "${AI_DEFAULT_MODELS[$provider]:-unknown}"
  else
    echo "$AI_MODEL"
  fi
}

# Check if a provider is available (has API key)
_is_provider_available() {
  local provider="${1:-$AI_PROVIDER}"
  local key
  key="$(_get_api_key "$provider")"
  [[ -n "$key" ]]
}

# Build the fallback chain — providers that have API keys, in priority order
_build_fallback_chain() {
  local chain=()
  for p in "${AI_FALLBACK_CHAIN[@]}"; do
    if _is_provider_available "$p"; then
      chain+=("$p")
    fi
  done
  echo "${chain[@]}"
}


# ═══════════════════════════════════════════════════════════════════════════════
#  CACHE LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

# Compute a hash of the port data for cache comparison
_compute_data_hash() {
  local data="$1"
  echo "$data" | sha256sum 2>/dev/null | cut -d' ' -f1 || echo "$data" | md5sum 2>/dev/null | cut -d' ' -f1 || echo "nocache"
}

# Check if we have a valid cached analysis
_check_cache() {
  local data_hash="$1"
  local now
  now="$(date +%s 2>/dev/null || echo 0)"

  # Cache disabled
  [[ $AI_CACHE_TTL -le 0 ]] && return 1

  # No cache file
  [[ ! -f "$AI_CACHE_FILE" ]] && return 1

  local cached_hash cached_time cached_result
  cached_hash="$(head -1 "$AI_CACHE_FILE" 2>/dev/null || echo "")"
  cached_time="$(sed -n '2p' "$AI_CACHE_FILE" 2>/dev/null || echo 0)"
  cached_result="$(tail -n +3 "$AI_CACHE_FILE" 2>/dev/null || echo "")"

  # Hash mismatch
  [[ "$cached_hash" != "$data_hash" ]] && return 1

  # Expired
  local age=$((now - cached_time))
  [[ $age -gt $AI_CACHE_TTL ]] && return 1

  # Valid cache hit
  AI_ANALYSIS_RESULT="$cached_result"
  AI_ANALYSIS_TIMESTAMP="$cached_time"
  return 0
}

# Save analysis result to cache
_save_cache() {
  local data_hash="$1" result="$2"
  local now
  now="$(date +%s 2>/dev/null || echo 0)"

  echo "$data_hash" > "$AI_CACHE_FILE"
  echo "$now" >> "$AI_CACHE_FILE"
  echo "$result" >> "$AI_CACHE_FILE"

  AI_ANALYSIS_RESULT="$result"
  AI_ANALYSIS_TIMESTAMP="$now"
  AI_LAST_HASH="$data_hash"
}


# ═══════════════════════════════════════════════════════════════════════════════
#  SYSTEM PROMPTS
# ═══════════════════════════════════════════════════════════════════════════════

# Build the system prompt for AI analysis
_build_system_prompt() {
  local mode="${1:-$AI_ANALYSIS_MODE}"

  case "$mode" in
    briefing)
      cat <<'SYSTEM'
You are Port Watcher AI — a cybersecurity AI assistant embedded in a port security scanning tool. Your job is to analyze open port data and produce a clear, actionable security briefing.

For each scan you receive, you must:
1. Summarize the overall security posture in 1-2 sentences
2. Identify the TOP 3 most dangerous findings and explain WHY they're dangerous
3. Note any unusual patterns (unknown processes, unexpected services, wide-open bindings)
4. Provide a risk summary table

Keep your response CONCISE. Use security terminology correctly. Be direct and honest — if the machine looks secure, say so. If it's a disaster, say that too.

Format your response in Markdown with clear sections.
SYSTEM
      ;;
    remediation)
      cat <<'SYSTEM'
You are Port Watcher AI — a cybersecurity AI assistant. Your job is to analyze open port data and provide SPECIFIC, ACTIONABLE remediation steps.

For each scan:
1. For every HIGH or CRITICAL risk finding, provide a concrete fix
2. Suggest hardening commands where appropriate (e.g., "ufw deny 22", "systemctl disable --now vsftpd")
3. Recommend configuration changes for exposed services
4. Prioritize fixes by risk level

Format as a numbered list of actions. Each action must be specific and implementable by a system administrator.

Be practical — don't suggest removing SSH on a server that needs it. Do suggest key-only auth and changing the port.
SYSTEM
      ;;
    attack)
      cat <<'SYSTEM'
You are Port Watcher AI acting as a red team operator. Analyze the open port data and describe how an attacker would chain these services into a compromise.

For each scan:
1. Identify the most promising attack path(s)
2. Map services to likely exploits or techniques
3. Describe the lateral movement possibilities
4. Estimate the time-to-compromise for each path
5. State what a successful compromise would give the attacker

This is for DEFENSIVE purposes — to help the system owner understand their true risk.
SYSTEM
      ;;
    full)
      cat <<'SYSTEM'
You are Port Watcher AI — a cybersecurity AI assistant embedded in a port security scanning tool. You have access to port scan results including risk scores, process info, user context, network bindings, MITRE ATT&CK mappings, anomaly detections, and attack surface grades.

Your job is to analyze this data and produce a comprehensive security assessment.

You MUST:
1. Assess the overall security posture (grade: Secure / Moderate / At Risk / Critical)
2. List the TOP findings (what's most important for the user to know)
3. Provide specific remediation steps for each critical/high finding
4. Include an attack narrative showing how an attacker would exploit these services
5. End with a prioritized action plan

Format your response in Markdown with these sections:
- ## Executive Summary
- ## Top Findings
- ## Attack Narrative
- ## Remediation Plan
- ## Quick Wins (things to fix in 5 minutes)

Keep the response actionable and specific. Don't be vague. If a finding is low risk, say so explicitly rather than generating false alarms.
SYSTEM
      ;;
    auto-fix)
      cat <<'SYSTEMFIX'
You are Port Watcher AI Auto-Fix — a cybersecurity AI that analyzes port scan data and outputs MACHINE-PARSEABLE fix actions in strict JSON format.

Your ONLY output must be a valid JSON object with this exact structure — no markdown, no explanation, no code fences:

{
  "assessment": "Brief 1-line summary of the security posture",
  "fixes": [
    {
      "port": 22,
      "service": "sshd",
      "risk": "HIGH",
      "action": "block",
      "tool": "iptables",
      "command": "iptables -A INPUT -p tcp --dport 22 -j DROP",
      "reason": "SSH exposed to all interfaces (0.0.0.0) running as root — remote brute force risk",
      "undo": "iptables -D INPUT -p tcp --dport 22 -j DROP",
      "safety": "medium"
    }
  ]
}

RULES:
1. Only output the JSON object. No other text, no markdown, no backticks.
2. Each fix MUST have all fields: port, service, risk, action, tool, command, reason, undo, safety.
3. Action must be one of: block, stop_service, restart_service, restrict_bind, change_config
4. Tool must be: iptables, ufw, systemctl, ss, or sed
5. Safety must be: safe, medium, or risky
   - safe: reversible, low impact (e.g., changing bind address)
   - medium: moderate impact (e.g., stopping a non-critical service)
   - risky: could break functionality (e.g., blocking SSH or a database port)
6. Prioritize HIGH and CRITICAL risk findings. Skip LOW and INFO.
7. Only suggest fixes that are PRACTICAL and make sense for the service.
8. For services you recognize as essential (sshd on port 22, DNS on 53, HTTP on 80/443), suggest restrict_bind or change_config instead of block/stop_service.
9. For services that are clearly unnecessary (FTP, Telnet, unused databases), suggest stop_service.
10. Provide a real, working command in "command" that could be executed by a sysadmin.
11. Provide the exact inverse command in "undo" to reverse the change.
12. If no fixes are needed, return: {"assessment": "No critical or high-risk issues found.", "fixes": []}

FAILURE TO OUTPUT VALID JSON WILL CAUSE THE SYSTEM TO CRASH. DO NOT ADD ANY TEXT OUTSIDE THE JSON OBJECT.
SYSTEMFIX
      ;;
  esac
}

# Build the user prompt from port scan data
_build_user_prompt() {
  local port_data="$1"
  local has_anomaly=false has_attack=false has_score=false has_topology=false has_profile=false has_threat=false
  declare -f run_anomaly_detection &>/dev/null && has_anomaly=true
  declare -f mitre_lookup &>/dev/null && has_attack=true
  declare -f calculate_attack_surface &>/dev/null && has_score=true

  local attack_info=""
  if $has_attack; then
    attack_info="$(show_attack_mapping 2>/dev/null || true)"
  fi

  local anomaly_info=""
  if $has_anomaly; then
    anomaly_info="$(show_anomaly_report 2>/dev/null || true)"
  fi

  local score_info=""
  if $has_score; then
    score_info="$(show_score_report 2>/dev/null || true)"
  fi

  cat <<PROMPT
## Port Scan Results

The following ports are currently listening on this machine:

$(echo "$port_data" | while IFS='|' read -r process pid user proto bind_addr port; do
  [[ -z "$port" ]] && continue
  local risk_info score risk bind_type
  risk_info="$(classify_port_risk "$port" 2>/dev/null || echo "UNKNOWN|3")"
  bind_type="$(classify_bind "$bind_addr" 2>/dev/null || echo "UNKNOWN")"
  score="$(calculate_score "$port" "$user" "$bind_type" "" 2>/dev/null || echo "?")"
  risk="$(score_to_risk "$score" 2>/dev/null || echo "UNKNOWN")"
  echo "  - Port $port/$proto | Process: $process (PID: $pid) | User: $user | Bind: $bind_addr | Risk: $risk | Score: $score"
done)

## System Context
- Hostname: $(hostname 2>/dev/null || echo "unknown")
- Kernel: $(uname -r 2>/dev/null || echo "unknown")
- Uptime: $(uptime -p 2>/dev/null || echo "unknown")
- User: $(whoami 2>/dev/null || echo "unknown")

$(if [[ -n "$attack_info" ]]; then
  echo "## MITRE ATT&CK Mappings"
  echo "\`\`\`"
  echo "$attack_info"
  echo "\`\`\`"
fi)

$(if [[ -n "$anomaly_info" ]]; then
  echo "## Anomaly Detections"
  echo "\`\`\`"
  echo "$anomaly_info"
  echo "\`\`\`"
fi)

$(if [[ -n "$score_info" ]]; then
  echo "## Attack Surface Score"
  echo "\`\`\`"
  echo "$score_info"
  echo "\`\`\`"
fi)

Provide your analysis based on the configured analysis mode.
PROMPT
}


# ═══════════════════════════════════════════════════════════════════════════════
#  API CALL FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Make API call to OpenAI-compatible providers
_call_openai_compatible() {
  local endpoint="$1" api_key="$2" model="$3" system_prompt="$4" user_prompt="$5"

  # Build JSON payload
  local payload
  payload="$(cat <<JSON
{
  "model": "$model",
  "messages": [
    {"role": "system", "content": $(echo "$system_prompt" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo "\"$system_prompt\"")},
    {"role": "user", "content": $(echo "$user_prompt" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo "\"$user_prompt\"")}
  ],
  "temperature": $AI_TEMPERATURE,
  "max_tokens": $AI_MAX_TOKENS,
  "stream": false
}
JSON
  )"

  curl -s --max-time 60 "$endpoint" \
    -H "Authorization: Bearer $api_key" \
    -H "Content-Type: application/json" \
    -H "HTTP-Referer: https://github.com/anonymous777999/Bash-Tools" \
    -H "X-OpenRouter-Title: Port Watcher AI" \
    -d "$payload" 2>/dev/null || echo '{"error":"curl_failed"}'
}

# Make API call to Google Gemini
_call_gemini() {
  local endpoint="$1" model="$2" system_prompt="$3" user_prompt="$4"

  local payload
  payload="$(cat <<JSON
{
  "system_instruction": {
    "parts": [{"text": $(echo "$system_prompt" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo "\"$system_prompt\"")}]
  },
  "contents": [
    {"role": "user", "parts": [{"text": $(echo "$user_prompt" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" 2>/dev/null || echo "\"$user_prompt\"")}]}
  ],
  "generationConfig": {
    "temperature": $AI_TEMPERATURE,
    "maxOutputTokens": $AI_MAX_TOKENS
  }
}
JSON
  )"

  curl -s --max-time 60 "$endpoint" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null || echo '{"error":"curl_failed"}'
}

# Extract the response text from various API response formats
_extract_response() {
  local provider="$1" json="$2"
  local content=""

  # Check for API errors
  if echo "$json" | grep -q '"error"'; then
    local error_msg
    error_msg="$(echo "$json" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    err = d.get('error', {})
    if isinstance(err, dict):
        print(err.get('message', str(err)))
    else:
        print(str(err))
except:
    print('Unknown API error')
" 2>/dev/null || echo "API error (could not parse)")"
    echo "⚠️  API Error: $error_msg"
    return 1
  fi

  case "$provider" in
    gemini)
      content="$(echo "$json" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    parts = d.get('candidates', [{}])[0].get('content', {}).get('parts', [])
    text = ' '.join(p.get('text', '') for p in parts)
    print(text)
except:
    print('Failed to parse Gemini response')
" 2>/dev/null || echo "Parse error")"
      ;;
    openai|openrouter|nvidia|groq|*)
      content="$(echo "$json" | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    print(d['choices'][0]['message']['content'])
except:
    print('Failed to parse API response')
" 2>/dev/null || echo "Parse error")"
      ;;
  esac

  echo "$content"
}

# ─── Provider Call with Fallback ───

# Call a single provider and return response via _PROVIDER_RESPONSE / _PROVIDER_ERROR
_call_provider() {
  local provider="$1" model="$2" system_prompt="$3" user_prompt="$4"
  _PROVIDER_RESPONSE=""
  _PROVIDER_ERROR=""

  local endpoint="$(_get_endpoint "$provider")"
  [[ -z "$endpoint" ]] && { _PROVIDER_ERROR="Unknown endpoint for $provider"; return 1; }

  local response_json=""
  if [[ "$provider" == "gemini" ]]; then
    response_json="$(_call_gemini "$endpoint" "$model" "$system_prompt" "$user_prompt")"
  else
    local api_key
    api_key="$(_get_api_key "$provider")"
    [[ -z "$api_key" ]] && { _PROVIDER_ERROR="No API key for $provider"; return 1; }
    response_json="$(_call_openai_compatible "$endpoint" "$api_key" "$model" "$system_prompt" "$user_prompt")"
  fi

  local response_text
  response_text="$(_extract_response "$provider" "$response_json" 2>/dev/null || true)"
  local extract_exit=$?

  if [[ $extract_exit -ne 0 || -z "$response_text" || "$response_text" == "Parse error" ]]; then
    _PROVIDER_ERROR="$response_text"
    _PROVIDER_RESPONSE="$response_json"
    return 1
  fi

  _PROVIDER_RESPONSE="$response_text"
  return 0
}


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN ANALYSIS FUNCTION (with automatic fallback chain)
# ═══════════════════════════════════════════════════════════════════════════════

# Run AI analysis on port scan data with automatic provider fallback
# Falls back through: groq → openrouter → nvidia → gemini → openai
run_ai_analysis() {
  local port_data="$1"
  local mode="${2:-$AI_ANALYSIS_MODE}"

  # Check if analysis is enabled
  if [[ "$AI_ANALYSIS_ENABLED" != "true" ]]; then
    cecho "$C_DIM" "  AI Analysis disabled (set AI_ANALYSIS_ENABLED=true in config)"
    return 0
  fi

  # Check curl availability
  if ! command -v curl &>/dev/null; then
    cecho "$C_BOLD_YELLOW" "  ⚠️  curl not found — AI analysis requires curl"
    return 0
  fi

  # Check python availability (for JSON processing)
  if ! command -v python3 &>/dev/null; then
    cecho "$C_BOLD_YELLOW" "  ⚠️  python3 not found — AI analysis requires python3"
    return 0
  fi

  # Check cache first
  local data_hash
  data_hash="$(_compute_data_hash "$port_data")"
  if _check_cache "$data_hash"; then
    local age=$(( $(date +%s) - AI_ANALYSIS_TIMESTAMP ))
    echo ""
    cecho "$C_DIM" "  [AI Analysis] Using cached result (${age}s old)"
    echo ""
    echo "$AI_ANALYSIS_RESULT"
    return 0
  fi

  # Check if there's data to analyze
  if [[ -z "$port_data" ]]; then
    echo ""
    cecho "$C_BOLD_YELLOW" "  No port data to analyze."
    return 0
  fi

  # Build the fallback chain — only providers with API keys, in priority order
  local chain
  chain=($(_build_fallback_chain))

  if [[ ${#chain[@]} -eq 0 ]]; then
    echo ""
    cecho "$C_BOLD_YELLOW" "  ╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_BOLD_YELLOW" "  ║  🤖 AI Analysis: No API Keys Configured                       ║"
    cecho "$C_BOLD_YELLOW" "  ╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  To enable AI-powered analysis, set at least one API key in ports.conf:"
    echo ""
    echo "    # Recommended (free tier):"
    echo "    GROQ_API_KEY=gsk_your_key_here"
    echo "    AI_PROVIDER=groq"
    echo ""
    echo "    # Or with OpenRouter:"
    echo "    OPENROUTER_API_KEY=sk-or-your-key-here"
    echo "    AI_PROVIDER=openrouter"
    echo ""
    echo "    # Or with NVIDIA NIM (free):"
    echo "    NVIDIA_API_KEY=nvapi-your-key-here"
    echo "    AI_PROVIDER=nvidia"
    echo ""
    echo "    # Or with Google Gemini (free):"
    echo "    GEMINI_API_KEY=AIza_your_key_here"
    echo "    AI_PROVIDER=gemini"
    echo ""
    return 0
  fi

  # Save and disable color to prevent ANSI codes bleeding into the AI prompt
  local saved_color="$COLOR"
  COLOR=false

  # Build system and user prompts ONCE (reused across all fallback attempts)
  local system_prompt user_prompt
  system_prompt="$(_build_system_prompt "$mode")"
  user_prompt="$(_build_user_prompt "$port_data")"

  # Restore color
  COLOR="$saved_color"

  # Determine which provider to try FIRST
  # If configured provider has a key AND is in the chain, start there
  # Otherwise start from the first available in the chain
  local start_idx=0
  local configured_in_chain=false
  for i in "${!chain[@]}"; do
    if [[ "${chain[$i]}" == "$AI_PROVIDER" ]]; then
      start_idx=$i
      configured_in_chain=true
      break
    fi
  done

  # Show header
  local mode_display="${mode^^}"
  [[ "$mode" == "auto-fix" ]] && mode_display="AUTO-FIX"
  echo ""
  cecho "$C_BOLD_CYAN" "  ╔═══════════════════════════════════════════════════════════════╗"
  cecho "$C_BOLD_CYAN" "  ║  🤖 AI Security Analysis  [${mode_display}]                              ║"
  cecho "$C_BOLD_CYAN" "  ╚═══════════════════════════════════════════════════════════════╝"
  if ! $configured_in_chain && [[ ${#chain[@]} -gt 1 ]]; then
    cecho "$C_DIM" "     Note: Configured provider '$AI_PROVIDER' has no key, using first available"
  fi
  cecho "$C_DIM" "     Available providers in fallback chain: ${chain[*]}"
  echo ""

  # Try providers in order until one succeeds
  # Start from start_idx, wrap around through the rest
  local succeeded=false
  local tried=()
  local total=${#chain[@]}
  local attempts=0

  # Try ALL providers in order, wrapping around if needed
  local i
  for ((i = 0; i < total; i++)); do
    local idx=$(( (start_idx + i) % total ))
    local provider="${chain[$idx]}"
    attempts=$((attempts + 1))

    # Deduplicate tries (safety check)
    local already_tried=false
    for t in "${tried[@]}"; do
      [[ "$t" == "$provider" ]] && { already_tried=true; break; }
    done
    $already_tried && continue
    tried+=("$provider")

    local model="$(_get_model "$provider")"
    cecho "$C_DIM" "  [AI] Trying provider ${attempts}/${total}: $provider ($model)..."

    _call_provider "$provider" "$model" "$system_prompt" "$user_prompt"
    if [[ $? -eq 0 ]]; then
      succeeded=true
      echo ""
      if [[ $attempts -gt 1 ]]; then
        cecho "$C_GREEN" "  ✓ Succeeded with fallback provider: $provider"
        echo ""
      fi
      # Save to cache
      _save_cache "$data_hash" "$_PROVIDER_RESPONSE"
      # Print the result
      echo "$_PROVIDER_RESPONSE"
      echo ""
      break
    else
      local err_msg="${_PROVIDER_ERROR:0:80}"
      cecho "$C_BOLD_YELLOW" "  ⚠️  $provider failed: ${err_msg}"
      if [[ $attempts -lt $total ]]; then
        cecho "$C_DIM" "     → Trying next provider..."
        echo ""
      fi
    fi
  done

  if ! $succeeded; then
    echo ""
    cecho "$C_BOLD_RED" "  ╔═══════════════════════════════════════════════════════════════╗"
    cecho "$C_BOLD_RED" "  ║  ✗ All providers failed — no analysis could be completed       ║"
    cecho "$C_BOLD_RED" "  ╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    cecho "$C_DIM" "  Tried providers: ${tried[*]}"
    echo ""
    cecho "$C_DIM" "  Last error saved to: /tmp/port-watcher-ai-error.json"
    if [[ -n "$_PROVIDER_RESPONSE" ]]; then
      echo "$_PROVIDER_RESPONSE" > /tmp/port-watcher-ai-error.json 2>/dev/null || true
    fi
    return 1
  fi

  return 0
}


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT DISPLAY
# ═══════════════════════════════════════════════════════════════════════════════

# Show AI analysis report
show_ai_analysis_report() {
  local port_data="$1"
  run_ai_analysis "$port_data" "$AI_ANALYSIS_MODE"
}


# ═══════════════════════════════════════════════════════════════════════════════
#  AUTO-FIX EXECUTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
#  Parses AI-generated fix JSON, shows confirmation prompts, executes fixes,
#  logs all actions, and provides undo capability.
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Fix Execution ───

# Execute a single fix action with proper tool
_execute_one_fix() {
  local port="$1" service="$2" action="$3" tool="$4" command="$5" undo="$6" reason="$7" safety="$8"

  # Log the action
  local log_dir="$AI_FIX_LOG_DIR"
  mkdir -p "$log_dir" 2>/dev/null || true
  local log_file="${log_dir}/fix-${port}-$(date +%Y%m%d_%H%M%S).log"

  {
    echo "=== Port Watcher AI Auto-Fix Action ==="
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Port: $port"
    echo "Service: $service"
    echo "Action: $action"
    echo "Tool: $tool"
    echo "Command: $command"
    echo "Undo: $undo"
    echo "Reason: $reason"
    echo "Safety: $safety"
  } > "$log_file"

  # Check if we should try IPS plugin first for block actions
  local executed=false
  if [[ "$action" == "block" ]] && declare -f block_port &>/dev/null; then
    block_port "$port" "$service" "$reason" 2>/dev/null && executed=true
  fi

  # Execute the command directly if IPS didn't handle it
  if ! $executed; then
    case "$tool" in
      iptables)
        if command -v iptables &>/dev/null; then
          eval "$command" 2>/dev/null && executed=true || cecho "$C_BOLD_RED" "    ✗ iptables command failed"
        else
          cecho "$C_BOLD_YELLOW" "    ⚠️  iptables not available — skipping firewall rule"
        fi
        ;;
      ufw)
        if command -v ufw &>/dev/null; then
          eval "$command" 2>/dev/null && executed=true || cecho "$C_BOLD_RED" "    ✗ ufw command failed"
        else
          cecho "$C_BOLD_YELLOW" "    ⚠️  ufw not available"
        fi
        ;;
      systemctl)
        if command -v systemctl &>/dev/null; then
          if echo "$command" | grep -q "sudo"; then
            eval "$command" 2>/dev/null && executed=true || cecho "$C_BOLD_RED" "    ✗ systemctl command failed (try running as root)"
          else
            sudo eval "$command" 2>/dev/null && executed=true || cecho "$C_BOLD_RED" "    ✗ systemctl command failed"
          fi
        else
          cecho "$C_BOLD_YELLOW" "    ⚠️  systemctl not available"
        fi
        ;;
      ss)
        eval "$command" 2>/dev/null && executed=true || cecho "$C_BOLD_RED" "    ✗ command failed"
        ;;
      sed|*)
        if echo "$command" | grep -q "sudo"; then
          eval "$command" 2>/dev/null && executed=true || cecho "$C_BOLD_RED" "    ✗ command failed"
        else
          eval "$command" 2>/dev/null || cecho "$C_BOLD_RED" "    ✗ command failed"
          executed=true
        fi
        ;;
    esac
  fi

  # Record the result
  if $executed; then
    AI_FIX_ACTIONS_TAKEN=$((AI_FIX_ACTIONS_TAKEN + 1))
    echo "#$port|$service|$undo" >> "$AI_FIX_UNDO_FILE"
    {
      echo "Status: EXECUTED"
      echo "Result: SUCCESS"
    } >> "$log_file"
    logger -t "port-watcher-ai-fix" "[ACTION] $action port $port ($service) — $reason"
    cecho "$C_GREEN" "    ✓ Executed (undo saved)"
  else
    AI_FIX_ACTIONS_FAILED=$((AI_FIX_ACTIONS_FAILED + 1))
    {
      echo "Status: FAILED"
    } >> "$log_file"
    cecho "$C_BOLD_RED" "    ✗ Failed to execute"
  fi

  # Record to SQLite if database plugin loaded
  if declare -f record_alert &>/dev/null; then
    local status="$($executed && echo 'executed' || echo 'failed')"
    record_alert "${safety^^}" "ai_fix_${action}" "$port" "$service" "AI auto-fix: ${action} on port ${port} (${service}) — ${status}" 2>/dev/null || true
  fi
}

# ─── Fix Parser ───

# Parse AI response JSON and extract fix actions into pipe-delimited lines
_parse_fixes() {
  local response="$1"
  local json_text="$response"

  # Using heredoc to avoid bash escaping issues with regex backslashes
  python3 << 'PYEOF' 2>/dev/null || echo "PARSE_ERROR: python3 failed"
import json, sys, re

text = sys.stdin.read()

# Match { "assessment": ... "fixes": [...] } with whitespace allowance after opening brace
json_match = re.search(r'\{\s*"assessment".*?"fixes"\s*:\s*\[.*?\]\s*\}', text, re.DOTALL)
if not json_match:
    # Relaxed match: JSON without assessment field
    json_match = re.search(r'\{[^{}]*"fixes"\s*:\s*\[[^\]]*\][^{}]*\}', text, re.DOTALL)

if json_match:
    text = json_match.group(0)

try:
    data = json.loads(text)
    fixes = data.get('fixes', [])
    if not fixes:
        print('NO_FIXES')
        sys.exit(0)
    for fix in fixes:
        port = fix.get('port', '?')
        service = fix.get('service', '?')
        risk = fix.get('risk', 'UNKNOWN')
        action = fix.get('action', '?')
        tool = fix.get('tool', '?')
        cmd = fix.get('command', '').replace('|', '/PIPE/')
        reason = fix.get('reason', '').replace('|', '/PIPE/')
        undo = fix.get('undo', '').replace('|', '/PIPE/')
        safety = fix.get('safety', 'medium')
        print(f'{port}|{service}|{risk}|{action}|{tool}|{cmd}|{reason}|{undo}|{safety}')
except Exception as e:
    print(f'PARSE_ERROR: {e}')
    sys.exit(1)
PYEOF
}

# ─── Confirmation Prompt ───

# Show a fix and ask for confirmation
_prompt_for_fix() {
  local index="$1" total="$2" port="$3" service="$4" risk="$5" action="$6" tool="$7" command="$8" reason="$9" safety="${10}" undo="${11}"

  local safety_color="$C_GREEN"
  case "$safety" in
    risky)  safety_color="$C_BOLD_RED" ;;
    medium) safety_color="$C_BOLD_YELLOW" ;;
    *)      safety_color="$C_GREEN" ;;
  esac

  local risk_color="$C_GREEN"
  case "$risk" in
    CRITICAL) risk_color="$C_BOLD_RED" ;;
    HIGH)     risk_color="$C_RED" ;;
    MEDIUM)   risk_color="$C_BOLD_YELLOW" ;;
    *)        risk_color="$C_GREEN" ;;
  esac

  echo ""
  cecho "$C_BOLD" "  ╔═══ Fix #${index}/${total} ════════════════════════════════════════╗"
  echo ""
  echo "    Port:    $(cecho "$C_BOLD" "$port") / $(cecho "$C_DIM" "$service")"
  echo "    Risk:    $(cecho "$risk_color" "$risk")"
  echo "    Action:  $(cecho "$C_BOLD_CYAN" "$action")"
  echo "    Tool:    $tool"
  echo "    Safety:  $(cecho "$safety_color" "$safety")"
  echo ""
  echo "    Command:"
  echo "      $(cecho "$C_YELLOW" "$ ${command}")"
  echo ""
  echo "    Reason:  $reason"
  echo "    Undo:    $undo"
  echo ""

  if [[ "$safety" == "risky" ]]; then
    cecho "$C_BOLD_RED" "  ⚠️  This action is marked as RISKY — could break functionality!"
    echo ""
  fi

  echo -n "  Apply this fix? [y/N/a/?] "
  read -r confirm

  case "$confirm" in
    y|Y|yes|YES)
      return 0
      ;;
    a|A|all|ALL)
      AI_FIX_BATCH_MODE=true
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

# Global batch mode flag
AI_FIX_BATCH_MODE=false

# ─── Undo ───

# Show and execute saved undo commands
show_undo_actions() {
  local undo_file="${1:-$AI_FIX_UNDO_FILE}"

  if [[ ! -f "$undo_file" ]]; then
    cecho "$C_BOLD_YELLOW" "  No undo actions found."
    return 0
  fi

  echo ""
  cecho "$C_BOLD_CYAN" "  ╔═══════════════════════════════════════════════════════════════╗"
  cecho "$C_BOLD_CYAN" "  ║  ↩️  Saved Undo Actions                                       ║"
  cecho "$C_BOLD_CYAN" "  ╚═══════════════════════════════════════════════════════════════╝"
  echo ""

  local count=0
  while IFS='|' read -r port service undo_cmd; do
    [[ -z "$port" || "$port" == "#"* ]] && continue
    count=$((count + 1))
    echo "  $count. Port $port ($service)"
    echo "     Undo: $ (cecho "$C_YELLOW" "${undo_cmd}")"
    echo ""
  done < "$undo_file"

  if [[ $count -eq 0 ]]; then
    cecho "$C_DIM" "  No undo actions found."
    return 0
  fi

  echo -n "  Apply all undo actions? [y/N] "
  read -r confirm
  if [[ "$confirm" == "y" || "$confirm" == "Y" || "$confirm" == "yes" ]]; then
    while IFS='|' read -r port service undo_cmd; do
      [[ -z "$port" || "$port" == "#"* ]] && continue
      cecho "$C_YELLOW" "  ↩️  Undoing fix for port $port ($service)..."
      eval "$undo_cmd" 2>/dev/null || cecho "$C_BOLD_RED" "    ✗ Undo failed"
    done < "$undo_file"
    cecho "$C_GREEN" "  ✓ All undo actions applied."
    rm -f "$undo_file"
  fi
}

# ─── Main Auto-Fix Entry Point ───

# Run AI analysis and auto-fix mode
run_ai_auto_fix() {
  local port_data="$1"
  local min_risk="${2:-$AI_FIX_LEVEL}"

  if [[ "$AI_ANALYSIS_ENABLED" != "true" ]]; then
    cecho "$C_BOLD_YELLOW" "  AI analysis disabled in config"
    return 1
  fi

  if ! command -v curl &>/dev/null || ! command -v python3 &>/dev/null; then
    cecho "$C_BOLD_YELLOW" "  curl and python3 required for AI analysis"
    return 1
  fi

  mkdir -p "$AI_FIX_LOG_DIR" 2>/dev/null || true

  local saved_cache_ttl="$AI_CACHE_TTL"
  AI_CACHE_TTL=0

  local analysis_result
  analysis_result="$(run_ai_analysis "$port_data" "auto-fix" 2>/dev/null || true)"

  AI_CACHE_TTL="$saved_cache_ttl"

  if [[ -z "$analysis_result" ]]; then
    cecho "$C_BOLD_YELLOW" "  No analysis result from AI."
    return 1
  fi

  if echo "$analysis_result" | grep -q "⚠️  API Error\|No API Keys\|Parse error"; then
    echo "$analysis_result"
    return 1
  fi

  local fixes_txt
  fixes_txt="$(_parse_fixes "$analysis_result")"

  if echo "$fixes_txt" | grep -q "NO_FIXES"; then
    echo ""
    cecho "$C_GREEN" "  ✓ AI analysis complete — no fixes needed."
    echo ""
    echo "$analysis_result"
    return 0
  fi

  if echo "$fixes_txt" | grep -q "PARSE_ERROR"; then
    cecho "$C_BOLD_RED" "  ⚠️  Failed to parse AI response as JSON."
    cecho "$C_DIM" "     The AI returned an unexpected format. Raw output:"
    echo ""
    echo "$analysis_result" | head -c 500
    echo ""
    echo "$analysis_result" > /tmp/port-watcher-ai-fix-error.txt
    cecho "$C_DIM" "     Full output saved to: /tmp/port-watcher-ai-fix-error.txt"
    return 1
  fi

  local total_fixes
  total_fixes="$(echo "$fixes_txt" | wc -l)"

  echo ""
  cecho "$C_BOLD_CYAN" "  ╔═══════════════════════════════════════════════════════════════╗"
  cecho "$C_BOLD_CYAN" "  ║  🛠️  AI Auto-Fix: ${total_fixes} Suggested Action(s)                         ║"
  cecho "$C_BOLD_CYAN" "  ╚═══════════════════════════════════════════════════════════════╝"
  echo ""
  cecho "$C_DIM" "  Assessment: $(echo "$analysis_result" | head -1)"
  echo ""

  local index=0
  AI_FIX_BATCH_MODE=false

  local fixes_file="/tmp/port-watcher-fixes.txt"
  echo "$fixes_txt" > "$fixes_file"

  while IFS='|' read -r port service risk action tool command reason undo safety; do
    [[ -z "$port" || "$port" == "#"* ]] && continue
    index=$((index + 1))

    # Restore pipe characters: /PIPE/ -> || (use ! delimiter to avoid pipe ambiguity)
    command="$(echo "$command" | sed 's!/PIPE/!||!g')"
    reason="$(echo "$reason" | sed 's!/PIPE/!||!g')"
    undo="$(echo "$undo" | sed 's!/PIPE/!||!g')"

    local skip=false
    case "$min_risk" in
      CRITICAL) [[ "$risk" != "CRITICAL" ]] && skip=true ;;
      HIGH)     [[ "$risk" != "CRITICAL" && "$risk" != "HIGH" ]] && skip=true ;;
      ALL|*)    ;;
    esac
    $skip && continue

    if $AI_FIX_BATCH_MODE; then
      _execute_one_fix "$port" "$service" "$action" "$tool" "$command" "$undo" "$reason" "$safety"
    elif [[ "$AI_FIX_CONFIRM" == "yes" ]]; then
      _execute_one_fix "$port" "$service" "$action" "$tool" "$command" "$undo" "$reason" "$safety"
    elif [[ "$AI_FIX_CONFIRM" == "dry-run" ]]; then
      echo "  [DRY-RUN] Would apply: $ ${command}"
    else
      _prompt_for_fix "$index" "$total_fixes" "$port" "$service" "$risk" "$action" "$tool" "$command" "$reason" "$safety" "$undo"
      local prompt_exit=$?
      if [[ $prompt_exit -eq 0 ]]; then
        _execute_one_fix "$port" "$service" "$action" "$tool" "$command" "$undo" "$reason" "$safety"
      else
        cecho "$C_DIM" "    — Skipped"
      fi
    fi
  done < "$fixes_file"

  echo ""
  cecho "$C_BOLD" "  ╔═══════════════════════════════════════════════════════════════╗"
  cecho "$C_BOLD" "  ║  📊 Auto-Fix Summary                                         ║"
  cecho "$C_BOLD" "  ╚═══════════════════════════════════════════════════════════════╝"
  echo ""
  cecho "$C_GREEN" "    ✓ Executed:  $AI_FIX_ACTIONS_TAKEN"
  if [[ $AI_FIX_ACTIONS_FAILED -gt 0 ]]; then
    cecho "$C_BOLD_RED" "    ✗ Failed:    $AI_FIX_ACTIONS_FAILED"
  fi
  echo ""
  cecho "$C_DIM" "    Logs:    $AI_FIX_LOG_DIR/"
  cecho "$C_DIM" "    Undo:    $AI_FIX_UNDO_FILE"
  echo ""

  rm -f "$fixes_file"
  return 0
}


# ═══════════════════════════════════════════════════════════════════════════════
#  PLUGIN INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════

# Plugin initialization — load keys from environment if not set in config
plugin_init_ai-analysis() {
  [[ -z "$OPENAI_API_KEY" && -n "${OPENAI_API_KEY_ENV:-}" ]] && OPENAI_API_KEY="$OPENAI_API_KEY_ENV"
  [[ -z "$OPENROUTER_API_KEY" && -n "${OPENROUTER_API_KEY_ENV:-}" ]] && OPENROUTER_API_KEY="$OPENROUTER_API_KEY_ENV"
  [[ -z "$NVIDIA_API_KEY" && -n "${NVIDIA_API_KEY_ENV:-}" ]] && NVIDIA_API_KEY="$NVIDIA_API_KEY_ENV"
  [[ -z "$GROQ_API_KEY" && -n "${GROQ_API_KEY_ENV:-}" ]] && GROQ_API_KEY="$GROQ_API_KEY_ENV"
  [[ -z "$GEMINI_API_KEY" && -n "${GEMINI_API_KEY_ENV:-}" ]] && GEMINI_API_KEY="$GEMINI_API_KEY_ENV"

  if $AI_ANALYSIS_ENABLED; then
    local available
    available="$(_build_fallback_chain)"
    if [[ -n "$available" ]]; then
      cecho "$C_DIM" "  [ai-analysis] Fallback chain: ${available}"
    else
      cecho "$C_DIM" "  [ai-analysis] No API keys configured. Use --ai-analyze for setup info."
    fi
  fi

  return 0
}
