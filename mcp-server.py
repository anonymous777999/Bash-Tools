#!/usr/bin/env python3
"""
Port Watcher MCP Server — Model Context Protocol implementation.

Lets AI agents (Claude, Codebuff, Cursor, etc.) interact with Port Watcher
as a pluggable tool. Uses stdio transport (JSON-RPC 2.0 over stdin/stdout).

Protocol: https://modelcontextprotocol.io

Usage:
    python3 mcp-server.py          # Run as stdio MCP server
    python3 mcp-server.py --help   # Show tool information

Clients connect via stdio. Example claude_desktop_config.json:
    {
      "mcpServers": {
        "port-watcher": {
          "command": "python3",
          "args": ["/path/to/mcp-server.py"]
        }
      }
    }
"""

import json
import subprocess
import sys
import os
import shutil
import time
import signal

# ─── Configuration ───

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PORT_WATCHER_PATH = os.path.join(SCRIPT_DIR, "src", "port-watcher.sh")
# Fallback: check if port-watcher is in PATH
if not os.path.isfile(PORT_WATCHER_PATH):
    PORT_WATCHER_PATH = shutil.which("port-watcher") or PORT_WATCHER_PATH

SERVER_INFO = {
    "name": "port-watcher-mcp",
    "version": "3.0.0",
}

# ─── Tool Definitions ───

TOOLS = [
    {
        "name": "scan_ports",
        "description": "Scan listening ports with dynamic risk scoring. Returns table of open ports with PID, user, process, bind address, risk level, and MITRE ATT&CK mapping.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {
                    "type": "string",
                    "enum": ["table", "json", "csv"],
                    "default": "table",
                    "description": "Output format",
                },
                "risk": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
                    "description": "Filter by risk level",
                },
                "port": {
                    "type": "string",
                    "description": "Filter by port(s): '22,80,443' or '8000-9000'",
                },
                "process": {
                    "type": "string",
                    "description": "Filter by process name",
                },
            },
        },
    },
    {
        "name": "scan_anomalies",
        "description": "Run AI anomaly detection. Compares current ports against learned 'normal' profile and flags changes (new ports, process swaps, user changes, bind changes). Builds profile over time: run twice for meaningful results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {
                    "type": "string",
                    "enum": ["table", "json"],
                    "default": "table",
                    "description": "Output format",
                },
            },
        },
    },
    {
        "name": "scan_threat_intel",
        "description": "Cross-reference discovered services with external threat intelligence feeds. Checks built-in C2/IP ranges, and optionally Shodan/AbuseIPDB/AlienVault (requires API keys in ports.conf).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {
                    "type": "string",
                    "enum": ["table", "json"],
                    "default": "table",
                    "description": "Output format",
                },
            },
        },
    },
    {
        "name": "scan_topology",
        "description": "Discover live hosts on the local network via ARP scan + mDNS, map service dependencies, and generate a network topology graph with risk-colored nodes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {
                    "type": "string",
                    "enum": ["table", "json"],
                    "default": "table",
                    "description": "Output format",
                },
            },
        },
    },
    {
        "name": "process_profile",
        "description": "Profile process behavior: check CPU, memory, file descriptors, threads, binary hash changes, zombie processes, and suspicious parent-child relationships. Use --profile-snapshot first to record baseline binary hashes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "snapshot": {
                    "type": "boolean",
                    "default": False,
                    "description": "Record current binary hashes as baseline (run this first)",
                },
                "output": {
                    "type": "string",
                    "enum": ["table", "json"],
                    "default": "table",
                    "description": "Output format",
                },
            },
        },
    },
    {
        "name": "attack_surface",
        "description": "Calculate the overall Attack Surface Score for the machine. Returns an A-F grade with breakdown of risk distribution, penalties, bonuses, and remediation suggestions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {
                    "type": "string",
                    "enum": ["table", "json"],
                    "default": "table",
                    "description": "Output format",
                },
            },
        },
    },
    {
        "name": "run_all",
        "description": "Run the FULL security audit: port scan + anomalies + attack surface + process profile + threat intel + topology. This is the ultimate command for a comprehensive machine assessment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "output": {
                    "type": "string",
                    "enum": ["table", "json"],
                    "default": "table",
                    "description": "Output format",
                },
                "skip_sudo": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip sudo-dependent scans (ARP, lsof) if not running as root",
                },
            },
        },
    },
    {
        "name": "ai_analyze",
        "description": "Run AI-powered security analysis on scan results. Pipes port data through an LLM (Groq, OpenRouter, NVIDIA, Gemini, or OpenAI) for natural-language security briefings, remediation advice, attack narratives, and risk explanations. Requires an API key configured in ports.conf.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["briefing", "remediation", "attack", "full"],
                    "default": "briefing",
                    "description": "Analysis mode: 'briefing' (summary), 'remediation' (fix steps), 'attack' (red team narrative), 'full' (comprehensive)",
                },
                "provider": {
                    "type": "string",
                    "enum": ["openai", "openrouter", "nvidia", "groq", "gemini"],
                    "description": "AI provider to use. Falls back to AI_PROVIDER in config if not specified.",
                },
                "model": {
                    "type": "string",
                    "description": "Model name to use (e.g., 'gpt-4o-mini', 'llama-3.3-70b-versatile'). Defaults to provider default if not specified.",
                },
            },
        },
    },
]

# ─── Resource Definitions ───

RESOURCES = [
    {
        "uri": "port-watcher://status",
        "name": "Tool Status",
        "description": "Port Watcher version, plugin status, configuration paths, and availability of external dependencies (lsof, ss, arp-scan, etc.)",
        "mimeType": "application/json",
    },
    {
        "uri": "port-watcher://scan/latest",
        "name": "Latest Scan Results",
        "description": "Results from the most recent port scan in JSON format including all ports, risk scores, MITRE mappings, and anomaly data",
        "mimeType": "application/json",
    },
    {
        "uri": "port-watcher://metrics",
        "name": "Prometheus Metrics",
        "description": "Prometheus-formatted metrics from the latest scan (port_risk_score gauges, port counts, attack surface grade)",
        "mimeType": "text/plain",
    },
]

# ─── Utilities ───

_log_messages = []


def log(msg: str):
    """Log to stderr (MCP stdio transport uses stderr for logging)."""
    print(msg, file=sys.stderr, flush=True)
    _log_messages.append(msg)


def run_port_watcher(args: list[str], timeout: int = 60) -> str:
    """
    Run port-watcher.sh with given args and return stdout.
    Raises RuntimeError on non-zero exit.
    """
    cmd = [PORT_WATCHER_PATH] + args
    log(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=SCRIPT_DIR,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            log(f"port-watcher exit code {result.returncode}: {stderr[:200]}")
            # Still return stdout — many commands produce useful output even on
            # non-zero exit (e.g. warnings about not being root)
            if result.stdout.strip():
                return result.stdout
            raise RuntimeError(
                f"port-watcher exited with code {result.returncode}: {stderr[:500]}"
            )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"port-watcher timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError(
            f"port-watcher not found at {PORT_WATCHER_PATH}. "
            "Ensure the script exists and is executable."
        )


def get_status_data() -> dict:
    """Get tool status information."""
    deps = {
        "lsof": shutil.which("lsof") is not None,
        "ss": shutil.which("ss") is not None,
        "arp-scan": shutil.which("arp-scan") is not None,
        "avahi-browse": shutil.which("avahi-browse") is not None,
        "socat": shutil.which("socat") is not None,
        "curl": shutil.which("curl") is not None,
        "sqlite3": shutil.which("sqlite3") is not None,
        "python3": shutil.which("python3") is not None,
    }

    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    watcher_exists = os.path.isfile(PORT_WATCHER_PATH)
    plugins_dir = os.path.join(SCRIPT_DIR, "src", "plugins", "enabled")
    plugin_count = len([
        f for f in os.listdir(plugins_dir) if f.endswith(".sh")
    ]) if os.path.isdir(plugins_dir) else 0

    return {
        "version": "3.0.0",
        "script_path": PORT_WATCHER_PATH,
        "script_exists": watcher_exists,
        "is_root": is_root,
        "dependencies": deps,
        "plugins_available": plugin_count,
        "plugins_dir": plugins_dir,
        "config_paths": [
            os.path.expanduser("~/.config/port-watcher/ports.conf"),
            "/etc/port-watcher/ports.conf",
        ],
        "config_exists": any(
            os.path.isfile(p) for p in [
                os.path.expanduser("~/.config/port-watcher/ports.conf"),
                "/etc/port-watcher/ports.conf",
            ]
        ),
    }


# ─── MCP Protocol ───

def make_response(request_id, result):
    """Build a JSON-RPC success response."""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def make_error(request_id, code: int, message: str):
    """Build a JSON-RPC error response."""
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def make_notification(method: str, params: dict = None):
    """Build a JSON-RPC notification (no id)."""
    msg = {"jsonrpc": "2.0", "method": method}
    if params:
        msg["params"] = params
    return msg


# ─── Method Handlers ───

def handle_initialize(params: dict):
    """Handle the initialize request — returns server capabilities."""
    protocol_version = params.get("protocolVersion", "2024-11-05")
    return {
        "protocolVersion": protocol_version,
        "capabilities": {
            "tools": {},        # We support tools/list + tools/call
            "resources": {},    # We support resources/list + resources/read
        },
        "serverInfo": SERVER_INFO,
    }


def handle_tools_list(params: dict):
    """Handle tools/list — return available tool definitions."""
    return {"tools": TOOLS}


def handle_tools_call(params: dict):
    """Handle tools/call — execute a tool and return results."""
    name = params.get("name", "")
    arguments = params.get("arguments", {})

    handlers = {
        "scan_ports": _call_scan_ports,
        "scan_anomalies": _call_scan_anomalies,
        "scan_threat_intel": _call_scan_threat_intel,
        "scan_topology": _call_scan_topology,
        "process_profile": _call_process_profile,
        "attack_surface": _call_attack_surface,
        "run_all": _call_run_all,
        "ai_analyze": _call_ai_analyze,
    }

    handler = handlers.get(name)
    if not handler:
        raise ValueError(f"Unknown tool: {name}")

    return handler(arguments)


def handle_resources_list(params: dict):
    """Handle resources/list — return available resources."""
    return {"resources": RESOURCES}


def handle_resources_read(params: dict):
    """Handle resources/read — return resource contents."""
    uri = params.get("uri", "")

    handlers = {
        "port-watcher://status": _read_status,
        "port-watcher://scan/latest": _read_scan_latest,
        "port-watcher://metrics": _read_metrics,
    }

    handler = handlers.get(uri)
    if not handler:
        raise ValueError(f"Unknown resource: {uri}")

    return {"contents": [handler(uri)]}


# ─── Tool Call Implementations ───

def _call_scan_ports(args: dict) -> dict:
    """Execute port scan."""
    output = args.get("output", "table")
    cmd = []

    if output == "json":
        cmd += ["--output", "json"]
    elif output == "csv":
        cmd += ["--output", "csv"]

    if risk := args.get("risk"):
        cmd += ["--risk", risk.upper()]
    if port := args.get("port"):
        cmd += ["--port", port]
    if process := args.get("process"):
        cmd += ["--process", process]

    stdout = run_port_watcher(cmd)
    return _text_content(stdout)


def _call_scan_anomalies(args: dict) -> dict:
    """Execute anomaly detection (with attack surface for context)."""
    output = args.get("output", "table")
    cmd = ["--anomalies", "--score"]
    if output == "json":
        cmd += ["--output", "json"]
    stdout = run_port_watcher(cmd)
    return _text_content(stdout)


def _call_scan_threat_intel(args: dict) -> dict:
    """Execute threat intelligence check."""
    output = args.get("output", "table")
    cmd = ["--threat-intel"]
    if output == "json":
        cmd += ["--output", "json"]
    stdout = run_port_watcher(cmd)
    return _text_content(stdout)


def _call_scan_topology(args: dict) -> dict:
    """Execute network topology discovery."""
    output = args.get("output", "table")
    cmd = ["--topology"]
    if output == "json":
        cmd += ["--output", "json"]
    stdout = run_port_watcher(cmd)
    return _text_content(stdout)


def _call_process_profile(args: dict) -> dict:
    """Execute process behavior profiling."""
    snapshot = args.get("snapshot", False)
    output = args.get("output", "table")

    cmd = ["--profile"]
    if snapshot:
        cmd.append("--profile-snapshot")
    if output == "json":
        cmd += ["--output", "json"]
    stdout = run_port_watcher(cmd)
    return _text_content(stdout)


def _call_attack_surface(args: dict) -> dict:
    """Execute attack surface scoring."""
    output = args.get("output", "table")
    cmd = ["--score"]
    if output == "json":
        cmd += ["--output", "json"]
    stdout = run_port_watcher(cmd)
    return _text_content(stdout)


def _call_run_all(args: dict) -> dict:
    """Execute all security checks."""
    output = args.get("output", "table")
    skip_sudo = args.get("skip_sudo", False)

    cmd = ["--anomalies", "--score", "--profile"]

    # Skip sudo-dependent scans if requested
    if not skip_sudo:
        cmd += ["--threat-intel", "--topology"]

    if output == "json":
        cmd += ["--output", "json"]

    stdout = run_port_watcher(cmd, timeout=120)
    return _text_content(stdout)


def _call_ai_analyze(args: dict) -> dict:
    """Execute AI-powered security analysis."""
    mode = args.get("mode", "briefing")
    provider = args.get("provider", "")
    model = args.get("model", "")

    cmd = ["--ai-analyze", "--ai-mode", mode]
    if provider:
        cmd += ["--ai-provider", provider]
    if model:
        cmd += ["--ai-model", model]

    stdout = run_port_watcher(cmd, timeout=120)
    return _text_content(stdout)


# ─── Resource Read Implementations ───

def _read_status(uri: str) -> dict:
    """Return tool status as JSON."""
    data = get_status_data()
    return {
        "uri": uri,
        "mimeType": "application/json",
        "text": json.dumps(data, indent=2),
    }


def _read_scan_latest(uri: str) -> dict:
    """Return latest scan as JSON."""
    try:
        stdout = run_port_watcher(["--output", "json"])
    except RuntimeError as e:
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps({"error": str(e)}, indent=2),
        }
    return {
        "uri": uri,
        "mimeType": "application/json",
        "text": stdout,
    }


def _read_metrics(uri: str) -> dict:
    """Return Prometheus metrics."""
    try:
        stdout = run_port_watcher(["--metrics"])
    except RuntimeError as e:
        return {
            "uri": uri,
            "mimeType": "text/plain",
            "text": f"# Error: {e}\n",
        }
    return {
        "uri": uri,
        "mimeType": "text/plain",
        "text": stdout,
    }


# ─── Response Helpers ───

def _text_content(text: str) -> dict:
    """Wrap text into MCP content response."""
    return {
        "content": [{"type": "text", "text": text}],
        "isError": False,
    }


# ─── Main Server Loop ───

def main():
    """MCP server main loop — reads JSON-RPC from stdin, writes to stdout."""
    # If --help is passed, print tool info and exit
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Port Watcher MCP Server")
        print("=======================")
        print(f"Script:    {PORT_WATCHER_PATH}")
        print(f"Workspace: {SCRIPT_DIR}")
        print()
        print("Available tools:")
        for tool in TOOLS:
            print(f"  {tool['name']}: {tool['description'][:80]}...")
        print()
        print("Available resources:")
        for res in RESOURCES:
            print(f"  {res['uri']}: {res['description'][:80]}...")
        print()
        print("Usage:")
        print("  Run without arguments for MCP stdio transport.")
        print("  AI clients connect automatically via subprocess.")
        sys.exit(0)

    log(f"Port Watcher MCP Server v{SERVER_INFO['version']} starting...")
    log(f"Script path: {PORT_WATCHER_PATH}")
    log(f"Workspace: {SCRIPT_DIR}")

    # Signal handling for graceful shutdown
    shutdown = False

    def handle_signal(signum, frame):
        nonlocal shutdown
        shutdown = True
        log(f"Received signal {signum}, shutting down...")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Main loop — read JSON-RPC lines from stdin
    for line in sys.stdin:
        if shutdown:
            break

        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            log(f"Invalid JSON: {e}")
            continue

        request_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        log(f"Request: {method} (id={request_id})")

        try:
            if method == "initialize":
                result = handle_initialize(params)
                response = make_response(request_id, result)

            elif method == "tools/list":
                result = handle_tools_list(params)
                response = make_response(request_id, result)

            elif method == "tools/call":
                result = handle_tools_call(params)
                response = make_response(request_id, result)

            elif method == "resources/list":
                result = handle_resources_list(params)
                response = make_response(request_id, result)

            elif method == "resources/read":
                result = handle_resources_read(params)
                response = make_response(request_id, result)

            elif method == "notifications/initialized":
                # No response needed for notifications
                continue

            elif method == "ping":
                response = make_response(request_id, {})

            else:
                log(f"Unknown method: {method}")
                response = make_error(request_id, -32601, f"Method not found: {method}")

        except ValueError as e:
            log(f"Error handling {method}: {e}")
            response = make_error(request_id, -32602, str(e))
        except RuntimeError as e:
            log(f"Runtime error handling {method}: {e}")
            response = make_error(request_id, -32000, str(e))
        except Exception as e:
            log(f"Unexpected error handling {method}: {type(e).__name__}: {e}")
            response = make_error(request_id, -32603, f"Internal error: {e}")

        # Write response to stdout (newline-delimited JSON)
        if response is not None:
            try:
                print(json.dumps(response), flush=True)
            except BrokenPipeError:
                log("Broken pipe (client disconnected)")
                break

    log("MCP Server shutting down.")


if __name__ == "__main__":
    main()
