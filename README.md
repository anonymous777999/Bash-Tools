# 🔍 Port Watcher v3 — Advanced Security Port Risk Analyzer

![Version](https://img.shields.io/badge/version-3.0.0-22D3EE?style=flat-square&labelColor=0A101F)
![Shell](https://img.shields.io/badge/shell-bash-10B981?style=flat-square&logo=gnubash&logoColor=white&labelColor=0A101F)
![Plugins](https://img.shields.io/badge/plugins-%E2%9C%93-A78BFA?style=flat-square&labelColor=0A101F)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-EF4444?style=flat-square&labelColor=0A101F)
![License](https://img.shields.io/badge/license-MIT-10B981?style=flat-square&labelColor=0A101F)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-22D3EE?style=flat-square&labelColor=0A101F)

**Port Watcher v3** is a professional security monitoring platform that scans open ports, maps them to running processes/users/PIDs, performs **dynamic risk scoring**, maps findings to **MITRE ATT&CK techniques**, records everything to a **SQLite database** for historical analysis, and supports a **drop-in plugin system** for extensibility.

> Built by [RedVortex](https://github.com/anonymous777999) — Ethical Hacker & Security Researcher

---

## 🚀 Features

### v3 New Features
| Feature | Description |
|---------|-------------|
| **🔌 Plugin System** | Drop-in `.sh` files in `~/.config/port-watcher/plugins/enabled/` — auto-loaded with hook-based extensibility |
| **🎯 MITRE ATT&CK Mapping** | Every port/process mapped to MITRE ATT&CK techniques (appears in table, JSON, CSV, HTML outputs) |
| **💾 SQLite Database** | Historical scan recording with `--history`, `--trend`, `--timeline` queries — trend analysis over time |
| **🧩 Plugin Commands** | `--plugins` to list loaded plugins, `--attack` to show full MITRE ATT&CK mapping table |

### Core Capabilities
- **Dynamic Risk Scoring** — Score = BASE(PORT) × USER_WEIGHT × BIND_WEIGHT × VERSION_WEIGHT
- **Full CLI** — 15+ flags for filtering, formatting, and automation
- **Dual-Stack** — Full IPv4 and IPv6 support (no more silently dropped IPv6 services)
- **Expanded Port DB** — 200+ ports across 9 categories (Web, Database, Cloud, Container, IoT, etc.)

### Output Formats
| Format | Use Case |
|--------|----------|
| **`--output table`** | Interactive terminal with MITRE ATT&CK column (default) |
| **`--output json`** | Machine parsing with MITRE technique IDs |
| **`--output csv`** | Spreadsheets with MITRE fields |
| **`--output html`** | Styled HTML report with dark hacker theme |

---

## ⚡ Quick Start

```bash
# Clone and install
git clone https://github.com/anonymous777999/Bash-Tools.git
cd Bash-Tools
sudo make install    # Installs to /usr/local/bin

# Or run directly
sudo ./src/port-watcher.sh
```

### Basic Usage

```bash
# Default table output (with MITRE ATT&CK column)
sudo port-watcher

# JSON output (with MITRE fields)
sudo port-watcher --output json

# MITRE ATT&CK mapping table
sudo port-watcher --attack

# Port history from database
sudo port-watcher --history 6379

# Risk trend over last 14 days
sudo port-watcher --trend 14

# Alert timeline
sudo port-watcher --timeline

# List loaded plugins
sudo port-watcher --plugins

# Filter by risk level
sudo port-watcher --risk CRITICAL

# Watch mode with change detection
sudo port-watcher --watch 5
```

---

## 🔌 Plugin System

Port Watcher v3 introduces a **drop-in plugin architecture**. Place `.sh` files in the enabled directory and they auto-load:

### Plugin Locations
```
~/.config/port-watcher/plugins/enabled/     # User plugins
/etc/port-watcher/plugins/enabled/          # System plugins
./src/plugins/enabled/                       # Bundled plugins (MITRE ATT&CK, SQLite)
./src/plugins/available/                     # Sample/example plugins
```

### Bundled Plugins (auto-loaded)
| Plugin | Description |
|--------|-------------|
| **`10-mitre-attack.sh`** | Maps every finding to MITRE ATT&CK techniques (T1046, T1021, etc.) |
| **`20-database-sqlite.sh`** | Records scan history, enables `--history`, `--trend`, `--timeline` |

### Sample Plugins (copy to enabled/ to activate)
| Plugin | Description |
|--------|-------------|
| **`alert-slack.sh`** | Sends CRITICAL/HIGH alerts to Slack or Discord webhooks |
| **`ssl-audit.sh`** | Checks SSL/TLS certificate expiry, self-signed, and weak ciphers |
| **`cve-lookup.sh`** | Cross-references service versions against CVE databases |

### Plugin Interface
```bash
# Hooks your plugin can implement:
plugin_init_<name>()            # Called once at startup
plugin_collect_<name>()         # Called during data collection
plugin_analyze_<name>()         # Called per port during analysis
plugin_render_table_<name>()    # Extra table columns
plugin_render_json_<name>()     # Extra JSON fields
plugin_cleanup_<name>()         # Called on exit
```

---

## 🎯 MITRE ATT&CK Mapping

Every discovered port/process combination is mapped to MITRE ATT&CK techniques:

```
PORT  PID   USER       PROCESS          BIND       RISK      ATT&CK
────  ────  ────       ───────          ────       ────      ──────
22    1234  root       sshd             0.0.0.0    HIGH      T1046
6379  4567  root       redis-server     0.0.0.0    CRITICAL  T1021.006
2375  7890  root       dockerd          0.0.0.0    CRITICAL  T1611
```

View the full mapping table:
```bash
sudo port-watcher --attack
```

---

## 💾 SQLite Historical Database

Every scan is automatically recorded to `~/.config/port-watcher/history.db`.

### Query Commands

```bash
# Show scan history for port 6379
sudo port-watcher --history 6379

# Show risk trend over last 14 days
sudo port-watcher --trend 14

# Show alert/incident timeline
sudo port-watcher --timeline

# Use custom database path
sudo port-watcher --db /path/to/custom.db --history 22
```

### Database Schema
```sql
scans:    id, timestamp, hostname, total_ports, critical, high, medium, low, score_avg
ports:    id, scan_id, port, pid, user, process, protocol, bind_addr, risk, score, mitre_id
alerts:   id, timestamp, severity, alert_type, port, process, message
```

---

## 📊 Dynamic Risk Scoring

```
RISK_SCORE = BASE_PORT_RISK × USER_WEIGHT × BIND_WEIGHT × VERSION_WEIGHT
```

| Scenario | Port | User | Bind | Version | Score | Risk | ATT&CK |
|----------|------|------|------|---------|-------|------|--------|
| MySQL 5.7 exposed | 3306 | root | 0.0.0.0 | old | 43.2 | 🔴 CRITICAL | T1552.001 |
| MySQL 8.0 localhost | 3306 | mysql | 127.0.0.1 | current | 0.96 | 🟢 LOW | T1552.001 |
| SSH key-only | 22 | root | LAN | current | 7.5 | 🟡 MEDIUM | T1046 |
| Redis no auth | 6379 | root | 0.0.0.0 | none | 24.0 | 🔴 HIGH | T1021.006 |

---

## 🔧 Configuration

```bash
mkdir -p ~/.config/port-watcher
cp config/ports.conf.example ~/.config/port-watcher/ports.conf
# Edit to add/remove ports, adjust scoring weights, plugin settings, etc.
```

---

## 🛠 Installation

### Option 1: Makefile (Recommended)
```bash
sudo make install    # Installs to /usr/local/bin/
make install-local   # Installs to ~/.local/bin/
```

### Option 2: One-liner
```bash
curl -fsSL https://raw.githubusercontent.com/anonymous777999/Bash-Tools/main/install.sh | bash
```

### Requirements
- `bash` 4.0+
- `lsof` **or** `ss` (one required for port collection)
- `sqlite3` (optional, for database features)
- `openssl` (optional, for SSL audit plugin)

---

## 🧪 Example Output (v3 with MITRE ATT&CK)

```
╔═══════════════════════════════════════════════════════════════╗
║  🔍 PORT WATCHER v3.0.0 — 2026-07-29 04:36:15               ║
╚═══════════════════════════════════════════════════════════════╝

┌───────┬──────┬──────────┬──────────────────┬────────────┬──────────┬──────────┐
│ PORT  │ PID  │ USER     │ PROCESS          │ BIND       │ RISK     │ ATT&CK   │
├───────┼──────┼──────────┼──────────────────┼────────────┼──────────┼──────────┤
│ 22    │ 1234 │ root     │ sshd             │ 0.0.0.0    │ HIGH     │ T1046    │
│ 443   │ 2345 │ www-data │ nginx            │ 0.0.0.0    │ MEDIUM   │ T1046    │
│ 5432  │ 3456 │ postgres │ postgres         │ 127.0.0.1  │ LOW      │ T1552.001│
│ 6379  │ 4567 │ root     │ redis-server     │ 0.0.0.0    │ CRITICAL │ T1021.006│
│ 9200  │ 5678 │ elastic  │ java             │ 0.0.0.0    │ CRITICAL │ T1119    │
└───────┴──────┴──────────┴──────────────────┴────────────┴──────────┴──────────┘
```

---

## 🔐 Use Cases

### Red Team / Penetration Testing
- Identify lateral movement vectors (Redis → T1021.006, Docker → T1611)
- Find exposed databases and cloud APIs
- Map findings to MITRE ATT&CK for professional reporting

### Blue Team / Incident Response
- Continuous monitoring with change detection
- Alert on new unauthorized services (possible backdoors)
- Historical trend analysis with SQLite queries

### DevOps / Site Reliability
- Monitor for unexpected services after deployments
- Container security auditing
- Track security posture improvements over time

---

## 🤝 Contributing

PRs and issues welcome! See the [Next Level Roadmap](BASH-TOOLS-NEXT-LEVEL-ROADMAP.md) for planned enhancements.

### Plugin Ideas
- Prometheus/Grafana metrics export
- Email/PagerDuty alerting
- Anomaly detection with baseline profiling
- Shodan/Censys integration
- Container/K8s deep scan

---

## ⚠️ Disclaimer

This tool is for **authorized security testing and monitoring only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

---

<p align="center">
  Built with 🧠 + 🛡️ by RedVortex — MIT License
</p>
