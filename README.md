# 🔍 Port Watcher v2 — Advanced Security Port Risk Analyzer

![Version](https://img.shields.io/badge/version-2.0.0-22D3EE?style=flat-square&labelColor=0A101F)
![Shell](https://img.shields.io/badge/shell-bash-10B981?style=flat-square&logo=gnubash&logoColor=white&labelColor=0A101F)
![License](https://img.shields.io/badge/license-MIT-A78BFA?style=flat-square&labelColor=0A101F)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-22D3EE?style=flat-square&labelColor=0A101F)

**Port Watcher v2** is a professional security tool that monitors open ports on Linux systems, maps them to running processes/users/PIDs, and performs **dynamic risk scoring** based on multiple contextual factors — not just port number.

> Built by [RedVortex](https://github.com/anonymous777999) — Ethical Hacker & Security Researcher

---

## 🚀 Features

### Core Capabilities
- **Dynamic Risk Scoring** — Score = BASE(PORT) × USER_WEIGHT × BIND_WEIGHT × VERSION_WEIGHT
- **Full CLI** — 15+ flags for filtering, formatting, and automation
- **Dual-Stack** — Full IPv4 and IPv6 support (no more silently dropped IPv6 services)
- **Expanded Port DB** — 200+ ports across 9 categories (Web, Database, Cloud, Container, IoT, etc.)

### Output Formats
| Format | Use Case |
|--------|----------|
| **`--output table`** | Interactive terminal (default) |
| **`--output json`** | Machine parsing, API integration, SIEM |
| **`--output csv`** | Spreadsheets, reporting |
| **`--output html`** | Styled HTML report with dark hacker theme |

### Advanced Features
| Feature | Description |
|---------|-------------|
| **`--watch N`** | Real-time monitoring with change detection |
| **`--baseline`** | Save/compare against baseline for differential scans |
| **`--syslog`** | Forward findings to syslog for centralized monitoring |
| **`--config`** | External config file for customizable risk rules |
| **Risk filters** | `--risk`, `--port`, `--process`, `--user` |

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
# Default table output
sudo port-watcher

# JSON output (for automation/parsing)
sudo port-watcher --output json

# Filter by risk level
sudo port-watcher --risk CRITICAL

# Watch mode — refresh every 5 seconds with change detection
sudo port-watcher --watch 5

# HTML report
sudo port-watcher --output html --output-file report.html

# Custom config file
sudo port-watcher --config ./custom-ports.conf

# Differential scan against baseline
sudo port-watcher --baseline yesterday.json
sudo port-watcher --baseline yesterday.json   # Shows changes since yesterday

# Log findings to syslog
sudo port-watcher --syslog
```

---

## 📊 Dynamic Risk Scoring

Unlike simple port-checkers that classify risk by port number alone, Port Watcher v2 calculates a **contextual risk score**:

```
RISK_SCORE = BASE_PORT_RISK × USER_WEIGHT × BIND_WEIGHT × VERSION_WEIGHT
```

### Scoring Example

| Scenario | Port | User | Bind | Version | Score | Risk |
|----------|------|------|------|---------|-------|------|
| MySQL 5.7 exposed | 3306 | root | 0.0.0.0 | old | 43.2 | 🔴 CRITICAL |
| MySQL 8.0 localhost | 3306 | mysql | 127.0.0.1 | current | 0.96 | 🟢 LOW |
| SSH key-only | 22 | root | LAN | current | 7.5 | 🟡 MEDIUM |
| Redis no auth | 6379 | root | 0.0.0.0 | none | 24.0 | 🔴 HIGH |

**Same port, different risk** — because context matters.

---

## 🔧 Configuration

Copy the example config and customize:

```bash
mkdir -p ~/.config/port-watcher
cp config/ports.conf.example ~/.config/port-watcher/ports.conf
# Edit to add/remove ports, adjust scoring weights, etc.
```

Config supports:
- 9 risk categories (CRITICAL, HIGH, MEDIUM, LOW, CLOUD, DATABASE, CONTAINER, IOT, RESEARCH)
- Scoring weights for user type (root, known user, unknown)
- Scoring weights for network binding (ALL, LOCAL, LAN)
- Display settings (color, table style, timestamp)
- Alert thresholds

---

## 🛠 Installation

### Option 1: Makefile (Recommended)

```bash
sudo make install    # Installs to /usr/local/bin/
make install-local   # Installs to ~/.local/bin/
```

### Option 2: Manual

```bash
chmod +x src/port-watcher.sh
sudo cp src/port-watcher.sh /usr/local/bin/port-watcher
```

### Option 3: One-liner

```bash
curl -fsSL https://raw.githubusercontent.com/anonymous777999/Bash-Tools/main/install.sh | bash
```

### Requirements

- `bash` 4.0+
- `lsof` **or** `ss` (one required for port collection)
- `grep`, `awk` (standard Unix tools)

---

## 🧪 Example Output

```
╔═══════════════════════════════════════════════════════════════╗
║  🔍 PORT WATCHER v2.0.0 — 2026-07-29 04:36:15               ║
╚═══════════════════════════════════════════════════════════════╝

┌───────┬──────┬──────────┬──────────────────┬────────────┬──────────┐
│ PORT  │ PID  │ USER     │ PROCESS          │ BIND       │ RISK     │
├───────┼──────┼──────────┼──────────────────┼────────────┼──────────┤
│ 22    │ 1234 │ root     │ sshd             │ 0.0.0.0    │ HIGH     │
│ 80    │ 2345 │ www-data │ nginx            │ 0.0.0.0    │ MEDIUM   │
│ 5432  │ 3456 │ postgres │ postgres         │ 127.0.0.1  │ LOW      │
│ 6379  │ 4567 │ root     │ redis-server     │ 0.0.0.0    │ CRITICAL │
└───────┴──────┴──────────┴──────────────────┴────────────┴──────────┘
```

---

## 📋 Port Classification

| Category | Examples | Risk Level |
|----------|----------|------------|
| **CRITICAL** | SSH (22), MySQL (3306), Redis (6379), MongoDB (27017), RDP (3389), PostgreSQL (5432) | 🔴 |
| **HIGH** | HTTP (80), HTTPS (443), SMTP (25), LDAP (389), SNMP (161), SMB (445) | 🟠 |
| **MEDIUM** | DNS (53), DHCP (67), NTP (123), FTP (21 data) | 🟡 |
| **LOW** | CUPS (631), mDNS (5353), UPnP (1900) | 🟢 |
| **CLOUD/NATIVE** | Docker (2375), Kubernetes (6443, 10250), Vault (8200), Consul (8500) | 🔴 |
| **DATABASE** | MSSQL (1433), Oracle (1521), Cassandra (9042), Elasticsearch (9200) | 🔴 |
| **CONTAINER** | Docker API (2375), K8s kubelet (10250) | 🔴 |
| **IOT/SCADA** | Modbus (502), Siemens S7 (102), EtherNet/IP (44818) | 🟠 |

---

## 🔐 Use Cases

### Red Team / Penetration Testing
- Post-exploitation: identify lateral movement vectors
- Find exposed databases, management interfaces, and cloud APIs
- Discover privilege escalation paths (root-owned services on 0.0.0.0)

### Blue Team / Incident Response
- Continuous monitoring with change detection
- Alert on new unauthorized services (possible backdoors)
- Verify hardening compliance

### DevOps / Site Reliability
- Monitor for unexpected services after deployments
- Validate firewall rules are working
- Container security auditing

---

## 🤝 Contributing

PRs and issues welcome! Areas for contribution:
- Add more ports to risk categories
- Improve output format parsers
- Add Prometheus/Grafana metrics output
- Add email/webhook alerting
- Add Docker container scanning support

---

## ⚠️ Disclaimer

This tool is for **authorized security testing and monitoring only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

---

<p align="center">
  Built with 🧠 + 🛡️ by RedVortex — MIT License
</p>
