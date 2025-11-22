# RedVortex ⚡ Ethical Hacker & Web Penetration Tester
![RedVortex Badge](https://img.shields.io/badge/RedVortex%20⚡%20Ethical%20Hacker%20%26%20Web%20Penetration%20Tester-8A2BE2?style=for-the-badge&logo=security&logoColor=white)

## ✨ Overview

`PORT WATCHER` is a lightweight Bash script that:

- Lists all **LISTEN** ports on your system using `lsof`
- Shows the **Port**, **PID**, **User**, and **Process name**
- Assigns a **Risk Level** (🟢 LOW, 🟡 MEDIUM, 🔴 HIGH, ❓ UNKNOWN)  
  based on predefined common service ports
- Uses **colored output** to make it easier to quickly spot risky services

This is especially useful for:

- Quickly auditing exposed ports
- Checking what services are running and by which users
- Basic security hygiene and monitoring



## 📸 Example Output

```text
🔍 PORT WATCHER - Security Based Listing

|  PORT  |  PID  | USER | PROCESS | RISK LEVEL |
|  22    |  1234 | root | sshd    |  HIGH      |
|  80    |  2345 | www  | nginx   |  MEDIUM    |
|  53    |  3456 | root | named   |  LOW       |
|  9999  |  4567 | user | myapp   |  UNKNOWN   |
```

Color legend:
- 🟢 **LOW** → Common low-risk infra ports (DNS, DHCP, NTP, etc.)
- 🟡 **MEDIUM** → Web, mail, Windows services, RDP, etc.
- 🔴 **HIGH** → SSH, DBs, VNC, SIP, SNMP, etc.
- ❓ **UNKNOWN** → Port not in the predefined lists

---

## 🧩 How It Works

1. **Defines color codes** for pretty terminal output.
2. **`risk_checking()` function**:
   - Takes a port number
   - Checks if it’s in `low`, `medium`, or `high` arrays
   - Prints the corresponding colored risk level
3. Uses:
   - `lsof -i -P -n | grep LISTEN` to find all listening sockets
   - `awk` and `cut` to parse process, PID, user, IP, and port
4. Prints a neat, table‑style summary for each port.

---

## 🚀 Installation

```bash
# 1️⃣ Clone this repository
git clone https://github.com/anonymous777999/Bash-Tools.git
cd Bash-Tools

# 2️⃣ Make the script executable
chmod +x port-watcher.sh
```

## ▶️ Usage

Run the script with:

```bash
./port-watcher.sh
```

or directly with `bash`:

```bash
bash port-watcher.sh
```

> 🔐 **Note:** The script uses `sudo lsof`, so you might be prompted for your password.

---

## 📦 Requirements

- 🐧 Linux / macOS / any Unix-like system with:
  - `bash`
  - `lsof`
  - `awk`
  - `grep`
- A terminal that supports **ANSI color codes** (most modern terminals do)

---

## 🛠 Configuration (Optional)

You can edit the script to adjust risk levels:

```bash
low=(53 67 68 123 443 514 179 546 547 69)
medium=(80 25 110 445 3389 389 636 135 2000 2001 587 995)
high=(21 22 23 5900 5901 3306 6379 27017 5060 4786 161 162 445)
```

- Add or remove ports from any list as needed.
- Useful if your environment has special rules for what’s considered “risky”.

---

## 🧪 Quick Security Checklist

Use PORT WATCHER to:

- ✅ Verify only expected services are listening
- ✅ Check which user runs sensitive services (e.g., DB, SSH)
- ✅ Spot unexpected or unknown ports quickly
- ✅ Periodically audit servers for new or suspicious services

---

## 📜 Full Script

```bash
#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  🔐 Port Watcher - Security-Based Port Risk Analyzer         ║
# ║                                                              ║
# ║  🧑‍💻 Author     : RedVortex                                  ║
# ║  🛡️ Purpose    : Monitors open ports, shows associated       ║
# ║                  process, user, PID and categorizes risks.   ║
# ║                                                              ║
# ║  ⚔️ Security     : Rated as Low | Medium | High | Unknown     ║
# ║  📌 Features     :                                           ║
# ║     • Real-time port-to-process mapping                      ║
# ║     • Risk classification based on security exposures        ║
# ║     • Color-coded severity levels                            ║
# ║     • Uses lsof + native shell only                          ║
# ║                                                              ║
# ║  📅 Version     : 1.0                                        ║
# ║  🐧 Compatible  : Linux (Debian, Kali, Ubuntu, Arch, Fedora) ║
# ╚══════════════════════════════════════════════════════════════╝

# ━━━━━━━━━ COLOR DEFINITIONS ━━━━━━━━━ #
RESET="\e[0m"
BOLD="\e[1m"
BOLD_RED="\e[1;31m"
BOLD_GREEN="\e[1;32m"
BOLD_YELLOW="\e[1;33m"
BOLD_CYAN="\e[1;36m"
# ━━━━━━━━━ COLOR DEFINITIONS ━━━━━━━━━ #

risk_checking(){
    local port="$1"
    local low=(53 67 68 123 443 514 179 546 547 69)
    local medium=(80 25 110 445 3389 389 636 135 2000 2001 587 995)
    local high=(21 22 23 5900 5901 3306 6379 27017 5060 4786 161 162 445)

    for p in "${low[@]}"; do [[ "$p" == "$port" ]] && echo -e "${BOLD_GREEN}LOW${RESET}" && return; done
    for p in "${medium[@]}"; do [[ "$p" == "$port" ]] && echo -e "${BOLD_YELLOW}MEDIUM${RESET}" && return; done
    for p in "${high[@]}"; do [[ "$p" == "$port" ]] && echo -e "${BOLD_RED}HIGH${RESET}" && return; done
    echo -e "${BOLD_YELLOW}UNKNOWN${RESET}"
}

echo -e "${BOLD_CYAN}\n  🔍 PORT WATCHER - Security Based Listing\n${RESET}"
echo -e "${BOLD_YELLOW}|  PORT  |  PID  | USER | PROCESS | RISK LEVEL |${RESET}"

sudo lsof -i -P -n | grep LISTEN | awk '{print $1, $2, $3, $9}' | while read process pid user addr
do
    ip=$(echo $addr | cut -d':' -f1)
    port=$(echo $addr | cut -d':' -f2)
    [[ -z "$port" ]] && continue

    risk=$(risk_checking "$port")
    echo "|  $port  |  $pid  |  $user  |  $process  |  $risk  |"
done
```

---

## 🤝 Contributing

Contributions are welcome! 🎉

- Add more ports to the risk lists
- Improve output formatting
- Add flags (e.g., JSON output, filter by risk, etc.)

Feel free to open:
- 🐛 Issues
- 🔀 Pull Requests

---

## ⚠️ Disclaimer

This tool is meant for **basic security awareness and monitoring**, not as a full security scanner or vulnerability assessment tool.  
Always follow best practices and use proper security tools in production environments.

---

<p align="center">
  Made with 🧠 + 🛡️ in Bash
</p>
```
