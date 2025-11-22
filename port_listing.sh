#!/bin/bash
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
    echo -e "${BOLD_RED}UNKNOWN${RESET}"
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


