#!/bin/bash
# ==============================
# Pro Bash Recon & Port Scanner
# Features:
# - Multi-port scan
# - SSL CN/SAN extraction
# - HTTP redirect handling (multi)
# - VHost fuzzing with discovered hosts
# - Basic service checks: FTP, SMB, Docker, Redis, K8S
# - /etc/hosts suggestions
# - Recon summary with next steps
# ==============================

###################### TODO #########################
# Fix Bash Concurrency Safety (CRITICAL)
#
# Add --top-ports / --full Scan Modes
#     --top-ports     current list (default)
#     --full          add common high ports
#     --web           web-only ports
#
# Structured Output Sections (Readability)
#
# Normalize Color Semantics (I Defined Them—Use Them)
#   Right now:
#    GREEN = open
#    YELLOW = interesting
#    RED = dangerous
#   But:
#    Some [i] messages use RED and Some warnings use YELLOW
#  Create wrappers:
#    info()     # blue
#    finding()  # yellow
#    risk()     # red
#    success()  # green
#
# CVE Hints → MITRE ATT&CK Mapping
#  Port 445 → SMB relay
#    ATT&CK: T1557, T1021.002
#
# Auto-Suggest Exploitation Paths (Still Safe)
#  [SMB + LDAP + Kerberos]
#    → Likely Active Directory
#    → Try AS-REP roast → SMB → WinRM
#
# Align output with OSCP-style methodology
#######################################################


set -euo pipefail

START_TIME=$(date +%s)

DEFAULT_TARGET="127.0.0.1"
TARGET=""
ENABLE_VHOST=false
ENABLE_KERB_ENUM=false
KERBEROS_FOUND=false
LDAP_FOUND=false
LDAP_ENUM_DONE=false
LDAP_ANON_BIND=false
LDAP_BASE_DN=""
LDAP_DOMAIN=""
SMB_FOUND=false
SMB_ENUM_DONE=false
NO_COLOR=false

# --------- Concurrency ----------
MAX_JOBS=20

# --------- Colors ----------
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
RESET="\033[0m"

# --------- Temporary Files ----------
HINT_FILE=$(mktemp)
HOSTS_FILE=$(mktemp)
DISCOVERED_HOSTS=$(mktemp)
REDIRECT_HOSTS=$(mktemp)
HTTP_MARKER=$(mktemp)
HTTPS_MARKER=$(mktemp)
SMB_MARKER=$(mktemp)
KERB_MARKER=$(mktemp)
LDAP_MARKER=$(mktemp)
OPEN_PORTS_FILE=$(mktemp)

trap 'rm -f "$HINT_FILE" "$HOSTS_FILE" "$DISCOVERED_HOSTS" "$REDIRECT_HOSTS" \
          "$HTTP_MARKER" "$HTTPS_MARKER" "$SMB_MARKER" "$KERB_MARKER" "$LDAP_MARKER" \
          "$OPEN_PORTS_FILE"' EXIT

# --------- Argument Parsing ----------
for arg in "$@"; do
    case "$arg" in
        --no-color) NO_COLOR=true ;;
        --vhost) ENABLE_VHOST=true ;;
        --kerb-enum) ENABLE_KERB_ENUM=true ;;
        *) [ -z "$TARGET" ] && TARGET="$arg" ;;
    esac
done

[ -z "$TARGET" ] && TARGET="$DEFAULT_TARGET" && echo "[i] No IP provided — defaulting to $TARGET"

$NO_COLOR && GREEN="" YELLOW="" RED="" BLUE="" RESET=""

# 🔥  High risk
# 💥  Critical exposure
# ☠   Dangerous
# 🚨  Alert
# 🛠  Tooling
# ⚙   Configuration
# 📌  Note
# ➡   Next step

# --------- Icons (UTF-8 with ASCII fallback) ----------
ICON_OK="✔"
ICON_WARN="⚠"
ICON_INFO="ℹ"
ICON_RISK="🔥"
ICON_ALERT="🚨"
ICON_CRIT="💥"
ICON_SCAN="🔍"
ICON_SHARE="📁"
ICON_WEB="🌐"
ICON_USER="👤"

# ASCII fallback for non-UTF8 terminals
if [[ "${LANG:-}" != *UTF-8* && "${LC_ALL:-}" != *UTF-8* ]]; then
    ICON_OK="[+]"
    ICON_WARN="[!]"
    ICON_INFO="[i]"
    ICON_RISK="[!!]"
    ICON_ALERT="[?]"
    ICON_CRIT="[!!!]"
    ICON_SCAN="[scan]"
    ICON_SHARE="[share]"
    ICON_WEB="[web]"
    ICON_USER="[user]"
fi

echo "Legend:"
echo "---------------------------"
echo "  $ICON_OK   Open / Success"
echo "  $ICON_WARN   Interesting / Needs Review"
echo "  $ICON_RISK  High-Risk Exposure"
echo "  $ICON_INFO   Informational"
echo "  $ICON_SCAN  Scanning / Enumeration"
echo "  $ICON_SHARE  File Shares / Storage"
echo "  $ICON_WEB  Web Services"
echo "  $ICON_USER  Users / Identities"
echo "---------------------------"

# --------- Message Helpers ----------
info()      { echo -e "${BLUE}ℹ ${RESET} $*"; }
success()   { echo -e "${GREEN}✔ ${RESET} $*"; }
notify()    { echo -e "${YELLOW}⚠ ${RESET} $*"; }
note()      { echo -e "${BLUE}📌 ${RESET} $*"; }
finding()   { echo -e "${YELLOW}[?] ${RESET} $*"; }
warn()      { echo -e "${RED}✖ ${RESET} $*"; }
risk()      { echo -e "${RED}[!] ${RESET} $*"; }
high_risk() { echo -e "${RED}🔥 ${RESET} ${RED}$*${RESET}"; }
critical()  { echo -e "${RED}💥 ${RESET} ${RED}$*${RESET}"; }
danger()    { echo -e "${RED}☠ ${RESET} $*"; }
alert()     { echo -e "${RED}🚨 ${RESET} $*"; }

# --------- SSL Certificate Extraction ----------
extract_ssl_info() {
    local host="$1"
    command -v openssl >/dev/null 2>&1 || return

    cert=$(timeout 4 openssl s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null)
    [ -z "$cert" ] && return

    cn=$(echo "$cert" | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*CN=//p')
    sans=$(echo "$cert" | openssl x509 -noout -ext subjectAltName 2>/dev/null \
        | sed -n 's/.*DNS://p' | tr ',' '\n' | sed 's/^[[:space:]]*//')

    [ -n "$cn" ] && {
        echo -e "${YELLOW}[i] SSL CN: $cn${RESET}"
        echo "$TARGET $cn" >> "$HOSTS_FILE"
        echo "$cn" >> "$DISCOVERED_HOSTS"
    }

    if [ -n "$sans" ]; then
        echo -e "${YELLOW}[i] SSL SANs:${RESET}"
        echo "$sans" | while read san; do
            [ -n "$san" ] && {
                echo -e "${YELLOW}    - $san${RESET}"
                echo "$TARGET $san" >> "$HOSTS_FILE"
                echo "$san" >> "$DISCOVERED_HOSTS"
            }
        done
    fi
}

getnpusers_cmd() {
    if command -v impacket-GetNPUsers >/dev/null 2>&1; then
        echo "impacket-GetNPUsers"
    elif command -v GetNPUsers.py >/dev/null 2>&1; then
        echo "GetNPUsers.py"
    else
        return 1
    fi
}
cme_enum_users() {
    local AUTH_LABEL="$1"
    local CME_ARGS="$2"

    command -v crackmapexec >/dev/null 2>&1 || return 1

    info "Enumerating SMB users via crackmapexec ($AUTH_LABEL)..."

    OUTPUT=$(crackmapexec smb "$TARGET" $CME_ARGS --users 2>/dev/null \
        | awk '/^[^ ]+\\[^ ]+/ {print $1}' \
        | sed 's/.*\\//' \
        | sort -u)

    [ -z "$OUTPUT" ] && return 1
    warn "SMB user enumeration possible ($AUTH_LABEL)"
    echo -e "   ${YELLOW}Users Discovered:${RESET}"

    echo "$OUTPUT" | while read -r user; do
        echo "      - $user"
    done

    return 0
}

ldap_enum() {
    command -v ldapsearch >/dev/null 2>&1 || {
        warn "ldapsearch not found — skipping LDAP enumeration"
        return
    }

    echo
    info "LDAP detected — starting safe LDAP enumeration"

    # Prefer LDAP over LDAPS for anon checks, fallback if needed
    if echo "$OPEN_PORTS_FILE" | grep -q '^636$'; then
        LDAP_URI="ldaps://$TARGET"
    else
        LDAP_URI="ldap://$TARGET"
    fi

    # -------- RootDSE --------
    info "Querying LDAP RootDSE"

    LDAP_BASE_DN=$(ldapsearch -x -H "$LDAP_URI" -s base -b "" defaultNamingContext 2>/dev/null \
        | sed -n 's/^defaultNamingContext:[[:space:]]*//p')

    if [[ ! "$LDAP_BASE_DN" =~ ^DC= ]]; then
        notify "LDAP present but naming context not disclosed"
        return
    fi

    LDAP_DOMAIN=$(echo "$LDAP_BASE_DN" | sed 's/DC=//g; s/,/./g')

    success "LDAP domain identified: $LDAP_DOMAIN"
    note "Base DN: $LDAP_BASE_DN"

    echo "$TARGET $LDAP_DOMAIN" >> "$HOSTS_FILE"

    # -------- Anonymous Bind Test --------
    info "Testing anonymous LDAP bind"

    if ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" -s base "(objectClass=*)" \
        >/dev/null 2>&1; then
        critical "Anonymous LDAP bind allowed"
        LDAP_ANON_BIND=true
    else
        notify "Anonymous bind not permitted"
        return
    fi

    # -------- Domain Info --------
    info "Enumerating domain password policy"

    ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(objectClass=domainDNS)" \
        minPwdLength lockoutThreshold maxPwdAge 2>/dev/null \
        | sed 's/^/    /'

    # -------- Users --------
    info "Enumerating users"

    ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(&(objectClass=user)(!(objectClass=computer)))" \
        sAMAccountName userPrincipalName 2>/dev/null \
        | awk '/^sAMAccountName:/ {print "    - "$2}'

    # -------- Groups --------
    info "Enumerating groups"

    ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(objectClass=group)" cn 2>/dev/null \
        | awk '/^cn:/ {print "    - "$2}'

    # -------- Computers --------
    info "Enumerating computers"

    ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(objectClass=computer)" dNSHostName 2>/dev/null \
        | awk '/^dNSHostName:/ {print "    - "$2}'

    # -------- LAPS --------
    info "Checking for LAPS exposure"

    ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwdExpirationTime 2>/dev/null \
        | grep -q ms-MCS-AdmPwd && \
        critical "LAPS attributes readable (HIGH RISK)"

    # -------- Delegation / SPNs --------
    info "Searching for Kerberos SPNs"

    ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(servicePrincipalName=*)" servicePrincipalName sAMAccountName 2>/dev/null \
        | awk '/^sAMAccountName:/ {print "    - "$2}'

    # -------- Optional ldapdomaindump --------
    if command -v ldapdomaindump >/dev/null 2>&1; then
        info "Running ldapdomaindump (read-only)"
        mkdir -p ldap_dump_$TARGET
        ldapdomaindump -u '' -p '' -o ldap_dump_$TARGET "$LDAP_URI" >/dev/null 2>&1 && \
            success "ldapdomaindump completed (ldap_dump_$TARGET)"
    fi

    LDAP_ENUM_DONE=true
}


# --------- Ports ----------
PORTS=(
    "21:FTP:interesting"
    "22:SSH:open"
    "23:Telnet:high"
    "25:SMTP:interesting"
    "53:DNS:open"
    "80:HTTP:open"
    "88:Kerberos:high"
    "110:POP3:interesting"
    "111:RPCBind:interesting"
    "135:MSRPC:high"
    "139:SMB:high"
    "143:IMAP:interesting"
    "389:LDAP:interesting"
    "443:HTTPS:open"
    "445:SMB:high"
    "515:PRINTER:open"
    "631:PRINTER:open"
    "636:LDAPS:interesting"
    "993:IMAPS:interesting"
    "1433:SQL Server:high"
    "2375:Docker API:high"
    "2377:Docker Swarm:interesting"
    "3000:Web Dev:interesting"
    "3306:MySQL:interesting"
    "3389:RDP:high"
    "5000:Web/Docker:interesting"
    "5985:WinRM:high"
    "5986:WinRM HTTPS:interesting"
    "6379:Redis:high"
    "6443:Kubernetes API:high"
    "8080:HTTP-Alt:interesting"
    "8443:HTTPS-Alt:interesting"
    "9090:Web:interesting"
    "9100:PRINTER:interesting"
    "27017:MongoDB:interesting"
    "54925:BROTHER_PRINTER:open"
)

# --------- CVE / Attack Surface Hints ----------
declare -A CVE_HINTS=(
  [21]="Anonymous FTP, writable dirs, legacy backdoors (CVE-2015-3306)"
  [22]="Weak creds, outdated OpenSSH, user enumeration (CVE-2018-15473)"
  [23]="Cleartext auth, legacy devices, credential reuse"
  [25]="Open relay, user enumeration, Exim RCE (CVE-2019-10149)"
  [53]="Zone transfer (AXFR), DNS recursion"
  [80]="Web vulns: file upload, auth bypass, outdated CMS"
  [88]="Kerberos roasting, AD misconfig, pre-auth disabled"
  [110]="Cleartext POP3, weak creds"
  [139]="SMB NULL session, EternalBlue class issues"
  [389]="Anonymous LDAP bind, domain info disclosure"
  [443]="TLS misconfig, weak ciphers, web vulns"
  [445]="SMB relay, signing disabled, MS17-010"
  [631]="CUPS info leak, printer RCE class issues"
  [1433]="MSSQL auth abuse, xp_cmdshell exposure"
  [2375]="Unauth Docker API → container escape risk"
  [3000]="Dev panels, default creds, debug mode"
  [3306]="Weak DB creds, data exposure"
  [3389]="RDP brute-force, BlueKeep (CVE-2019-0708)"
  [5985]="WinRM lateral movement, credential reuse"
  [6379]="Unauth Redis → file write / RCE"
  [6443]="K8s API anonymous access"
  [8080]="Admin consoles, exposed dashboards"
  [9100]="Raw printer protocol info disclosure"
  [27017]="Unauth MongoDB data exposure"
)

print_cve_hint() {
    local port="$1"
    if [[ -n "${CVE_HINTS[$port]:-}" ]]; then
        echo -e "  - ${CVE_HINTS[$port]}"
    fi
}

# --------- After port scanning completes ----------
OPEN_PORTS=()   # Will store open ports

# =========================================================
# ================= SCRIPT START ==========================
# =========================================================
echo
echo -e "${BLUE}========================================${RESET}"
echo -e "${BLUE} Educational Recon Mode ${RESET}"
echo -e "${BLUE}----------------------------------------${RESET}"
echo "  • Authorized environments only (training & lab)"
echo "  • No exploitation performed automatically"
echo "  • Output provides learning-oriented next steps"
echo -e "${BLUE}========================================${RESET}"
echo

# --------- Function to Scan a Single Port ----------
# ---------- PORT SCAN LOOP ----------
for ENTRY in "${PORTS[@]}"; do # ---- MAX_JOBS throttle ----
    while (( $(jobs -rp | wc -l) >= MAX_JOBS )); do
        sleep 0.05
    done
(
    IFS=: read PORT SERVICE LEVEL <<< "$ENTRY"
    timeout 2 bash -c "echo >/dev/tcp/$TARGET/$PORT" 2>/dev/null || exit
    
    #Add Port to Open Ports Array
    #OPEN_PORTS+=("$PORT")
    echo "$PORT" >> "$OPEN_PORTS_FILE"
    
    case "$LEVEL" in
        high) COLOR=$RED ;;
        interesting) COLOR=$YELLOW ;;
        *) COLOR=$GREEN ;;
    esac

    #echo -e "${COLOR}[+] Port $PORT OPEN ($SERVICE)${RESET}"
    success "Port $PORT OPEN ($SERVICE)"
    

    case "$PORT" in
        80|8080|3000|5000) echo http >> "$HTTP_MARKER" ;;
        443|8443) echo https >> "$HTTPS_MARKER" ;;
        21) echo "FTP" >> "$HINT_FILE" ;;
        139|445) echo "SMB" >> "$HINT_FILE"; echo "$PORT" >> "$SMB_MARKER" ;;
        88) echo "KERBEROS" >> "$HINT_FILE"; KERBEROS_FOUND=true; echo "$PORT" >> "$KERB_MARKER" ;;
        389|636) echo "LDAP" >> "$HINT_FILE" ; echo "$PORT" >> "$LDAP_MARKER" ;;
        6379) echo "REDIS" >> "$HINT_FILE" ;;
        2375) echo "DOCKER" >> "$HINT_FILE" ;;
        6443) echo "K8S" >> "$HINT_FILE" ;;
        3389) echo "RDP" >> "$HINT_FILE" ;;
        5985) echo "WINRM" >> "$HINT_FILE" ;;
        3306|1433) echo "DB" >> "$HINT_FILE" ;;
        80|443|8080|8443) echo "WEB" >> "$HINT_FILE" ;;
    esac

    # HTTP Redirect Discovery
    if [[ "$PORT" =~ ^(80|8080|3000)$ ]] && command -v curl >/dev/null; then
        redirect=$(curl -sI --max-time 3 "http://$TARGET:$PORT" \
            | awk -F': ' 'tolower($1)=="location"{print $2}' | tr -d '\r')

        if [ -n "$redirect" ]; then
            if [[ "$redirect" =~ ^(https?:)?// ]]; then
                host=$(echo "$redirect" | sed -E 's#^(https?:)?//([^/]+).*#\2#')
                echo "$TARGET $host" >> "$HOSTS_FILE"
                echo "$host" >> "$REDIRECT_HOSTS"
                echo -e "${YELLOW}[i] HTTP redirect → $redirect${RESET}"
            fi
        fi
    fi
    
    #  Kerberos Check
    if [ "$PORT" = "88" ]; then
        echo -e "  ${YELLOW}[i] Kerberos service detected${RESET}"

	if $ENABLE_KERB_ENUM; then
	    KERB_CMD=$(getnpusers_cmd 2>/dev/null || true)

	    if [ -n "$KERB_CMD" ]; then
		echo -e "  [i] Running safe Kerberos user enumeration..."

		COMMON_USERS=( administrator admin guest krbtgt test backup
			svc svc_backup svc_sql svc_mssql svc_web svc_app svc_ldap
			sqlsvc mssql exchange iis websvc appsvc backupsvc veeam
			student lab training )

		for user in "${COMMON_USERS[@]}"; do
		    timeout 3 $KERB_CMD "$TARGET/$user" -no-pass 2>&1 \
		        | grep -qi 'preauth' && \
		        notify "    Valid Kerberos user: ${GREEN}$user${RESET}"
		done
	    else
		echo -e "  ${YELLOW}[i] Kerberos enum requested, but impacket GetNPUsers not found${RESET}"
		echo -e "      ${YELLOW}Install: sudo apt install impacket-scripts${RESET}"
	    fi
	fi
    fi
    
    # -------- LDAP / LDAPS Domain Detection --------
    if [[ "$PORT" == "389" || "$PORT" == "636" ]] && command -v ldapsearch >/dev/null; then
        
        info "Querying LDAP RootDSE..."

        if [ "$PORT" = "389" ]; then
		LDAP_URI="ldap://$TARGET"
        else
		LDAP_URI="ldaps://$TARGET"
        fi

        ldap_dn=$(
		ldapsearch -x -H "$LDAP_URI" -s base -b "" defaultNamingContext 2>/dev/null \
		| sed -n 's/^defaultNamingContext:[[:space:]]*//p'
	    )

        if [[ "$ldap_dn" =~ ^DC= ]]; then
		ldap_domain=$(echo "$ldap_dn" | sed 's/DC=//g; s/,/./g')
		
		note "LDAP domain detected: ${GREEN}$ldap_domain${RESET}"

		echo "$TARGET $ldap_domain" >> "$HOSTS_FILE"
		echo "$ldap_domain" >> "$DISCOVERED_HOSTS"
		echo "LDAP" >> "$HINT_FILE"
		echo "KERBEROS" >> "$HINT_FILE"
        else
		info "LDAP service present/open but DOMAIN not disclosed"
        fi
    fi
    
    # Get Cert Info
    [ "$PORT" = "636" ] && extract_ssl_info $TARGET
    [ "$PORT" = "443" ] && extract_ssl_info $TARGET

    if [ "$PORT" = "6379" ] && command -v redis-cli >/dev/null; then
        if redis-cli -h "$TARGET" ping 2>/dev/null | grep -qi PONG; then
        	critical "Redis unauthenticated"
	fi
    fi

    if [ "$PORT" = "2375" ] && command -v curl >/dev/null; then
        if curl -s "http://$TARGET:2375/containers/json" | grep -q '^\['; then
        	critical "Unauthenticated Docker API (CVE-2025-9074)"
	fi
    fi
) &
done

wait

# --------- Reconstruct OPEN_PORTS safely ----------
OPEN_PORTS=()
if [ -s "$OPEN_PORTS_FILE" ]; then
    mapfile -t OPEN_PORTS < <(sort -n "$OPEN_PORTS_FILE")
fi

# --------- Debug / Visibility ----------
if [ "${#OPEN_PORTS[@]}" -gt 0 ]; then
    echo
    info "Open ports detected: ${OPEN_PORTS[*]}"
    echo
    info "CVE / Attack Surface Hints:"
    for port in "${OPEN_PORTS[@]}"; do
        print_cve_hint "$port"
    done
else
    warn "No open ports detected"
fi

echo
echo "Running Post-Scan Service Exposure Checks"
echo "---------------------------------------------------"


# --------- FTP Anonymous Check (post-scan) ----------
if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "21"; then
    if command -v ftp >/dev/null; then
        echo
        info "FTP detected — checking anonymous access"

        if echo -e "user anonymous\npass anonymous\nquit" \
            | timeout 5 ftp -n "$TARGET" 2>/dev/null \
            | grep -qi "^230"; then

            critical "Anonymous FTP login allowed"
        else
            notify "Anonymous FTP login not permitted"
        fi
    else
        warn "FTP client not installed — skipping anonymous FTP check"
    fi
fi

# --------- SMB Enumeration (only if 139 or 445 is open) ----------
SMB_NULL_OK=false
SMB_GUEST_OK=false

if [ -s "$SMB_MARKER" ]; then
    echo
    info "SMB ports detected (139/445) — enumerating shares & permissions..."

    SMB_ENUM_SUCCESS=false

    color_perm() {
        local val="$1"
        if [ "$val" = "yes" ]; then
            echo -e "${GREEN}yes${RESET}"
        else
            echo -e "${RED}no${RESET}"
        fi
    }

    # -------- smbclient enumeration (NULL + GUEST explicitly) --------
    smb_enum_smbclient() {
        local AUTH="$1"
        local LABEL="$2"

        SHARES=$(smbclient -L "//$TARGET" -U "$AUTH" 2>/dev/null \
            | awk '$2 == "Disk" { print $1 }')

        [ -z "$SHARES" ] && return 1

        critical "  SMB allows $LABEL access"
        notify "  $ICON_SHARE SMB shares ($LABEL):"

        for share in $SHARES; do
            [[ "$share" =~ ^(IPC\$|ADMIN\$)$ ]] && continue

            smbclient "//$TARGET/$share" -U "$AUTH" -c "ls" >/dev/null 2>&1 \
                && READ="yes" || READ="no"

            smbclient "//$TARGET/$share" -U "$AUTH" -c "put /dev/null test_$$_tmp" >/dev/null 2>&1 \
                && WRITE="yes" || WRITE="no"

            echo -e "      - $share [read=$(color_perm "$READ") write=$(color_perm "$WRITE")]"
        done

        SMB_ENUM_SUCCESS=true
        [ "$LABEL" = "NULL session" ] && SMB_NULL_OK=true
        [ "$LABEL" = "GUEST" ] && SMB_GUEST_OK=true
    }

    # -------- smbmap fallback --------
    smb_enum_smbmap() {
        local LABEL="$1"
        local SMBMAP_ARGS="$2"

        command -v smbmap >/dev/null 2>&1 || return 1

        OUTPUT=$(smbmap -H "$TARGET" $SMBMAP_ARGS 2>/dev/null \
            | awk '
                /^[A-Za-z0-9_$-]+[[:space:]]+(READ|WRITE|READ,WRITE|NO)/ {
                    print $1, $2
                }
            ')

        [ -z "$OUTPUT" ] && return 1

        critical "  SMB allows $LABEL access"
        notify "  $ICON_SHARE SMB shares ($LABEL):"

        echo "$OUTPUT" | while read -r share perms; do
            [[ "$share" =~ ^(IPC\$|ADMIN\$)$ ]] && continue

            perms=$(echo "$perms" | tr '[:upper:]' '[:lower:]')
            [[ "$perms" =~ read ]] && READ="yes" || READ="no"
            [[ "$perms" =~ write ]] && WRITE="yes" || WRITE="no"

            echo -e "      - $share [read=$(color_perm "$READ") write=$(color_perm "$WRITE")]"
        done

        SMB_ENUM_SUCCESS=true
        [ "$LABEL" = "NULL session" ] && SMB_NULL_OK=true
        [ "$LABEL" = "GUEST" ] && SMB_GUEST_OK=true
    }

    # -------- Auth Attempts (ORDER MATTERS) --------
    # 1) True NULL session
    smb_enum_smbclient "%" "NULL session" || true

    # 2) Guest with empty password (matches CME behavior)
    smb_enum_smbclient "guest%" "GUEST" || true

    # -------- Fallback to smbmap --------
    if ! $SMB_ENUM_SUCCESS; then
        info "smbclient yielded no shares — trying smbmap fallback..."
        smb_enum_smbmap "NULL session" "" || true
        smb_enum_smbmap "GUEST" "-u guest -p ''" || true
    fi

    # -------- CME Enumeration --------
    if command -v crackmapexec >/dev/null 2>&1; then
        info "SMB Shares Detected!"
        info "  Attempting to Enumerate Access..."

        if $SMB_NULL_OK; then
            cme_enum_users "NULL session" "" || true
        fi

        if $SMB_GUEST_OK; then
            cme_enum_users "GUEST" "-u guest -p ''" || true
        fi
    fi

    # -------- CME RID Brute (CRITICAL if Guest allowed) --------
    if command -v crackmapexec >/dev/null 2>&1 && $SMB_GUEST_OK; then
        echo
        critical "SMB RID brute-force possible as GUEST with NoPassword (DOMAIN USER ENUMERATION)"

        info "Running crackmapexec RID brute (safe enumeration)..."

        RID_OUTPUT=$(crackmapexec smb "$TARGET" -u guest -p '' --rid-brute 2>/dev/null)

        USERS=$(echo "$RID_OUTPUT" | awk -F'\\\\' '
             /SidTypeUser/ && !/\$/ {
                 split($2,a," ")
                 print a[1]
             }' | sort -u)

        if [ -n "$USERS" ]; then
            # Timestamped users file (always unique)
            DATE_TAG=$(date +"%Y%m%d_%H%M%S")
            USERS_FILE="users_${TARGET}_${DATE_TAG}.txt"

            notify "Discovered domain users via RID brute:"
            for user in $USERS; do
                echo "      - $user"
                echo "$user" >> "$USERS_FILE"
            done

            note "User list saved to: ${GREEN}$USERS_FILE${RESET}"

            # Feed recon hints
            echo "KERBEROS" >> "$HINT_FILE"
            echo "LDAP" >> "$HINT_FILE"
        else
            notify "RID brute completed, but no users parsed"
        fi
    fi

    # -------- No Shares Found Case --------
    if ! $SMB_ENUM_SUCCESS; then
        info "No SMB Shares Detected. Maybe retry with user creds?"
    fi
fi


# --------- LDAP Enumeration ----------
if [ -s "$LDAP_MARKER" ] && ! $LDAP_ENUM_DONE; then
    ldap_enum
fi

# -------- Kerberos Reminder --------
if [[ -s "$KERB_MARKER" && "$ENABLE_KERB_ENUM" == false ]]; then
    echo
    alert "${BLUE}Tip:${RESET} Kerberos detected"
    echo "  ----------------------------"
    echo "    Re-run with --kerb-enum to attempt safe user enumeration"
    echo "    Example:"
    echo "      ./bash_simpleportscan.sh $TARGET --kerb-enum"
fi

# --------- Detect HTTP/HTTPS availability ----------
HTTP_FOUND=false
HTTPS_FOUND=false
[ -s "$HTTP_MARKER" ] && HTTP_FOUND=true
[ -s "$HTTPS_MARKER" ] && HTTPS_FOUND=true
rm -f "$HTTP_MARKER" "$HTTPS_MARKER"

# --------- Merge redirect hosts ----------
[ -s "$REDIRECT_HOSTS" ] && sort -u "$REDIRECT_HOSTS" >> "$DISCOVERED_HOSTS"

# --------- VHost Fuzzing ----------
if $ENABLE_VHOST && [ -s "$DISCOVERED_HOSTS" ] && command -v curl >/dev/null; then
    echo
    echo -e "${YELLOW}[i]${RESET} Running VHost fuzzing..."

    COMMON_VHOSTS=(admin api dev test staging beta internal portal dashboard)
    [ "$HTTP_FOUND" = true ] && BASE_HTTP_LEN=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" "http://$TARGET")
    [ "$HTTPS_FOUND" = true ] && BASE_HTTPS_LEN=$(curl -ks -o /dev/null -w "%{http_code}:%{size_download}" "https://$TARGET")

    sort -u "$DISCOVERED_HOSTS" | grep -v '^$' | while read base; do
        echo -e "    [~] Fuzzing base domain: $base"
        for word in "${COMMON_VHOSTS[@]}"; do
            vhost="$word.$base"
            if [ "$HTTP_FOUND" = true ]; then
                len=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -H "Host: $vhost" "http://$TARGET")
                [ "$len" != "$BASE_HTTP_LEN" ] && echo -e "${YELLOW}      [+] Possible HTTP VHost: $vhost${RESET}" && echo "$TARGET $vhost" >> "$HOSTS_FILE"
            fi
            if [ "$HTTPS_FOUND" = true ]; then
                len=$(curl -ks -o /dev/null -w "%{http_code}:%{size_download}" -H "Host: $vhost" "https://$TARGET")
                [ "$len" != "$BASE_HTTPS_LEN" ] && echo -e "${YELLOW}      [+] Possible HTTPS VHost: $vhost${RESET}" && echo "$TARGET $vhost" >> "$HOSTS_FILE"
            fi
        done
    done
fi

# ---------- /etc/hosts suggestions ----------
if [ -s "$HOSTS_FILE" ]; then

    # Load ALL existing hostnames from /etc/hosts (columns 2..N)
    mapfile -t EXISTING_DOMAINS < <(
        awk '$1 !~ /^#/ { for (i=2; i<=NF; i++) print $i }' /etc/hosts | sort -u
    )

    MISSING=false
    MISSING_LINES=()

    while read -r entry; do
        entry=$(echo "$entry" | xargs)
        IP=$(awk '{print $1}' <<< "$entry")
        DOMAIN=$(awk '{print $2}' <<< "$entry")

        if [[ ! " ${EXISTING_DOMAINS[*]} " =~ " $DOMAIN " ]]; then
            MISSING=true
            MISSING_LINES+=("echo '$IP $DOMAIN' | sudo tee -a /etc/hosts")
        fi
    done < <(sort -u "$HOSTS_FILE")

    # ONLY print anything if something is actually missing
    if $MISSING; then
        echo
        alert "${BLUE}Tip:${RESET} /etc/hosts suggestions:"
        echo "  ----------------------------"
        for line in "${MISSING_LINES[@]}"; do
            echo "    $line"
        done
    fi
fi

# --------- Recon Summary & Next Steps ----------
echo
echo -e "${BLUE}============================${RESET}"
echo -e "${BLUE}Recon Summary & Next Steps${RESET}"
echo -e "${BLUE}============================${RESET}"

sort -u "$HINT_FILE" | while read HINT; do
    case "$HINT" in
        DOCKER)
cat <<EOF
[Docker API]
  - Review container mounts and bind volumes
  - Check for privileged containers
  - Inspect images for credentials or SSH keys
EOF
        ;;
        K8S)
cat <<EOF
[Kubernetes API]
  - Test anonymous access to /version and /api
  - Enumerate namespaces and pods
  - Look for exposed service account tokens
EOF
        ;;
        SMB)
cat <<EOF
[SMB]
  - Enumerate shares and permissions
  - Check for anonymous or guest access
  - Search for configuration files or backups
  - Tools: smbclient, crackmapexec, enum4linux-ng, nxc, smbmap, responder
EOF
        ;;
        KERBEROS)
cat <<EOF
[Kerberos / Active Directory]
  - Likely Windows domain controller
  - Identify realm and domain name
  - Enumerate users via Kerberos pre-auth
  - Attempt AS-REP roasting if pre-auth disabled (impacket-GetNPUsers, kerbrute, Rubeus)
  - Combine with LDAP/SMB/WinRM
  - Tools: impacket-GetNPUsers, kerbrute, kinit, impacket
EOF
	;;
        LDAP)
cat <<EOF
[LDAP]
  - Anonymous bind allowed → full directory disclosure
  - Harvest users for:
      • Kerberos roasting
      • SMB / WinRM auth attempts
  - Check for:
      • LAPS password exposure
      • Kerberoastable SPNs
      • Delegation misconfigurations
  - Tools:
      ldapsearch, ldapdomaindump, bloodhound-python
EOF
	;;
        RDP)
cat <<EOF
[RDP]
  - Identify valid usernames
  - Check for weak or reused credentials
  - Inspect NLA configuration
EOF
        ;;
        DB)
cat <<EOF
[Databases]
  - Identify database versions
  - Check authentication requirements
  - Test for default or weak credentials
  - Tools: nxc, sqlmap
EOF
        ;;
        DNS)
cat <<EOF
[DNS]
  - Attempt zone transfers (AXFR)
  - Enumerate subdomains
EOF
        ;;
        WINRM)
cat <<EOF
[WinRM]
  - Check for valid domain or local users
  - Look for credential reuse
  - Combine with SMB, MSSQL, or LDAP findings
  - Tools: evil-winrm
EOF
        ;;
        WEB)
cat <<EOF
[Web Services]
  - Fingerprint applications and frameworks
  - Enumerate directories and APIs
  - Look for admin panels or debug endpoints
  - Look for subdomains
  - Tools: dirbuster, ffuf
EOF
        ;;
        REDIS)
cat <<EOF
[Redis]
  - Test CONFIG GET *
  - Look for writable directories
  - Attempt SSH key injection
EOF
        ;;
    esac
done

# --------- Cleanup ----------
rm -f "$HINT_FILE" "$HOSTS_FILE" "$DISCOVERED_HOSTS" "$REDIRECT_HOSTS" "$KERB_MARKER"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo
success "Scan completed in ${DURATION}s"

echo
echo "Scan complete."

