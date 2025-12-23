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
OPEN_PORTS_FILE=$(mktemp)

trap 'rm -f "$HINT_FILE" "$HOSTS_FILE" "$DISCOVERED_HOSTS" "$REDIRECT_HOSTS" \
          "$HTTP_MARKER" "$HTTPS_MARKER" "$SMB_MARKER" "$KERB_MARKER" \
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

# --------- Legend ----------
echo "Legend:"
echo -e "  ${GREEN}GREEN${RESET}  = Open / Standard"
echo -e "  ${YELLOW}YELLOW${RESET} = Interesting"
echo -e "  ${RED}RED${RESET}    = High-risk exposure"
echo "---------------------------"

# --------- Message Helpers ----------
info()    { echo -e "${BLUE}[i]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${RED}[!]${RESET} $*"; }

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

    echo -e "  ${YELLOW}[i] Enumerating SMB users via crackmapexec ($AUTH_LABEL)...${RESET}"

    OUTPUT=$(crackmapexec smb "$TARGET" $CME_ARGS --users 2>/dev/null \
        | awk '/^[^ ]+\\[^ ]+/ {print $1}' \
        | sed 's/.*\\//' \
        | sort -u)

    [ -z "$OUTPUT" ] && return 1

    echo -e "  ${RED}[!] SMB user enumeration possible ($AUTH_LABEL)${RESET}"
    echo -e "  ${YELLOW}[i] Users discovered:${RESET}"

    echo "$OUTPUT" | while read -r user; do
        echo "      - $user"
    done

    return 0
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
        info "  - ${CVE_HINTS[$port]}"
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
        389|636) echo "LDAP" >> "$HINT_FILE"; LDAP_FOUND=true ;;
        6379) echo "REDIS" >> "$HINT_FILE" ;;
        2375) echo "DOCKER" >> "$HINT_FILE" ;;
        6443) echo "K8S" >> "$HINT_FILE" ;;
        3389) echo "RDP" >> "$HINT_FILE" ;;
        5985) echo "WINRM" >> "$HINT_FILE" ;;
        3306|1433) echo "DB" >> "$HINT_FILE" ;;
        80|443|8080|8443) echo "WEB" >> "$HINT_FILE" ;;
    esac

    # FTP Anonymous
    if [ "$PORT" = "21" ]; then
        if command -v ftp >/dev/null; then
            echo -e "  [i] Checking FTP anonymous access..."
            echo -e "user anonymous\npass anonymous\nquit" | ftp -n "$TARGET" 2>/dev/null \
                | grep -qi "230" && echo -e "${RED}[!] Anonymous FTP login allowed${RESET}"
        fi
    fi

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

		COMMON_USERS=(administrator admin guest krbtgt test svc backup)

		for user in "${COMMON_USERS[@]}"; do
		    timeout 3 $KERB_CMD "$TARGET/$user" -no-pass 2>&1 \
		        | grep -qi 'preauth' && \
		        echo -e "    ${YELLOW}[+] Valid Kerberos user:${RESET} $user"
		done
	    else
		echo -e "  ${YELLOW}[i] Kerberos enum requested, but impacket GetNPUsers not found${RESET}"
		echo -e "      Install: sudo apt install impacket-scripts${RESET}"
	    fi
	fi
    fi
    
    # -------- LDAP / LDAPS Domain Detection --------
    if [[ "$PORT" == "389" || "$PORT" == "636" ]] && command -v ldapsearch >/dev/null; then
        echo -e "  ${YELLOW}[i] Querying LDAP RootDSE...${RESET}"

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

		echo -e "  ${YELLOW}[i] LDAP domain detected:${RESET} $ldap_domain"

		echo "$TARGET $ldap_domain" >> "$HOSTS_FILE"
		echo "$ldap_domain" >> "$DISCOVERED_HOSTS"
		echo "LDAP" >> "$HINT_FILE"
		echo "KERBEROS" >> "$HINT_FILE"
        else
		echo -e "  [i] LDAP present but domain not disclosed"
        fi
    fi
    
    # Get Cert Info
    [ "$PORT" = "636" ] && extract_ssl_info $TARGET
    [ "$PORT" = "443" ] && extract_ssl_info $TARGET

    if [ "$PORT" = "6379" ] && command -v redis-cli >/dev/null; then
        redis-cli -h "$TARGET" ping 2>/dev/null | grep -qi PONG && \
            echo -e "${RED}[!] Redis unauthenticated${RESET}"
    fi

    if [ "$PORT" = "2375" ] && command -v curl >/dev/null; then
        curl -s "http://$TARGET:2375/containers/json" | grep -q '^\[' && \
            echo -e "${RED}[!] Unauthenticated Docker API (CVE-2025-9074)${RESET}"
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

    smb_enum_smbclient() {
        local AUTH="$1"
        local LABEL="$2"

        SHARES=$(smbclient -L "//$TARGET" -U "$AUTH" 2>/dev/null \
		| awk '$2 == "Disk" { print $1 }')

        [ -z "$SHARES" ] && return 1

        echo -e "  ${RED}[!] SMB allows $LABEL access${RESET}"
        echo -e "  ${YELLOW}[i] SMB shares ($LABEL):${RESET}"

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
        return 0
    }
    
    smb_enum_smbmap() {
        local AUTH_LABEL="$1"
        local SMBMAP_ARGS="$2"

        command -v smbmap >/dev/null 2>&1 || return 1

        OUTPUT=$(smbmap -H "$TARGET" $SMBMAP_ARGS 2>/dev/null \
		| awk '
		    /^[A-Za-z0-9_$-]+[[:space:]]+(READ|WRITE|READ,WRITE|NO)/ {
		        print $1, $2
		    }
		')

        [ -z "$OUTPUT" ] && return 1
	
        echo -e "  ${RED}[!] SMB allows $AUTH_LABEL access (via smbmap)${RESET}"
        echo -e "  ${YELLOW}[i] SMB shares ($AUTH_LABEL):${RESET}"

        echo "$OUTPUT" | while read -r share perms; do
		[[ "$share" =~ ^(IPC\$|ADMIN\$)$ ]] && continue

		perms=$(echo "$perms" | tr '[:upper:]' '[:lower:]')

		[[ "$perms" =~ read ]] && READ="yes" || READ="no"
		[[ "$perms" =~ write ]] && WRITE="yes" || WRITE="no"

		echo -e "      - $share [read=$(color_perm "$READ") write=$(color_perm "$WRITE")]"
        done
	
        return 0
    }

    # ---- Try smbclient first ----
    smb_enum_smbclient "" "NULL session" || true
    smb_enum_smbclient "guest%" "GUEST" || true

    # ---- Fallback to smbmap ----
    if ! $SMB_ENUM_SUCCESS; then
        info "smbclient yielded no shares — trying smbmap fallback..."
        smb_enum_smbmap "NULL session" "" || true
        smb_enum_smbmap "GUEST" "-u guest -p ''" || true
    fi
    
    # --------- CME User Enumeration (only if SMB access exists) ----------
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

    # --------- No Shares Found Case ----------
    if ! $SMB_ENUM_SUCCESS; then
        info "No SMB Shares Detected. Maybe retry with user creds?"
    fi
fi

# -------- Kerberos Reminder --------
if [[ -s "$KERB_MARKER" && "$ENABLE_KERB_ENUM" == false ]]; then
    echo
    echo -e "${YELLOW}[i] Tip:${RESET} Kerberos detected"
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
        echo -e "${BLUE}[i] Tip:${RESET} /etc/hosts suggestions:"
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
  - Attempt AS-REP roasting if pre-auth disabled
  - Combine with LDAP/SMB/WinRM
  - Tools: impacket-GetNPUsers, kerbrute, kinit, impacket
EOF
	;;
        LDAP)
cat <<EOF
[LDAP]
  - Check for anonymous binds
  - Enumerate users and groups if allowed
  - Search for sensitive attributes (users, emails, passwords, groups
    descriptions, computers, LAPS)
  - Tools: ldapsearch, enum4linux, ldapdomaindump
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
info "Scan completed in ${DURATION}s"

echo
echo "Scan complete."

