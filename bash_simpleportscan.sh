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
# Fix why "SMB auth failed for provided credentials" is displayed
#    when the creds clearly output SMB Shares.
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
KERB_DETECTED=false
KERB_ENUM_DONE=false
KERB_REALM=""
USERS_FILE=""

# --- Passing in User Info -----
AUTH_USER=""
AUTH_PASS=""
AUTH_DOMAIN=""
CREDS_PROVIDED=false

# --------- Concurrency ----------
MAX_JOBS=20

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
        --user=*) AUTH_USER="${arg#*=}" ;;
        --pass=*) AUTH_PASS="${arg#*=}" ;;
        --domain=*) AUTH_DOMAIN="${arg#*=}" ;;
        *) [ -z "$TARGET" ] && TARGET="$arg" ;;
    esac
done

if [ -n "$AUTH_DOMAIN" ] && [ -z "$LDAP_DOMAIN" ]; then
    LDAP_DOMAIN="${AUTH_DOMAIN,,}"
fi

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
ICON_TIP="💡"
ICON_PIN="📌"

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
    ICON_TIP="[TIP]"
    ICON_PIN="[O--]"
fi

echo
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
echo "  $ICON_TIP  Tip/Copyable Commands"
echo "---------------------------"

# --------- Message Helpers ----------
info()      { echo -e "${BLUE}ℹ ${RESET} $*"; }
success()   { echo -e "${GREEN}${ICON_OK} ${RESET} $*"; }
notify()    { echo -e "${YELLOW}${ICON_WARN} ${RESET} $*"; }
note()      { echo -e "${BLUE}${ICON_PIN} ${RESET} $*"; }
finding()   { echo -e "${YELLOW}[?] ${RESET} $*"; }
warn()      { echo -e "${RED}✖ ${RESET} $*"; }
risk()      { echo -e "${RED}[!] ${RESET} $*"; }
high_risk() { echo -e "${RED}${ICON_RISK} ${RESET} ${RED}$*${RESET}"; }
critical()  { echo -e "${RED}${ICON_CRIT} ${RESET} ${RED}$*${RESET}"; }
danger()    { echo -e "${RED}☠ ${RESET} $*"; }
alert()     { echo -e "${RED}${ICON_ALERT} ${RESET} $*"; }
lightbulb() { echo -e "${YELLOW}${ICON_TIP} ${RESET} $*"; }

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
        finding "SSL CN: $cn"
        echo "$TARGET $cn" >> "$HOSTS_FILE"
        echo "$cn" >> "$DISCOVERED_HOSTS"
    }

    if [ -n "$sans" ]; then
        finding "SSL SANs:"
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
    local FOUND_DESC=0

    command -v crackmapexec >/dev/null 2>&1 || return 1

    info "Enumerating SMB users via crackmapexec ($AUTH_LABEL)..."
    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}crackmapexec smb $TARGET $CME_ARGS --users${RESET}"

    # Capture full CME output (stdout + stderr)
    RAW_CME=$(crackmapexec smb "$TARGET" $CME_ARGS --users 2>&1)

    # --- 1. Hard failure: no auth at all ---
    if echo "$RAW_CME" | grep -qiE '\[-\].*(STATUS_LOGON_FAILURE|NT_STATUS_LOGON_FAILURE|ACCESS_DENIED)'; then
        warn "SMB authentication failed ($AUTH_LABEL)"
        return 1
    fi

    # --- 2. Auth success but enumeration explicitly denied ---
    if echo "$RAW_CME" | grep -qiE 'Error enumerating domain users|NTLM needs domain\\\\username'; then
        notify "SMB authentication successful ($AUTH_LABEL), but user enumeration is not permitted"
        return 0
    fi

    # --- 3. Parse enumerated users ONLY ---
    OUTPUT=$(echo "$RAW_CME" | awk '
        /^[A-Z]+[[:space:]]+[0-9.]+/ {
            user=""
            desc=""

            for (i=1; i<=NF; i++) {
                if ($i ~ /\\/) {
                    split($i,a,"\\")
                    user=a[2]
                }
            }

            # Skip self-echo or empty results
            if (user == "" || tolower(user) == "guest") next

            # Capture description if present
            match($0, /desc:[[:space:]]*(.*)$/, d)
            if (d[1] != "") {
                desc=d[1]
            }

            if (user != "") {
                print user "|" desc
            }
        }
    ' | sort -u)

    # --- 4. No users parsed (but no explicit failure) ---
    if [[ -z "$OUTPUT" ]]; then
        notify "SMB authentication successful ($AUTH_LABEL), but no domain users were returned"
        return 0
    fi

    # --- 5. Enumeration succeeded ---
    high_risk "SMB user enumeration successful ($AUTH_LABEL)"
    echo -e "   ${YELLOW}Users Discovered:${RESET}"

    while IFS="|" read -r user desc; do
        echo -e "      - ${BYELLOW}$user${RESET}"

        if [[ -n "$desc" ]]; then
            if echo "$desc" | grep -Ei 'pass|pwd|creds|password|secret|key|cont|contractor|temp' >/dev/null; then
                echo -e "          ${RED}⚠ Description:${RESET} $desc"
                echo -e "[LOOT] $TARGET SMB DESC $user : $desc" >> smb_user_descriptions.txt
                FOUND_DESC=1
            else
                echo -e "          ℹ Description: $desc"
            fi
        fi
    done <<< "$OUTPUT"

    # Save clean user list
    echo "$OUTPUT" | cut -d'|' -f1 > "users_smb_$TARGET.txt"
    success "Saved user list to users_smb_$TARGET.txt"

    if [ "$FOUND_DESC" -eq 1 ]; then
        success "Suspicious descriptions logged to smb_user_descriptions.txt"
    fi

    return 0
}

ldap_enum() {
    local USE_AUTH="$1"
    local PASSED_DOMAIN="${2:-}"

    # LDAP is noisy — do not let set -e kill enumeration
    set +e

    command -v ldapsearch >/dev/null 2>&1 || {
        warn "ldapsearch not found — skipping LDAP enumeration"
        set -e
        return
    }

    echo
    info "LDAP detected — starting safe LDAP enumeration"

    ########################################
    # 1. Protocol Selection (LDAP FIRST)
    ########################################
    LDAP_URI="ldap://$TARGET"
    # Use LDAPS only if LDAP (389) is NOT open and LDAPS (636) IS open
    if ! grep -qx 389 "$OPEN_PORTS_FILE" 2>/dev/null \
        && grep -qx 636 "$OPEN_PORTS_FILE" 2>/dev/null; then
        LDAP_URI="ldaps://$TARGET"
    fi

    info "Using LDAP URI: $LDAP_URI"

    ########################################
    # 2. Bind Arguments
    ########################################
    LDAP_BIND_ARGS="-x"

    if [[ "$USE_AUTH" == "auth" && "$CREDS_PROVIDED" == true ]]; then
        info "Using authenticated LDAP bind"
        LDAP_BIND_ARGS="-x -D ${AUTH_DOMAIN:+$AUTH_DOMAIN\\}$AUTH_USER -w $AUTH_PASS"
    fi

    ########################################
    # 3. Base DN Resolution (STATE-AWARE)
    ########################################

    # 3a. If BASE DN already known — reuse it
    if [[ -n "$LDAP_BASE_DN" && "$LDAP_BASE_DN" =~ ^DC= ]]; then
        info "Reusing previously discovered LDAP base DN"
    else
        # 3b. If domain passed explicitly — derive Base DN
        if [[ -n "$PASSED_DOMAIN" ]]; then
            info "Using provided domain for LDAP base DN"
            LDAP_DOMAIN="${PASSED_DOMAIN,,}"
            LDAP_BASE_DN=$(echo "$LDAP_DOMAIN" | awk -F. '{
                for (i=1;i<=NF;i++)
                    printf "DC=%s%s", toupper($i), (i<NF?",":"")
            }')
        else
            # 3c. Query RootDSE over LDAP FIRST
            info "Querying LDAP RootDSE for naming context"

            LDAP_BASE_DN=$(
                ldapsearch -x -H ldap://$TARGET -s base -b "" defaultNamingContext 2>/dev/null \
                | sed -n 's/^defaultNamingContext:[[:space:]]*//p'
            )

            # 3d. Fallback to LDAPS only if LDAP fails AND auth is used
            if [[ -z "$LDAP_BASE_DN" && "$USE_AUTH" == "auth" ]] && grep -qx 636 "$OPEN_PORTS_FILE"; then
                warn "LDAP RootDSE failed — retrying over LDAPS"
                LDAP_BASE_DN=$(
                    ldapsearch -x -H ldaps://$TARGET -s base -b "" defaultNamingContext 2>/dev/null \
                    | sed -n 's/^defaultNamingContext:[[:space:]]*//p'
                )
            fi
        fi

        # Derive domain if Base DN resolved
        if [[ "$LDAP_BASE_DN" =~ ^DC= ]]; then
            LDAP_DOMAIN=$(echo "$LDAP_BASE_DN" | sed 's/DC=//g; s/,/./g' | tr '[:upper:]' '[:lower:]')
        fi
    fi

    ########################################
    # 4. Validate Naming Context
    ########################################
    if [[ -z "$LDAP_BASE_DN" || ! "$LDAP_BASE_DN" =~ ^DC= ]]; then
        notify "LDAP present but naming context not disclosed"
        set -e
        return
    fi

    success "LDAP domain identified: $LDAP_DOMAIN"
    note "Base DN: $LDAP_BASE_DN"

    echo "$TARGET $LDAP_DOMAIN" >> "$HOSTS_FILE"

    ########################################
    # 5. Anonymous Bind Test (Only if anon)
    ########################################
    if [[ "$USE_AUTH" != "auth" ]]; then
        info "Testing anonymous LDAP bind"

        ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" -s base "(objectClass=*)" \
            >/dev/null 2>&1

        if [[ $? -ne 0 ]]; then
            notify "Anonymous LDAP bind not permitted"
            set -e
            return
        fi

        critical "Anonymous LDAP bind allowed"
        LDAP_ANON_BIND=true
    fi

    ########################################
    # 6. Enumeration (Read-Only)
    ########################################

    info "Enumerating domain password policy"
    ldapsearch $LDAP_BIND_ARGS -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(objectClass=domainDNS)" \
        minPwdLength lockoutThreshold maxPwdAge 2>/dev/null \
        | sed 's/^/    /'

    info "Enumerating users"
    ldapsearch $LDAP_BIND_ARGS -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(&(objectClass=user)(!(objectClass=computer)))" \
        sAMAccountName userPrincipalName 2>/dev/null \
        | awk '/^sAMAccountName:/ {print "    - "$2}'

    info "Enumerating groups"
    ldapsearch $LDAP_BIND_ARGS -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(objectClass=group)" cn 2>/dev/null \
        | awk '/^cn:/ {print "    - "$2}'

    info "Enumerating computers"
    ldapsearch $LDAP_BIND_ARGS -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(objectClass=computer)" dNSHostName 2>/dev/null \
        | awk '/^dNSHostName:/ {print "    - "$2}'

    ########################################
    # 7. High-Impact Checks
    ########################################

    info "Checking for LAPS exposure"
    if ldapsearch $LDAP_BIND_ARGS -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwdExpirationTime 2>/dev/null \
        | grep -q ms-MCS-AdmPwd; then
        critical "LAPS attributes readable (HIGH RISK)"
    fi

    info "Searching for Kerberos SPNs"
    ldapsearch $LDAP_BIND_ARGS -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
        "(servicePrincipalName=*)" sAMAccountName servicePrincipalName 2>/dev/null \
        | awk '/^sAMAccountName:/ {print "    - "$2}'

    ########################################
    # 8. Optional ldapdomaindump
    ########################################
    if command -v ldapdomaindump >/dev/null 2>&1; then
        info "Running ldapdomaindump (read-only)"
        mkdir -p "ldap_dump_$TARGET"
        ldapdomaindump -u '' -p '' -o "ldap_dump_$TARGET" "$LDAP_URI" >/dev/null 2>&1 \
            && success "ldapdomaindump completed (ldap_dump_$TARGET)"
    fi

    ########################################
    # 9. Auth-Only Enumeration
    ########################################
    if [[ "$USE_AUTH" == "auth" ]]; then
        echo
        critical "Authenticated LDAP access confirmed"

        info "Enumerating all domain users (authenticated)"

        ldapsearch $LDAP_BIND_ARGS -H "$LDAP_URI" -b "$LDAP_BASE_DN" \
            "(&(objectClass=user)(!(objectClass=computer)))" \
            sAMAccountName memberOf userPrincipalName 2>/dev/null \
        | awk '
            /^sAMAccountName:/ {
                user=$2
                print "    - " user
            }
        '
    fi

    LDAP_ENUM_DONE=true
    set -e
}

kerberos_auth_check() {
    command -v kinit >/dev/null 2>&1 || {
        notify "kinit not found — skipping Kerberos auth check"
        return
    }

    if [[ -z "$KERB_REALM" ]]; then
        notify "Kerberos realm not known — skipping auth check"
        return
    fi

    echo
    info "Validating Kerberos credentials (safe check)"
    echo "[DEBUG] kinit $AUTH_USER@$KERB_REALM"

    if echo "$AUTH_PASS" | kinit "$AUTH_USER@$KERB_REALM" >/dev/null 2>&1; then
        success "Kerberos authentication successful"
        kdestroy
    else
        warn "Kerberos authentication failed (non-fatal)"
    fi
}

resolve_kerberos_realm() {
    # Priority:
    # 1. LDAP-derived domain
    # 2. --domain argument
    # 3. DNS reverse / hostname (optional future)

    if [[ -n "$LDAP_DOMAIN" ]]; then
        KERB_REALM="${LDAP_DOMAIN^^}"
    elif [[ -n "$AUTH_DOMAIN" ]]; then
        KERB_REALM="${AUTH_DOMAIN^^}"
    else
        return 1
    fi

    success "Kerberos realm identified: $KERB_REALM"
    return 0
}

kerberos_enum_users() {
    command -v impacket-GetNPUsers >/dev/null 2>&1 || \
    command -v GetNPUsers.py >/dev/null 2>&1 || {
        warn "Kerberos enum requested, but GetNPUsers not installed"
        return
    }

    local KERB_CMD
    KERB_CMD=$(getnpusers_cmd) || return

    if [[ -z "$KERB_REALM" ]]; then
        notify "Kerberos detected, but realm not resolved — skipping enum"
        return
    fi

    echo
    info "Kerberos detected — starting user enumeration"

    COMMON_USERS=(
        administrator admin guest krbtgt test backup
        svc svc_backup svc_sql svc_mssql svc_web svc_app svc_ldap
        sqlsvc mssql exchange iis websvc appsvc backupsvc veeam
        student lab training
    )
    
    USERFILE_OK=true
    
    # Validate USERS_FILE
    if [[ -z "${USERS_FILE:-}" ]]; then
        notify "USERS_FILE variable not set — skipping AS-REP roasting"
        USERFILE_OK=false
    fi
    if [[ ! -f "$USERS_FILE" ]]; then
        notify "USERS_FILE does not exist ($USERS_FILE) — skipping AS-REP roasting"
        USERFILE_OK=false
    fi
    if [[ ! -s "$USERS_FILE" ]]; then
        notify "USERS_FILE exists but is empty — skipping AS-REP roasting"
        USERFILE_OK=false
    fi

    FOUND=false
    AUTH_OK=false
    ASREP_OK=false

    ########################################
    # 1. Unauthenticated enumeration
    ########################################
    info "Attempting unauthenticated Kerberos user enumeration"
    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}$KERB_CMD $KERB_REALM/[user] -dc-ip $TARGET -no-pass${RESET}"

    for user in "${COMMON_USERS[@]}"; do
        timeout 3 "$KERB_CMD" "$KERB_REALM/$user" -dc-ip "$TARGET" -no-pass 2>&1 \
            | grep -qi 'preauth' && {
                success "Valid Kerberos user (unauth): ${BYELLOW}$user${RESET}"
                FOUND=true
            }
    done

    ########################################
    # 2. Authenticated enumeration (FIXED)
    ########################################
    if $CREDS_PROVIDED; then
        echo
        info "Attempting authenticated Kerberos enumeration"

        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$KERB_CMD '$KERB_REALM/$AUTH_USER:$AUTH_PASS' -dc-ip $TARGET${RESET}"

        OUT=$(timeout 6 "$KERB_CMD" \
            "$KERB_REALM/$AUTH_USER:$AUTH_PASS" \
            -dc-ip "$TARGET" 2>&1)

        # --- AUTH SUCCESS CONDITIONS ---
        if echo "$OUT" | grep -qiE '\$krb5asrep\$|No entries found!'; then
            success "Kerberos authentication successful (authenticated enumeration)"
            AUTH_OK=true
            FOUND=true
        fi

        # --- REAL AUTH FAILURE ---
        if echo "$OUT" | grep -qiE 'KDC_ERR_PREAUTH_FAILED|C_PRINCIPAL_UNKNOWN|Cannot find KDC'; then
            warn "Kerberos authentication failed"
            return
        fi
    fi
    
    ########################################
    # 4. Attempt to perform ASREP Roast
    ########################################
    if $USERFILE_OK; then
        ########################################
        #   AS-REP roast attempt - Unauthenticate
        ########################################
        info "Attempting AS-REP roast using discovered users - Unauthenticated"
        note "User file: $USERS_FILE"

        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$KERB_CMD '$KERB_REALM/' -dc-ip $TARGET -usersfile $USERS_FILE${RESET}"

        OUT=$(timeout 15 "$KERB_CMD" \
            "$KERB_REALM/" \
            -dc-ip "$TARGET" \
            -usersfile "$USERS_FILE" 2>&1)

        ########################################
        # Interpret output correctly
        ########################################
        # --- protocol success ---
        if echo "$OUT" | grep -qiE '\$krb5asrep\$|No entries found!'; then
            success "Kerberos AS-REP request completed successfully"
            AUTH_OK=true
            FOUND=true
            fi

            # --- AS-REP hashes found ---
            if echo "$OUT" | grep -q '\$krb5asrep\$'; then
            critical "AS-REP roastable users identified!"
            echo "$OUT" | grep '\$krb5asrep\$' > "asrep_hashes_$TARGET.txt"
            success "Saved AS-REP hashes to asrep_hashes_$TARGET.txt"
            ASREP_OK=true
        fi

        # --- Real failure conditions ---
        if echo "$OUT" | grep -qiE 'KDC_ERR_PREAUTH_FAILED|C_PRINCIPAL_UNKNOWN|Cannot find KDC'; then
            warn "Kerberos AS-REP request failed"
            ASREP_OK=false
        fi
        
        
        if $CREDS_PROVIDED; then     
            ########################################
            #   AS-REP roast attempt
            ########################################
            info "Attempting AS-REP roast using discovered users - Authenticated"
            note "User file: $USERS_FILE"

            echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "        ${GREEN}$KERB_CMD '$KERB_REALM/$AUTH_USER:$AUTH_PASS' -dc-ip $TARGET -usersfile $USERS_FILE${RESET}"

            OUT=$(timeout 15 "$KERB_CMD" \
                "'$KERB_REALM/$AUTH_USER:$AUTH_PASS'" \
                -dc-ip "$TARGET" \
                -usersfile "$USERS_FILE" 2>&1)

            ########################################
            # Interpret output correctly
            ########################################

            # --- Authentication / protocol success ---
            if echo "$OUT" | grep -qiE '\$krb5asrep\$|No entries found!'; then
                success "Kerberos AS-REP request completed successfully"
                AUTH_OK=true
                FOUND=true
            fi

            # --- AS-REP hashes found ---
            if echo "$OUT" | grep -q '\$krb5asrep\$'; then
                critical "AS-REP roastable users identified!"
                echo "$OUT" | grep '\$krb5asrep\$' > "asrep_hashes_$TARGET.txt"
                success "Saved AS-REP hashes to asrep_hashes_$TARGET.txt"
                ASREP_OK=true
            fi

            # --- Real failure conditions ---
            if echo "$OUT" | grep -qiE 'KDC_ERR_PREAUTH_FAILED|C_PRINCIPAL_UNKNOWN|Cannot find KDC'; then
                warn "Kerberos AS-REP request failed"
                ASREP_OK=false
            fi
        fi
    fi

    ########################################
    # 4. Final status
    ########################################
    if $USERFILE_OK; then
        if ! $ASREP_OK; then
             warn "No AS-REP roastable users found"
        fi
    fi
    if ! $FOUND; then
        warn "Kerberos enumeration completed — no users identified"
    fi

    KERB_ENUM_DONE=true
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

if [ -n "$AUTH_USER" ] && [ -n "$AUTH_PASS" ]; then
    CREDS_PROVIDED=true
    success "Credentials provided for authenticated checks"
    echo -e "   - User:      ${YELLOW}$AUTH_USER${RESET}"
    echo -e "   - Password:  ${YELLOW}$AUTH_PASS${RESET}"
    if [ -n "$AUTH_DOMAIN" ] ; then
        echo -e "   - Domain:    ${YELLOW}$AUTH_DOMAIN${RESET}"
    fi
    echo
fi

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
        88) echo "KERBEROS" >> "$HINT_FILE" ; echo "$PORT" >> "$KERB_MARKER" ;;
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
		LDAP_DOMAIN=$(echo "$ldap_dn" | sed 's/DC=//g; s/,/./g' | tr '[:upper:]' '[:lower:]')
		note "LDAP domain detected: ${GREEN}$LDAP_DOMAIN${RESET}"
		
		note "LDAP domain detected: ${GREEN}$LDAP_DOMAIN${RESET}"

		echo "$TARGET $LDAP_DOMAIN" >> "$HOSTS_FILE"
		echo "$LDAP_DOMAIN" >> "$DISCOVERED_HOSTS"
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

HAS_SMB=$(grep -q SMB "$HINT_FILE" && echo 1 || echo 0)
HAS_LDAP=$(grep -q LDAP "$HINT_FILE" && echo 1 || echo 0)
HAS_KERB=$(grep -q KERBEROS "$HINT_FILE" && echo 1 || echo 0)

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
    
    highlight_keywords() {
        sed -E \
            -e "s/(password|passwd|pwd)/${RED}\1${RESET}/Ig" \
            -e "s/(backup|bak|old)/${RED}\1${RESET}/Ig" \
            -e "s/(\.kdbx)/${RED}\1${RESET}/Ig" \
            -e "s/(\.xlsx)/${RED}\1${RESET}/Ig"
    }
    
    smb_auth_check() {
        local AUTH="$1"

	smbclient -L "//$TARGET" -U "$AUTH" -m SMB3 -c 'exit' >/dev/null 2>&1
	return $?
    }

    smb_list_files() {
        local SHARE="$1"
        local AUTH="$2"
        local LABEL="$3"

        echo -e "        ${BLUE}$ICON_SHARE Listing files in //$TARGET/$SHARE ($LABEL, read-only)${RESET}"
	
	# ---- NEW: Copy-paste helper ----
        local USER="${AUTH%%%*}"
        local PASS="${AUTH#*%}"

        if [ -z "$USER" ]; then
            COPY_CMD="smbclient //$TARGET/$SHARE -N"
        elif [ -z "$PASS" ]; then
            COPY_CMD="smbclient //$TARGET/$SHARE -U $USER"
        else
            COPY_CMD="smbclient //$TARGET/$SHARE -U '$USER%$PASS'"
        fi

        echo -e "        ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "           ${GREEN}$COPY_CMD${RESET}"
	
        # Root listing first (most reliable)
        ROOT_LIST=$(timeout 6 smbclient "//$TARGET/$SHARE" -U "$AUTH" \
             -c "ls" 2>/dev/null)

        if echo "$ROOT_LIST" | grep -q 'NT_STATUS'; then
            echo -e "          ${YELLOW}(directory listing restricted)${RESET}"
            return
        fi

        echo -e "$ROOT_LIST" \
            | awk '
                /blocks of size/ {next}
                /NT_STATUS/ {next}
                NF {print "          - "$0}
            ' #\
            #| highlight_keywords

        # Loot detection
        if echo "$ROOT_LIST" | grep -Eqi '(password|passwd|pwd|backup|\.kdbx|\.xlsx)'; then
            critical "        High-value files detected in //$TARGET/$SHARE"
        fi

        # Optional shallow recursion (safe)
        SUBDIRS=$(echo "$ROOT_LIST" | awk '$1 ~ /^d/ {print $NF}')

        for dir in $SUBDIRS; do
            echo -e "          ${BLUE}↳ $dir/${RESET}"
            timeout 4 smbclient "//$TARGET/$SHARE" -U "$AUTH" \
                -c "cd \"$dir\"; ls" 2>/dev/null \
                | awk '
                    /blocks of size/ {next}
                    /NT_STATUS/ {next}
                    NF {print}
                ' \
                | sed 's/^/            - /'
        done
    }

    # -------- smbclient enumeration (NULL + GUEST explicitly) --------
    smb_enum_smbclient() {
        local AUTH="$1" # User
        local LABEL="$2"

        SHARES=$(smbclient -L "//$TARGET" -U "$AUTH" 2>/dev/null \
            | awk '$2 == "Disk" { print $1 }')

        [ -z "$SHARES" ] && return 1

        critical "  SMB allows $LABEL access"
        notify "   $ICON_SHARE SMB shares ($LABEL):"

        for share in $SHARES; do
            [[ "$share" =~ ^(IPC\$|ADMIN\$)$ ]] && continue

            smbclient "//$TARGET/$share" -U "$AUTH" -c "ls" >/dev/null 2>&1 \
                && READ="yes" || READ="no"

            smbclient "//$TARGET/$share" -U "$AUTH" -c "put /dev/null test_$$_tmp" >/dev/null 2>&1 \
                && WRITE="yes" || WRITE="no"

            echo -e "      - $share [read=$(color_perm "$READ") write=$(color_perm "$WRITE")]"
            if [ "$READ" = "yes" ]; then
            	# Read Share Contents - List Files.
            	#echo "     [DEBUG] smb_enum_smbclient()"
   		smb_list_files "$share" "$AUTH" "$LABEL"
	    fi
        done

        SMB_ENUM_SUCCESS=true
        [ "$LABEL" = "NULL session" ] && SMB_NULL_OK=true
        [ "$LABEL" = "GUEST" ] && SMB_GUEST_OK=true
    }

    # -------- smbmap fallback --------
    smb_enum_smbmap() {
        local LABEL="$1" # User
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
	    
	    if [ "$READ" = "yes" ] && [[ "$share" =~ ^(NETLOGON|SYSVOL)$ ]]; then
         	critical "  READ access to $share — Active Directory attack surface exposed"

         	echo "KERBEROS" >> "$HINT_FILE"
    	    	echo "LDAP" >> "$HINT_FILE"
	    fi
	    
            echo -e "      - $share [read=$(color_perm "$READ") write=$(color_perm "$WRITE")]"
            if [ "$READ" = "yes" ]; then
            	#Attempt to list files in Share that you have "Read" Access to.
            	# echo "         [DEBUG] SMBMAP()"
    		smb_list_files "$share" "$LABEL" ""
	    fi
        done

        SMB_ENUM_SUCCESS=true
        [ "$LABEL" = "NULL session" ] && SMB_NULL_OK=true
        [ "$LABEL" = "GUEST" ] && SMB_GUEST_OK=true
    }

    # -------- Auth Attempts (ORDER MATTERS) --------
    # 1) True NULL session
    if smb_auth_check "%"; then
        success "SMB NUll Session successful"
    	smb_enum_smbclient "%" "NULL session" || \
            notify "NULL Session Allowed, but no shares are visible to this user"
    else
        warn "SMB NULL Session failed"
    fi 

    # 2) Guest with empty password (matches CME behavior)
    if smb_auth_check "guest%"; then
        success "SMB GUEST (No Password) Successful"
    	smb_enum_smbclient "guest%" "GUEST" || \
            notify "Guest Access Allowed, but no shares are visible to this user"
    else
        warn "SMB Guest (No Password) Session Failed"
    fi 
    
    # 3) Check for authenticated access.
    if $CREDS_PROVIDED; then
        echo
        info "Attempting SMB authentication with provided credentials"

        if smb_auth_check "$AUTH_USER%$AUTH_PASS"; then
            success "SMB authentication successful"

            smb_enum_smbclient "$AUTH_USER%$AUTH_PASS" "AUTHENTICATED" || \
                notify "Authenticated but no shares are visible to this user"
        else
            warn "SMB authentication failed for provided credentials"
        fi
    fi

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
        
        if $CREDS_PROVIDED; then 
            cme_enum_users "AUTHENTICATED" "-u $AUTH_USER -p $AUTH_PASS" || true
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
                echo -e "      - ${BYELLOW}$user${RESET}"
                echo "$user" >> "$USERS_FILE"
            done

            note "User list saved to: ${GREEN}$USERS_FILE${RESET}"
            lightbulb " Maybe try a Password Spary if you know a 'default' Password"
            lightbulb "   ${YELLOW}Copy/Paste:${RESET}"
            echo -e "        crackmapexec smb ${TARGET} -u $USERS_FILE -p 'ADefaultPassword'"

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
    echo "LDAP_ENUM ANON"
    ldap_enum anon "${AUTH_DOMAIN:-$LDAP_DOMAIN}"

    echo "LDAP_ENUM With Creds"
    $CREDS_PROVIDED && ldap_enum auth "${AUTH_DOMAIN:-$LDAP_DOMAIN}"
fi

# --------- Kerberos Post-Scan Handling ----------
if [ -s "$KERB_MARKER" ]; then
    KERB_DETECTED=true

    if resolve_kerberos_realm; then
        if $ENABLE_KERB_ENUM; then
            kerberos_enum_users
        else
            alert "Kerberos detected — re-run with --kerb-enum to enumerate users"
        fi

        if $CREDS_PROVIDED; then
            kerberos_auth_check
        fi
    else
        notify "Kerberos detected, but domain/realm could not be resolved"
    fi
fi

if $CREDS_PROVIDED; then
    #echo "[DEBUG] Creds were provided"
    # Check creds is Kerberos Service is deteted.
    if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "88"; then
        KERB_AUTH_OK=false
        $CREDS_PROVIDED && kerberos_auth_check || true
    fi
 
    echo
    info "Single-shot credential reuse check..."   
    # WinRM
    if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "5985" \
       && command -v crackmapexec >/dev/null; then

       #echo "[DEBUG] Creds were provided for CME targeting WINRM"
       
       info "Trying WinRM:"
       lightbulb "    ${YELLOW}Copy/Paste:${RESET}"
             echo -e "        ${GREEN}crackmapexec winrm $TARGET -u '$AUTH_USER' -p '$AUTH_PASS'${RESET}"
       
       if crackmapexec winrm "$TARGET" -u "$AUTH_USER" -p "$AUTH_PASS" 2>/dev/null \
                | grep -qP 'WINRM\s+\S+\s+\d+\s+\S+\s+\[\+\]'; then
            critical "WinRM credential reuse confirmed"
        else
            warn "WinRM authentication failed or not permitted"
        fi
    fi

    # MSSQL
    if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "1433" \
       && command -v crackmapexec >/dev/null; then

       #echo "[DEBUG] Creds were provided for CME targeting MSSQL"
       
       lightbulb "Trying MSSQL:"
       lightbulb "   ${YELLOW}Copy/Paste:${RESET}"
             echo -e "        ${GREEN}crackmapexec mssql $TARGET -u '$AUTH_USER' -p '$AUTH_PASS'${RESET}"
       
       if crackmapexec mssql "$TARGET" -u "$AUTH_USER" -p "$AUTH_PASS" 2>/dev/null \
            | grep -qi success; then
            critical "MSSQL credential reuse confirmed"
        else
            warn "MSSQL authentication failed or not permitted"
        fi
    fi
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
HAS_WEB=0
if [ -s "$HTTP_MARKER" ] || [ -s "$HTTPS_MARKER" ]; then
    HAS_WEB=1
fi
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

if [[ $HAS_SMB -eq 1 && $HAS_LDAP -eq 1 && $HAS_KERB -eq 1 ]]; then
    critical "ATTACK SURFACE: ACTIVE DIRECTORY"
    lightbulb "Suggested path:"
    echo "    → Kerberos user enum"
    echo "    → AS-REP roast"
    echo "    → SMB share creds"
    echo "    → WinRM / RDP"
    echo "    → User / Password Spray"
    echo
elif [[ $HAS_SMB -eq 1 ]]; then
    alert "ATTACK SURFACE: FILE SHARES / WINDOWS HOST"
elif [[ $HAS_WEB -eq 1 ]]; then
    alert "ATTACK SURFACE: WEB APPLICATION"
fi
if [[ $HAS_WEB -eq 1 && $HAS_SMB -eq 1 ]]; then
    finding "  Web + SMB attack surface overlap detected"
fi

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

