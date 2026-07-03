# Tooling

A collection of Shell, Python, and PowerShell utilities for authorized penetration testing, security labs, Active Directory assessment, web testing, and general operator workflow.

> [!WARNING]
> Use these tools only on systems you own or are explicitly authorized to test. Several scripts can generate high-volume traffic, attempt credentials, modify Active Directory objects, reset passwords, request certificates, or create sensitive output files.

## Contents

| Tool | Purpose | Primary requirements |
|---|---|---|
| `bash_simpleportscan.sh` | Experimental recon and service-enumeration workflow with optional web, DNS, SMB, LDAP, Kerberos, MSSQL, AD CS, BloodHound, and service-detection features | Bash; capabilities expand with tools such as `nmap`, `curl`, `openssl`, `ffuf`, DNS/LDAP/SMB utilities, Impacket, Certipy, and BloodHound tooling |
| `bash_simpleportscan_simple.sh` | Fast Bash `/dev/tcp` scan of common ports | Bash and `timeout` |
| `sh_simpleportscan_simple.sh` | Minimal common-port scanner using `/dev/tcp` | `sh`, `timeout`, and a shell implementation that supports `/dev/tcp` |
| `vhost_ffuf.py` | Calculates a fake-host response baseline and launches `ffuf` for virtual-host discovery | Python 3, `curl`, `ffuf`, and a wordlist |
| `lfi_tester.py` | Tests common parameters and traversal payloads for possible local file inclusion, with optional loot and logging | Python 3 and `requests` |
| `mssql_brute.sh` | Tests one or more username/password combinations against Microsoft SQL Server | Bash, `timeout`, and `impacket-mssqlclient` |
| `ntlmhashgen.py` | Generates an NT hash from a supplied plaintext password in several output formats | Python 3 |
| `parse_passwd_users.py` | Extracts likely interactive users from a captured `/etc/passwd` file | Python 3 |
| `cert_esc1_exploit.sh` | Interactive/non-interactive Certipy wrapper for authorized AD CS ESC1 testing | Bash, `certipy-ad`, and a time-sync utility when needed |
| `PowerShell/ForcePasswordReset.ps1` | Resets an AD user's password through the ActiveDirectory module or a PowerView fallback | Windows PowerShell, ActiveDirectory module or PowerView |
| `PowerShell/Invoke-FCP.ps1` | Performs a ForceChangePassword workflow using PowerView, with optional ownership and ACL changes | Windows PowerShell and PowerView |
| `PowerShell/TargetedKerberoast.ps1` | Temporarily sets an SPN, requests a TGS, and writes the resulting Kerberoast hash | Windows PowerShell and PowerView |
| `zsh_changes` | Zsh aliases and helper functions for lab workflow, listeners, file serving, and payload generation | Zsh; some helpers also require Netcat or Metasploit |

## Quick Start

```bash
git clone https://github.com/Scuba-Steev3/Tooling.git
cd Tooling

chmod +x ./*.sh ./*.py
```

Create an optional Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install requests impacket certipy-ad
```

Install only the dependencies required for the tool and feature set you intend to use. The larger recon script integrates with several optional external utilities and will have reduced functionality when they are unavailable.

## Usage

### Advanced Recon and Port Scanner

Basic scan:

```bash
./bash_simpleportscan.sh 10.10.10.10
```

Credentialed AD-oriented scan:

```bash
./bash_simpleportscan.sh dc01.example.local \
  --domain=example.local \
  --user=analyst \
  --pass='REPLACE_ME' \
  --kerb-enum \
  --check-certs \
  --service-detect
```

Common feature flags:

| Flag | Function |
|---|---|
| `--vhost` | Enable virtual-host discovery |
| `--web-enum` | Enable additional web enumeration |
| `--service-detect` or `--svc` | Run targeted Nmap service/version detection against discovered ports |
| `--kerb-enum` | Enable Kerberos-focused enumeration |
| `--run-blood` | Run the BloodHound export workflow |
| `--kerberoast` | Enable Kerberoast checks |
| `--check-certs`, `--check-cert`, or `--check-ca` | Enable AD CS checks |
| `--check-mssql` | Enable MSSQL enumeration |
| `--mssql-brute` | Enable the MSSQL credential-testing workflow |
| `--dns-enum` | Enable DNS enumeration |
| `--dns-brute` | Enable DNS enumeration and brute-force discovery |
| `--dns-domain=DOMAIN` | Supply the DNS domain |
| `--dns-wordlist=FILE` | Supply a DNS brute-force wordlist |
| `--dns-no-axfr` | Disable zone-transfer attempts |
| `--user=USER`, `-u=USER` | Supply a username |
| `--pass=PASS`, `-p=PASS` | Supply a password |
| `--domain=DOMAIN` | Supply an authentication domain |
| `--no-color` | Disable colored output |

> [!IMPORTANT]
> `bash_simpleportscan.sh` is an active-development helper script rather than a finished scanning framework. Review its code and test it in a lab before relying on it during an assessment.

### Simple Common-Port Scanners

Bash version:

```bash
./bash_simpleportscan_simple.sh 10.10.10.10
```

Minimal `sh` version:

```bash
./sh_simpleportscan_simple.sh 10.10.10.10
```

Both default to `127.0.0.1` when no target is supplied. The `sh` version is not portable to shells that do not implement `/dev/tcp`.

### Virtual-Host Discovery

Preview the generated `ffuf` command without running it:

```bash
python3 vhost_ffuf.py \
  -i 10.10.10.10 \
  -d example.htb \
  --dry-run
```

Run an HTTPS scan and save an HTML report:

```bash
python3 vhost_ffuf.py \
  -i 10.10.10.10 \
  -d example.htb \
  -s https \
  -k \
  -o ffuf_vhosts.html
```

Useful options:

```text
-w, --wordlist FILE   Subdomain wordlist
-t, --threads N       ffuf thread count; default: 40
--fake-host NAME      Fake subdomain used for response-size baselining
-k, --insecure        Ignore HTTPS certificate errors
--dry-run             Show the baseline and command without running ffuf
```

The default wordlist path is:

```text
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### LFI Tester

Basic test:

```bash
python3 lfi_tester.py http://10.10.10.10 \
  --path /index.php \
  --params file page path
```

Save positive responses and scan logs:

```bash
python3 lfi_tester.py https://example.test \
  --path /download.php \
  --params file document \
  --save-loot \
  --loot-dir lfi_loot \
  --log-file lfi_scan.log \
  --jsonl-log lfi_findings.jsonl
```

Additional options include `--timeout`, `--verbose`, `--show-fingerprints`, and `--progress-every`.

### MSSQL Credential Testing

Single username with a password list:

```bash
./mssql_brute.sh 10.10.10.10 \
  -u='sa' \
  -p='passwords.txt'
```

Username list with a single password:

```bash
./mssql_brute.sh 10.10.10.10 \
  -u='users.txt' \
  -p='REPLACE_ME'
```

Windows authentication on a non-default port:

```bash
./mssql_brute.sh 10.10.10.10 \
  -u='users.txt' \
  -p='passwords.txt' \
  --port=1433 \
  --win-auth
```

### NT Hash Generator

```bash
python3 ntlmhashgen.py \
  -u Administrator \
  -p 'REPLACE_ME' \
  --format all
```

Available formats:

```text
userhash   username:hash
hash       hash only
impacket   username:::hash:::
all        all supported formats
```

Treat generated hashes as secrets.

### Parse Users from `/etc/passwd`

```bash
python3 parse_passwd_users.py \
  -f passwd.txt \
  -o users.txt
```

Include system accounts or non-interactive shells when needed:

```bash
python3 parse_passwd_users.py \
  -f passwd.txt \
  -o all_users.txt \
  --include-system \
  --all-shells
```

By default, the script keeps `root` and users with UID 1000 or greater that have a recognized interactive shell.

### AD CS ESC1 Workflow

Interactive mode:

```bash
./cert_esc1_exploit.sh
```

Non-interactive example:

```bash
./cert_esc1_exploit.sh \
  --template 'VulnerableTemplate' \
  --domain example.local \
  --dc-ip 10.10.10.10 \
  --ca-name 'EXAMPLE-CA' \
  --dns dc01.example.local \
  --target-user Administrator \
  --username tester \
  --password 'REPLACE_ME' \
  --maq no
```

Use an existing machine account:

```bash
./cert_esc1_exploit.sh \
  --owned-comp 'LABHOST-01$' \
  --owned-comp-pass 'REPLACE_ME'
```

This workflow can create or use machine accounts, request certificates, authenticate with PFX files, and perform time synchronization. Review the script before execution and preserve assessment evidence before accepting any cleanup prompts.

## PowerShell Tools

Run these from an authorized Windows domain context. PowerView is not included in this repository and must be supplied separately when a script requires it.

### Force Password Reset

```powershell
.\PowerShell\ForcePasswordReset.ps1 `
  -TargetUser andy `
  -NewPassword 'REPLACE_ME' `
  -ForceChangeAtLogon
```

Optional alternate credentials:

```powershell
.\PowerShell\ForcePasswordReset.ps1 `
  -TargetUser andy `
  -NewPassword 'REPLACE_ME' `
  -AltUsername svc-helpdesk `
  -AltPassword 'REPLACE_ME'
```

The script first attempts the native ActiveDirectory module and then uses a PowerView fallback when available.

### Invoke-FCP

```powershell
.\PowerShell\Invoke-FCP.ps1 -TargetIdentity 'svc-app'
```

With optional ownership and ACL operations:

```powershell
.\PowerShell\Invoke-FCP.ps1 `
  -TargetIdentity 'svc-app' `
  -NewPassword 'REPLACE_ME' `
  -TakeOwnership `
  -AddResetAcl
```

### Targeted Kerberoast

```powershell
.\PowerShell\TargetedKerberoast.ps1 `
  -TargetUser sqlsvc `
  -OutputFormat Hashcat
```

With alternate credentials:

```powershell
.\PowerShell\TargetedKerberoast.ps1 `
  -TargetUser sqlsvc `
  -AltUsername delegatedUser `
  -AltPassword 'REPLACE_ME' `
  -OutputFormat John
```

The script writes output to a file named similar to:

```text
hash_yyyyMMdd_HHmmss_TargetUser.txt
```

SPN changes and password resets are auditable Active Directory events. Validate cleanup and confirm the environment's rules of engagement before running these workflows.

## Zsh Helpers

Review the file before sourcing it:

```bash
source /path/to/Tooling/zsh_changes
```

To load it automatically, add the source command to `~/.zshrc` rather than blindly appending the file multiple times:

```bash
echo 'source /path/to/Tooling/zsh_changes' >> ~/.zshrc
source ~/.zshrc
```

Run `shell_help` after loading the file to display its helper commands.

## Sensitive Output and Credential Handling

Several tools accept plaintext credentials on the command line. Command-line arguments may be stored in shell history or exposed to other local users through process inspection. Prefer disposable lab credentials and remove sensitive history entries when permitted by the rules of engagement.

Generated files may include:

- PFX certificates and Kerberos credential caches
- Passwords, NT hashes, and Kerberoast hashes
- LFI response bodies and JSONL logs
- Nmap output and ffuf reports
- Enumerated usernames and domain data

Consider adding the following patterns to a local `.gitignore`:

```gitignore
.venv/
__pycache__/
*.pyc

*.pfx
*.ccache
hash_*.txt
valid_*_creds.txt

lfi_loot/
*.jsonl
*.log
ffuf_*.html
nmap_service_*.txt
nmap_service_*.screen.txt

users.txt
passwords.txt
```

Never commit real credentials, hashes, certificates, tickets, assessment evidence, or client data.

## Validation Before Committing

```bash
bash -n ./*.sh
python3 -m py_compile ./*.py
```

Where available, also use:

```bash
shellcheck ./*.sh
```

For PowerShell, review built-in help and run syntax validation in a controlled environment:

```powershell
Get-Help .\PowerShell\ForcePasswordReset.ps1 -Full
Get-Help .\PowerShell\TargetedKerberoast.ps1 -Full
```

## Contributing

1. Create a focused branch.
2. Keep each pull request limited to one tool or behavior change.
3. Document new dependencies and output files.
4. Add a usage example that contains no real credentials or client data.
5. Test destructive or state-changing functions in an isolated lab.
6. Update this README when adding, renaming, or removing a tool.

## Disclaimer

These scripts are provided for education, lab work, and explicitly authorized security testing. You are responsible for obtaining permission, defining scope, protecting collected data, and complying with all applicable laws, contracts, and rules of engagement. The repository owner and contributors are not responsible for unauthorized or harmful use.
