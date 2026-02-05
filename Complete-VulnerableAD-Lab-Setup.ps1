<#
.SYNOPSIS
    Complete Automated Vulnerable AD Lab Setup - Single Script Solution
    
.DESCRIPTION
    This script automates the entire process of setting up a vulnerable Active Directory lab:
    - Configures static IP address
    - Installs AD Domain Services
    - Promotes server to Domain Controller
    - Creates vulnerable AD configurations
    - Handles automatic reboot and continuation
    
.NOTES
    Author: Vulnerable AD Lab Automation
    Version: 1.0
    Requires: Windows Server 2019 (Desktop Experience)
    Initial User: Administrator
    Initial Password: P@ssw0rd
    
.EXAMPLE
    .\Complete-VulnerableAD-Lab-Setup.ps1
    
.EXAMPLE
    .\Complete-VulnerableAD-Lab-Setup.ps1 -DomainName "pentest.local" -NumberOfUsers 50
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = "vulnerable.local",
    
    [Parameter(Mandatory=$false)]
    [string]$DomainNetBIOSName = "VULNERABLE",
    
    [Parameter(Mandatory=$false)]
    [string]$SafeModePassword = "P@ssw0rd123!",
    
    [Parameter(Mandatory=$false)]
    [int]$NumberOfUsers = 100,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseStaticIP,
    
    [Parameter(Mandatory=$false)]
    [string]$StaticIP = "",
    
    [Parameter(Mandatory=$false)]
    [string]$SubnetPrefixLength = "24",
    
    [Parameter(Mandatory=$false)]
    [string]$DefaultGateway = ""
)

#region Global Variables and State Management
$Global:ScriptPath = $PSCommandPath
$Global:StateFile = "C:\ADLab-Setup-State.json"
$Global:LogFile = "C:\ADLab-Setup.log"
$Global:VulnADPath = "C:\vulnerable-AD"
$Global:RebootPending = $false

# Setup state tracking
$Global:SetupState = @{
    NetworkConfigured = $false
    ADDSInstalled = $false
    DCPromoted = $false
    VulnADDownloaded = $false
    VulnADExecuted = $false
    LastStep = "Start"
    Timestamp = (Get-Date).ToString()
}
#endregion

#region Logging and Output Functions
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $Global:LogFile -Value $logMessage
}

function Write-Success { 
    param($msg) 
    Write-Host "[+] $msg" -ForegroundColor Green
    Write-Log -Message $msg -Level "SUCCESS"
}

function Write-Failure { 
    param($msg) 
    Write-Host "[-] $msg" -ForegroundColor Red
    Write-Log -Message $msg -Level "ERROR"
}

function Write-Status { 
    param($msg) 
    Write-Host "[*] $msg" -ForegroundColor Cyan
    Write-Log -Message $msg -Level "INFO"
}

function Write-Warning { 
    param($msg) 
    Write-Host "[!] $msg" -ForegroundColor Yellow
    Write-Log -Message $msg -Level "WARNING"
}
#endregion

#region State Management Functions
function Save-SetupState {
    $Global:SetupState.Timestamp = (Get-Date).ToString()
    $Global:SetupState | ConvertTo-Json | Out-File -FilePath $Global:StateFile -Force
    Write-Log "State saved: $($Global:SetupState.LastStep)"
}

function Load-SetupState {
    if (Test-Path $Global:StateFile) {
        try {
            $state = Get-Content -Path $Global:StateFile -Raw | ConvertFrom-Json
            
            # Convert PSCustomObject back to hashtable
            $Global:SetupState = @{
                NetworkConfigured = $state.NetworkConfigured
                ADDSInstalled = $state.ADDSInstalled
                DCPromoted = $state.DCPromoted
                VulnADDownloaded = $state.VulnADDownloaded
                VulnADExecuted = $state.VulnADExecuted
                LastStep = $state.LastStep
                Timestamp = $state.Timestamp
            }
            
            Write-Status "Resuming from last state: $($Global:SetupState.LastStep)"
            Write-Log "State loaded successfully"
            return $true
        } catch {
            Write-Warning "Could not load previous state: $_"
            Write-Log "State load failed: $_" -Level "ERROR"
            return $false
        }
    }
    return $false
}

function Set-AutoRunOnReboot {
    Write-Status "Configuring script to auto-run after reboot..."
    
    $runOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    $scriptCmd = "PowerShell.exe -ExecutionPolicy Bypass -WindowStyle Normal -File `"$Global:ScriptPath`""
    
    try {
        Set-ItemProperty -Path $runOnceKey -Name "VulnADSetup" -Value $scriptCmd
        Write-Success "Auto-run configured for next boot"
        Write-Log "RunOnce registry key set"
    } catch {
        Write-Failure "Failed to set auto-run: $_"
        Write-Log "RunOnce setup failed: $_" -Level "ERROR"
    }
}

function Remove-AutoRunOnReboot {
    $runOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    try {
        Remove-ItemProperty -Path $runOnceKey -Name "VulnADSetup" -ErrorAction SilentlyContinue
        Write-Log "RunOnce registry key removed"
    } catch {
        # Silently continue if it doesn't exist
    }
}
#endregion

#region Banner and Information Display
function Show-Banner {
    Clear-Host
    $banner = @"

╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║         VULNERABLE AD LAB - COMPLETE AUTOMATED SETUP              ║
║                                                                   ║
║         Single Script Solution - Zero to Vulnerable               ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

Configuration:
--------------
Domain Name      : $DomainName
NetBIOS Name     : $DomainNetBIOSName
Network Mode     : $(if ($UseStaticIP) { "Static IP: $StaticIP" } else { "DHCP (Dynamic IP)" })
Users to Create  : $NumberOfUsers
Safe Mode Pass   : $SafeModePassword

Current Status   : $($Global:SetupState.LastStep)

"@
    Write-Host $banner -ForegroundColor Cyan
}

function Show-Progress {
    param([string]$Step)
    
    $steps = @(
        "Network Configuration",
        "AD DS Installation",
        "Domain Controller Promotion",
        "Vulnerable-AD Download",
        "Vulnerable Configurations"
    )
    
    $completed = @{
        "Network Configuration" = $Global:SetupState.NetworkConfigured
        "AD DS Installation" = $Global:SetupState.ADDSInstalled
        "Domain Controller Promotion" = $Global:SetupState.DCPromoted
        "Vulnerable-AD Download" = $Global:SetupState.VulnADDownloaded
        "Vulnerable Configurations" = $Global:SetupState.VulnADExecuted
    }
    
    Write-Host "`nSetup Progress:" -ForegroundColor Yellow
    Write-Host "---------------" -ForegroundColor Yellow
    
    foreach ($s in $steps) {
        if ($completed[$s]) {
            Write-Host "  [✓] $s" -ForegroundColor Green
        } elseif ($s -eq $Step) {
            Write-Host "  [→] $s (In Progress)" -ForegroundColor Cyan
        } else {
            Write-Host "  [ ] $s" -ForegroundColor Gray
        }
    }
    Write-Host ""
}
#endregion

#region Network Configuration
function Set-NetworkConfiguration {
    if ($Global:SetupState.NetworkConfigured) {
        Write-Success "Network already configured, skipping..."
        return $true
    }
    
    Show-Progress -Step "Network Configuration"
    
    try {
        # Get the active network adapter
        $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
        
        if (-not $adapter) {
            Write-Failure "No active network adapter found"
            return $false
        }
        
        Write-Status "Using adapter: $($adapter.Name)"
        Write-Status "Interface: $($adapter.InterfaceDescription)"
        
        # Disable IPv6 first (reduces noise in lab environment)
        Write-Status "Disabling IPv6..."
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        
        # Check if user wants static IP
        if ($UseStaticIP) {
            Write-Status "Configuring STATIC IP address..."
            
            if ([string]::IsNullOrEmpty($StaticIP) -or [string]::IsNullOrEmpty($DefaultGateway)) {
                Write-Failure "Static IP requested but IP or Gateway not provided"
                Write-Status "Usage: -UseStaticIP -StaticIP '192.168.1.50' -DefaultGateway '192.168.1.1'"
                return $false
            }
            
            # Remove existing IP configuration
            Remove-NetIPAddress -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            Remove-NetRoute -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            
            # Set static IP
            New-NetIPAddress -InterfaceAlias $adapter.Name `
                             -IPAddress $StaticIP `
                             -PrefixLength $SubnetPrefixLength `
                             -DefaultGateway $DefaultGateway `
                             -ErrorAction Stop | Out-Null
            
            # Set DNS to loopback (this server will be the DNS)
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses "127.0.0.1" -ErrorAction Stop
            
            Write-Success "Static IP configured: $StaticIP"
            Write-Success "Gateway: $DefaultGateway"
            
        } else {
            # DHCP Configuration (DEFAULT)
            Write-Status "Configuring DHCP (Dynamic IP)..."
            Write-Status "This is the recommended mode for bridged networking"
            
            # Enable DHCP on interface
            Set-NetIPInterface -InterfaceAlias $adapter.Name -Dhcp Enabled -ErrorAction Stop
            
            # Reset DNS to DHCP initially
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ResetServerAddresses -ErrorAction SilentlyContinue
            
            Write-Status "Renewing DHCP lease..."
            ipconfig /renew | Out-Null
            
            # Wait for DHCP to assign IP
            Start-Sleep -Seconds 5
            
            # Get the assigned IP
            $ipConfig = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
            
            if ($ipConfig) {
                $currentIP = $ipConfig.IPAddress
                Write-Success "DHCP configuration successful!"
                Write-Success "Assigned IP: $currentIP"
                Write-Host ""
                Write-Warning "IMPORTANT: Configure DHCP reservation for this IP on your router!"
                Write-Warning "MAC Address: $((Get-NetAdapter -Name $adapter.Name).MacAddress)"
                Write-Host ""
            } else {
                Write-Warning "No IP assigned yet, but continuing..."
                Write-Status "IP should be assigned after reboot"
            }
            
            # Set DNS to loopback (this server will become the DNS after DC promotion)
            Write-Status "Setting DNS to localhost (127.0.0.1)..."
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses "127.0.0.1" -ErrorAction Stop
        }
        
        # Show current configuration
        Write-Host ""
        Write-Status "Current Network Configuration:"
        Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 | Format-Table -Property IPAddress, PrefixLength, InterfaceAlias -AutoSize
        Get-NetIPConfiguration -InterfaceAlias $adapter.Name | Select-Object -ExpandProperty IPv4DefaultGateway | Format-Table
        
        Write-Success "Network configuration completed!"
        
        $Global:SetupState.NetworkConfigured = $true
        $Global:SetupState.LastStep = "Network Configured"
        Save-SetupState
        
        return $true
        
    } catch {
        Write-Failure "Failed to configure network: $_"
        Write-Status "Error details: $($_.Exception.Message)"
        
        if ($adapter) {
            Write-Status "`nCurrent network settings:"
            Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Format-List
        }
        
        return $false
    }
}
#endregion

#region AD DS Installation
function Install-ADDomainServices {
    if ($Global:SetupState.ADDSInstalled) {
        Write-Success "AD DS already installed, skipping..."
        return $true
    }
    
    Show-Progress -Step "AD DS Installation"
    Write-Status "Checking AD Domain Services installation..."
    
    $addsFeature = Get-WindowsFeature -Name AD-Domain-Services
    
    if ($addsFeature.Installed) {
        Write-Success "AD DS is already installed"
        $Global:SetupState.ADDSInstalled = $true
        $Global:SetupState.LastStep = "AD DS Installed"
        Save-SetupState
        return $true
    }
    
    Write-Status "Installing AD Domain Services... (This may take 5-10 minutes)"
    Write-Status "Please wait..."
    
    try {
        $result = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
        
        if ($result.Success) {
            Write-Success "AD DS installed successfully"
            $Global:SetupState.ADDSInstalled = $true
            $Global:SetupState.LastStep = "AD DS Installed"
            Save-SetupState
            return $true
        } else {
            Write-Failure "AD DS installation completed with issues"
            return $false
        }
    } catch {
        Write-Failure "Failed to install AD DS: $_"
        return $false
    }
}
#endregion

#region Domain Controller Promotion
function Test-IsDomainController {
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Install-DomainController {
    if ($Global:SetupState.DCPromoted) {
        Write-Success "Server already promoted to DC, skipping..."
        return $true
    }
    
    # Double-check if already a DC (in case state file was lost)
    if (Test-IsDomainController) {
        Write-Success "Server is already a Domain Controller"
        $Global:SetupState.DCPromoted = $true
        $Global:SetupState.LastStep = "DC Promoted"
        Save-SetupState
        return $true
    }
    
    Show-Progress -Step "Domain Controller Promotion"
    Write-Status "Promoting server to Domain Controller..."
    Write-Warning "This will create a new forest and reboot the server"
    
    try {
        $securePassword = ConvertTo-SecureString $SafeModePassword -AsPlainText -Force
        
        Write-Status "Creating new forest: $DomainName"
        Write-Status "NetBIOS Name: $DomainNetBIOSName"
        Write-Status ""
        Write-Warning "Server will reboot automatically after promotion"
        Write-Warning "Script will continue automatically after reboot"
        Write-Status ""
        
        # Set auto-run for after reboot
        Set-AutoRunOnReboot
        
        # Mark as promoted in state (will complete after reboot)
        $Global:SetupState.DCPromoted = $true
        $Global:SetupState.LastStep = "DC Promotion - Reboot Pending"
        Save-SetupState
        
        # Countdown
        for ($i = 10; $i -gt 0; $i--) {
            Write-Host "`rPromotion starting in $i seconds... (Press Ctrl+C to cancel)" -NoNewline -ForegroundColor Yellow
            Start-Sleep -Seconds 1
        }
        Write-Host ""
        
        # Promote to DC
        Install-ADDSForest `
            -DomainName $DomainName `
            -DomainNetBIOSName $DomainNetBIOSName `
            -InstallDNS:$true `
            -SafeModeAdministratorPassword $securePassword `
            -Force:$true `
            -NoRebootOnCompletion:$false `
            -ErrorAction Stop
        
        # If we get here, reboot didn't happen automatically
        Write-Warning "Reboot did not occur automatically. Rebooting now..."
        Restart-Computer -Force
        
        return $false # Won't reach here
        
    } catch {
        Write-Failure "Failed to promote to Domain Controller: $_"
        Write-Failure "Error details: $($_.Exception.Message)"
        
        # Remove auto-run on failure
        Remove-AutoRunOnReboot
        
        return $false
    }
}
#endregion

#region Vulnerable-AD Setup
function Wait-ForADReady {
    Write-Status "Waiting for Active Directory to be fully operational..."
    
    $maxAttempts = 30
    $attemptCount = 0
    
    while ($attemptCount -lt $maxAttempts) {
        try {
            $domain = Get-ADDomain -ErrorAction Stop
            $rootDSE = Get-ADRootDSE -ErrorAction Stop
            
            Write-Success "Active Directory is ready!"
            Write-Status "Domain: $($domain.DNSRoot)"
            Write-Status "Domain DN: $($domain.DistinguishedName)"
            
            return $true
        } catch {
            $attemptCount++
            Write-Host "." -NoNewline
            Start-Sleep -Seconds 2
        }
    }
    
    Write-Failure "Active Directory did not become ready in time"
    return $false
}

function Install-Git {
    Write-Status "Checking for Git installation..."
    
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Success "Git is already installed"
        return $true
    }
    
    Write-Status "Git not found. Installing via direct download..."
    
    try {
        # Download Git installer
        $gitUrl = "https://github.com/git-for-windows/git/releases/download/v2.43.0.windows.1/Git-2.43.0-64-bit.exe"
        $gitInstaller = "$env:TEMP\GitInstaller.exe"
        
        Write-Status "Downloading Git installer..."
        Invoke-WebRequest -Uri $gitUrl -OutFile $gitInstaller -UseBasicParsing
        
        Write-Status "Installing Git (silent)..."
        Start-Process -FilePath $gitInstaller -ArgumentList "/VERYSILENT /NORESTART" -Wait
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        # Verify installation
        if (Get-Command git -ErrorAction SilentlyContinue) {
            Write-Success "Git installed successfully"
            return $true
        } else {
            Write-Warning "Git installed but not in PATH. May need manual configuration."
            return $false
        }
        
    } catch {
        Write-Failure "Failed to install Git: $_"
        return $false
    }
}

function Get-VulnerableADScript {
    if ($Global:SetupState.VulnADDownloaded) {
        Write-Success "Vulnerable-AD already downloaded, skipping..."
        return $true
    }
    
    Show-Progress -Step "Vulnerable-AD Download"
    Write-Status "Downloading Vulnerable-AD repository..."
    
    # Install Git if needed
    if (-not (Install-Git)) {
        Write-Warning "Git installation failed, trying direct download..."
    }
    
    # Remove existing directory
    if (Test-Path $Global:VulnADPath) {
        Write-Status "Removing existing directory..."
        Remove-Item -Path $Global:VulnADPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Try Git clone first
    if (Get-Command git -ErrorAction SilentlyContinue) {
        try {
            Write-Status "Cloning repository with Git..."
            git clone https://github.com/safebuffer/vulnerable-AD.git $Global:VulnADPath 2>&1 | Out-Null
            
            if (Test-Path "$Global:VulnADPath\vulnad.ps1") {
                Write-Success "Repository cloned successfully"
                $Global:SetupState.VulnADDownloaded = $true
                $Global:SetupState.LastStep = "VulnAD Downloaded"
                Save-SetupState
                return $true
            }
        } catch {
            Write-Warning "Git clone failed: $_"
        }
    }
    
    # Fallback: Direct ZIP download
    Write-Status "Downloading as ZIP file..."
    try {
        $zipUrl = "https://github.com/safebuffer/vulnerable-AD/archive/refs/heads/main.zip"
        $zipPath = "$env:TEMP\vulnerable-AD.zip"
        
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
        
        # Extract ZIP
        Expand-Archive -Path $zipPath -DestinationPath "$env:TEMP\vuln-ad-extract" -Force
        
        # Move to final location
        Move-Item -Path "$env:TEMP\vuln-ad-extract\vulnerable-AD-main" -Destination $Global:VulnADPath -Force
        
        # Cleanup
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:TEMP\vuln-ad-extract" -Recurse -Force -ErrorAction SilentlyContinue
        
        if (Test-Path "$Global:VulnADPath\vulnad.ps1") {
            Write-Success "Repository downloaded successfully (ZIP)"
            $Global:SetupState.VulnADDownloaded = $true
            $Global:SetupState.LastStep = "VulnAD Downloaded"
            Save-SetupState
            return $true
        } else {
            Write-Failure "Script file not found after download"
            return $false
        }
        
    } catch {
        Write-Failure "Failed to download repository: $_"
        return $false
    }
}

function Invoke-VulnerableADSetup {
    if ($Global:SetupState.VulnADExecuted) {
        Write-Success "Vulnerable configurations already applied, skipping..."
        return $true
    }
    
    Show-Progress -Step "Vulnerable Configurations"
    Write-Status "Loading and executing Vulnerable-AD script..."
    
    # Wait for AD to be ready
    if (-not (Wait-ForADReady)) {
        Write-Failure "Active Directory is not ready"
        return $false
    }
    
    # Load the script
    $scriptPath = "$Global:VulnADPath\vulnad.ps1"
    
    if (-not (Test-Path $scriptPath)) {
        Write-Failure "Vulnerable-AD script not found at: $scriptPath"
        return $false
    }
    
    try {
        Write-Status "Loading script from: $scriptPath"
        . $scriptPath
        
        Write-Status "Executing Invoke-VulnAD..."
        Write-Status "Creating $NumberOfUsers users with vulnerabilities..."
        Write-Status "This will take several minutes..."
        Write-Status ""
        
        # Execute the vulnerable AD setup
        Invoke-VulnAD -DomainName $DomainName -UsersLimit $NumberOfUsers
        
        Write-Success "Vulnerable AD configuration completed!"
        
        $Global:SetupState.VulnADExecuted = $true
        $Global:SetupState.LastStep = "Complete"
        Save-SetupState
        
        return $true
        
    } catch {
        Write-Failure "Error executing Vulnerable-AD script: $_"
        Write-Failure "Error details: $($_.Exception.Message)"
        return $false
    }
}
#endregion

#region Completion and Summary
function Show-CompletionSummary {
    Clear-Host
    
    # Get actual IP address
    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
    $actualIP = "Unknown"
    if ($adapter) {
        $ipConfig = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ipConfig) {
            $actualIP = $ipConfig.IPAddress
        }
    }
    
    $summary = @"

╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║              🎉 SETUP COMPLETED SUCCESSFULLY! 🎉                  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

DOMAIN INFORMATION:
═══════════════════════════════════════════════════════════════════
Domain Name          : $DomainName
NetBIOS Name         : $DomainNetBIOSName
Domain Controller IP : $actualIP
Safe Mode Password   : $SafeModePassword
Users Created        : $NumberOfUsers

ADMINISTRATOR CREDENTIALS:
═══════════════════════════════════════════════════════════════════
Username: $DomainNetBIOSName\Administrator
Password: P@ssw0rd

VULNERABLE FEATURES CONFIGURED:
═══════════════════════════════════════════════════════════════════
✓ Weak password policy (min 4 chars, no complexity required)
✓ Kerberoastable service accounts with weak passwords
✓ AS-REP Roastable accounts (no pre-authentication)
✓ Misconfigured ACLs (GenericAll, WriteDACL, WriteOwner, etc.)
✓ Users with DCSync privileges
✓ DnsAdmins group memberships
✓ Passwords stored in user descriptions
✓ Default passwords (Changeme123!)
✓ Shared passwords for password spraying (ncc1701)
✓ SMB signing disabled
✓ Multiple privilege escalation paths

NEXT STEPS:
═══════════════════════════════════════════════════════════════════

1. *** CRITICAL: TAKE A VM SNAPSHOT NOW! ***
   - This allows you to reset the lab easily
   - Name it: "Fresh Vulnerable AD Lab"

2. Create Windows 10/11 Client VMs:
   - Network: Bridged (same as DC)
   - DNS Server: $actualIP (this DC)
   - Join to domain: $DomainName
   - Login with domain credentials

3. Create Attacker Machine (Kali Linux):
   - Network: Bridged (same network as DC)
   - IP: DHCP or Static on same subnet
   - Gateway: Same as your network
   - Tools to install:
     • BloodHound: https://github.com/BloodHoundAD/BloodHound
     • Impacket: pip install impacket
     • CrackMapExec: pipx install crackmapexec
     • Rubeus, Mimikatz, PowerView

EXAMPLE ATTACKS TO PRACTICE:
═══════════════════════════════════════════════════════════════════

# Initial Enumeration
nmap -p 88,389,445,135,139 $actualIP
enum4linux -a $actualIP

# Kerberoasting
GetUserSPNs.py $DomainName/user:password -dc-ip $actualIP -request

# AS-REP Roasting
GetNPUsers.py $DomainName/ -dc-ip $actualIP -usersfile users.txt -format hashcat

# BloodHound Collection
SharpHound.exe -c All -d $DomainName --zipfilename bh_data.zip

# Password Spraying
crackmapexec smb $actualIP -u users.txt -p 'ncc1701'
crackmapexec smb $actualIP -u users.txt -p 'Changeme123!'

# SMB Relay (since signing is disabled)
ntlmrelayx.py -tf targets.txt -smb2support

# DCSync Attack (if you compromise a user with DCSync rights)
secretsdump.py $DomainName/user:password@$actualIP

USEFUL BLOODHOUND QUERIES:
═══════════════════════════════════════════════════════════════════
- Find all Domain Admins
- Shortest Path to Domain Admins from Owned Principals
- Find Kerberoastable Users
- Find AS-REP Roastable Users
- Find Computers with Unconstrained Delegation
- Shortest Path from Domain Users to High Value Targets

LAB FILES LOCATION:
═══════════════════════════════════════════════════════════════════
Setup Log        : $Global:LogFile
Setup State      : $Global:StateFile
VulnAD Scripts   : $Global:VulnADPath

SECURITY WARNINGS:
═══════════════════════════════════════════════════════════════════
⚠ This lab is INTENTIONALLY VULNERABLE - DO NOT use in production!
⚠ NEVER connect this lab to the internet or production networks!
⚠ Use NAT or Host-Only networking ONLY!
⚠ Keep regular VM snapshots for easy recovery!
⚠ This is for EDUCATIONAL and TESTING purposes ONLY!

DOCUMENTATION & RESOURCES:
═══════════════════════════════════════════════════════════════════
Vulnerable-AD GitHub  : https://github.com/safebuffer/vulnerable-AD
BloodHound Docs       : https://bloodhound.readthedocs.io/
Impacket GitHub       : https://github.com/SecureAuthCorp/impacket
HackTricks AD Guide   : https://book.hacktricks.xyz/windows-hardening/active-directory-methodology

═══════════════════════════════════════════════════════════════════

Setup completed at: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Happy hacking! 🎯

Press any key to exit...
"@
    
    Write-Host $summary -ForegroundColor Green
    
    # Save summary to file
    $summary | Out-File -FilePath "C:\Lab-Setup-Summary.txt" -Force
    
    # Cleanup
    Remove-AutoRunOnReboot
    
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
#endregion

#region Main Execution
function Main {
    try {
        # Initialize logging
        "=== Vulnerable AD Lab Setup Started ===" | Out-File -FilePath $Global:LogFile -Append
        Write-Log "Script started by: $env:USERNAME"
        Write-Log "Script path: $Global:ScriptPath"
        
        # Load previous state if exists
        Load-SetupState
        
        # Show banner
        Show-Banner
        
        # Check admin privileges
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Failure "This script must be run as Administrator"
            Write-Status "Right-click PowerShell and select 'Run as Administrator'"
            pause
            exit 1
        }
        
        # Set execution policy for this process
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        
        Write-Success "Running with Administrator privileges"
        Write-Status "Setup will proceed automatically..."
        Write-Status ""
        
        # Phase 1: Network Configuration
        if (-not (Set-NetworkConfiguration)) {
            Write-Failure "Network configuration failed. Please check and retry."
            pause
            exit 1
        }
        
        # Phase 2: Install AD DS
        if (-not (Install-ADDomainServices)) {
            Write-Failure "AD DS installation failed. Please check logs."
            pause
            exit 1
        }
        
        # Phase 3: Promote to DC (will reboot)
        if (-not (Install-DomainController)) {
            # If this returns false, either failed or rebooting
            # Script will continue after reboot via RunOnce
            exit 0
        }
        
        # Phase 4: Download Vulnerable-AD (happens after reboot)
        if (-not (Get-VulnerableADScript)) {
            Write-Failure "Failed to download Vulnerable-AD scripts"
            Write-Status "You can manually download from: https://github.com/safebuffer/vulnerable-AD"
            pause
            exit 1
        }
        
        # Phase 5: Execute Vulnerable Configurations
        if (-not (Invoke-VulnerableADSetup)) {
            Write-Failure "Failed to apply vulnerable configurations"
            Write-Status "Check the log file at: $Global:LogFile"
            pause
            exit 1
        }
        
        # Success! Show summary
        Show-CompletionSummary
        
    } catch {
        Write-Failure "Critical error occurred: $_"
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        Write-Log "Critical error: $_" -Level "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
        
        Write-Status "`nCheck the log file for details: $Global:LogFile"
        pause
        exit 1
    }
}

# Script entry point
Write-Host "Starting Vulnerable AD Lab Setup..." -ForegroundColor Cyan
Write-Host "Press Ctrl+C within 5 seconds to cancel..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Main
#endregion
