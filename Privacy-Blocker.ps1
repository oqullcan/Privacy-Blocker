<#
    Privacy Hardening Script for Windows Systems
    Version: 2.0
    Author: Security Engineering Team
    Description: Comprehensive privacy-focused configurations for Windows
    Requirements: PowerShell 5.1+ with Administrative Privileges
#>

#region Configuration Constants
$SCRIPT_NAME = "Privacy-Blocker"
$LOG_PREFIX = "[$SCRIPT_NAME]"
$SECURE_DNS_SERVERS = @("9.9.9.9", "149.112.112.112")
#endregion

#region Logging Utilities
function Write-Log {
    param([string]$message, [string]$level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp $LOG_PREFIX [$level] $message"
    Write-Output $logMessage
}

function Format-ErrorMessage {
    param([string]$ErrorMessage, [string]$Detail)
    return "$ErrorMessage - $Detail"
}

function Safe-Execute {
    param(
        [ScriptBlock]$Code,
        [string]$ErrorMessage,
        [string]$Context = "General"
    )
    try {
        & $Code
    } catch {
        $exceptionType = $_.Exception.GetType().Name
        $errorDetail = $_.Exception.Message
        
        switch ($exceptionType) {
            "UnauthorizedAccessException" {
                Write-Log "Access Denied: $ErrorMessage" -level "ERROR"
            }
            "ItemNotFoundException" {
                Write-Log "Resource Not Found: $ErrorMessage" -level "WARNING"
            }
            default {
                Write-Log (Format-ErrorMessage $ErrorMessage $errorDetail) -level "ERROR"
            }
        }
    }
}
#endregion

#region Registry Management
function Apply-RegistrySettings {
    Write-Log "Initializing comprehensive telemetry and privacy registry configuration..."
    
    $registryChanges = @(
        # Enhanced Telemetry and Data Collection Settings
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "LimitEnhancedDiagnosticDataWindowsAnalytics"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DisableTelemetryOptInSettingsUx"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DisableEnterpriseAuthProxy"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DisableOneSettingsDownloads"; Value = 1 },
        
        # Windows Update and Experience Settings
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableOSUpgrade"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DeferFeatureUpdates"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DeferQualityUpdates"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"; Name = "PauseFeatureUpdates"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"; Name = "PauseQualityUpdates"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"; Value = 1 },
        
        # Enhanced Security and Privacy Settings
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LimitBlankPasswordUse"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "NoLMHash"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymous"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymousSAM"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "DisableDomainCreds"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "DisableLoopbackCheck"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictRemoteSAM"; Value = "O:BAG:BAD:(A;;RC;;;BA)" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableAutomaticRestartSignOn"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = "DisableCAD"; Value = 1 },
        
        # Network and Internet Settings
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableICMPRedirect"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableIPSourceRouting"; Value = 2 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "TcpMaxDataRetransmissions"; Value = 3 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "SynAttackProtect"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "EnableDeadGWDetect"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name = "DisableTaskOffload"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"; Name = "DisableIPSourceRouting"; Value = 2 },
        
        # User Experience and Advertising Settings
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "ContentDeliveryAllowed"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContentEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightFeatures"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableCloudOptimizedContent"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableThirdPartySuggestions"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "DisableAutomaticRestartSignOn"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name = "NoLockScreen"; Value = 1 },
        
        # Application Compatibility and Performance Settings
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "DisableEngine"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "AITEnable"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "DisableUAR"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "DisablePCA"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "DisableInventory"; Value = 1 },
        
        # Error Reporting Settings
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "DontSendAdditionalData"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "DontShowUI"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "DisableArchive"; Value = 1 },
        
        # Additional Telemetry Disable Settings
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsRunInBackground"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessLocation"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessCamera"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessMicrophone"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessNotifications"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessAccountInfo"; Value = 2 },
        
        # Windows Search and Cortana Settings
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "DisableWebSearch"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "ConnectedSearchUseWeb"; Value = 0 },
        
        # Enhanced Privacy Settings
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitTextCollection"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitInkCollection"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"; Name = "PreventHandwritingErrorReports"; Value = 1 }
    )

    foreach ($reg in $registryChanges) {
        Safe-Execute -Code {
            if (-not (Test-Path $reg.Path)) {
                New-Item -Path $reg.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value
        } -ErrorMessage "Failed to apply registry setting for $($reg.Name)" -Context "Registry"
    }
    
    Write-Log "Comprehensive registry configuration completed successfully."
}
#endregion

#region Service Management
function Disable-Services {
    Write-Log "Disabling non-essential services..."
    
    $servicesToDisable = @(
        "DiagTrack",        # Diagnostics Tracking Service
        "dmwappushsvc",     # WAP Push Message Routing Service
        "RemoteRegistry",   # Remote Registry Service
        "WaaSMedicSvc"      # Windows Update Medic Service
    )

    foreach ($service in $servicesToDisable) {
        Safe-Execute -Code {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Start-Process -FilePath "sc.exe" -ArgumentList "config $service start= disabled" -NoNewWindow -Wait
            }
        } -ErrorMessage "Failed to disable service: $service" -Context "Service"
    }
    
    Write-Log "Service configuration completed."
}
#endregion

#region Network Security
function Block-TelemetryHosts {
    Write-Log "Updating hosts file to block telemetry domains..."
    
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $telemetryDomains = @(
        "0.0.0.0 settings-win.data.microsoft.com",
        "0.0.0.0 settings.data.microsoft.com",
        "0.0.0.0 browser.pipe.aria.microsoft.com",
        "0.0.0.0 dmd.metaservices.microsoft.com",
        "0.0.0.0 ris.api.iris.microsoft.com",
        "0.0.0.0 teams.events.data.microsoft.com",
        "0.0.0.0 telecommand.telemetry.microsoft.com",
        "0.0.0.0 telemetry.microsoft.com",
        "0.0.0.0 vortex-win.data.microsoft.com",
        "0.0.0.0 watson.events.data.microsoft.com",
        "0.0.0.0 activity.windows.com",
        "0.0.0.0 browser.events.data.microsoft.com",
        "0.0.0.0 outlookads.live.com",
        "0.0.0.0 watson.microsoft.com",
        "0.0.0.0 watson.telemetry.microsoft.com",
        "0.0.0.0 umwatsonc.events.data.microsoft.com",
        "0.0.0.0 ceuswatcab01.blob.core.windows.net",
        "0.0.0.0 ceuswatcab02.blob.core.windows.net",
        "0.0.0.0 eaus2watcab01.blob.core.windows.net",
        "0.0.0.0 eaus2watcab02.blob.core.windows.net",
        "0.0.0.0 weus2watcab01.blob.core.windows.net",
        "0.0.0.0 weus2watcab02.blob.core.windows.net",
        "0.0.0.0 events-sandbox.data.microsoft.com",
        "0.0.0.0 events.data.microsoft.com",
        "0.0.0.0 v10.events.data.microsoft.com",
        "0.0.0.0 v20.events.data.microsoft.com",
        "0.0.0.0 v10c.events.data.microsoft.com",
        "0.0.0.0 v10.vortex-win.data.microsoft.com",
        "0.0.0.0 eu-v10.events.data.microsoft.com",
        "0.0.0.0 eu-v20.events.data.microsoft.com",
        "0.0.0.0 au.vortex-win.data.microsoft.com",
        "0.0.0.0 au-v10.events.data.microsoft.com",
        "0.0.0.0 au-v20.events.data.microsoft.com",
        "0.0.0.0 uk.vortex-win.data.microsoft.com",
        "0.0.0.0 uk-v20.events.data.microsoft.com",
        "0.0.0.0 us-v10.events.data.microsoft.com",
        "0.0.0.0 us-v20.events.data.microsoft.com",
        "0.0.0.0 us4-v20.events.data.microsoft.com",
        "0.0.0.0 us5-v20.events.data.microsoft.com",
        "0.0.0.0 pipe.dev.trafficmanager.net",
        "0.0.0.0 in-v10.events.data.microsoft.com",
        "0.0.0.0 in-v20.events.data.microsoft.com",
        "0.0.0.0 jp-v10.events.data.microsoft.com",
        "0.0.0.0 jp-v20.events.data.microsoft.com",
        "0.0.0.0 p3a.brave.com",
        "0.0.0.0 p2a.brave.com",
        "0.0.0.0 p3a-json.brave.com",
        "0.0.0.0 p2a-json.brave.com",
        "0.0.0.0 cr.brave.com",
        "0.0.0.0 star-randsrv.bsg.brave.com",
        "0.0.0.0 dc.services.visualstudio.com",
        "0.0.0.0 visualstudio-devdiv-c2s.msedge.net",
        "0.0.0.0 az667904.vo.msecnd.net",
        "0.0.0.0 scus-breeziest-in.cloudapp.net",
        "0.0.0.0 nw-umwatson.events.data.microsoft.com",
        "0.0.0.0 mobile.events.data.microsoft.com"
    )

    foreach ($domain in $telemetryDomains) {
        Safe-Execute -Code {
            $hostsContent = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue
            if (-not ($hostsContent -like "*$domain*")) {
                Add-Content -Path $hostsPath -Value $domain -ErrorAction SilentlyContinue
            }
        } -ErrorMessage "Failed to block domain: $domain" -Context "Hosts"
    }
}

function Add-FirewallRules {
    Write-Log "Configuring firewall rules..."
    
    $telemetryIPs = @(
        "20.42.65.90", "20.234.120.54", "104.208.16.91", "20.118.138.130", "65.52.100.9", "20.189.173.16",
        "20.42.65.92", "20.54.232.160", "20.44.10.123", "104.208.16.93", "52.168.117.173", "20.209.184.65",
        "20.60.241.65", "20.60.225.129", "20.209.154.161", "20.150.87.132", "20.50.201.194", "52.168.112.67",
        "13.70.79.200", "20.189.173.27", "52.168.117.171", "13.89.178.26", "20.50.201.195", "13.69.239.78",
        "104.46.162.225", "40.79.173.41", "51.104.15.252", "20.189.173.8", "20.189.173.14", "20.140.200.208",
        "52.245.136.44", "20.192.184.194", "104.211.81.232", "40.79.189.59", "40.79.197.35", "52.32.227.103",
        "20.50.88.235", "13.107.5.88", "13.89.179.12", "20.42.73.26"
    )

    foreach ($ip in $telemetryIPs) {
        Safe-Execute -Code {
            if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
                $null = New-NetFirewallRule -DisplayName "$SCRIPT_NAME Block $ip" `
                    -Direction Outbound `
                    -RemoteAddress $ip `
                    -Action Block `
                    -Profile Any `
                    -Enabled True
            }
        } -ErrorMessage "Failed to add firewall rule for IP: $ip" -Context "Firewall"
    }
    
    Safe-Execute -Code {
        $null = Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow
    } -ErrorMessage "Failed to configure firewall profiles" -Context "Firewall"
}

function Set-SecureDNS {
    Write-Log "Configuring secure DNS settings..."
    
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface }
    
    foreach ($adapter in $adapters) {
        Safe-Execute -Code {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.IfIndex -ServerAddresses $SECURE_DNS_SERVERS
        } -ErrorMessage "Failed to configure DNS for adapter: $($adapter.Name)" -Context "DNS"
    }
}
#endregion

#region Main Execution
try {
    Write-Log "Starting privacy hardening process..."
    
    Apply-RegistrySettings
    Disable-Services
    Block-TelemetryHosts
    Add-FirewallRules
    Set-SecureDNS
    
    Write-Log "Privacy hardening completed successfully."
} catch {
    Write-Log "Fatal error during execution: $($_.Exception.Message)" -level "ERROR"
    exit 1
}
#endregion
