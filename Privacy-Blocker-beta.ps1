# Privacy-Blocker.ps1
# This script applies comprehensive privacy-focused configurations on Windows systems.

# credit: revision-team

# Utility Functions
function Write-Log {
    param([string]$message)
    Write-Output "[Privacy-Blocker] $message"
}

function Format-ErrorMessage {
    param([string]$ErrorMessage, [string]$Detail)
    return "$ErrorMessage - $Detail"
}

function Safe-Execute {
    param([ScriptBlock]$Code, [string]$ErrorMessage)
    try { & $Code } catch {
        if ($_.Exception -is [System.UnauthorizedAccessException]) {
            Write-Log "Unauthorized access: $ErrorMessage"
        } else {
            Write-Log (Format-ErrorMessage $ErrorMessage $($_.Exception.Message))
        }
    }
}

# 1. Registry Settings
function Apply-RegistrySettings {
    Write-Log "Applying registry settings..."
    $registryChanges = @(
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "DisableEngine"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "AITEnable"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "DisableUAR"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "DisablePCA"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "DisableInventory"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\AppCompat"; Name = "SbEnable"; Value = 1 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "ContentDeliveryAllowed"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContentEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds"; Name = "EnableConfigFlighting"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "LimitEnhancedDiagnosticDataWindowsAnalytics"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DisableTelemetryOptInSettingsUx"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds"; Name = "EnableConfigFlighting"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableSoftLanding"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "ConfigureWindowsSpotlight"; Value = 2 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableTailoredExperiencesWithDiagnosticData"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightFeatures"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableCloudOptimizedContent"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\Messaging"; Name = "AllowMessageSync"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\EdgeUI"; Name = "DisableHelpSticker"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI"; Name = "DisableMFUTracking"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoPublishingWizard"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoWebServices"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"; Name = "NoGenTicket"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching"; Name = "DontSearchWindowsUpdate"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports"; Name = "PreventHandwritingErrorReports"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\WindowsMovieMaker"; Name = "WebHelp"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\WindowsMovieMaker"; Name = "CodecDownload"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\WindowsMovieMaker"; Name = "WebPublish"; Value = 1 },
        @{ Path = "HKCU:\Software\NVIDIA Corporation\NVControlPanel2\Client"; Name = "OptInOrOutPreference"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"; Name = "Block-Unified-Telemetry-Client"; Value = "v2.31|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=%SystemRoot%\system32\svchost.exe|Svc=DiagTrack|Name=Block-Unified-Telemetry-Client|Desc=Block-Unified-Telemetry-Client|EmbedCtxt=DiagTrack|"; Type = "REG_SZ" },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"; Name = "Block-Windows-Error-Reporting"; Value = "v2.31|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=%SystemRoot%\system32\svchost.exe|Svc=WerSvc|Name=Block-Unified-Telemetry-Client|Desc=Block-Windows-Error-Reporting|EmbedCtxt=WerSvc|"; Type = "REG_SZ" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"; Name = "AllowExperimentation"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\Diagtrack-Listener"; Name = "Start"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\SQMLogger"; Name = "Start"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\SetupPlatformTel"; Name = "Start"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "AutoApproveOSDumps"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "LoggingDisabled"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1 },
        @{ Path = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent"; Name = "DefaultConsent"; Value = 0 },
        @{ Path = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent"; Name = "DefaultOverrideBehavior"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "DontSendAdditionalData"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "DontShowUI"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent"; Name = "0"; Value = "" }
    )
    foreach ($reg in $registryChanges) {
        Safe-Execute {
            if (-not (Test-Path $reg.Path)) {
                New-Item -Path $reg.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value
        } "Failed to apply registry setting for $($reg.Name)"
    }
    
    Write-Log "Registry settings applied successfully."
}

# 2. Disabling Services
function Disable-Services {
    Write-Log "Disabling unnecessary services..."
    $services = @("DiagTrack", "dmwappushsvc", "RemoteRegistry", "WaaSMedicSvc", "DoSvc", "RemoteAccess", "SessionEnv", "TermService")
    foreach ($service in $services) {
        Safe-Execute {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                # Use sc.exe to change the startup type
                Start-Process -FilePath "sc.exe" -ArgumentList "config $service start= disabled" -NoNewWindow -Wait
            }
        } "Failed to disable service: $service"
    }
    Write-Log "Services disabled successfully."
}

# 3. Blocking Telemetry via Hosts File
function Block-TelemetryHosts {
    Write-Log "Modifying the hosts file to block telemetry domains..."
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $telemetryDomains = @(
        "0.0.0.0 settings-win.data.microsoft.com",
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
        Safe-Execute {
            if (-not (Select-String -Path $hostsPath -Pattern ([regex]::Escape($domain)) -Quiet)) {
                Add-Content -Path $hostsPath -Value $domain
            }
        } "Failed to block domain: $domain"
    }
}

# 4. Firewall Rules
function Add-FirewallRules {
    Write-Log "Adding firewall rules to block telemetry IPs..."
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
        Safe-Execute {
            if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
                New-NetFirewallRule -DisplayName "Privacy-Blocker Telemetry - $ip" -Direction Outbound -RemoteAddress $ip -Action Block -Profile Any -Enabled True
                New-NetFirewallRule -DisplayName "Privacy-Blocker Telemetry (Inbound) - $ip" -Direction Inbound -RemoteAddress $ip -Action Block -Profile Any -Enabled True
            } else {
                Write-Log "Invalid IP address: $ip"
            }
        } "Failed to add firewall rule for IP: $ip"
    }
    Safe-Execute { Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow } "Failed to harden firewall settings"
}

# 5. Set Secure DNS (DNS Leak Protection)
function Set-SecureDNS {
    Write-Log "Configuring secure DNS settings..."
    $dnsServers = @("9.9.9.9", "149.112.112.112")
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface }
    foreach ($adapter in $adapters) {
        Safe-Execute {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.IfIndex -ServerAddresses $dnsServers
            Write-Log "DNS for adapter '$($adapter.Name)' set to: $($dnsServers -join ', ')"
        } "Failed to set DNS for adapter: $($adapter.Name)"
    }
}

# Main Execution
Apply-RegistrySettings
Disable-Services
Block-TelemetryHosts
Add-FirewallRules
Set-SecureDNS
