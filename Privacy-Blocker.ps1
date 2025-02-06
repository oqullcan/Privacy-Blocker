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
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessMicrophone"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessNotifications"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name = "LetAppsAccessAccountInfo"; Value = 2 },
        
        # Windows Search and Cortana Settings
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "AllowCortana"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "DisableWebSearch"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "ConnectedSearchUseWeb"; Value = 0 },
        
        # Enhanced Privacy Settings
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitTextCollection"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitInkCollection"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"; Name = "PreventHandwritingErrorReports"; Value = 1 },

        # New Registry
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "ContentDeliveryAllowed"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "OemPreInstalledAppsEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEverEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338387Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338388Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338389Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-353698Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SystemPaneSuggestionsEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"; Name = "NumberOfSIUFInPeriod"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications"; Value = 1 },
        @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableTailoredExperiencesWithDiagnosticData"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name = "DisabledByGroupPolicy"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"; Name = "DODownloadMode"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"; Name = "fAllowToGetHelp"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"; Name = "EnthusiastMode"; Value = 1 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowTaskViewButton"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"; Name = "PeopleBand"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "LaunchTo"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name = "LongPathsEnabled"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name = "SystemResponsiveness"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name = "NetworkThrottlingIndex"; Value = 4294967295 },
        @{ Path = "HKCU:\Control Panel\Desktop"; Name = "MenuShowDelay"; Value = 1 },
        @{ Path = "HKCU:\Control Panel\Desktop"; Name = "AutoEndTasks"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "ClearPageFileAtShutdown"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Services\Ndu"; Name = "Start"; Value = 2 },
        @{ Path = "HKCU:\Control Panel\Mouse"; Name = "MouseHoverTime"; Value = "400" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "IRPStackSize"; Value = 30 },
        @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"; Name = "EnableFeeds"; Value = 0 },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds"; Name = "ShellFeedsTaskbarViewMode"; Value = 2 },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "HideSCAMeetNow"; Value = 1 },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement"; Name = "ScoobeSystemSettingEnabled"; Value = 0 }
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
    
    # Scheduled tasks to disable
    $scheduledTasksToDisable = @(
        "Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
        "Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
        "Microsoft\\Windows\\Autochk\\Proxy",
        "Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
        "Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
        "Microsoft\\Windows\\DiskDiagnostic\\Microsoft-Windows-DiskDiagnosticDataCollector",
        "Microsoft\\Windows\\Feedback\\Siuf\\DmClient",
        "Microsoft\\Windows\\Feedback\\Siuf\\DmClientOnScenarioDownload",
        "Microsoft\\Windows\\Windows Error Reporting\\QueueReporting",
        "Microsoft\\Windows\\Application Experience\\MareBackup",
        "Microsoft\\Windows\\Application Experience\\StartupAppTask",
        "Microsoft\\Windows\\Application Experience\\PcaPatchDbTask",
        "Microsoft\\Windows\\Maps\\MapsUpdateTask"
    )

    foreach ($task in $scheduledTasksToDisable) {
        # Check if the scheduled task exists
        $taskExists = schtasks /query /TN $task 2>$null
        if ($taskExists) {
            Safe-Execute -Code {
                schtasks /Change /TN $task /DISABLE
            } -ErrorMessage "Failed to disable scheduled task: $task" -Context "Scheduled Task"
        }
    }
    
    Write-Log "Service and scheduled task configuration completed."
}
#endregion

#region Network Security
function Block-TelemetryHosts {
    Write-Log "Updating hosts file to block telemetry domains..."
    
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    
    # Grouped telemetry domains for better readability
    $telemetryDomains = @(
        # Microsoft settings and data collection
        "0.0.0.0 settings-win.data.microsoft.com",
        "0.0.0.0 settings.data.microsoft.com",
        "0.0.0.0 settings-sandbox.data.microsoft.com",
        
        # Browser and telemetry related
        "0.0.0.0 browser.pipe.aria.microsoft.com",
        "0.0.0.0 browser.events.data.microsoft.com",
        
        # Microsoft services and APIs
        "0.0.0.0 dmd.metaservices.microsoft.com",
        "0.0.0.0 ris.api.iris.microsoft.com",
        "0.0.0.0 redir.metaservices.microsoft.com",
        
        # Teams and events
        "0.0.0.0 teams.events.data.microsoft.com",
        "0.0.0.0 events.data.microsoft.com",
        "0.0.0.0 events-sandbox.data.microsoft.com",
        
        # Telemetry and monitoring
        "0.0.0.0 telemetry.microsoft.com",
        "0.0.0.0 telecommand.telemetry.microsoft.com",
        "0.0.0.0 oca.telemetry.microsoft.com",
        "0.0.0.0 sqm.telemetry.microsoft.com",
        "0.0.0.0 watson.telemetry.microsoft.com",
        "0.0.0.0 watson.ppe.telemetry.microsoft.com",
        "0.0.0.0 telemetry.urs.microsoft.com",
        
        # Vortex related
        "0.0.0.0 vortex-win.data.microsoft.com",
        "0.0.0.0 vortex.data.microsoft.com",
        "0.0.0.0 vortex-sandbox.data.microsoft.com",
        "0.0.0.0 v10.vortex-win.data.microsoft.com",
        
        # Watson related
        "0.0.0.0 watson.events.data.microsoft.com",
        "0.0.0.0 watson.microsoft.com",
        "0.0.0.0 umwatsonc.events.data.microsoft.com",
        "0.0.0.0 nw-umwatson.events.data.microsoft.com",
        "0.0.0.0 survey.watson.microsoft.com",
        "0.0.0.0 watson.live.com",
        
        # Regional endpoints
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
        "0.0.0.0 in-v10.events.data.microsoft.com",
        "0.0.0.0 in-v20.events.data.microsoft.com",
        "0.0.0.0 jp-v10.events.data.microsoft.com",
        "0.0.0.0 jp-v20.events.data.microsoft.com",
        
        # Azure storage and services
        "0.0.0.0 ceuswatcab01.blob.core.windows.net",
        "0.0.0.0 ceuswatcab02.blob.core.windows.net",
        "0.0.0.0 eaus2watcab01.blob.core.windows.net",
        "0.0.0.0 eaus2watcab02.blob.core.windows.net",
        "0.0.0.0 weus2watcab01.blob.core.windows.net",
        "0.0.0.0 weus2watcab02.blob.core.windows.net",
        "0.0.0.0 az667904.vo.msecnd.net",
        "0.0.0.0 az361816.vo.msecnd.net",
        
        # Brave browser telemetry
        "0.0.0.0 p3a.brave.com",
        "0.0.0.0 p2a.brave.com",
        "0.0.0.0 p3a-json.brave.com",
        "0.0.0.0 p2a-json.brave.com",
        "0.0.0.0 cr.brave.com",
        "0.0.0.0 star-randsrv.bsg.brave.com",
        
        # Visual Studio and diagnostics
        "0.0.0.0 dc.services.visualstudio.com",
        "0.0.0.0 visualstudio-devdiv-c2s.msedge.net",
        "0.0.0.0 diagnostics.support.microsoft.com",
        
        # Miscellaneous
        "0.0.0.0 activity.windows.com",
        "0.0.0.0 outlookads.live.com",
        "0.0.0.0 mobile.events.data.microsoft.com",
        "0.0.0.0 pipe.dev.trafficmanager.net",
        "0.0.0.0 choice.microsoft.com",
        "0.0.0.0 df.telemetry.microsoft.com",
        "0.0.0.0 reports.wes.df.telemetry.microsoft.com",
        "0.0.0.0 wes.df.telemetry.microsoft.com",
        "0.0.0.0 services.wes.df.telemetry.microsoft.com",
        "0.0.0.0 sqm.df.telemetry.microsoft.com",
        "0.0.0.0 statsfe2.ws.microsoft.com",
        "0.0.0.0 statsfe1.ws.microsoft.com",
        "0.0.0.0 a-0001.a-msedge.net",
        "0.0.0.0 pre.footprintpredict.com",
        "0.0.0.0 i1.services.social.microsoft.com",
        "0.0.0.0 feedback.windows.com",
        "0.0.0.0 feedback.search.microsoft.com",
        "0.0.0.0 rad.msn.com",
        "0.0.0.0 preview.msn.com",
        "0.0.0.0 dart.l.doubleclick.net",
        "0.0.0.0 ads.msn.com",
        "0.0.0.0 ssw.live.com"
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
    
    # Grouped IP addresses for better readability
    $telemetryIPs = @(
        # Group 1
        "20.42.65.90", "20.234.120.54", "104.208.16.91", "20.118.138.130", 
        "65.52.100.9", "20.189.173.16", "20.42.65.92", "20.54.232.160",
        "20.44.10.123", "104.208.16.93", "52.168.117.173", "20.209.184.65",
        "20.60.241.65", "20.60.225.129", "20.209.154.161", "20.150.87.132",
        "20.50.201.194", "52.168.112.67", "13.70.79.200", "20.189.173.27",
        "52.168.117.171", "13.89.178.26", "20.50.201.195", "13.69.239.78",
        
        # Group 2
        "104.46.162.225", "40.79.173.41", "51.104.15.252", "20.189.173.8",
        "20.189.173.14", "20.140.200.208", "52.245.136.44", "20.192.184.194",
        "104.211.81.232", "40.79.189.59", "40.79.197.35", "52.32.227.103",
        "20.50.88.235", "13.107.5.88", "13.89.179.12", "20.42.73.26",
        
        # Group 3
        "191.232.139.254", "65.55.252.92", "65.55.252.63", "65.55.252.93",
        "65.55.252.43", "65.52.108.29", "194.44.4.200", "194.44.4.208",
        "157.56.91.77", "65.52.100.7", "65.52.100.91", "65.52.100.93",
        "65.52.100.92", "65.52.100.94", "65.52.100.9", "65.52.100.11",
        "168.63.108.233", "157.56.74.250", "111.221.29.177", "64.4.54.32",
        
        # Group 4
        "207.68.166.254", "207.46.223.94", "65.55.252.71", "64.4.54.22",
        "131.107.113.238", "23.99.10.11", "68.232.34.200", "204.79.197.200",
        "64.4.54.22", "157.56.77.139", "134.170.58.121", "134.170.58.123",
        "134.170.53.29", "66.119.144.190", "134.170.58.189", "134.170.58.118",
        
        # Group 5
        "134.170.53.30", "134.170.51.190", "157.56.121.89", "131.107.113.238",
        "134.170.115.60", "204.79.197.200", "104.82.22.249", "134.170.185.70",
        "64.4.6.100", "65.55.39.10", "157.55.129.21", "207.46.194.25",
        "23.102.21.4", "173.194.113.220", "173.194.113.219", "216.58.209.166",
        
        # Group 6
        "157.56.91.82", "157.56.23.91", "104.82.14.146", "207.123.56.252",
        "185.13.160.61", "8.254.209.254", "198.78.208.254", "185.13.160.61",
        "185.13.160.61", "8.254.209.254", "207.123.56.252", "68.232.34.200",
        "65.55.252.63", "207.46.101.29", "65.55.108.23", "23.218.212.69"
    )

    # Process each IP address
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
    
    # Configure firewall profiles
    Safe-Execute -Code {
        $null = Set-NetFirewallProfile -Profile Domain,Public,Private `
            -DefaultInboundAction Block `
            -DefaultOutboundAction Allow
    } -ErrorMessage "Failed to configure firewall profiles" -Context "Firewall"
}

function Set-SecureDNS {
    Write-Log "Configuring secure DNS settings with Quad9 and DoH..."
    
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface }
    
    foreach ($adapter in $adapters) {
        Safe-Execute -Code {
            # Set Quad9 DNS servers
            Set-DnsClientServerAddress -InterfaceIndex $adapter.IfIndex -ServerAddresses $SECURE_DNS_SERVERS
            
            # Force enable DNS over HTTPS via registry
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$($adapter.InterfaceGuid)\DohInterfaceSettings"
            
            # Create or update registry settings
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            
            # Set DoHFlags as DWord
            Set-ItemProperty -Path $regPath -Name 'DoHFlags' -Value 1 -Type DWord -Force
            
            # Set string values as String type
            Set-ItemProperty -Path $regPath -Name 'DoHServerAddress' -Value '9.9.9.9' -Type String -Force
            Set-ItemProperty -Path $regPath -Name 'DoHTemplate' -Value 'https://dns.quad9.net/dns-query' -Type String -Force
            
            # Force refresh DNS settings with error handling
            try {
                Stop-Service -Name Dnscache -Force -ErrorAction Stop
                Start-Service -Name Dnscache -ErrorAction Stop
            } catch {
                Write-Log "Warning: Could not restart DNS Client service. Changes may require a system restart to take effect." -level "WARNING"
            }
            
        } -ErrorMessage "Failed to configure DNS for adapter: $($adapter.Name)" -Context "DNS"
    }
}
#endregion

function Flush-DNSCache {
    Write-Log "Flushing DNS cache..."
    $null = ipconfig /flushdns 2>&1 | Out-Null
    Write-Log "DNS cache flushed successfully."
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
    Flush-DNSCache
    
    Write-Log "Privacy hardening completed successfully."
} catch {
    Write-Log "Fatal error during execution: $($_.Exception.Message)" -level "ERROR"
    exit 1
}
#endregion
