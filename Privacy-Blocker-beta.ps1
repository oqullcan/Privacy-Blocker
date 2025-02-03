# Privacy-Blocker.ps1

# ----------------------
# Utility Functions
# ----------------------
function Write-Log {
    param([string]$message)
    Write-Output "[Privacy-Blocker] $message"
}

# Error Handling Wrapper
function Safe-Execute {
    param(
        [ScriptBlock]$Code,
        [string]$ErrorMessage
    )
    try {
        & $Code
    } catch {
        Write-Log "$ErrorMessage - $($_.Exception.Message)"
    }
}

# ----------------------
# 1. Registry Settings
# ----------------------
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
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "ContentDeliveryAllowed"; Value = 0 },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContentEnabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContentEnabled"; Value = 0 },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-310093Enabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-310093Enabled"; Value = 0 },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SoftLandingEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338389Enabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SoftLandingEnabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338389Enabled"; Value = 0 },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0 },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEverEnabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEnabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "PreInstalledAppsEverEnabled"; Value = 0 },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "OemPreInstalledAppsEnabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "OemPreInstalledAppsEnabled"; Value = 0 },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "FeatureManagementEnabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "FeatureManagementEnabled"; Value = 0 },

        # Remove unwanted registry keys:
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions"; RemoveKey = $true },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions"; RemoveKey = $true },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps"; RemoveKey = $true },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps"; RemoveKey = $true },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "RemediationRequired"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "RemediationRequired"; Value = 0 },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-314559Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-280815Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-314563Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-202914Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338387Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-280810Enabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-280811Enabled"; Value = 0 },

        # For DEFAULT USER:
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-314559Enabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-280815Enabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-314563Enabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-202914Enabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338387Enabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-280810Enabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-280811Enabled"; Value = 0 },

        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "RotatingLockScreenEnabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "RotatingLockScreenEnabled"; Value = 0 },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "RotatingLockScreenOverlayEnabled"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "RotatingLockScreenOverlayEnabled"; Value = 0 },

        @{ Path = "HKLM:\Software\Policies\Microsoft\SQMClient\Windows"; Name = "CEIPEnable"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP"; Name = "CEIPEnable"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Internet Explorer\SQM"; Name = "DisableCustomerImprovementProgram"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Messenger\Client"; Name = "CEIP"; Value = 2 },
        @{ Path = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient"; Name = "CEIPEnabled"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableSoftLanding"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "ConfigureWindowsSpotlight"; Value = 2 },
        @{ Path = "HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent"; Name = "ConfigureWindowsSpotlight"; Value = 2 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "IncludeEnterpriseSpotlight"; Value = 0 },
        @{ Path = "HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent"; Name = "IncludeEnterpriseSpotlight"; Value = 0 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableThirdPartySuggestions"; Value = 1 },
        @{ Path = "HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableThirdPartySuggestions"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableTailoredExperiencesWithDiagnosticData"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableTailoredExperiencesWithDiagnosticData"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightFeatures"; Value = 1 },
        @{ Path = "HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightFeatures"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightWindowsWelcomeExperience"; Value = 1 },
        @{ Path = "HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightWindowsWelcomeExperience"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightOnActionCenter"; Value = 1 },
        @{ Path = "HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightOnActionCenter"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightOnSettings"; Value = 1 },
        @{ Path = "HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsSpotlightOnSettings"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableCloudOptimizedContent"; Value = 1 },

        # === App runtime ===
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "MSAOptional"; Value = 1 },

        # === Messaging ===
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\Messaging"; Name = "AllowMessageSync"; Value = 0 },

        # === Edge UI ===
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\EdgeUI"; Name = "DisableHelpSticker"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI"; Name = "DisableMFUTracking"; Value = 1 },
        @{ Path = "HKU:\.DEFAULT\Software\Policies\Microsoft\Windows\EdgeUI"; Name = "DisableMFUTracking"; Value = 1 },

        # === Restrict Internet communication (HKEY_CURRENT_USER) ===
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoPublishingWizard"; Value = 1 },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoWebServices"; Value = 1 },
        @{ Path = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"; Name = "NoGenTicket"; Value = 1 },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoOnlinePrintsWizard"; Value = 1 },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoInternetOpenWith"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows NT\Printers"; Name = "DisableHTTPPrinting"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows NT\Printers"; Name = "DisableWebPnPDownload"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports"; Name = "PreventHandwritingErrorReports"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0"; Name = "NoOnlineAssist"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0"; Name = "NoExplicitFeedback"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0"; Name = "NoImplicitFeedback"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\WindowsMovieMaker"; Name = "WebHelp"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\WindowsMovieMaker"; Name = "CodecDownload"; Value = 1 },
        @{ Path = "HKCU:\Software\Policies\Microsoft\WindowsMovieMaker"; Name = "WebPublish"; Value = 1 },

        # === Restrict Internet communication (HKLM) ===
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoPublishingWizard"; Value = 1 },
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoWebServices"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"; Name = "NoGenTicket"; Value = 1 },
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoOnlinePrintsWizard"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\PCHealth\HelpSvc"; Name = "Headlines"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\PCHealth\HelpSvc"; Name = "MicrosoftKBSearch"; Value = 0 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\PCHealth\ErrorReporting"; Name = "DoReport"; Value = 0 },
        @{ Path = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1 },
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoInternetOpenWith"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\Internet Connection Wizard"; Name = "ExitOnMSICW"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\EventViewer"; Name = "MicrosoftEventVwrDisableLinks"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control"; Name = "NoRegistration"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\SearchCompanion"; Name = "DisableContentFileUpdates"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"; Name = "DisableHTTPPrinting"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"; Name = "DisableWebPnPDownload"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching"; Name = "DontSearchWindowsUpdate"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports"; Name = "PreventHandwritingErrorReports"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\WindowsMovieMaker"; Name = "WebHelp"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\WindowsMovieMaker"; Name = "CodecDownload"; Value = 1 },
        @{ Path = "HKLM:\Software\Policies\Microsoft\WindowsMovieMaker"; Name = "WebPublish"; Value = 1 },

        # === NVIDIA Telemetry - Disabled ===
        @{ Path = "HKCU:\Software\NVIDIA Corporation\NVControlPanel2\Client"; Name = "OptInOrOutPreference"; Value = 0 },

        # === Firewall Rules via Registry (Block Telemetry & Error Reporting) ===
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"; Name = "Block-Unified-Telemetry-Client"; Value = "v2.31|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=%SystemRoot%\system32\svchost.exe|Svc=DiagTrack|Name=Block-Unified-Telemetry-Client|Desc=Block-Unified-Telemetry-Client|EmbedCtxt=DiagTrack|"; Type = "REG_SZ" },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"; Name = "Block-Windows-Error-Reporting"; Value = "v2.31|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=%SystemRoot%\system32\svchost.exe|Svc=WerSvc|Name=Block-Unified-Telemetry-Client|Desc=Block-Windows-Error-Reporting|EmbedCtxt=WerSvc|"; Type = "REG_SZ" },
        
        # === Allow Telemetry - Disabled
        @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry"; Name = "value"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\DevicePolicy\AllowTelemetry"; Name = "DefaultValue"; Value = 0 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\Store\AllowTelemetry"; Name = "Value"; Value = 0 },

        # === Allow commercial data pipeline - Disabled
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "AllowCommercialDataPipeline"; Value = 0 },

        # === Allow device name to be sent in Windows diagnostic data - Disabled
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "AllowDeviceNameInTelemetry"; Value = 0 },

        # === Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service - Disabled
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DisableEnterpriseAuthProxy"; Value = 1 },

        # === Configure collection of browsing data for Desktop Analytics - Disabled
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "MicrosoftEdgeDataOptIn"; Value = 0 },

        # === Configure telemetry opt-in change notifications - Disable telemetry change notifications
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DisableTelemetryOptInChangeNotification"; Value = 1 },

        # === Configure telemetry opt-in setting user interface - Disable telemetry opt-in Settings
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DisableTelemetryOptInSettingsUx"; Value = 1 },

        # === Disable pre-release features or settings - Enabled (Disable experimentations)
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds"; Name = "EnableConfigFlighting"; Value = 0 },

        # === Do not show feedback notifications - Enabled
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications"; Value = 1 },

        # === Limit Enhanced diagnostic data to the minimum required by Windows Analytics - Disabled collection
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "LimitEnhancedDiagnosticDataWindowsAnalytics"; Value = 0 },

        # === Toggle user control over Insider builds - Disabled
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "AllowBuildPreview"; Value = 0 },

        # === Limit Diagnostic Log Collection - Enabled
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "LimitDiagnosticLogCollection"; Value = 1 },

        # === Limit Dump Collection - Enabled
        @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name = "LimitDumpCollection"; Value = 1 },

        # === Allow Experimentation - Disabled
        @{ Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System"; Name = "AllowExperimentation"; Value = 0 },

        # === WMI\Autologger - Disabled
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\Diagtrack-Listener"; Name = "Start"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\SQMLogger"; Name = "Start"; Value = 0 },
        @{ Path = "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\SetupPlatformTel"; Name = "Start"; Value = 0 },

        # === Automatically send memory dumps for OS-generated error reports - Disabled
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "AutoApproveOSDumps"; Value = 0 },

        # === Disable logging - Enabled
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "LoggingDisabled"; Value = 1 },

        # === Disable Windows Error Reporting - Enabled
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1 },

        # === DefaultConsent settings for Windows Error Reporting
        @{ Path = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent"; Name = "DefaultConsent"; Value = 0 },
        @{ Path = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent"; Name = "DefaultOverrideBehavior"; Value = 1 },

        # === Do not send additional data - Enabled
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "DontSendAdditionalData"; Value = 1 },

        # === Prevent display of the user interface for critical errors - Enabled
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "DontShowUI"; Value = 1 },

        # ======> Consent: Customize consent settings (Disable data sending)
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent"; Name = "0"; Value = "" }
    
    )
    
    foreach ($reg in $registryChanges) {
        Safe-Execute {
            # Prior to creating a registry path, it is imperative to verify its existence to prevent redundant operations.
            if (-not (Test-Path $reg.Path)) {
                New-Item -Path $reg.Path -Force | Out-Null
            }
            # The Set-ItemProperty cmdlet is employed to assign a specified value to a registry key, ensuring the desired configuration is applied.
            Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value
        } "Failed to apply registry setting for $($reg.Name)"
    }
}

# ----------------------
# 2. Disabling Services
# ----------------------
function Disable-Services {
    Write-Log "Disabling unnecessary services..."
    
    $services = @("DiagTrack", "dmwappushsvc", "RemoteRegistry", "WaaSMedicSvc", "DoSvc", "RemoteAccess", "SessionEnv", "TermService")
    
    foreach ($service in $services) {
        Safe-Execute {
            # The existence of a service is verified before any attempt to stop or disable it, ensuring that operations are only performed on valid services.
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled
            }
        } "Failed to disable service: $service"
    }
}

# ----------------------
# 3. Blocking Telemetry via Hosts File
# ----------------------
function Block-TelemetryHosts {
    Write-Log "Modifying the hosts file to block telemetry domains..."
    
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    # Comprehensive list of telemetry and related domains
    $telemetryDomains = @(

        # Microsoft Telemetry & Related Services
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

        # Windows Error Reporting Endpoints
        "0.0.0.0 watson.microsoft.com",
        "0.0.0.0 watson.telemetry.microsoft.com",
        "0.0.0.0 umwatsonc.events.data.microsoft.com",
        "0.0.0.0 ceuswatcab01.blob.core.windows.net",
        "0.0.0.0 ceuswatcab02.blob.core.windows.net",
        "0.0.0.0 eaus2watcab01.blob.core.windows.net",
        "0.0.0.0 eaus2watcab02.blob.core.windows.net",
        "0.0.0.0 weus2watcab01.blob.core.windows.net",
        "0.0.0.0 weus2watcab02.blob.core.windows.net",

        # DiagTrack/Telemetry Endpoints
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

        # Brave Browser Telemetry
        "0.0.0.0 p3a.brave.com",
        "0.0.0.0 p2a.brave.com",
        "0.0.0.0 p3a-json.brave.com",
        "0.0.0.0 p2a-json.brave.com",
        "0.0.0.0 cr.brave.com",
        "0.0.0.0 star-randsrv.bsg.brave.com",

        # Visual Studio / VSCode Telemetry
        "0.0.0.0 dc.services.visualstudio.com",
        "0.0.0.0 visualstudio-devdiv-c2s.msedge.net",
        "0.0.0.0 az667904.vo.msecnd.net",
        "0.0.0.0 scus-breeziest-in.cloudapp.net",
        "0.0.0.0 nw-umwatson.events.data.microsoft.com",
        "0.0.0.0 mobile.events.data.microsoft.com"

    )
    
    foreach ($domain in $telemetryDomains) {
        Safe-Execute {
            # It is crucial to ascertain that the hosts file is not being accessed by another process to avoid file access conflicts.
            if (-not (Select-String -Path $hostsPath -Pattern ([regex]::Escape($domain)) -Quiet)) {
                Add-Content -Path $hostsPath -Value $domain
            }
        } "Failed to block domain: $domain"
    }
}

# ----------------------
# 4. Firewall Rules
# ----------------------
function Add-FirewallRules {
    Write-Log "Adding firewall rules to block telemetry IPs..."
    
    $telemetryIPs = @(
        "20.42.65.90",
        "20.234.120.54",
        "104.208.16.91",
        "20.118.138.130",
        "65.52.100.9",
        "20.189.173.16",
        "20.42.65.92",
        "20.54.232.160",
        "20.44.10.123",
        "2603",
        "104.208.16.93",
        "52.168.117.173",
        "20.42.65.92",
        "20.209.184.65",
        "20.60.241.65",
        "20.60.225.129",
        "20.60.225.129",
        "20.209.154.161",
        "20.150.87.132",
        "20.50.201.194",
        "52.168.112.67",
        "13.70.79.200",
        "20.189.173.27",
        "52.168.117.171",
        "13.89.178.26",
        "20.50.201.195",
        "13.69.239.78",
        "20.42.65.90",
        "104.46.162.225",
        "40.79.173.41",
        "51.104.15.252",
        "51.104.15.252",
        "20.189.173.8",
        "20.189.173.14",
        "20.140.200.208",
        "52.245.136.44",
        "0.0.0.0",
        "20.192.184.194",
        "104.211.81.232",
        "40.79.189.59",
        "40.79.197.35",
        "2a04",
        "2606",
        "2a04",
        "2606",
        "2a04",
        "52.32.227.103",
        "20.50.88.235",
        "13.107.5.88",
        "2a02",
        "13.89.179.12",
        "20.42.73.26"
    )
    
    foreach ($ip in $telemetryIPs) {
        Safe-Execute {
            New-NetFirewallRule -DisplayName "Block Telemetry - $ip" -Direction Outbound -RemoteAddress $ip -Action Block -Profile Any -Enabled True
            New-NetFirewallRule -DisplayName "Block Telemetry (Inbound) - $ip" -Direction Inbound -RemoteAddress $ip -Action Block -Profile Any -Enabled True
        } "Failed to add firewall rule for IP: $ip"
    }
    
    # Harden Windows Defender Firewall: Block inbound traffic by default.
    Safe-Execute {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    } "Failed to harden firewall settings"
}

# ----------------------
# 7. Set Secure DNS (DNS Leak Protection)
# ----------------------
function Set-SecureDNS {
    Write-Log "Configuring secure DNS settings..."
    # Define secure DNS servers (Quad9 and Cloudflare as examples)
    $dnsServers = @("9.9.9.9", "149.112.112.112")
    
    # Get all active physical network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface }
    
    foreach ($adapter in $adapters) {
        Safe-Execute {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.IfIndex -ServerAddresses $dnsServers
            Write-Log "DNS for adapter '$($adapter.Name)' set to: $($dnsServers -join ', ')"
        } "Failed to set DNS for adapter: $($adapter.Name)"
    }
}

# ----------------------
# Main Execution (updated)
# ----------------------
Apply-RegistrySettings
Apply-AdditionalRegistrySettings
Apply-TelemetryRegistrySettings
Disable-Services
Block-TelemetryHosts
Add-FirewallRules
Set-SecureDNS
