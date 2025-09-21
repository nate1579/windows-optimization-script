# Windows Optimization Script - Complete Combined Tweaks
# WARNING: This script makes significant system changes. Use at your own risk.
# Create a system restore point before running this script.
# Some changes may require a reboot to take effect.

# Self-elevate the script if required
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    try {
        # Re-run this script as Administrator
        Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
    catch {
        Write-Error "Failed to elevate to Administrator privileges. Please run PowerShell as Administrator manually."
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
}

Write-Host "Starting Windows Optimization Script..." -ForegroundColor Green
Write-Host "WARNING: This will make significant system changes!" -ForegroundColor Yellow

# Function to safely set registry values
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Value,
        [string]$Type
    )
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
        Write-Host "Set registry: $Path\$Name = $Value" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Failed to set registry value: $Path\$Name"
    }
}

# Function to safely set service startup type
function Set-ServiceStartup {
    param(
        [string]$ServiceName,
        [string]$StartupType
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Set-Service -Name $ServiceName -StartupType $StartupType -ErrorAction SilentlyContinue
            Write-Host "Set service $ServiceName to $StartupType" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Failed to configure service: $ServiceName"
    }
}

# Function to safely disable scheduled tasks
function Disable-ScheduledTaskSafe {
    param([string]$TaskName)
    
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Disabled scheduled task: $TaskName" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Failed to disable scheduled task: $TaskName"
    }
}

Write-Host "1. Cleaning temporary files..." -ForegroundColor Cyan
try {
    Get-ChildItem -Path "C:\Windows\Temp" *.* -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    Get-ChildItem -Path $env:TEMP *.* -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    Write-Host "Temporary files cleaned" -ForegroundColor Green
}
catch {
    Write-Warning "Some temporary files could not be deleted (may be in use)"
}

Write-Host "2. Disabling Consumer Features..." -ForegroundColor Cyan
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value "1" -Type "DWord"

Write-Host "3. Disabling Telemetry..." -ForegroundColor Cyan

# Disable telemetry scheduled tasks
$telemetryTasks = @(
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "Microsoft\Windows\Autochk\Proxy",
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "Microsoft\Windows\Feedback\Siuf\DmClient",
    "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
    "Microsoft\Windows\Windows Error Reporting\QueueReporting",
    "Microsoft\Windows\Application Experience\MareBackup",
    "Microsoft\Windows\Application Experience\StartupAppTask",
    "Microsoft\Windows\Application Experience\PcaPatchDbTask",
    "Microsoft\Windows\Maps\MapsUpdateTask"
)

foreach ($task in $telemetryTasks) {
    Disable-ScheduledTaskSafe -TaskName $task
}

# Complete telemetry registry settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value "1" -Type "DWord"

# Content Delivery Manager settings
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value "0" -Type "DWord"

# Additional telemetry settings
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value "0" -Type "DWord"

# Explorer and UI settings
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value "1" -Type "DWord"

# System performance settings
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value "4294967295" -Type "DWord"

# Desktop and input settings
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Value "2" -Type "DWord"
Set-RegistryValue -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Value "400" -Type "String"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Value "30" -Type "DWord"

# Windows Feeds and Meet Now
Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Value "2" -Type "DWord"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value "0" -Type "DWord"

# Additional telemetry script actions
try {
    # Set boot menu policy
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
    
    # Configure Task Manager (Windows 10 build < 22557)
    $currentBuild = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild).CurrentBuild
    if ($currentBuild -lt 22557) {
        $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
        do {
            Start-Sleep -Milliseconds 100
            $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
        } while (-not $preferences)
        Stop-Process $taskmgr
        $preferences.Preferences[28] = 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    }
    
    # Remove 3D Objects from This PC
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
    
    # Remove Edge managed by organization
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge") {
        Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Recurse -ErrorAction SilentlyContinue
    }
    
    # Configure svchost grouping based on RAM
    $ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $ram -Force
    
    # Disable AutoLogger
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    if (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
    
    # Disable Defender Auto Sample Submission
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue | Out-Null
    
    Write-Host "Advanced telemetry configuration completed" -ForegroundColor Green
}
catch {
    Write-Warning "Some advanced telemetry configurations failed"
}

Write-Host "4. Disabling Activity History..." -ForegroundColor Cyan
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value "0" -Type "DWord"

Write-Host "5. Disabling GameDVR..." -ForegroundColor Cyan
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value "2" -Type "DWord"
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Value "1" -Type "DWord"
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value "0" -Type "DWord"

Write-Host "6. Disabling HomeGroup services..." -ForegroundColor Cyan
Set-ServiceStartup -ServiceName "HomeGroupListener" -StartupType "Manual"
Set-ServiceStartup -ServiceName "HomeGroupProvider" -StartupType "Manual"

Write-Host "7. Disabling Location Tracking..." -ForegroundColor Cyan
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Type "String"
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Value "0" -Type "DWord"

Write-Host "8. Disabling Storage Sense..." -ForegroundColor Cyan
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value "0" -Type "DWord"

Write-Host "9. Disabling WiFi Sense..." -ForegroundColor Cyan
Set-RegistryValue -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value "0" -Type "DWord"
Set-RegistryValue -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value "0" -Type "DWord"

Write-Host "10. Enabling End Task on Taskbar..." -ForegroundColor Cyan
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" -Name "TaskbarEndTask" -Value "1" -Type "DWord"

Write-Host "11. Disabling PowerShell 7 Telemetry..." -ForegroundColor Cyan
try {
    [Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')
    Write-Host "PowerShell 7 telemetry disabled" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to set PowerShell telemetry environment variable"
}

Write-Host "12. Configuring all services to optimal startup types..." -ForegroundColor Cyan

# Complete service configuration from original script (cleaned of duplicates)
$serviceConfigurations = @{
    "AJRouter" = "Disabled"
    "ALG" = "Manual"
    "AppIDSvc" = "Manual"
    "AppMgmt" = "Manual"
    "AppReadiness" = "Manual"
    "AppVClient" = "Disabled"
    "AppXSvc" = "Manual"
    "Appinfo" = "Manual"
    "AssignedAccessManagerSvc" = "Disabled"
    "AudioEndpointBuilder" = "Automatic"
    "AudioSrv" = "Automatic"
    "AxInstSV" = "Manual"
    "BDESVC" = "Manual"
    "BFE" = "Automatic"
    "BITS" = "AutomaticDelayedStart"
    "BTAGService" = "Manual"
    "BrokerInfrastructure" = "Automatic"
    "Browser" = "Manual"
    "BthAvctpSvc" = "Automatic"
    "BthHFSrv" = "Automatic"
    "CDPSvc" = "Manual"
    "COMSysApp" = "Manual"
    "CertPropSvc" = "Manual"
    "ClipSVC" = "Manual"
    "CoreMessagingRegistrar" = "Automatic"
    "CryptSvc" = "Automatic"
    "CscService" = "Manual"
    "DPS" = "Automatic"
    "DcomLaunch" = "Automatic"
    "DcpSvc" = "Manual"
    "DevQueryBroker" = "Manual"
    "DeviceAssociationService" = "Manual"
    "DeviceInstall" = "Manual"
    "Dhcp" = "Automatic"
    "DiagTrack" = "Disabled"
    "DialogBlockingService" = "Disabled"
    "DispBrokerDesktopSvc" = "Automatic"
    "DisplayEnhancementService" = "Manual"
    "DmEnrollmentSvc" = "Manual"
    "Dnscache" = "Automatic"
    "DoSvc" = "AutomaticDelayedStart"
    "DsSvc" = "Manual"
    "DsmSvc" = "Manual"
    "DusmSvc" = "Automatic"
    "EFS" = "Manual"
    "EapHost" = "Manual"
    "EntAppSvc" = "Manual"
    "EventLog" = "Automatic"
    "EventSystem" = "Automatic"
    "FDResPub" = "Manual"
    "Fax" = "Manual"
    "FontCache" = "Automatic"
    "FrameServer" = "Manual"
    "FrameServerMonitor" = "Manual"
    "GraphicsPerfSvc" = "Manual"
    "HomeGroupListener" = "Manual"
    "HomeGroupProvider" = "Manual"
    "HvHost" = "Manual"
    "IEEtwCollectorService" = "Manual"
    "IKEEXT" = "Manual"
    "InstallService" = "Manual"
    "InventorySvc" = "Manual"
    "IpxlatCfgSvc" = "Manual"
    "KeyIso" = "Automatic"
    "KtmRm" = "Manual"
    "LSM" = "Automatic"
    "LanmanServer" = "Automatic"
    "LanmanWorkstation" = "Automatic"
    "LicenseManager" = "Manual"
    "LxpSvc" = "Manual"
    "MSDTC" = "Manual"
    "MSiSCSI" = "Manual"
    "MapsBroker" = "AutomaticDelayedStart"
    "McpManagementService" = "Manual"
    "MicrosoftEdgeElevationService" = "Manual"
    "MixedRealityOpenXRSvc" = "Manual"
    "MpsSvc" = "Automatic"
    "MsKeyboardFilter" = "Manual"
    "NaturalAuthentication" = "Manual"
    "NcaSvc" = "Manual"
    "NcbService" = "Manual"
    "NcdAutoSetup" = "Manual"
    "NetSetupSvc" = "Manual"
    "NetTcpPortSharing" = "Disabled"
    "Netlogon" = "Automatic"
    "Netman" = "Manual"
    "NgcCtnrSvc" = "Manual"
    "NgcSvc" = "Manual"
    "NlaSvc" = "Manual"
    "PNRPAutoReg" = "Manual"
    "PNRPsvc" = "Manual"
    "PcaSvc" = "Manual"
    "PeerDistSvc" = "Manual"
    "PerfHost" = "Manual"
    "PhoneSvc" = "Manual"
    "PlugPlay" = "Manual"
    "PolicyAgent" = "Manual"
    "Power" = "Automatic"
    "PrintNotify" = "Manual"
    "ProfSvc" = "Automatic"
    "PushToInstall" = "Manual"
    "QWAVE" = "Manual"
    "RasAuto" = "Manual"
    "RasMan" = "Manual"
    "RemoteAccess" = "Disabled"
    "RemoteRegistry" = "Disabled"
    "RetailDemo" = "Manual"
    "RmSvc" = "Manual"
    "RpcEptMapper" = "Automatic"
    "RpcLocator" = "Manual"
    "RpcSs" = "Automatic"
    "SCPolicySvc" = "Manual"
    "SCardSvr" = "Manual"
    "SDRSVC" = "Manual"
    "SEMgrSvc" = "Manual"
    "SENS" = "Automatic"
    "SNMPTRAP" = "Manual"
    "SSDPSRV" = "Manual"
    "SamSs" = "Automatic"
    "ScDeviceEnum" = "Manual"
    "Schedule" = "Automatic"
    "SecurityHealthService" = "Manual"
    "Sense" = "Manual"
    "SensorDataService" = "Manual"
    "SensorService" = "Manual"
    "SensrSvc" = "Manual"
    "SessionEnv" = "Manual"
    "SgrmBroker" = "Automatic"
    "SharedAccess" = "Manual"
    "SharedRealitySvc" = "Manual"
    "ShellHWDetection" = "Automatic"
    "SmsRouter" = "Manual"
    "Spooler" = "Automatic"
    "SstpSvc" = "Manual"
    "StateRepository" = "Manual"
    "StiSvc" = "Manual"
    "StorSvc" = "Manual"
    "SysMain" = "Automatic"
    "SystemEventsBroker" = "Automatic"
    "TabletInputService" = "Manual"
    "TapiSrv" = "Manual"
    "TermService" = "Automatic"
    "TextInputManagementService" = "Manual"
    "Themes" = "Automatic"
    "TieringEngineService" = "Manual"
    "TimeBroker" = "Manual"
    "TimeBrokerSvc" = "Manual"
    "TokenBroker" = "Manual"
    "TrkWks" = "Automatic"
    "TroubleshootingSvc" = "Manual"
    "TrustedInstaller" = "Manual"
    "UI0Detect" = "Manual"
    "UevAgentService" = "Disabled"
    "UmRdpService" = "Manual"
    "UserManager" = "Automatic"
    "UsoSvc" = "Manual"
    "VGAuthService" = "Automatic"
    "VMTools" = "Automatic"
    "VSS" = "Manual"
    "VacSvc" = "Manual"
    "VaultSvc" = "Automatic"
    "W32Time" = "Manual"
    "WEPHOSTSVC" = "Manual"
    "WFDSConMgrSvc" = "Manual"
    "WMPNetworkSvc" = "Manual"
    "WManSvc" = "Manual"
    "WPDBusEnum" = "Manual"
    "WSService" = "Manual"
    "WSearch" = "AutomaticDelayedStart"
    "WaaSMedicSvc" = "Manual"
    "WalletService" = "Manual"
    "WarpJITSvc" = "Manual"
    "WbioSrvc" = "Manual"
    "Wcmsvc" = "Automatic"
    "WcsPlugInService" = "Manual"
    "WdNisSvc" = "Manual"
    "WdiServiceHost" = "Manual"
    "WdiSystemHost" = "Manual"
    "WebClient" = "Manual"
    "Wecsvc" = "Manual"
    "WerSvc" = "Manual"
    "WiaRpc" = "Manual"
    "WinDefend" = "Automatic"
    "WinHttpAutoProxySvc" = "Manual"
    "WinRM" = "Manual"
    "Winmgmt" = "Automatic"
    "WlanSvc" = "Automatic"
    "WpcMonSvc" = "Manual"
    "WpnService" = "Manual"
    "XblAuthManager" = "Manual"
    "XblGameSave" = "Manual"
    "XboxGipSvc" = "Manual"
    "XboxNetApiSvc" = "Manual"
    "autotimesvc" = "Manual"
    "bthserv" = "Manual"
    "camsvc" = "Manual"
    "cloudidsvc" = "Manual"
    "dcsvc" = "Manual"
    "defragsvc" = "Manual"
    "diagnosticshub.standardcollector.service" = "Manual"
    "diagsvc" = "Manual"
    "dmwappushservice" = "Manual"
    "dot3svc" = "Manual"
    "edgeupdate" = "Manual"
    "edgeupdatem" = "Manual"
    "embeddedmode" = "Manual"
    "fdPHost" = "Manual"
    "fhsvc" = "Manual"
    "gpsvc" = "Automatic"
    "hidserv" = "Manual"
    "icssvc" = "Manual"
    "iphlpsvc" = "Automatic"
    "lfsvc" = "Manual"
    "lltdsvc" = "Manual"
    "lmhosts" = "Manual"
    "msiserver" = "Manual"
    "netprofm" = "Manual"
    "nsi" = "Automatic"
    "p2pimsvc" = "Manual"
    "p2psvc" = "Manual"
    "perceptionsimulation" = "Manual"
    "pla" = "Manual"
    "seclogon" = "Manual"
    "shpamsvc" = "Disabled"
    "smphost" = "Manual"
    "spectrum" = "Manual"
    "sppsvc" = "AutomaticDelayedStart"
    "ssh-agent" = "Disabled"
    "svsvc" = "Manual"
    "swprv" = "Manual"
    "tiledatamodelsvc" = "Automatic"
    "tzautoupdate" = "Disabled"
    "uhssvc" = "Disabled"
    "upnphost" = "Manual"
    "vds" = "Manual"
    "vm3dservice" = "Manual"
    "vmicguestinterface" = "Manual"
    "vmicheartbeat" = "Manual"
    "vmickvpexchange" = "Manual"
    "vmicrdv" = "Manual"
    "vmicshutdown" = "Manual"
    "vmictimesync" = "Manual"
    "vmicvmsession" = "Manual"
    "vmicvss" = "Manual"
    "vmvss" = "Manual"
    "wbengine" = "Manual"
    "wcncsvc" = "Manual"
    "webthreatdefsvc" = "Manual"
    "wercplsupport" = "Manual"
    "wisvc" = "Manual"
    "wlidsvc" = "Manual"
    "wlpasvc" = "Manual"
    "wmiApSrv" = "Manual"
    "workfolderssvc" = "Manual"
    "wscsvc" = "AutomaticDelayedStart"
    "wuauserv" = "Manual"
    "wudfsvc" = "Manual"
}

# Apply service configurations
foreach ($serviceName in $serviceConfigurations.Keys) {
    Set-ServiceStartup -ServiceName $serviceName -StartupType $serviceConfigurations[$serviceName]
}

# Handle services with wildcard patterns (user services)
$userServicePatterns = @(
    "BcastDVRUserService_*",
    "BluetoothUserService_*",
    "CDPUserSvc_*",
    "CaptureService_*",
    "ConsentUxUserSvc_*",
    "CredentialEnrollmentManagerUserSvc_*",
    "DeviceAssociationBrokerSvc_*",
    "DevicePickerUserSvc_*",
    "DevicesFlowUserSvc_*",
    "MessagingService_*",
    "NPSMSvc_*",
    "OneSyncSvc_*",
    "P9RdrService_*",
    "PenService_*",
    "PimIndexMaintenanceSvc_*",
    "PrintWorkflowUserSvc_*",
    "UdkUserSvc_*",
    "UnistoreSvc_*",
    "UserDataSvc_*",
    "WpnUserService_*",
    "cbdhsvc_*",
    "webthreatdefusersvc_*"
)

foreach ($pattern in $userServicePatterns) {
    $baseName = $pattern -replace '\*$', ''
    $services = Get-Service | Where-Object { $_.Name -like $pattern }
    foreach ($service in $services) {
        Set-ServiceStartup -ServiceName $service.Name -StartupType "Manual"
    }
}

Write-Host "13. Enabling Classic Right-Click Menu (Windows 11)..." -ForegroundColor Cyan
try {
    New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Name "InprocServer32" -Force -Value "" | Out-Null
    Write-Host "Classic right-click menu enabled" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to enable classic right-click menu (may not be Windows 11)"
}

Write-Host "Script completed!" -ForegroundColor Green
Write-Host "IMPORTANT: A system restart is recommended for all changes to take effect." -ForegroundColor Yellow
Write-Host "Some features may be disabled. If you experience issues, you can create an undo script or restore from a system restore point." -ForegroundColor Yellow

# Ask user about restarting Explorer
$restart = Read-Host "Do you want to restart Windows Explorer now to apply some changes immediately? (y/n)"
if ($restart -eq 'y' -or $restart -eq 'Y') {
    Write-Host "Restarting Windows Explorer..." -ForegroundColor Yellow
    Stop-Process -Name "explorer" -Force
    Start-Sleep -Seconds 2
    Start-Process "explorer.exe"
}

# Automatically open system utilities for review
Write-Host ""
Write-Host "Opening system utilities for review and additional configuration..." -ForegroundColor Cyan
try {
    Write-Host "Opening Programs and Features (Add/Remove Programs)..." -ForegroundColor Gray
    Start-Process "appwiz.cpl"
    Start-Sleep -Seconds 1
    
    Write-Host "Opening System Configuration (MSConfig)..." -ForegroundColor Gray
    Start-Process "msconfig.exe"
    Start-Sleep -Seconds 1
    
    Write-Host "Opening Task Manager..." -ForegroundColor Gray
    Start-Process "taskmgr.exe"
    
    Write-Host ""
    Write-Host "System utilities opened. You can now:" -ForegroundColor Yellow
    Write-Host "- Remove unwanted programs in Programs & Features" -ForegroundColor White
    Write-Host "- Review startup items and services in MSConfig" -ForegroundColor White  
    Write-Host "- Manage startup programs in Task Manager (Startup tab)" -ForegroundColor White
    Write-Host "- Monitor system performance after optimization" -ForegroundColor White
}
catch {
    Write-Warning "Failed to open some system utilities. You can open them manually if needed."
}

Write-Host ""
Write-Host "Windows optimization script finished. Reboot your system when convenient." -ForegroundColor Green
