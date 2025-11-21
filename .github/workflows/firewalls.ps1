# ============================================================
# CORRECTED CCDC WINDOWS SERVICE HARDENING SCRIPT
# ============================================================

$DisableServices = @(
    "DiagTrack",
    "DoSvc",
    "DPS",
    "SysMain",
    "TabletInputService",
    "WpnService",
    "WpnUserService",
    "TrkWks",
    "Themes",
    "TokenBroker",
    "AppXSvc",
    "DispBrokerDesktopSvc",
    "LicenseManager",
    "MapsBroker",
    "OneSyncSvc",
    "MessagingService",
    "CDPSvc",
    "CDPUserSvc",
    "cbdhsvc",
    "StorSvc",
    "ShellHWDetection",
    "PhoneSvc",
    "Fax",
    "RetailDemo",
    "UevAgentService",
    "SEMgrSvc",
    "SCardSvr",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc",
    "SharedAccess",
    "lfsvc",
    "WbioSrvc",
    "bthserv",
    "BluetoothUserService"
)

foreach ($svc in $DisableServices) {
    Write-Host "Processing service: $svc"
    
    # Stop service safely
    sc.exe stop $svc 2>$null
    
    # Disable service (correct syntax with required space)
    sc.exe config $svc start= disabled 2>$null
}

Write-Host "Finished disabling unnecessary services."

