# ============================================================
# CCDC WINDOWS SERVER SERVICE-HARDENING SCRIPT
# DISABLE ALL UNNECESSARY SERVICES
# ============================================================

$DisableServices = @(
    "DiagTrack",                  # Telemetry / Tracking
    "DoSvc",                      # Delivery Optimization
    "DPS",                        # Diagnostic Policy Service
    "SysMain",                    # Superfetch
    "TabletInputService",         # Touch/Handwriting
    "WpnService",                 # Push Notifications
    "WpnUserService",             # User Push Notifications
    "TrkWks",                     # Distributed Link Tracking
    "Themes",                     # Visual Themes
    "TokenBroker",                # AAD Token Service
    "AppXSvc",                    # AppX Deployment
    "DispBrokerDesktopSvc",       # Display Policy Broker
    "LicenseManager",             # Store Licensing
    "MapsBroker",                 # Maps Service
    "OneSyncSvc",                 # Cloud sync
    "MessagingService",           # Messaging
    "CDPSvc",                     # Connected Devices
    "CDPUserSvc",                 # Connected Devices User
    "cbdhsvc",                    # Clipboard User Service
    "StorSvc",                    # Storage Service (safe to disable)
    "ShellHWDetection",           # AutoPlay / Media detection
    "PhoneSvc",                   # Phone service (if present)
    "Fax",                        # Fax service
    "RetailDemo",                 # Demo mode
    "UevAgentService",            # UE-V (if present)
    "SEMgrSvc",                   # Payments / Wallet
    "SCardSvr",                   # Smart card service (unless using)
    "TermService2",               # Duplicate RDP instance (rare)
    "XblAuthManager",             # Xbox
    "XblGameSave",
    "XboxNetApiSvc",
    "SharedAccess",               # ICS internet connection sharing
    "lfsvc",                      # Geolocation service
    "WbioSrvc",                   # Biometrics
    "BluetoothUserService",       # Bluetooth
    "bthserv"                     # Bluetooth service
)

foreach ($svc in $DisableServices) {
    Write-Host "Disabling service: $svc"
    sc.exe stop $svc -ErrorAction SilentlyContinue
    sc.exe config $svc start= disabled -ErrorAction SilentlyContinue
}

Write-Host "All unnecessary services disabled."
