Set-Service RpcSs -StartupType Automatic
Set-Service Winmgmt -StartupType Automatic
Start-Service Winmgmt
Set-Service RemoteRegistry -StartupType Automatic
Start-Service RemoteRegistry
Set-Service ServerManagerService -StartupType Automatic
Start-Service ServerManagerService
Set-Service Wscsvc -StartupType Automatic
Start-Service Wscsvc
