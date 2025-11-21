Set-Service Winmgmt -StartupType Automatic
Start-Service Winmgmt

Set-Service RemoteRegistry -StartupType Automatic
Start-Service RemoteRegistry

Set-Service ServerManagerService -StartupType Automatic
Start-Service ServerManagerService

Set-Service RpcSs -StartupType Automatic

Set-Service Wscsvc -StartupType Automatic
Start-Service Wscsvc
sc.exe stop SharedAccess; sc.exe config SharedAccess start= disabled
sc.exe stop lfsvc; sc.exe config lfsvc start= disabled
sc.exe stop WbioSrvc; sc.exe config WbioSrvc start= disabled
sc.exe stop bthserv; sc.exe config bthserv start= disabled
sc.exe stop BluetoothUserService; sc.exe config BluetoothUserService start= disabled
