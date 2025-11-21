# ============================================================
# CCDC ESSENTIAL WINDOWS SERVICE FIREWALL RULESET
# Run as Administrator
# ============================================================

# -------- RDP --------
netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=3389

# -------- SMB / FILE SHARING --------
netsh advfirewall firewall add rule name="SMB-137" dir=in action=allow protocol=UDP localport=137
netsh advfirewall firewall add rule name="SMB-138" dir=in action=allow protocol=UDP localport=138
netsh advfirewall firewall add rule name="SMB-139" dir=in action=allow protocol=TCP localport=139
netsh advfirewall firewall add rule name="SMB-445" dir=in action=allow protocol=TCP localport=445

# -------- DNS (TCP/UDP 53) --------
netsh advfirewall firewall add rule name="DNS-TCP" dir=in action=allow protocol=TCP localport=53
netsh advfirewall firewall add rule name="DNS-UDP" dir=in action=allow protocol=UDP localport=53

# -------- WEB SERVER (HTTP/HTTPS) --------
netsh advfirewall firewall add rule name="HTTP" dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="HTTPS" dir=in action=allow protocol=TCP localport=443

# -------- WinRM (Remote PowerShell) --------
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985
netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in action=allow protocol=TCP localport=5986

# -------- WMI (RPC Endpoint) --------
netsh advfirewall firewall add rule name="WMI-RPC" dir=in action=allow protocol=TCP localport=135

# -------- ACTIVE DIRECTORY (DOMAIN CONTROLLER PORTS) --------
# Kerberos
netsh advfirewall firewall add rule name="Kerberos-TCP" dir=in action=allow protocol=TCP localport=88
netsh advfirewall firewall add rule name="Kerberos-UDP" dir=in action=allow protocol=UDP localport=88

# LDAP
netsh advfirewall firewall add rule name="LDAP-TCP" dir=in action=allow protocol=TCP localport=389
netsh advfirewall firewall add rule name="LDAP-UDP" dir=in action=allow protocol=UDP localport=389

# LDAPS
netsh advfirewall firewall add rule name="LDAPS" dir=in action=allow protocol=TCP localport=636

# Global Catalog
netsh advfirewall firewall add rule name="GC" dir=in action=allow protocol=TCP localport=3268
netsh advfirewall firewall add rule name="GC-SSL" dir=in action=allow protocol=TCP localport=3269

# -------- DHCP SERVER --------
netsh advfirewall firewall add rule name="DHCP-67" dir=in action=allow protocol=UDP localport=67
netsh advfirewall firewall add rule name="DHCP-68" dir=in action=allow protocol=UDP localport=68

# ============================================================
# END RULESET
# ============================================================
