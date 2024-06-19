### Tweaks

# NTFS Tweaks
fsutil 8dot3name set 1
fsutil behavior set disableCompression 1
fsutil behavior set disableLastAccess 1

# Disable Memory Compression
Disable-MMAgent -mc

### Registry Tweaks

# Disable Firewall
New-Item -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -ItemType Directory -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Value 0 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Value 0 -Type Dword -Force

# Set PageFile
New-Item -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "C:\pagefile.sys 4096 4096" -Type String -Force

# Disable Mitigations
New-Item -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettings" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 3 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force

# Set Win32PrioritySeparation to Long, Fixed
New-Item -Path "HKLM:\System\CurrentControlSet\Control\PriorityControl" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 24 -Type DWord -Force

# Windows Update Tweaks
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -ItemType Directory -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -ItemType Directory -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ItemType Directory -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 99 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Type Dword -Force

# Enable Detailed Status Messages
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1 -Type Dword -Force

# Enable Win32 Long Paths
New-Item -Path "HKLM:\System\CurrentControlSet\Control\FileSystem" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -Type Dword -Force

# Enable Powershell RemoteSigned Scripts
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -Value 1 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Name "ExecutionPolicy" -Value "RemoteSigned" -Type String -Force

# Disable Storage Sense
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\StorageSense" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\StorageSense" -Name "AllowStorageSenseGlobal" -Value 0 -Type Dword -Force

# Set NTP Server
New-Item -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "NtpServer" -Value "time.cloudflare.com" -Type String -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\W32time\Parameters" -Name "Type" -Value "NTP" -Type String -Force

# Disable AutoPlay
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type Dword -Force

# Disable Diagnostic Data
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type Dword -Force

# Disable Windows Defender Antivirus
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type Dword -Force

# Disable Window Defender SmartScreen
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 0 -Type Dword -Force

# Disable Windows Error Reporting
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type Dword -Force

# Disable Virtualization Based Security
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -Type Dword -Force