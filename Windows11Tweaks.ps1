# NTFS Tweaks
fsutil 8dot3name set 1
fsutil behavior set disableCompression 1
fsutil behavior set disableLastAccess 1
fsutil behavior set memoryUsage 2

# Disable Memory Compression
Disable-MMAgent -mc

# Registry Tweaks

# Disable Firewall
New-Item -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -ItemType Directory -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Value 0 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Value 0 -Type Dword -Force

# Set PageFile
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "C:\pagefile.sys 8192 8192" -Type String -Force

# Disable Mitigations
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettings" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 3 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force

# Set Win32PrioritySeparation to Long, Variable, 3x Foreground Boost
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
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1 -Type Dword -Force

# Enable Win32 Long Paths
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -Type Dword -Force

# Enable Powershell RemoteSigned Scripts
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Name "EnableScripts" -Value 1 -Type Dword -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell" -Name "ExecutionPolicy" -Value "RemoteSigned" -Type String -Force

# Disable Automatic Scheduled Maintenance
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\ScheduledDiagnostics" -ItemType Directory -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\ScheduledDiagnostics" -Name "EnabledExecution" -Value 0 -Type Dword -Force