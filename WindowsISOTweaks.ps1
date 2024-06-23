# Print DISM image information
Write-Host "Getting DISM image information..."
$output = DISM /Get-ImageInfo /ImageFile:install.wim
Write-Output $output

# Prompt user for index
$index = Read-Host "Enter the index of the image you want to mount:"

# Create a temporary directory
$mountDir = "C:\TMPIMG"
New-Item -Path $mountDir -ItemType Directory -Force

# Mount the image with DISM
Write-Host "Mounting the image..."
DISM /Mount-Image /ImageFile:install.wim /Index:$index /MountDir:$mountDir /Optimize /CheckIntegrity

# Load registry
reg load "HKLM\TMPSOFTWARE" "$mountDir\Windows\System32\config\SOFTWARE"
reg load "HKLM\TMPSYSTEM" "$mountDir\Windows\System32\config\SYSTEM"

# Set tweaks
Write-Host "Setting tweaks..."

# NTFS Tweaks
fsutil 8dot3name set 1
fsutil behavior set disableCompression 1
fsutil behavior set disableLastAccess 1

# Disable Memory Compression
powershell Disable-MMAgent -mc

# Disable WPBT
reg add "HKLM\TMPSYSTEM\ControlSet001\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f

# Disable Firewall
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0 /f

# Set PageFile
reg add "HKLM\TMPSYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v PagingFiles /t REG_SZ /d "C:\pagefile.sys 8192 8192" /f

# Disable Mitigations
reg add "HKLM\TMPSYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d 1 /f
reg add "HKLM\TMPSYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
reg add "HKLM\TMPSYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f

# Set Win32PrioritySeparation to Long, Fixed
reg add "HKLM\TMPSYSTEM\ControlSet001\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 24 /f

# Windows Update Tweaks
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 99 /f
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f

# Enable Detailed Status Messages
reg add "HKLM\TMPSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v VerboseStatus /t REG_DWORD /d 1 /f

# Enable Win32 Long Paths
reg add "HKLM\TMPSYSTEM\ControlSet001\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f

# Enable Powershell RemoteSigned Scripts
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\Windows\PowerShell" /v EnableScripts /t REG_DWORD /d 1 /f
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /t REG_SZ /d RemoteSigned /f

# Disable Storage Sense
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\Windows\StorageSense" /v AllowStorageSenseGlobal /t REG_DWORD /d 0 /f

# Set NTP Server
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\W32time\Parameters" /v NtpServer /t REG_SZ /d time.cloudflare.com /f
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\W32time\Parameters" /v Type /t REG_SZ /d NTP /f

# Disable Diagnostic Data
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

# Disable Windows Error Reporting
reg add "HKLM\TMPSOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

# Unload the SYSTEM hive
Write-Host "Unloading the SYSTEM hive..."
reg unload "HKLM\TMPSOFTWARE"
reg unload "HKLM\TMPSYSTEM"

# Unmount the image with DISM
Write-Host "Unmounting the image..."
DISM /Unmount-Image /MountDir:$mountDir /Commit /CheckIntegrity

Write-Host "Script completed."
