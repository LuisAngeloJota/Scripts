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

# Load the SYSTEM hive into HKLM\TMPSYS
reg load "HKLM\TMPSYS" "$mountDir\Windows\System32\config\SYSTEM"

# Set the registry key to disable WPBT
Write-Host "Setting the registry key..."
reg add "HKLM\TMPSYS\ControlSet001\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f

# Unload the SYSTEM hive
Write-Host "Unloading the SYSTEM hive..."
reg unload "HKLM\TMPSYS"

# Unmount the image with DISM
Write-Host "Unmounting the image..."
DISM /Unmount-Image /MountDir:$mountDir /Commit /CheckIntegrity

Write-Host "Script execution completed."