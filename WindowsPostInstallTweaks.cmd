@echo off

REM Disable Memory Compression
powershell.exe Disable-MMAgent -mc

REM Disable SysMain
sc config "SysMain" start=disabled

REM NTFS Tweaks
fsutil 8dot3name set 1
fsutil behavior set disableCompression 1
fsutil behavior set disableLastAccess 1

REM Disable Firewall
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0 /f

REM Set PageFile
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v PagingFiles /t REG_SZ /d "C:\pagefile.sys 8192 8192" /f

REM Disable Mitigations
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f

REM Set Win32PrioritySeparation to Long, Fixed
reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 24 /f

REM Windows Update Tweaks
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 99 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f

REM Enable Detailed Status Messages
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v VerboseStatus /t REG_DWORD /d 1 /f

REM Enable Win32 Long Paths
reg add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f

REM Enable Powershell RemoteSigned Scripts
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /v EnableScripts /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /t REG_SZ /d RemoteSigned /f

REM Disable Storage Sense
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /v AllowStorageSenseGlobal /t REG_DWORD /d 0 /f

REM Set NTP Server
reg add "HKLM\SOFTWARE\Policies\Microsoft\W32time\Parameters" /v NtpServer /t REG_SZ /d time.cloudflare.com /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\W32time\Parameters" /v Type /t REG_SZ /d NTP /f

REM Disable Diagnostic Data
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

REM Disable Windows Error Reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

REM Use UTC Time
reg add "HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f

echo Tweaks applied successfully!
pause
