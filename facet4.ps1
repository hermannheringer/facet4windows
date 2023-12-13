<#
Facet4 Windows 10/11 distribution
Author: Hermann Heringer
Version : 0.1.8
Source: https://github.com/hermannheringer/
#>


# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Write-Host "This script will self elevate to run as an Administrator and continue."
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}
}



Function AddOrRemoveTweak($tweak) {
	If ($tweak[0] -eq "!") {
		# If the name starts with exclamation mark (!), exclude the tweak from selection
		$script:tweaks = $script:tweaks | Where-Object { $_ -ne $tweak.Substring(1) }
	} ElseIf ($tweak -ne "") {
		# Otherwise add the tweak function in the array
		$script:tweaks += $tweak
	}
}



# Creates a record of all or part of a PowerShell session to a log file.
Function LogScript {
	$facet4Folder = "C:\Temp\facet4"
	If (Test-Path $facet4Folder) {
		Write-Output "$facet4Folder exists. Skipping..."
	}
	Else {
		Write-Output "The folder '$facet4Folder' doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
		Start-Sleep 1
		New-Item -Path "$facet4Folder" -ItemType Directory -Force -ErrorAction SilentlyContinue
		Write-Output "The folder $facet4Folder was successfully created."
	}
	Start-Transcript -OutputDirectory $facet4Folder
}



# Creating a System Restore Point
Function RestorePoint {
# Restore points are essentially frozen copies of what your computer's operating system looked like at a given time without having to touch any of your personal files.
Write-Output "Creating a System Restore Point on the local computer. Please wait..."
$LocalDrives = Get-CimInstance -Class 'Win32_LogicalDisk' | Where-Object { $_.DriveType -eq 3 } | Select-Object -ExpandProperty DeviceID
$LocalDrive = $LocalDrives[0][0] + ":"  # This hack is required when there is more than 1 HD in the computer, generating a call error due to a change in array behaviour.
Enable-ComputerRestore -Drive $LocalDrive
Start-Sleep 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type DWord -Value 0
Start-Sleep 1
$startTime = Get-Date
Checkpoint-Computer -Description "<System Restore Point dated $startTime before running facet4 script.>" -RestorePointType "MODIFY_SETTINGS"
Start-Sleep 1
Write-Output "System Restore Point created."
}



Function DeepSystemClean {
Write-Host "Performing a deep system clean..."

Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches" | ForEach-Object {
	If ((Test-Path $_.PsPath)) {
		Set-ItemProperty -Path $_.PsPath -Name "StateFlags0011" -Type DWord -Value 0x00000002
	}
}

Start-Process cleanmgr -ArgumentList “/sagerun:11” -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches" | ForEach-Object {
	If ((Test-Path $_.PsPath)) {
		#Remove-ItemProperty -Path $_.PsPath -Name "StateFlags0011" -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path $_.PsPath -Name "StateFlags*" -ErrorAction SilentlyContinue
	}
}

Get-ChildItem $Env:windir\temp | Remove-Item -rec -for -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Get-ChildItem $Env:windir\logs\CBS | Remove-Item -rec -for -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Get-ChildItem $Env:temp | Remove-Item -rec -for -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Get-ChildItem $Env:windir\Prefetch | Remove-Item -rec -for -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Get-ChildItem $Env:HOMEPATH\AppData\Local\Temp | Remove-Item -rec -for -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

logman stop -ets UserNotPresentTraceSession | Out-Null
logman stop -ets ScreenOnPowerStudyTraceSession | Out-Null

Get-ChildItem $Env:windir\System32\SleepStudy | Remove-Item -rec -for -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

Write-Host "Clean Up the WinSxS Folder. This process can take a few minutes..."
dism /online /cleanup-Image /StartComponentCleanup /ResetBase

Write-Host "Clearing All Event Viewer logs."
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object { Clear-EventLog $_.LogName -ErrorAction SilentlyContinue }

}



<#
The Optimize-Volume cmdlet optimizes a volume, performing defragmentation, trim, slab consolidation, and storage tier processing.
If no parameter is specified, then the default operation will be performed per the drive type as follows.

·HDD, Fixed VHD, Storage Space. -Analyze -Defrag.
·Tiered Storage Space. -TierOptimize.
·SSD with TRIM support. -Retrim.
·Storage Space (Thinly provisioned), SAN Virtual Disk (Thinly provisioned), Dynamic VHD, Differencing VHD. -Analyze -SlabConsolidate -Retrim.
·SSD without TRIM support, Removable FAT, Unknown. No operation.
#>
Function OptimizeVolume {
	Write-Host "Performs volume optimization according to storage technology..."
	$LocalDrives = Get-CimInstance -Class 'Win32_LogicalDisk' | Where-Object { $_.DriveType -eq 3 } | Select-Object -ExpandProperty DeviceID
	Optimize-Volume -DriveLetter $LocalDrives[0][0]
}



# Wait for key press
Function WaitForKey {
	Stop-Transcript -ErrorAction SilentlyContinue
	Write-Host "Unloading the HKCR drive..."
	Remove-PSDrive HKCR -ErrorAction SilentlyContinue
	Write-Output "`nEnd of script execution. Press any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}



# Restart computer
Function Restart {
    #Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName PresentationCore, PresentationFramework
    $Button = [Windows.MessageBoxButton]::YesNoCancel
    $Reboot = "Consider restarting your operating system for some of the changes you made to take effect."
    $Warn = [Windows.MessageBoxImage]::Warning

    $Prompt0 = [Windows.MessageBox]::Show($Reboot, "Reboot", $Button, $Warn)
    Switch ($Prompt0) {
        Yes {
            Start-Sleep 1
            Write-Host "Initiating reboot..."
            Start-Sleep 1
            Restart-Computer
        }
        No {
            Start-Sleep 1
            Write-Host "Exiting..."
            Start-Sleep 1
            Exit
        }
    }
}



Clear-Host
$tweaks = @()
$PSCommandArgs = @()



# Parse and resolve paths in past previous arguments
$i = 0
While ($i -lt $args.Length) {
	If ($args[$i].ToLower() -eq "-include") {
		# Resolve full path to the included file
		$include = Resolve-Path $args[++$i] -ErrorAction Stop
		$PSCommandArgs += "-include `"$include`""
		# Import the included file as a module
		Import-Module -Name $include -ErrorAction Stop
	} ElseIf ($args[$i].ToLower() -eq "-preset") {
		# Resolve full path to the preset file
		$preset = Resolve-Path $args[++$i] -ErrorAction Stop
		$PSCommandArgs += "-preset `"$preset`""
		# Load each tweak functions defined in the ""script.preset"" file
		Get-Content $preset -ErrorAction Stop | ForEach-Object { AddOrRemoveTweak($_.Split("#")[0].Trim()) }
	}
	$i++
}



# Call each tweak function defined in the file "script.preset"
$tweaks | ForEach-Object { Invoke-Expression $_ }