<#
Facet4 Windows 10/11 distribution
Author: Hermann Heringer
Version : 0.1.0
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



Function ElevatingPrivileges {
	Write-Output "Elevating owner privileges for some registry keys."
	# See more at https://www.remkoweijnen.nl/blog/2012/01/16/take-ownership-of-a-registry-key-in-powershell/

<#
Due to the complex nature of authentication and privilege escalation mechanisms in Windows,
this variable $ErrorActionPreference is to minimize error warnings in this function.
I still haven't found a simple solution for some specific cases where the user is not enabled in any Group Member.
#>
$ErrorActionPreference = 'silentlycontinue'


$definition = @"
using System;
using System.Runtime.InteropServices; 

namespace Win32Api
{

	public class NtDll
	{
		[DllImport("ntdll.dll", EntryPoint="RtlAdjustPrivilege")]
		public static extern int RtlAdjustPrivilege(ulong Privilege, bool Enable, bool CurrentThread, ref bool Enabled);
	}
}
"@ 

	Add-Type -TypeDefinition $definition -PassThru

	#$bEnabled = $false
	#$res = [Win32Api.NtDll]::RtlAdjustPrivilege(9, $true, $false, [ref]$bEnabled)
	Try{
		$r = Get-LocalGroupMember -Group "Administrators"
		$me = [System.Security.Principal.NTAccount]$r[1].Name 
	}
	Catch{
		Try{
		$r = Get-LocalGroupMember -Group "Administradores"
		$me = [System.Security.Principal.NTAccount]$r[1].Name
		}
		Catch{
			$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
		}
	}

	Write-Output $me
	#$me = [System.Security.Principal.NTAccount]"computer\login"

	$Reg_keys = @(
	"SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter"
	)

	foreach ($Reg_key in $Reg_keys) {
		$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$Reg_key",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)
		$acl = $key.GetAccessControl()
		$acl.SetOwner($me)
		$key.SetAccessControl($acl)

		$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$Reg_key",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
		$acl = $key.GetAccessControl()
		Try{
			$rule = New-Object System.Security.AccessControl.RegistryAccessRule ("Users","FullControl",@("ObjectInherit","ContainerInherit"),"None","Allow") 
			$acl.SetAccessRule($rule)
		}
		Catch{
			Try{
			$rule = New-Object System.Security.AccessControl.RegistryAccessRule ("Usuários","FullControl",@("ObjectInherit","ContainerInherit"),"None","Allow")
			$acl.SetAccessRule($rule)
			}
			Catch{
				$rule = New-Object System.Security.AccessControl.RegistryAccessRule ("usuarios","FullControl",@("ObjectInherit","ContainerInherit"),"None","Allow")
				$acl.SetAccessRule($rule)
			}
		}
		$key.SetAccessControl($acl)
		Write-Output "key -> $Reg_key"
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
Enable-ComputerRestore -Drive $LocalDrives
Start-Sleep 1
$startTime = Get-Date
Checkpoint-Computer -Description "<System Restore Point dated $startTime before running facet4 script.>" -RestorePointType "MODIFY_SETTINGS"
Start-Sleep 1
Write-Output "System Restore Point created."
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