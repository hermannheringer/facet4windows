<#
Facet4 Windows 10/11 distribution
Author: Hermann Heringer
Version : 0.2.1
Source: https://github.com/hermannheringer/
#>



Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip {
    param([string]$zipfile, [string]$outpath)
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}



###					   ###
### Application Tweaks ###
###					   ###



# Check if winget is installed
Function InstallWinget {
	# Check if winget is installed
		Write-Host "Checking if Winget is Installed..."
		if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe) {
			#Checks if winget executable exists and if the Windows Version is 1809 or higher
			Write-Host "Winget Already Installed."
		}
		else {
			if (((((Get-ComputerInfo).OSName.IndexOf("LTSC")) -ne -1) -or ((Get-ComputerInfo).OSName.IndexOf("Server") -ne -1)) -and (((Get-ComputerInfo).WindowsVersion) -ge "1809")) {
				#Checks if Windows edition is LTSC/Server 2019+
				#Manually Installing Winget
				Write-Host "Running Alternative Installer for LTSC/Server Editions"
	
				#Download Needed Files
				Write-Host "Downloading Needed Files to install Winget. Please wait..."

				Start-BitsTransfer -Source "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -Destination "$facet4Folder\Microsoft.VCLibs.x64.14.00.Desktop.appx"
				Start-BitsTransfer -Source "https://globalcdn.nuget.org/packages/microsoft.ui.xaml.2.7.3.nupkg" -Destination "$facet4Folder\microsoft.ui.xaml.2.7.3.nupkg"

				Unzip "$facet4Folder\microsoft.ui.xaml.2.7.3.nupkg" "$facet4Folder\microsoft.ui.xaml"
			
				#& ${env:ProgramFiles}\7-Zip\7z.exe x "$facet4Folder\microsoft.ui.xaml.2.7.3.nupkg" "-o$("$facet4Folder\microsoft.ui.xaml")" -y > $null
				
				Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.2.10271/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Destination "$facet4Folder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
				Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.2.10271/b0a0692da1034339b76dce1c298a1e42_License1.xml" -Destination "$facet4Folder\b0a0692da1034339b76dce1c298a1e42_License1.xml"
	
				Add-AppxProvisionedPackage -Online -PackagePath "$facet4Folder\Microsoft.VCLibs.x64.14.00.Desktop.appx" -SkipLicense
				Add-AppxProvisionedPackage -Online -PackagePath "$facet4Folder\microsoft.ui.xaml\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx" -SkipLicense
				Add-AppxProvisionedPackage -Online -PackagePath "$facet4Folder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -LicensePath "$facet4Folder\b0a0692da1034339b76dce1c298a1e42_License1.xml"
	
				Remove-Item -Path "$facet4Folder\Microsoft.VCLibs.x64.14.00.Desktop.appx" -Force -ErrorAction SilentlyContinue
				Remove-Item -Path "$facet4Folder\microsoft.ui.xaml.2.7.3.nupkg" -Force -ErrorAction SilentlyContinue
				Remove-Item -Path "$facet4Folder\microsoft.ui.xaml" -Force -Recurse -ErrorAction SilentlyContinue
				Remove-Item -Path "$facet4Folder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Force -ErrorAction SilentlyContinue
				Remove-Item -Path "$facet4Folder\b0a0692da1034339b76dce1c298a1e42_License1.xml" -Force -ErrorAction SilentlyContinue
	
			}
			elseif (((Get-ComputerInfo).WindowsVersion) -lt "1809") {
				Write-Host "Winget is not supported on this version of Windows (Pre-1809)"
			}
			else {
				#Installing Winget from the Microsoft Store
				Write-Host "Winget not found, installing it now."
				Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
				$nid = (Get-Process AppInstaller).Id
				Wait-Process -Id $nid
				Write-Host "Winget Installed"
			}
		}
	}



###					###
### Debloat Windows ###
###					###



Function DebloatBlacklist {

	$Bloatware = @(
		# Unnecessary default Windows 10 Apps
		"*Microsoft.3DBuilder*"
		#"*Microsoft.AppConnector*"
		#"*Microsoft.CommsPhone*"
		#"*Microsoft.ConnectivityStore*"
		"*Microsoft.Disney*"
		"*Microsoft.FreshPaint*"
		"*Microsoft.GamingApp*"
		"*Microsoft.GamingBar*"
		"*Microsoft.GamingServices*"
		"*Microsoft.GetHelp*"
		"*Microsoft.Getstarted*"
		"*Microsoft.HelpAndTips*"
		"*Microsoft.Media.PlayReadyClient*"
		"*Microsoft.Messaging*"
		"*Microsoft.Microsoft3DViewer*"
		"*Microsoft.MicrosoftOfficeHub*"
		#"*Microsoft.MicrosoftPowerBIForWindows*"
		"*Microsoft.MicrosoftSolitaireCollection*"
		#"*Teams*"
		"*Microsoft.MinecraftUWP*"
		"*Microsoft.MixedReality.Portal*"
		#"*Microsoft.NetworkSpeedTest*"
		"*Microsoft.News*"
		#"*Microsoft.Office.OneNote*"
		#"*Microsoft.Office.Todo.List*"
		#"*Microsoft.Office.Lens*"
		#"*Microsoft.Office.Sway*"
		#"*Microsoft.OneConnect*"
		#"*Microsoft.People*"
		"*Microsoft.Print3D*"
		"*Microsoft.Reader*"
		#"*Microsoft.RemoteDesktop*"
		#"*Microsoft.ScreenSketch*"
		"*Microsoft.SkypeApp*"
		#"*Microsoft.StorePurchaseApp*"
		#"*Microsoft.Todos*"
		#"*Microsoft.Wallet*"
		#"*Microsoft.WebMediaExtensions*"
		#"*Microsoft.Whiteboard*"
		#"*Microsoft.WindowsAlarms*"
		#"*Microsoft.WindowsCamera*"
		#"*Microsoft.windowscommunicationsapps*"
		#"*Microsoft.WindowsMaps*"
		#"*Microsoft.WindowsReadingList*"
		"*Microsoft.WindowsScan*"
		#"*Microsoft.WindowsSoundRecorder*"
		"*Microsoft.WinJS.1.0*"
		"*Microsoft.WinJS.2.0*"
		"*Microsoft.Xbox.TCUI*"
		"*Microsoft.XboxApp*"
		"*Microsoft.XboxGameOverlay*"
		"*Microsoft.XboxGamingOverlay*"
		"*Microsoft.XboxSpeechToTextOverlay*"
		"*Microsoft.YourPhone*"
		"*Microsoft.ZuneMusic*"
		"*Microsoft.ZuneVideo*"


		# Redstone Apps
		"*Microsoft.BingFinance*"
		"*Microsoft.BingFoodAndDrink*"
		"*Microsoft.BingHealthAndFitness*"
		"*Microsoft.BingMaps*"
		"*Microsoft.BingNews*"
		"*Microsoft.BingSports*"
		"*Microsoft.BingTranslator*"
		"*Microsoft.BingTravel*"
		"*Microsoft.BingWeather*"


		# Aponsored non-Microsoft Apps
		"*2414FC7A.Viber*"
		"*2FE3CB00.PicsArt-PhotoStudio*"
		"*41038Axilesoft.ACGMediaPlayer*"
		"*46928bounde.EclipseManager*"
		"*4DF9E0F8.Netflix*"
		"*64885BlueEdge.OneCalendar*"
		"*6Wunderkinder.Wunderlist*"
		"*7EE7776C.LinkedInforWindows*"
		"*828B5831.HiddenCityMysteryofShadows*"
		"*89006A2E.AutodeskSketchBook*"
		"*9E2F88E3.Twitter*"
		"*A278AB0D.DisneyMagicKingdoms*"
		"*A278AB0D.DragonManiaLegends*"
		"*A278AB0D.MarchofEmpires*"
		"*ActiproSoftwareLLC*"
		"*ActiproSoftwareLLC.562882FEEB491*"
		"*AD2F1837.GettingStartedwithWindows8*"
		"*AD2F1837.HPJumpStart*"
		"*AD2F1837.HPRegistration*"
		"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
		"*Amazon.com.Amazon*"
		"*BubbleWitch3Saga*"
		"*C27EB4BA.DropboxOEM*"
		"*CAF9E577.Plex*"
		"*CandyCrush*"
		"*ClearChannelRadioDigital.iHeartRadio*"
		"*CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC*"
		"*D52A8D61.FarmVille2CountryEscape*"
		"*D5EA27B7.Duolingo-LearnLanguagesforFree*"
		"*DB6EA5DB.CyberLinkMediaSuiteEssentials*"
		"*Disney*"
		#"*Dolby*"
		#"*DolbyLaboratories.DolbyAccess*"
		"*Drawboard.DrawboardPDF*"
		"*Duolingo-LearnLanguagesforFree*"
		"*EclipseManager*"
		"*Facebook*"
		"*Facebook.Facebook*"
		"*Fitbit.FitbitCoach*"
		"*flaregamesGmbH.RoyalRevolt2*"
		"*Flipboard*"
		"*Flipboard.Flipboard*"
		"*GAMELOFTSA.Asphalt8Airborne*"
		"*HotspotShieldFreeVPN*"
		"*Hulu*"
		"*KeeperSecurityInc.Keeper*"
		"*king.com.*"
		"*king.com.BubbleWitch3Saga*"
		"*king.com.CandyCrushFriends*"
		"*king.com.CandyCrushSaga*"
		"*king.com.CandyCrushSodaSaga*"
		"*king.com.FarmHeroesSaga*"
		"*Minecraft*"
		"*Netflix*"
		"*Nordcurrent.CookingFever*"
		"*PandoraMediaInc*"
		"*PandoraMediaInc.29680B314EFC2*"
		"*Playtika.CaesarsSlotsFreeCasino*"
		"*PricelinePartnerNetwork.Booking.comBigsavingsonhot*"
		"*RoyalRevolt*"
		"*ShazamEntertainmentLtd.Shazam*"
		#"*SpeedTest*"
		"*Spotify*"
		"*SpotifyAB.SpotifyMusic*"
		"*TheNewYorkTimes.NYTCrossword*"
		"*ThumbmunkeysLtd.PhototasticCollage*"
		"*TuneIn.TuneInRadio*"
		"*Twitter*"
		"*WinZipComputing.WinZipUniversal*"
		"*Wunderlist*"
		"*XINGAG.XING*"


		# Apps which cannot be removed using Remove-AppxPackage
		#"*Microsoft.BioEnrollment*"
		#"*Microsoft.MicrosoftEdge*"
		#"*Microsoft.Windows.Cortana*"
		#"*Microsoft.WindowsFeedback*"
		#"*Microsoft.WindowsFeedbackHub*"
		#"*Microsoft.XboxGameCallableUI*"
		#"*Microsoft.XboxIdentityProvider*"
		#"*Windows.ContactSupport*"


		# Optional: Typically not removed but you can if you need to for some reason
		#"*Microsoft.Advertising.Xaml*"
		#"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
		#"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
		#"*Microsoft.MicrosoftStickyNotes*"
		#"*Microsoft.MSPaint*"
		#"*Microsoft.Windows.Photos*"
		#"*Microsoft.WindowsCalculator*"
		#"*Microsoft.WindowsPhone*"
		#"*Microsoft.WindowsStore*"

	)
	foreach ($Bloat in $Bloatware) {
		Get-AppxPackage -Name $Bloat| Remove-AppxPackage -ErrorAction SilentlyContinue
		Get-AppxPackage -Name $Bloat -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
		Start-Sleep 1
		Write-Output "Trying to remove $Bloat"
	}
}



Function AvoidDebloatReturn {
	Write-Output "Adding Registry key to prevent bloatware apps from returning and removes some suggestions settings."
	$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
	$registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
	If (!(Test-Path $registryPath)) { 
		New-Item $registryPath
	}
	Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1

	If (!(Test-Path $registryOEM)) {
		New-Item $registryOEM
	}
	Set-ItemProperty $registryOEM  ContentDeliveryAllowed  -Type DWord -Value 0x00000001		# Default 1
	Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled  -Type DWord -Value 0x00000000	# Default 1
	Set-ItemProperty $registryOEM  PreInstalledAppsEnabled  -Type DWord -Value 0x00000000		# Default 1
	Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled  -Type DWord -Value 0x00000000	# Default 1
	Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled  -Type DWord -Value 0x00000000	# Default 1
	Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled  -Type DWord -Value 0x00000000	# Default 1

	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0x00000000	#
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0x00000000	#
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0x00000000	# Spotlight fun tips and facts #Default 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0x00000000	# Show Suggestions Occasionally in Start
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0x00000000	# Tips and Suggestions Notifications #Default 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0x00000000	# Suggest new content and apps you may find interesting
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0x00000000	# Suggest new content and apps you may find interesting
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0x00000000	# Suggest new content and apps you may find interesting
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0x00000000	# Timeline Suggestions
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000326Enabled" -Type DWord -Value 0x00000000 # Use Spotlight image as Desktop wallpaper
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name "BackgroundType" -Type DWord -Value 0x00000002		# Use Spotlight image as Desktop wallpaper

	<#
	Get-AppxPackage  | Where name -match windowscommunicationsapps | foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
	Get-AppxPackage -Name Microsoft.Windows.ContentDeliveryManager | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose}
	Get-AppxPackage -AllUsers | Where name -match weather | foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -Verbose }
	LockApp XML located at "C:\Windows\SystemApps\Microsoft.LockApp_cw5n1h2txyewy" WindowsDefaultLockScreen
	#>
}



Function SetMixedReality {
	Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings."
	$Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"
	If (Test-Path $Holo) {
		Set-ItemProperty $Holo  FirstRunSucceeded -Value 0
	}
}



###							  ###
### 	Features Tweaks		  ###
###							  ###



Function DisableAppCompat {
	Write-Host "Disabling Application Compatibility Program."
	# See more at https://admx.help/?Category=Windows_11_2022

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
	}

	Write-Host "Prevent access to 16-bit applications"
	# You can use this setting to turn off the MS-DOS subsystem, which will reduce resource usage and prevent users from running 16-bit applications.
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatPrevent16BitMach
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "VDMDisallowed" -Type DWord -Value 0x00000001	


	Write-Host "Turn off Application Compatibility Engine."
	<#
	Turning off the application compatibility engine will boost system performance.
	However, this will degrade the compatibility of many popular legacy applications,
	and will not block known incompatible applications from installing.
	(For Instance: This may result in a blue screen if an old anti-virus application is installed.)
	#>
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffEngine
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableEngine" -Type DWord -Value 0x00000001


	Write-Host "Turn off Application Telemetry."
	# If the customer Experience Improvement program is turned off, Application Telemetry will be turned off regardless of how this policy is set.
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffApplicationImpactTelemetry
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0x00000000

	
	Write-Host "Turn off Inventory Collector."
	<#
	The Inventory Collector inventories applications, files, devices, and drivers on the system and sends the information to Microsoft.
	This information is used to help diagnose compatibility problems.
	#>
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffProgramInventory
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 0x00000001


	Write-Host "Turn off Program Compatibility Assistant."
	<#
	If you enable this policy setting, the PCA will be turned off.
	The user will not be presented with solutions to known compatibility issues when running applications.
	Turning off the PCA can be useful for system administrators who require better performance and are already aware of application compatibility issues.
	#>
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffProgramCompatibilityAssistant_2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Type DWord -Value 0x00000001


	Write-Host "Turn off Steps Recorder."
	<#
	Steps Recorder keeps a record of steps taken by the user.
	The data generated by Steps Recorder can be used in feedback systems such as Windows Error Reporting
	to help developers understand and fix problems. The data includes user actions such as keyboard input and mouse input,
	user interface data, and screen shots. Steps Recorder includes an option to turn on and off data collection.
	#>
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffUserActionRecord
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type DWord -Value 0x00000001

	Write-Host "Turn off SwitchBack Compatibility Engine."
	<#
	If you enable this policy setting, Switchback will be turned off.
	Turning Switchback off may degrade the compatibility of older applications.
	This option is useful for server administrators who require performance and are aware of compatibility of the applications they are using.
	#>
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffSwitchBack
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "SbEnable" -Type DWord -Value 0x00000000

}



function DisableBackgroundApp {
	# Leaving Xiaomi Mi Blaze Unlock 'on' (8497DDF3*) you can continue using your band to unlock your computer.
	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. -> Disabling All Background Application Access."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -Type DWord -Value 0x00000000
		
	}
	<#
	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. -> Disabling All Background Application Access."
		[string[]]$Excludes = @("8497DDF3*", "Microsoft.Windows.Cortana*")
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude $Excludes | ForEach-Object {
			Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 0x00000001
			Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 0x00000001
		}
	}
	#>

	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Windows 11 Detected. -> Reverting all background app access to default. Windows 11 does a better job of this."
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
			Remove-ItemProperty -Path $_.PsPath -Name "Disabled" -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -ErrorAction SilentlyContinue
		}
	}
}



Function RemoveCloudStore {
	Write-Output "Removing deprecated TileDataLayer from registry if it exists."
	# See more at https://4sysops.com/archives/roaming-profiles-and-start-tiles-tiledatalayer-in-the-windows-10-1703-creators-update
	$CloudStore = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore"
	#$p = Get-Process -Name "explorer"
	If (Test-Path $CloudStore) {
		Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
		Get-Process | Where-Object {$_.HasExited}
		Remove-Item $CloudStore -Force -Recurse -ErrorAction SilentlyContinue
		Start-Process Explorer.exe -Wait
	}
}



function DisableDeleteNotify {
	<#
	TRIM (also called Trim or Trim Command) allows your SSD drive to handle garbage more evidentially.
	TRIM allows the operating system to decide which blocks are already in use so they can be wiped internally.
	Anytime you delete something, TRIM automatically deletes that page or block.
	The next time the page or block is written to, the operating system does not have to wait for that block to be deleted.
	SSD TRIM can prolong the life and performance of your SSD drive.
	#>
	Write-Output "Force Trim state to ON."
	fsutil behavior set DisableDeleteNotify 0
	#fsutil behavior query DisableDeleteNotify
}  



function SetLastAccessTimeStamp {
	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. Disable NTFS Last Access Time Stamp Updates."
		#fsutil behavior query disablelastaccess
		#fsutil behavior set disablelastaccess 0
		fsutil behavior set disablelastaccess 2
	}

	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Windows 11 Detected. Disable NTFS Last Access Time Stamp Updates."
		#fsutil behavior query disablelastaccess
		#fsutil behavior set disablelastaccess 1
		fsutil behavior set disablelastaccess 3

	}
}



Function EnableMemoryCompression {
	Write-Output "Enabling Memory Compression."
	<#
	If the Windows Memory Manager detects low memory,
	it tries to compress unused pages of memory instead of writing them to a paging file on disk to free up RAM for other processes.
	No paging means a faster computer.
	Disabling memory compression is a good idea, it conserves CPU resources, if you have lots of RAM.
	#>
	# See more at http://woshub.com/memory-compression-process-high-usage-windows-10/
	Enable-MMAgent -mc -ErrorAction SilentlyContinue
	#Get-MMAgent
	#Get-Process -Name "Memory Compression"

	#Disable-MMAgent –MemoryCompression
}



Function DisablePerformanceCounters {
	Write-Host "Disable All Performance Counters."
	<#
	Deprecated
	If ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib")) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib" -Name "Disable" -Type DWord -Value 1
	}
	#>

	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
	$Var = $_.PsPath + "\Performance"
		If ((Test-Path $Var)) {
			Set-ItemProperty -Path $Var -Name "Disable Performance Counters" -Type DWord -Value 0x00000001
		}
	}
}



Function DisableStartupEventTraceSession  {
	Write-Host "Disable All Startup Event Trace Session."
	<#
	Event tracing sessions record events from one or more providers that a controller enables. The session is also responsible for managing and flushing the buffers. 
	The controller defines the session, which typically includes specifying the session and log file name, type of log file to use, and the resolution of the time stamp used to record the events.
	Event Tracing supports a maximum of 64 event tracing sessions executing simultaneously. 
	Of these sessions, there are two special purpose sessions. The remaining sessions are available for general use. The two special purpose sessions are:
		-Global Logger Session
		-NT Kernel Logger Session
	#>
		Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger" | ForEach-Object {
			$Var = $_.PsPath
				If ((Test-Path $Var)) {
					Set-ItemProperty -Path $Var -Name "Start" -Type DWord -Value 0x00000000 -erroraction SilentlyContinue
				}
			}
}



function SetPowerManagment {
	Write-Host "Disabling Hibernation and Optimizing Performance on Balanced Performance scheme."
	<#
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type DWord -Value 0x00000000
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0x00000000
	#>
	powercfg -h off

	Write-Output "Disabling Fast Startup."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0x00000000

	# Force enable "traditional" power plans
	#reg add HKLM\System\CurrentControlSet\Control\Power /v PlatformAoAcOverride /t REG_DWORD /d 0
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Power" -Name "PlatformAoAcOverride" -Type DWord -Value 0x00000000

	# Balanced Performance
	powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e

	# High performance
	#powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

	# Ultimate Performance
	#powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61

	#Disable display and sleep mode timeouts
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 3
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0


	<#
	Tuning CPU performance boost
	This feature determines how processors select a performance level when current operating conditions allow for boosting performance above the nominal level.
	See more at https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning
	See more at https://superuser.com/questions/1435110/why-does-windows-10-have-cpu-core-parking-disabled
	#>
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" -Name "Attributes" -Type DWord -Value 0x00000002

	#IF (Get-WmiObject -Class Win32_Processor | where {( $_.Manufacturer -like "*AMD*" ) -or ($_.Manufacturer -like "*Intel*")})

	IF (Get-ComputerInfo | where {( $_.PowerPlatformRole -like "*mobile*" )}) {
		Write-Host "Mobile platform detected. Disabling Performance Boost for less heat output and more sustainable performance over time providing full power to iGPU and dGPU."
		<#
		Load balancing should be automatic as both Intel and AMD have features for this and it usually works very well,
		but if your laptop/notebook/ultrabook makes more noise than an airplane's engines,
		you will be rewarded with performance slightly smaller on some tasks and better on some games and there will be an awkward silence.
		It will be another computer!
		#>
		Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 0
		Powercfg -setdcvalueindex scheme_current sub_processor PERFBOOSTMODE 0  
	}

	IF (Get-ComputerInfo | where {( $_.PowerPlatformRole -notlike "*mobile*" )}) {
		IF (Get-WmiObject -Class Win32_Processor | where {( $_.Manufacturer -like "*AMD*" )}) {
			Write-Host "AMD CPU Detected. Changing Performance Boost to Aggressive." # AMD CPUs with BOOST parameter other than "2" (Aggressive) usually disable Performance Boost completely
			Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2
			Powercfg -setdcvalueindex scheme_current sub_processor PERFBOOSTMODE 0
		}

		IF (Get-WmiObject -Class Win32_Processor | where {($_.Manufacturer -like "*Intel*")}) {
			Write-Host "Intel CPU Detected. Changing Performance Boost to Efficient Aggressive At Guaranteed." # Intel CPUs generally run very well with BOOST 6
			Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 6
			Powercfg -setdcvalueindex scheme_current sub_processor PERFBOOSTMODE 0
		}
	}

	# Require a password on wakeup
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 0
	
	# Turn off hard disk after
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 300
	
	# JavaScript 
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 02f815b5-a5cf-4c84-bf20-649d1f75d3d8 4c793e7d-a264-42e1-87d3-7a0d2f523ccd 1
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 02f815b5-a5cf-4c84-bf20-649d1f75d3d8 4c793e7d-a264-42e1-87d3-7a0d2f523ccd 1
	
	# Desktop background settings - Slide show
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 0
	
	# Wireless Adapter Settings - Power Saving Mode
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 3
	
	# Sleep after - Never
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
	
	# Allow hybrid sleep - Off
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0
	
	# Hibernate after
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
	
	# Allow wake timers - No
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
	
	# USB selective suspend setting - Off
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 1
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 1
	
	# Lid close action - Do Nothing
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
	
	# Power button action - Shutdown
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
	
	# Sleep button action - Sleep
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 1
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 1
	
	# Start menu power button - Shutdown
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 2
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 2
	
	# PCI Express
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 2
	
	# CPU Min
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 5
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 5
	
	# CPU Max
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100
	
	# CPU Fan
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 1
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 1
	
	# Enable Adaptive Brightness
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 1
	
	# Dim display after
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 300
	
	# Desligar Monitor (configured above)
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 180
	
	# Display brightness - %
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 100
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 50
	
	# Dimmed display brightness - %
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 75
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 50
	
	# When sharing media
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 03680956-93bc-4294-bba6-4e0f09bb717f 2
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 03680956-93bc-4294-bba6-4e0f09bb717f 2
	
	# Reproduzir Vídeo
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 2
	
	# Critical battery action - Shutdown
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 3
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 3
	
	# Critical battery level - 7%
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 7
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 7
	
	# Low battery level - 10%
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 10
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 10
	
	# Low battery notification - On
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 1
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 1
	
	# Low battery action - Shutdown
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 3
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 3
	
	# Reserve battery level - 3min
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 3
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 3
	
	# AMD Graphics Power Settings
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e f693fb01-e858-4f00-b20f-f30e12ac06d6 191f65b5-d45c-4a4f-8aae-1ab8bfd980e6 1 # Maximize Performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e f693fb01-e858-4f00-b20f-f30e12ac06d6 191f65b5-d45c-4a4f-8aae-1ab8bfd980e6 0 # Optimize Battery
	
	# Switchable Dynamic Graphics
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 3 # Maximize performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 1 # Optimize power savings
	
	# AMD Power Slider
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 3 # Best performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 0 # Battery saver

	# Intel(R) Graphics Power Plan 
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 2 # Maximum Performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 0 # Maximum Battery Life

	# Intel(R) Dynamic Tuning Settings
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 48df9d60-4f68-11dc-8314-0800200c9a66 07029cd8-4664-4698-95d8-43b2e9666596 0 # 25.0W @ 2.1GHz
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 48df9d60-4f68-11dc-8314-0800200c9a66 07029cd8-4664-4698-95d8-43b2e9666596 2 # 10.0W @ 0.8GHz

	# Hidden New CPU Optimizations
	# Determines whether desired performance requests should be provided to the platform
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFAUTONOMOUS 1 # default 1
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFAUTONOMOUS 1 # default 1	

	# Core Parking allows your processors to go into a sleep mode. The main purposes of core parking is to allow the computer/laptop/device to only use the processors when required, thus saving on energy.
	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100 # default 100
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100 # default 10
	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES 100 # default 100
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES 100 # default 100

	# Processor performance core parking utility distribution
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL 0 # High performance
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL 0 # High performance

	# Processor energy performance preference policy(Percent). Specify how much processors should favor energy savings over performance when operating in autonomous mode.
	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\36687f9e-e3a5-4dbf-b1dc-15eb381c6863" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFEPP 0 # default 50 
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFEPP 50 # default 25

	# The Processor Performance Boost Policy is a percentage value from 0 to 100(hexa:00000064). In the default Balanced power plan this parameter is 35 percent and any value lower than 51 disables Turbo Boost.
	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL 100 # default 60
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL 100 # default 40

	Powercfg -setactive scheme_current

	<#
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR CPMINCORES
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR PERFEPP
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL

	powercfg /Q

	PowerCfg: CPMINCORES, CPMINCORES1
	PowerCfg: CPMAXCORES, CPMAXCORES1
	PowerCfg: LATENCYHINTUNPARK, LATENCYHINTUNPARK1
	PowerCfg: PROCTHROTTLEMAX, PROCTHROTTLEMAX1
	PowerCfg: PROCTHROTTLEMIN, PROCTHROTTLEMIN1
	PowerCfg: PERFINCTHRESHOLD, PERFINCTHRESHOLD1
	PowerCfg: PERFINCTIME, PERFINCTIME1
	PowerCfg: PERFDECTHRESHOLD, PERFDECTHRESHOLD1
	PowerCfg: PERFDECTIME, PERFDECTIME1
	PowerCfg: LATENCYHINTPERF, LATENCYHINTPERF1
	PowerCfg: PERFAUTONOMOUS
	PowerCfg: PERFEPP
	#>
}



function revertPowerManagment {
	Write-Output "Reset All Power Plans to Their Defaults."
	powercfg -restoredefaultschemes
	Start-Sleep 1
	powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e
}



Function RemoveFeaturesKeys {

	# These are the registry keys that it will delete.
	$Keys = @(
		# Remove Background Tasks
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
		#"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
		#"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.19041.1_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.19041.1023.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy"

		# Windows File
		"HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"

		# Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		#"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
		#"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.19041.1_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.19041.1023.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy"
		

		# Scheduled Tasks to delete
		"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"

		# Windows Protocol Keys
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		#"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
		#"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.19041.1_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.19041.1023.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy" 

		# Windows Share Target
		"HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
	)

	# This writes the output of each key it is removing and also removes the keys listed above.
    If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}

	ForEach ($Key in $Keys) {
		Write-Output "Removing $Key from registry"
		Remove-Item -Path $Key -Force -Recurse -ErrorAction SilentlyContinue
	}
}


Function RemoveScheduledTasks {
	Write-Output "`n"
	Write-Output "`nDisables scheduled tasks that are considered unnecessary."
	Write-Output "...If nothing happens within 30 seconds, please close this window and run the script again.`n"
	Write-Output "`n"


	# See more at http://wiki.webperfect.ch/index.php?title=Windows_Telemetry

	Write-Output "Disabling scheduled Xbox service components."
	if(Get-ScheduledTask XblGameSaveTaskLogon -ErrorAction Ignore) { Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask } else { 'XblGameSaveTaskLogon does not exist on this device.'}
	if(Get-ScheduledTask XblGameSaveTask -ErrorAction Ignore) { Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask } else { 'XblGameSaveTask does not exist on this device.'}


	Write-Output "Disabling scheduled group telemetry."
	if(Get-ScheduledTask Consolidator -ErrorAction Ignore) { Get-ScheduledTask  Consolidator | Disable-ScheduledTask } else { 'Consolidator task does not exist on this device.'} # collects and sends usage data to Microsoft (if the user has consented to participate in the CEIP)
	if(Get-ScheduledTask KernelCeipTask -ErrorAction Ignore) { Get-ScheduledTask  KernelCeipTask | Disable-ScheduledTask } else { 'KernelCeipTask does not exist on this device.'} # collects additional information related to customer experience and sends it to Microsoft (if the user consented to participate in the Windows CEIP)
	if(Get-ScheduledTask UsbCeip -ErrorAction Ignore) { Get-ScheduledTask  UsbCeip | Disable-ScheduledTask } else { 'UsbCeip task does not exist on this device.'}
	if(Get-ScheduledTask BthSQM -ErrorAction Ignore) { Get-ScheduledTask  BthSQM | Disable-ScheduledTask } else { 'BthSQM task does not exist on this device.'} # collects Bluetooth-related statistics and information about your machine and sends it to Microsoft (if you have consented to participate in the Windows CEIP). The information received is used to help.


	Write-Output "Disabling Microsoft Office telemetry."
	if(Get-ScheduledTask OfficeTelemetryAgentFallBack -ErrorAction Ignore) { Get-ScheduledTask  OfficeTelemetryAgentFallBack | Disable-ScheduledTask } else { 'OfficeTelemetryAgentFallBack task does not exist on this device.'} # initiates the background task for the Office Telemetry Agent that scans and uploads usage and error information for Office solutions
	if(Get-ScheduledTask 'OfficeTelemetryAgentFallBack2016' -ErrorAction Ignore) { Get-ScheduledTask  'OfficeTelemetryAgentFallBack2016' | Disable-ScheduledTask } else { 'OfficeTelemetryAgentFallBack2016 task does not exist on this device.'} #
	if(Get-ScheduledTask OfficeTelemetryAgentLogOn -ErrorAction Ignore) { Get-ScheduledTask  OfficeTelemetryAgentLogOn | Disable-ScheduledTask } else { 'OfficeTelemetryAgentLogOn task does not exist on this device.'} # initiates the Office Telemetry Agent that scans and uploads usage and error information for Office solutions when a user logs on to the computer
	if(Get-ScheduledTask 'OfficeTelemetryAgentLogOn2016' -ErrorAction Ignore) { Get-ScheduledTask  'OfficeTelemetryAgentLogOn2016' | Disable-ScheduledTask } else { 'OfficeTelemetryAgentLogOn2016 task does not exist on this device.'} #


	Write-Output "Disabling collects data for Microsoft SmartScreen."
	if(Get-ScheduledTask SmartScreenSpecific -ErrorAction Ignore) { Get-ScheduledTask  SmartScreenSpecific | Disable-ScheduledTask } else { 'SmartScreenSpecific task does not exist on this device.'}


	Write-Output "Disabling scheduled customer experience improvement program."
	if(Get-ScheduledTask Proxy -ErrorAction Ignore) { Get-ScheduledTask  Proxy | Disable-ScheduledTask } else { 'Proxy task does not exist on this device.'} # collects and uploads Software Quality Management (SQM) data if opted-in to the CEIP
	if(Get-ScheduledTask StartupAppTask -ErrorAction Ignore) { Get-ScheduledTask  StartupAppTask | Disable-ScheduledTask } else { 'StartupAppTask does not exist on this device.'}
	if(Get-ScheduledTask ProgramDataUpdater -ErrorAction Ignore) { Get-ScheduledTask  ProgramDataUpdater | Disable-ScheduledTask } else { 'ProgramDataUpdater task does not exist on this device.'} # collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program (CEIP)
	if(Get-ScheduledTask 'Microsoft Compatibility Appraiser' -ErrorAction Ignore) { Get-ScheduledTask  'Microsoft Compatibility Appraiser' | Disable-ScheduledTask } else { 'Microsoft Compatibility Appraiser task does not exist on this device.'} # collects program telemetry information if opted-in to the CEIP
	if(Get-ScheduledTask Uploader -ErrorAction Ignore) { Get-ScheduledTask  Uploader | Disable-ScheduledTask } else { 'Uploader task does not exist on this device.'}


	Write-Output "Disabling scheduled feedback."
	if(Get-ScheduledTask DmClient -ErrorAction Ignore) { Get-ScheduledTask  DmClient | Disable-ScheduledTask } else { 'DmClient task does not exist on this device.'}
	if(Get-ScheduledTask DmClientOnScenarioDownload -ErrorAction Ignore) { Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask } else { 'DmClientOnScenarioDownload task does not exist on this device.'}


	Write-Output "Disabling scheduled windows system assessment tool."
	if(Get-ScheduledTask WinSAT -ErrorAction Ignore) { Get-ScheduledTask  WinSAT | Disable-ScheduledTask } else { 'WinSAT task does not exist on this device.'} # measures system performance and capabilities


	Write-Output "Disabling scheduled family safety settings."
	if(Get-ScheduledTask FamilySafetyMonitor -ErrorAction Ignore) { Get-ScheduledTask  FamilySafetyMonitor | Disable-ScheduledTask } else { 'FamilySafetyMonitor task does not exist on this device.'} # initializes family safety monitoring and enforcement
	if(Get-ScheduledTask FamilySafetyRefresh -ErrorAction Ignore) { Get-ScheduledTask  FamilySafetyRefresh | Disable-ScheduledTask } else { 'FamilySafetyRefresh task does not exist on this device.'} # synchronizes the latest settings with the family safety website


	Write-Output "Disabling scheduled collects network information."
	if(Get-ScheduledTask GatherNetworkInfo -ErrorAction Ignore) { Get-ScheduledTask  GatherNetworkInfo | Disable-ScheduledTask } else { 'GatherNetworkInfo task does not exist on this device.'} # collects network information


	Write-Output "Disabling scheduled legacy tasks."
	if(Get-ScheduledTask AitAgent -ErrorAction Ignore) { Get-ScheduledTask  AitAgent | Disable-ScheduledTask } else { 'AitAgent task does not exist on this device.'} # aggregates and uploads application telemetry information if opted-in to the CEIP
	if(Get-ScheduledTask ScheduledDefrag -ErrorAction Ignore) { Get-ScheduledTask  ScheduledDefrag | Disable-ScheduledTask } else { 'ScheduledDefrag task does not exist on this device.'}
	if(Get-ScheduledTask 'SQM data sender' -ErrorAction Ignore) { Get-ScheduledTask  'SQM data sender' | Disable-ScheduledTask } else { 'SQM Data Sender task does not exist on this device.'} # sends SQM data to Microsoft
	if(Get-ScheduledTask DiskDiagnosticResolver -ErrorAction Ignore) { Get-ScheduledTask  DiskDiagnosticResolver | Disable-ScheduledTask } else { 'DiskDiagnosticResolver task does not exist on this device.'}
	if(Get-ScheduledTask Microsoft-Windows-DiskDiagnosticResolver -ErrorAction Ignore) { Get-ScheduledTask  Microsoft-Windows-DiskDiagnosticResolver | Disable-ScheduledTask } else { 'Microsoft-Windows-DiskDiagnosticResolver task does not exist on this device.'}
	if(Get-ScheduledTask DiskDiagnosticDataCollector -ErrorAction Ignore) { Get-ScheduledTask  DiskDiagnosticDataCollector | Disable-ScheduledTask } else { 'DiskDiagnosticDataCollector task does not exist on this device.'} # collects general disk and system information and sends it to Microsoft (if the user users participates in the CEIP)
	if(Get-ScheduledTask Microsoft-Windows-DiskDiagnosticDataCollector -ErrorAction Ignore) { Get-ScheduledTask  Microsoft-Windows-DiskDiagnosticDataCollector | Disable-ScheduledTask } else { 'Microsoft-Windows-DiskDiagnosticDataCollector task does not exist on this device.'} # collects general disk and system information and sends it to Microsoft (if the user users participates in the CEIP)


	Write-Output "Disabling scheduled error reporting."
	if(Get-ScheduledTask QueueReporting -ErrorAction Ignore) { Get-ScheduledTask  QueueReporting | Disable-ScheduledTask } else { 'QueueReporting task does not exist on this device.'}


	Write-Output "Disabling other annoying scheduled tasks."
	if(Get-ScheduledTask 'Adobe Acrobat Update Task' -ErrorAction Ignore) { Get-ScheduledTask  'Adobe Acrobat Update Task' | Disable-ScheduledTask } else { 'Adobe Acrobat Update Task does not exist on this device.'}
	if(Get-ScheduledTask 'CCleaner Update' -ErrorAction Ignore) { Get-ScheduledTask  'CCleaner Update' | Disable-ScheduledTask } else { 'CCleaner Update task does not exist on this device.'}
	$tempCCleaner = 'CCleanerSkipUAC - ' + $env:USERNAME
	if(Get-ScheduledTask $tempCCleaner -ErrorAction Ignore) { Get-ScheduledTask  $tempCCleaner | Disable-ScheduledTask } else { 'CCleanerSkipUAC task does not exist on this device.'}
	if(Get-ScheduledTask AMDRyzenMasterSDKTask -ErrorAction Ignore) { Get-ScheduledTask  AMDRyzenMasterSDKTask | Disable-ScheduledTask } else { 'AMDRyzenMasterSDKTask does not exist on this device.'}
	if(Get-ScheduledTask SystemOptimizer -ErrorAction Ignore) { Get-ScheduledTask  SystemOptimizer | Disable-ScheduledTask } else { 'HP SystemOptimizer task does not exist on this device.'}
	if(Get-ScheduledTask DuetUpdater -ErrorAction Ignore) { Get-ScheduledTask  DuetUpdater | Disable-ScheduledTask } else { 'DuetUpdater task does not exist on this device.'}
	if(Get-ScheduledTask 'Duet Updater' -ErrorAction Ignore) { Get-ScheduledTask  'Duet Updater' | Disable-ScheduledTask } else { 'Duet Updater task does not exist on this device.'} # collects program telemetry information if opted-in to the CEIP
}



Function SetSplitThreshold {
	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
	#(systeminfo | Select-String 'Memória física total').ToString().Split(':')[1].Trim()
	$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $ram -Force -ErrorAction SilentlyContinue
	Write-Output "Setting SvcHostSplitThresholdInKB to $ram"
}



Function DisableStorageSense {
	# Not applicable to Servers
	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. -> Disabling Storage Sense."
		#Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force -Recurse -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0x00000000
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 0x00000000
	}

	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Windows 11 Detected. -> Disabling Storage Sense."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0x00000000
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 0x00000000
	}
}



Function AllowMiracast {
	#See more at https://bbs.pcbeta.com/forum.php?mod=viewthread&tid=1912839
	Write-Host "Allowing Projection To PC."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "AllowProjectionToPC" -Type DWord -Value 0x00000001

	if (((((Get-ComputerInfo).OSName.IndexOf("LTSC")) -ne -1) -or ((Get-ComputerInfo).OSName.IndexOf("Server") -ne -1)) -and (((Get-ComputerInfo).WindowsVersion) -ge "1809")) {
		Write-Host "Manually Installing Wireless Display App..."

		Dism /Online /Add-Package /PackagePath:"$PSScriptRoot\Miracast_LTSC\Microsoft-PPIProjection-Package-amd64-10.0.19041.1.cab" /IgnoreCheck
		Dism /Online /Add-Package /PackagePath:"$PSScriptRoot\Miracast_LTSC\Microsoft-PPIProjection-Package-amd64-10.0.19041.1-zh-CN.cab" /IgnoreCheck

		Add-appxpackage -register "C:\Windows\SystemApps\Microsoft.PPIProjection_cw5n1h2txyewy\AppxManifest.xml" -disabledevelopmentmode

		Write-Host "Wireless Display App installed."
	}
	elseif (((Get-ComputerInfo).WindowsVersion) -lt "1809") {
		Write-Host "Wireless Display App is not supported on this version of Windows (Pre-1809)"
	}
	else {
		#Installing Wireless Display App from Windows Feature Repository
		Write-Host "Installing Wireless Display App..."
		DISM /Online /Add-Capability /CapabilityName:App.WirelessDisplay.Connect~~~~0.0.1.0
		Write-Host "Wireless Display App installed."
	}
}



function TurnWSLlight {
	Write-Output "WSL Performance Tweaks."
	$user_home = "$env:USERPROFILE\.wslconfig"
$wslconfig = @'
[wsl2]
kernelCommandLine=noibrs noibpb nopti nospectre_v1 nospectre_v2 nospec_store_bypass_disable no_stf_barrier spectre_v2_user=noibrs noibpb nopti nospectre_v1 nospectre_v2 nospec_store_bypass_disable no_stf_barrier spectre_v2_user=off spec_store_bypass_disable=off l1tf=off mitigations=off mds=off tsx_async_abort=off  spectre_v2=off kvm.nx_huge_pages=off kvm-intel.vmentry_l1d_flush=never ssbd=force-off tsx=on
'@
	New-Item -Path $user_home -Value $wslconfig -Force -ErrorAction SilentlyContinue
}



function DisableVBS_HVCI {
	<#
	Not recommended if you use it as a server in production. It can reduce your computer security capabilities.
	See more at https://www.tomshardware.com/how-to/disable-vbs-windows-11
	#>

	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. Turn off Virtualization-based security."
	#reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v "Enabled" /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f
	}

	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Windows 11 Detected. Turn off Virtualization-based security."
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f

	}
}

function DisableWindowsDefender {
	Write-Output "`nTrying to disable Windows Defender. First, you need to manually modify it by going to the:"
	Write-Output "`nSettings -> Privacy & Security -> Windows Security -> Virus & threat protection -> Manage settings -> Tamper Protection -> Off"

	Write-Output "`nAfter manual modification, press any key to continue the script."
	[Console]::ReadKey($true) | Out-Null


	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableSpecialRunningModes" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Type DWord -Value 0x00000000


	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0x00000001


	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Type DWord -Value 0x00000001


	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 0x00000001


	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ForceUpdateFromMU" -Type DWord -Value 0x00000000


	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 0x00000002

	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Type DWord -Value 0x00000000


}



###							  ###
### 	Features Tweaks-GPU	  ###
###							  ###



function RemoveXboxFeatures {
	Write-Output "Disabling Xbox features."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0x00000001

	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Type DWord -Value 0x00000000


	#Stop-Service "xbgm" -ea Stop
	Set-Service "xbgm" -StartupType Disabled -erroraction SilentlyContinue


	Write-Output "Disable GameDVR and Broadcast used for game recordings and live broadcasts."
	#Stop-Service "BcastDVRUserService" -ea Stop
	Set-Service "BcastDVRUserService" -StartupType Disabled -erroraction SilentlyContinue

	#Stop-Service "BcastDVRUserService_48486de" -ea Stop
	Set-Service "BcastDVRUserService_48486de" -StartupType Disabled -erroraction SilentlyContinue

	#Stop-Service "BcastDVRUserService_5a109" -ea Stop
	Set-Service "BcastDVRUserService_5a109" -StartupType Disabled -erroraction SilentlyContinue

	#Stop-Service "BcastDVRUserService_6fa5a" -ea Stop
	Set-Service "BcastDVRUserService_6fa5a" -StartupType Disabled -erroraction SilentlyContinue


	# It is necessary to take ownership of a registry key and change permissions to modify the key below.
	Write-Output "Elevating privileges for this process..."

	$myIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

	enable-privilege SeTakeOwnershipPrivilege 
	$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)
	# You must get a blank acl for the key b/c you do not currently have access
	$acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
	$me = [System.Security.Principal.NTAccount]$myIdentity.ToString()
	$acl.SetOwner($me)
	$key.SetAccessControl($acl)

	# After you have set owner you need to get the acl with the perms so you can modify it.
	$acl = $key.GetAccessControl()
	$rule = New-Object System.Security.AccessControl.RegistryAccessRule ($myIdentity.ToString(),"FullControl","Allow")
	$acl.SetAccessRule($rule)
	$key.SetAccessControl($acl)

	$key.Close()

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Force -Name "ActivationType" -Type DWord -Value 0x00000000

	Write-Host "Finished Removing Xbox features."
}



function enable-privilege {
 $ErrorActionPreference = 'silentlycontinue'
 param(
  ## The privilege to adjust. This set is taken from
  ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
  [ValidateSet(
   "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
   "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
   "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
   "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
   "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
   "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
   "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
   "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
   "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
   "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
   "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
  $Privilege,
  ## The process on which to adjust the privilege. Defaults to the current process.
  $ProcessId = $pid,
  ## Switch to disable the privilege, rather than enable it.
  [Switch] $Disable
 )

 ## Taken from P/Invoke.NET with minor adjustments.
 $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

 $processHandle = (Get-Process -id $ProcessId).Handle
 $type = Add-Type $definition -PassThru
 $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}



Function EnableGPUScheduling {
	Write-Host "Turn On Hardware Accelerated GPU Scheduling."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 0x00000002
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "PlatformSupportMiracast" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "UnsupportedMonitorModesAllowed" -Type DWord -Value 0x00000001
}



Function EnableVRR_AutoHDR {
	Write-Host "Turn On Variable Refresh Rate - Auto HDR - Optimizations for Windowed Games."
	If (!(Test-Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences")) {
		New-Item -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "DirectXUserGlobalSettings" -Type String -Value "VRROptimizeEnable=1;AutoHDREnable=1;SwapEffectUpgradeEnable=1;"
	
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Name "EnableHDRForPlayback" -Type DWord -Value 0x00000001

}



Function EnableEdge_GPU {
	Write-Host "Turn On Hardware Accelerated GPU on Microsoft Edge Canary."
	If (!(Test-Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences")) {
		New-Item -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" -Type String -Value "GpuPreference=2;"

}



###				   ###
### Privacy Tweaks ###
###				   ###



Function AcceptedPrivacyPolicy {
	Write-Output "Turning off AcceptedPrivacyPolicy."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0x00000000
}



Function DisableActivityHistory {
	Write-Host "Disabling activity history."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0x00000000

	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0x00000000
}



Function DisableAdvertisingID {
	Write-Host "Disabling Advertising ID."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 0x00000001
}



Function DisableAdvertisingInfo {

	Write-Output "Disabling Windows Feedback Experience program."
	$Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
	If (Test-Path $Advertising) {
		Set-ItemProperty $Advertising Enabled -Type DWord -Value 0x00000000
	}
}



Function DisableAppDiagnostics {
	Write-Output "Turning off AppDiagnostics."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Type String -Value "Deny"
}



Function DisableCEIP {
	Write-Host "Microsoft Customer Experience Improvement Program (CEIP)."
	<#
	The program collects information about computer hardware and how you use Microsoft Application Virtualization without interrupting you.
	This helps Microsoft identify which Microsoft Application Virtualization features to improve.
	No information collected is used to identify or contact you.
	#>
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.AppV::CEIP_Enable

	$SQMClient1 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient"
	If (Test-Path $SQMClient1) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient" -Name "CEIPEnabled" -Type DWord -Value 0x00000000
	}

	$SQMClient2 = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
	If (Test-Path $SQMClient2) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnabled" -Type DWord -Value 0x00000000
	}

	$SQMClient3 = "HKLM:\Software\Microsoft\SQMClient\Windows"
	If (Test-Path $SQMClient3) {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0x00000000
	}

	$SQMClient4 = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient"
	If (Test-Path $SQMClient4) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient" -Name "CEIPEnabled" -Type DWord -Value 0x00000000
	}

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0x00000000


	#Disable CEIP for SSDT and SSDT-BI for Visual studio 2013.
	If (!(Test-Path "HKCU:\Software\Microsoft\Microsoft SQL Server\120")) {
		New-Item -Path "HKCU:\Software\Microsoft\Microsoft SQL Server\120" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Microsoft SQL Server\120" -Name "CustomerFeedback" -Type DWord -Value 0x00000000


	#Disable SSDT for Visual Studio 2015 is the data modeling tool that ships with SQL Server 2016.
	If (!(Test-Path "HKCU:\Software\Microsoft\VSCommon\14.0\SQM")) {
		New-Item -Path "HKCU:\Software\Microsoft\VSCommon\14.0\SQM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\VSCommon\14.0\SQM" -Name "OptIn" -Type DWord -Value 0x00000000


	#Disable SSDT for Visual Studio 2017 is the data modeling tool that ships with SQL Server 2017.
	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Name "OptIn" -Type DWord -Value 0x00000000
}



Function DisableDataCollection {
	Write-Output "Turning off Data Collection via the AllowTelemtry key by changing it to 0"
	$DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
	$DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
	$DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
	If (Test-Path $DataCollection1) {
		Set-ItemProperty $DataCollection1  AllowTelemetry -Type DWord -Value 0x00000000
	}
	If (Test-Path $DataCollection2) {
		Set-ItemProperty $DataCollection2  AllowTelemetry -Type DWord -Value 0x00000000
	}
	If (Test-Path $DataCollection3) {
		Set-ItemProperty $DataCollection3  AllowTelemetry -Type DWord -Value 0x00000000
	}
}



function DisableDiagTrack {
	Write-Output "Stopping and disabling Connected User Experiences and Telemetry Service."

	#Stop-Service "DiagTrack" -ea Stop
	Set-Service "DiagTrack" -StartupType Disabled -erroraction SilentlyContinue

	#Stop-Service "diagnosticshub.standardcollector.service" -ea Stop
	Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled -erroraction SilentlyContinue
} 



Function DisableErrorReporting {
	Write-Host "Disabling Error reporting."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0x00000001

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Type DWord -Value 0x00000001

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0x00000001
}




Function DisableFeedbackExperience {
	Write-Output "Stops the Windows Feedback Experience from sending anonymous data."
	$Period1 = "HKCU:\Software\Microsoft\Siuf\Rules"
	$Period2 = "HKCU:\Software\Microsoft\Siuf"
	If (!(Test-Path $Period1)) { 
		If (!(Test-Path $Period2)) { 
			New-Item $Period2
		}
		New-Item $Period1
	}
	Set-ItemProperty $Period1 PeriodInNanoSeconds -Type DWord -Value 0x00000000
	Set-ItemProperty $Period1 NumberOfSIUFInPeriod -Type DWord -Value 0x00000000
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 0x00000001
}



Function DisableLocationTracking {
	# Disabling this will break Microsoft Find My Device functionality.
	Write-Output "Disabling Location Tracking."
	$SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
	$LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
	If (!(Test-Path $SensorState)) {
		New-Item $SensorState
	}
	Set-ItemProperty $SensorState SensorPermissionState -Type DWord -Value 0x00000000
	If (!(Test-Path $LocationConfig)) {
		New-Item $LocationConfig
	}
	Set-ItemProperty $LocationConfig Status -Type DWord -Value 0x00000000


	#Stop-Service "lfsvc" -ea Stop
	Set-Service "lfsvc" -StartupType Disabled -erroraction SilentlyContinue

	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"

}



Function DisableTailoredExperiences {
	Write-Host "Disabling Tailored Experiences."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 0x00000001
}



###					###
### Security Tweaks ###
###					###



Function RemoveAutoLogger {
	Write-Host "Removing AutoLogger file and restricting directory."
	$autoLoggerDir = "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\Autologger"
	If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
		Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl" -Force -ErrorAction SilentlyContinue
	}
	icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
}



Function DisableRemoteAssistance {
	Write-Host "Disabling Remote Assistance."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0x00000000
}



###					###
### Network Tweaks  ###
###					###



# Improve network performance by improving how many buffers your computer can use simultaneously on your LAN. 
Function SetIRPStackSize {
	Write-Output "Setting IRPStackSize."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 0x0000000c 	# Values may range from 1 to 12 in decimal notation.
}



function SettingTimeService {
	Write-Host "Setting BIOS time to UTC and fixing any inconsistency."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1

	# Secure Time Seeding – improving time keeping in Windows. This resolve a lot of problems with VM's & WSL time out of sync in some devices.
	# See more at http://byronwright.blogspot.com/2016/03/windows-10-time-synchronization-and.html

	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\w32time\SecureTimeLimits\RunTime" -Name "SecureTimeTickCount" -Type QWORD -Value 8735562

	net stop w32time

	w32tm /unregister
	w32tm /register

	net start w32time
	w32tm /resync /nowait
}



Function DisableWiFiSense {
	Write-Output "Disabling Wi-Fi Sense."
	$WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
	$WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
	$WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
	If (!(Test-Path $WifiSense1)) {
		New-Item $WifiSense1
	}
	Set-ItemProperty $WifiSense1  Value -Type DWord -Value 0x00000000
	If (!(Test-Path $WifiSense2)) {
		New-Item $WifiSense2
	}
	Set-ItemProperty $WifiSense2  Value -Type DWord -Value 0x00000000
	Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Type DWord -Value 0x00000000
}



###					###
### Service Tweaks 	###
###					###



<#
Device Management Wireless Application Protocol (WAP) Push Message Routing Service
Useful for Windows tablet devices with mobile (3G/4G) connectivity
#>
function DisableWAPPush {
	Write-Host "Stopping and disabling WAP Push Service."

	#Stop-Service "dmwappushservice" -ea Stop
	Set-Service "dmwappushservice" -StartupType Disabled -erroraction SilentlyContinue
} 



function DisableServices {

	Write-Output "Stopping and disabling AdobeARM Service."

	#Stop-Service "AdobeARMservice" -ea Stop
	Set-Service "AdobeARMservice" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Application Management."

	#Stop-Service "AppMgmt" -ea Stop
	Set-Service "AppMgmt" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Certificate Propagation Service. Copies user certificates and root certificates from smart cards into the current user's certificate store."

	#Stop-Service "CertPropSvc" -ea Stop
	Set-Service "CertPropSvc" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables ActiveX Installer."

	#Stop-Service "AxInstSV" -ea Stop
	Set-Service "AxInstSV" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables offline files service."

	#Stop-Service "CscService" -ea Stop
	Set-Service "CscService" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables fax."

	#Stop-Service "Fax" -ea Stop
	Set-Service "Fax" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables File History Service."

	#Stop-Service "fhsvc" -ea Stop
	Set-Service "fhsvc" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Stopping and disabling Home Groups services."

	#Stop-Service "HomeGroupListener" -ea Stop
	Set-Service "HomeGroupListener" -StartupType Disabled -erroraction SilentlyContinue
	#Stop-Service "HomeGroupProvider" -ea Stop
	Set-Service "HomeGroupProvider" -StartupType Disabled -erroraction SilentlyContinue


	<#
	Write-Output "Stopping and disabling HP App Helper Service."

	Stop-Service "HPAppHelperCap" -ea Stop
	Set-Service "HPAppHelperCap" -StartupType Disabled -erroraction SilentlyContinue
	#>


	Write-Output "Stopping and disabling HP Diagnostics Service."

	#Stop-Service "HPDiagsCap" -ea Stop
	Set-Service "HPDiagsCap" -StartupType Disabled -erroraction SilentlyContinue


	<#
	Write-Output "Stopping and disabling HP Network Service."

	Stop-Service "HPNetworkCap" -ea Stop
	Set-Service "HPNetworkCap" -StartupType Disabled -erroraction SilentlyContinue
	#>


	<#
	Write-Output "Stopping and disabling HP Omen Service."

	Stop-Service "HPOmenCap" -ea Stop
	Set-Service "HPOmenCap" -StartupType Disabled -erroraction SilentlyContinue
	#>


	Write-Output "Stopping and disabling HP Print Scan Doctor Service."

	#Stop-Service "HPPrintScanDoctorService" -ea Stop
	Set-Service "HPPrintScanDoctorService" -StartupType Disabled -erroraction SilentlyContinue


	<#
	Write-Output "Stopping and disabling HP System Info Service."

	Stop-Service "HPSysInfoCap" -ea Stop
	Set-Service "HPSysInfoCap" -StartupType Disabled -erroraction SilentlyContinue
	#>


	Write-Output "Stopping and disabling HP Telemetry Service."

	#Stop-Service "HpTouchpointAnalyticsService" -ea Stop
	Set-Service "HpTouchpointAnalyticsService" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Microsoft iSCSI Initiator Service."

	#Stop-Service "MSiSCSI" -ea Stop
	Set-Service "MSiSCSI" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables The Network Access Protection (NAP) agent service. It collects and manages health information for client computers on a network."

	#Stop-Service "napagent" -ea Stop
	Set-Service "napagent" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disable the Network Data Usage Monitoring Driver."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Ndu" -Name "Start" -Type DWord -Value 4


	Write-Host "Disables Peer Networking Identity Manager."

	#Stop-Service "p2pimsvc" -ea Stop
	Set-Service "p2pimsvc" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Peer Networking Grouping."	

	#Stop-Service "p2psvc" -ea Stop
	Set-Service "p2psvc" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disable BranchCache service.This service caches network content from peers on the local subnet."	

	#Stop-Service "PeerDistSvc" -ea Stop
	Set-Service "PeerDistSvc" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disable Performance Logs and Alerts Service."

	#Stop-Service "pla" -ea Stop
	Set-Service "pla" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Peer Name Resolution Protocol."

	#Stop-Service "PNRPsvc" -ea Stop
	Set-Service "PNRPsvc" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Windows Remote Registry service."

	#Stop-Service "RemoteRegistry" -ea Stop
	Set-Service "RemoteRegistry" -StartupType Disabled -erroraction SilentlyContinue


	<#
	The smart card removal policy service is applicable when a user has signed in with a smart card and then removes that smart card from the reader. 
	The action that is performed when the smart card is removed is controlled by Group Policy settings. 
	For more information, see Smart Card Group Policy and Registry Settings.
	#>
	Write-Host "Disabling Smart Card Removal Policy Service."

	#Stop-Service "ScPolicySvc" -ea Stop
	Set-Service "ScPolicySvc" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Windows Remote Registry service."

	#Stop-Service "SQLTELEMETRY$SQLEXPRESS" -ea Stop
	Set-Service "SQLCEIP" -StartupType Disabled -erroraction SilentlyContinue


	<#
	An SNMP trap message is an unsolicited message sent from an agent to the the manager.
	The objective of this message is to allow the remote devices to alert the manager in case an important event happens,
	commonly used in companies.
	#>
	Write-Host "Disables Simple Network Management Protocol (SNMP) service."

	#Stop-Service "SNMPTRAP" -ea Stop
	Set-Service "SNMPTRAP" -StartupType Disabled -erroraction SilentlyContinue


	<#
	The Memory Compression process is serviced by the SysMain (formerly SuperFetch) service.
	SysMain reduces disk writes (paging) by compressing and consolidating memory pages.
	If this service is stopped, then Windows does not use RAM compression.
	Write-Host "Disables Superfetch service."

	Stop-Service "SysMain" -ea Stop
	Set-Service "SysMain" -StartupType Disabled -erroraction SilentlyContinue
	#>
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "DelayedAutoStart" -Type DWord -Value 00000001

	<#
	Disabling this will break WSL keyboard functionality.
	Write-Output "Stopping and disabling Touch Keyboard and Handwriting Panel Service."

	Stop-Service "TabletInputService" -ea Stop
	Set-Service "TabletInputService" -StartupType Disabled -erroraction SilentlyContinue
	#>


	Write-Host "Disables WebClient service."

	#Stop-Service "WebClient" -ea Stop
	Set-Service "WebClient" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Windows Error Reporting."

	#Stop-Service "WerSvc" -ea Stop
	Set-Service "WerSvc" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Windows Remote Management."

	#Stop-Service "WinRM" -ea Stop
	Set-Service "WinRM" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disables Windows Insider Service. Caution! Windows Insider will not work anymore."

	#Stop-Service "wisvc" -ea Stop
	Set-Service "wisvc" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Stopping and disabling Windows Search Indexing service."

	#Stop-Service "WSearch" -ea Stop
	Set-Service "WSearch" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Stopping and disabling Diagnostic Policy service."

	#Stop-Service "DPS" -ea Stop
	Set-Service "DPS" -StartupType Disabled -erroraction SilentlyContinue



	Write-Host "Stopping and disabling Program Compatibility Assistant service."

	#Stop-Service "PcaSvc" -ea Stop
	Set-Service "PcaSvc" -StartupType Disabled -erroraction SilentlyContinue
}



###					###
### Speed Up System	###
###					###


#The AutoplayHandler element specifies a UWP device app that should appear as the recommended AutoPlay action when a user plugs in a device.
Function DisableAutoplayHandler {
	Write-Output "Disabling AutoplayHandlers."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0x00000001
}



Function DisableBingSearch {
	Write-Output "Disabling Bing Search in Start Menu."
	$WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	
	If (!(Test-Path $WebSearch)) {
		New-Item $WebSearch
	}
	Set-ItemProperty $WebSearch DisableWebSearch -Type DWord -Value 0x00000001

	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0x00000000

	$DisableSearchBox = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
	
	If (!(Test-Path $DisableSearchBox)) {
		New-Item $DisableSearchBox
	}
	Set-ItemProperty $DisableSearchBox DisableSearchBoxSuggestions -Type DWord -Value 0x00000001

}



Function DisableCortanaSearch {
	Write-Output "Stopping Cortana from being used as part of your Windows Search Function."
	$Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	If (Test-Path $Search) {
		Set-ItemProperty $Search AllowCortana -Type DWord -Value 0x00000000
	}
}



Function GetFullContextMenu {
	Write-Output "Setting Full Context Menus."
	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Setting Full Context Menus in Windows 11."
		If (!(Test-Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}")) {
			New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Force | Out-Null
			New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
			Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" '(Default)' -Value ""
		}
	}
# reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve

}

Function PrintScreenToSnippingTool {
	Write-Output "Use print screen to open snipping tool."
	If (!(Test-Path "HKCU:\Control Panel\Keyboard")) {
		New-Item -Path "HKCU:\Control Panel\Keyboard" -Force | Out-Null
	}
		Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Type DWord -Value 0x00000001
}


Function DisableLiveTiles {
	Write-Output "Disabling live tiles."
	$Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
	If (!(Test-Path $Live)) {  
		New-Item $Live
	}
	Set-ItemProperty $Live  NoTileApplicationNotification -Type DWord -Value 0x00000001
}


### Disk Cache Optimization ###


Function SetWaitToKillAppTimeout {
	Write-Output "Optimize program response time to improve system response speed."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Type String -Value 10000		#Default 20000
}


Function SetHungAppTimeout {
	Write-Output "Shorten the wait time for unresponsive mouse and keyboard caused by error program."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "HungAppTimeout" -Type String -Value 3000			#Default 5000
}


Function SetPriorityControl {
	Write-Output "Optimize processor resource allocation to make multimedia smoother."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000026		#Default 00000002
}


Function SetAutoEndTasks {
	Write-Output "Automatically end unresponsive programs to avoid system crash."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Type String -Value 1					#Default ""
}


Function SetBootOptimizeFunction {
	Write-Output "Disable Windows auto disk defragmetation and automatically optimize boot partition to make the bootup speed faster."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Type String -Value "Y"					#Default ""	
	
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Dfrg\BootOptimizeFunction")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Dfrg\BootOptimizeFunction" -Force | Out-Null
	}	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Type String -Value "Y"		#Default ""
}


### Desktop Menu Optimization ###


Function SetMinAnimate {
	Write-Output "Disable useless visual effects to speed up response and display of desktop."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value "0"
}


Function SetDesktopProcess {
	Write-Output "Optimize the priority of program processes and independent processes to avoid system crash."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DesktopProcess" -Type DWord -Value 0x00000001					#Default 00000000
}


Function SetTaskbarAnimations {
	Write-Output "Play animations in the taskbar and start menu."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0x00000000		#Default 00000001
}


Function SetWaitToKillServiceTimeout {
	Write-Output "Optimize the speed of ending processes."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type String -Value "2000"								#Default "5000"
}


Function SetNoSimpleNetIDList {
	Write-Output "Optimize the refresh strategy of the system file list."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSimpleNetIDList" -Type DWord -Value 0x00000001
}


Function SetMouseHoverTime {
	Write-Output "Reduce the display time of taskbar preview."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "100"						#Default "400"
}


Function SetMenuShowDelay {
	Write-Output "Speed up the response and display of system commands."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value "0"
}


Function SetForegroundLockTimeout {
	Write-Output "Improve the response speed of foreground program."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ForegroundLockTimeout" -Type DWord -Value 0x000249f0		#Default 00030d40

}


Function SetAlwaysUnloadDLL {
	Write-Output "Release unused dlls in memory."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "AlwaysUnloadDLL" -Type DWord -Value 0x00000001
}


Function SetFontStyleShortcut{
	Write-Output "Remove the font style of the desktop shortcut."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type String -Value "0"					#Default "1E 00 00 00"
}


Function SetAutoRestartShell {
	Write-Output "Optimize user interface components. Auto-refresh when there is an error to avoid system crash."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Type DWord -Value 0x00000001					#Default 00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Type DWord -Value 0x00000001		#Default 00000000
}


Function SetVisualEffects {
	Write-Output "Optimize the visual effects of system menus and lists to improve system performance."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0x00000000					#Default 00000001
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 0x00000002
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" -Name "DefaultApplied" -Type DWord -Value 0x00000000		#Default 00000001
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" -Name "DefaultApplied" -Type DWord -Value 0x00000000			#Default 00000001
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Name "DefaultApplied" -Type DWord -Value 0x00000000		#Default 00000001
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Name "DefaultApplied" -Type DWord -Value 0x00000000	#Default 00000001
}


Function SetSystemResponsiveness {
	Write-Output "Determines the percentage of CPU resources that should be guaranteed to low-priority tasks (MMCSS)."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0x0000000a			#Default 00000014
}


Function DisableHPET {
	Write-Output "Disable HPET, Synthetic Timers and Dynamic Ticks."
	bcdedit /set useplatformclock no
	#bcdedit /deletevalue useplatformclock
	bcdedit /set useplatformtick yes
	bcdedit /set disabledynamictick yes
}


### File System Optimization ###


Function SetAeDebug {
	Write-Output "Turn off Just-In-Time Debugging function to improve system performance."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name "Auto" -Type String -Value "0"								#Default "1"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name "Auto" -Type String -Value "0"		#Default "1"
}


Function SetNoLowDiskSpaceChecks {
	Write-Output "Improve hard disk performance to enhance disk read/write capacity."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoLowDiskSpaceChecks" -Type DWord -Value 0x00000001	#Default 00000000
}


Function SetNtfsDisable8dot3NameCreation {
	Write-Output "Disable short file names feature."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisable8dot3NameCreation" -Type DWord -Value 0x00000001		#Default 00000000
}


Function SetDoReport {
	Write-Output "Disable Windows error reporting function to get better system response speed."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PCHealth\ErrorReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PCHealth\ErrorReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PCHealth\ErrorReporting" -Name "ShowUI" -Type DWord -Value 0x00000000

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\PCHealth\ErrorReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\PCHealth\ErrorReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\PCHealth\ErrorReporting" -Name "ShowUI" -Type DWord -Value 0x00000000
}


Function SetMaxCachedIcons {
	Write-Output "Increase the system image buffer to display images faster."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Type String -Value "4000"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Type String -Value "4000"
}


Function SetNoDriveTypeAutoRun {
	Write-Output "Disable AutoPlay for external devices to avoid potential risks such as malware."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 0x000000dd		#Default 00000091
}


### Network Optimization ###


Function SetDefaultTTL {
	Write-Output "Optimize default TTL to decrease bandwidth loss and increase available bandwidth."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 0x00000040
}


Function SetFastForwarding {
	Write-Output "Optimize network fast forwarding mechanism to get better internet speed."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SackOpts" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDupAcks" -Type DWord -Value 0x00000002
}


Function SetMaxConnectionsPerServerIE {
	Write-Output "Add more IE concurrent connections."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "iexplore.exe" -Type DWord -Value 0x0000000a
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "iexplore.exe" -Type DWord -Value 0x0000000a
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "iexplore.exe" -Type DWord -Value 0x0000000a
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "iexplore.exe" -Type DWord -Value 0x0000000a
	
	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
	Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPerServer" -Type DWord -Value 0x0000000a
	Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPer1_0Server" -Type DWord -Value 0x0000000a
	Set-ItemProperty -Path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPerServer" -Type DWord -Value 0x0000000a
	Set-ItemProperty -Path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPer1_0Server" -Type DWord -Value 0x0000000a

	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPerServer" -Type DWord -Value 0x0000000a
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPer1_0Server" -Type DWord -Value 0x0000000a
}


Function SetMaxConnectionsPerServer {
	Write-Output "Optimize Network Adapter performance to get better Internet speed."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxConnectionsPerServer" -Type DWord -Value 0x00000000
}


Function SetKeyboardDelay {
	Write-Output "Adjust the keyboards delayed response time."
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type String -Value "2"		#Default "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type String -Value "0"					#Default "1"
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardSpeed" -Type String -Value "48"				#Default "31"
}


Function SetAutoDetectionMTUsize {
	Write-Output "Enable auto-detection of MTU size and black hole router detection to get better internet speed."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUDiscovery" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUBHDetect" -Type DWord -Value 0x00000001
}


Function SetNameSrvQueryTimeout {
	Write-Output "Optimize network WINS name query time to enhance network data transmission capacity."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NameSrvQueryTimeout" -Type DWord -Value 0x00000bb8
}


Function SetDnsCache {
	Write-Output "Optimize DNS to get better parsing speed."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NegativeSOACacheTime" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NetFailureCacheTime" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheEntryTtlLimit" -Type DWord -Value 0x00002a30
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl" -Type DWord -Value 0x00002a30
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxNegativeCacheTtl" -Type DWord -Value 0x00000000
}


Function SetNoUpdateCheckonIE {
	Write-Output "Disable automatic updates on IE."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name "NoUpdateCheck" -Type DWord -Value 0x00000001
	
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name "NoUpdateCheck" -Type DWord -Value 0x00000001
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "NoUpdateCheck" -Type DWord -Value 0x00000001
}


Function SetTcp1323Opts {
	Write-Output "Enable auto-adjustment of transport unit buffer to shorten network response time."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Tcp1323Opts" -Type DWord -Value 0x00000001
}


Function SetMaxCmds {
	Write-Output "Optimize network parameter configuration to improve network performance and throughput."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "MaxCmds" -Type DWord -Value 0x0000001e
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "MaxThreads" -Type DWord -Value 0x0000001e
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "MaxCollectionCount" -Type DWord -Value 0x00000020
}


Function SetNoNetCrawling {
	Write-Output "Optimize LAN connection."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NoNetCrawling" -Type DWord -Value 0x00000001		#Default 00000000
}


Function SetGlobalMaxTcpWindowSize {
	Write-Output "Speed up the broadband network."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "GlobalMaxTcpWindowSize" -Type DWord -Value 0x00007fff
}



###						  ###
### Server-related Tweaks ###
###						  ###



Function DisableEventTracker {
	Write-Output "Disabling Shutdown Event Tracker."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0x00000000
}



### 		  ###
###   Unpin   ###
### 		  ###



Function RemovingFax {
	Write-Output "Removing Default Fax Printer."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}



<#
PropertyTypes
Specifies the type of property that this cmdlet adds. The acceptable values for this parameter are:

	String: Specifies a null-terminated string. Used for REG_SZ values.
	ExpandString: Specifies a null-terminated string that contains unexpanded references to environment variables that are expanded when the value is retrieved. Used for REG_EXPAND_SZ values.
	Binary: Specifies binary data in any form. Used for REG_BINARY values.
	DWord: Specifies a 32-bit binary number. Used for REG_DWORD values.
	MultiString: Specifies an array of null-terminated strings terminated by two null characters. Used for REG_MULTI_SZ values.
	Qword: Specifies a 64-bit binary number. Used for REG_QWORD values.
	Unknown: Indicates an unsupported registry data type, such as REG_RESOURCE_LIST values.
#>


# Export functions
Export-ModuleMember -Function *