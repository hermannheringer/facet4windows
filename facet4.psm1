<#
Facet4 Windows 10/11 distribution
Author: Hermann Heringer
Version : 0.3.7
Source: https://github.com/hermannheringer/
#>

#.............................................................................................................................................................................................
#....................................................  Default values at the end of each instruction extracted from Windows 11 Home 22H2  ....................................................
#.......                                                                                                                                                                               .......
#.......  "Default NA" means that the instruction is not there on a fresh install, but it does not mean it is not valid if placed there. If in doubt, look for official documentation  .......
# .......................................................  https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features  ..........................................................
#.............................................................................................................................................................................................

Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip {
    param([string]$zipfile, [string]$outpath)
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}



###				 ###
###  Application ###
###				 ###



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
				Remove-Item -Path "$facet4Folder\microsoft.ui.xaml" -Force -ErrorAction SilentlyContinue
				Remove-Item -Path "$facet4Folder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Force -ErrorAction SilentlyContinue
				Remove-Item -Path "$facet4Folder\b0a0692da1034339b76dce1c298a1e42_License1.xml" -Force -ErrorAction SilentlyContinue

				winget install "App Installer" -s msstore --silent --accept-package-agreements --accept-source-agreements --force
	
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



###		      ###
###  Debloat  ###
###		      ###



Function DebloatBlacklist {

	$Bloatware = @(
		# Unnecessary default Windows 10 Apps
		"*Clipchamp*"
		"*Microsoft.3DBuilder*"
		#"*Microsoft.AppConnector*"
		#"*Microsoft.CommsPhone*"
		#"*Microsoft.ConnectivityStore*"
		"*Microsoft.Disney*"
		"*Microsoft.FreshPaint*"
		"*Microsoft.feedbackhub*"
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
		"*Microsoft.People*"
		#"*Microsoft.PowerAutomateDesktop*"
		"*Microsoft.Print3D*"
		"*Microsoft.Reader*"
		#"*Microsoft.RemoteDesktop*"
		#"*Microsoft.ScreenSketch*"
		"*Microsoft.SkypeApp*"
		#"*Microsoft.StorePurchaseApp*"
		"*Microsoft.Todos*"
		"*Microsoft.Wallet*"
		#"*Microsoft.WebMediaExtensions*"
		"*Microsoft.Whiteboard*"
		#"*Microsoft.WindowsAlarms*"
		#"*Microsoft.WindowsCamera*"
		"*Microsoft.windowscommunicationsapps*"
		"*Microsoft.WindowsMaps*"
		"*Microsoft.WindowsReadingList*"
		"*Microsoft.WindowsScan*"
		"*Microsoft.WindowsSoundRecorder*"
		"*Microsoft.WinJS.1.0*"
		"*Microsoft.WinJS.2.0*"
		"*Microsoft.Xbox.TCUI*"
		"*Microsoft.XboxApp*"
		"*Microsoft.XboxGameOverlay*"
		"*Microsoft.XboxGamingOverlay*"
		"*Microsoft.XboxSpeechToTextOverlay*"
		#"*Microsoft.YourPhone*"
		"*Microsoft.ZuneMusic*"
		"*Microsoft.ZuneVideo*"
		#"*MicrosoftCorporationII.MicrosoftFamily*"
		#"*MicrosoftCorporationII.QuickAssist*"

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


		# Sponsored non-Microsoft Apps
		"*22364Disney.ESPNBetaPWA*"
		"*2414FC7A.Viber*"
		"*2FE3CB00.PicsArt-PhotoStudio*"
		"*41038Axilesoft.ACGMediaPlayer*"
		"*46928bounde.EclipseManager*"
		"*4DF9E0F8.Netflix*"
		#"*5319275A.WhatsAppDesktop*"
		"*5A894077.McAfeeSecurity*"
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
		"*AD2F1837.GettingStartedwithWindows8*"
		"*AD2F1837.HPDesktopSupportUtilities*"
		"*AD2F1837.HPEasyClean*"
		"*AD2F1837.HPJumpStart*"
		"*AD2F1837.HPJumpStarts*"
		"*AD2F1837.HPPCHardwareDiagnosticsWindows*"
		"*AD2F1837.HPPowerManager*"
		"*AD2F1837.HPPrivacySettings*"
		"*AD2F1837.HPQuickDrop*"
		"*AD2F1837.HPQuickTouch*"
		"*AD2F1837.HPRegistration*"
		"*AD2F1837.HPSupportAssistant*"
		"*AD2F1837.HPSureShieldAI*"
		"*AD2F1837.HPSystemInformation*"
		"*AD2F1837.HPWorkWell*"
		"*AD2F1837.myHP*"
		"*AdobeSystemsIncorporated.AdobeCreativeCloudExpress*"
		"*AdobeSystemsIncorporated.AdobeLightroom*"
		"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
		"*Amazon.com.Amazon*"
		"*AmazonVideo.PrimeVideo*"
		#"*AppUp.IntelGraphicsExperience*"
		"*B9ECED6F.ASUSPCAssistant*"
		"*B9ECED6F.ScreenPadMaster*"
		"*BubbleWitch3Saga*"
		"*BytedancePte.Ltd.TikTok*"
		"*C27EB4BA.DropboxOEM*"
		"*CAF9E577.Plex*"
		"*CandyCrush*"
		"*ClearChannelRadioDigital.iHeartRadio*"
		"*CorelCorporation.PaintShopPro*"
		"*CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC*"
		"*D52A8D61.FarmVille2CountryEscape*"
		"*D5EA27B7.Duolingo-LearnLanguagesforFree*"
		"*DB6EA5DB.CyberLinkMediaSuiteEssentials*"
		"*Disney*"
		#"*Dolby*"
		"*Drawboard.DrawboardPDF*"
		#"*DTSInc.DTSAudioProcess*"
		"*Duolingo-LearnLanguagesforFree*"
		"*EclipseManager*"
		"*Facebook*"
		"*Fitbit.FitbitCoach*"
		"*flaregamesGmbH.RoyalRevolt2*"
		"*Flipboard*"
		"*GAMELOFTSA*"
		"*HotspotShieldFreeVPN*"
		"*Hulu*"
		"*KeeperSecurityInc.Keeper*"
		"*king.com.*"
		"*Minecraft*"
		"*NAVER.LINE*"
		"*Netflix*"
		"*Nordcurrent.CookingFever*"
		"*PandoraMediaInc*"
		"*Playtika.CaesarsSlotsFreeCasino*"
		"*PricelinePartnerNetwork.Booking*"
		"*RoyalRevolt*"
		"*ShazamEntertainmentLtd.Shazam*"
		#"*SpeedTest*"
		"*Spotify*"
		"*TheNewYorkTimes.NYTCrossword*"
		"*ThumbmunkeysLtd.PhototasticCollage*"
		"*TuneIn.TuneInRadio*"
		"*Twitter*"
		"*WinZipComputing.WinZipUniversal*"
		"*Wunderlist*"
		"*XINGAG.XING*"


		# Apps which cannot be removed using Remove-AppxPackage
		#"*Microsoft.BioEnrollment*"
		"*Microsoft-Windows-InternetExplorer*"
		#"*Microsoft.MicrosoftEdge*"
		"*Microsoft.Windows.Cortana*"
		"*Microsoft.549981C3F5F10*"
		"*Microsoft.WindowsFeedback*"
		"*Microsoft.WindowsFeedbackHub*"
		#"*Microsoft.XboxGameCallableUI*"
		"*Microsoft.XboxIdentityProvider*"
		"*Windows.ContactSupport*"


		# Optional: Typically not removed but you can if you need to for some reason
		#"*Microsoft.Advertising.Xaml*"
		#"*Microsoft.MicrosoftStickyNotes*"
		#"*Microsoft.MSPaint*"
		#"*Microsoft.Windows.Photos*"
		#"*Microsoft.WindowsCalculator*"
		#"*Microsoft.WindowsPhone*"
		#"*Microsoft.WindowsStore*"	
	)
	
	foreach ($Bloat in $Bloatware) {
		# Get-AppxPackage -Name $Bloat| Remove-AppxPackage -ErrorAction SilentlyContinue
		Get-AppxPackage -Name $Bloat -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
		Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
		Start-Sleep 1
		Write-Output "Trying to remove $Bloat"
	}
}



Function AvoidDebloatReturn {
	
	Write-Output "Adding Registry key to prevent bloatware Apps from returning and removes some suggestions settings."
	
	$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
	If (!(Test-Path $registryPath)) { 
		New-Item $registryPath  -Force | Out-Null
	}
	Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Type DWord -Value 0x00000001  # Win11 Home NA


	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed"  -Type DWord -Value 0x00000001			# Win11 Home 1		LTSC 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled"  -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled"  -Type DWord -Value 0x00000000			# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled"  -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled"  -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 1 Automatic Installation of apps
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled"  -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 1

	# Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Type DWord -Value 0x00000000
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0x00000000	# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0x00000000	# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0x00000001	# Win11 Home 1		LTSC NA Spotlight fun tips and facts
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0x00000000	# Win11 Home NA		LTSC NA Show Suggestions Occasionally in Start
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0x00000000	# Win11 Home 1		LTSC NA Tips and Suggestions Notifications
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0x00000000	# Win11 Home NA		LTSC NA Suggest new content and apps you may find interesting
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0x00000000	# Win11 Home NA		LTSC NA Suggest new content and apps you may find interesting
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0x00000000	# Win11 Home NA		LTSC NA Suggest new content and apps you may find interesting
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0x00000000	# Win11 Home 1		LTSC NA Timeline Suggestions
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-88000326Enabled" -Type DWord -Value 0x00000001 # Win11 Home 0		LTSC NA Use Spotlight image as Desktop wallpaper
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name "BackgroundType" -Type DWord -Value 0x00000002						# Win11 Home NA	LTSC NA Use Spotlight image as Desktop wallpaper


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
		Set-ItemProperty $Holo  FirstRunSucceeded -Type DWord -Value 0x00000000		# Win11 Home 0		LTSC NA
	}
}



###				                        ###
###	Disable Unecessary Windows Services	###
###				                        ###



# Get-Service | select -property name,starttype

<#
Device Management Wireless Application Protocol (WAP) Push Message Routing Service
Useful for Windows tablet devices with mobile (3G/4G) connectivity
#>
function DisableWAPPush {

	Write-Host "Stopping and disabling WAP Push Service."
	
	#Stop-Service "dmwappushservice" -ea SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled -erroraction SilentlyContinue					# Win11 Home Manual		LTSC Manual

#This is a complementary function to the DisableStartupEventTraceSession function \ DisableDataCollection \ RemoveAutoLogger \ DisableDiagTrack.	
} 



function DisableServices {

	Write-Output "Stopping and disabling AdobeARM Service."
	#Stop-Service "AdobeARMservice" -ea SilentlyContinue
	Set-Service "AdobeARMservice" -StartupType Disabled -erroraction SilentlyContinue

	<#
	Write-Host "Disabling AMD Crash Defender Service."
	#Stop-Service "AMD Crash Defender Service" -ea SilentlyContinue
	Set-Service "AMD Crash Defender Service" -StartupType Disabled -erroraction SilentlyContinue
	#>
	

	Write-Host "Disabling Application Management."
	#Stop-Service "AppMgmt" -ea SilentlyContinue
	Set-Service "AppMgmt" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home NA			LTSC Manual


	Write-Host "Disabling Certificate Propagation Service."
	# Copies user certificates and root certificates from smart cards into the current user's certificate store.
	#Stop-Service "CertPropSvc" -ea SilentlyContinue
	Set-Service "CertPropSvc" -StartupType Disabled -erroraction SilentlyContinue						# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling ActiveX Installer."
	#Stop-Service "AxInstSV" -ea SilentlyContinue
	Set-Service "AxInstSV" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling offline files service."
	#Stop-Service "CscService" -ea SilentlyContinue
	Set-Service "CscService" -StartupType Disabled -erroraction SilentlyContinue						# Win11 Home NA			LTSC Manual

	
	Write-Host "Stopping and disabling HP ETD Telemetry Service."
	#Stop-Service "ETDservice" -ea SilentlyContinue
	Set-Service "ETDservice" -StartupType Disabled -erroraction SilentlyContinue


	Write-Host "Disabling fax."
	#Stop-Service "Fax" -ea SilentlyContinue
	Set-Service "Fax" -StartupType Disabled -erroraction SilentlyContinue								# Win11 Home NA			LTSC Manual


	Write-Host "Disabling File History Service."
	#Stop-Service "fhsvc" -ea SilentlyContinue
	Set-Service "fhsvc" -StartupType Disabled -erroraction SilentlyContinue								# Win11 Home Manual		LTSC Manual


	Write-Host "Stopping and disabling Home Groups services."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Force | Out-Null
	}
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Type DWord -Value 0x00000001					# Win11 Home NA		LTSC NA

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HomeGroup")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HomeGroup" -Force | Out-Null
	}
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA

	#Stop-Service "HomeGroupListener" -ea SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled -erroraction SilentlyContinue					# Win11 Home NA		LTSC NA
	#Stop-Service "HomeGroupProvider" -ea SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled -erroraction SilentlyContinue					# Win11 Home NA		LTSC NA


	<#
	Write-Output "Stopping and disabling HP App Helper Service."
	Stop-Service "HPAppHelperCap" -ea SilentlyContinue
	Set-Service "HPAppHelperCap" -StartupType Disabled -erroraction SilentlyContinue					# Win11 Home NA
	#>


	Write-Output "Stopping and disabling HP Diagnostics Service."
	#Stop-Service "HPDiagsCap" -ea SilentlyContinue
	Set-Service "HPDiagsCap" -StartupType Disabled -erroraction SilentlyContinue						# Win11 Home NA		LTSC Auto


	<#
	Write-Output "Stopping and disabling HP Network Service."
	Stop-Service "HPNetworkCap" -ea SilentlyContinue
	Set-Service "HPNetworkCap" -StartupType Disabled -erroraction SilentlyContinue						# Win11 Home NA
	#>


	<#
	Write-Output "Stopping and disabling HP Omen Service."
	Stop-Service "HPOmenCap" -ea SilentlyContinue
	Set-Service "HPOmenCap" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home NA
	#>


	Write-Output "Stopping and disabling HP Print Scan Doctor Service."
	#Stop-Service "HPPrintScanDoctorService" -ea SilentlyContinue
	Set-Service "HPPrintScanDoctorService" -StartupType Disabled -erroraction SilentlyContinue			# Win11 Home NA		LTSC NA


	<#
	Write-Output "Stopping and disabling HP System Info Service."
	Stop-Service "HPSysInfoCap" -ea SilentlyContinue
	Set-Service "HPSysInfoCap" -StartupType Disabled -erroraction SilentlyContinue						# Win11 Home NA
	#>


	Write-Output "Stopping and disabling HP Telemetry Service."
	#Stop-Service "HpTouchpointAnalyticsService" -ea SilentlyContinue
	Set-Service "HpTouchpointAnalyticsService" -StartupType Disabled -erroraction SilentlyContinue		# Win11 Home NA		LTSC Auto


	Write-Host "Disabling Microsoft iSCSI Initiator Service."
	#Stop-Service "MSiSCSI" -ea SilentlyContinue
	Set-Service "MSiSCSI" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Manual	LTSC Manual


	Write-Host "Disabling The Network Access Protection (NAP) agent service."
	# It collects and manages health information for client computers on a network.
	#Stop-Service "napagent" -ea SilentlyContinue
	Set-Service "napagent" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home NA		LTSC NA


	Write-Host "Disabling the Network Data Usage Monitoring Driver."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Ndu" -Name "Start" -Type DWord -Value 4		# Win11 Home 2		LTSC 2


	Write-Host "Disabling Peer Networking Identity Manager."
	#Stop-Service "p2pimsvc" -ea SilentlyContinue
	Set-Service "p2pimsvc" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling Peer Networking Grouping."	
	#Stop-Service "p2psvc" -ea SilentlyContinue
	Set-Service "p2psvc" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling BranchCache service."
	#This service caches network content from peers on the local subnet.
	#Stop-Service "PeerDistSvc" -ea SilentlyContinue
	Set-Service "PeerDistSvc" -StartupType Disabled -erroraction SilentlyContinue						# Win11 Home NA			LTSC Manual


	Write-Host "Disabling Performance Logs and Alerts Service."
	#Stop-Service "pla" -ea SilentlyContinue
	Set-Service "pla" -StartupType Disabled -erroraction SilentlyContinue								# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling Peer Name Resolution Protocol."
	#Stop-Service "PNRPsvc" -ea SilentlyContinue
	Set-Service "PNRPsvc" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling Windows Remote Registry service."
	#Stop-Service "RemoteRegistry" -ea SilentlyContinue
	Set-Service "RemoteRegistry" -StartupType Disabled -erroraction SilentlyContinue					# Win11 Home Disabled	LTSC Disabled


	<#
	The smart card removal policy service is applicable when a user has signed in with a smart card and then removes that smart card from the reader. 
	The action that is performed when the smart card is removed is controlled by Group Policy settings. 
	For more information, see Smart Card Group Policy and Registry Settings.
	#>
	Write-Host "Disabling Smart Card Removal Policy Service."
	#Stop-Service "ScPolicySvc" -ea SilentlyContinue
	Set-Service "ScPolicySvc" -StartupType Disabled -erroraction SilentlyContinue						# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling Windows Remote Registry service."
	#Stop-Service "SQLTELEMETRY$SQLEXPRESS" -ea SilentlyContinue
	Set-Service "SQLCEIP" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home NA			LTSC NA


	<#
	An SNMP trap message is an unsolicited message sent from an agent to the the manager.
	The objective of this message is to allow the remote devices to alert the manager in case an important event happens,
	commonly used in companies.
	#>
	Write-Host "Disabling Simple Network Management Protocol (SNMP) service."
	#Stop-Service "SNMPTRAP" -ea SilentlyContinue
	Set-Service "SNMPTRAP" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Manual		LTSC Manual


	<#
	The Memory Compression process is serviced by the SysMain (formerly SuperFetch) service.
	SysMain reduces disk writes (paging) by compressing and consolidating memory pages.
	If this service is stopped, then Windows does not use RAM compression.
	Write-Host "Disabling Superfetch service."
	Stop-Service "SysMain" -ea SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Auto
	#>
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "DelayedAutoStart" -Type DWord -Value 00000001	# Win11 Home 2		LTSC NA


	<#
	Disabling this will break WSL keyboard functionality.
	Write-Output "Stopping and disabling Touch Keyboard and Handwriting Panel Service."
	Stop-Service "TabletInputService" -ea SilentlyContinue
	Set-Service "TabletInputService" -StartupType Disabled -erroraction SilentlyContinue				# Win11 Home NA
	#>


	Write-Host "Disabling WebClient service."
	#Stop-Service "WebClient" -ea SilentlyContinue
	Set-Service "WebClient" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling Windows Error Reporting."
	#Stop-Service "WerSvc" -ea SilentlyContinue
	Set-Service "WerSvc" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling Windows Remote Management."
	#Stop-Service "WinRM" -ea SilentlyContinue
	Set-Service "WinRM" -StartupType Disabled -erroraction SilentlyContinue								# Win11 Home Manual		LTSC Manual


	Write-Host "Disabling Windows Insider Service."
	# Caution! Windows Insider will not work anymore.
	#Stop-Service "wisvc" -ea SilentlyContinue
	Set-Service "wisvc" -StartupType Disabled -erroraction SilentlyContinue								# Win11 Home Manual		LTSC Manual

	
	<#
	Write-Host "Stopping and disabling Windows Search Indexing service."
	#Stop-Service "WSearch" -ea SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Auto		LTSC Auto
	#>

	
	Write-Host "Stopping and disabling Diagnostic Policy service."
	#Stop-Service "DPS" -ea SilentlyContinue
	Set-Service "DPS" -StartupType Disabled -erroraction SilentlyContinue								# Win11 Home Auto		LTSC Auto


	Write-Host "Stopping and disabling Program Compatibility Assistant service."
	#Stop-Service "PcaSvc" -ea SilentlyContinue
	Set-Service "PcaSvc" -StartupType Disabled -erroraction SilentlyContinue							# Win11 Home Auto		LTSC Manual
}



###		     		    ###
###  Optional Features  ###
###		                ###



Function AllowMiracast {
	
	Write-Host "Checking if Wireless Display App is installed..."
	
	if (Test-Path $Env:windir\SystemApps\Microsoft.PPIProjection_cw5n1h2txyewy\Receiver.exe) {
		Write-Host "Wireless Display App already installed."
	}
	else {
		#See more at https://bbs.pcbeta.com/forum.php?mod=viewthread&tid=1912839
		
		Write-Host "Allowing Projection To PC."
		
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "AllowProjectionToPC" -Type DWord -Value 0x00000001		# Win11 Home NA

		if (((((Get-ComputerInfo).OSName.IndexOf("LTSC")) -ne -1) -or ((Get-ComputerInfo).OSName.IndexOf("Server") -ne -1)) -and (((Get-ComputerInfo).WindowsVersion) -ge "1809")) {
			Write-Host "Manually Installing Wireless Display App..."

			Dism /Online /Add-Package /PackagePath:"$PSScriptRoot\Miracast_LTSC\Microsoft-PPIProjection-Package-amd64-10.0.19041.1.cab" /IgnoreCheck
			Dism /Online /Add-Package /PackagePath:"$PSScriptRoot\Miracast_LTSC\Microsoft-PPIProjection-Package-amd64-10.0.19041.1~en-US~.cab" /IgnoreCheck
			Dism /Online /Add-Package /PackagePath:"$PSScriptRoot\Miracast_LTSC\Microsoft-PPIProjection-Package-amd64-10.0.19041.1~en-GB~.cab" /IgnoreCheck
			Dism /Online /Add-Package /PackagePath:"$PSScriptRoot\Miracast_LTSC\Microsoft-PPIProjection-Package-amd64-10.0.19041.1~es-ES~.cab" /IgnoreCheck
			Dism /Online /Add-Package /PackagePath:"$PSScriptRoot\Miracast_LTSC\Microsoft-PPIProjection-Package-amd64-10.0.19041.1~pt-BR~.cab" /IgnoreCheck

			Add-appxpackage -register "C:\Windows\SystemApps\Microsoft.PPIProjection_cw5n1h2txyewy\AppxManifest.xml" -disabledevelopmentmode

			Write-Host "Wireless Display App installed."
		}
		elseif (((Get-ComputerInfo).WindowsVersion) -lt "1809") {
			Write-Host "Wireless Display App is not supported on this version of Windows (Pre-1809)"
		}
		else {
			
			#Installing Wireless Display App from Windows Feature Repository
			
			Write-Host "Installing Wireless Display App..."
			
			If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUdate\AU")) {
				New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUdate\AU" -Force | Out-Null# Win11 Home NA
			}
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUdate\AU" -Name "UseWUserver" -Type DWord -Value 0x00000000		# Win11 Home NA
			Get-Service wuauserv | Restart-Service
			Start-Sleep 1
			DISM /Online /Add-Capability /CapabilityName:App.WirelessDisplay.Connect~~~~0.0.1.0
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUdate\AU" -Name "UseWUserver" -Type DWord -Value 0x00000001		# Win11 Home NA
			Get-Service wuauserv | Restart-Service
			Start-Sleep 1
			Write-Host "Wireless Display App installed."
		}
	}
}


###		              			   ###
### Performance Game / GPU Related ###
###		      			           ###



function RemoveXboxFeatures {
	
	Write-Output "Disabling Xbox features."

	# Xbox Live Auth Manager. If you don't use Xbox app to play games, then you don't need any of the Xbox services.
	Stop-Service "XblAuthManager" -ea SilentlyContinue
	Set-Service "XblAuthManager" -StartupType Disabled -ErrorAction SilentlyContinue			# Win11 Home Manual		LTSC Manual
	

	# Xbox Live Game Save Service.
	Stop-Service "XblGameSave" -ea SilentlyContinue
	Set-Service "XblGameSave" -StartupType Disabled -erroraction SilentlyContinue				# Win11 Home Manual		LTSC Manual
	

	# Xbox Live Networking Service.
	Stop-Service "XboxNetApiSvc" -ea SilentlyContinue
	Set-Service "XboxNetApiSvc" -StartupType Disabled -erroraction SilentlyContinue				# Win11 Home Manual		LTSC Manual
	

	# Xbox Game Monitoring Service.
	Stop-Service "xbgm" -ea SilentlyContinue
	Set-Service "xbgm" -StartupType Disabled -erroraction SilentlyContinue						# Win11 Home NA			LTSC NA

	
	# Xbox Accessory Management Service.
	Stop-Service "XboxGipSvc" -ea SilentlyContinue
	Set-Service "XboxGipSvc" -StartupType Disabled -erroraction SilentlyContinue
	

	# Disable GameDVR and Broadcast used for game recordings and live broadcasts.
	Stop-Service "BcastDVRUserService" -ea SilentlyContinue
	Set-Service "BcastDVRUserService" -StartupType Disabled -erroraction SilentlyContinue		# Win11 Home Manual		LTSC Manual


	Write-Output "Disabling scheduled Xbox service components."
	
	if(Get-ScheduledTask XblGameSaveTask* -ErrorAction Ignore) { Get-ScheduledTask  XblGameSaveTask* | Stop-ScheduledTask ; Get-ScheduledTask  XblGameSaveTask* | Disable-ScheduledTask } else { 'XblGameSaveTaskLogon does not exist on this device.'}		# Win11 Home Ready

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0x00000000							# Win11 Home NA		LTSC NA

	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 0x00000001										# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0x00000001										# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Type DWord -Value 0x00000000								# Win11 Home 0		LTSC NA

	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0x00000000												# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 0x00000002										# Win11 Home 2		LTSC 0

	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type DWord -Value 0x00000000				# Win11 Home 1		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Type DWord -Value 0x00000000				# Win11 Home 1		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Type DWord -Value 0x00000000				# Win11 Home 1		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "EchoCancellationEnabled" -Type DWord -Value 0x00000000			# Win11 Home 1		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "GameDVR_Enabled" -Type DWord -Value 0x00000000					# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "HistoricalCaptureEnabled" -Type DWord -Value 0x00000000			# Win11 Home 0		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "MicrophoneCaptureEnabled" -Type DWord -Value 0x00000000			# Win11 Home 1		LTSC NA

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "Value" -Type DWord -Value 0x00000000	# Win11 Home 1		LTSC 1

	# Add workaround for bug that shows "You'll need a new app to open this ms-gamingoverlay" when starting a game
    If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	If (!(Test-Path "HKCR:\ms-gamingoverlay")) {
		New-Item -Path "HKCR:\ms-gamingoverlay" -Force | Out-Null
	}
	# reg add HKEY_CLASSES_ROOT\ms-gamingoverlay /t REG_SZ /d "URL:ms-gamingoverlay" /f
	Set-ItemProperty -Path "HKCR:\ms-gamingoverlay" '(Default)' -Type String -Value "URL:ms-gamingoverlay" -Force											# Win11 Home "URL:ms-gamingoverlay"


	$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
	$acl = $key.GetAccessControl()
	$rule = New-Object System.Security.AccessControl.RegistryAccessRule (".\USERS","FullControl",@("ObjectInherit","ContainerInherit"),"None","Allow")
	$acl.SetAccessRule($rule)
	$key.SetAccessControl($acl)

	$key.Close()

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Name "ActivationType" -Type DWord -Value 0x00000000 -Force		# Win11 Home 1	LTSC 1

	Start-Sleep 1

	# It is necessary to take ownership of a registry key and change permissions to modify the key below.
	if ((Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter').ActivationType -eq 1) {
		Write-Output 'GameBar Presence Writer feature is still active.' '' 'Disable it manually, go to:' '' 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\' 'Microsoft\WindowsRuntime\ActivatableClassId\' 'Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter' '' 'in Registry Editor and change the parameter' '' 'ActivationType to 0' | msg /w *
	}

	Write-Host "Finished Removing Xbox features."
}



Function EnableGPUScheduling {
	
	Write-Host "Turn On Hardware Accelerated GPU Scheduling."

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 0x00000002							# Win11 Home NA		LTSC 2
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "PlatformSupportMiracast" -Type DWord -Value 0x00000001			# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "UnsupportedMonitorModesAllowed" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC 1
}



Function EnableVRR_AutoHDR {
	
	Write-Host "Turn On Variable Refresh Rate - Auto HDR - Optimizations for Windowed Games."
	
	If (!(Test-Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences")) {
		New-Item -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "DirectXUserGlobalSettings" -Type String -Value "VRROptimizeEnable=1;AutoHDREnable=1;SwapEffectUpgradeEnable=1;"		# Win11 Home SwapEffectUpgradeEnable=1;
	

	If (!(Test-Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings")) {
		New-Item -Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings" -Name "SwapEffectUpgradeCache" -Type DWord -Value 0x00000001		# Win11 Home NA
		
	
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Name "AllowLowResolution" -Type DWord -Value 0x00000001						# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Name "EnableOutsideModeFeature" -Type DWord -Value 0x00000001				# Win11 Home NA		LTSC NA Adjust Video Based on Lighting
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Name "EnableHDRForPlayback" -Type DWord -Value 0x00000001					# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Name "EnableAutoEnhanceDuringPlayback" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA

}



Function EnableEdge_GPU {
	
	Write-Host "Turn On Hardware Accelerated GPU on Microsoft Edge."

	<#
	If (!(Test-Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences")) {
		New-Item -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" -Type String -Value "GpuPreference=2;"		# Win11 Home NA		LTSC NA
	#>

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HardwareAccelerationModeEnabled " -Type DWord -Value 0x00000001

	<# 
	# Disable giant Bing search (AI chat) button in Edge Browser.
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HubsSidebarEnabled" -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA

	#>
}



###				  	###
###		Privacy		###
###				  	###



Function RemoveAutoLogger {
	
	Write-Host "Removing AutoLogger file and restricting directory."
	
	$autoLoggerDir = "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\Autologger"
	If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
		Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl" -Force -ErrorAction SilentlyContinue
	}
	icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

#This is a complementary function to the RemoveAutoLogger \ DisableDataCollection \ DisableDiagTrack \ DisableStartupEventTraceSession.
}

Function DisableDataCollection {
	
	Write-Output "Turning off Data Collection via the AllowTelemtry key by changing it to 0"
	
	$DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
	$DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
	$DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
	If (Test-Path $DataCollection1) {
		Set-ItemProperty $DataCollection1  AllowTelemetry -Type DWord -Value 0x00000000				# Win11 Home 1		LTSC 1
		Set-ItemProperty $DataCollection1  MaxTelemetryAllowed -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 1
	}
	If (Test-Path $DataCollection2) {
		Set-ItemProperty $DataCollection2  AllowTelemetry -Type DWord -Value 0x00000000				# Win11 Home NA		LTSC NA
	}
	If (Test-Path $DataCollection3) {
		Set-ItemProperty $DataCollection3  AllowTelemetry -Type DWord -Value 0x00000000				# Win11 Home 1		LTSC 1
		Set-ItemProperty $DataCollection3  MaxTelemetryAllowed -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 1
	}

#This is a complementary function to the RemoveAutoLogger \ DisableDataCollection \ DisableDiagTrack \ DisableStartupEventTraceSession.
}


function DisableDiagTrack {
	
	Write-Output "Stopping and disabling Connected User Experiences and Telemetry Service."
	
	#Stop-Service "DiagTrack" -ea SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled -erroraction SilentlyContinue										# Win11 Home Auto		LTSC Auto

	#Stop-Service "DcpSvc" -ea SilentlyContinue
	Set-Service "DcpSvc" -StartupType Disabled -erroraction SilentlyContinue

	#Stop-Service "diagnosticshub.standardcollector.service" -ea SilentlyContinue
	Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled -erroraction SilentlyContinue		# Win11 Home Manual		LTSC Manual

	#Stop-Service "WdiServiceHost" -ea SilentlyContinue
	Set-Service "WdiServiceHost" -StartupType Disabled -erroraction SilentlyContinue

#This is a complementary function to the RemoveAutoLogger \ DisableDataCollection \ DisableDiagTrack \ DisableStartupEventTraceSession.
}


Function DisableStartupEventTraceSession  {
	
	Write-Host "Disable All Startup Event Trace Session."
	
	<#
	Event tracing sessions record events from one or more providers that a controller enables. The session is also responsible for managing and flushing the buffers. 
	The controller defines the session, which typically includes specifying the session and log file name, type of log file to use, and the resolution of the time stamp used to record the events.
	#>

		Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger" | ForEach-Object {
			$Var = $_.PsPath
				If ((Test-Path $Var)) {
					Set-ItemProperty -Path $Var -Name "Start" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
				}
			}
	
			<#
	The operating system should not allow changes to the events below as it would cause chronic anomalies, however, we will ensure everything works as it should.
	As time passes, more trace sessions will appear active. This is normal. Do not change the behaviour of this.
	#>	

		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue	# Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue			# Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue		# Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue					# Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NetCore" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue					# Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RadioMgr" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue				# Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue		# Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue		# Win11 Home 1	LTSC 1

		# Delete all entries from Windows event logs on a computer or a server.
		Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }

		# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

		$events = @('SleepStudy','Kernel-Processor-Power','UserModePowerService')
		foreach ($event in $events) {

			wevtutil sl Microsoft-Windows-"$event"/Diagnostic /e:false
		}

#This is a complementary function to the RemoveAutoLogger \ DisableDataCollection \ DisableDiagTrack \ DisableStartupEventTraceSession.
}



Function DisableRemoteAssistance {
	
	Write-Host "Disabling Remote Assistance."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type DWord -Value 0x00000000	# Win11 Home 1		LTSC 1
}



Function DisableRDP {
	
	<#
	RDP consumes system resources, including CPU processing power, memory, and network bandwidth. 
	When RDP is enabled, the system must maintain the ability to accept remote connections and process data transmitted over that connection.
	#>

	Write-Host "Disabling Remote Desktop."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0x00000001	# Win11 Home 1		LTSC 1
	Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue														# Win11 Home NA

	Write-Host "Disabling Remote Desktop Services."
	#Stop-Service "TermService" -ea SilentlyContinue
	Set-Service "TermService" -StartupType Disabled -erroraction SilentlyContinue																# Win11 Home Manual		LTSC Manual

}



Function AcceptedPrivacyPolicy {
	
	Write-Output "Turning off AcceptedPrivacyPolicy."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0x00000000	# Win11 Home 1		LTSC 1
}



Function DisableActivityHistory {
	
	Write-Host "Disabling activity history."
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0x00000000								# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0x00000000							# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0x00000000							# Win11 Home NA		LTSC NA
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA

	Write-Host "Disable Shared Experiences."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0x00000000										# Win11 Home NA		LTSC NA
}



Function DisableAdvertisingID {
	
	Write-Host "Disabling Advertising ID."
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 0x00000001					# Win11 Home NA		LTSC NA
}



Function DisableAdvertisingInfo {
	
	Write-Output "Disabling Windows Feedback Experience program."
	
	# Microsoft assigns a unique identificator to track your activity in the Microsoft Store and on UWP apps to target you with relevant ads.
	
	$Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
	If (Test-Path $Advertising) {
		Set-ItemProperty $Advertising Enabled -Type DWord -Value 0x00000000																							# Win11 Home 0		LTSC 0
	}
}



Function DisableAppDiagnostics {
	
	Write-Output "Turning off AppDiagnostics."
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Type String -Value "Deny"	# Win11 Home Allow		LTSC Allow

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
		Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient" -Name "CEIPEnable" -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC NA
	}

	$SQMClient2 = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
	If (!(Test-Path $SQMClient2)) {
		New-Item -Path $SQMClient2 -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0x00000000												# Win11 Home NA		LTSC NA

	$SQMClient3 = "HKLM:\Software\Microsoft\SQMClient\Windows"
	If (Test-Path $SQMClient3) {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0x00000000													# Win11 Home 0		LTSC 0
	}

	$SQMClient4 = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient"
	If (Test-Path $SQMClient4) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient" -Name "CEIPEnabled" -Type DWord -Value 0x00000000				# Win11 Home 1		LTSC 1
	}


	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0x00000000														# Win11 Home NA		LTSC NA
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Type DWord -Value 0x00000000					# Win11 Home NA		LTSC NA

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Type DWord -Value 0x00000002														# Win11 Home NA		LTSC NA

}



Function DisableTelemetryTasks {
	Write-Host "Disable Telemetry Tasks."

	# This process is periodically collecting a variety of technical data about your computer and its performance and sending it to Microsoft for its Windows Customer Experience Improvement Program.

	# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide

	If (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) {
		New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Force | Out-Null
	}

	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 


	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Force | Out-Null
	}

	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 


	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Force | Out-Null
	}

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 


	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Force | Out-Null
	}

	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 

}



Function DisableErrorReporting {
	
	Write-Output "Disable Windows Error Reporting function to get better system response speed."
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0x00000001								# Win11 Home NA		LTSC NA

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0x00000001						# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Type DWord -Value 0x00000001				# Win11 Home NA		LTSC NA

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0x00000001			# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA

#This is a complementary function to the SetDoReport \ DisableErrorReporting.
}



Function SetDoReport {
	
	Write-Output "Disable Windows Error Reporting function to get better system response speed."

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Type DWord -Value 0x00000000				# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "ShowUI" -Type DWord -Value 0x00000000					# Win11 Home NA		LTSC NA


	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\PCHealth\ErrorReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\PCHealth\ErrorReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Type DWord -Value 0x00000000	# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\PCHealth\ErrorReporting" -Name "ShowUI" -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA

	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport")) { 
		New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Force | Out-Null															# Win11 Home NA	LTSC NA
	}

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -Type DWord -Value 0x00000004						# Win11 Home NA	LTSC NA

#This is a complementary function to the SetDoReport \ DisableErrorReporting.
}




Function DisableFeedbackExperience {
	
	Write-Output "Stops the Windows Feedback Experience from sending anonymous data."
	
	$Period1 = "HKCU:\Software\Microsoft\Siuf\Rules"
	$Period2 = "HKCU:\Software\Microsoft\Siuf"
	If (!(Test-Path $Period1)) { 
		If (!(Test-Path $Period2)) { 
			New-Item $Period2 -Force | Out-Null
		}
		New-Item $Period1 -Force | Out-Null
	}
	Set-ItemProperty $Period1 NumberOfSIUFInPeriod -Type DWord -Value 0x00000000						# Win11 Home NA		LTSC NA
	Set-ItemProperty $Period1 PeriodInNanoSeconds -Type DWord -Value 0x00000000							# Win11 Home NA		LTSC NA
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
}



Function DisableLocationTracking {
	
	# Disabling this will break Microsoft Find My Device functionality.
	
	Write-Output "Disabling Location Tracking."

	#Stop-Service "lfsvc" -ea SilentlyContinue
	Set-Service "lfsvc" -StartupType Disabled -erroraction SilentlyContinue					# Win11 Home Manual
	

	$SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
	$LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"

	Set-ItemProperty $SensorState SensorPermissionState -Type DWord -Value 0x00000000		# Win11 Home 1
	Set-ItemProperty $LocationConfig Status -Type DWord -Value 0x00000000					# Win11 Home 1


	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"		# Win11 Home Allow
}



Function DisableTailoredExperiences {
	
	Write-Host "Disabling Tailored Experiences AKA Spying and Diagnostic Data."
	
	# Diagnostic data for personalized tips, ads, and recommendations.

	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA

	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0x00000000	# Win11 Home 0		LTSC 0
}
																							


function BlockTelemetrybyHosts {
	
Write-Output "Windows has a lot of telemetry and spying and connects to third-party data collection sites. We will block this."

$user_home = "$Env:windir\System32\drivers\etc\hosts"
$wslconfig = @'
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
127.0.0.1     localhost
::1           localhost
127.0.0.1     data.microsoft.com
127.0.0.1     msftconnecttest.com
127.0.0.1     azureedge.net
127.0.0.1     activity.windows.com
127.0.0.1     bingapis.com
127.0.0.1     msedge.net
127.0.0.1     assets.msn.com
127.0.0.1     scorecardresearch.com
127.0.0.1     edge.microsoft.com
127.0.0.1     data.msn.com
'@
New-Item -Path $user_home -Value $wslconfig -Force | Out-Null
}



###								   ###
###  Remove Third Party Telemetry  ###
###								   ###



function DisableMozillaFirefoxTelemetry {	

	Write-Host "Disable Mozilla Firefox Telemetry."
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox")) { 
		New-Item "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"  -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type DWord -Value 0x00000001
}



function DisableGoogleChromeTelemetry {

	Write-Host "Disable Google Chrome Telemetry."

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome")) { 
		New-Item "HKLM:\SOFTWARE\Policies\Google\Chrome"  -Force | Out-Null
	}

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome")) { 
		New-Item "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome"  -Force | Out-Null
	}

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type DWord -Value 0x00000000

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "UserFeedbackAllowed" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DeviceMetricsReportingEnabled" -Type DWord -Value 0x00000000

	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome" -Name "UserFeedbackAllowed" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome" -Name "DeviceMetricsReportingEnabled" -Type DWord -Value 0x00000000

	###- Block Google Chrome Software Reporter Tool
	# The Software Reporter Tool (also known as Chrome Cleanup Tool and Software Removal Tool, the executable file is software_reporter_tool.exe), is a tool that Google distributes with the Google Chrome web browser. 
	# It is a part of Google Chrome's Clean up Computer feature which scans your computer for harmful software. If this tool finds any harmful app or extension which can cause problems, it removes them from your computer. 
	# Anything that interferes with a user's browsing experience may be removed by the tool.
	# Its disadvantages, high CPU load or privacy implications, may be reason enough to block it from running. This script will disable the software_reporter_tool.exe in a more cleaner way using Image File Execution Options Debugger value. 
	# Setting this value to an executable designed to kill processes disables it. Chrome won't re-enable it with almost each update.

	# This will disable the software_reporter_tool.exe in a more cleaner way using Image File Execution Options Debugger value. 
	# Setting this value to an executable designed to kill processes disables it. Chrome won't re-enable it with almost each update. 
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Force | Out-Null
	}

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 

}



function DisableCCleanerMonitoring {

	Write-Host "Disable CCleaner Monitoring."

	<#	Since Avast acquired Piriform, the popular system cleaning software CCleaner has become bloated with malware, bundled PUPs(potentially unwanted programs), and an alarming amount of pop-up ads.
		If you're highly dependent on CCleaner you can disable with this script the CCleaner Active Monitoring ("Active Monitoring" feature has been renamed to "Smart Cleaning"), 
		automatic Update check and download function, trial offer notifications, the new integrated Software Updater and the privacy option to "Help Improve CCleaner by sending anonymous usage data".
	#>

	If (!(Test-Path "HKCU:\Software\Piriform\CCleaner")) { 
		New-Item "HKCU:\Software\Piriform\CCleaner" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "Monitoring" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HelpImproveCCleaner" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoring" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateAuto" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateCheck" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "CheckTrialOffer" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "(Cfg)GetIpmForTrial" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdater" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdaterIpm" -Type DWord -Value 0x00000000

	if(Get-ScheduledTask 'CCleaner Update' -ErrorAction Ignore) { Get-ScheduledTask  'CCleaner Update' | Stop-ScheduledTask ; Get-ScheduledTask  'CCleaner Update' | Disable-ScheduledTask } else { 'CCleaner Update task does not exist on this device.'}
	$tempCCleaner = 'CCleanerSkipUAC - ' + $env:USERNAME
	if(Get-ScheduledTask $tempCCleaner -ErrorAction Ignore) { Get-ScheduledTask  $tempCCleaner | Stop-ScheduledTask ; Get-ScheduledTask  $tempCCleaner | Disable-ScheduledTask } else { 'CCleanerSkipUAC task does not exist on this device.'}

}



function DisableMediaPlayerTelemetry {

	Write-Host "Disable Media Player Telemetry."

	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type DWord -Value 0x00000000		# Win11 Home NA

	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer")) { 
		New-Item "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type DWord -Value 0x00000000		# Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type DWord -Value 0x00000000	# Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type DWord -Value 0x00000000		# Win11 Home NA	LTSC NA

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM")) { 
		New-Item "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 0x00000001		# Win11 Home NA	LTSC NA


	#Stop-Service "WMPNetworkSvc" -ea SilentlyContinue
	Set-Service "WMPNetworkSvc" -StartupType Disabled -erroraction SilentlyContinue												# Win11 Home Manual	LTSC Manual

}



function DisableMicrosoftOfficeTelemetry {
	
	Write-Host "Disable Microsoft Office Telemetry."

	# This will disable Microsoft Office telemetry (supports Microsoft Office 2013 and 2016)

		New-Item "HKCU:\SOFTWARE\Microsoft\Office\Common" -Force | Out-Null
		New-Item "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Force | Out-Null

		New-Item "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Force | Out-Null
		New-Item "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Force | Out-Null

		New-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Force | Out-Null
		New-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Force | Out-Null
		New-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Force | Out-Null

	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Name "QMEnable" -Type DWord -Value 0x00000000											# Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Name "Enabled" -Type DWord -Value 0x00000000									# Win11 Home NA	LTSC NA
	
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Name "QMEnable" -Type DWord -Value 0x00000000											# Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "DisableTelemetry" -Type DWord -Value 0x00000001					# Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Name "Enabled" -Type DWord -Value 0x00000000									# Win11 Home NA	LTSC NA

	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Type DWord -Value 0x00000001						# Win11 Home NA	LTSC NA

	if(Get-ScheduledTask OfficeTelemetry* -ErrorAction Ignore) { Get-ScheduledTask  OfficeTelemetry* | Stop-ScheduledTask ; Get-ScheduledTask  OfficeTelemetry* | Disable-ScheduledTask } else { 'OfficeTelemetryAgentFallBack task does not exist on this device.'} # initiates the background task for the Office Telemetry Agent that scans and uploads usage and error information for Office solutions

}



Function DisableVisualStudioTelemetry {
	
	Write-Host "Disable Visual Studio Telemetry."

	If (!(Test-Path "HKCU:\Software\Microsoft\Microsoft SQL Server\120")) {
		New-Item -Path "HKCU:\Software\Microsoft\Microsoft SQL Server\120" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Microsoft SQL Server\120" -Name "CustomerFeedback" -Type DWord -Value 0x00000000

	If (!(Test-Path "HKCU:\Software\Microsoft\VSCommon\14.0\SQM")) {
		New-Item -Path "HKCU:\Software\Microsoft\VSCommon\14.0\SQM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\VSCommon\14.0\SQM" -Name "OptIn" -Type DWord -Value 0x00000000

	If (!(Test-Path "HKCU:\Software\Microsoft\VSCommon\15.0\SQM")) {
		New-Item -Path "HKCU:\Software\Microsoft\VSCommon\15.0\SQM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Type DWord -Value 0x00000000

	If (!(Test-Path "HKCU:\Software\Microsoft\VSCommon\16.0\SQM")) {
		New-Item -Path "HKCU:\Software\Microsoft\VSCommon\16.0\SQM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\VSCommon\16.0\SQM" -Name "OptIn" -Type DWord -Value 0x00000000

	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM")) {
		New-Item -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Name "OptIn" -Type DWord -Value 0x00000000

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableFeedbackDialog" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableEmailInput" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableScreenshotCapture" -Type DWord -Value 0x00000001

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Setup")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Setup" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Setup" -Name "ConcurrentDownloads" -Type DWord -Value 0x00000002

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\VisualStudio\Feedback")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\VisualStudio\Feedback" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableFeedbackDialog" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableEmailInput" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableScreenshotCapture" -Type DWord -Value 0x00000001

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\VisualStudio\Setup")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\VisualStudio\Setup" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\VisualStudio\Setup" -Name "ConcurrentDownloads" -Type DWord -Value 0x00000002


	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\Telemetry")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\Telemetry" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\Telemetry" -Name "TurnOffSwitch" -Type DWord -Value 0x00000001

}



function DisableNvidiaDriverTelemetry {

	Write-Host "Disable Nvidia Driver Telemetry."

	If (!(Test-Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client")) { 
		New-Item "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Force | Out-Null															# Win11 Home NA	LTSC NA
	}

	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup")) { 
		New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Force | Out-Null													# Win11 Home NA	LTSC NA
	}
	
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer")) { 
		New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" -Force | Out-Null														# Win11 Home NA	LTSC NA
	}

	Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Name "OptInOrOutPreference" -Type DWord -Value 0x00000000		# Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Name "SendTelemetryData" -Type DWord -Value 0x00000000	# Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" -Name "Start" -Type DWord -Value 0x00000004					# Win11 Home NA	LTSC NA

}



###		   ###
###	System ###
###        ###



Function RemoveScheduledTasks {
	
	Write-Output "`n"
	Write-Output "`nDisabling scheduled tasks that are considered unnecessary."
	Write-Output "...If nothing happens within 30 seconds, please close this window and run the script again.`n"
	Write-Output "`n"


	# See more at http://wiki.webperfect.ch/index.php?title=Windows_Telemetry



	Write-Output "Disabling scheduled group telemetry."

	if(Get-ScheduledTask Consolidator -ErrorAction Ignore) { Get-ScheduledTask  Consolidator | Stop-ScheduledTask ; Get-ScheduledTask  Consolidator | Disable-ScheduledTask } else { 'Consolidator task does not exist on this device.'}		# Win11 Home Ready		collects and sends usage data to Microsoft (if the user has consented to participate in the CEIP)
	if(Get-ScheduledTask KernelCeipTask -ErrorAction Ignore) { Get-ScheduledTask  KernelCeipTask | Stop-ScheduledTask ; Get-ScheduledTask  KernelCeipTask | Disable-ScheduledTask } else { 'KernelCeipTask does not exist on this device.'}		# Win11 Home NA		collects additional information related to customer experience and sends it to Microsoft (if the user consented to participate in the Windows CEIP)
	if(Get-ScheduledTask UsbCeip -ErrorAction Ignore) { Get-ScheduledTask  UsbCeip | Stop-ScheduledTask ; Get-ScheduledTask  UsbCeip | Disable-ScheduledTask } else { 'UsbCeip task does not exist on this device.'}							# Win11 Home Ready
	if(Get-ScheduledTask BthSQM -ErrorAction Ignore) { Get-ScheduledTask  BthSQM | Stop-ScheduledTask ; Get-ScheduledTask  BthSQM | Disable-ScheduledTask } else { 'BthSQM task does not exist on this device.'}								# Win11 Home NA		collects Bluetooth-related statistics and information about your machine and sends it to Microsoft (if you have consented to participate in the Windows CEIP). The information received is used to help.


	Write-Output "Disabling collects data for Microsoft SmartScreen."
	if(Get-ScheduledTask SmartScreenSpecific -ErrorAction Ignore) { Get-ScheduledTask  SmartScreenSpecific | Stop-ScheduledTask ; Get-ScheduledTask  SmartScreenSpecific | Disable-ScheduledTask } else { 'SmartScreenSpecific task does not exist on this device.'}	# Win11 Home NA


	Write-Output "Disabling scheduled customer experience improvement program."
	if(Get-ScheduledTask Proxy -ErrorAction Ignore) { Get-ScheduledTask  Proxy | Stop-ScheduledTask ; Get-ScheduledTask  Proxy | Disable-ScheduledTask } else { 'Proxy task does not exist on this device.'}														# Win11 Home Ready		collects and uploads Software Quality Management (SQM) data if opted-in to the CEIP
	if(Get-ScheduledTask ProgramDataUpdater -ErrorAction Ignore) { Get-ScheduledTask  ProgramDataUpdater | Stop-ScheduledTask ; Get-ScheduledTask  ProgramDataUpdater | Disable-ScheduledTask } else { 'ProgramDataUpdater task does not exist on this device.'}	# Win11 Home NA		collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program (CEIP)

	if(Get-ScheduledTask 'Microsoft Compatibility Appraiser' -ErrorAction Ignore) { Get-ScheduledTask  'Microsoft Compatibility Appraiser' | Stop-ScheduledTask ; Get-ScheduledTask  'Microsoft Compatibility Appraiser' | Disable-ScheduledTask } else { 'Microsoft Compatibility Appraiser task does not exist on this device.'}	# Win11 Home Ready		collects program telemetry information if opted-in to the CEIP
	if(Get-ScheduledTask MareBackup -ErrorAction Ignore) { Get-ScheduledTask  MareBackup | Stop-ScheduledTask ; Get-ScheduledTask  MareBackup | Disable-ScheduledTask } else { 'MareBackup task does not exist on this device.'}
	if(Get-ScheduledTask PcaPatchDbTask -ErrorAction Ignore) { Get-ScheduledTask  PcaPatchDbTask | Stop-ScheduledTask ; Get-ScheduledTask  PcaPatchDbTask | Disable-ScheduledTask } else { 'PcaPatchDbTask task does not exist on this device.'}
	if(Get-ScheduledTask SdbinstMergeDbTask -ErrorAction Ignore) { Get-ScheduledTask  SdbinstMergeDbTask | Stop-ScheduledTask ; Get-ScheduledTask  SdbinstMergeDbTask | Disable-ScheduledTask } else { 'SdbinstMergeDbTask task does not exist on this device.'}
	if(Get-ScheduledTask StartupAppTask -ErrorAction Ignore) { Get-ScheduledTask  StartupAppTask | Stop-ScheduledTask ; Get-ScheduledTask  StartupAppTask | Disable-ScheduledTask } else { 'StartupAppTask does not exist on this device.'}							# Win11 Home Ready
	
	if(Get-ScheduledTask Uploader -ErrorAction Ignore) { Get-ScheduledTask  Uploader | Stop-ScheduledTask ; Get-ScheduledTask  Uploader | Disable-ScheduledTask } else { 'Uploader task does not exist on this device.'}											# Win11 Home NA


	Write-Output "Disabling scheduled feedback."
	if(Get-ScheduledTask DmClient -ErrorAction Ignore) { Get-ScheduledTask  DmClient | Stop-ScheduledTask ; Get-ScheduledTask  DmClient | Disable-ScheduledTask } else { 'DmClient task does not exist on this device.'}						# Win11 Home Ready
	if(Get-ScheduledTask DmClientOnScenarioDownload -ErrorAction Ignore) { Get-ScheduledTask  DmClientOnScenarioDownload | Stop-ScheduledTask ; Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask } else { 'DmClientOnScenarioDownload task does not exist on this device.'}	# Win11 Home Ready


	Write-Output "Disabling scheduled windows system assessment tool."
	if(Get-ScheduledTask WinSAT -ErrorAction Ignore) { Get-ScheduledTask  WinSAT | Stop-ScheduledTask ; Get-ScheduledTask  WinSAT | Disable-ScheduledTask } else { 'WinSAT task does not exist on this device.'}								# Win11 Home Ready		measures system performance and capabilities


	Write-Output "Disabling scheduled family safety settings."
	if(Get-ScheduledTask FamilySafetyMonitor -ErrorAction Ignore) { Get-ScheduledTask  FamilySafetyMonitor | Stop-ScheduledTask ; Get-ScheduledTask  FamilySafetyMonitor | Disable-ScheduledTask } else { 'FamilySafetyMonitor task does not exist on this device.'}	# Win11 Home Ready		initializes family safety monitoring and enforcement
	if(Get-ScheduledTask FamilySafetyRefresh* -ErrorAction Ignore) { Get-ScheduledTask  FamilySafetyRefresh* | Stop-ScheduledTask ; Get-ScheduledTask  FamilySafetyRefresh* | Disable-ScheduledTask } else { 'FamilySafetyRefresh task does not exist on this device.'}	# Win11 Home Ready		synchronizes the latest settings with the family safety website


	Write-Output "Disabling scheduled collects network information."
	if(Get-ScheduledTask GatherNetworkInfo -ErrorAction Ignore) { Get-ScheduledTask  GatherNetworkInfo | Stop-ScheduledTask ; Get-ScheduledTask  GatherNetworkInfo | Disable-ScheduledTask } else { 'GatherNetworkInfo task does not exist on this device.'}			# Win11 Home Ready		collects network information

	
	Write-Output "Disabling scheduled legacy tasks."
	if(Get-ScheduledTask AitAgent -ErrorAction Ignore) { Get-ScheduledTask  AitAgent | Stop-ScheduledTask ; Get-ScheduledTask  AitAgent | Disable-ScheduledTask } else { 'AitAgent task does not exist on this device.'}															# Win11 Home NA	aggregates and uploads application telemetry information if opted-in to the CEIP
	if(Get-ScheduledTask ScheduledDefrag -ErrorAction Ignore) { Get-ScheduledTask  ScheduledDefrag | Stop-ScheduledTask ; Get-ScheduledTask  ScheduledDefrag | Disable-ScheduledTask } else { 'ScheduledDefrag task does not exist on this device.'}								# Win11 Home Ready
	if(Get-ScheduledTask 'SQM data sender' -ErrorAction Ignore) { Get-ScheduledTask  'SQM data sender' | Stop-ScheduledTask ; Get-ScheduledTask  'SQM data sender' | Disable-ScheduledTask } else { 'SQM Data Sender task does not exist on this device.'}							# Win11 Home NA	sends SQM data to Microsoft
	if(Get-ScheduledTask *DiskDiagnostic* -ErrorAction Ignore) { Get-ScheduledTask  *DiskDiagnostic* | Stop-ScheduledTask ; Get-ScheduledTask  *DiskDiagnostic* | Disable-ScheduledTask } else { 'DiskDiagnosticResolver task does not exist on this device.'}	# Win11 Home Ready	collects general disk and system information and sends it to Microsoft (if the user users participates in the CEIP)


	Write-Output "Disabling scheduled error reporting."
	if(Get-ScheduledTask QueueReporting -ErrorAction Ignore) { Get-ScheduledTask  QueueReporting | Stop-ScheduledTask ; Get-ScheduledTask  QueueReporting | Disable-ScheduledTask } else { 'QueueReporting task does not exist on this device.'}									# Win11 Home Ready

	Write-Output "Disabling scheduled Power Efficiency Diagnostics."
	if(Get-ScheduledTask AnalyzeSystem -ErrorAction Ignore) { Get-ScheduledTask  AnalyzeSystem | Stop-ScheduledTask ; Get-ScheduledTask  AnalyzeSystem | Disable-ScheduledTask } else { 'AnalyzeSystem task does not exist on this device.'}										# Win11 Home Ready


	Write-Output "Disabling scheduled tasks From Third-Party Apps."
	if(Get-ScheduledTask 'Adobe Acrobat Update Task' -ErrorAction Ignore) { Get-ScheduledTask  'Adobe Acrobat Update Task' | Stop-ScheduledTask ; Get-ScheduledTask  'Adobe Acrobat Update Task' | Disable-ScheduledTask } else { 'Adobe Acrobat Update Task does not exist on this device.'}

	if(Get-ScheduledTask AMDInstallLauncher -ErrorAction Ignore) { Get-ScheduledTask  AMDInstallLauncher| Stop-ScheduledTask ; Get-ScheduledTask  AMDInstallLauncher | Disable-ScheduledTask } else { 'AMDInstallLauncher does not exist on this device.'}
	if(Get-ScheduledTask AMDRyzenMasterSDKTask -ErrorAction Ignore) { Get-ScheduledTask  AMDRyzenMasterSDKTask | Stop-ScheduledTask ; Get-ScheduledTask  AMDRyzenMasterSDKTask | Disable-ScheduledTask } else { 'AMDRyzenMasterSDKTask does not exist on this device.'}
	if(Get-ScheduledTask AMDScoSupportTypeUpdate -ErrorAction Ignore) { Get-ScheduledTask  AMDScoSupportTypeUpdate | Stop-ScheduledTask ; Get-ScheduledTask  AMDScoSupportTypeUpdate | Disable-ScheduledTask } else { 'AMDScoSupportTypeUpdate does not exist on this device.'}
	if(Get-ScheduledTask StartCN -ErrorAction Ignore) { Get-ScheduledTask  StartCN | Stop-ScheduledTask ; Get-ScheduledTask  StartCN | Disable-ScheduledTask } else { 'StartCN does not exist on this device.'}

	if(Get-ScheduledTask SystemOptimizer -ErrorAction Ignore) { Get-ScheduledTask  SystemOptimizer | Stop-ScheduledTask ; Get-ScheduledTask  SystemOptimizer | Disable-ScheduledTask } else { 'HP SystemOptimizer task does not exist on this device.'}
	if(Get-ScheduledTask 'Printer Health Monitor' -ErrorAction Ignore) { Get-ScheduledTask  'Printer Health Monitor' | Stop-ScheduledTask ; Get-ScheduledTask  'Printer Health Monitor' | Disable-ScheduledTask } else { 'HP Printer Health Monitor task does not exist on this device.'} # sends SQM data to Microsoft
	if(Get-ScheduledTask 'Printer Health Monitor Logon' -ErrorAction Ignore) { Get-ScheduledTask  'Printer Health Monitor Logon' | Stop-ScheduledTask ; Get-ScheduledTask  'Printer Health Monitor Logon' | Disable-ScheduledTask } else { 'HP Printer Health Monitor Logon task does not exist on this device.'} # sends SQM data to Microsoft

	if(Get-ScheduledTask Duet* -ErrorAction Ignore) { Get-ScheduledTask  Duet* | Stop-ScheduledTask ; Get-ScheduledTask  Duet* | Disable-ScheduledTask } else { 'Duet Updater task does not exist on this device.'}
}



Function DisableAppCompat {
	
	Write-Host "Disabling Application Compatibility Program."

	# See more at https://admx.help/?Category=Windows_11_2022

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
	}

	Write-Host "Prevent access to 16-bit applications."

	# You can use this setting to turn off the MS-DOS subsystem, which will reduce resource usage and prevent users from running 16-bit applications.
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatPrevent16BitMach
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "VDMDisallowed" -Type DWord -Value 0x00000001	# Win11 Home NA	LTSC NA


	Write-Host "Turn off Application Compatibility Engine."
	
	<#
	Turning off the application compatibility engine will boost system performance.
	However, this will degrade the compatibility of many popular legacy applications,
	and will not block known incompatible applications from installing.
	(For Instance: This may result in a blue screen if an old anti-virus application is installed.)
	#>

	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffEngine
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableEngine" -Type DWord -Value 0x00000001	# Win11 Home NA	LTSC NA


	Write-Host "Turn off Application Telemetry."

	# If the customer Experience Improvement program is turned off, Application Telemetry will be turned off regardless of how this policy is set.
	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffApplicationImpactTelemetry
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0x00000000		# Win11 Home NA	LTSC NA


	Write-Host "Turn off Inventory Collector."
	
	<#
	The Inventory Collector inventories applications, files, devices, and drivers on the system and sends the information to Microsoft.
	This information is used to help diagnose compatibility problems.
	#>

	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffProgramInventory
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 0x00000001	# Win11 Home NA	LTSC NA


	Write-Host "Turn off Program Compatibility Assistant."
	
	<#
	If you enable this policy setting, the PCA will be turned off.
	The user will not be presented with solutions to known compatibility issues when running applications.
	Turning off the PCA can be useful for system administrators who require better performance and are already aware of application compatibility issues.
	#>

	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffProgramCompatibilityAssistant_2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Type DWord -Value 0x00000001		# Win11 Home NA	LTSC NA


	Write-Host "Turn off Steps Recorder."
	
	<#
	Steps Recorder keeps a record of steps taken by the user.
	The data generated by Steps Recorder can be used in feedback systems such as Windows Error Reporting
	to help developers understand and fix problems. The data includes user actions such as keyboard input and mouse input,
	user interface data, and screen shots. Steps Recorder includes an option to turn on and off data collection.
	#>

	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffUserActionRecord
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type DWord -Value 0x00000001		# Win11 Home NA	LTSC NA


	Write-Host "Turn off SwitchBack Compatibility Engine."
	
	<#
	If you enable this policy setting, Switchback will be turned off.
	Turning Switchback off may degrade the compatibility of older applications.
	This option is useful for server administrators who require performance and are aware of compatibility of the applications they are using.
	#>

	# See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffSwitchBack
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "SbEnable" -Type DWord -Value 0x00000000			# Win11 Home NA	LTSC NA
}



#The AutoplayHandler element specifies a UWP device app that should appear as the recommended AutoPlay action when a user plugs in a device.
Function DisableAutoplayHandler {
	
	Write-Output "Disabling AutoplayHandlers."
	
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0x00000001	# Win11 Home 0		LTSC 1
}



Function DisableBingSearch {
	
	Write-Output "Disabling Bing Search in Start Menu."
	
	$WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	
	If (!(Test-Path $WebSearch)) {
		New-Item $WebSearch -Force | Out-Null
	}
	Set-ItemProperty $WebSearch DisableWebSearch -Type DWord -Value 0x00000001																	# Win11 Home NA		LTSC NA

	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA

	$DisableSearchBox = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
	
	If (!(Test-Path $DisableSearchBox)) {
		New-Item $DisableSearchBox -Force | Out-Null
	}
	Set-ItemProperty $DisableSearchBox DisableSearchBoxSuggestions -Type DWord -Value 0x00000001												# Win11 Home NA		LTSC NA
}



Function DisableCortanaSearch {
	
	Write-Output "Stopping Cortana from being used as part of your Windows Search Function."

	# Cortana was deprecated in June 2023.
	
	$Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	If (!(Test-Path $Search)) {
		New-Item $Search -Force | Out-Null
	}
	Set-ItemProperty $Search AllowCortana -Type DWord -Value 0x00000000																			# Win11 Home NA		LTSC NA

}



Function PrintScreenToSnippingTool {
	
	Write-Output "Use print screen to open snipping tool."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
}



Function DisableLiveTiles {
	
	Write-Output "Disabling live tiles."
	
	$Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
	If (!(Test-Path $Live)) {  
		New-Item $Live -Force | Out-Null
	}
	Set-ItemProperty $Live  NoTileApplicationNotification -Type DWord -Value 0x00000001													# Win11 Home NA		LTSC NA
}



Function DisableWidgets {
	
	Write-Output "Disable and uninstall Widgets. The Widgets app runs in the background even with the option turned off."
	
	Write-Host "Checking if Widgets is installed..."
	if (Test-Path $Env:windir\SystemApps\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy) {
		winget uninstall "windows web experience pack" --silent		
	}
	else {
		Write-Host "Widgets do not exist on this device."

	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0x00000000	# Win11 Home 0		LTSC NA
}



function DisableBackgroundApp {
	
	# Leaving Xiaomi Mi Blaze Unlock 'on' (8497DDF3*) you can continue using your band to unlock your computer.

	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. -> Disabling All Background Application Access."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 0x00000001	# Win11 Home NA	LTSC NA
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -Type DWord -Value 0x00000000					# Win11 Home NA	LTSC NA
		
	}

	<#
	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. -> Disabling All Background Application Access."
		[string[]]$Excludes = @("8497DDF3*", "Microsoft.Windows.Cortana*")
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude $Excludes | ForEach-Object {
			Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue
			Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue
		}
	}
	#>

	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Windows 11 Detected. -> Reverting all background app access to default. Windows 11 does a better job of this."
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
			Remove-ItemProperty -Path $_.PsPath -Name "Disabled" -Force -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Force -ErrorAction SilentlyContinue
		}
	}
}



Function RemoveCloudStore {
	
	Write-Output "Removing deprecated TileDataLayer from registry if it exists."
	
	# See more at https://4sysops.com/archives/roaming-profiles-and-start-tiles-tiledatalayer-in-the-windows-10-1703-creators-update
	
	$CloudStore = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore" # Win11 Home (Folder Exist)
	#$p = Get-Process -Name "explorer"
	If (Test-Path $CloudStore) {
		# Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
		# Get-Process | Where-Object {$_.HasExited}
		Remove-Item $CloudStore -Force -Recurse -ErrorAction SilentlyContinue
		# Start-Process Explorer.exe -Wait
	}
}



Function SetAeDebug {
	
	Write-Output "Turn off Just-In-Time Debugging function to improve system performance (Dr. Watson)."

	# https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/disable-enable-dr-watson-program
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name "Auto" -Type String -Value "0"					# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name "Auto" -Type String -Value "0"		# Win11 Home NA		LTSC NA
}



Function SetSplitThreshold {
	
	$InstalledMemory = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory
	$MemoryKB = [math]::Round($InstalledMemory / 1KB, 2)
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $MemoryKB	# Win11 Home 0x00380000 (3670016)		LTSC 0x00380000 (3670016)
	Write-Output "Setting SvcHostSplitThresholdInKB to $MemoryKB"
}



function SetPagedPoolMemoryUsage {
	
	<#
		Configures the internal cache levels of NTFS paged-pool memory and NTFS nonpaged-pool memory.
		https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
	#>


	$InstalledMemory = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory
	$MemoryGB = [math]::Round($InstalledMemory / 1GB, 2)
	if ($MemoryGB -gt 8) {

		# fsutil behavior query memoryusage
		fsutil behavior set memoryusage 2 	# Win11 Home 1 	LTSC 1 (The default memory consumption values are used for caching NTFS metadata)
		
		Write-Output "Use big system memory caching to improve microstuttering."
	
		# Yeah, that might sound the opposite of the project's objective, but that's right. Free up and optimize resources to the maximum and provide comfort for the system kernel simultaneously.
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 0x00000001	# Win11 Home 0	LTSC 0
		
	} else {
    	Write-Host "The computer does not have more than 8 GB of RAM. This function will have the opposite effect in terms of performance gains on systems with low memory."
		fsutil behavior set memoryusage 1 	# Win11 Home 1 	LTSC 1 (The default memory consumption values are used for caching NTFS metadata)

		# https://answers.microsoft.com/en-us/windows/forum/all/run-out-of-memory-error/fefe0bf0-9a40-42cf-b533-f419791ad338

		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems" -Name "Windows" -Type ExpandString -Value "%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,1024 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16"
		# Win11 Home	%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
		# LTSC			%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16

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
	Enable-MMAgent -mc -ErrorAction SilentlyContinue	# Win11 Home Enabled
	
	#Get-MMAgent
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
			Set-ItemProperty -Path $Var -Name "Disable Performance Counters" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue		# Default (Everything Enabled)
		}
	}
}



Function SetSystemResponsiveness {

	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" -Name "GPU Priority" -Type DWord -Value 0x00000008
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" -Name "Priority" -Type DWord -Value 0x00000008
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" -Name "Scheduling Category" -Type String -Value "High"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" -Name "SFIO Priority" -Type String -Value "High"


	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 0x00000008
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 0x00000008
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value "High"

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Type DWord -Value 0x00000000


	# Disable Camera Frame Server. It controls whether multiple applications can access the camera feed simultaneously.
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Media Foundation\Platform" -Name "EnableFrameServerMode" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Media Foundation\Platform" -Name "EnableFrameServerMode" -Type DWord -Value 0x00000000

	# https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service
	
	# SystemResponsiveness determines the percentage of CPU resources that should be guaranteed to low-priority tasks (MMCSS).
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0x0000000a			# Win11 Home 0x00000014 (20)	LTSC 0x00000014 (20)
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NoLazyMode" -Type DWord -Value 0x00000001					# Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Type DWord -Value 0x00000001						# Win11 Home NA	LTSC NA


#This is a complementary function to the SetSystemResponsiveness \ SomeKernelTweaks.
}



Function SomeKernelTweaks {

	Write-Output "Disable Meltdown/Spectre/Zombieload patches."
	
	# https://support.microsoft.com/en-us/topic/kb4072698-windows-server-and-azure-stack-hci-guidance-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-2f965763-00e2-8f98-b632-0d96f30c8c8e
	# https://support.microsoft.com/en-us/topic/guidance-for-disabling-intel-transactional-synchronization-extensions-intel-tsx-capability-0e3a560c-ab73-11d2-12a6-ed316377c99c


	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Type DWord -Value 0x00000003			# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Type DWord -Value 0x00000003		# Win11 Home NA		LTSC NA

	# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableTsx" -Type DWord -Value 0x00000000								# Win11 Home NA

	Write-Output "Disable 57-bits 5-level paging."
	bcdedit /set linearaddress57 OptOut | Out-Null
	# https://community.amd.com/t5/archives-discussions/5-level-paging-and-57-bit-linear-address-stop-that-stupid/td-p/80014
	# In short, if you use a cluster of 16 Hard Disks with 16 TBytes each (>256 TBytes) in your work, revert this option!  bcdedit /deletevalue linearaddress57 | Out-Null


	
	Write-Output "Disable automatic TCG/Opal disk locking on supported SSD drives with PSID."
	
	#reg add HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices /v TCGSecurityActivationDisabled /t REG_DWORD /d 1 /f
	
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "TCGSecurityActivationDisabled" -Type DWord -Value 0x00000001			# Win11 Home 0		LTSC 0
	
	# Set this value to 1 to enable stronger protection on system base objects such as the KnownDLLs list.
	
	# https://learn.microsoft.com/en-US/troubleshoot/windows-client/networking/system-error-85-net-use-command
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Type DWord -Value 0x00000000									# Win11 Home 1		LTSC 1


	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Build greater than 22000 detected. Fixed requesting a higher resolution timer from Jurassic Period apps."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -Type DWord -Value 0x00000001				# Win11 NA		LTSC NA
	} 

	# https://github.com/amitxv/PC-Tuning/blob/main/docs/research.md#fixing-timing-precision-in-windows-after-the-great-rule-change

#This is a complementary function to the SetSystemResponsiveness \ SomeKernelTweaks.
}



Function MisconceptionHPET {
	
	Write-Output "Reverting misconception about HPET-TSC-PMT to system default values."
	
	<#
	"Unless you need to run a very very certain and specific program that requires HPET, useplatformclock + HPET is not suggested.
	HPET should only used as a platform source for synchronization purposes or different purposes when actually required.
	While TSC runs at an average frequency of 3 MHz, depending on your processor characteristics, HPET is a high precision timer, and can run at up to 22 MHz on modern computers!
	This makes your computer perform poorly due to using HPET when not needed.
	Such a level of precision is not required on every single application and will slowdown your computer's performance."
	
	https://sites.google.com/view/melodystweaks/misconceptions-about-timers-hpet-tsc-pmt
	https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
	#>

	# Reverting this misconception about HPET-TSC-PMT to system default values as below.
	bcdedit /deletevalue useplatformclock | Out-Null
	bcdedit /deletevalue useplatformtick | Out-Null
	bcdedit /deletevalue disabledynamictick | Out-Null
	bcdedit /deletevalue tscsyncpolicy | Out-Null
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

	powercfg -h off		# Win11 Home On

	Write-Output "Disabling Fast Startup."

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0x00000000 # Win11 Home 1		LTSC 1


	# Force enable "traditional" power plans
	#reg add HKLM\System\CurrentControlSet\Control\Power /v PlatformAoAcOverride /t REG_DWORD /d 0
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Power" -Name "PlatformAoAcOverride" -Type DWord -Value 0x00000000 			# Win11 Home NA		LTSC NA


	# Balanced Performance
	# ActivePowerScheme is the GUID (Globally Unique Identifier) of the current active power plan for your account.
	powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e	# Win11 Home Enabled


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
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" -Name "Attributes" -Type DWord -Value 0x00000002	# Win11 Home 1


	#IF (Get-WmiObject -Class Win32_Processor | where {( $_.Manufacturer -like "*AMD*" ) -or ($_.Manufacturer -like "*Intel*")})

	IF (Get-ComputerInfo | where {( $_.PowerPlatformRole -like "*mobile*" )}) {
		
		Write-Host "Mobile platform detected. Disabling Performance Boost on Battery for less heat output and more sustainable performance over time providing full power to iGPU and dGPU."
		
		<#
		Load balancing should be automatic as both Intel and AMD have features for this and it usually works very well,
		but if your laptop/notebook/ultrabook makes more noise than an airplane's engines,
		you will be rewarded with performance slightly smaller on some tasks and better on some games and there will be an awkward silence.
		It will be another computer!
		#>

		IF (Get-WmiObject -Class Win32_Processor | where {( $_.Manufacturer -like "*AMD*" )}) {
			Write-Host "AMD CPU Detected. Changing Performance Boost to Aggressive." # AMD CPUs with BOOST parameter other than "2" (Aggressive) usually disable Performance Boost completely. 
			Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2	# Win11 Home 2 (Aggressive)
			Powercfg -setdcvalueindex scheme_current sub_processor PERFBOOSTMODE 0	# Win11 Home 2 (Aggressive)
		}

		IF (Get-WmiObject -Class Win32_Processor | where {($_.Manufacturer -like "*Intel*")}) {
			Write-Host "Intel CPU Detected. Changing Performance Boost to Efficient Aggressive At Guaranteed." # Intel CPUs generally run very well with BOOST 6
			Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2	# Win11 Home 2 (Aggressive)
			Powercfg -setdcvalueindex scheme_current sub_processor PERFBOOSTMODE 0	# Win11 Home 2 (Aggressive)
		}
	}
	else {
		Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2		# Default 2 (Aggressive)
		Powercfg -setdcvalueindex scheme_current sub_processor PERFBOOSTMODE 2		# Default 2 (Aggressive)
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


	# USB 3 Link Power Management
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 3

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
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 2 # Maximize performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 1 # Optimize power savings
	

	# AMD Power Slider
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 3 # Best performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 0 # Battery saver


	# Intel(R) Graphics Power Plan 
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 2 # Maximum Performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 0 # Maximum Battery Life


	# Intel(R) Dynamic Tuning Settings
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 48df9d60-4f68-11dc-8314-0800200c9a66 07029cd8-4664-4698-95d8-43b2e9666596 0 # 25.0W @ 2.1GHz (Max Value)
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 48df9d60-4f68-11dc-8314-0800200c9a66 07029cd8-4664-4698-95d8-43b2e9666596 2 # 10.0W @ 0.8GHz (Min Value)


	# Hidden New CPU Optimizations
	# Determines whether desired performance requests should be provided to the platform
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFAUTONOMOUS 1 # Default 1
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFAUTONOMOUS 1 # Default 1	


	# Core Parking allows your processors to go into a sleep mode. The main purposes of core parking is to allow the computer/laptop/device to only use the processors when required, thus saving on energy.
	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100 # Default 100
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 10 # Default 10
	
	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES 100 # Default 100
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES 100 # Default 100

	# Processor performance core parking utility distribution
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL 0 # High performance
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL 0 # High performance

	# Processor energy performance preference policy(Percent). Specify how much processors should favor energy savings over performance when operating in autonomous mode.
	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\36687f9e-e3a5-4dbf-b1dc-15eb381c6863" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFEPP 0 # Default 50 
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFEPP 50 # Default 25

	# The Processor Performance Boost Policy is a percentage value from 0 to 100(hexa:00000064). In the default Balanced power plan this parameter is 35 percent and any value lower than 51 disables Turbo Boost.
	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL 100 # Default 60
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL 100 # Default 40


	# Processor performance time check interval
	powercfg -attributes 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 -ATTRIB_HIDE
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 5000 # 15
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 5000 # 30

	
	Powercfg -setactive scheme_current


	<#
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR CPMINCORES
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR PERFEPP
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE
	powercfg /qh SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL
	powercfg /qh SCHEME_CURRENT SUB_SLEEP STANDBYIDLE

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



###					###
###		Security	###
###					###



function DisableVBS_HVCI {
	
	<#
	Not recommended if you use it as a server in production. It can reduce your computer security capabilities.
	See more at https://www.tomshardware.com/how-to/disable-vbs-windows-11
	#>

	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. Turn off Virtualization-based security."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0x00000000							# LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "HVCIMATRequired" -Type DWord -Value 0x00000000											# LTSC NA

		If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
			New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 0x00000000		# LTSC NA
	}

	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Windows 11 Detected. Turn off Virtualization-based security."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0x00000000							# Win11 Home NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "HVCIMATRequired" -Type DWord -Value 0x00000000											# Win11 Home NA
		
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
			New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 0x00000000		# Win11 Home NA
	}
}



function TurnWSLlight {
	
Write-Output "WSL Performance Tweaks."

$user_home = "$env:USERPROFILE\.wslconfig"
$wslconfig = @'
[wsl2]
kernelCommandLine=noibrs noibpb nopti nospectre_v1 nospectre_v2 nospec_store_bypass_disable no_stf_barrier spectre_v2_user=noibrs noibpb nopti nospectre_v1 nospectre_v2 nospec_store_bypass_disable no_stf_barrier spectre_v2_user=off spec_store_bypass_disable=off l1tf=off mitigations=off mds=off tsx_async_abort=off  spectre_v2=off kvm.nx_huge_pages=off kvm-intel.vmentry_l1d_flush=never ssbd=force-off tsx=on
'@
New-Item -Path $user_home -Value $wslconfig -Force | Out-Null
}



function DisableWindowsDefender {
	

<#
	The author explains that he disabled only the features related to Real-Time Protection, Cloud-Delivered Protection, Automatic Sample Submission, Control Flow Guard (CFG), 
	 and Core Isolation (for WSL) because they directly impact system performance.

	It is essential to clarify that the Windows operating system needs some level of protection, and the author of this project does not believe that removing all of these features
	 is the best solution. Leaving the system as the project proposes would be insane, as even opening a harmless Nuget plugin could lead to an invasion (init.ps1).

	Features such as Quick Scan (Windows Malicious Software Removal Tool), Virus and Threat Protection Updates, Account Protection, Firewall and Network Protection, Reputation-Based Protection,
	 Exploit Protection (DEP/ASLR/SEHOP/KASAN), and Parental Controls have not been changed.
#>


	<#
	Write-Output "`nTrying to disable Windows Defender. First, you need to manually modify it by going to the:"
	Write-Output "`nSettings -> Privacy & Security -> Windows Security -> Virus & threat protection -> Manage settings -> Tamper Protection -> Off"

	Write-Output "`nAfter manual modification, press any key to continue the script."
	[Console]::ReadKey($true) | Out-Null
	#>

	if (!(Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows Defender\Features').TamperProtection -eq 4) {
		Write-Output 'Windows Defender can not be disabled, Tamper Protection is still active' '' 'Disable Tamper Protection manually, then press OK' '' 'Go to:' '' 'Settings -> Privacy & Security -> Windows Security -> Virus & Threat Protection -> Manage Settings -> Tamper Protection -> Off' | msg /w *
	}
	else {

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableEnhancedNotifications" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
	
	
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" -Name "Notification_Suppress" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
	
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Type DWord -Value 0x00000001								# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0x00000001							# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Type DWord -Value 0x00000001					# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableSpecialRunningModes" -Type DWord -Value 0x00000001					# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Type DWord -Value 0x00000000								# Win11 Home NA		LTSC NA
	
		If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender")) {
			New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0x00000001				# Win11 Home NA		LTSC NA
	
	
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA

	
		If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
			New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA
	
	
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ForceUpdateFromMU" -Type DWord -Value 0x00000000				# Win11 Home NA		LTSC NA
	
	
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -Type DWord -Value 0x00000001					# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0x00000000							# Win11 Home NA		LTSC NA
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 0x00000002						# Win11 Home NA		LTSC NA
	
		
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name "EnableControlledFolderAccess" -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA
	
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue # Win11 Home "%windir%\system32\SecurityHealthSystray.exe"		# LTSC "%windir%\system32\SecurityHealthSystray.exe"

		# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide

		
		# Disable ALL System Mitigations (https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/customize-exploit-protection?view=o365-worldwide)
		
		# Get-ProcessMitigation -System				# 
		
		Set-ProcessMitigation -System -Reset		# Reset All Mitigations at the system level.
		Start-Sleep 1
		<#
		Mitigation											Applies to				PowerShell cmdlets
		Control flow guard (CFG)							System and app-level	CFG, StrictCFG, SuppressExports
		Data Execution Prevention (DEP)						System and app-level	DEP, EmulateAtlThunks
		Force randomization for images (Mandatory ASLR)		System and app-level	ForceRelocateImages
		Randomize memory allocations (Bottom-Up ASLR)		System and app-level	BottomUp, HighEntropy
		Validate exception chains (SEHOP)					System and app-level	SEHOP, SEHOPTelemetry
		Validate heap integrity								System and app-level	TerminateOnError
		
		#>	

		# Set-Processmitigation -System -Disable CFG, StrictCFG, SuppressExports ( breaks WSL functionality on Windows 11 !)
		
	
	} 
}



###                            ###
### Desktop Menu Optimizations ###
###                            ###



Function SetMinAnimate {
	
	Write-Output "Disable useless visual effects to speed up response and display of desktop."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value "0"						# Win11 Home 1		LTSC 1
}



Function SetDesktopProcess {
	
	Write-Output "Optimize the priority of program processes and independent processes to avoid system crash."
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DesktopProcess" -Type DWord -Value 0x00000001					# Win11 Home NA		LTSC NA
}



Function SetTaskbarAnimations {
	
	Write-Output "Play animations in the taskbar and start menu."
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 1
}



Function SetWaitToKillServiceTimeout {
	
	Write-Output "Optimize the speed of ending processes."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type String -Value "2000"								# Win11 Home 5000		LTSC 5000
}



Function SetNoSimpleNetIDList {
	
	Write-Output "Optimize the refresh strategy of the system file list."
	
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSimpleNetIDList" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
}



Function SetMouseHoverTime {
	
	Write-Output "Reduce the display time of taskbar preview."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "100"						# Win11 Home 400		LTSC 400
}



Function SetMenuShowDelay {
	
	Write-Output "Speed up the response and display of system commands."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value "0"					# Win11 Home 400		LTSC 400
}



Function SetForegroundLockTimeout {
	
	Write-Output "Improve the response speed of foreground program."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ForegroundLockTimeout" -Type DWord -Value 0x000249f0		# Win11 Home 0x00030d40 (200000)		LTSC 0x00030d40 (200000)
}



Function SetAlwaysUnloadDLL {
	
	Write-Output "Release unused dlls in memory."
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "AlwaysUnloadDLL" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA
}



Function SetFontStyleShortcut{
	
	Write-Output "Remove the font style of the desktop shortcut."
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type String -Value "0"					# Win11 Home NA		LTSC NA
}



Function SetAutoRestartShell {
	
	Write-Output "Optimize user interface components. Auto-refresh when there is an error to avoid system crash."
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Type DWord -Value 0x00000001					# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
}



Function SetVisualEffects {
	
	Write-Output "Optimize the visual effects of system menus and lists to improve system performance."
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0x00000000					# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 0x00000002					# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" -Name "DefaultApplied" -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" -Name "DefaultApplied" -Type DWord -Value 0x00000000			# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Name "DefaultApplied" -Type DWord -Value 0x00000000		# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Name "DefaultApplied" -Type DWord -Value 0x00000000	# Win11 Home 1		LTSC 1
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



Function SetKeyboardDelay {
	
	Write-Output "Adjust the keyboards delayed response time."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type String -Value "2"		# Win11 Home 0		LTSC 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type String -Value "0"					# Win11 Home 1		LTSC 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardSpeed" -Type String -Value "48"				# Win11 Home 31		LTSC 31
}



Function SetMaxCachedIcons {
	
	Write-Output "Increase the system image buffer to display images faster."
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Type String -Value "4000"				# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Type String -Value "4000"	# Win11 Home NA		LTSC NA
}



###                           ###
### File System Optimizations ###
###                           ###


Function SetNoLowDiskSpaceChecks {
	
	Write-Output "Improve hard disk performance to enhance disk read/write capacity."
	
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoLowDiskSpaceChecks" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA
}



Function DisableStorageSense {
	
	# Not applicable to Servers
	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. -> Disabling Storage Sense."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0x00000000		# LTSC NA
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 0x00000000		# LTSC NA
	}

	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Windows 11 Detected. -> Disabling Storage Sense."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0x00000000		# Win11 Home 1
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 0x00000000		# Win11 Home 1
	}
}



Function SetNtfsDisable8dot3NameCreation {
	Write-Output "Disable short file names feature."

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisable8dot3NameCreation" -Type DWord -Value 0x00000001			# Win11 Home 2		LTSC 2

	# fsutil behavior query disable8dot3	# Win11 Home 2 (Per volume setting - the default)
}



Function SetNoDriveTypeAutoRun {
	
	Write-Output "Disable AutoPlay for external devices to avoid potential risks such as malware."
	
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 0x000000dd	# Win11 Home NA		LTSC NA
}



function DisableDeleteNotify {
	
	<#
	TRIM (also called Trim or Trim Command) allows your SSD drive to handle garbage more evidentially.
	TRIM allows the operating system to decide which blocks are already in use so they can be wiped internally.
	Anytime you delete something, TRIM automatically deletes that page or block.
	The next time the page or block is written to, the operating system does not have to wait for that block to be deleted.
	SSD TRIM can prolong the life and performance of your SSD drive.

	https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior
	#>

	Write-Output "Force TRIM state to On."
	
	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. Allows TRIM operations to be sent to the storage device."
		# fsutil behavior query DisableDeleteNotify
		fsutil behavior set DisableDeleteNotify 0			# LTSC 0 (DisableDeleteNotify = 0  (Disabled) "TRIM ENABLED")
		fsutil behavior set DisableDeleteNotify ReFS 0		# LTSC 0 (DisableDeleteNotify = 0  (Disabled) "TRIM ENABLED")
	}

	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Windows 11 Detected. Allows TRIM operations to be sent to the storage device."
		# fsutil behavior query DisableDeleteNotify
		fsutil behavior set DisableDeleteNotify 0			# Win11 Home 0 (Allows TRIM operations to be sent to the storage device. "TRIM ENABLED")
		fsutil behavior set DisableDeleteNotify ReFS 0		# Win11 Home 0 (Allows TRIM operations to be sent to the storage device. "TRIM ENABLED")
	} 
}  



function SetLastAccessTimeStamp {
	
	<#
		https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior

		# The disablelastaccess parameter can affect programs such as Backup and Remote Storage, which rely on this feature.
	#>

	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. Disable NTFS Last Access Time Stamp Updates."
		# fsutil behavior query disablelastaccess
		# fsutil behavior set disablelastaccess 0
		fsutil behavior set disablelastaccess 1 # LTSC 2 (System Managed, "Last Access Time Updates DISABLED")
	}

	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Windows 11 Detected. Disable NTFS Last Access Time Stamp Updates."
		# fsutil behavior query disablelastaccess
		# fsutil behavior set disablelastaccess 1
		fsutil behavior set disablelastaccess 1 # Win11 Home 2 (System Managed, "Last Access Time Updates ENABLED")
	}
}



Function SetWaitToKillAppTimeout {
	
	Write-Output "Optimize program response time to improve system response speed."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Type String -Value "10000"	# Win11 Home NA		LTSC NA
}



Function SetHungAppTimeout {
	
	Write-Output "Shorten the wait time for unresponsive mouse and keyboard caused by error program."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "HungAppTimeout" -Type String -Value "3000"			# Win11 Home NA		LTSC NA
}



Function SetPriorityControl {
	
	Write-Output "Optimize Win32PrioritySeparation value to make system smoother."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000026		# Win11 Home 0x00000002		LTSC 0x00000002

	<#

	Specifies the strategy used for optimizing processor time on the system. The value of this
	entry determines, in part, how much processor time the threads of a process receive each
	time they are scheduled, and how much the allotted time can vary. It also affects the
	relative priority of the threads of foreground and background processes.

	Also, You can change the value of this entry, in Control Panel, double-click System, click the
	Advanced tab, click Performance Options, and then, in the Application response
	section, select either Applications or Background services.

	2A Hex = Short, Fixed , High foreground boost.
	29 Hex = Short, Fixed , Medium foreground boost.
	28 Hex = Short, Fixed , No foreground boost.

	26 Hex = Short, Variable , High foreground boost.
	25 Hex = Short, Variable , Medium foreground boost.
	24 Hex = Short, Variable , No foreground boost.

	1A Hex = Long, Fixed, High foreground boost.
	19 Hex = Long, Fixed, Medium foreground boost.
	18 Hex = Long, Fixed, No foreground boost.

	16 Hex = Long, Variable, High foreground boost.
	15 Hex = Long, Variable, Medium foreground boost.
	14 Hex = Long, Variable, No foreground boost.
	#>

	# https://github.com/amitxv/PC-Tuning/blob/main/docs/research.md
}



Function SetAutoEndTasks {
	
	Write-Output "Automatically end unresponsive programs to avoid system crash."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Type String -Value "1"									# Win11 Home NA		LTSC NA
}



Function SetBootOptimizeFunction {
	
	Write-Output "Disable Windows auto disk defragmetation and automatically optimize boot partition to make the bootup speed faster."
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Type String -Value ""					# Win11 Home NA		LTSC NA
	
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Dfrg\BootOptimizeFunction")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Dfrg\BootOptimizeFunction" -Force | Out-Null
	}	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Type String -Value ""		# Win11 Home NA		LTSC NA
}



###					      ###
###	Network	Optimizations ###
###					      ###


Function SetInterruptModeration  {
	# Disabling (0) "Packet Coalescing" or "Interrupt Coalescing" or "Interrupt Moderation Rate" or "SetInterruptModeration".
	
	Write-Output "Setting Packet Coalescing / InterruptModeration to LOW."
	
	New-NetAdapterAdvancedProperty -Name Wi-Fi -RegistryKeyword "*InterruptModeration" -RegistryValue 1 -ErrorAction Ignore
	New-NetAdapterAdvancedProperty -Name Ethernet -RegistryKeyword "*InterruptModeration" -RegistryValue 1 -ErrorAction Ignore

	Set-NetAdapterAdvancedProperty -Name Wi-Fi -RegistryKeyword "*InterruptModeration" -RegistryValue 1 -ErrorAction Ignore
	Set-NetAdapterAdvancedProperty -Name Ethernet -RegistryKeyword "*InterruptModeration" -RegistryValue 1 -ErrorAction Ignore

	# Restart-NetAdapter -Name Wi-Fi
	# Restart-NetAdapter -Name Ethernet
}



Function SetIRPStackSize {
	# Improve network performance by improving how many buffers your computer can use simultaneously on your LAN. 
	
	Write-Output "Setting IRPStackSize."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 0x0000000c 	# Win11 Home NA		LTSC NA
}



function SettingTimeService {
	
	Write-Host "Setting BIOS time to UTC and fixing any inconsistency."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA

	# Secure Time Seeding – improving time keeping in Windows. This resolve a lot of problems with VM's & WSL time out of sync in some devices.
	# See more at http://byronwright.blogspot.com/2016/03/windows-10-time-synchronization-and.html

	#Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\w32time\SecureTimeLimits\RunTime" -Name "SecureTimeTickCount" -Type QWORD -Value 8735562		# Win11 Home NA

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
		New-Item $WifiSense1 -Force | Out-Null
	}
	Set-ItemProperty $WifiSense1  value -Type DWord -Value 0x00000000						# Win11 Home NA		LTSC NA
	
	If (!(Test-Path $WifiSense2)) {
		New-Item $WifiSense2 -Force | Out-Null
	}
	Set-ItemProperty $WifiSense2  value -Type DWord -Value 0x00000000						# Win11 Home 1		LTSC 1
	Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA
}



Function DisableWFPlogs {
	
	Write-Output "Disabling WFP logs."
	
	# https://social.technet.microsoft.com/Forums/en-US/7d0d2721-35ea-418e-9e7c-0bef1366a25f/wfpdiagetl-disk-usage-constantly-writing?forum=win10itprogeneral
	# wfpdiag.etl disk usage, constantly writing
	
	# netsh wfp show options netevents
	netsh wfp set options netevents=off		# Win11 Home On
}



Function SetDefaultTTL {
	Write-Output "Optimize default TTL to decrease bandwidth loss and increase available bandwidth."

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 0x00000040					# Win11 Home NA		LTSC NA
}


Function SetFastForwarding {
	Write-Output "Optimize network fast forwarding mechanism to get better internet speed."

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SackOpts" -Type DWord -Value 0x00000001					# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDupAcks" -Type DWord -Value 0x00000002				# Win11 Home NA		LTSC NA
}


Function SetMaxConnectionsPerServerIE {
	Write-Output "Add more IE concurrent connections."

	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "iexplore.exe" -Type DWord -Value 0x0000000a				# Win11 Home 0x00000004		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "iexplore.exe" -Type DWord -Value 0x0000000a					# Win11 Home 0x00000002		LTSC NA

	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "iexplore.exe" -Type DWord -Value 0x0000000a	# Win11 Home 0x00000004		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "iexplore.exe" -Type DWord -Value 0x0000000a		# Win11 Home 0x00000002		LTSC NA
	
	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
	Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPerServer" -Type DWord -Value 0x0000000a							# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPer1_0Server" -Type DWord -Value 0x0000000a							# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPerServer" -Type DWord -Value 0x0000000a							# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPer1_0Server" -Type DWord -Value 0x0000000a							# Win11 Home NA		LTSC NA

	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPerServer" -Type DWord -Value 0x0000000a									# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPer1_0Server" -Type DWord -Value 0x0000000a									# Win11 Home NA		LTSC NA
}


Function SetMaxConnectionsPerServer {
	
	Write-Output "Optimize Network Adapter performance to get better Internet speed."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxConnectionsPerServer" -Type DWord -Value 0x00000000							# Win11 Home NA		LTSC NA
}



Function SetAutoDetectionMTUsize {
	
	Write-Output "Enable auto-detection of MTU size and black hole router detection to get better internet speed."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUDiscovery" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUBHDetect" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
}



Function SetNameSrvQueryTimeout {
	
	Write-Output "Optimize network WINS name query time to enhance network data transmission capacity."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NameSrvQueryTimeout" -Type DWord -Value 0x00000bb8			# Win11 Home 0x000005dc (1500) 		LTSC 0x000005dc (1500)
}



Function SetDnsCache {
	
	Write-Output "Optimize DNS to get better parsing speed."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheEntryTtlLimit" -Type DWord -Value 0x00002a30	# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl" -Type DWord -Value 0x00002a30				# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxNegativeCacheTtl" -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NegativeSOACacheTime" -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NetFailureCacheTime" -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA
}



Function SetNoUpdateCheckonIE {
	
	Write-Output "Disable automatic updates on IE."
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name "NoUpdateCheck" -Type DWord -Value 0x00000001				# Win11 Home NA
	
	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name "NoUpdateCheck" -Type DWord -Value 0x00000001	# Win11 Home NA
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "NoUpdateCheck" -Type DWord -Value 0x00000001											# Win11 Home NA
}



Function SetTcp1323Opts {
	
	Write-Output "Enable auto-adjustment of transport unit buffer to shorten network response time."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Tcp1323Opts" -Type DWord -Value 0x00000001							# Win11 Home NA		LTSC NA
}



Function SetMaxCmds {
	
	Write-Output "Optimize network parameter configuration to improve network performance and throughput."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "MaxCmds" -Type DWord -Value 0x0000001e					# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "MaxThreads" -Type DWord -Value 0x0000001e				# Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "MaxCollectionCount" -Type DWord -Value 0x00000020		# Win11 Home NA		LTSC NA
}



Function SetNoNetCrawling {
	
	Write-Output "Optimize LAN connection."
	
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NoNetCrawling" -Type DWord -Value 0x00000001		# Win11 Home NA		LTSC NA
}



Function SetGlobalMaxTcpWindowSize {
	
	Write-Output "Speed up the broadband network."
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "GlobalMaxTcpWindowSize" -Type DWord -Value 0x00007fff		# Win11 Home NA		LTSC NA
}



Function SetOptimizeNetwrok {

	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0x00000000				# Win11 Home NA		LTSC NA

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Psched")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Psched" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0x00000000	# Win11 Home NA		LTSC NA


	# Disable throttling mechanism to control network performance
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff		# Win11 Home 0x0000000a (10)	LTSC 0x0000000a (10)
		

	# Disable Nagle’s Algorithm
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
		if(Get-ItemProperty -Path $_.PsPath -Name "DhcpServer" -ErrorAction SilentlyContinue )	 {
			Set-ItemProperty -Path $_.PsPath -Name "TcpNoDelay" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue												# Win11 Home NA	LTSC NA
			Set-ItemProperty -Path $_.PsPath -Name "TcpAckFrequency" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue											# Win11 Home NA	LTSC NA
			Set-ItemProperty -Path $_.PsPath -Name "TcpDelAckTicks" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue											# Win11 Home NA	LTSC NA
		}	
	}

	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Name "TCPNoDelay" -Type DWord -Value 0x00000001	# Win11 Home NA		LTSC NA

}



###				   ###
###	Server-Related ###
###				   ###



Function DisableEventTracker {
	
	Write-Output "Disabling Shutdown Event Tracker."
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0x00000000		# Win11 Home NA		LTSC NA
}






### 	  ###
### Unpin ###
###       ###



Function RemovingFax {
	
	Write-Output "Removing Default Fax Printer."
	
	# Get-Printer
	#Remove-Printer -Name "Microsoft Print to PDF" -ErrorAction SilentlyContinue
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
	Remove-Printer -Name "OneNote (Desktop)" -ErrorAction SilentlyContinue
}



Function RemoveFeaturesKeys {

	# These are the registry keys that it will delete.
	
	$Keys = @(
		# Remove Background Tasks
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\AD2F1837.OMENCommandCenter_1101.2305.3.0_x64__v10z8vjag6ke6"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\AD2F1837.OMENCommandCenter_1101.2305.4.0_x64__v10z8vjag6ke6"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\AD2F1837.OMENCommandCenter_1101.2307.1.0_x64__v10z8vjag6ke6"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
		#"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
		#"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.19041.1_neutral_neutral_cw5n1h2txyewy"
		#"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.22621.1_neutral_neutral_cw5n1h2txyewy"
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
		#"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.22621.1_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.19041.1023.0_neutral_neutral_cw5n1h2txyewy"
		"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy"
		

		# Scheduled Tasks to delete
		"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
		"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\AD2F1837.OMENCommandCenter_1101.2305.3.0_x64__v10z8vjag6ke6"
		"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\AD2F1837.OMENCommandCenter_1101.2305.4.0_x64__v10z8vjag6ke6"
		"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\AD2F1837.OMENCommandCenter_1101.2307.1.0_x64__v10z8vjag6ke6"

		# Windows Protocol Keys
		"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		#"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
		#"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.19041.1_neutral_neutral_cw5n1h2txyewy"
		#"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.22621.1_neutral_neutral_cw5n1h2txyewy"
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