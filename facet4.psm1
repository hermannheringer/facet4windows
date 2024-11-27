<#
Facet4 Windows 10/11 distribution
Author: Hermann Heringer
Version : 0.4.1
Date: 2024-11-27
License: MIT
Source: https://github.com/hermannheringer/
#>

 #.............................................................................................................................................................................................
 # .......................................................  https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features  ..........................................................
 #.............................................................................................................................................................................................


Add-Type -AssemblyName System.IO.Compression.FileSystem

function Unzip {
    param(
        [string]$zipfile,   # Caminho do arquivo ZIP
        [string]$outpath    # Caminho do diretório de saída
    )

    # Verifica se o arquivo ZIP existe
    if (-Not (Test-Path $zipfile)) {
        Write-Output "O arquivo ZIP '$zipfile' não foi encontrado."
        return
    }

    # Verifica se o diretório de saída existe; se não, cria
    if (-Not (Test-Path $outpath)) {
        Write-Output "O diretório de saída '$outpath' não existe. Criando..."
        New-Item -Path $outpath -ItemType Directory -Force | Out-Null
    }

    try {
        # Extrai o conteúdo do arquivo ZIP para o diretório de saída
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
        Write-Output "Extraído '$zipfile' para '$outpath' com sucesso."
    } catch {
        Write-Output "Ocorreu um erro ao extrair o arquivo ZIP: $_"
    }
}



 ###				 ###
 ###  Application	 ###
 ###				 ###



function InstallWinget {
    # Define URLs para downloads
    $wingetInstallerUrl = "https://aka.ms/getwinget"
    $vclibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
    $xamlUrl = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx"
    
    Write-Host "Checking if Winget is Installed..."

    # Verifica se o winget já está instalado
    if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe) {
        Write-Host "Winget Already Installed."
    }
    else {
        $osInfo = Get-ComputerInfo

        # Verifica se o Windows é LTSC/Server 2019 ou superior
        if ((($osInfo.OSName.IndexOf("LTSC") -ne -1) -or ($osInfo.OSName.IndexOf("Server") -ne -1)) -and ($osInfo.WindowsVersion -ge "1809")) {
            Write-Host "Running Alternative Installer for LTSC/Server Editions"

            # Desativa a exibição de progresso para downloads
            $progressPreference = 'silentlyContinue'
            
            try {
                Write-Information "Downloading WinGet and its dependencies..."
                Invoke-WebRequest -Uri $wingetInstallerUrl -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
                Invoke-WebRequest -Uri $vclibsUrl -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
                Invoke-WebRequest -Uri $xamlUrl -OutFile Microsoft.UI.Xaml.2.8.x64.appx

                # Instala as dependências
                Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
                Add-AppxPackage Microsoft.UI.Xaml.2.8.x64.appx
                Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
                
                Write-Host "Winget Installed Successfully."
            } catch {
                Write-Host "Error during installation: $_"
            }
        }
        elseif ($osInfo.WindowsVersion -lt "1809") {
            Write-Host "Winget is not supported on this version of Windows (Pre-1809)"
        }
        else {
            # Tenta instalar o Winget a partir da Microsoft Store
            Write-Host "Winget not found, installing it now."
            Start-Process "ms-appinstaller:?source=$wingetInstallerUrl"
            $nid = (Get-Process AppInstaller).Id
            Wait-Process -Id $nid
            Write-Host "Winget Installed."
        }
    }
}



 ###		      ###
 ###  Debloat     ###
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
		 #"*MicrosoftTeams*"
		 #"*MSTeams*"
		"*Microsoft.MinecraftUWP*"
		"*Microsoft.MixedReality.Portal*"
		 #"*Microsoft.NetworkSpeedTest*"
		"*Microsoft.News*"
		 #"*Microsoft.Office.OneNote*"
		 #"*Microsoft.Office.Todo.List*"
		 #"*Microsoft.Office.Lens*"
		 #"*Microsoft.Office.Sway*"
		 #"*Microsoft.OneConnect*"
		"*Microsoft.OutlookForWindows*"
		"*Microsoft.People*"
		 #"*Microsoft.PowerAutomateDesktop*"
		"*Microsoft.Print3D*"
		"*Microsoft.Reader*"
		"*Microsoft.RemoteDesktop*"
		 #"*Microsoft.ScreenSketch*"
		"*Microsoft.SkypeApp*"
		 #"*Microsoft.StorePurchaseApp*"
		"*Microsoft.Todos*"
		"*Microsoft.Wallet*"
		 #"*Microsoft.WebMediaExtensions*"
		"*Microsoft.Whiteboard*"
		 #"*Microsoft.WindowsAlarms*"
		"*Microsoft.WindowsCamera*"
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
		"*MicrosoftCorporationII.MicrosoftFamily*"
		"*MicrosoftCorporationII.QuickAssist*"

		 # Redstone Apps
		"*Microsoft.BingFinance*"
		"*Microsoft.BingFoodAndDrink*"
		"*Microsoft.BingHealthAndFitness*"
		"*Microsoft.BingMaps*"
		"*Microsoft.BingNews*"
		"*Microsoft.BingSports*"
		"*Microsoft.BingSearch*"
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
		 #"*Microsoft-Windows-InternetExplorer*"
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
		"*Microsoft.MicrosoftStickyNotes*"
		 #"*Microsoft.MSPaint*"
		 #"*Microsoft.Windows.Photos*"
		 #"*Microsoft.WindowsCalculator*"
		 #"*Microsoft.WindowsPhone*"
		 #"*Microsoft.WindowsStore*"	
	)
	
    # Remover aplicativos para o usuário atual e para todos os usuários
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage $Bloat | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxPackage -AllUsers | Where-Object DisplayName -like $Bloat | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -ErrorAction SilentlyContinue
        Start-Sleep 1
        Write-Output "Tentando remover $Bloat"
    }

    # Lista de capacidades a serem removidas
    $Capabilities = @(
        "Microsoft-Windows-TextToSpeech",
        "Microsoft-Windows-Handwriting",
        "Microsoft-Windows-OCR",
        "Microsoft-Windows-SpeechRecognition",
        "Microsoft-Windows-LanguageFeatures-Handwriting",
        "Microsoft-Windows-LanguageFeatures-OCR",
        "Microsoft-Windows-LanguageFeatures-Speech",
        "Microsoft-Windows-LanguageFeatures-TextToSpeech",
        "Microsoft-Windows-TabletPCMath",
        "Microsoft-Windows-InternetExplorer-Optional"
    )

    # Remover cada capacidade listada
    foreach ($capabilityName in $Capabilities) {
        try {
            Get-WindowsCapability -Online | Where-Object {$_.Name -like "*$capabilityName*"} | Remove-WindowsCapability -ErrorAction SilentlyContinue
            Write-Host "Capacidade ${capabilityName} removida com sucesso."
        } catch {
            Write-Host "Ocorreu um erro ao tentar remover a capacidade ${capabilityName}: $_"
        }
    }

    # Remover componentes adicionais (Get Help, Tips, Xbox Game Bar)
    $AdditionalComponents = @(
        "*GetHelp*",
        "*HelpAndTips*",
        "*XboxGameOverlay*"
    )

    foreach ($component in $AdditionalComponents) {
        Get-AppxPackage -AllUsers | Where-Object {$_.Name -like $component} | Remove-AppxPackage -ErrorAction SilentlyContinue
        Write-Output "Tentando remover $component"
    }

    Write-Host "Remoção de bloatware e capacidades concluída."
}



function AvoidDebloatReturn {

    Write-Output "Adicionando chaves de registro para impedir que apps patrocinados retornem e removendo algumas configurações de sugestões."

    # Caminho para bloquear funcionalidades de consumidor
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath -Force | Out-Null
    }
    Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Type DWord -Value 0x00000001
    Write-Output "Desativada a instalação de recursos para consumidores do Windows."

    # Caminho para o ContentDeliveryManager
    $contentDeliveryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

    # Verifica se o caminho do ContentDeliveryManager existe e cria, se necessário
    If (!(Test-Path $contentDeliveryPath)) {
        New-Item $contentDeliveryPath -Force | Out-Null
    }

    # Lista de ajustes a serem aplicados no ContentDeliveryManager
    $settings = @{
        "ContentDeliveryAllowed"            = 0x00000001;
        "OemPreInstalledAppsEnabled"        = 0x00000000;
        "PreInstalledAppsEnabled"           = 0x00000000;
        "PreInstalledAppsEverEnabled"       = 0x00000000;
        "SilentInstalledAppsEnabled"        = 0x00000000;
        "SystemPaneSuggestionsEnabled"      = 0x00000000;
        "SubscribedContent-310093Enabled"   = 0x00000000;
        "SubscribedContent-314559Enabled"   = 0x00000000;
        "SubscribedContent-338387Enabled"   = 0x00000001; # Spotlight fun tips and facts
        "SubscribedContent-338388Enabled"   = 0x00000000; # Show Suggestions Occasionally in Start
        "SubscribedContent-338389Enabled"   = 0x00000000; # Tips and Suggestions Notifications
        "SubscribedContent-338393Enabled"   = 0x00000000; # Suggest new content and apps
        "SubscribedContent-353694Enabled"   = 0x00000000; # Suggest new content and apps
        "SubscribedContent-353696Enabled"   = 0x00000000; # Suggest new content and apps
        "SubscribedContent-353698Enabled"   = 0x00000000; # Timeline Suggestions
        "SubscribedContent-88000326Enabled" = 0x00000001  # Use Spotlight image as Desktop wallpaper
    }

    # Aplica as configurações no ContentDeliveryManager
    foreach ($setting in $settings.Keys) {
        Set-ItemProperty -Path $contentDeliveryPath -Name $setting -Type DWord -Value $settings[$setting]
        Write-Output "Configurada $setting com sucesso."
    }

    # Ajuste adicional para a imagem do Spotlight como papel de parede
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name "BackgroundType" -Type DWord -Value 0x00000002
    Write-Output "Configuração de imagem Spotlight aplicada como papel de parede."
}



function SetMixedReality {

    Write-Output "Configurando o valor do Mixed Reality Portal para 0 para permitir sua desinstalação nas Configurações."

    # Caminho do registro para Mixed Reality
    $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"

    # Verifica se o caminho existe
    If (Test-Path $Holo) {
        # Define o valor de FirstRunSucceeded para 0
        Set-ItemProperty -Path $Holo -Name FirstRunSucceeded -Type DWord -Value 0x00000000
        Write-Output "Valor FirstRunSucceeded configurado como 0."
    }
    else {
        Write-Output "Caminho de registro para Holographic não encontrado. Nenhuma alteração foi feita."
    }
}



 ###				                        ###
 ###  Disable Unecessary Windows Services   ###
 ###				                        ###



 # Get-Service | select -property name,starttype

<#
Device Management Wireless Application Protocol (WAP) Push Message Routing Service
Useful for Windows tablet devices with mobile (3G/4G) connectivity
#>

function DisableWAPPush {

    Write-Host "Configurando o serviço Device Metadata Retrieval Client (WMIS) para Manual."

    # Verifica se o serviço dmwappushservice existe
    $service = Get-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue

    if ($service) {
        try {
            # Define o serviço para inicialização manual
            Set-Service "dmwappushservice" -StartupType Manual -ErrorAction SilentlyContinue
            Write-Host "Serviço 'dmwappushservice' configurado para inicialização manual."
        } catch {
            Write-Host "Ocorreu um erro ao configurar o serviço: $_"
        }
    }
    else {
        Write-Host "O serviço 'dmwappushservice' não foi encontrado neste sistema."
    }
}



function DisableServices {

    Write-Output "Desativando serviços selecionados."

    # Função auxiliar para verificar e desabilitar serviços
    function Disable-Service {
        param (
            [string]$serviceName,
            [string]$displayName
        )

        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

        if ($service) {
            try {
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Output "$displayName desativado com sucesso."
            } catch {
                Write-Output "Erro ao desativar ${displayName}: $_"
            }
        } else {
            Write-Output "Serviço $displayName não encontrado."
        }
    }

    # Desativando os serviços especificados
    Disable-Service "AdobeARMservice" "Adobe ARM Service"
    # Disable-Service "AMD Crash Defender Service" "AMD Crash Defender Service"
	Disable-Service "AppMgmt" "Application Management"
    Disable-Service "CertPropSvc" "Certificate Propagation"
    # Copies user certificates and root certificates from smart cards into the current user's certificate store.

	Disable-Service "AxInstSV" "ActiveX Installer"
    Disable-Service "CscService" "Offline Files Service"
    Disable-Service "ETDservice" "HP ETD Telemetry Service"
    Disable-Service "Fax" "Fax Service"
    Disable-Service "fhsvc" "File History Service"
    
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Force | Out-Null
	}
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Type DWord -Value 0x00000001					  # Win11 Home NA		LTSC NA

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HomeGroup")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HomeGroup" -Force | Out-Null
	}
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\HomeGroup" -Name "DisableHomeGroup" -Type DWord -Value 0x00000001		  # Win11 Home NA		LTSC NA

	Disable-Service "HomeGroupListener" "Home Group Listener"
    Disable-Service "HomeGroupProvider" "Home Group Provider"
    
	# Disable-Service "HPAppHelperCap" "HP App Helper Service"
	Disable-Service "HPDiagsCap" "HP Diagnostics Service"
    # Disable-Service "HPNetworkCap" "HP Network Service"
	# Disable-Service "HPOmenCap" "HP Omen Service"
	# Disable-Service "HPSysInfoCap" "HP System Info Service"
	Disable-Service "MSiSCSI" "Microsoft iSCSI Initiator Service"
    Disable-Service "napagent" "Network Access Protection Agent"
	# It collects and manages health information for client computers on a network.

	Disable-Service "p2pimsvc" "Peer Networking Identity Manager"
    Disable-Service "p2psvc" "Peer Networking Grouping"
    Disable-Service "PeerDistSvc" "BranchCache Service"
    # This service caches network content from peers on the local subnet.

	Disable-Service "pla" "Performance Logs and Alerts"
    Disable-Service "PNRPsvc" "Peer Name Resolution Protocol"
    Disable-Service "RemoteRegistry" "Remote Registry Service"
    Disable-Service "ScPolicySvc" "Smart Card Removal Policy"
    <#
	The smart card removal policy service is applicable when a user has signed in with a smart card and then removes that smart card from the reader. 
	The action that is performed when the smart card is removed is controlled by Group Policy settings. 
	For more information, see Smart Card Group Policy and Registry Settings.
	#>
	
	Disable-Service "SQLCEIP" "SQLCEIP Service"
    Disable-Service "SNMPTRAP" "SNMP Service"
	<#
	An SNMP trap message is an unsolicited message sent from an agent to the the manager.
	The objective of this message is to allow the remote devices to alert the manager in case an important event happens,
	commonly used in companies.
	#>
    
	# Disable-Service "TabletInputService" "Touch Keyboard and Handwriting Panel Service"
	# Disabling this will break WSL keyboard functionality.
	
	Disable-Service "WebClient" "WebClient Service"
    Disable-Service "WerSvc" "Windows Error Reporting"
    Disable-Service "WinRM" "Windows Remote Management"
    Disable-Service "wisvc" "Windows Insider Service"
	
	# Caution! Windows Insider will not work anymore!
    # Disable-Service "WSearch" "Windows Search Indexing"
	
	Disable-Service "DPS" "Diagnostic Policy Service"
    Disable-Service "PcaSvc" "Program Compatibility Assistant"

	<#
	The Memory Compression process is serviced by the SysMain (formerly SuperFetch) service.
	SysMain reduces disk writes (paging) by compressing and consolidating memory pages.
	If this service is stopped, then Windows does not use RAM compression.
	Write-Host "Disabling Superfetch service."
	Stop-Service "SysMain" -ea SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled -erroraction SilentlyContinue							  # Win11 Home Auto
	#>
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "DelayedAutoStart" -Type DWord -Value 00000001	 # Win11 Home 2		LTSC NA

    Write-Host "Desativação de serviços concluída."
}



 ###		     		    ###
 ###  Optional Features     ###
 ###		                ###



function HideNewOutlookToggle {

    Write-Output "Ocultando o botão 'Try New Outlook'."

    # Caminho do registro para a opção do Outlook
    $registryPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Options\General"

    # Verifica se o caminho existe, se não, cria
    If (!(Test-Path $registryPath)) {
        try {
            New-Item -Path $registryPath -Force | Out-Null
            Write-Output "Caminho do registro criado com sucesso."
        } catch {
            Write-Output "Erro ao criar o caminho do registro: $_"
            return
        }
    }

    # Define o valor HideNewOutlookToggle para ocultar o botão
    try {
        Set-ItemProperty -Path $registryPath -Name "HideNewOutlookToggle" -Type DWord -Value 0x00000001
        Write-Output "'Try New Outlook' ocultado com sucesso."
    } catch {
        Write-Output "Erro ao definir o valor HideNewOutlookToggle: $_"
    }
}



 ###		              			   ###
 ###  Performance Game / GPU Related   ###
 ###		      			           ###



function RemoveXboxFeatures {

    Write-Output "Desativando recursos do Xbox."

    # Função auxiliar para desativar serviços
    function Disable-Service {
        param (
            [string]$serviceName,
            [string]$displayName
        )

        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

        if ($service) {
            try {
                Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Output "$displayName desativado com sucesso."
            } catch {
                Write-Output "Erro ao desativar {$displayName}: $_"
            }
        } else {
            Write-Output "Serviço $displayName não encontrado."
        }
    }

    # Desativando os serviços relacionados ao Xbox
    Disable-Service "XblAuthManager" "Xbox Live Auth Manager"
    Disable-Service "XblGameSave" "Xbox Live Game Save"
    Disable-Service "XboxNetApiSvc" "Xbox Live Networking"
    Disable-Service "xbgm" "Xbox Game Monitoring"
    Disable-Service "XboxGipSvc" "Xbox Accessory Management"
    Disable-Service "BcastDVRUserService" "GameDVR and Broadcast"

    Write-Output "Desativando componentes agendados do Xbox."
    
    # Desativar tarefas agendadas
    if (Get-ScheduledTask -TaskName "XblGameSaveTask*" -ErrorAction Ignore) {
        Get-ScheduledTask -TaskName "XblGameSaveTask*" | Stop-ScheduledTask
        Get-ScheduledTask -TaskName "XblGameSaveTask*" | Disable-ScheduledTask
        Write-Output "Tarefas agendadas do Xbox desativadas."
    } else {
        Write-Output "Tarefas agendadas do Xbox não encontradas."
    }

    # Desabilitar o GameDVR no registro
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0x00000000
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "Value" -Value 0x00000000

    # Modificar o ms-gamingoverlay para evitar mensagens indesejadas
    If (!(Test-Path "HKLM:\SOFTWARE\Classes\ms-gamingoverlay")) {
        New-Item -Path "HKLM:\SOFTWARE\Classes\ms-gamingoverlay" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\ms-gamingoverlay" -Name '(Default)' -Value "URL:ms-gamingoverlay"

    # Alterar permissões para PresenceWriter
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        $acl = $key.GetAccessControl()
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule (".\USERS", "FullControl", @("ObjectInherit", "ContainerInherit"), "None", "Allow")
        $acl.SetAccessRule($rule)
        $key.SetAccessControl($acl)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Name "ActivationType" -Value 0x00000000 -Force
        Write-Output "PresenceWriter desativado com sucesso."
    } catch {
        Write-Output "Erro ao desativar PresenceWriter: $_"
    }

    # Verificar se a modificação no PresenceWriter foi aplicada
    if ((Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter").ActivationType -eq 1) {
        Write-Output "Feature PresenceWriter ainda ativa. Desative-a manualmente em: 'Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter'."
    }

    Write-Output "Recursos do Xbox desativados."
}



function EnableGPUScheduling {
    
    Write-Host "Ativando o Agendamento de GPU Acelerado por Hardware."

    # Função auxiliar para definir uma chave de registro
    function Set-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [int]$value,
            [string]$displayName
        )

        try {
            Set-ItemProperty -Path $path -Name $name -Type DWord -Value $value
            Write-Host "$displayName configurado com sucesso."
        } catch {
            Write-Host "Erro ao configurar {$displayName}: $_"
        }
    }

    # Caminho do registro para drivers gráficos
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"

    # Definindo valores de registro
    Set-RegistryValue -Path $registryPath -Name "HwSchMode" -Value 0x00000002 -displayName "HwSchMode"
    Set-RegistryValue -Path $registryPath -Name "PlatformSupportMiracast" -Value 0x00000001 -displayName "PlatformSupportMiracast"
    Set-RegistryValue -Path $registryPath -Name "UnsupportedMonitorModesAllowed" -Value 0x00000001 -displayName "UnsupportedMonitorModesAllowed"
    
    Write-Host "Configurações de GPU concluídas."
}



function EnableVRR_AutoHDR {
    
    Write-Host "Ativando Variable Refresh Rate e Auto HDR para otimizações em jogos em janela."

    # Função auxiliar para definir uma chave de registro
    function Set-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [object]$value,  # Mudou para object para aceitar strings
            [string]$displayName
        )

        try {
            Set-ItemProperty -Path $path -Name $name -Value $value -ErrorAction SilentlyContinue
            Write-Host "$displayName configurado com sucesso."
        } catch {
            Write-Host "Erro ao configurar {$displayName}: $_"
        }
    }

    # Chave do registro para UserGpuPreferences
    If (!(Test-Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences")) {
        New-Item -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Force | Out-Null
    }
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "DirectXUserGlobalSettings" -Value "VRROptimizeEnable=1;AutoHDREnable=1;SwapEffectUpgradeEnable=1;" -displayName "DirectXUserGlobalSettings"

    # Chave do registro para GraphicsSettings
    If (!(Test-Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings")) {
        New-Item -Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings" -Force | Out-Null
    }
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\DirectX\GraphicsSettings" -Name "SwapEffectUpgradeCache" -Value 0x00000001 -displayName "SwapEffectUpgradeCache"

    # Chave do registro para VideoSettings
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Force | Out-Null
    }
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Name "AllowLowResolution" -Value 0x00000001 -displayName "AllowLowResolution"
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Name "EnableOutsideModeFeature" -Value 0x00000001 -displayName "EnableOutsideModeFeature"
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Name "EnableHDRForPlayback" -Value 0x00000001 -displayName "EnableHDRForPlayback"
    Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\VideoSettings" -Name "EnableAutoEnhanceDuringPlayback" -Value 0x00000001 -displayName "EnableAutoEnhanceDuringPlayback"

    Write-Host "Configurações de VRR e Auto HDR concluídas."
}



function EnableEdge_GPU {
    
    Write-Host "Ativando Aceleração de GPU no Microsoft Edge."

    # Função auxiliar para definir uma chave de registro
    function Set-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [object]$value,  # Tipo como object para aceitar strings e DWord
            [string]$displayName
        )

        try {
            Set-ItemProperty -Path $path -Name $name -Value $value -ErrorAction SilentlyContinue
            Write-Host "$displayName configurado com sucesso."
        } catch {
            Write-Host "Erro ao configurar {$displayName}: $_"
        }
    }

    # Chave do registro para habilitar a aceleração de hardware
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
    }
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HardwareAccelerationModeEnabled" -Value 0x00000001 -displayName "HardwareAccelerationModeEnabled"

    # Bloco comentado para desativar o botão de pesquisa do Bing (opcional)
    <#
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
    }
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HubsSidebarEnabled" -Value 0x00000000 -displayName "HubsSidebarEnabled"
    #>

    Write-Host "Configurações de aceleração de GPU para Microsoft Edge concluídas."
}



 ###				  	 ###
 ###		Privacy		 ###
 ###				  	 ###



function RemoveAutoLogger {
    
    Write-Host "Removendo o arquivo AutoLogger e restringindo o diretório."

    $autoLoggerDir = "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\Autologger"
    $autoLoggerFile = "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"

    # Remover o arquivo de log se existir
    try {
        if (Test-Path $autoLoggerFile) {
            Remove-Item $autoLoggerFile -Force -ErrorAction SilentlyContinue
            Write-Host "Arquivo de log removido com sucesso."
        } else {
            Write-Host "Arquivo de log não encontrado."
        }
    } catch {
        Write-Host "Erro ao remover o arquivo de log: $_"
    }

    # Restringir o diretório
    try {
        icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
        Write-Host "Permissões do diretório restringidas com sucesso."
    } catch {
        Write-Host "Erro ao restringir permissões do diretório: $_"
    }

    Write-Host "A remoção do AutoLogger foi concluída."
}



function DisableDataCollection {
    
    Write-Output "Desativando a coleta de dados alterando a chave AllowTelemetry para 0."

    $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"

    # Função auxiliar para definir uma chave de registro
    function Set-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [int]$value,
            [string]$displayName
        )

        try {
            Set-ItemProperty -Path $path -Name $name -Value $value -ErrorAction SilentlyContinue
            Write-Host "$displayName configurado para $value com sucesso."
        } catch {
            Write-Host "Erro ao configurar {$displayName}: $_"
        }
    }

    # Modificar a primeira chave de registro
    if (Test-Path $DataCollection1) {
        Set-RegistryValue -Path $DataCollection1 -Name "AllowTelemetry" -Value 0x00000000 -displayName "AllowTelemetry"
        Set-RegistryValue -Path $DataCollection1 -Name "MaxTelemetryAllowed" -Value 0x00000000 -displayName "MaxTelemetryAllowed"
    }

    # Modificar a segunda chave de registro
    if (Test-Path $DataCollection2) {
        Set-RegistryValue -Path $DataCollection2 -Name "AllowTelemetry" -Value 0x00000000 -displayName "AllowTelemetry"
    }

    # Modificar a terceira chave de registro
    if (Test-Path $DataCollection3) {
        Set-RegistryValue -Path $DataCollection3 -Name "AllowTelemetry" -Value 0x00000000 -displayName "AllowTelemetry"
        Set-RegistryValue -Path $DataCollection3 -Name "MaxTelemetryAllowed" -Value 0x00000000 -displayName "MaxTelemetryAllowed"
    }

    Write-Output "Configurações de coleta de dados desativadas."
}



function DisableDiagTrack {
    
    Write-Output "Parando e desativando o serviço de Experiências do Usuário Conectadas e Telemetria."

    # Função auxiliar para parar e desativar serviços
    function Stop-AndDisableService {
        param (
            [string]$serviceName,
            [string]$displayName
        )

        try {
            # Tente parar o serviço
            Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
            Write-Host "Serviço $displayName parado com sucesso."
        } catch {
            Write-Host "Erro ao parar o serviço {$displayName}: $_"
        }

        try {
            # Tente desativar o serviço
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "Serviço $displayName desativado com sucesso."
        } catch {
            Write-Host "Erro ao desativar o serviço {$displayName}: $_"
        }
    }

    # Parar e desativar os serviços relacionados à telemetria
    Stop-AndDisableService -serviceName "DiagTrack" -displayName "Connected User Experiences and Telemetry Service"
    Stop-AndDisableService -serviceName "DcpSvc" -displayName "Data Collection Service"
    Stop-AndDisableService -serviceName "diagnosticshub.standardcollector.service" -displayName "Diagnostics Hub Standard Collector Service"
    Stop-AndDisableService -serviceName "WdiServiceHost" -displayName "Windows Diagnostic Infrastructure Service"

    Write-Output "Todos os serviços de telemetria foram desativados."
}



function DisableStartupEventTraceSession {
	<#
	Event tracing sessions record events from one or more providers that a controller enables. The session is also responsible for managing and flushing the buffers. 
	The controller defines the session, which typically includes specifying the session and log file name, type of log file to use, and the resolution of the time stamp used to record the events.
	#>

    Write-Host "Desativando todas as sessões de rastreamento de eventos de inicialização."

    # Função auxiliar para desativar sessões de rastreamento
    function Disable-EventTraceSession {
        param (
            [string]$path,
            [string]$name,
            [string]$displayName
        )

        try {
            Set-ItemProperty -Path $path -Name $name -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
            Write-Host "Sessão $displayName desativada com sucesso."
        } catch {
            Write-Host "Erro ao desativar a sessão {$displayName}: $_"
        }
    }

    # Desativar sessões de rastreamento
    Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger" | ForEach-Object {
        $Var = $_.PsPath
        if (Test-Path $Var) {
            Disable-EventTraceSession -path $Var -name "Start" -displayName $_.PsChildName
        }
    }

    # Listar todos os logs de eventos
    $logs = wevtutil el

    # Iterar sobre cada log e desabilitá-lo
    foreach ($log in $logs) {
        try {
            wevtutil sl "$log" /e:false
            Write-Output "Log desativado: $log"
        } catch {
            Write-Output "Falha ao desativar log: $log"
        }
    }

    <#
	The operating system should not allow changes to the events below as it would cause chronic anomalies, however, we will ensure everything works as it should.
	As time passes, more trace sessions will appear active. This is normal. Do not change the behaviour of this.
	#>

    # Configurações específicas
 		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue	  # Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue			  # Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue		  # Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue					  # Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NetCore" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue					  # Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RadioMgr" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue				  # Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue		  # Win11 Home 1	LTSC 1
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" -Name "Start" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue		  # Win11 Home 1	LTSC 1


	# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

    # Desativar eventos específicos
    $events = @('SleepStudy', 'Kernel-Processor-Power', 'UserModePowerService')
    foreach ($event in $events) {
        try {
            wevtutil sl Microsoft-Windows-"$event" /e:false
            Write-Output "Evento desativado: Microsoft-Windows-$event"
        } catch {
            Write-Output "Falha ao desativar evento: Microsoft-Windows-$event"
        }
    }

    # Desativar logs de canais
		Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels" | ForEach-Object {
			$Var = $_.PsPath
				If ((Test-Path $Var)) {
					Set-ItemProperty -Path $Var -Name "Enabled" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
				}
			}

    Write-Host "Desativação de todas as sessões de rastreamento de eventos concluída."
}



function DisableKernelDebugTracing {
    Write-Host "Disabling and Cleaning Kernel Debug Traces."

    try {
        # Disable Kernel Debug Tracing
        wevtutil sl Microsoft-Windows-Kernel-Debug /e:false
    } catch {
        Write-Host "Failed to disable Kernel Debug Tracing: $_" -ForegroundColor Red
    }

    try {
        # Clean up kernel debug traces
        $backupPath = "C:\Windows\System32\LogFiles\WMI\RtBackup\*.*"
        Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
        Write-Host "Kernel debug traces cleaned up successfully."
    } catch {
        Write-Host "Failed to clean kernel debug traces: $_" -ForegroundColor Red
    }
}



function DisableDriverLogging {
    Write-Host "Disabling Driver Logging."

    try {
        # Disable driver logging by setting TrackLockedPages to 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "TrackLockedPages" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Host "Driver logging has been disabled successfully."
    } catch {
        Write-Host "Failed to disable driver logging: $_" -ForegroundColor Red
    }
}



function DisableRemoteAssistance {
    Write-Host "Disabling Remote Assistance."

    try {
        # Disable Remote Assistance features
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        
        Write-Host "Remote Assistance has been disabled successfully."
    } catch {
        Write-Host "Failed to disable Remote Assistance: $_" -ForegroundColor Red
    }
}



function DisableRDP {
    <#
    RDP consumes system resources, including CPU processing power, memory, and network bandwidth. 
    When RDP is enabled, the system must maintain the ability to accept remote connections and process data transmitted over that connection.
    #>

    Write-Host "Disabling Remote Desktop."

    try {
        # Disable RDP connections by setting fDenyTSConnections to 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue
        Write-Host "Remote Desktop connections have been disabled."
    } catch {
        Write-Host "Failed to disable Remote Desktop connections: $_" -ForegroundColor Red
    }

    try {
        # Disable firewall rules related to Remote Desktop
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        Write-Host "Remote Desktop firewall rules have been disabled."
    } catch {
        Write-Host "Failed to disable Remote Desktop firewall rules: $_" -ForegroundColor Red
    }

    Write-Host "Disabling Remote Desktop Services."

    try {
        # Stop and disable the Remote Desktop service (TermService)
        Stop-Service "TermService" -ErrorAction SilentlyContinue
        Set-Service "TermService" -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "Remote Desktop Services have been disabled."
    } catch {
        Write-Host "Failed to disable Remote Desktop Services: $_" -ForegroundColor Red
    }
}



function AcceptedPrivacyPolicy {
    Write-Output "Turning off AcceptedPrivacyPolicy."

    try {
        # Disable AcceptedPrivacyPolicy by setting it to 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        Write-Host "AcceptedPrivacyPolicy has been turned off successfully."
    } catch {
        Write-Host "Failed to turn off AcceptedPrivacyPolicy: $_" -ForegroundColor Red
    }
}



function DisableActivityHistory {
    Write-Host "Disabling activity history."

    try {
        # Ensure registry path exists and disable activity history-related settings
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
        }

        # Disable activity feed, user activity publishing, and uploading
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        Write-Host "Activity history settings disabled successfully."
    } catch {
        Write-Host "Failed to disable activity history settings: $_" -ForegroundColor Red
    }

    try {
        # Disable local device search history
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        Write-Host "Device search history disabled successfully."
    } catch {
        Write-Host "Failed to disable device search history: $_" -ForegroundColor Red
    }

    Write-Host "Disabling Shared Experiences."
    try {
        # Disable Shared Experiences
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        Write-Host "Shared Experiences disabled successfully."
    } catch {
        Write-Host "Failed to disable Shared Experiences: $_" -ForegroundColor Red
    }
}



function DisableAdvertisingID {
    Write-Host "Disabling Advertising ID."

    try {
        # Ensure the registry path exists for AdvertisingInfo
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
        }

        # Set the Advertising ID to be disabled by group policy
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue
        Write-Host "Advertising ID has been disabled successfully."
    } catch {
        Write-Host "Failed to disable Advertising ID: $_" -ForegroundColor Red
    }
}



function DisableAdvertisingInfo {
    Write-Output "Disabling Windows Feedback Experience program."

    try {
        # Ensure the registry path exists
        $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        If (!(Test-Path $Advertising)) {
            New-Item -Path $Advertising -Force | Out-Null
        }

        # Disable the Advertising Info feature
        Set-ItemProperty -Path $Advertising -Name "Enabled" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        Write-Host "Advertising Info has been disabled successfully."
    } catch {
        Write-Host "Failed to disable Advertising Info: $_" -ForegroundColor Red
    }
}



function DisableAppDiagnostics {
    Write-Output "Turning off AppDiagnostics."

    try {
        # Ensure the registry path exists
        $AppDiagnosticsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"
        If (!(Test-Path $AppDiagnosticsPath)) {
            New-Item -Path $AppDiagnosticsPath -Force | Out-Null
        }

        # Set the Value to "Deny" to disable app diagnostics
        Set-ItemProperty -Path $AppDiagnosticsPath -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue
        Write-Host "App Diagnostics has been disabled successfully."
    } catch {
        Write-Host "Failed to disable App Diagnostics: $_" -ForegroundColor Red
    }
}


Function DisableCEIP {
    
    <#
	The program collects information about computer hardware and how you use Microsoft Application Virtualization without interrupting you.
	This helps Microsoft identify which Microsoft Application Virtualization features to improve.
	No information collected is used to identify or contact you.
	#>

    Write-Host "Disabling Microsoft Customer Experience Improvement Program (CEIP)."

    # CEIP for Application Virtualization (App-V) - WOW6432Node
    $SQMClient1 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient"
    If (Test-Path $SQMClient1) {
        Set-ItemProperty -Path $SQMClient1 -Name "CEIPEnable" -Type DWord -Value 0x00000000 -ErrorAction SilentlyContinue
        Write-Host "CEIP disabled for SQMClient (WOW6432Node)."
    }

    # CEIP policy in general Windows policies
    $SQMClient2 = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
    If (!(Test-Path $SQMClient2)) {
        New-Item -Path $SQMClient2 -Force | Out-Null
    }
    Set-ItemProperty -Path $SQMClient2 -Name "CEIPEnable" -Type DWord -Value 0x00000000 -ErrorAction SilentlyContinue
    Write-Host "CEIP disabled for Windows policies."

    # CEIP for Microsoft SQMClient
    $SQMClient3 = "HKLM:\Software\Microsoft\SQMClient\Windows"
    If (Test-Path $SQMClient3) {
        Set-ItemProperty -Path $SQMClient3 -Name "CEIPEnable" -Type DWord -Value 0x00000000 -ErrorAction SilentlyContinue
        Write-Host "CEIP disabled for SQMClient."
    }

    # CEIP for Microsoft SQMClient - Unattend Settings
    $SQMClient4 = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UnattendSettings\SQMClient"
    If (Test-Path $SQMClient4) {
        Set-ItemProperty -Path $SQMClient4 -Name "CEIPEnabled" -Type DWord -Value 0x00000000 -ErrorAction SilentlyContinue
        Write-Host "CEIP disabled for unattend settings."
    }

    # CEIP for App-V
    $AppVCEIP = "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP"
    If (!(Test-Path $AppVCEIP)) {
        New-Item -Path $AppVCEIP -Force | Out-Null
    }
    Set-ItemProperty -Path $AppVCEIP -Name "CEIPEnable" -Type DWord -Value 0x00000000 -ErrorAction SilentlyContinue
    Write-Host "CEIP disabled for App-V."

    # CEIP for Internet Explorer
    $IECEIP = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM"
    If (!(Test-Path $IECEIP)) {
        New-Item -Path $IECEIP -Force | Out-Null
    }
    Set-ItemProperty -Path $IECEIP -Name "DisableCustomerImprovementProgram" -Type DWord -Value 0x00000000 -ErrorAction SilentlyContinue
    Write-Host "CEIP disabled for Internet Explorer."

    # Optional: Remove Microsoft Messenger CEIP, although it's outdated
    $MessengerCEIP = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
    If (!(Test-Path $MessengerCEIP)) {
        New-Item -Path $MessengerCEIP -Force | Out-Null
    }
    Set-ItemProperty -Path $MessengerCEIP -Name "CEIP" -Type DWord -Value 0x00000002 -ErrorAction SilentlyContinue
    Write-Host "CEIP disabled for Microsoft Messenger (deprecated)."
}


Function DisableTelemetryTasks {
	Write-Host "Disabling Telemetry Tasks."
	
    # This process is periodically collecting a variety of technical data about your computer and its performance and sending it to Microsoft for its Windows Customer Experience Improvement Program.

	# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection-reference?view=o365-worldwide

	# Block CompatTelRunner.exe
	If (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) {
		New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 
	Write-Host "Blocked CompatTelRunner.exe in registry."

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 
	Write-Host "Blocked CompatTelRunner.exe (WOW6432Node) in registry."

	# Disable CompatTelRunner scheduled tasks
	if(Get-ScheduledTask "CompatTelRunner" -ErrorAction Ignore) { 
		Get-ScheduledTask "CompatTelRunner" | Stop-ScheduledTask
		Get-ScheduledTask "CompatTelRunner" | Disable-ScheduledTask
		Write-Host "Disabled CompatTelRunner task."
	} else { 
		Write-Host 'CompatTelRunner task does not exist on this device.' 
	}

	# Block DeviceCensus.exe
	If (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe")) {
		New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 
	Write-Host "Blocked DeviceCensus.exe in registry."

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 
	Write-Host "Blocked DeviceCensus.exe (WOW6432Node) in registry."

	# Additional telemetry-related tasks
	$additionalTasks = @("Microsoft Compatibility Appraiser", "ProgramDataUpdater")
	foreach ($task in $additionalTasks) {
		if(Get-ScheduledTask $task -ErrorAction Ignore) {
			Get-ScheduledTask $task | Stop-ScheduledTask
			Get-ScheduledTask $task | Disable-ScheduledTask
			Write-Host "Disabled scheduled task: $task."
		} else {
			Write-Host "$task task does not exist on this device."
		}
	}
}


Function DisableErrorReporting {
    Write-Output "Disabling Windows Error Reporting for better system response speed."

    # Desabilita o Windows Error Reporting
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Type DWord -Value 0x00000000

        # Verifica e cria a chave de registro se não existir
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Type DWord -Value 0x00000001

        # Verifica e cria a chave WOW6432Node se não existir
        If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting")) {
            New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Type DWord -Value 0x00000001

        Write-Output "Windows Error Reporting has been disabled successfully."
    } catch {
        Write-Host "An error occurred while disabling Windows Error Reporting: $_" -ForegroundColor Red
    }
    
    # Esta função é complementar à função SetDoReport, que deve ser implementada para ativar novamente o Relatório de Erros, se necessário.
}


Function SetDoReport {
    Write-Output "Disabling Windows Error Reporting for better system response speed."

    # Verifica e cria a chave de registro se não existir
    try {
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Type DWord -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "ShowUI" -Type DWord -Value 0x00000000

        # Verifica e cria a chave WOW6432Node se não existir
        If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\PCHealth\ErrorReporting")) {
            New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\PCHealth\ErrorReporting" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Type DWord -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\PCHealth\ErrorReporting" -Name "ShowUI" -Type DWord -Value 0x00000000

        # Verifica e cria a chave de serviço se não existir
        If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport")) { 
            New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -Type DWord -Value 0x00000004  # Desativa o serviço

        Write-Output "Windows Error Reporting has been disabled successfully."
    } catch {
        Write-Host "An error occurred while disabling Windows Error Reporting: $_" -ForegroundColor Red
    }

    # Esta função é complementar à função DisableErrorReporting, que deve ser usada para ativar novamente o Relatório de Erros, se necessário.
}


Function DisableFeedbackExperience {

    Write-Output "Stopping Windows Feedback Experience and blocking feedback notifications."

    # Check and create registry paths for feedback data collection
    $Period1 = "HKCU:\Software\Microsoft\Siuf\Rules"
    $Period2 = "HKCU:\Software\Microsoft\Siuf"

    If (!(Test-Path $Period1)) { 
        If (!(Test-Path $Period2)) { 
            New-Item $Period2 -Force | Out-Null
        }
        New-Item $Period1 -Force | Out-Null
    }

    # Disable data collection by setting values to 0
    Set-ItemProperty $Period1 NumberOfSIUFInPeriod -Type DWord -Value 0x00000000
    Set-ItemProperty $Period1 PeriodInNanoSeconds -Type DWord -Value 0x00000000
    Write-Host "Feedback collection has been disabled."

    # Disable feedback notifications via group policy
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
    }

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 0x00000001
    Write-Host "Feedback notifications have been disabled."

}


Function DisableLocationTracking {

    # Disabling this will break Microsoft Find My Device functionality.
    Write-Output "Disabling Location Tracking."

    # Disable and stop the Location Framework Service (lfsvc)
    Set-Service "lfsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "Location Framework Service disabled."

    # Modify registry values to disable location tracking
    $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"

    # Disable sensor permissions for location tracking
    If (!(Test-Path $SensorState)) {
        New-Item -Path $SensorState -Force | Out-Null
    }
    Set-ItemProperty -Path $SensorState -Name "SensorPermissionState" -Type DWord -Value 0x00000000
    Write-Host "Sensor permissions for location tracking disabled."

    # Disable location configuration
    If (!(Test-Path $LocationConfig)) {
        New-Item -Path $LocationConfig -Force | Out-Null
    }
    Set-ItemProperty -Path $LocationConfig -Name "Status" -Type DWord -Value 0x00000000
    Write-Host "Location configuration disabled."

    # Deny location access in the ConsentStore
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Write-Host "Location access denied for applications."
}


Function DisableTailoredExperiences {

    Write-Host "Disabling Tailored Experiences (Personalized Ads, Tips, and Recommendations based on Diagnostic Data)."

    # Disable Tailored Experiences using Group Policy
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 0x00000001
    Write-Host "Tailored experiences disabled via Group Policy."

    # Disable Tailored Experiences in Windows privacy settings
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0x00000000
    Write-Host "Tailored experiences disabled in privacy settings."
}

																							

function BlockTelemetrybyHosts {
    
    Write-Output "Blocking telemetry and tracking by adding entries to the hosts file."

    # Path to hosts file
    $hostsPath = "$Env:windir\System32\drivers\etc\hosts"
    
    # Backup path
    $backupPath = "$Env:windir\System32\drivers\etc\hosts.bak"
    
    # Create a backup if it doesn't already exist
    If (!(Test-Path $backupPath)) {
        Copy-Item -Path $hostsPath -Destination $backupPath -Force
        Write-Host "Backup of hosts file created at $backupPath."
    }

    # List of domains to block
    $TelemetryDomains = @"
# Microsoft Telemetry and Ads
127.0.0.1    activity.windows.com
127.0.0.1    ads.msn.com
127.0.0.1    analytics.microsoft.com
127.0.0.1    browser.events.data.msn.com
127.0.0.1    checkappexec.microsoft.com
127.0.0.1    data.microsoft.com
127.0.0.1    diagnostics.support.microsoft.com
127.0.0.1    edge.microsoft.com
127.0.0.1    eu-mobile.events.data.microsoft.com
127.0.0.1    feedback.windows.com
127.0.0.1    i1.services.social.microsoft.com
127.0.0.1    jp-mobile.events.data.microsoft.com
127.0.0.1    msftconnecttest.com
127.0.0.1    msftncsi.com
127.0.0.1    oca.microsoft.com
127.0.0.1    sb.scorecardresearch.com
127.0.0.1    scorecardresearch.com
127.0.0.1    settings-win.data.microsoft.com
127.0.0.1    telemetry.microsoft.com
127.0.0.1    telemetry.urs.microsoft.com
127.0.0.1    uk-mobile.events.data.microsoft.com
127.0.0.1    us-mobile.events.data.microsoft.com
127.0.0.1    v10.vortex.data.microsoft.com
127.0.0.1    v10.vortex-win.data.microsoft.com
127.0.0.1    v20.vortex.data.microsoft.com
127.0.0.1    v20.vortex-win.data.microsoft.com
127.0.0.1    vortex.data.microsoft.com
127.0.0.1    vortex-win.data.microsoft.com
127.0.0.1    watson.microsoft.com

# Apple Telemetry
127.0.0.1    analytics.apple.com
127.0.0.1    api-glb-crashlytics.itunes.apple.com
127.0.0.1    config.push.apple.com
127.0.0.1    e.crashlytics.com
127.0.0.1    events.apple.com
127.0.0.1    experience.apple.com
127.0.0.1    gateway.push.apple.com
127.0.0.1    gsp10-ssl.ls.apple.com
127.0.0.1    gsp11-ssl.ls.apple.com
127.0.0.1    icloud-content.com
127.0.0.1    init-p01md.apple.com
127.0.0.1    metrics.apple.com
127.0.0.1    radarsubmissions.apple.com
127.0.0.1    sp.analytics.itunes.apple.com
127.0.0.1    telemetry.apple.com

# Google Ads and Telemetry
127.0.0.1    ad.doubleclick.net
127.0.0.1    ads.google.com
127.0.0.1    adservice.google.co.in
127.0.0.1    adservice.google.com
127.0.0.1    adservice.google.com.ar
127.0.0.1    adservice.google.com.au
127.0.0.1    adservice.google.com.co
127.0.0.1    adservice.google.com.mx
127.0.0.1    adservice.google.com.tr
127.0.0.1    adssettings.google.com
127.0.0.1    beacon.google.com
127.0.0.1    beacon.scorecardresearch.com
127.0.0.1    doubleclick.net
127.0.0.1    googleads.g.doubleclick.net
127.0.0.1    googleadservices.com
127.0.0.1    google-analytics.com
127.0.0.1    googleoptimize.com
127.0.0.1    googletagmanager.com
127.0.0.1    pagead2.googlesyndication.com
127.0.0.1    secure-us.imrworldwide.com
127.0.0.1    ssl.google-analytics.com
127.0.0.1    stats.g.doubleclick.net
127.0.0.1    tagmanager.google.com
127.0.0.1    tags.tiqcdn.com
127.0.0.1    www.google-analytics.com

# Facebook Ads and Tracking
127.0.0.1    adaccount.instagram.com
127.0.0.1    ads.facebook.com
127.0.0.1    connect.facebook.net
127.0.0.1    graph.facebook.com
127.0.0.1    instagram.com/ads
127.0.0.1    l.facebook.com
127.0.0.1    marketing-api.facebook.com
127.0.0.1    pixel.facebook.com
127.0.0.1    tr.facebook.com
127.0.0.1    tracking.facebook.com

# Mozilla Telemetry
127.0.0.1    blocklists.settings.services.mozilla.com
127.0.0.1    crash-stats.mozilla.com
127.0.0.1    data.mozilla.com
127.0.0.1    fxmetrics.mozilla.com
127.0.0.1    incoming.telemetry.mozilla.org
127.0.0.1    shavar.services.mozilla.com
127.0.0.1    telemetry.mozilla.org

# General Ads and Telemetry
127.0.0.1    ads.linkedin.com
127.0.0.1    ads.pinterest.com
127.0.0.1    ads.twitter.com
127.0.0.1    ads.yahoo.com
127.0.0.1    adserver.adtechus.com
127.0.0.1    adssettings.yahoo.com
127.0.0.1    analytics.snapchat.com
127.0.0.1    analytics.tiktok.com
127.0.0.1    app-measurement.com
127.0.0.1    atdmt.com
127.0.0.1    beacon.scorecardresearch.com
127.0.0.1    cdn.ampproject.org
127.0.0.1    chartbeat.com
127.0.0.1    edge-metrics.com
127.0.0.1    engine.adzerk.net
127.0.0.1    hotjar.com
127.0.0.1    logs.tiktokv.com
127.0.0.1    m.stripe.network
127.0.0.1    matomo.cloud
127.0.0.1    media6degrees.com
127.0.0.1    openx.net
127.0.0.1    pagead.l.doubleclick.net
127.0.0.1    pixel.quantserve.com
127.0.0.1    quantserve.com
127.0.0.1    scorecardresearch.com
127.0.0.1    secure-us.imrworldwide.com
127.0.0.1    ssl.google-analytics.com
127.0.0.1    stats.wordpress.com
127.0.0.1    tags.tiqcdn.com
127.0.0.1    tracking-proxy-prod.msn.com
127.0.0.1    yieldmanager.com

# End of list of domains to block
"@

    # Append the telemetry list to the hosts file
    Add-Content -Path $hostsPath -Value $TelemetryDomains
    Write-Host "Telemetry domains have been blocked in the hosts file."

    <#
    Principais Domínios de Telemetria da Microsoft:
    Incluímos uma lista ampliada de domínios, como vortex, telemetry, settings, msftconnecttest, e muito mais, que são conhecidos por coleta de dados ou envio de telemetria.

    Serviços de Publicidade:
    Bloqueio de serviços de publicidade, como ads.msn.com, adnexus.net, ad.doubleclick.net, para evitar rastreamento de anúncios.

    Serviços de Diagnóstico:
    Bloqueio de diagnostics.support.microsoft.com, feedback.windows.com, e outros.

    MSN e Bing:
    Bloqueio de bingapis.com, edge.microsoft.com, msn.com, para evitar conexões indesejadas.
    
    Apple (macOS e iOS):
    Adicionamos telemetry.apple.com, metrics.apple.com, e alguns servidores SSL da Apple, conhecidos por coleta de dados em dispositivos Apple.

    Plataformas Gerais:
    Vários domínios relacionados ao Google, DoubleClick, Facebook e ScorecardResearch são incluídos, usados para rastreamento e telemetria em sistemas Linux e em navegadores de todos os sistemas operacionais.
    #>

}






 ###								   ###
 ###   Remove Third Party Telemetry    ###
 ###								   ###



function DisableMozillaFirefoxTelemetry {	

	Write-Host "Desabilitando a Telemetria do Mozilla Firefox."
	
	# Verifica se o caminho do registro existe, se não, cria o diretório de políticas do Firefox
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox")) { 
		New-Item "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Force | Out-Null
	}

	# Desativa a telemetria
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type DWord -Value 0x00000001

	# Desativa o agente que verifica se o Firefox é o navegador padrão
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type DWord -Value 0x00000001
}


function DisableGoogleChromeTelemetry {

	Write-Host "Desabilitando a Telemetria do Google Chrome."

	# Verifica e cria o caminho do registro para políticas do Google Chrome
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome")) { 
		New-Item "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
	}

	If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome")) { 
		New-Item "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome" -Force | Out-Null
	}

	# Desativa várias opções de telemetria e relatórios
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "UserFeedbackAllowed" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DeviceMetricsReportingEnabled" -Type DWord -Value 0x00000000

	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome" -Name "UserFeedbackAllowed" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome" -Name "DeviceMetricsReportingEnabled" -Type DWord -Value 0x00000000

	# The Software Reporter Tool (also known as Chrome Cleanup Tool and Software Removal Tool, the executable file is software_reporter_tool.exe), is a tool that Google distributes with the Google Chrome web browser. 
	# It is a part of Google Chrome's Clean up Computer feature which scans your computer for harmful software. If this tool finds any harmful app or extension which can cause problems, it removes them from your computer. 
	# Anything that interferes with a user's browsing experience may be removed by the tool.
	# Its disadvantages, high CPU load or privacy implications, may be reason enough to block it from running. This script will disable the software_reporter_tool.exe in a more cleaner way using Image File Execution Options Debugger value. 
	# Setting this value to an executable designed to kill processes disables it. Chrome won't re-enable it with almost each update.

	# Bloqueia o Google Chrome Software Reporter Tool
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Force | Out-Null
	}

	# Define o Debugger para o Software Reporter Tool para um comando que encerra o processo
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -Force 
}


function DisableCCleanerMonitoring {

	Write-Host "Disabling CCleaner Monitoring."

	<#	
	Since Avast acquired Piriform, the popular system cleaning software CCleaner has become bloated with malware, bundled PUPs (potentially unwanted programs), and an alarming amount of pop-up ads.
	If you're highly dependent on CCleaner, you can disable with this script the CCleaner Active Monitoring ("Active Monitoring" feature has been renamed to "Smart Cleaning"), 
	automatic Update check and download function, trial offer notifications, the new integrated Software Updater, and the privacy option to "Help Improve CCleaner by sending anonymous usage data."
	#>

	# Check and create the CCleaner registry path if it doesn't exist
	If (!(Test-Path "HKCU:\Software\Piriform\CCleaner")) { 
		New-Item "HKCU:\Software\Piriform\CCleaner" -Force | Out-Null
	}

	# Disable various CCleaner monitoring features
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "Monitoring" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HelpImproveCCleaner" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoring" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateAuto" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateCheck" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "CheckTrialOffer" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "(Cfg)GetIpmForTrial" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdater" -Type DWord -Value 0x00000000
	Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdaterIpm" -Type DWord -Value 0x00000000

	# Disable the scheduled CCleaner Update task if it exists
	if(Get-ScheduledTask 'CCleaner Update' -ErrorAction Ignore) { 
		Get-ScheduledTask 'CCleaner Update' | Stop-ScheduledTask 
		Get-ScheduledTask 'CCleaner Update' | Disable-ScheduledTask 
	} else { 
		Write-Host 'CCleaner Update task does not exist on this device.'
	}

	# Disable the CCleaner UAC skip task if it exists
	$tempCCleaner = 'CCleanerSkipUAC - ' + $env:USERNAME
	if(Get-ScheduledTask $tempCCleaner -ErrorAction Ignore) { 
		Get-ScheduledTask $tempCCleaner | Stop-ScheduledTask 
		Get-ScheduledTask $tempCCleaner | Disable-ScheduledTask 
	} else { 
		Write-Host 'CCleanerSkipUAC task does not exist on this device.'
	}
}


function DisableMediaPlayerTelemetry {

	Write-Host "Disabling Media Player Telemetry."

	# Disable usage tracking for Windows Media Player
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type DWord -Value 0x00000000

	# Create Policies registry path if it doesn't exist
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer")) { 
		New-Item "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
	}

	# Disable metadata retrieval for CDs, DVDs, and music files
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type DWord -Value 0x00000001
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type DWord -Value 0x00000001

	# Create WMDRM registry path if it doesn't exist
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM")) { 
		New-Item "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Force | Out-Null
	}

	# Disable online features for WMDRM
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 0x00000001

	# Disable the Windows Media Player Network Sharing Service
	Set-Service "WMPNetworkSvc" -StartupType Disabled -ErrorAction SilentlyContinue
}


function DisableMicrosoftOfficeTelemetry {
	
	Write-Host "Disabling Microsoft Office Telemetry."

	# This will disable Microsoft Office telemetry (supports Microsoft Office 2013 and 2016)

	# Create necessary registry paths if they don't exist
	New-Item "HKCU:\SOFTWARE\Microsoft\Office\Common" -Force | Out-Null
	New-Item "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Force | Out-Null

	New-Item "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Force | Out-Null
	New-Item "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Force | Out-Null

	New-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Force | Out-Null
	New-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Force | Out-Null
	New-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Force | Out-Null

	# Disable telemetry settings for Office 2013
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Name "QMEnable" -Type DWord -Value 0x00000000											  # Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Name "Enabled" -Type DWord -Value 0x00000000									  # Win11 Home NA	LTSC NA
	
	# Disable telemetry settings for Office 2016
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Name "QMEnable" -Type DWord -Value 0x00000000											  # Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "DisableTelemetry" -Type DWord -Value 0x00000001					  # Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Name "Enabled" -Type DWord -Value 0x00000000									  # Win11 Home NA	LTSC NA

	# Disable telemetry in common client settings
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Type DWord -Value 0x00000001						  # Win11 Home NA	LTSC NA

	# Disable any existing scheduled tasks related to Office Telemetry
	if(Get-ScheduledTask "OfficeTelemetry*" -ErrorAction Ignore) { 
		Get-ScheduledTask "OfficeTelemetry*" | Stop-ScheduledTask 
		Get-ScheduledTask "OfficeTelemetry*" | Disable-ScheduledTask 
	} else { 
		Write-Host 'OfficeTelemetryAgentFallBack task does not exist on this device.' 
	}
}




#########################################################################################################################################################################################################
#########################################################################################################################################################################################################
#########################################################################################################################################################################################################
#########################################################################################################################################################################################################
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
		New-Item "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Force | Out-Null															  # Win11 Home NA	LTSC NA
	}

	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup")) { 
		New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Force | Out-Null													  # Win11 Home NA	LTSC NA
	}
	
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer")) { 
		New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" -Force | Out-Null														  # Win11 Home NA	LTSC NA
	}

	Set-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" -Name "OptInOrOutPreference" -Type DWord -Value 0x00000000		  # Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Name "SendTelemetryData" -Type DWord -Value 0x00000000	  # Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" -Name "Start" -Type DWord -Value 0x00000004					  # Win11 Home NA	LTSC NA

}



 ###				 ###
 ###	System		 ###
 ###				 ###



Function RemoveScheduledTasks {
	
	Write-Output "`n"
	Write-Output "`nDisabling scheduled tasks that are considered unnecessary."
	Write-Output "...If nothing happens within 30 seconds, please close this window and run the script again.`n"
	Write-Output "`n"


	 # See more at http://wiki.webperfect.ch/index.php?title=Windows_Telemetry



	Write-Output "Disabling scheduled group telemetry."

	if(Get-ScheduledTask Consolidator -ErrorAction Ignore) { Get-ScheduledTask  Consolidator | Stop-ScheduledTask ; Get-ScheduledTask  Consolidator | Disable-ScheduledTask } else { 'Consolidator task does not exist on this device.'}		  # Win11 Home Ready		collects and sends usage data to Microsoft (if the user has consented to participate in the CEIP)
	if(Get-ScheduledTask KernelCeipTask -ErrorAction Ignore) { Get-ScheduledTask  KernelCeipTask | Stop-ScheduledTask ; Get-ScheduledTask  KernelCeipTask | Disable-ScheduledTask } else { 'KernelCeipTask does not exist on this device.'}		  # Win11 Home NA		collects additional information related to customer experience and sends it to Microsoft (if the user consented to participate in the Windows CEIP)
	if(Get-ScheduledTask UsbCeip -ErrorAction Ignore) { Get-ScheduledTask  UsbCeip | Stop-ScheduledTask ; Get-ScheduledTask  UsbCeip | Disable-ScheduledTask } else { 'UsbCeip task does not exist on this device.'}							  # Win11 Home Ready
	if(Get-ScheduledTask Sqm-Tasks -ErrorAction Ignore) { Get-ScheduledTask  Sqm-Tasks | Stop-ScheduledTask ; Get-ScheduledTask  Sqm-Tasks | Disable-ScheduledTask } else { 'Sqm-Tasks task does not exist on this device.'}
	if(Get-ScheduledTask BthSQM -ErrorAction Ignore) { Get-ScheduledTask  BthSQM | Stop-ScheduledTask ; Get-ScheduledTask  BthSQM | Disable-ScheduledTask } else { 'BthSQM task does not exist on this device.'}								  # Win11 Home NA		collects Bluetooth-related statistics and information about your machine and sends it to Microsoft (if you have consented to participate in the Windows CEIP). The information received is used to help.
	if(Get-ScheduledTask "Microsoft-Windows-DiskDiagnosticDataCollector" -ErrorAction Ignore) { Get-ScheduledTask  "Microsoft-Windows-DiskDiagnosticDataCollector" | Stop-ScheduledTask ; Get-ScheduledTask  "Microsoft-Windows-DiskDiagnosticDataCollector" | Disable-ScheduledTask } else { 'Microsoft-Windows-DiskDiagnosticDataCollector task does not exist on this device.'}
		

	Write-Output "Disabling collects data for Microsoft SmartScreen."
	if(Get-ScheduledTask SmartScreenSpecific -ErrorAction Ignore) { Get-ScheduledTask  SmartScreenSpecific | Stop-ScheduledTask ; Get-ScheduledTask  SmartScreenSpecific | Disable-ScheduledTask } else { 'SmartScreenSpecific task does not exist on this device.'}	  # Win11 Home NA


	Write-Output "Disabling scheduled customer experience improvement program."
	if(Get-ScheduledTask Proxy -ErrorAction Ignore) { Get-ScheduledTask  Proxy | Stop-ScheduledTask ; Get-ScheduledTask  Proxy | Disable-ScheduledTask } else { 'Proxy task does not exist on this device.'}														  # Win11 Home Ready		collects and uploads Software Quality Management (SQM) data if opted-in to the CEIP
	if(Get-ScheduledTask ProgramDataUpdater -ErrorAction Ignore) { Get-ScheduledTask  ProgramDataUpdater | Stop-ScheduledTask ; Get-ScheduledTask  ProgramDataUpdater | Disable-ScheduledTask } else { 'ProgramDataUpdater task does not exist on this device.'}	  # Win11 Home NA		collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program (CEIP)

	if(Get-ScheduledTask 'Microsoft Compatibility Appraiser' -ErrorAction Ignore) { Get-ScheduledTask  'Microsoft Compatibility Appraiser' | Stop-ScheduledTask ; Get-ScheduledTask  'Microsoft Compatibility Appraiser' | Disable-ScheduledTask } else { 'Microsoft Compatibility Appraiser task does not exist on this device.'}	 # Win11 Home Ready		collects program telemetry information if opted-in to the CEIP
	if(Get-ScheduledTask MareBackup -ErrorAction Ignore) { Get-ScheduledTask  MareBackup | Stop-ScheduledTask ; Get-ScheduledTask  MareBackup | Disable-ScheduledTask } else { 'MareBackup task does not exist on this device.'}
	 # if(Get-ScheduledTask PcaPatchDbTask -ErrorAction Ignore) { Get-ScheduledTask  PcaPatchDbTask | Stop-ScheduledTask ; Get-ScheduledTask  PcaPatchDbTask | Disable-ScheduledTask } else { 'PcaPatchDbTask task does not exist on this device.'}
	 # if(Get-ScheduledTask SdbinstMergeDbTask -ErrorAction Ignore) { Get-ScheduledTask  SdbinstMergeDbTask | Stop-ScheduledTask ; Get-ScheduledTask  SdbinstMergeDbTask | Disable-ScheduledTask } else { 'SdbinstMergeDbTask task does not exist on this device.'}
	if(Get-ScheduledTask StartupAppTask -ErrorAction Ignore) { Get-ScheduledTask  StartupAppTask | Stop-ScheduledTask ; Get-ScheduledTask  StartupAppTask | Disable-ScheduledTask } else { 'StartupAppTask does not exist on this device.'}							  # Win11 Home Ready
	
	if(Get-ScheduledTask Uploader -ErrorAction Ignore) { Get-ScheduledTask  Uploader | Stop-ScheduledTask ; Get-ScheduledTask  Uploader | Disable-ScheduledTask } else { 'Uploader task does not exist on this device.'}											  # Win11 Home NA


	Write-Output "Disabling scheduled feedback."
	if(Get-ScheduledTask DmClient -ErrorAction Ignore) { Get-ScheduledTask  DmClient | Stop-ScheduledTask ; Get-ScheduledTask  DmClient | Disable-ScheduledTask } else { 'DmClient task does not exist on this device.'}											  # Win11 Home Ready
	if(Get-ScheduledTask DmClientOnScenarioDownload -ErrorAction Ignore) { Get-ScheduledTask  DmClientOnScenarioDownload | Stop-ScheduledTask ; Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask } else { 'DmClientOnScenarioDownload task does not exist on this device.'}	  # Win11 Home Ready


	Write-Output "Disabling scheduled windows system assessment tool."
	if(Get-ScheduledTask WinSAT -ErrorAction Ignore) { Get-ScheduledTask  WinSAT | Stop-ScheduledTask ; Get-ScheduledTask  WinSAT | Disable-ScheduledTask } else { 'WinSAT task does not exist on this device.'}																	  # Win11 Home Ready		measures system performance and capabilities


	Write-Output "Disabling scheduled family safety settings."
	if(Get-ScheduledTask FamilySafetyMonitor -ErrorAction Ignore) { Get-ScheduledTask  FamilySafetyMonitor | Stop-ScheduledTask ; Get-ScheduledTask  FamilySafetyMonitor | Disable-ScheduledTask } else { 'FamilySafetyMonitor task does not exist on this device.'}				  # Win11 Home Ready		initializes family safety monitoring and enforcement
	if(Get-ScheduledTask FamilySafetyRefresh* -ErrorAction Ignore) { Get-ScheduledTask  FamilySafetyRefresh* | Stop-ScheduledTask ; Get-ScheduledTask  FamilySafetyRefresh* | Disable-ScheduledTask } else { 'FamilySafetyRefresh task does not exist on this device.'}				  # Win11 Home Ready		synchronizes the latest settings with the family safety website


	Write-Output "Disabling scheduled collects network information."
	if(Get-ScheduledTask GatherNetworkInfo -ErrorAction Ignore) { Get-ScheduledTask  GatherNetworkInfo | Stop-ScheduledTask ; Get-ScheduledTask  GatherNetworkInfo | Disable-ScheduledTask } else { 'GatherNetworkInfo task does not exist on this device.'}						  # Win11 Home Ready		collects network information

	Write-Output "Disabling scheduled legacy tasks."
	if(Get-ScheduledTask AitAgent -ErrorAction Ignore) { Get-ScheduledTask  AitAgent | Stop-ScheduledTask ; Get-ScheduledTask  AitAgent | Disable-ScheduledTask } else { 'AitAgent task does not exist on this device.'}															  # Win11 Home NA	aggregates and uploads application telemetry information if opted-in to the CEIP
	if(Get-ScheduledTask ScheduledDefrag -ErrorAction Ignore) { Get-ScheduledTask  ScheduledDefrag | Stop-ScheduledTask ; Get-ScheduledTask  ScheduledDefrag | Disable-ScheduledTask } else { 'ScheduledDefrag task does not exist on this device.'}								  # Win11 Home Ready
	if(Get-ScheduledTask 'SQM data sender' -ErrorAction Ignore) { Get-ScheduledTask  'SQM data sender' | Stop-ScheduledTask ; Get-ScheduledTask  'SQM data sender' | Disable-ScheduledTask } else { 'SQM Data Sender task does not exist on this device.'}							  # Win11 Home NA	sends SQM data to Microsoft
	if(Get-ScheduledTask *DiskDiagnostic* -ErrorAction Ignore) { Get-ScheduledTask  *DiskDiagnostic* | Stop-ScheduledTask ; Get-ScheduledTask  *DiskDiagnostic* | Disable-ScheduledTask } else { 'DiskDiagnosticResolver task does not exist on this device.'}	 					  # Win11 Home Ready	collects general disk and system information and sends it to Microsoft (if the user users participates in the CEIP)


	Write-Output "Disabling scheduled error reporting."
	if(Get-ScheduledTask QueueReporting -ErrorAction Ignore) { Get-ScheduledTask  QueueReporting | Stop-ScheduledTask ; Get-ScheduledTask  QueueReporting | Disable-ScheduledTask } else { 'QueueReporting task does not exist on this device.'}									  # Win11 Home Ready

	Write-Output "Disabling scheduled Power Efficiency Diagnostics."
	if(Get-ScheduledTask AnalyzeSystem -ErrorAction Ignore) { Get-ScheduledTask  AnalyzeSystem | Stop-ScheduledTask ; Get-ScheduledTask  AnalyzeSystem | Disable-ScheduledTask } else { 'AnalyzeSystem task does not exist on this device.'}										  # Win11 Home Ready

	Write-Output "Disabling unnecessary HP Omen scheduled tasks."
	if(Get-ScheduledTask 'OmenInstallMonitor' -ErrorAction Ignore) { Get-ScheduledTask  'OmenInstallMonitor' | Stop-ScheduledTask ; Get-ScheduledTask  'OmenInstallMonitor' | Disable-ScheduledTask } else { 'OmenInstallMonitor Task does not exist on this device.'}
	if(Get-ScheduledTask 'OmenInstallMonitorCustomEvent' -ErrorAction Ignore) { Get-ScheduledTask  'OmenInstallMonitorCustomEvent' | Stop-ScheduledTask ; Get-ScheduledTask  'OmenInstallMonitorCustomEvent' | Disable-ScheduledTask } else { 'OmenInstallMonitorCustomEvent Task does not exist on this device.'}
	if(Get-ScheduledTask 'OmenOverlay' -ErrorAction Ignore) { Get-ScheduledTask  'OmenOverlay' | Stop-ScheduledTask ; Get-ScheduledTask  'OmenOverlay' | Disable-ScheduledTask } else { 'OmenOverlay Task does not exist on this device.'}
	if(Get-ScheduledTask 'OmenOverlayCustomEvent' -ErrorAction Ignore) { Get-ScheduledTask  'OmenOverlayCustomEvent' | Stop-ScheduledTask ; Get-ScheduledTask  'OmenOverlayCustomEvent' | Disable-ScheduledTask } else { 'OmenOverlayCustomEvent Task does not exist on this device.'}
	if(Get-ScheduledTask 'SystemOptimizer' -ErrorAction Ignore) { Get-ScheduledTask  'SystemOptimizer' | Stop-ScheduledTask ; Get-ScheduledTask  'SystemOptimizer' | Disable-ScheduledTask } else { 'SystemOptimizer Task does not exist on this device.'}
	if(Get-ScheduledTask 'SystemOptimizerCustomEvent' -ErrorAction Ignore) { Get-ScheduledTask  'SystemOptimizerCustomEvent' | Stop-ScheduledTask ; Get-ScheduledTask  'SystemOptimizerCustomEvent' | Disable-ScheduledTask } else { 'SystemOptimizerCustomEvent Task does not exist on this device.'}

	Write-Output "Disabling scheduled tasks From Third-Party Apps."
	if(Get-ScheduledTask 'Adobe Acrobat Update Task' -ErrorAction Ignore) { Get-ScheduledTask  'Adobe Acrobat Update Task' | Stop-ScheduledTask ; Get-ScheduledTask  'Adobe Acrobat Update Task' | Disable-ScheduledTask } else { 'Adobe Acrobat Update Task does not exist on this device.'}

	if(Get-ScheduledTask AMDInstallLauncher -ErrorAction Ignore) { Get-ScheduledTask  AMDInstallLauncher| Stop-ScheduledTask ; Get-ScheduledTask  AMDInstallLauncher | Disable-ScheduledTask } else { 'AMDInstallLauncher does not exist on this device.'}
	if(Get-ScheduledTask AMDRyzenMasterSDKTask -ErrorAction Ignore) { Get-ScheduledTask  AMDRyzenMasterSDKTask | Stop-ScheduledTask ; Get-ScheduledTask  AMDRyzenMasterSDKTask | Disable-ScheduledTask } else { 'AMDRyzenMasterSDKTask does not exist on this device.'}
	if(Get-ScheduledTask AMDScoSupportTypeUpdate -ErrorAction Ignore) { Get-ScheduledTask  AMDScoSupportTypeUpdate | Stop-ScheduledTask ; Get-ScheduledTask  AMDScoSupportTypeUpdate | Disable-ScheduledTask } else { 'AMDScoSupportTypeUpdate does not exist on this device.'}
	if(Get-ScheduledTask StartCN -ErrorAction Ignore) { Get-ScheduledTask  StartCN | Stop-ScheduledTask ; Get-ScheduledTask  StartCN | Disable-ScheduledTask } else { 'StartCN does not exist on this device.'}

	if(Get-ScheduledTask SystemOptimizer -ErrorAction Ignore) { Get-ScheduledTask  SystemOptimizer | Stop-ScheduledTask ; Get-ScheduledTask  SystemOptimizer | Disable-ScheduledTask } else { 'HP SystemOptimizer task does not exist on this device.'}
	if(Get-ScheduledTask 'Printer Health Monitor' -ErrorAction Ignore) { Get-ScheduledTask  'Printer Health Monitor' | Stop-ScheduledTask ; Get-ScheduledTask  'Printer Health Monitor' | Disable-ScheduledTask } else { 'HP Printer Health Monitor task does not exist on this device.'}							  # sends SQM data to Microsoft
	if(Get-ScheduledTask 'Printer Health Monitor Logon' -ErrorAction Ignore) { Get-ScheduledTask  'Printer Health Monitor Logon' | Stop-ScheduledTask ; Get-ScheduledTask  'Printer Health Monitor Logon' | Disable-ScheduledTask } else { 'HP Printer Health Monitor Logon task does not exist on this device.'}	  # sends SQM data to Microsoft

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
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "VDMDisallowed" -Type DWord -Value 0x00000001	  # Win11 Home NA	LTSC NA


	Write-Host "Turn off Application Compatibility Engine."
	
	<#
	Turning off the application compatibility engine will boost system performance.
	However, this will degrade the compatibility of many popular legacy applications,
	and will not block known incompatible applications from installing.
	(For Instance: This may result in a blue screen if an old anti-virus application is installed.)
	#>

	 # See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffEngine
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableEngine" -Type DWord -Value 0x00000001	  # Win11 Home NA	LTSC NA


	Write-Host "Turn off Application Telemetry."

	 # If the customer Experience Improvement program is turned off, Application Telemetry will be turned off regardless of how this policy is set.
	 # See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffApplicationImpactTelemetry
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0x00000000		  # Win11 Home NA	LTSC NA


	Write-Host "Turn off Inventory Collector."
	
	<#
	The Inventory Collector inventories applications, files, devices, and drivers on the system and sends the information to Microsoft.
	This information is used to help diagnose compatibility problems.
	#>

	 # See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffProgramInventory
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 0x00000001	  # Win11 Home NA	LTSC NA


	Write-Host "Turn off Program Compatibility Assistant."
	
	<#
	If you enable this policy setting, the PCA will be turned off.
	The user will not be presented with solutions to known compatibility issues when running applications.
	Turning off the PCA can be useful for system administrators who require better performance and are already aware of application compatibility issues.
	#>

	 # See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffProgramCompatibilityAssistant_2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisablePCA" -Type DWord -Value 0x00000001		  # Win11 Home NA	LTSC NA


	Write-Host "Turn off Steps Recorder."
	
	<#
	Steps Recorder keeps a record of steps taken by the user.
	The data generated by Steps Recorder can be used in feedback systems such as Windows Error Reporting
	to help developers understand and fix problems. The data includes user actions such as keyboard input and mouse input,
	user interface data, and screen shots. Steps Recorder includes an option to turn on and off data collection.
	#>

	 # See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffUserActionRecord
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type DWord -Value 0x00000001		  # Win11 Home NA	LTSC NA


	Write-Host "Turn off SwitchBack Compatibility Engine."
	
	<#
	If you enable this policy setting, Switchback will be turned off.
	Turning Switchback off may degrade the compatibility of older applications.
	This option is useful for server administrators who require performance and are aware of compatibility of the applications they are using.
	#>

	 # See more at https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ApplicationCompatibility::AppCompatTurnOffSwitchBack
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "SbEnable" -Type DWord -Value 0x00000000			  # Win11 Home NA	LTSC NA
}



 # The AutoplayHandler element specifies a UWP device app that should appear as the recommended AutoPlay action when a user plugs in a device.
Function DisableAutoplayHandler {
	
	Write-Output "Disabling AutoplayHandlers."
	
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0x00000001	  # Win11 Home 0		LTSC 1
}



Function DisableBingSearch {
	
	Write-Output "Disabling Bing Search in Start Menu."
	
	$WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	
	If (!(Test-Path $WebSearch)) {
		New-Item $WebSearch -Force | Out-Null
	}
	Set-ItemProperty $WebSearch DisableWebSearch -Type DWord -Value 0x00000001																	  # Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0x00000000		  # Win11 Home NA		LTSC NA

	$DisableSearchBox = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
	
	If (!(Test-Path $DisableSearchBox)) {
		New-Item $DisableSearchBox -Force | Out-Null
	}
	Set-ItemProperty $DisableSearchBox DisableSearchBoxSuggestions -Type DWord -Value 0x00000001												  # Win11 Home NA		LTSC NA
}



Function DisableCortanaSearch {
	
	Write-Output "Stopping Cortana from being used as part of your Windows Search Function."

	 # Cortana was deprecated in June 2023.
	
	$Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	If (!(Test-Path $Search)) {
		New-Item $Search -Force | Out-Null
	}
	Set-ItemProperty $Search AllowCortana -Type DWord -Value 0x00000000 																	  # Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "AllowCortana" -Type DWord -Value 0x00000000		  # Win11 Home NA		LTSC NA
}



Function PrintScreenToSnippingTool {
	
	Write-Output "Use print screen to open snipping tool."
	
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Type DWord -Value 0x00000001		 		 # Win11 Home NA		LTSC NA
}



Function DisableLiveTiles {
	
	Write-Output "Disabling live tiles."
	
	$Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
	If (!(Test-Path $Live)) {  
		New-Item $Live -Force | Out-Null
	}
	Set-ItemProperty $Live  NoTileApplicationNotification -Type DWord -Value 0x00000001															  # Win11 Home NA		LTSC NA
}



Function DisableWidgets {
	
	Write-Output "Disable and uninstall Widgets. The Widgets app runs in the background even with the option turned off."
	
    winget uninstall "windows web experience pack" --silent

}



function DisableBackgroundApp {
	
	 # Leaving Xiaomi Mi Blaze Unlock 'on' (8497DDF3*) you can continue using your band to unlock your computer.

	IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {Write-Host "Windows 10 Detected. -> Disabling All Background Application Access."
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 0x00000001	  # Win11 Home NA	LTSC NA
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -Type DWord -Value 0x00000000					  # Win11 Home NA	LTSC NA
		
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
	
	$CloudStore = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore"		  # Win11 Home (Folder Exist)
	 # $p = Get-Process -Name "explorer"
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
	
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name "Auto" -Type String -Value "0"					  # Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" -Name "Auto" -Type String -Value "0"		  # Win11 Home NA		LTSC NA
}



Function SetSplitThreshold {
	
	 # Obter a quantidade total de memória física instalada
	$InstalledMemory = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory
	$MemoryKB = [math]::Round($InstalledMemory / 1KB, 2)

	 # Determinar o valor a ser atribuído com base na quantidade de memória
	if ($MemoryKB -lt 400000) {
		$SvcHostSplitThresholdInKB = 0x380000  # Menos de 4 GB
	}
	elseif ($MemoryKB -lt 600000) {
		$SvcHostSplitThresholdInKB = 0x400000  # 4 GB
	}
	elseif ($MemoryKB -lt 800000) {
		$SvcHostSplitThresholdInKB = 0x600000  # 6 GB
	}
	elseif ($MemoryKB -lt 0xC00000) {
		$SvcHostSplitThresholdInKB = 0x800000  # 8 GB
	}
	elseif ($MemoryKB -lt 1000000) {
		$SvcHostSplitThresholdInKB = 0xc00000  # 12 GB
	}
	elseif ($MemoryKB -lt 1800000) {
		$SvcHostSplitThresholdInKB = 0x1000000  # 16 GB
	}
	elseif ($MemoryKB -lt 2000000) {
		$SvcHostSplitThresholdInKB = 0x1800000  # 24 GB
	}
	elseif ($MemoryKB -lt 4000000) {
		$SvcHostSplitThresholdInKB = 0x2000000  # 32 GB
	}
	else {
		$SvcHostSplitThresholdInKB = 0x4000000  # 64 GB ou mais
	}

	 # Definir o valor no registro do Windows
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $SvcHostSplitThresholdInKB	 # Win11 Home 0x00380000 (3670016)		LTSC 0x00380000 (3670016)
	Write-Output "Setting SvcHostSplitThresholdInKB to $SvcHostSplitThresholdInKB"

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
		fsutil behavior set memoryusage 2 	  # Win11 Home 1 	LTSC 1 (The default memory consumption values are used for caching NTFS metadata)
		
		Write-Output "Use big system memory caching to improve microstuttering."
	
		 # Yeah, that might sound the opposite of the project's objective, but that's right. Free up and optimize resources to the maximum and provide comfort for the system kernel simultaneously.
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 0x00000001	  # Win11 Home 0	LTSC 0
		
	} else {
    	Write-Host "The computer does not have more than 8 GB of RAM. This function will have the opposite effect in terms of performance gains on systems with low memory."
		fsutil behavior set memoryusage 1 	  # Win11 Home 1 	LTSC 1 (The default memory consumption values are used for caching NTFS metadata)

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
	Enable-MMAgent -mc -ErrorAction SilentlyContinue	  # Win11 Home Enabled
	
	 # Get-MMAgent
	 # Disable-MMAgent –MemoryCompression
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
			Set-ItemProperty -Path $Var -Name "Disable Performance Counters" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue		  # Default (Everything Enabled)
		}
	}
}



Function SetSystemResponsiveness {

	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" -Name "Priority" -Type DWord -Value 0x00000008
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" -Name "Scheduling Category" -Type String -Value "High"


	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 0x00000008
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value "High"

	Write-Host "Disabling System Crash Dump."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue


	 # Disable Camera Frame Server. It controls whether multiple applications can access the camera feed simultaneously.
	 # Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Media Foundation\Platform" -Name "EnableFrameServerMode" -Type DWord -Value 0x00000000
	 # Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Media Foundation\Platform" -Name "EnableFrameServerMode" -Type DWord -Value 0x00000000
	 # Enabling Camera Frame Server.
	 Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Media Foundation\Platform" -Name "EnableFrameServerMode" -Force -ErrorAction SilentlyContinue
	 Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Media Foundation\Platform" -Name "EnableFrameServerMode" -Force -ErrorAction SilentlyContinue

	 # https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service
	
	 # SystemResponsiveness determines the percentage of CPU resources that should be guaranteed to low-priority tasks (MMCSS).
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0x0000000a			  # Win11 Home 0x00000014 (20)	LTSC 0x00000014 (20)
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NoLazyMode" -Type DWord -Value 0x00000001					  # Win11 Home NA	LTSC NA
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Type DWord -Value 0x00000001						  # Win11 Home NA	LTSC NA


 # This is a complementary function to the SetSystemResponsiveness \ SomeKernelTweaks.
}



Function SomeKernelTweaks {

	Write-Output "Disable Meltdown/Spectre/Zombieload patches."
	
	 # ren mcupdate_GenuineIntel.dll to mcupdate_GenuineIntel.bak 
	 # ren mcupdate_AuthenticAMD.dll to mcupdate_AuthenticAMD.bak

	 # https://support.microsoft.com/en-us/topic/kb4072698-windows-server-and-azure-stack-hci-guidance-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-2f965763-00e2-8f98-b632-0d96f30c8c8e
	 # https://support.microsoft.com/en-us/topic/guidance-for-disabling-intel-transactional-synchronization-extensions-intel-tsx-capability-0e3a560c-ab73-11d2-12a6-ed316377c99c


	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Type DWord -Value 0x00000003			  # Win11 Home NA		LTSC NA
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Type DWord -Value 0x00000003		  # Win11 Home NA		LTSC NA

	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 1 /f
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f

	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableTsx" -Type DWord -Value 0x00000000								  # Win11 Home NA

	Write-Output "Disable 57-bits 5-level paging."
	bcdedit /set linearaddress57 OptOut | Out-Null
	
	 # Remove-WindowsCapability -Online -Name Microsoft-Windows-Kernel-LA57-FoD-Package~31bf3856ad364e35~amd64~~.0.0.1 -ErrorAction SilentlyContinue

	$capabilityName = "Microsoft-Windows-Kernel-LA57-FoD-Package"
	$cmd = "DISM.exe /Online /Remove-Capability /CapabilityName:$capabilityName"
	Start-Process -FilePath "powershell.exe" -ArgumentList "/c $cmd" -Verb RunAs -Wait

	 # https://community.amd.com/t5/archives-discussions/5-level-paging-and-57-bit-linear-address-stop-that-stupid/td-p/80014
	 # In short, if you use a cluster of 16 Hard Disks with 16 TBytes each (>256 TBytes) in your work, revert this option!  bcdedit /deletevalue linearaddress57 | Out-Null
	

	
	Write-Output "Disable automatic TCG/Opal disk locking on supported SSD drives with PSID."
	
	 # reg add HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices /v TCGSecurityActivationDisabled /t REG_DWORD /d 1 /f
	
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "TCGSecurityActivationDisabled" -Type DWord -Value 0x00000001			  # Win11 Home 0		LTSC 0
	
	 # Set this value to 1 to enable stronger protection on system base objects such as the KnownDLLs list.
	
	 # https://learn.microsoft.com/en-US/troubleshoot/windows-client/networking/system-error-85-net-use-command
	
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Type DWord -Value 0x00000000									  # Win11 Home 1		LTSC 1


	IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {Write-Host "Build greater than 22000 detected. Fixed requesting a higher resolution timer from Jurassic Period apps."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -Type DWord -Value 0x00000001				  # Win11 NA		LTSC NA
	} 

	 # https://github.com/amitxv/PC-Tuning/blob/main/docs/research.md#fixing-timing-precision-in-windows-after-the-great-rule-change


	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DistributeTimers" -Type DWord -Value 0x00000001				  			  # Win11 NA		LTSC NA



 # This is a complementary function to the SetSystemResponsiveness \ SomeKernelTweaks.
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
	
	powercfg -restoredefaultschemes
	Start-Sleep 1
	powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e

	Write-Host "Disabling Hibernation and Optimizing Performance on Balanced Performance scheme."
	
	<#
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type DWord -Value 0x00000000
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0x00000000
	#>

	Write-Output "Disabling Fast Startup."

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0x00000000		  # Win11 Home 1		LTSC 1


	 # Force enable "traditional" power plans
	 # reg add HKLM\System\CurrentControlSet\Control\Power /v PlatformAoAcOverride /t REG_DWORD /d 0
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Power" -Name "PlatformAoAcOverride" -Type DWord -Value 0x00000000					  # Win11 Home NA		LTSC NA


	 # Balanced Performance
	 # ActivePowerScheme is the GUID (Globally Unique Identifier) of the current active power plan for your account.
	powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e				  # Win11 Home Enabled


	 # High performance
	 # powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
	 # powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c


	 # Ultimate Performance
	 # powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
	 # powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61


	 # Disable display, disk, standby, hibernate timeouts 
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 3
	powercfg /X disk-timeout-ac 0
	powercfg /X disk-timeout-dc 3
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 30
	powercfg /X hibernate-timeout-ac 0
	powercfg /X hibernate-timeout-dc 0

	powercfg -h off			 # Win11 Home On

	<#
	Tuning CPU performance boost
	This feature determines how processors select a performance level when current operating conditions allow for boosting performance above the nominal level.
	See more at https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/hardware/power/power-performance-tuning
	See more at https://superuser.com/questions/1435110/why-does-windows-10-have-cpu-core-parking-disabled
	#>
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" -Name "Attributes" -Type DWord -Value 0x00000002	  # Win11 Home 1


	 # IF (Get-WmiObject -Class Win32_Processor | where {( $_.Manufacturer -like "*AMD*" ) -or ($_.Manufacturer -like "*Intel*")})

	IF (Get-ComputerInfo | where {( $_.PowerPlatformRole -like "*mobile*" )}) {
		
		Write-Host "Mobile platform detected. Disabling Performance Boost on Battery for less heat output and more sustainable performance over time providing full power to iGPU and dGPU."
		
		<#
		Load balancing should be automatic as both Intel and AMD have features for this and it usually works very well,
		but if your laptop/notebook/ultrabook makes more noise than an airplane's engines,
		you will be rewarded with performance slightly smaller on some tasks and better on some games and there will be an awkward silence.
		It will be another computer!
		#>

		IF (Get-WmiObject -Class Win32_Processor | where {( $_.Manufacturer -like "*AMD*" )}) {
			Write-Host "AMD CPU Detected. Changing Performance Boost to Aggressive."  # AMD CPUs with BOOST parameter other than "2" (Aggressive) usually disable Performance Boost completely. 
			Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2	  # Win11 Home 2 (Aggressive)
			Powercfg -setdcvalueindex scheme_current sub_processor PERFBOOSTMODE 0	  # Win11 Home 2 (Aggressive)
		}

		IF (Get-WmiObject -Class Win32_Processor | where {($_.Manufacturer -like "*Intel*")}) {
			Write-Host "Intel CPU Detected. Changing Performance Boost to Efficient Aggressive At Guaranteed." # Intel CPUs generally run very well with BOOST 6
			Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2	  # Win11 Home 2 (Aggressive)
			Powercfg -setdcvalueindex scheme_current sub_processor PERFBOOSTMODE 0	  # Win11 Home 2 (Aggressive)
		}
	}
	else {
		Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2		  # Default 2 (Aggressive)
		Powercfg -setdcvalueindex scheme_current sub_processor PERFBOOSTMODE 2		  # Default 2 (Aggressive)
	}


	 # Require a password on wakeup
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 0
	

	 # Turn off hard disk after
	 <#
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 300
	 #>

	 # JavaScript 
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 02f815b5-a5cf-4c84-bf20-649d1f75d3d8 4c793e7d-a264-42e1-87d3-7a0d2f523ccd 1
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 02f815b5-a5cf-4c84-bf20-649d1f75d3d8 4c793e7d-a264-42e1-87d3-7a0d2f523ccd 1
	

	 # Desktop background settings - Slide show
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 0
	

	 # Wireless Adapter Settings - Power Saving Mode
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 3
	

	 <#
	 # Sleep after - Never
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
	 #>


	 # Allow hybrid sleep - Off
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0
	

	 # Hibernate after
	 <#
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
	 #>


	 # Allow wake timers - No
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
	

	 # USB selective suspend setting - Off
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
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
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100
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
	

	 # Desligar Monitor
	 <#
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 180
	 #>


	 # Display brightness - %
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 100
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 50
	

	 # Dimmed display brightness - %
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 100
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 50
	

	 # When sharing media
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 03680956-93bc-4294-bba6-4e0f09bb717f 1
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 03680956-93bc-4294-bba6-4e0f09bb717f 1
	

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
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e f693fb01-e858-4f00-b20f-f30e12ac06d6 191f65b5-d45c-4a4f-8aae-1ab8bfd980e6 1  # Maximize Performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e f693fb01-e858-4f00-b20f-f30e12ac06d6 191f65b5-d45c-4a4f-8aae-1ab8bfd980e6 0  # Optimize Battery
	

	 # Switchable Dynamic Graphics
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 2  # Maximize performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 1  # Optimize power savings
	

	 # AMD Power Slider
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 3  # Best performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 0  # Battery saver


	 # Intel(R) Graphics Power Plan 
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 2  # Maximum Performance
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 0  # Maximum Battery Life


	 # Intel(R) Dynamic Tuning Settings
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 48df9d60-4f68-11dc-8314-0800200c9a66 07029cd8-4664-4698-95d8-43b2e9666596 0  # 25.0W @ 2.1GHz (Max Value)
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 48df9d60-4f68-11dc-8314-0800200c9a66 07029cd8-4664-4698-95d8-43b2e9666596 2  # 10.0W @ 0.8GHz (Min Value)


	 # Hidden New CPU Optimizations
	 # Processor performance autonomous mode
	 # Specify whether processors should autonomously determine their target performance state.
	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\8baa4a8a-14c6-4451-8e8b-14bdbd197537" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFAUTONOMOUS 1  # Default 1
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFAUTONOMOUS 1  # Default 1	


	 <#
	 # Processor idle demote threshold
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119" -Name "Attributes" -Type DWord -Value 0x00000001
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 4b92d758-5a24-4851-a470-815d78aee119  40  # Default 40
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 4b92d758-5a24-4851-a470-815d78aee119  20  # Default 20

	
	 # Processor idle promote threshold
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c" -Name "Attributes" -Type DWord -Value 0x00000001
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 7b224883-b3cc-4d79-819f-8374152cbe7c  60  # Default 60
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 7b224883-b3cc-4d79-819f-8374152cbe7c  40  # Default 40
	 #>


	 # Core Parking allows your processors to go into a sleep mode. The main purposes of core parking is to allow the computer/laptop/device to only use the processors when required, thus saving on energy.
	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100  # Default 100
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 25   # Default 25
	
	
	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES 100  # Default 100
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES 100  # Default 100


	 # Processor performance core parking utility distribution.
	 # Specify whether the core parking engine should distribute utility across processors.
	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\e0007330-f589-42ed-a401-5ddb10e785d3" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL 0  # High performance - disabled
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL 0  # High performance - disabled


	 # Processor energy performance preference policy(Percent). Specify how much processors should favor energy savings over performance when operating in autonomous mode.
	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\36687f9e-e3a5-4dbf-b1dc-15eb381c6863" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFEPP 0   # Default 25 
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFEPP 60  # Default 60

	
	 # The Processor Performance Boost Policy is a percentage value from 0 to 100(hexa:00000064). In the default Balanced power plan this parameter is 35 percent and any value lower than 51 disables Turbo Boost.
	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59" -Name "Attributes" -Type DWord -Value 0x00000002
	powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL 100  # Default 60
	powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTPOL 100  # Default 40


	 # Processor performance time check interval
	 # Specifies the duration, in milliseconds, between subsequent evaluations of the processor performance state and Core Parking algorithms.
	powercfg -attributes 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 -ATTRIB_HIDE
	powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 5000  # 15
	powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 5000  # 30
	

	 # Processor idle time check
	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c4581c31-89ab-4597-8e2b-9c9cab440e6b" -Name "Attributes" -Type DWord -Value 0x00000002
	<# 
	 powercfg -attributes 54533251-82be-4824-96c1-47b60b740d00 c4581c31-89ab-4597-8e2b-9c9cab440e6b -ATTRIB_HIDE
	 powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 c4581c31-89ab-4597-8e2b-9c9cab440e6b 100000  # 50000
	 powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 54533251-82be-4824-96c1-47b60b740d00 c4581c31-89ab-4597-8e2b-9c9cab440e6b 50000  # 50000
 	#>


	 # Primary NVMe Idle Timeout
	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\d639518a-e56d-4345-8af2-b9f32fb26109" -Name "Attributes" -Type DWord -Value 0x00000002
	<# 
	 powercfg -attributes 0012ee47-9041-4b5d-9b77-535fba8b1442 d639518a-e56d-4345-8af2-b9f32fb26109 -ATTRIB_HIDE
	 powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 d3d55efd-c1ff-424e-9dc3-441be7833010 1000  # 200
	 powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 d3d55efd-c1ff-424e-9dc3-441be7833010 1000  # 100
	#>


	 # Secondary NVMe Idle Timeout
	 # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\d3d55efd-c1ff-424e-9dc3-441be7833010" -Name "Attributes" -Type DWord -Value 0x00000002
	<# 
	 powercfg -attributes 0012ee47-9041-4b5d-9b77-535fba8b1442 d3d55efd-c1ff-424e-9dc3-441be7833010 -ATTRIB_HIDE
	 powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 d3d55efd-c1ff-424e-9dc3-441be7833010 1000  # 200
	 powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 d3d55efd-c1ff-424e-9dc3-441be7833010 1000  # 100
	#>

	Powercfg -setactive scheme_current

	# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes" -Name "ActiveOverlayDcPowerScheme" -Type String -Value "961cc777-2547-4f9d-8174-7d86181b8a7a"
	# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes" -Name "ActiveOverlayAcPowerScheme" -Type String -Value "ded574b5-45a0-4f42-8737-46345c09c238"


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



function revertPowerManagement {
    <#
    Restaura todos os planos de energia para suas configurações padrão.
    #>

    Write-Output "Resetando todos os planos de energia para suas configurações padrão."

    # Restaura todos os planos de energia
    powercfg -restoredefaultschemes
    Start-Sleep -Seconds 1  # Espera 1 segundo para garantir que a restauração foi concluída

    # Ativa o plano de energia "Equilibrado"
    powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e
    Write-Output "Plano de energia 'Equilibrado' ativado."
}



function DisableRecall {
    <#
    Desativa o recurso de Recall do Windows e ajusta a configuração de análise de dados da IA.
    #>

    Write-Output "Desativando o recurso Recall do Windows."

    # Verifica se o recurso Recall está habilitado
    $recallFeature = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq 'Recall' }

    if ($recallFeature.State -ne "Disabled") {
        # Desativa o recurso Recall
        Dism /Online /Disable-Feature /Featurename:Recall
        Write-Output "Recall feature has been disabled."
    } else {
        Write-Output "Recall feature is already disabled."
    }
    
    # Verifica a chave de registro para ajustar a análise de dados da IA
    if (Test-Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI") {
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Type DWord -Value 0x00000001
        Write-Output "AI data analysis has been disabled."
    } else {
        Write-Output "The WindowsAI key does not exist in the registry."
    }
}





 ###					 ###
 ###		Security	 ###
 ###					 ###



function TurnWSLlight {
    <#
    Aplica ajustes de desempenho no Windows Subsystem for Linux (WSL).
    #>

    Write-Output "Ajustes de desempenho do WSL."

    # Caminho para o arquivo de configuração do WSL
    $user_home = "$env:USERPROFILE\.wslconfig"

    # Verifica se o arquivo .wslconfig existe
    if (Test-Path $user_home) {
        # Cria um backup do arquivo existente
        Copy-Item -Path $user_home -Destination "$user_home.bak" -Force
        Write-Host "Backup do .wslconfig existente criado como .wslconfig.bak"
    }

    # Configurações para o arquivo .wslconfig
    $wslconfig = @'
[wsl2]
kernelCommandLine=noibrs noibpb nopti nospectre_v1 nospectre_v2 nospec_store_bypass_disable no_stf_barrier spectre_v2_user=off spec_store_bypass_disable=off l1tf=off mitigations=off mds=off tsx_async_abort=off spectre_v2=off ssbd=force-off tsx=on kpti=off pti=off nopcid nosmap slub_debug=- page_alloc.shuffle=0 systemd.unified_cgroup_hierarchy=0
'@

    # Cria ou substitui o arquivo .wslconfig
    Set-Content -Path $user_home -Value $wslconfig -Force
    Write-Output ".wslconfig atualizado com as novas configurações."
}



function DisableWindowsDefender {

    <#
    Desativa funcionalidades do Windows Defender que impactam diretamente o desempenho do sistema,
    incluindo Proteção em Tempo Real, Proteção Entregue na Nuvem, Envio Automático de Amostras e configurações de Isolamento de Núcleo.
    #>

    # Verifica e interrompe o serviço do Windows Defender se estiver em execução
    $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($defenderService -and $defenderService.Status -eq "Running") {
        try {
            Stop-Service -Name "WinDefend" -Force -ErrorAction SilentlyContinue
            Write-Host "Serviço Windows Defender interrompido."
        } catch {
            Write-Host "Não foi possível interromper o serviço do Windows Defender. Verifique as permissões administrativas." -ForegroundColor Red
            return
        }
    }

    # Cria as chaves de diretiva (Policies) para desativar o Windows Defender e Isolamento de Núcleo
    $policyPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Device Guard",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\ExploitGuard\ControlledFolderAccess"
    )

    foreach ($path in $policyPaths) {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
    }

    # Configurações para desativar o Windows Defender usando Policies
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 2 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ForceUpdateFromMU" -Value 0 -Force

    # Configurações de Isolamento de Núcleo e Proteções Adicionais
    # Memory Integrity
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -Force

    # Kernel-mode Hardware-enforced Stack Protection
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Device Guard" -Name "HypervisorEnforcedCodeIntegrity" -Value 0 -Force

    # Local Security Authority Protection
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPLBoot" -Value 0 -Force

    # Microsoft Vulnerable Driver Blocklist
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Device Guard" -Name "EnableVulnerableDriverBlocklist" -Value 0 -Force

    # Feedback para o usuário
    Write-Host "Configurações de Windows Defender e Isolamento de Núcleo desativadas com sucesso usando diretivas (Policies)."

    # Alterar mitigações ao estado original
    Set-ProcessMitigation -System -Reset
    Write-Host "Configurações de mitigação alteradas ao estado original."

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





 ###                            ###
 ### Desktop Menu Optimizations ###
 ###                            ###



function SetMinAnimate {
    <#
    Desativa animações desnecessárias para acelerar a resposta e a exibição do desktop.
    #>

    Write-Output "Desabilitando animações desnecessárias para aumentar a velocidade de resposta e a exibição do desktop."

    # Define a propriedade MinAnimate no registro
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value "0" -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Animações mínimas desativadas com sucesso."
    } else {
        Write-Output "Falha ao desativar animações mínimas."
    }
}



function SetDesktopProcess {
    <#
    Otimiza a prioridade dos processos de programas e processos independentes para evitar travamentos do sistema.
    #>

    Write-Output "Otimizando a prioridade dos processos do programa e processos independentes para evitar falhas do sistema."

    # Define a propriedade DesktopProcess no registro
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "DesktopProcess" -Type DWord -Value 0x00000001 -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Prioridade do processo do desktop otimizada com sucesso."
    } else {
        Write-Output "Falha ao otimizar a prioridade do processo do desktop."
    }
}




function SetTaskbarAnimations {
    <#
    Desativa animações na barra de tarefas e no menu Iniciar.
    #>

    Write-Output "Desativando animações na barra de tarefas e no menu Iniciar."

    # Define a propriedade TaskbarAnimations no registro
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0x00000000 -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Animações da barra de tarefas desativadas com sucesso."
    } else {
        Write-Output "Falha ao desativar animações da barra de tarefas."
    }
}



function SetWaitToKillServiceTimeout {
    <#
    Otimiza a velocidade de finalização dos processos ajustando o tempo de espera para serviços.
    #>

    Write-Output "Otimizando a velocidade de finalização dos serviços."

    # Define a propriedade WaitToKillServiceTimeout no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type String -Value "2000" -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Tempo de espera para finalizar serviços ajustado para 2000 milissegundos com sucesso."
    } else {
        Write-Output "Falha ao ajustar o tempo de espera para finalizar serviços."
    }
}



function SetNoSimpleNetIDList {
    <#
    Otimiza a estratégia de atualização da lista de arquivos do sistema, desativando a lista simples de identificadores de rede.
    #>

    Write-Output "Otimizando a estratégia de atualização da lista de identificadores de rede."

    # Verifica se o caminho da chave de registro existe, se não, cria
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }

    # Define a propriedade NoSimpleNetIDList no registro
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSimpleNetIDList" -Type DWord -Value 0x00000001 -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Estratégia de atualização da lista de identificadores de rede otimizada com sucesso."
    } else {
        Write-Output "Falha ao otimizar a estratégia de atualização da lista de identificadores de rede."
    }
}




function SetMouseHoverTime {
    <#
    Reduz o tempo de exibição da pré-visualização da barra de tarefas ajustando o tempo de espera do mouse.
    #>

    Write-Output "Reduzindo o tempo de exibição da pré-visualização da barra de tarefas."

    # Define a propriedade MouseHoverTime no registro
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "100" -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Tempo de exibição da pré-visualização da barra de tarefas ajustado para 100 milissegundos com sucesso."
    } else {
        Write-Output "Falha ao ajustar o tempo de exibição da pré-visualização da barra de tarefas."
    }
}




function SetMenuShowDelay {
    <#
    Acelera a resposta e a exibição dos comandos do sistema ajustando o atraso na exibição de menus.
    #>

    Write-Output "Acelerando a resposta e a exibição de comandos do sistema."

    # Define a propriedade MenuShowDelay no registro
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value "0" -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Atraso na exibição de menus ajustado para 0 milissegundos com sucesso."
    } else {
        Write-Output "Falha ao ajustar o atraso na exibição de menus."
    }
}




function SetForegroundLockTimeout {
    <#
    Melhora a velocidade de resposta do programa em primeiro plano ajustando o tempo de bloqueio do primeiro plano.
    #>

    Write-Output "Ajustando o tempo de bloqueio do primeiro plano para melhorar a resposta do programa."

    # Define a propriedade ForegroundLockTimeout no registro
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ForegroundLockTimeout" -Type String -Value "150000" -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Tempo de bloqueio do primeiro plano ajustado para 150000 milissegundos com sucesso."
    } else {
        Write-Output "Falha ao ajustar o tempo de bloqueio do primeiro plano."
    }
}




function SetAlwaysUnloadDLL {
    <#
    Libera DLLs não utilizadas da memória para otimizar o uso de memória.
    #>

    Write-Output "Liberando DLLs não utilizadas da memória."

    # Define a propriedade AlwaysUnloadDLL no registro
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "AlwaysUnloadDLL" -Type DWord -Value 0x00000001 -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "DLLs não utilizadas agora serão liberadas da memória com sucesso."
    } else {
        Write-Output "Falha ao configurar a liberação de DLLs não utilizadas."
    }
}




function SetFontStyleShortcut {
    <#
    Remove o estilo de fonte dos atalhos na área de trabalho.
    #>

    Write-Output "Removendo o estilo de fonte do atalho na área de trabalho."

    # Verifica se a chave de registro existe
    if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer") {
        # Define a propriedade link no registro
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type String -Value "0" -Force

        # Confirmação de sucesso
        if ($?) {
            Write-Output "Estilo de fonte do atalho removido com sucesso."
        } else {
            Write-Output "Falha ao remover o estilo de fonte do atalho."
        }
    } else {
        Write-Output "A chave de registro especificada não existe."
    }
}




function SetAutoRestartShell {
    <#
    Otimiza os componentes da interface do usuário, permitindo a reinicialização automática do shell em caso de falhas.
    #>

    Write-Output "Otimizando os componentes da interface do usuário. Habilitando reinicialização automática do shell."

    # Define a propriedade AutoRestartShell para sistemas de 64 bits
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Type DWord -Value 0x00000001 -Force
    
    # Define a propriedade AutoRestartShell para sistemas de 32 bits
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Type DWord -Value 0x00000001 -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Configuração de reinicialização automática do shell aplicada com sucesso."
    } else {
        Write-Output "Falha ao aplicar a configuração de reinicialização automática do shell."
    }
}




function SetVisualEffects {
    <#
    Otimiza os efeitos visuais dos menus e listas do sistema para melhorar o desempenho.
    #>

    Write-Output "Otimizing visual effects of system menus and lists for improved performance."

    # Desativa vários efeitos visuais
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0x00000000 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 0x00000002 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" -Name "DefaultApplied" -Type DWord -Value 0x00000000 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" -Name "DefaultApplied" -Type DWord -Value 0x00000000 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Name "DefaultApplied" -Type DWord -Value 0x00000000 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Name "DefaultApplied" -Type DWord -Value 0x00000000 -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Visual effects optimized successfully."
    } else {
        Write-Output "Failed to optimize visual effects." -ForegroundColor Red
    }
}




function GetFullContextMenu {
    <#
    Configura o menu de contexto completo no Windows 11.
    #>

    Write-Output "Configurando Menus de Contexto Completo."

    # Verifica se a versão do Windows é 11 (Build 22000 ou superior)
    if ([System.Environment]::OSVersion.Version.Build -ge 22000) {
        Write-Host "Configurando Menus de Contexto Completo no Windows 11."

        # Verifica se a chave de registro já existe
        if (!(Test-Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}")) {
            # Cria a chave de registro
            New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Force | Out-Null
            New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
            Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name '(Default)' -Value ""
        }

        Write-Output "Menus de contexto completos configurados com sucesso."
    } else {
        Write-Output "Este script é compatível apenas com Windows 11."
    }
}




function SetKeyboardDelay {
    <#
    Ajusta o tempo de resposta do teclado.
    #>

    Write-Output "Ajustando o tempo de resposta do teclado."

    # Define as propriedades do teclado no registro
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type String -Value "2" -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type String -Value "0" -Force
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardSpeed" -Type String -Value "48" -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Configurações do teclado ajustadas com sucesso."
    } else {
        Write-Output "Falha ao ajustar as configurações do teclado."
    }
}




function SetMaxCachedIcons {
    <#
    Aumenta o buffer de ícones do sistema para exibir imagens mais rapidamente.
    #>

    Write-Output "Aumentando o buffer de ícones do sistema para exibir imagens mais rapidamente."

    # Define a propriedade Max Cached Icons no registro para sistemas de 64 bits
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Type String -Value "4000" -Force
    
    # Define a propriedade Max Cached Icons no registro para sistemas de 32 bits
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Type String -Value "4000" -Force

    # Confirmação de sucesso
    if ($?) {
        Write-Output "Número máximo de ícones em cache definido para 4000 com sucesso."
    } else {
        Write-Output "Falha ao definir o número máximo de ícones em cache."
    }
}




 ###                           ###
 ### File System Optimizations ###
 ###                           ###



function DisableUnusedDiskControllerDriver {
    <#
    Use with caution!
    Desativa o driver de controlador de disco IDE legado.
    #>

    Write-Host "Desativando o driver de controlador de disco IDE legado."

    # Desativa o driver pciide no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\pciide" -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue

    Write-Host "Driver IDE legado desativado com sucesso."
}



function SetNoLowDiskSpaceChecks {
    <#
    Desativa as verificações automáticas de espaço em disco baixo, removendo notificações de espaço insuficiente.
    #>

    Write-Output "Desativando as verificações de espaço em disco baixo para melhorar a performance."

    # Verifica se a chave de registro existe
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        # Cria a chave de registro se ela não existir
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }

    # Define a propriedade NoLowDiskSpaceChecks no registro
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoLowDiskSpaceChecks" -Type DWord -Value 0x00000001 -Force

    Write-Output "Verificações de espaço em disco baixo desativadas com sucesso."
}



function DisableStorageSense {
    <#
    Desativa o Storage Sense com base na versão do Windows (Windows 10 ou Windows 11).
    #>

    # Verifica se o sistema é Windows 10
    IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {
        Write-Host "Windows 10 Detectado. -> Desativando o Storage Sense."
        
        # Verifica e cria a chave de registro se não existir
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
        }

        # Define as propriedades que desativam o Storage Sense no Windows 10
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0x00000000
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 0x00000000
    }

    # Verifica se o sistema é Windows 11
    IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {
        Write-Host "Windows 11 Detectado. -> Desativando o Storage Sense."

        # Verifica e cria a chave de registro se não existir
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
        }

        # Define as propriedades que desativam o Storage Sense no Windows 11
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0x00000000
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "04" -Type DWord -Value 0x00000000
    }
}




function SetNtfsDisable8dot3NameCreation {
    <#
    Desativa o recurso de criação de nomes curtos (formato 8.3) no sistema de arquivos NTFS.
    #>

    Write-Output "Desativando o recurso de criação de nomes curtos (8.3) no NTFS."

    # Desativa a criação de nomes 8.3 globalmente
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisable8dot3NameCreation" -Type DWord -Value 0x00000001 -Force

    Write-Output "A criação de nomes curtos (8.3) foi desativada."

    # Comando opcional para verificar a configuração:
    Write-Output "Execute 'fsutil behavior query disable8dot3' para verificar o status atual."
}




function SetNoDriveTypeAutoRun {
    <#
    Desativa o AutoPlay para dispositivos externos, evitando riscos como a execução automática de malware.
    #>

    Write-Output "Desativando o AutoPlay para dispositivos externos para reduzir riscos de segurança."

    # Verifica se a chave de registro existe
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        # Cria a chave de registro se ela não existir
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }

    # Define a propriedade NoDriveTypeAutoRun no registro
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 0x000000dd -Force

    Write-Output "AutoPlay desativado com sucesso para unidades removíveis e externas."

	<#
	0x80: Desativa o AutoPlay em unidades de rede.
	0x04: Desativa o AutoPlay em unidades removíveis (como pen drives).
	0x08: Desativa o AutoPlay em unidades fixas.
	0x10: Desativa o AutoPlay em CDs/DVDs.
	0x20: Desativa o AutoPlay em discos RAM.
	O valor 0xdd é a soma dessas bandeiras (0x80 + 0x08 + 0x04 + 0x01 + 0x10).
#>
}




function DisableDeleteNotify {
    <#
    Habilita o TRIM para prolongar a vida útil e melhorar o desempenho das unidades SSD.
    #>

    Write-Output "Forçando o estado TRIM para ativado."

    # Verifica se o sistema é Windows 10
    IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {
        Write-Host "Windows 10 Detectado. Permitindo operações de TRIM para serem enviadas ao dispositivo de armazenamento."
        fsutil behavior set DisableDeleteNotify 0    # Habilita TRIM
        fsutil behavior set DisableDeleteNotify ReFS 0  # Habilita TRIM para ReFS
    }

    # Verifica se o sistema é Windows 11
    IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {
        Write-Host "Windows 11 Detectado. Permitindo operações de TRIM para serem enviadas ao dispositivo de armazenamento."
        fsutil behavior set DisableDeleteNotify 0    # Habilita TRIM
        fsutil behavior set DisableDeleteNotify ReFS 0  # Habilita TRIM para ReFS
    }

    Write-Output "TRIM foi habilitado com sucesso."
}




function SetLastAccessTimeStamp {
    <#
    Desativa as atualizações de "Last Access Time Stamp" em sistemas de arquivos NTFS para melhorar o desempenho.
    #>

    # Verifica se o sistema é Windows 10
    IF ([System.Environment]::OSVersion.Version.Build -lt 22000) {
        Write-Host "Windows 10 Detectado. Desativando as atualizações de Last Access Time Stamp no NTFS."
        fsutil behavior set disablelastaccess 1  # Desativa as atualizações de Last Access Time
    }

    # Verifica se o sistema é Windows 11
    IF ([System.Environment]::OSVersion.Version.Build -ge 22000) {
        Write-Host "Windows 11 Detectado. Desativando as atualizações de Last Access Time Stamp no NTFS."
        fsutil behavior set disablelastaccess 1  # Desativa as atualizações de Last Access Time
    }

    Write-Output "Atualizações de Last Access Time Stamp desativadas com sucesso."
}



function SetWaitToKillAppTimeout {
    <#
    Ajusta o tempo de espera para encerrar aplicativos, melhorando a velocidade de resposta do sistema.
    #>

    Write-Output "Otimização do tempo de espera para encerrar aplicativos."

    # Define o tempo de espera para encerrar aplicativos no registro
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Type String -Value "10000" -Force

    Write-Output "Tempo de espera para encerrar aplicativos ajustado para 10000 milissegundos (10 segundos)."
}



function SetHungAppTimeout {
    <#
    Reduz o tempo de espera para aplicativos não responsivos, melhorando a experiência do usuário.
    #>

    Write-Output "Ajustando o tempo de espera para aplicativos não responsivos."

    # Define o tempo de espera para aplicativos não responsivos no registro
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "HungAppTimeout" -Type String -Value "3000" -Force

    Write-Output "Tempo de espera para aplicativos não responsivos ajustado para 3000 milissegundos (3 segundos)."
}




function SetDataQueueSize {
    <#
    Ajusta o tamanho das filas de dados para teclado e mouse para melhorar a responsividade.
    #>

    Write-Output "Definindo MouseDataQueueSize e KeyboardDataQueueSize para 0x00000032."

    # Verifica se a chave de registro para o mouse existe e cria se não existir
    If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Force | Out-Null
    }
    # Define o tamanho da fila de dados do mouse
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 0x00000032 -Force

    # Define o tamanho da fila de dados do teclado
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 0x00000032 -Force

    Write-Output "Tamanhos das filas de dados para mouse e teclado ajustados com sucesso."
}



function DisableThreadedDPCs {
    <#
    Desativa os DPCs em thread para potencialmente melhorar a resposta do sistema.
    #>

    Write-Output "Otimização do tempo de resposta do programa desativando DPCs em thread."

    # Define o valor para desativar os DPCs em thread
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadDpcEnable" -Type DWord -Value 0x00000000 -Force

    Write-Output "DPCs em thread desativados com sucesso."
}




function SetPriorityControl {
    <#
    Otimiza o valor de Win32PrioritySeparation para melhorar a responsividade do sistema.
    #>

    Write-Output "Otimização do valor de Win32PrioritySeparation para um sistema mais suave."

    # Ajusta o valor de Win32PrioritySeparation no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000024 -Force

    Write-Output "Valor de Win32PrioritySeparation ajustado para 0x00000024."
	
	<#
	https://www.youtube.com/watch?v=bqDMG1ZS-Yw

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

}



function SetAutoEndTasks {
    <#
    Habilita a finalização automática de programas não responsivos para evitar travamentos do sistema.
    #>

    Write-Output "Habilitando a finalização automática de programas não responsivos."

    # Define a propriedade AutoEndTasks no registro
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Type String -Value "1" -Force

    Write-Output "Finalização automática de tarefas habilitada com sucesso."
}




function SetBootOptimizeFunction {
    <#
    Desativa a desfragmentação automática de disco e habilita a otimização da partição de inicialização para melhorar a velocidade de inicialização.
    #>

    Write-Output "Desativando a desfragmentação automática e habilitando a otimização da partição de inicialização."

    # Define o valor para desativar a desfragmentação automática
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Type String -Value "" -Force

    # Verifica se a chave WOW6432Node existe e cria se necessário
    If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Dfrg\BootOptimizeFunction")) {
        New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Dfrg\BootOptimizeFunction" -Force | Out-Null
    }

    # Define o valor para desativar a desfragmentação automática na chave WOW6432Node
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Type String -Value "" -Force

    Write-Output "Desfragmentação automática desativada e otimização da partição de inicialização habilitada com sucesso."
}




 ###					      ###
 ###	Network	Optimizations ###
 ###					      ###


function SetInterruptModeration {
    <#
    Ajusta a modulação de interrupções para os adaptadores de rede Wi-Fi e Ethernet para otimizar a performance.
    #>

    Write-Output "Configurando Packet Coalescing / Interrupt Moderation para LOW."

    # Adiciona a propriedade de modulação de interrupções para Wi-Fi e Ethernet
    New-NetAdapterAdvancedProperty -Name "Wi-Fi" -RegistryKeyword "*InterruptModeration" -RegistryValue 1 -ErrorAction Ignore
    New-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "*InterruptModeration" -RegistryValue 1 -ErrorAction Ignore

    # Define a propriedade de modulação de interrupções para Wi-Fi e Ethernet
    Set-NetAdapterAdvancedProperty -Name "Wi-Fi" -RegistryKeyword "*InterruptModeration" -RegistryValue 1 -ErrorAction Ignore
    Set-NetAdapterAdvancedProperty -Name "Ethernet" -RegistryKeyword "*InterruptModeration" -RegistryValue 1 -ErrorAction Ignore

    # Reinicia os adaptadores para aplicar as novas configurações (descomente se necessário)
    # Restart-NetAdapter -Name "Wi-Fi" -Confirm:$false
    # Restart-NetAdapter -Name "Ethernet" -Confirm:$false

    Write-Output "Modulação de interrupções ajustada para ambos os adaptadores com sucesso."
}


function DisableIPv6 {
    <#
    Desativa o protocolo IPv6 no sistema para evitar problemas de conectividade em redes que não utilizam IPv6.
    #>

    Write-Output "Desativando o protocolo IPv6."

    # Define o valor para desativar o IPv6 no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Type DWord -Value 0x000000FF -Force

    Write-Output "IPv6 desativado com sucesso."
}




function SetIRPStackSize {
    <#
    Ajusta o tamanho da pilha IRP para melhorar o desempenho da rede local (LAN).
    #>

    Write-Output "Configurando o tamanho da pilha IRP."

    # Define o valor de IRPStackSize no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 0x0000000c -Force

    Write-Output "Tamanho da pilha IRP configurado para 12 (0x0000000c) com sucesso."
}



function SettingTimeService {
    <#
    Configura o relógio da BIOS para UTC e ajusta o serviço de tempo do Windows.
    #>

    Write-Host "Configurando o tempo da BIOS para UTC e corrigindo inconsistências."

    # Define o relógio da BIOS como UTC
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 0x00000001 -Force

    # Reinicia o serviço de tempo do Windows
    Write-Host "Reiniciando o serviço de tempo do Windows."

    net stop w32time
    w32tm /unregister
    w32tm /register
    net start w32time

    # Sincroniza o tempo imediatamente
    w32tm /resync /nowait

    Write-Output "Configuração do serviço de tempo concluída com sucesso."
}



function DisableWiFiSense {
    <#
    Desativa o recurso Wi-Fi Sense, que permite conexões automáticas a hotspots Wi-Fi.
    #>

    Write-Output "Desativando o Wi-Fi Sense."

    # Definindo os caminhos das chaves de registro
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"

    # Criando e definindo a chave AllowWiFiHotSpotReporting
    If (!(Test-Path $WifiSense1)) {
        New-Item -Path $WifiSense1 -Force | Out-Null
    }
    Set-ItemProperty -Path $WifiSense1 -Name "value" -Type DWord -Value 0x00000000 -Force

    # Criando e definindo a chave AllowAutoConnectToWiFiSenseHotspots
    If (!(Test-Path $WifiSense2)) {
        New-Item -Path $WifiSense2 -Force | Out-Null
    }
    Set-ItemProperty -Path $WifiSense2 -Name "value" -Type DWord -Value 0x00000000 -Force

    # Definindo a opção de AutoConnectAllowedOEM
    If (!(Test-Path $WifiSense3)) {
        New-Item -Path $WifiSense3 -Force | Out-Null
    }
    Set-ItemProperty -Path $WifiSense3 -Name "AutoConnectAllowedOEM" -Type DWord -Value 0x00000000 -Force

    Write-Output "Wi-Fi Sense desativado com sucesso."
}




function DisableWFPlogs {
    <#
    Desativa os logs do Windows Filtering Platform (WFP) para reduzir o uso de disco.
    #>

    Write-Output "Desativando os logs do WFP."

    # Desativa a gravação de eventos de rede
    netsh wfp set options netevents=off

    Write-Output "Logs do WFP desativados com sucesso."
}




function SetDefaultTTL {
    <#
    Ajusta o valor do Time To Live (TTL) padrão para otimizar o uso da largura de banda.
    #>

    Write-Output "Otimização do TTL padrão para diminuir a perda de largura de banda e aumentar a largura de banda disponível."

    # Define o valor do TTL padrão no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 0x00000040 -Force

    Write-Output "TTL padrão ajustado para 64 (0x00000040) com sucesso."
}



function SetFastForwarding {
    <#
    Otimiza o mecanismo de encaminhamento rápido de rede para melhorar a velocidade da Internet.
    #>

    Write-Output "Otimização do mecanismo de encaminhamento rápido de rede para melhorar a velocidade da Internet."

    # Ativa o suporte a SACK (Selective Acknowledgments)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SackOpts" -Type DWord -Value 0x00000001 -Force
    
    # Define o número máximo de ACKs duplicados permitidos
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDupAcks" -Type DWord -Value 0x00000002 -Force

    Write-Output "Configurações de encaminhamento rápido aplicadas com sucesso."
}



function SetMaxConnectionsPerServerIE {
    <#
    Aumenta o número máximo de conexões simultâneas permitidas por servidor no Internet Explorer.
    #>

    Write-Output "Aumentando as conexões simultâneas permitidas por servidor no Internet Explorer."

    # Ajusta as configurações para o Internet Explorer
    $value = 0x0000000a  # 10 conexões

    # Configurações para HKLM
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "iexplore.exe" -Type DWord -Value $value -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "iexplore.exe" -Type DWord -Value $value -Force

    # Configurações para HKLM WOW6432Node
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" -Name "iexplore.exe" -Type DWord -Value $value -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" -Name "iexplore.exe" -Type DWord -Value $value -Force

    # Cria um novo PSDrive para HKEY_USERS
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS

    # Configurações para HKU .DEFAULT e S-1-5-18
    $userPaths = @(
        "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    )

    foreach ($path in $userPaths) {
        Set-ItemProperty -Path $path -Name "MaxConnectionsPerServer" -Type DWord -Value $value -Force
        Set-ItemProperty -Path $path -Name "MaxConnectionsPer1_0Server" -Type DWord -Value $value -Force
    }

    # Configurações para HKCU
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPerServer" -Type DWord -Value $value -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "MaxConnectionsPer1_0Server" -Type DWord -Value $value -Force

    Write-Output "Conexões simultâneas configuradas com sucesso."
}


function SetMaxConnectionsPerServer {
    <#
    Ajusta o número máximo de conexões permitidas por servidor para otimizar o desempenho do adaptador de rede.
    #>

    Write-Output "Otimização do desempenho do adaptador de rede para melhorar a velocidade da Internet."

    # Define o número máximo de conexões por servidor no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxConnectionsPerServer" -Type DWord -Value 0x00000000 -Force

    Write-Output "Número máximo de conexões por servidor configurado para ilimitado (0x00000000) com sucesso."
}




function SetAutoDetectionMTUsize {
    <#
    Habilita a detecção automática do tamanho MTU e a detecção de roteadores black hole para melhorar a velocidade da Internet.
    #>

    Write-Output "Habilitando a detecção automática do tamanho MTU e a detecção de roteadores black hole."

    # Ativa a descoberta do tamanho máximo do pacote transmissível
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUDiscovery" -Type DWord -Value 0x00000001 -Force
    
    # Habilita a detecção de roteadores black hole
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUBHDetect" -Type DWord -Value 0x00000001 -Force

    Write-Output "Detecção automática do MTU e detecção de roteadores black hole habilitadas com sucesso."
}




function SetNameSrvQueryTimeout {
    <#
    Ajusta o tempo de consulta do nome WINS para otimizar a capacidade de transmissão de dados na rede.
    #>

    Write-Output "Otimização do tempo de consulta do nome WINS para melhorar a transmissão de dados na rede."

    # Define o valor do tempo de consulta do nome no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NameSrvQueryTimeout" -Type DWord -Value 0x00000bb8 -Force

    Write-Output "Tempo de consulta do nome WINS ajustado para 3000 milissegundos (0x00000bb8) com sucesso."
}



function SetDnsCache {
    <#
    Otimiza as configurações de cache DNS para melhorar a velocidade de resolução de nomes.
    #>

    Write-Output "Otimização do cache DNS para melhorar a velocidade de resolução de nomes."

    # Define o tempo máximo de cache DNS
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheEntryTtlLimit" -Type DWord -Value 0x00002a30 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl" -Type DWord -Value 0x00002a30 -Force

    # Define o tempo de cache para entradas negativas como zero
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxNegativeCacheTtl" -Type DWord -Value 0x00000000 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NegativeSOACacheTime" -Type DWord -Value 0x00000000 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NetFailureCacheTime" -Type DWord -Value 0x00000000 -Force

    Write-Output "Configurações de cache DNS aplicadas com sucesso."
}




function SetNoUpdateCheckonIE {
    <#
    Desativa as atualizações automáticas no Internet Explorer.
    #>

    Write-Output "Desativando atualizações automáticas no Internet Explorer."

    # Verifica e cria a chave de registro para HKLM (64 bits)
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name "NoUpdateCheck" -Type DWord -Value 0x00000001 -Force

    # Verifica e cria a chave de registro para HKLM WOW6432Node (32 bits)
    If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions")) {
        New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" -Name "NoUpdateCheck" -Type DWord -Value 0x00000001 -Force

    # Desativa atualizações para o usuário atual
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name "NoUpdateCheck" -Type DWord -Value 0x00000001 -Force

    Write-Output "Atualizações automáticas no Internet Explorer desativadas com sucesso."
}




function SetTcp1323Opts {
    <#
    Habilita o autoajuste do buffer de unidade de transporte para melhorar o tempo de resposta da rede.
    #>

    Write-Output "Habilitando o ajuste automático das opções TCP 1323."

    # Define a opção Tcp1323Opts no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Tcp1323Opts" -Type DWord -Value 0x00000001 -Force

    Write-Output "Opções TCP 1323 habilitadas com sucesso."
}



function SetMaxCmds {
    <#
    Otimiza as configurações do Lanman Workstation para melhorar o desempenho e a capacidade de resposta da rede.
    #>

    Write-Output "Otimização das configurações do Lanman Workstation para melhorar o desempenho da rede."

    # Define o número máximo de comandos
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "MaxCmds" -Type DWord -Value 0x0000001e -Force
    
    # Define o número máximo de threads
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "MaxThreads" -Type DWord -Value 0x0000001e -Force
    
    # Define o número máximo de coleções
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "MaxCollectionCount" -Type DWord -Value 0x00000020 -Force

    Write-Output "Configurações do Lanman Workstation ajustadas com sucesso."
}



function SetNoNetCrawling {
    <#
    Desativa a indexação de rede para otimizar as conexões LAN.
    #>

    Write-Output "Desativando a indexação de rede para otimizar a conexão LAN."

    # Define a propriedade NoNetCrawling no registro
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NoNetCrawling" -Type DWord -Value 0x00000001 -Force

    Write-Output "Indexação de rede desativada com sucesso."
}




function SetGlobalMaxTcpWindowSize {
    <#
    Ajusta o tamanho da janela TCP global para otimizar o desempenho da rede de banda larga.
    #>

    Write-Output "Otimização do tamanho da janela TCP global para melhorar a velocidade da rede."

    # Define o tamanho máximo da janela TCP global no registro
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "GlobalMaxTcpWindowSize" -Type DWord -Value 0x00007fff -Force

    Write-Output "Tamanho da janela TCP global ajustado para 32767 (0x00007fff) com sucesso."
}



function SetOptimizeNetwrok {
    <#
    Otimiza as configurações de rede para melhorar o desempenho e a capacidade de resposta.
    #>

    Write-Output "Otimização das configurações de rede."

    # Verifica e cria a chave para HKLM (64 bits)
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0x00000000 -Force

    # Verifica e cria a chave para HKLM WOW6432Node (32 bits)
    If (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Psched")) {
        New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Psched" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0x00000000 -Force

    # Desativa o mecanismo de limitação da rede
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff -Force

    # Desativa o Algoritmo de Nagle
    Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
        if (Get-ItemProperty -Path $_.PsPath -Name "DhcpServer" -ErrorAction SilentlyContinue) {
            Set-ItemProperty -Path $_.PsPath -Name "TcpNoDelay" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $_.PsPath -Name "TcpAckFrequency" -Type DWord -Value 0x00000001 -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $_.PsPath -Name "TcpDelAckTicks" -Type DWord -Value 0x00000000 -Force -ErrorAction SilentlyContinue
        }
    }

    # Verifica e cria a chave para MSMQ
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters" -Name "TCPNoDelay" -Type DWord -Value 0x00000001 -Force

    Write-Output "Configurações de rede otimizadas com sucesso."
}





 ###				   ###
 ###	Server-Related ###
 ###				   ###



function DisableEventTracker {
    <#
    Desativa o rastreador de eventos de desligamento no Windows.
    #>

    Write-Output "Desativando o Shutdown Event Tracker."

    # Verifica e cria a chave de registro para Reliability
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Force | Out-Null
    }
    
    # Define a propriedade ShutdownReasonOn para desativar o rastreador de eventos
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0x00000000 -Force

    Write-Output "Shutdown Event Tracker desativado com sucesso."
}






 ### 	   ###
 ### Unpin ###
 ###       ###



function RemovingFax {
    <#
    Remove impressoras específicas do sistema, incluindo a impressora de fax padrão e a do OneNote.
    #>

    Write-Output "Removendo a impressora de fax padrão e a impressora do OneNote."

    # Remove a impressora de fax, caso exista
    Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue

    # Remove a impressora do OneNote, caso exista
    Remove-Printer -Name "OneNote (Desktop)" -ErrorAction SilentlyContinue

    Write-Output "Impressoras removidas com sucesso."
}




function RemoveFeaturesKeys {
    <#
    Remove uma lista específica de chaves de registro associadas a aplicativos e funcionalidades do Windows.
    #>

    Write-Output "Iniciando a remoção de chaves de registro específicas."

    # Lista de chaves de registro para remover
    $Keys = @(
        # Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\AD2F1837.OMENCommandCenter_1101.2305.3.0_x64__v10z8vjag6ke6",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\AD2F1837.OMENCommandCenter_1101.2305.4.0_x64__v10z8vjag6ke6",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\AD2F1837.OMENCommandCenter_1101.2307.1.0_x64__v10z8vjag6ke6",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.19041.1023.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy",

        # Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0",

        # Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y",
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0",
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.19041.1023.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy",

        # Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe",
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\AD2F1837.OMENCommandCenter_1101.2305.3.0_x64__v10z8vjag6ke6",
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\AD2F1837.OMENCommandCenter_1101.2305.4.0_x64__v10z8vjag6ke6",
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\AD2F1837.OMENCommandCenter_1101.2307.1.0_x64__v10z8vjag6ke6",

        # Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0",
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.19041.1023.0_neutral_neutral_cw5n1h2txyewy",
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy", 
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.25128.1000.0_neutral_neutral_cw5n1h2txyewy", 

        # Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )

    # Remover cada chave de registro da lista
    ForEach ($Key in $Keys) {
        Write-Output "Removendo $Key do registro."
        Remove-Item -Path $Key -Force -Recurse -ErrorAction SilentlyContinue
    }

    Write-Output "Remoção das chaves de registro concluída."
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