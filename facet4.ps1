<#
Facet4 Windows 10/11 distribution
Author: Hermann Heringer
Version : 0.1.15
Date: 2024-11-27
Source: https://github.com/hermannheringer/
#>



Function RequireAdmin {
    # Verifica se o script está sendo executado como Administrador
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Write-Host "This script is not running as Administrator. Attempting to self elevate..."
        try {
            # Reexecuta o script atual como Administrador
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
            Write-Host "The script is being re-launched with elevated privileges. Please confirm the UAC prompt."
            Exit
        } catch {
            Write-Host "Failed to elevate the script: $_" -ForegroundColor Red
            Exit 1
        }
    }
}



Function CIM_server {
    # Nome do serviço WMI/CIM
    $serviceName = "Winmgmt"
    
    # Tenta acessar o CIM para garantir que o serviço esteja funcionando
    try {
        Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue | Out-Null
        Write-Host "CIM server is operational." -ForegroundColor Green
        return $true  # CIM server está funcionando
    } catch {
        Write-Host "CIM connection failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Attempting to restart the CIM (WMI) service: $serviceName..."

        # Reinicia o serviço WMI/CIM
        try {
            Restart-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5  # Aguarda alguns segundos para o serviço reiniciar

            # Verifica novamente se o CIM está acessível após o restart
            Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue | Out-Null
            Write-Host "CIM server restarted and is now operational." -ForegroundColor Green
            return $true
        } catch {
            Write-Host "Failed to restart the CIM server: $($_.Exception.Message)" -ForegroundColor Red
            return $false  # Falha ao reiniciar o servidor CIM
        }
    }
}



Function AddOrRemoveTweak($tweak) {
    # Inicializa a variável $script:tweaks se não estiver definida
    if (-not $script:tweaks) {
        $script:tweaks = @()
    }

    # Se o ajuste começa com "!", remove-o da lista de ajustes
    if ($tweak[0] -eq "!") {
        $tweakToRemove = $tweak.Substring(1)
        if ($script:tweaks -contains $tweakToRemove) {
            $script:tweaks = $script:tweaks | Where-Object { $_ -ne $tweakToRemove }
            Write-Host "Tweak '$tweakToRemove' was not found in the list."
        } else {
            Write-Host "Tweak '$tweakToRemove' removed from the list."
        }
    }
    
    # Caso contrário, adiciona o ajuste à lista se ele não estiver vazio
    elseif ($tweak -ne "") {
        if (-not ($script:tweaks -contains $tweak)) {
            $script:tweaks += $tweak
            Write-Host "Tweak '$tweak' is already in the list."
        } else {
            Write-Host "Tweak '$tweak' added to the list."
        }
    }
}



 # Creates a record of all or part of a PowerShell session to a log file.
Function LogScript {
    $facet4Folder = "C:\Temp\facet4"
    
    # Verifica se o diretório existe
    If (Test-Path $facet4Folder) {
        Write-Output "$facet4Folder exists. Skipping folder creation..."
    }
    Else {
        Write-Output "The folder '$facet4Folder' doesn't exist. Creating now."
        Start-Sleep 1
        New-Item -Path "$facet4Folder" -ItemType Directory -Force -ErrorAction SilentlyContinue
        Write-Output "The folder $facet4Folder was successfully created."
    }
    
    # Gera um nome de arquivo de log único com base no timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $logFile = Join-Path $facet4Folder "PowerShell_Log_$timestamp.txt"
    
    # Inicia a transcrição da sessão PowerShell
    try {
        Start-Transcript -Path $logFile
        Write-Output "Logging session started. Logs will be saved to $logFile"
    } catch {
        Write-Host "Failed to start transcript: $_" -ForegroundColor Red
    }
}



 # Creating a System Restore Point
Function RestorePoint {
    Write-Output "Creating a System Restore Point on the local computer. Please wait..."

    # Seleciona a unidade C:\ para a restauração do sistema, a unidade típica do sistema
    $LocalDrive = "C:"

    try {
        # Ativa a Restauração do Sistema na unidade C:
        Enable-ComputerRestore -Drive $LocalDrive
        Write-Output "System Restore enabled on drive $LocalDrive."
    } catch {
        Write-Host "Failed to enable System Restore on drive ${LocalDrive}: $_" -ForegroundColor Red
        return
    }

    Start-Sleep 1

    try {
        # Define a frequência para permitir a criação de pontos de restauração sem restrição de tempo
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type DWord -Value 0
        Write-Output "System restore point creation frequency set to 0."
    } catch {
        Write-Host "Failed to set System Restore Point creation frequency: $_" -ForegroundColor Red
        return
    }

    Start-Sleep 1

    try {
        # Cria um ponto de restauração do sistema com a descrição especificada
        $startTime = Get-Date
        Checkpoint-Computer -Description "System Restore Point created on $startTime before running facet4 script." -RestorePointType "MODIFY_SETTINGS"
        Write-Output "System Restore Point created successfully."
    } catch {
        Write-Host "Failed to create System Restore Point: $_" -ForegroundColor Red
    }

    Start-Sleep 1
}



Function DeepSystemClean {
    Write-Host "Performing a deep system clean..."

    # Inicia o 'cleanmgr' com argumentos para limpar discos com muito pouco espaço
    $cleanmgrProcess = Start-Process cleanmgr -ArgumentList "/VERYLOWDISK", "/AUTOCLEAN" -NoNewWindow -PassThru

    # Espera o processo 'cleanmgr' terminar em vez de usar um tempo fixo
    $cleanmgrProcess.WaitForExit()

    # Caso ainda esteja em execução após um tempo limite, forçar o encerramento
    $timeoutSeconds = 180  # 3 minutos
    if (-not $cleanmgrProcess.HasExited) {
        Start-Sleep -Seconds $timeoutSeconds
        if (-not $cleanmgrProcess.HasExited) {
            Stop-Process -Id $cleanmgrProcess.Id -Force
            Write-Output "Forced termination of 'cleanmgr' process."
        }
    }

    # Limpa pastas de arquivos temporários e caches adicionais
    $pathsToClean = @(
        $Env:temp,
        "$Env:windir\temp",
        "$Env:windir\SystemTemp",
        "$Env:windir\logs\CBS",
        "$Env:windir\Prefetch",
        "$Env:windir\SoftwareDistribution\Download",
        "$Env:LOCALAPPDATA\Microsoft\Windows\INetCache",
        "$Env:LOCALAPPDATA\Microsoft\Office\16.0\Wef",
        "$Env:LOCALAPPDATA\Temp",
        "$Env:LOCALAPPDATA\CrashDumps",
        "$Env:LOCALAPPDATA\Downloaded Installations",
        "$Env:LOCALAPPDATA\NVIDIA\GLCache",
        "$Env:LOCALAPPDATA\NVIDIA Corporation\NV_Cache",
        "$Env:APPDATA\NVIDIA\ComputeCache",
        "$Env:LOCALAPPDATA\Intel\ShaderCache",
        "$Env:LOCALAPPDATA\Packages\Microsoft.Win32WebViewHost_cw5n1h2txyewy\AC\#!123\INetCache",
        "$Env:ProgramData\Microsoft\Windows\WER\ReportQueue",
        "$Env:ProgramData\Microsoft\Windows\WER\ReportArchive",
        "$Env:LOCALAPPDATA\Microsoft\Windows\WER",
        "$Env:HOMEPATH\AppData\LocalLow\Intel\ShaderCache",
        "$Env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
        "$Env:LOCALAPPDATA\Google\Chrome\User Data\Default\Media Cache",
        "$Env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*\cache2",
        "$Env:LOCALAPPDATA\Microsoft Edge\User Data\Default\Cache"
    )

    foreach ($path in $pathsToClean) {
        if (Test-Path $path) {
            Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Cleaned: $path"
        }
    }

    # Limpeza de DLLs órfãs
    Write-Host "Cleaning up orphaned DLLs..."
    $sharedDlls = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\SharedDLLs"
    foreach ($dll in $sharedDlls.PSObject.Properties.Name) {
        $usageCount = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\SharedDLLs").$dll
        if ($usageCount -eq 0) {
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\SharedDLLs" -Name $dll -Force -ErrorAction SilentlyContinue
            Write-Output "Removed orphaned DLL: $dll"
        }
    }

    # Limpeza de objetos COM/ActiveX órfãos
    Write-Host "Cleaning up orphaned COM/ActiveX entries..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }

    # Obter todos os objetos COM registrados
    $comObjects = Get-ChildItem -Path "HKCR:\CLSID"

    foreach ($obj in $comObjects) {
        $inProcServer32 = Get-ItemProperty -Path "$($obj.PSPath)\InprocServer32" -ErrorAction SilentlyContinue

        # Verifica se a propriedade existe e se não é nula ou vazia antes de chamar Test-Path
        if ($inProcServer32 -and $inProcServer32.'(default)' -ne $null -and $inProcServer32.'(default)' -ne "" -and !(Test-Path $inProcServer32.'(default)')) {
            try {
                Remove-Item -Path $obj.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Output "Removed orphaned COM/ActiveX entry: $($obj.PSPath)"
            } catch {
                Write-Output "Failed to remove: $($obj.PSPath). Error: $_" -ForegroundColor Red
            }
        }
    }

    # Limpeza de entradas de instaladores MSI órfãs
    Write-Host "Cleaning up orphaned MSI installer entries..."
    $installerKeys = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    foreach ($key in $installerKeys) {
        $installSource = Get-ItemProperty -Path "$($key.PSPath)\InstallProperties" -ErrorAction SilentlyContinue
        if ($installSource -and $installSource.InstallSource -and !(Test-Path $installSource.InstallSource)) {
            try {
                Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Output "Removed orphaned MSI installer entry: $($key.PSPath)"
            } catch {
                Write-Output "Failed to remove: $($key.PSPath). Error: $_" -ForegroundColor Red
            }
        }
    }

    # Limpeza de caminhos de aplicação órfãos
    Write-Host "Cleaning up orphaned application paths..."
    $appKeys = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths"
    foreach ($key in $appKeys) {
        $appPath = (Get-ItemProperty -Path $key.PSPath).'(default)'
        if ($appPath -and $appPath -ne $null -and !(Test-Path $appPath)) {
            try {
                Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Output "Removed orphaned application path: $($key.PSPath)"
            } catch {
                Write-Output "Failed to remove: $($key.PSPath). Error: $_" -ForegroundColor Red
            }
        }
    }

    # Limpeza de entradas de inicialização órfãs
    Write-Host "Cleaning up orphaned startup entries..."
    $startupKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($path in $startupKeys) {
        $keys = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        foreach ($key in $keys.PSObject.Properties) {
            $filePath = $key.Value
            if (!(Test-Path $filePath)) {
                try {
                    Remove-ItemProperty -Path $path -Name $key.Name -Force -ErrorAction SilentlyContinue
                    Write-Output "Removed orphaned startup entry: $($key.Name)"
                } catch {
                    Write-Output "Failed to remove: $($key.Name). Error: $_" -ForegroundColor Red
                }
            }
        }
    }

    Write-Host "Cleaning up orphaned start menu entries..."
    $startMenuPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage"
    )

    foreach ($path in $startMenuPaths) {
        $startMenuKeys = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        foreach ($key in $startMenuKeys.PSObject.Properties) {
            $appPath = $key.Value
            if ($appPath -and !(Test-Path $appPath)) {
                try {
                    Remove-ItemProperty -Path $path -Name $key.Name -Force -ErrorAction SilentlyContinue
                    Write-Output "Removed orphaned start menu entry: $($key.Name)"
                } catch {
                    Write-Output "Failed to remove: $($key.Name). Error: $_" -ForegroundColor Red
                }
            }
        }
    }

    # Limpeza de cache de DNS e logs
    Write-Host "Flushed DNS Cache"
    ipconfig /flushdns

    Write-Host "Clean Up the WinSxS Folder. This process can take a few minutes..."
    dism /online /cleanup-Image /StartComponentCleanup /ResetBase

    Write-Host "Clean Up the User Not Present Trace Session. This process can take a few minutes..."
    logman stop -ets UserNotPresentTraceSession | Out-Null


    Write-Host "Clean Up the Screen On Power Study Trace Session. This process can take a few minutes..."
    logman stop -ets ScreenOnPowerStudyTraceSession | Out-Null

    Write-Host "Clean Up the SleepStudy Folder. This process can take a few minutes..."
    if (Test-Path $Env:windir\System32\SleepStudy) {
        Get-ChildItem $Env:windir\System32\SleepStudy | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }

    Write-Host "Clearing All Event Viewer logs."
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object { Clear-EventLog $_.LogName -ErrorAction SilentlyContinue }  # For Windows 11
    Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }  # For Windows 10

    Write-Host "Deep system clean completed."
}


Function OptimizeVolume {
    Write-Host "Performs volume optimization according to storage technology..."

    <#
    The Optimize-Volume cmdlet optimizes a volume, performing defragmentation, trim, slab consolidation, and storage tier processing.
    If no parameter is specified, then the default operation will be performed per the drive type as follows.

    ·HDD, Fixed VHD, Storage Space. -Analyze -Defrag.
    ·Tiered Storage Space. -TierOptimize.
    ·SSD with TRIM support. -Retrim.
    ·Storage Space (Thinly provisioned), SAN Virtual Disk (Thinly provisioned), Dynamic VHD, Differencing VHD. -Analyze -SlabConsolidate -Retrim.
    ·SSD without TRIM support, Removable FAT, Unknown. No operation.
    #>

    # Obtém todos os volumes (unidades) no sistema
    $volumes = Get-Volume

    # Itera por cada volume e executa a otimização adequada
    foreach ($volume in $volumes) {
        if ($volume.FileSystemType -eq "NTFS") {  # Verifica se o volume é do tipo NTFS
            # Verifica se há um DriveLetter associado
            if ($volume.DriveLetter) {
                try {
                    # Executa otimização padrão
                    Optimize-Volume -DriveLetter $volume.DriveLetter -Verbose
                    Write-Host "Otimização concluída para o volume $($volume.DriveLetter)."
                } catch {
                    Write-Host "Erro ao otimizar o volume $($volume.DriveLetter): $_"
                }
            } else {
                Write-Host "Volume sem letra de unidade não está associado a um disco físico."
            }
        }
    }
}


Function WaitForKey {
    Stop-Transcript -ErrorAction SilentlyContinue  # Finaliza a transcrição, se houver
    Write-Host "Unloading the HKCR drive..."  # Mensagem informando a remoção da unidade HKCR

    # Remove a unidade de registro HKCR, caso tenha sido montada anteriormente
    Remove-PSDrive HKCR -ErrorAction SilentlyContinue

    # Mensagem final para o usuário e espera por uma tecla
    Write-Output "`nEnd of script execution. Press any key to continue..."
    [Console]::ReadKey($true) | Out-Null  # Aguarda o usuário pressionar uma tecla e não mostra o input
}


Function Restart {
    # Verifica se o PowerShell está sendo executado como Administrador
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script needs to be run as an Administrator to restart the computer." -ForegroundColor Red
        return
    }

    # Adiciona tipos necessários para a caixa de mensagem
    Add-Type -AssemblyName PresentationCore, PresentationFramework

    # Define os botões e mensagens
    $Button = [Windows.MessageBoxButton]::YesNoCancel
    $Reboot = "Consider restarting your operating system for some of the changes you made to take effect."
    $Warn = [Windows.MessageBoxImage]::Warning

    # Exibe a caixa de mensagem
    $Prompt0 = [Windows.MessageBox]::Show($Reboot, "Reboot", $Button, $Warn)

    # Verifica a resposta do usuário
    Switch ([System.Windows.MessageBoxResult]$Prompt0) {
        "Yes" {
            Start-Sleep -Seconds 1
            Write-Host "Initiating reboot..."
            Start-Sleep -Seconds 1
            Restart-Computer -Force
        }
        "No" {
            Start-Sleep -Seconds 1
            Write-Host "Exiting..."
            Start-Sleep -Seconds 1
            Exit
        }
        "Cancel" {
            Start-Sleep -Seconds 1
            Write-Host "Operation canceled."
            Exit
        }
    }
}


Clear-Host

# Array para armazenar ajustes e argumentos do comando
$tweaks = @()
$PSCommandArgs = @()

# Parse and resolve paths in past previous arguments
$i = 0
While ($i -lt $args.Length) {
    if ($args[$i].ToLower() -eq "-include") {
        # Resolve full path to the included file
        $include = Resolve-Path $args[++$i] -ErrorAction SilentlyContinue
        $PSCommandArgs += "-include `"$include`""
        # Import the included file as a module, with error handling
        try {
            Import-Module -Name $include -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Error importing module: $_" -ForegroundColor Red
            Exit
        }
    } elseif ($args[$i].ToLower() -eq "-preset") {
        # Resolve full path to the preset file
        $preset = Resolve-Path $args[++$i] -ErrorAction SilentlyContinue
        $PSCommandArgs += "-preset `"$preset`""
        # Load each tweak function defined in the preset file
        if (Test-Path $preset) {
            Get-Content $preset -ErrorAction SilentlyContinue | ForEach-Object {
                $line = $_.Split("#")[0].Trim()
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    AddOrRemoveTweak($line)
                }
            }
        } else {
            Write-Host "Preset file not found: $preset" -ForegroundColor Red
            Exit
        }
    }
    $i++
}

# Call each tweak function defined in the preset file
$tweaks | ForEach-Object {
    try {
        Invoke-Expression $_
    } catch {
        Write-Host "Error invoking tweak function: $_" -ForegroundColor Red
    }
}