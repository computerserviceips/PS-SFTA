<#
.SYNOPSIS
    Set File Type Association Windows 8/10/11

.DESCRIPTION
    Set File/Protocol Type Association Default Application Windows 8/10/11

.NOTES
    Version    : 1.3.0
    Author(s)  : Danyfirex & Dany3j
    Maintainer : winnme
    Credits    : https://bbs.pediy.com/thread-213954.htm
                 LMongrain - Hash Algorithm PureBasic Version
    License    : MIT License
    Copyright  : 2022 Danysys. <danysys.com>
                 2025 Computerservice ips
  
.EXAMPLE
    Get-FTA
    Show All Application Program Id

.EXAMPLE
    Get-FTA .pdf
    Show Default Application Program Id for an Extension

.EXAMPLE
    Get-FTA -Extension .pdf -Detailed
    Show Default Application Program Id and Hash for an Extension

.EXAMPLE
    Set-FTA AcroExch.Document.DC .pdf
    Set Acrobat Reader DC as Default .pdf reader
 
.EXAMPLE
    Set-FTA Applications\SumatraPDF.exe .pdf
    Set Sumatra PDF as Default .pdf reader

.EXAMPLE
    Set-PTA ChromeHTML http
    Set Google Chrome as Default for http Protocol

.EXAMPLE
    Register-FTA "C:\SumatraPDF.exe" .pdf -Icon "shell32.dll,100"
    Register Application and Set as Default for .pdf reader

.EXAMPLE
    Remove-FTA -Extension .pdf -ExtensionOnly
    Remove user specific File Type Association for .pdf

.LINK
    https://github.com/DanysysTeam/PS-SFTA
    
#>



function Get-FTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $false)]
    [String]
    $Extension,

    [Parameter(Mandatory = $false)]
    [switch]
    $Detailed
  )

  $powershellExePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $powershellTempName = "powershell_{0}.exe" -f ([System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName()))
  $powershellTempPath = Join-Path -Path (Split-Path -Path $powershellExePath) -ChildPath $powershellTempName
  $tempPowerShellCreated = $false

  function local:Invoke-RenamedPowerShell {
    param (
      [Parameter(Mandatory = $true)]
      [scriptblock]
      $ScriptBlock,

      [object[]]
      $ArgumentList = @()
    )

    & $powershellTempPath -NoProfile -NonInteractive -Command $ScriptBlock @ArgumentList
  }

  try {
    Copy-Item -Path $powershellExePath -Destination $powershellTempPath -Force -ErrorAction Stop
    $tempPowerShellCreated = $true

    $scriptBlock = {
      param($extension, $detailed)

      if ($extension) {
        Write-Verbose "Get File Type Association for $extension"

        $assocFile = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$extension\UserChoice" -ErrorAction SilentlyContinue

        if ($detailed) {
          [PSCustomObject]@{
            Extension = $extension
            ProgId    = $assocFile.ProgId
            Hash      = $assocFile.Hash
          }
        }
        else {
          $assocFile.ProgId
        }
      }
      else {
        Write-Verbose "Get File Type Association List"

        Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\* |
        ForEach-Object {
          $assocFile = Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue
          if ($assocFile.ProgId) {
            if ($detailed) {
              [PSCustomObject]@{
                Extension = $_.PSChildName
                ProgId    = $assocFile.ProgId
                Hash      = $assocFile.Hash
              }
            }
            else {
              "$($_.PSChildName), $($assocFile.ProgId)"
            }
          }
        }
      }
    }

    Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($Extension, $Detailed)
  }
  finally {
    if ($tempPowerShellCreated) {
      try { Remove-Item -Path $powershellTempPath -Force -ErrorAction SilentlyContinue } catch {}
    }
  }
}

function Get-PTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $false)]
    [String]
    $Protocol
  )

  $powershellExePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $powershellTempName = "powershell_{0}.exe" -f ([System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName()))
  $powershellTempPath = Join-Path -Path (Split-Path -Path $powershellExePath) -ChildPath $powershellTempName
  $tempPowerShellCreated = $false

  function local:Invoke-RenamedPowerShell {
    param (
      [Parameter(Mandatory = $true)]
      [scriptblock]
      $ScriptBlock,

      [object[]]
      $ArgumentList = @()
    )

    & $powershellTempPath -NoProfile -NonInteractive -Command $ScriptBlock @ArgumentList
  }

  try {
    Copy-Item -Path $powershellExePath -Destination $powershellTempPath -Force -ErrorAction Stop
    $tempPowerShellCreated = $true

    $scriptBlock = {
      param($protocol)

      if ($protocol) {
        Write-Verbose "Get Protocol Type Association for $protocol"

        (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$protocol\UserChoice" -ErrorAction SilentlyContinue).ProgId
      }
      else {
        Write-Verbose "Get Protocol Type Association List"

        Get-ChildItem HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\* |
        ForEach-Object {
          $progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
          if ($progId) {
            "$($_.PSChildName), $progId"
          }
        }
      }
    }

    Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($Protocol)
  }
  finally {
    if ($tempPowerShellCreated) {
      try { Remove-Item -Path $powershellTempPath -Force -ErrorAction SilentlyContinue } catch {}
    }
  }
}

function Register-FTA {
  [CmdletBinding()]
  param (
    [Parameter( Position = 0, Mandatory = $true)]
    [ValidateScript( { Test-Path $_ })]
    [String]
    $ProgramPath,

    [Parameter( Position = 1, Mandatory = $true)]
    [Alias("Protocol")]
    [String]
    $Extension,

    [Parameter( Position = 2, Mandatory = $false)]
    [String]
    $ProgId,

    [Parameter( Position = 3, Mandatory = $false)]
    [String]
    $Icon
  )

  Write-Verbose "Register Application + Set Association"
  Write-Verbose "Application Path: $ProgramPath"
  if ($Extension.Contains(".")) {
    Write-Verbose "Extension: $Extension"
  }
  else {
    Write-Verbose "Protocol: $Extension"
  }

  if (!$ProgId) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgramPath).replace(" ", "") + $Extension
  }

  $progCommand = '""{0}"" ""%1""' -f $ProgramPath
  Write-Verbose "ApplicationId: $ProgId"
  Write-Verbose "ApplicationCommand: $progCommand"

  $powershellExePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $powershellTempName = "powershell_{0}.exe" -f ([System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName()))
  $powershellTempPath = Join-Path -Path (Split-Path -Path $powershellExePath) -ChildPath $powershellTempName
  $tempPowerShellCreated = $false

  function local:Invoke-RenamedPowerShell {
    param (
      [Parameter(Mandatory = $true)]
      [scriptblock]
      $ScriptBlock,

      [object[]]
      $ArgumentList = @()
    )

    & $powershellTempPath -NoProfile -NonInteractive -Command $ScriptBlock @ArgumentList
  }

  try {
    Copy-Item -Path $powershellExePath -Destination $powershellTempPath -Force -ErrorAction Stop
    $tempPowerShellCreated = $true
  }
  catch {
    throw "Register ProgId and ProgId Command FAILED: Unable to create temporary PowerShell copy"
  }

  try {
    $scriptBlock = {
      param($extension, $progId, $progCommand)

      $openWithKeyPath = "HKCU:\SOFTWARE\Classes\$extension\OpenWithProgids"
      $commandKeyPath = "HKCU:\SOFTWARE\Classes\$progId\shell\open\command"

      try {
        if (-not (Test-Path -Path $openWithKeyPath)) {
          New-Item -Path $openWithKeyPath -Force | Out-Null
        }

        New-ItemProperty -Path $openWithKeyPath -Name $progId -Value ([byte[]]@()) -PropertyType None -Force -ErrorAction Stop | Out-Null

        New-Item -Path $commandKeyPath -Force | Out-Null
        Set-ItemProperty -Path $commandKeyPath -Name '(default)' -Value $progCommand -Force -ErrorAction Stop | Out-Null

        Write-Verbose "Register ProgId and ProgId Command OK"
      }
      catch {
        throw "Register ProgId and ProgId Command FAILED"
      }
    }

    Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($Extension, $ProgId, $progCommand)
  }
  finally {
    if ($tempPowerShellCreated) {
      try { Remove-Item -Path $powershellTempPath -Force -ErrorAction SilentlyContinue } catch {}
    }
  }

  Set-FTA -ProgId $ProgId -Extension $Extension -Icon $Icon
}


function Remove-FTA {
  [CmdletBinding(DefaultParameterSetName = "Full")]
  param (
    [Parameter(Mandatory = $true, ParameterSetName = "Full")]
    [Alias("ProgId")]
    [String]
    $ProgramPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Full")]
    [Parameter(Mandatory = $true, ParameterSetName = "ExtensionOnly")]
    [String]
    $Extension,

    [Parameter(Mandatory = $false, ParameterSetName = "ExtensionOnly")]
    [switch]
    $ExtensionOnly
  )

  $powershellExePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $powershellTempName = "powershell_{0}.exe" -f ([System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName()))
  $powershellTempPath = Join-Path -Path (Split-Path -Path $powershellExePath) -ChildPath $powershellTempName
  $tempPowerShellCreated = $false

  function local:Invoke-RenamedPowerShell {
    param (
      [Parameter(Mandatory = $true)]
      [scriptblock]
      $ScriptBlock,

      [object[]]
      $ArgumentList = @()
    )

    & $powershellTempPath -NoProfile -NonInteractive -Command $ScriptBlock @ArgumentList
  }

  try {
    Copy-Item -Path $powershellExePath -Destination $powershellTempPath -Force -ErrorAction Stop
    $tempPowerShellCreated = $true
  }
  catch {
    throw "Remove-FTA FAILED: Unable to create temporary PowerShell copy"
  }

  function local:Update-Registry {
    $code = @'
    [System.Runtime.InteropServices.DllImport("Shell32.dll")]
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);
    }
'@

    try {
      Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
    }
    catch {}

    try {
      [SHChange.Notify]::Refresh()
    }
    catch {}
  }

  try {
    if ($PSCmdlet.ParameterSetName -eq "ExtensionOnly") {
      $scriptBlock = {
        param($extension)

        $userChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$extension\UserChoice"
        if (Test-Path -Path $userChoicePath) {
          try {
            Remove-Item -Path $userChoicePath -Recurse -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Remove UserChoice Key If Exist: $userChoicePath"
          }
          catch {
            Write-Verbose "UserChoice Key No Exist: $userChoicePath"
          }
        }
        else {
          Write-Verbose "UserChoice Key No Exist: $userChoicePath"
        }
      }

      Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($Extension)

      Update-Registry
      Write-Output "Removed: $Extension"
    }
    else {
      if (Test-Path -Path $ProgramPath) {
        $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgramPath).replace(" ", "") + $Extension
      }
      else {
        $ProgId = $ProgramPath
      }

      $scriptBlock = {
        param($extension, $progId)

        $userChoicePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$extension\UserChoice"
        $classPath = "HKCU:\SOFTWARE\Classes\$progId"
        $openWithKey = "HKCU:\SOFTWARE\Classes\$extension\OpenWithProgids"

        if (Test-Path -Path $userChoicePath) {
          try {
            Remove-Item -Path $userChoicePath -Recurse -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Remove User UserChoice Key If Exist: $userChoicePath"
          }
          catch {
            Write-Verbose "UserChoice Key No Exist: $userChoicePath"
          }
        }
        else {
          Write-Verbose "UserChoice Key No Exist: $userChoicePath"
        }

        if (Test-Path -Path $classPath) {
          try {
            Remove-Item -Path $classPath -Recurse -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Remove Key If Exist: $classPath"
          }
          catch {
            Write-Verbose "Key No Exist: $classPath"
          }
        }
        else {
          Write-Verbose "Key No Exist: $classPath"
        }

        if (Test-Path -Path $openWithKey) {
          try {
            Remove-ItemProperty -Path $openWithKey -Name $progId -ErrorAction Stop | Out-Null
            Write-Verbose "Remove Property If Exist: $openWithKey Property $progId"
          }
          catch {
            Write-Verbose "Property No Exist: $openWithKey Property: $progId"
          }
        }
        else {
          Write-Verbose "Property No Exist: $openWithKey Property: $progId"
        }
      }

      Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($Extension, $ProgId)

      Update-Registry
      Write-Output "Removed: $ProgId"
    }
  }
  finally {
    if ($tempPowerShellCreated) {
      try { Remove-Item -Path $powershellTempPath -Force -ErrorAction SilentlyContinue } catch {}
    }
  }
}

function Set-FTA {

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [String]
    $ProgId,

    [Parameter(Mandatory = $true)]
    [Alias("Protocol")]
    [String]
    $Extension,

    [String]
    $Icon,

    [String]
    $AllowedGroup,

    [switch]
    $DomainSID,

    [switch]
    $SuppressNewAppAlert,

    [String]
    $LogFile,

    [switch]
    $Silent,

    [switch]
    $SkipExplorerRestart,

    [switch]
    $PassThru
  )

  $powershellExePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $powershellTempName = "powershell_{0}.exe" -f ([System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName()))
  $powershellTempPath = Join-Path -Path (Split-Path -Path $powershellExePath) -ChildPath $powershellTempName
  $tempPowerShellCreated = $false

  $logFilePath = $null
  if ($LogFile) {
    $logFilePath = If ([System.IO.Path]::IsPathRooted($LogFile)) { $LogFile } Else { Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $LogFile }

    try {
      $logDirectory = Split-Path -Path $logFilePath -Parent
      if ($logDirectory -and -not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
      }

      if (-not (Test-Path -Path $logFilePath)) {
        New-Item -Path $logFilePath -ItemType File -Force | Out-Null
      }
    }
    catch {
      Write-Verbose ("Unable to initialize log file at {0}: {1}" -f $logFilePath, $_)
      $logFilePath = $null
    }
  }

  function local:Write-LogMessage {
    param (
      [string] $Message,
      [string] $Level = 'INFO',
      [string] $Color = 'Gray'
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    if ($logFilePath) {
      try {
        "$timestamp [$Level] $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
      }
      catch {
        Write-Verbose ("Failed to write to log file {0}: {1}" -f $logFilePath, $_)
      }
    }

    if (-not $Silent) {
      switch ($Level) {
        'WARN'  { Write-Warning "[SFTA] $Message" }
        'ERROR' { Write-Error "[SFTA] $Message" -ErrorAction Continue }
        default { Write-Host "[SFTA] $Message" -ForegroundColor $Color }
      }
    }
  }

  function local:Is-InGroup {
    param (
      [string] $GroupName
    )

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
      return $true
    }

    try {
      $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
      $principal = [Security.Principal.WindowsPrincipal] $identity

      if ($principal.IsInRole($GroupName)) {
        return $true
      }

      $sid = (New-Object Security.Principal.NTAccount($GroupName)).Translate([Security.Principal.SecurityIdentifier]).Value
      return $principal.IsInRole($sid)
    }
    catch {
      Write-Verbose "Group membership check failed for '$GroupName': $_"
    }

    return $false
  }

    function local:Get-CurrentAssociation {
      param (
        [Parameter(Mandatory = $true)]
        [string]
        $Target
      )

      $scriptBlock = {
        param($target)

        $result = [ordered]@{
          ProgId           = $null
          Hash             = $null
          LatestProgId     = $null
          LatestHash       = $null
          Type             = 'Extension'
        }

        if ($target.Contains('.')) {
          $userChoice = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$target\UserChoice" -ErrorAction SilentlyContinue
          $latestChoice = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$target\UserChoiceLatest" -ErrorAction SilentlyContinue
          $result.ProgId = $userChoice.ProgId
          $result.Hash = $userChoice.Hash
          $result.LatestProgId = $latestChoice.ProgId
          $result.LatestHash = $latestChoice.Hash
        }
        else {
          $result.Type = 'Protocol'
          $userChoice = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$target\UserChoice" -ErrorAction SilentlyContinue
          $result.ProgId = $userChoice.ProgId
          $result.Hash = $userChoice.Hash
        }

        return [PSCustomObject]$result
      }

      Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($Target)
    }

  try {
    # Use a temporary copy of PowerShell to bypass UCPD.sys registry write restrictions (e.g., KB5034765)
    Copy-Item -Path $powershellExePath -Destination $powershellTempPath -Force -ErrorAction Stop
    $tempPowerShellCreated = $true
  }
  catch {
    Write-LogMessage "Unable to create a temporary copy of PowerShell. Registry updates cannot proceed." 'ERROR' 'Red'
    throw
  }

  function local:Invoke-RenamedPowerShell {
    param (
      [Parameter(Mandatory = $true)]
      [scriptblock]
      $ScriptBlock,

      [object[]]
      $ArgumentList = @()
    )

    & $powershellTempPath -NoProfile -NonInteractive -Command $ScriptBlock @ArgumentList
  }

  if (Test-Path -Path $ProgId) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgId).replace(" ", "") + $Extension
  }

  $targetType = If ($Extension.Contains(".")) { "extension" } Else { "protocol" }
  if ($logFilePath) {
    Write-LogMessage "Logging enabled at: $logFilePath" 'INFO' 'Gray'
  }

  Write-LogMessage "Applying default $targetType '$Extension' to ProgId '$ProgId'..." 'INFO' 'Cyan'

  if (-not (Is-InGroup $AllowedGroup)) {
    Write-LogMessage "Skipping $targetType '$Extension' because the current user is not in group '$AllowedGroup'." 'WARN' 'Yellow'
    return
  }

  Write-Verbose "ProgId: $ProgId"
  Write-Verbose "Extension/Protocol: $Extension"

  function local:Disable-NewAppAlertToast {
    $scriptBlock = {
      $policyRoots = @('HKCU:\Software\Policies\Microsoft\Windows\Explorer')

      $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()

      if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $policyRoots += 'HKLM:\Software\Policies\Microsoft\Windows\Explorer'
      }

      foreach ($policyPath in $policyRoots) {
        try {
          if (-not (Test-Path -Path $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
          }

          $toastValue = Set-ItemProperty -Path $policyPath -Name 'NoNewAppAlert' -Value 1 -Type DWord -PassThru -ErrorAction Stop
          Write-Verbose "New app alert toast disabled: $($toastValue.PSPath)"
        }
        catch {
          Write-Verbose "Failed to disable new app alert toast at $policyPath"
        }
      }
    }

    Invoke-RenamedPowerShell -ScriptBlock $scriptBlock
  }

  if ($SuppressNewAppAlert) {
    Write-LogMessage "Disabling new app alert prompts..." 'INFO' 'Yellow'
    Disable-NewAppAlertToast
  }


  #Write required Application Ids to ApplicationAssociationToasts
  #When more than one application associated with an Extension/Protocol is installed ApplicationAssociationToasts need to be updated
  function local:Write-RequiredApplicationAssociationToasts {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Extension
    )

    $scriptBlock = {
      param($progId, $extension)

      try {
        $keyPath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts"
        New-Item -Path $keyPath -Force | Out-Null
        Set-ItemProperty -Path $keyPath -Name "$progId`_$extension" -Value 0 -Type DWord -Force -ErrorAction Stop | Out-Null
        Write-Verbose ("Write Reg ApplicationAssociationToasts OK: " + $progId + "_" + $extension)
      }
      catch {
        Write-Verbose ("Write Reg ApplicationAssociationToasts FAILED: " + $progId + "_" + $extension)
      }

      $allApplicationAssociationToasts = Get-ChildItem -Path HKLM:\SOFTWARE\Classes\$extension\OpenWithList\* -ErrorAction SilentlyContinue |
      ForEach-Object {
        "Applications\$($_.PSChildName)"
      }

      $allApplicationAssociationToasts += @(
        ForEach ($item in (Get-ItemProperty -Path HKLM:\SOFTWARE\Classes\$extension\OpenWithProgids -ErrorAction SilentlyContinue).PSObject.Properties ) {
          if ([string]::IsNullOrEmpty($item.Value) -and $item -ne "(default)") {
            $item.Name
          }
        })


      $allApplicationAssociationToasts += Get-ChildItem -Path HKLM:SOFTWARE\Clients\StartMenuInternet\* , HKCU:SOFTWARE\Clients\StartMenuInternet\* -ErrorAction SilentlyContinue |
      ForEach-Object {
      (Get-ItemProperty ("$($_.PSPath)\Capabilities\" + (@("URLAssociations", "FileAssociations") | Select-Object -Index $extension.Contains("."))) -ErrorAction SilentlyContinue).$extension
      }

      $allApplicationAssociationToasts |
      ForEach-Object { if ($_) {
          if (Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts $_"_"$extension -Value 0 -Type DWord -ErrorAction SilentlyContinue -PassThru) {
            Write-Verbose  ("Write Reg ApplicationAssociationToastsList OK: " + $_ + "_" + $extension)
          }
          else {
            Write-Verbose  ("Write Reg ApplicationAssociationToastsList FAILED: " + $_ + "_" + $extension)
          }
        }
      }
    }

    Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($ProgId, $Extension)

  }

  function local:Update-RegistryChanges {
    $code = @'
    [System.Runtime.InteropServices.DllImport("Shell32.dll")]
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);    
    }
'@ 

    try {
      Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
    }
    catch {}

    try {
      [SHChange.Notify]::Refresh()
    }
    catch {}
  }

  function local:Restart-ExplorerShell {
    Write-LogMessage "Restarting explorer.exe to apply the changes..." 'INFO' 'Yellow'

    try {
      $existing = Get-Process -Name explorer -ErrorAction SilentlyContinue
      if ($existing) {
        Stop-Process -Id $existing.Id -Force -ErrorAction Stop
      }
    }
    catch {
      Write-LogMessage "Could not stop explorer.exe automatically: $_" 'WARN' 'Yellow'
    }

    try {
      Start-Process -FilePath (Join-Path -Path $env:SystemRoot -ChildPath 'explorer.exe') | Out-Null
      Write-LogMessage "explorer.exe restarted successfully." 'INFO' 'Green'
    }
    catch {
      Write-LogMessage "Failed to relaunch explorer.exe. Please start it manually to finalize defaults." 'WARN' 'Yellow'
    }
  }

  $changesApplied = $false
  $restartRequired = $false
  

    function local:Set-Icon {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Icon
    )

    $scriptBlock = {
      param($progId, $icon)

      try {
        $keyPath = "Registry::HKEY_CURRENT_USER\SOFTWARE\Classes\$progId\DefaultIcon"
        New-Item -Path $keyPath -Force | Out-Null
        Set-ItemProperty -Path $keyPath -Name '(default)' -Value $icon -Force -ErrorAction Stop | Out-Null
        Write-Verbose "Write Reg Icon OK"
        Write-Verbose "Reg Icon: $keyPath"
      }
      catch {
        Write-Verbose "Write Reg Icon FAILED"
      }
    }

    Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($ProgId, $Icon)
    }


    function local:Get-MachineIdBytes {
      $scriptBlock = {
        try {
          $machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
          if (-not [string]::IsNullOrWhiteSpace($machineGuid)) {
            return [System.Text.Encoding]::UTF8.GetBytes($machineGuid)
          }
        }
        catch {
          Write-Verbose "MachineGuid lookup failed, skipping UserChoiceLatest hash support"
        }

        return $null
      }

      Invoke-RenamedPowerShell -ScriptBlock $scriptBlock

    }


    function local:Get-NewHash {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $BaseInfo,

        [byte[]]
        $MachineIdBytes
      )

      $machineIdBytes = $MachineIdBytes
      if (-not $machineIdBytes) {
        $machineIdBytes = Get-MachineIdBytes
      }

      if (-not $machineIdBytes) {
        return $null
      }

      $hmac = [System.Security.Cryptography.HMACSHA256]::new($machineIdBytes)
      $hashBytes = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($BaseInfo.ToLower()))

      # UserChoiceLatest hashes observed in the wild are 8-byte payloads (base64 length 12)
      $trimmed = $hashBytes[0..7]
      return [Convert]::ToBase64String($trimmed)
    }



    function local:Clear-CurrentUserDenyRules {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $SubKey
      )

      $scriptBlock = {
        param($subKey)

        $desiredRights = [System.Security.AccessControl.RegistryRights]::FullControl

        try {
          $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::CurrentUser,
            [Microsoft.Win32.RegistryView]::Default
          )

          $key = $baseKey.OpenSubKey(
            $subKey,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            $desiredRights
          )

          if (-not $key) {
            $key = $baseKey.CreateSubKey(
              $subKey,
              [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
            )
          }

          if (-not $key) {
            Write-Verbose "Unable to open HKCU:\$subKey to adjust permissions"
            return
          }

          $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
          $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
          $denyRules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference -eq $currentSid -and $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny }

          $removed = $false

          foreach ($rule in $denyRules) {
            $acl.RemoveAccessRuleSpecific($rule) | Out-Null
            $removed = $true
          }

          $allowRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $currentSid,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
          )

          $acl.SetAccessRuleProtection($true, $false)
          $acl.SetAccessRule($allowRule)

          if ($removed) {
            Write-Verbose "Removed deny permissions for current user on HKCU:\$subKey"
          }
          else {
            Write-Verbose "No deny permissions for current user on HKCU:\$subKey"
          }

          $key.SetAccessControl($acl)

          $key.Close()
          $baseKey.Close()
        }
        catch [System.UnauthorizedAccessException] {
          Write-Verbose ("Unable to adjust permissions on HKCU:\{0} with standard rights: {1}" -f $subKey, $_)

          try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
              [Microsoft.Win32.RegistryHive]::CurrentUser,
              [Microsoft.Win32.RegistryView]::Default
            )

            $takeOwnershipRights = [System.Security.AccessControl.RegistryRights]::TakeOwnership -bor [System.Security.AccessControl.RegistryRights]::ReadPermissions
            $ownershipKey = $baseKey.OpenSubKey(
              $subKey,
              [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
              $takeOwnershipRights
            )

            if (-not $ownershipKey) {
              $ownershipKey = $baseKey.CreateSubKey(
                $subKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
              )
            }

            if (-not $ownershipKey) {
              Write-Verbose "Unable to take ownership of HKCU:\$subKey"
              return
            }

            $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $acl = $ownershipKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner)
            $acl.SetOwner($currentSid)
            $ownershipKey.SetAccessControl($acl)
            $ownershipKey.Close()

            # Retry with desired rights now that ownership was updated
            $retryKey = $baseKey.OpenSubKey(
              $subKey,
              [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
              $desiredRights
            )

            if ($retryKey) {
              $acl = $retryKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
              $denyRules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference -eq $currentSid -and $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny }

              foreach ($rule in $denyRules) {
                $acl.RemoveAccessRuleSpecific($rule) | Out-Null
              }

              $allowRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                $currentSid,
                [System.Security.AccessControl.RegistryRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
              )

              $acl.SetAccessRuleProtection($true, $false)
              $acl.SetAccessRule($allowRule)

              $retryKey.SetAccessControl($acl)
              Write-Verbose "Removed deny permissions for current user on HKCU:\$subKey after taking ownership"
              $retryKey.Close()
            }
            else {
              Write-Verbose "Unable to reopen HKCU:\$subKey after taking ownership"
            }

            $baseKey.Close()
          }
          catch {
            Write-Verbose ("Unable to take ownership of HKCU:\{0}: {1}" -f $subKey, $_)
          }
        }
        catch {
          Write-Verbose ("Unable to adjust permissions on HKCU:\{0}: {1}" -f $subKey, $_)
        }
      }

      Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($SubKey)
    }

    function local:Write-ExtensionKeys {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Extension,

      [Parameter( Position = 2, Mandatory = $True )]
      [String]
      $ProgHash
    )

    $scriptBlock = {
      param($extension, $progId, $progHash, $newHash)

      $basePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$extension"

      foreach ($choiceKey in 'UserChoice','UserChoiceLatest') {
        $choicePath = "$basePath\$choiceKey"
        if (Test-Path -Path $choicePath) {
          try {
            Remove-Item -Path $choicePath -Recurse -Force -ErrorAction Stop
            Write-Verbose "Remove Extension $choiceKey Key OK: $choicePath"
          }
          catch {
            Write-Verbose "Extension $choiceKey Key No Exist: $choicePath"
          }
        }
      }

      try {
        $openWithKeyPath = "$basePath\OpenWithProgids"
        if (-not (Test-Path -Path $openWithKeyPath)) {
          New-Item -Path $openWithKeyPath -Force | Out-Null
        }

        New-ItemProperty -Path $openWithKeyPath -Name $progId -Value ([byte[]]@()) -PropertyType None -Force -ErrorAction Stop | Out-Null
        Write-Verbose "Write Reg Extension OpenWithProgids OK: $openWithKeyPath"
      }
      catch {
        Write-Verbose "Write Reg Extension OpenWithProgids FAILED: $openWithKeyPath"
      }

      try {
        $userChoicePath = "$basePath\UserChoice"
        New-Item -Path $userChoicePath -Force | Out-Null
        New-ItemProperty -Path $userChoicePath -Name 'ProgId' -Value $progId -PropertyType String -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $userChoicePath -Name 'Hash' -Value $progHash -PropertyType String -Force -ErrorAction Stop | Out-Null

        if ($newHash) {
          $latestChoicePath = "$basePath\UserChoiceLatest"
          New-Item -Path $latestChoicePath -Force | Out-Null
          New-ItemProperty -Path $latestChoicePath -Name 'ProgId' -Value $progId -PropertyType String -Force -ErrorAction Stop | Out-Null
          New-ItemProperty -Path $latestChoicePath -Name 'Hash' -Value $newHash -PropertyType String -Force -ErrorAction Stop | Out-Null

          $latestProgIdPath = "$latestChoicePath\ProgId"
          New-Item -Path $latestProgIdPath -Force | Out-Null
          New-ItemProperty -Path $latestProgIdPath -Name 'ProgId' -Value $progId -PropertyType String -Force -ErrorAction Stop | Out-Null
        }

        Write-Verbose "Write Reg Extension UserChoice/UserChoiceLatest OK"
      }
      catch {
        throw "Write Reg Extension UserChoice FAILED: $($_.Exception.Message)"
      }
    }

    Clear-CurrentUserDenyRules "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\$Extension\\UserChoice"

    $newHash = Get-NewHash "$Extension$userSid$ProgId$userDateTime$userExperience" $machineIdBytes

    if ($newHash) {
      Clear-CurrentUserDenyRules "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\$Extension\\UserChoiceLatest"
    }

    Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($Extension, $ProgId, $ProgHash, $newHash)
    }

  function local:Write-ProtocolKeys {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Protocol,

      [Parameter( Position = 2, Mandatory = $True )]
      [String]
      $ProgHash
    )

    $scriptBlock = {
      param($protocol, $progId, $progHash)

      $userChoicePath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$protocol\UserChoice"

      try {
        if (Test-Path -Path $userChoicePath) {
          Remove-Item -Path $userChoicePath -Recurse -Force -ErrorAction Stop | Out-Null
          Write-Verbose "Remove Protocol UserChoice Key If Exist: $userChoicePath"
        }
        else {
          Write-Verbose "Protocol UserChoice Key No Exist: $userChoicePath"
        }
      }
      catch {
        Write-Verbose "Protocol UserChoice Key No Exist: $userChoicePath"
      }

      try {
        New-Item -Path $userChoicePath -Force | Out-Null
        New-ItemProperty -Path $userChoicePath -Name 'ProgId' -PropertyType String -Value $progId -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $userChoicePath -Name 'Hash' -PropertyType String -Value $progHash -Force -ErrorAction Stop | Out-Null
        Write-Verbose "Write Reg Protocol UserChoice OK"
      }
      catch {
        throw "Write Reg Protocol UserChoice FAILED"
      }
    }

    Clear-CurrentUserDenyRules "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\$Protocol\\UserChoice"

    Invoke-RenamedPowerShell -ScriptBlock $scriptBlock -ArgumentList @($Protocol, $ProgId, $ProgHash)

  }

  
  function local:Get-UserExperience {
    [OutputType([string])]
    $hardcodedExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
    $userExperienceSearch = "User Choice set via Windows User Experience"
    $userExperienceString = ""
    $user32Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
    $fileStream = [System.IO.File]::Open($user32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $binaryReader = New-Object System.IO.BinaryReader($fileStream)
    [Byte[]] $bytesData = $binaryReader.ReadBytes(5mb)
    $fileStream.Close()
    $dataString = [Text.Encoding]::Unicode.GetString($bytesData)
    $position1 = $dataString.IndexOf($userExperienceSearch)
    $position2 = $dataString.IndexOf("}", $position1)
    try {
      $userExperienceString = $dataString.Substring($position1, $position2 - $position1 + 1)
    }
    catch {
      $userExperienceString = $hardcodedExperience
    }
    Write-Output $userExperienceString
  }
  

  function local:Get-UserSid {
    [OutputType([string])]
    $userSid = ((New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()
    Write-Output $userSid
  }

  #use in this special case
  #https://github.com/DanysysTeam/PS-SFTA/pull/7
  function local:Get-UserSidDomain {
    if (-not ("System.DirectoryServices.AccountManagement" -as [type])) {
      Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    }
    [OutputType([string])]
    $userSid = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).SID.Value.ToLower()
    Write-Output $userSid
  }



  function local:Get-HexDateTime {
    [OutputType([string])]

    $now = [DateTime]::Now
    $dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
    $fileTime = $dateTime.ToFileTime()
    $hi = ($fileTime -shr 32)
    $low = ($fileTime -band 0xFFFFFFFFL)
    $dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
    Write-Output $dateTimeHex
  }
  
  function Get-Hash {
    [CmdletBinding()]
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [string]
      $BaseInfo
    )


    function local:Get-ShiftRight {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [long] $iValue, 
            
        [Parameter( Position = 1, Mandatory = $true)]
        [int] $iCount 
      )
    
      if ($iValue -band 0x80000000) {
        Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
      }
      else {
        Write-Output  ($iValue -shr $iCount)
      }
    }
    

    function local:Get-Long {
      [CmdletBinding()]
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [byte[]] $Bytes,
    
        [Parameter( Position = 1)]
        [int] $Index = 0
      )
    
      Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
    }
    

    function local:Convert-Int32 {
      param (
        [Parameter( Position = 0, Mandatory = $true)]
        [long] $Value
      )
    
      [byte[]] $bytes = [BitConverter]::GetBytes($Value)
      return [BitConverter]::ToInt32( $bytes, 0) 
    }

    [Byte[]] $bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo) 
    $bytesBaseInfo += 0x00, 0x00  
    
    $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    [Byte[]] $bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
    
    $lengthBase = ($baseInfo.Length * 2) + 2 
    $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase  2) - 1
    $base64Hash = ""

    if ($length -gt 1) {
    
      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
        R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
      }
    
      $map.CACHE = 0
      $map.OUTHASH1 = 0
      $map.PDATA = 0
      $map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
      $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
      $map.INDEX = Get-ShiftRight ($length - 2) 1
      $map.COUNTER = $map.INDEX + 1
    
      while ($map.COUNTER) {
        $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
        $map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
        $map.PDATA = $map.PDATA + 8
        $map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
        $map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
        $map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16) ))
        $map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
        $map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
        $map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
        $map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
        $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
        $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
        $map.CACHE = ([long]$map.OUTHASH2)
        $map.COUNTER = $map.COUNTER - 1
      }

      [Byte[]] $outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      [byte[]] $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
      $buffer.CopyTo($outHash, 0)
      $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
      $buffer.CopyTo($outHash, 4)
    
      $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
        R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
      }
    
      $map.CACHE = 0
      $map.OUTHASH1 = 0
      $map.PDATA = 0
      $map.MD51 = ((Get-Long $bytesMD5) -bor 1)
      $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
      $map.INDEX = Get-ShiftRight ($length - 2) 1
      $map.COUNTER = $map.INDEX + 1

      while ($map.COUNTER) {
        $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
        $map.PDATA = $map.PDATA + 8
        $map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
        $map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
        $map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
        $map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
        $map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
        $map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
        $map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
        $map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
        $map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
        $map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
        $map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3) 
        $map.CACHE = ([long]$map.OUTHASH2)
        $map.COUNTER = $map.COUNTER - 1
      }
    
      $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
      $buffer.CopyTo($outHash, 8)
      $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
      $buffer.CopyTo($outHash, 12)
    
      [Byte[]] $outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
      $hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
      $hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))
    
      $buffer = [BitConverter]::GetBytes($hashValue1)
      $buffer.CopyTo($outHashBase, 0)
      $buffer = [BitConverter]::GetBytes($hashValue2)
      $buffer.CopyTo($outHashBase, 4)
      $base64Hash = [Convert]::ToBase64String($outHashBase) 
    }

    Write-Output $base64Hash
  }

  try {
    Write-Verbose "Getting Hash For $ProgId   $Extension"
    If ($DomainSID.IsPresent) { Write-Verbose  "Use Get-UserSidDomain" } Else { Write-Verbose  "Use Get-UserSid" }
    $userSid = If ($DomainSID.IsPresent) { Get-UserSidDomain } Else { Get-UserSid }
    $userExperience = Get-UserExperience
    $userDateTime = Get-HexDateTime
    Write-Debug "UserDateTime: $userDateTime"
    Write-Debug "UserSid: $userSid"
    Write-Debug "UserExperience: $userExperience"

    $baseInfo = "$Extension$userSid$ProgId$userDateTime$userExperience".ToLower()
    Write-Verbose "baseInfo: $baseInfo"

    $progHash = Get-Hash $baseInfo
    Write-Verbose "Hash: $progHash"

    $machineIdBytes = $null
    if ($Extension.Contains('.')) {
      $machineIdBytes = Get-MachineIdBytes
    }

    $current = Get-CurrentAssociation $Extension
    $targetMatches = $current.ProgId -eq $ProgId -and (($current.Type -eq 'Protocol') -or (-not $current.LatestProgId -or $current.LatestProgId -eq $ProgId))
    $hashesMissing = [string]::IsNullOrWhiteSpace($current.Hash)

    if ($current.Type -eq 'Extension' -and $machineIdBytes) {
      if (-not $current.LatestProgId -or $current.LatestProgId -ne $ProgId) {
        $hashesMissing = $true
      }
    }

    if ($current.Type -eq 'Extension' -and $current.LatestProgId -and $current.LatestProgId -eq $ProgId) {
      if ([string]::IsNullOrWhiteSpace($current.LatestHash)) {
        $hashesMissing = $true
      }
    }

    if ($targetMatches -and -not $hashesMissing) {
      Write-LogMessage "Skipping $targetType '$Extension' because '$ProgId' is already set with required hashes." 'INFO' 'Gray'
      $restartRequired = $false
    }
    else {
      #Write AssociationToasts List
      Write-RequiredApplicationAssociationToasts $ProgId $Extension

      #Handle Extension Or Protocol
      if ($Extension.Contains(".")) {
        Write-Verbose "Write Registry Extension: $Extension"
        Write-LogMessage "Updating file association registry keys..." 'INFO' 'Cyan'
        Write-ExtensionKeys $ProgId $Extension $progHash

      }
      else {
        Write-Verbose "Write Registry Protocol: $Extension"
        Write-LogMessage "Updating protocol association registry keys..." 'INFO' 'Cyan'
        Write-ProtocolKeys $ProgId $Extension $progHash
      }

      if ($Icon) {
        Write-Verbose  "Set Icon: $Icon"
        Set-Icon $ProgId $Icon
      }

      $changesApplied = $true
      $restartRequired = $true

      Update-RegistryChanges

      if (-not $SkipExplorerRestart) {
        Restart-ExplorerShell
        Write-LogMessage "Defaults applied. Explorer was refreshed so the changes take effect immediately." 'INFO' 'Green'
      }
      elseif (-not $Silent) {
        Write-LogMessage "Defaults applied. Explorer restart is deferred; please restart it to finalize changes." 'INFO' 'Yellow'
      }
    }
  }
  finally {
    if ($tempPowerShellCreated) {
      try {
        Remove-Item -Path $powershellTempPath -Force -ErrorAction SilentlyContinue
      }
      catch {}
    }

    if ($PassThru) {
      Write-Output ([PSCustomObject]@{ Changed = $changesApplied; RestartRequired = $restartRequired })
    }
  }

}

function Set-PTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [String]
    $ProgId,

    [Parameter(Mandatory = $true)]
    [String]
    $Protocol,

    [String]
    $Icon,

    [String]
    $LogFile,

    [switch]
    $Silent,

    [switch]
    $SuppressNewAppAlert
  )

  Set-FTA -ProgId $ProgId -Protocol $Protocol -Icon $Icon -LogFile $LogFile -Silent:$Silent -SuppressNewAppAlert:$SuppressNewAppAlert
}

function Set-FTAFromConfig {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $Path,

    [switch]
    $DomainSID,

    [switch]
    $SuppressNewAppAlert,

    [string]
    $LogFile,

    [switch]
    $Silent
  )

  $logFilePath = $null
  if ($LogFile) {
    $logFilePath = If ([System.IO.Path]::IsPathRooted($LogFile)) { $LogFile } Else { Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $LogFile }

    try {
      $logDirectory = Split-Path -Path $logFilePath -Parent
      if ($logDirectory -and -not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
      }

      if (-not (Test-Path -Path $logFilePath)) {
        New-Item -Path $logFilePath -ItemType File -Force | Out-Null
      }
    }
    catch {
      Write-Verbose ("Unable to initialize log file at {0}: {1}" -f $logFilePath, $_)
      $logFilePath = $null
    }
  }

  function local:Write-ConfigLog {
    param (
      [string] $Message,
      [string] $Level = 'INFO',
      [string] $Color = 'Gray'
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    if ($logFilePath) {
      try {
        "$timestamp [$Level] $Message" | Out-File -FilePath $logFilePath -Append -Encoding utf8
      }
      catch {
        Write-Verbose ("Failed to write to log file {0}: {1}" -f $logFilePath, $_)
      }
    }

    if (-not $Silent) {
      switch ($Level) {
        'WARN'  { Write-Warning "[SFTA] $Message" }
        'ERROR' { Write-Error "[SFTA] $Message" -ErrorAction Continue }
        default { Write-Host "[SFTA] $Message" -ForegroundColor $Color }
      }
    }
  }

  try {
    $resolvedPath = (Resolve-Path -Path $Path -ErrorAction Stop).ProviderPath
  }
  catch {
    throw "Configuration file '$Path' was not found."
  }

  Write-ConfigLog "Reading associations from config file '$resolvedPath'..." 'INFO' 'Cyan'

  $lines = Get-Content -Path $resolvedPath -ErrorAction Stop
  $restartRequired = $false
  $changesDetected = $false

  foreach ($line in $lines) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }

    $parts = $trimmed -split ',', 3 | ForEach-Object { $_.Trim() }
    if ($parts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
      Write-ConfigLog "Skipping invalid line: '$line'" 'WARN' 'Yellow'
      continue
    }

    $configExtension = $parts[0]
    $configProgId = $parts[1]
    $configGroup = if ($parts.Count -ge 3) { $parts[2] } else { $null }

    $result = Set-FTA -ProgId $configProgId -Extension $configExtension -AllowedGroup $configGroup -DomainSID:$DomainSID -SuppressNewAppAlert:$SuppressNewAppAlert -LogFile $logFilePath -Silent:$Silent -SkipExplorerRestart -PassThru

    if ($result) {
      $changesDetected = $changesDetected -or $result.Changed
      $restartRequired = $restartRequired -or $result.RestartRequired
    }
  }

  if ($restartRequired) {
    Write-ConfigLog "Restarting explorer.exe once to apply updated defaults..." 'INFO' 'Yellow'

    try {
      $existing = Get-Process -Name explorer -ErrorAction SilentlyContinue
      if ($existing) {
        Stop-Process -Id $existing.Id -Force -ErrorAction Stop
      }
    }
    catch {
      Write-ConfigLog "Could not stop explorer.exe automatically: $_" 'WARN' 'Yellow'
    }

    try {
      Start-Process -FilePath (Join-Path -Path $env:SystemRoot -ChildPath 'explorer.exe') | Out-Null
      Write-ConfigLog "explorer.exe restarted successfully." 'INFO' 'Green'
    }
    catch {
      Write-ConfigLog "Failed to relaunch explorer.exe. Please start it manually to finalize defaults." 'WARN' 'Yellow'
    }
  }
  elseif (-not $changesDetected) {
    Write-ConfigLog "No changes were required; explorer.exe restart was not needed." 'INFO' 'Gray'
  }
}
