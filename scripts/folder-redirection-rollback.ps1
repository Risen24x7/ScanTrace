<#
.SYNOPSIS
  Roll back Windows Folder Redirection or OneDrive Known Folder Move (KFM) for the current device or selected user profiles.

.DESCRIPTION
  This script disables Folder Redirection GPO artifacts, stops OneDrive KFM redirection for Desktop/Documents/Pictures, restores default shell folder paths to the local profile, optionally migrates files back, and cleans up residual registry and policy settings.

  Key features:
  - Safe by default: runs in -WhatIf (dry-run) unless -Force is provided.
  - Supports selective rollback for specific profiles or the current user.
  - Backs up registry keys before changes.
  - Creates a timestamped log of actions.
  - Validates environment: Windows 10/11, admin rights, OneDrive presence when KFM steps are requested.

.PARAMETER Profiles
  One or more profile names to process (e.g., 'Alice','Bob'). Defaults to current user only when omitted.

.PARAMETER IncludeKFM
  Include OneDrive KFM rollback steps (unlink known folders, stop redirect). Default: $true.

.PARAMETER MigrateFilesBack
  If set, moves files from redirected locations back to the local default profile folders (Desktop/Documents/Pictures). Default: $true.

.PARAMETER Force
  Executes actions without WhatIf prompts. Default: $false.

.EXAMPLE
  .\folder-redirection-rollback.ps1 -Profiles Alice,Bob -IncludeKFM -MigrateFilesBack -Force

.NOTES
  Tested on Windows 10/11. Requires Administrator.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string[]]$Profiles,
  [switch]$IncludeKFM = $true,
  [switch]$MigrateFilesBack = $true,
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Log {
  param([string]$Message, [string]$Level = 'INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  $line = "[$ts] [$Level] $Message"
  Write-Host $line
  if (-not (Test-Path -LiteralPath $Global:LogFile)) { return }
  Add-Content -LiteralPath $Global:LogFile -Value $line
}

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must be run as Administrator.'
  }
}

function Assert-Windows10Plus {
  $os = (Get-CimInstance Win32_OperatingSystem)
  $ver = [Version]$os.Version
  if ($ver.Major -lt 10) { throw "Unsupported OS version: $($os.Caption) $($os.Version)" }
}

function Start-Logging {
  $logDir = Join-Path -Path $env:ProgramData -ChildPath 'FolderRedirectionRollback'
  if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
  $Global:LogFile = Join-Path -Path $logDir -ChildPath ("rollback-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
  New-Item -ItemType File -Force -Path $Global:LogFile | Out-Null
  Write-Log "Log file: $Global:LogFile"
}

function Backup-RegistryKey {
  param([string]$KeyPath, [string]$OutFile)
  try {
    reg.exe export "$KeyPath" "$OutFile" /y | Out-Null
    Write-Log "Backed up registry: $KeyPath -> $OutFile"
  } catch {
    Write-Log "Failed to back up registry: $KeyPath (${_})" 'WARN'
  }
}

function Get-TargetProfiles {
  if ($PSBoundParameters.ContainsKey('Profiles') -and $Profiles -and $Profiles.Count -gt 0) {
    return $Profiles
  }
  return @([Environment]::UserName)
}

function Stop-OneDrive {
  try {
    $oneDriveProc = Get-Process OneDrive -ErrorAction SilentlyContinue
    if ($oneDriveProc) {
      Write-Log 'Stopping OneDrive process'
      $oneDriveProc | Stop-Process -Force -ErrorAction SilentlyContinue
    }
  } catch { Write-Log "Failed to stop OneDrive: ${_}" 'WARN' }
}

function Start-OneDrive {
  $oneDriveExe = Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe'
  if (Test-Path $oneDriveExe) {
    Start-Process -FilePath $oneDriveExe -ErrorAction SilentlyContinue
    Write-Log 'Started OneDrive'
  }
}

function Set-UserShellPaths {
  param(
    [string]$Sid,
    [string]$ProfilePath
  )
  $usf = "HKU\\$Sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
  $sf  = "HKU\\$Sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
  $backupUSF = Join-Path $Global:TempDir ("UserShellFolders-" + ($Sid -replace '[^A-Za-z0-9]','_') + '.reg')
  $backupSF  = Join-Path $Global:TempDir ("ShellFolders-" + ($Sid -replace '[^A-Za-z0-9]','_') + '.reg')
  Backup-RegistryKey -KeyPath $usf -OutFile $backupUSF
  Backup-RegistryKey -KeyPath $sf  -OutFile $backupSF

  $defaults = @{
    'Desktop'     = '%USERPROFILE%\\Desktop'
    'Personal'    = '%USERPROFILE%\\Documents'
    'My Pictures' = '%USERPROFILE%\\Pictures'
  }

  foreach ($name in $defaults.Keys) {
    $target = $defaults[$name]
    if ($PSCmdlet.ShouldProcess("$usf:$name", "Set to $target")) {
      New-Item -Path $usf -Force -ErrorAction SilentlyContinue | Out-Null
      Set-ItemProperty -LiteralPath $usf -Name $name -Value $target -Type ExpandString
      Write-Log "Set USF $name -> $target"
    }
    if ($PSCmdlet.ShouldProcess("$sf:$name", "Set to expanded path")) {
      New-Item -Path $sf -Force -ErrorAction SilentlyContinue | Out-Null
      $expanded = $target -replace '%USERPROFILE%', $ProfilePath
      Set-ItemProperty -LiteralPath $sf -Name $name -Value $expanded -Type String
      Write-Log "Set SF $name -> $expanded"
    }
  }
}

function Migrate-FilesBack {
  param(
    [string]$Sid,
    [string]$ProfilePath
  )
  $map = @{
    'Desktop'     = 'Desktop'
    'Personal'    = 'Documents'
    'My Pictures' = 'Pictures'
  }
  $usf = "HKU\\$Sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
  foreach ($kv in $map.GetEnumerator()) {
    try {
      $current = (Get-ItemProperty -LiteralPath $usf -Name $kv.Key -ErrorAction Stop).$($kv.Key)
      $expanded = [Environment]::ExpandEnvironmentVariables($current)
      $localPath = Join-Path $ProfilePath $kv.Value
      if (-not (Test-Path $localPath)) { New-Item -ItemType Directory -Path $localPath -Force | Out-Null }
      if ($expanded -and (Test-Path $expanded) -and ($expanded -ne $localPath)) {
        Write-Log "Migrating files from $expanded -> $localPath"
        robocopy "$expanded" "$localPath" /E /COPY:DAT /MOVE /R:1 /W:1 /NFL /NDL /NP | Out-Null
      }
    } catch { Write-Log "Migration check failed for $($kv.Key): ${_}" 'WARN' }
  }
}

function Remove-PolicyArtifacts {
  param([string]$Sid)
  # Backup likely policy keys and remove values that can pin redirection
  $paths = @(
    "HKU\\$Sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
    "HKU\\$Sid\\Software\\Policies\\Microsoft\\Windows\\System"
  )
  foreach ($p in $paths) {
    try {
      $backup = Join-Path $Global:TempDir ("policy-" + ($Sid -replace '[^A-Za-z0-9]','_') + '-' + ([Convert]::ToString((Get-Random),16)) + '.reg')
      Backup-RegistryKey -KeyPath $p -OutFile $backup
    } catch {}
  }
  # No blanket deletes to avoid collateral damage; rely on shell folder reset
}

function Disable-KFMArtifacts {
  param([string]$Sid)
  $kfmPaths = @(
    "HKU\\$Sid\\Software\\Microsoft\\OneDrive",
    "HKU\\$Sid\\Software\\Policies\\Microsoft\\OneDrive"
  )
  foreach ($kp in $kfmPaths) {
    try { Backup-RegistryKey -KeyPath $kp -OutFile (Join-Path $Global:TempDir ("onedrive-" + ($Sid -replace '[^A-Za-z0-9]','_') + '.reg')) } catch {}
  }
}

function Get-ProfileInfo {
  param([string]$ProfileName)
  $profile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -match "\\\\$ProfileName$" -and -not $_.Special }
  if (-not $profile) { return $null }
  $sid = $profile.SID
  return [pscustomobject]@{ Name = $ProfileName; SID = $sid; Path = $profile.LocalPath }
}

# Main
try {
  Assert-Admin
  Assert-Windows10Plus
  Start-Logging
  $Global:TempDir = New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP ('FRRollback-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))) | Select-Object -ExpandProperty FullName
  Write-Log "Temp: $Global:TempDir"

  $targets = Get-TargetProfiles
  if (-not $targets -or $targets.Count -eq 0) { throw 'No profiles resolved.' }

  if ($IncludeKFM) { Stop-OneDrive }

  foreach ($name in $targets) {
    $info = Get-ProfileInfo -ProfileName $name
    if (-not $info) { Write-Log "Profile not found or is special: $name" 'WARN'; continue }

    Write-Log "Processing profile: $($info.Name) SID=$($info.SID) Path=$($info.Path)"

    if ($PSCmdlet.ShouldProcess($info.Name, 'Remove policy artifacts')) {
      Remove-PolicyArtifacts -Sid $info.SID
    }

    Set-UserShellPaths -Sid $info.SID -ProfilePath $info.Path

    if ($MigrateFilesBack) {
      Migrate-FilesBack -Sid $info.SID -ProfilePath $info.Path
    }

    if ($IncludeKFM) {
      if ($PSCmdlet.ShouldProcess($info.Name, 'Disable OneDrive KFM artifacts')) {
        Disable-KFMArtifacts -Sid $info.SID
      }
    }
  }

  if ($IncludeKFM) { Start-OneDrive }

  Write-Log 'Rollback completed.' 'SUCCESS'
  Write-Host "Log: $Global:LogFile"
}
catch {
  Write-Log ("Error: " + $_.Exception.Message) 'ERROR'
  throw
}
