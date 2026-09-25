<#
.SYNOPSIS
  Turns on Windows file-read auditing for Mirage's decoy files. Needs an elevated PowerShell.
.DESCRIPTION
  1. Backs up the current audit policy to data\auditpol-backup.csv (only once).
  2. Enables success auditing for the "File System" subcategory. It uses the GUID, so it works
     on any Windows display language.
  3. Adds a ReadData audit rule for Everyone (SID S-1-1-0) to each decoy in data\decoy_paths.txt.
  Only decoy files get the rule, so the Security log sees reads of decoys and nothing else.
  Undo everything with demo\disable_read_audit.ps1.
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$data = Join-Path $root 'data'
$pathsFile = Join-Path $data 'decoy_paths.txt'
$backup = Join-Path $data 'auditpol-backup.csv'
$fileSystemSubcategory = '{0CCE921D-69AE-11D9-BED3-505054503030}'

if (-not (Test-Path $pathsFile)) { throw "No decoys found. Run 'python -m mirage deploy' first." }

if (-not (Test-Path $backup)) {
    auditpol /backup /file:"$backup" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'auditpol /backup failed; nothing was changed.' }
}
auditpol /set /subcategory:"$fileSystemSubcategory" /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'auditpol /set failed. Restore with demo\disable_read_audit.ps1.' }

$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    $everyone,
    [System.Security.AccessControl.FileSystemRights]::ReadData,
    [System.Security.AccessControl.AuditFlags]::Success)

$count = 0
foreach ($path in Get-Content $pathsFile | Where-Object { $_.Trim() }) {
    $acl = Get-Acl -LiteralPath $path -Audit
    $acl.AddAuditRule($rule)
    try {
        Set-Acl -LiteralPath $path -AclObject $acl
    } catch {
        # Set-Acl also rewrites the owner; this writes only the audit section.
        [System.IO.File]::SetAccessControl($path, $acl)
    }
    $count++
}
Write-Host "Read auditing is on for $count decoy files. Audit policy backup: $backup"
