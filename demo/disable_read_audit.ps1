<#
.SYNOPSIS
  Undoes demo\enable_read_audit.ps1: removes the audit rules and restores the saved audit policy.
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$data = Join-Path $root 'data'
$pathsFile = Join-Path $data 'decoy_paths.txt'
$backup = Join-Path $data 'auditpol-backup.csv'
$fileSystemSubcategory = '{0CCE921D-69AE-11D9-BED3-505054503030}'

if (Test-Path $pathsFile) {
    foreach ($path in Get-Content $pathsFile | Where-Object { $_.Trim() }) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $acl = Get-Acl -LiteralPath $path -Audit
        $rules = @($acl.GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
        foreach ($rule in $rules) {
            if ($rule.IdentityReference.Value -eq 'S-1-1-0') { [void]$acl.RemoveAuditRuleSpecific($rule) }
        }
        try {
            Set-Acl -LiteralPath $path -AclObject $acl
        } catch {
            [System.IO.File]::SetAccessControl($path, $acl)
        }
    }
}

if (Test-Path $backup) {
    auditpol /restore /file:"$backup" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol /restore failed. The backup is still at $backup." }
    Remove-Item $backup
    Write-Host 'Audit policy restored to its pre-demo state.'
} else {
    Write-Host 'No audit policy backup found; nothing to restore.'
}
auditpol /get /subcategory:"$fileSystemSubcategory"
