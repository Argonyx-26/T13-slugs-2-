<#
.SYNOPSIS
  Runs the Mirage Engine demo: six scenes, each one answering a judge question.
.PARAMETER ReadAudit
  Also turn on Windows file-read auditing, so a "stolen" warning (process and user) appears
  before the stolen key is used. Needs an elevated PowerShell. The audit policy is backed up
  first and restored during clean-up.
.PARAMETER Auto
  Don't wait for Enter between scenes (for rehearsals and automated checks).
.PARAMETER NoBrowser
  Don't open the dashboard in the browser.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
#>
param([switch]$ReadAudit, [switch]$Auto, [switch]$NoBrowser)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUNBUFFERED = '1'
# Stage-friendly timings: the pipeline alarm fires ~15 s after the sensor dies, and a long
# Q&A pause between scenes doesn't reset the circuit breaker's count.
if (-not $env:MIRAGE_SELFTEST_INTERVAL) { $env:MIRAGE_SELFTEST_INTERVAL = '5' }
if (-not $env:MIRAGE_SELFTEST_STALE_AFTER) { $env:MIRAGE_SELFTEST_STALE_AFTER = '15' }
if (-not $env:MIRAGE_BREAKER_WINDOW) { $env:MIRAGE_BREAKER_WINDOW = '1800' }

$dashboard = 'http://127.0.0.1:7000'

function Scene($text) { Write-Host ''; Write-Host "== $text" -ForegroundColor Cyan }
function Say($text) { Write-Host "   $text" -ForegroundColor Yellow }
function Wait-Presenter($prompt) {
    if ($Auto) { Start-Sleep -Seconds 2; return }
    Read-Host "`n>> $prompt [Enter]" | Out-Null
}
function Invoke-Python {
    & python @args
    if ($LASTEXITCODE -ne 0) { throw "python $args failed with exit code $LASTEXITCODE" }
}
function Wait-Health([bool]$wantOk, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $health = Invoke-RestMethod "$dashboard/api/health" -TimeoutSec 2
            if ([bool]$health.pipeline_ok -eq $wantOk -and -not $health.starting) { return $true }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

if ($ReadAudit) {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '-ReadAudit needs an elevated PowerShell (right-click PowerShell > Run as Administrator).'
    }
}

$processes = @{}
$auditOn = $false
try {
    Scene 'Setting up a fresh demo estate'
    Invoke-Python -m mirage reset --yes
    Invoke-Python demo/build_estate.py
    Invoke-Python -m mirage init

    Scene 'Scene 1 - Deploy: one unique decoy per location'
    Invoke-Python -m mirage deploy
    if ($ReadAudit) { & (Join-Path $PSScriptRoot 'enable_read_audit.ps1'); $auditOn = $true }

    New-Item -ItemType Directory -Force -Path (Join-Path $root 'data\logs') | Out-Null
    $roles = @('control', 'sensor')
    if ($ReadAudit) { $roles += 'readaudit' }
    foreach ($role in $roles) {
        $processes[$role] = Start-Process -FilePath python -ArgumentList '-m', 'mirage', 'serve', $role `
            -WorkingDirectory $root -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $root "data\logs\$role.log") `
            -RedirectStandardError (Join-Path $root "data\logs\$role.err.log")
    }
    if (-not (Wait-Health $true 30)) { throw 'The control plane did not become healthy. See data\logs\.' }
    Say 'Control plane and decoy sensor are up, and the self-test token has made the round trip.'
    if (-not $NoBrowser) { Start-Process "$dashboard/" }
    Wait-Presenter 'Dashboard is open. Walk through the decoy registry, then start the attack'

    Scene 'Scene 2 - An attacker harvests laptop-dev-07 and the fs-01 file share'
    Invoke-Python demo/attacker_sim.py attacker
    Say 'Laptop: contained automatically. The decoy was local to it, so the attribution is solid.'
    Say 'File share: approval required. A shared folder means the planted host may not be the breached one.'
    Say 'Point at "Next steps": the real [default] AWS key in the same file was stolen too. Rotate it.'
    Wait-Presenter 'Next: the crown jewel'

    Scene 'Scene 3 - A decoy taken from the production database server'
    Invoke-Python demo/attacker_sim.py crown-jewel
    Say 'db-prod-01 is never isolated automatically. Click "Approve containment" on the dashboard.'
    Wait-Presenter 'Next: harmless trigger versus spoofed scanner'

    Scene 'Scene 4 - The AppSec secret scanner, then an attacker pretending to be it'
    Invoke-Python demo/attacker_sim.py scanner
    Invoke-Python demo/attacker_sim.py spoofed-scanner
    Say 'Known scanner host AND user-agent: LOW, nothing contained, but still recorded.'
    Say 'Same user-agent from an unknown host: HIGH, possible spoofing.'
    Wait-Presenter 'Next: an attacker flooding decoys to make us isolate our own machines'

    Scene 'Scene 5 - Flood: decoy abuse'
    Invoke-Python demo/attacker_sim.py flood
    Say 'Fifty uses of one key became one incident. The circuit breaker tripped: automatic response is paused.'
    Wait-Presenter 'Next: what happens after the network is cut?'

    Scene 'Scene 6 - After containment: finish the playbook for laptop-dev-07'
    Say 'Already done automatically: evidence captured (with SHA-256), attacker IP blocked, sessions revoked, hunt run.'
    Invoke-Python demo/respond.py laptop-dev-07
    Say 'Release was refused until secrets were rotated, the burned decoy replaced and the laptop reimaged.'
    Say 'Open "Incident report" on the card: every step, who did it, when, and the evidence hash.'
    Wait-Presenter 'Next: what if Mirage itself breaks?'

    Scene 'Scene 7 - Kill the decoy sensor'
    Stop-Process -Id $processes['sensor'].Id -Force
    Say 'Watch the header: "PIPELINE DOWN" appears within about 15 seconds. Silence is an alert too.'
    if ($Auto) {
        if (Wait-Health $false 45) { Say 'Pipeline alarm raised.' } else { throw 'The pipeline alarm did not fire.' }
    }
    Wait-Presenter 'Demo complete. Press Enter to shut everything down'
}
finally {
    Scene 'Cleaning up'
    foreach ($process in $processes.Values) {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
    if ($auditOn) { & (Join-Path $PSScriptRoot 'disable_read_audit.ps1') }
    Say 'All Mirage processes stopped. The estate and registry are kept for questions.'
    Say "Delete them with: python -m mirage reset --yes"
}
