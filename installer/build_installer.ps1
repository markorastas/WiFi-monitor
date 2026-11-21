# Build standalone WiFiMonitor.exe and Windows installer WiFiMonitor-Setup.exe
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir

Write-Host "1/3 Generating application icon..." -ForegroundColor Cyan
python installer\generate_icon.py

Write-Host "2/3 Building standalone WiFiMonitor.exe with PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name WiFiMonitor `
    --icon build\wifi_monitor.ico `
    --exclude-module numpy `
    --exclude-module scipy `
    --exclude-module matplotlib `
    --exclude-module tkinter `
    --exclude-module unittest `
    --exclude-module pytest `
    --exclude-module gi `
    wifi_monitor.py

Write-Host "3/3 Building Windows installer with Inno Setup..." -ForegroundColor Cyan
$IsccCandidates = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)
$Iscc = $IsccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Iscc) {
    $cmd = Get-Command iscc -ErrorAction SilentlyContinue
    if ($cmd) { $Iscc = $cmd.Source }
}
if (-not $Iscc) {
    throw "Inno Setup (ISCC.exe) not found. Install it with: winget install JRSoftware.InnoSetup"
}

& $Iscc "installer\wifi_monitor.iss"
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "Done! Installer ready at: $RootDir\dist\WiFiMonitor-Setup.exe" -ForegroundColor Green
