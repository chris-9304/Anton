
# deploy_shortcut.ps1
# Windows-only. On macOS, see build_and_install.sh / macos/build_app_bundle.sh instead.
# Creates "Anton Anti-Ransomware" desktop shortcut with Run as Administrator.
# Run from project root; "Start in" is set to project root so ui/ and assets are found.

$ErrorActionPreference = "Stop"

# 1. Project root = directory containing this script
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
Set-Location $ScriptDir
$ProjectRoot = (Get-Location).Path

# 2. Release binary (default bin name from Cargo.toml is "anton")
$ExeName = "anton.exe"
$ReleasePath = Join-Path $ProjectRoot "target\release\$ExeName"

if (-not (Test-Path -LiteralPath $ReleasePath)) {
    Write-Host "ERROR: Release binary not found at: $ReleasePath" -ForegroundColor Red
    Write-Host "Run 'cargo build --release' first." -ForegroundColor Yellow
    exit 1
}

# 3. Desktop folder
$Desktop = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "Anton Anti-Ransomware.lnk"

# 4. Create shortcut via COM
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $ReleasePath
$Shortcut.WorkingDirectory = $ProjectRoot
$Shortcut.Description = "Anton - Professional Anti-Ransomware System"
$Shortcut.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null

# 5. Set "Run as administrator" (LNK byte at offset 0x15, bit 0x20)
$Bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
if ($Bytes.Length -gt 0x16) {
    $Bytes[0x15] = $Bytes[0x15] -bor 0x20
    [System.IO.File]::WriteAllBytes($ShortcutPath, $Bytes)
}

Write-Host "Shortcut created: $ShortcutPath" -ForegroundColor Green
Write-Host "  Target: $ReleasePath" -ForegroundColor Gray
Write-Host "  Start in: $ProjectRoot" -ForegroundColor Gray
Write-Host "  Run as administrator: requested (patch applied)." -ForegroundColor Gray
exit 0
