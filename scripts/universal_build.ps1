<#
.SYNOPSIS
  Universal Build Script für ELF-Inspector (Windows/macOS/Linux).

.DESCRIPTION
  Dieses Script führt Clean, Restore, Build, Publish und ZIP-Packaging
  für das .NET Projekt ELF-Inspector in einem plattformübergreifenden
  PowerShell-Kontext aus.
#>

# To Run on
# On Windows: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass .\build.ps1
# On macOS/Linux: pwsh build.ps1

param(
  [string]$Configuration = "Release"
)

function Write-Info($message) {
  Write-Host "[INFO] $message"
}

function Write-ErrorAndExit($message) {
  Write-Host "[ERROR] $message" -ForegroundColor Red
  exit 1
}

Write-Info "Detected platform: $([System.Environment]::OSVersion.Platform)"

# Prüfen ob dotnet CLI verfügbar ist
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
  Write-ErrorAndExit "dotnet CLI nicht gefunden — bitte .NET SDK installieren!"
}

# Clean
Write-Info "Cleaning project..."
dotnet clean -c $Configuration

# Restore
Write-Info "Restoring dependencies..."
dotnet restore

# Build
Write-Info "Building project..."
dotnet build -c $Configuration

# Publish in einen temporären Ordner
$outputDir = "publish"
Write-Info "Publishing to $outputDir..."
dotnet publish -c $Configuration -o $outputDir

if (-not (Test-Path $outputDir)) {
  Write-ErrorAndExit "Publish folder konnte nicht gefunden werden!"
}

# ZIP-Packaging
$zipName = "ELF-Inspector-$($Configuration).zip"
Write-Info "Creating ZIP archive: $zipName"

if (Test-Path $zipName) {
  Remove-Item $zipName -Force
}

# Plattformunabhängiges Zip
if ($IsWindows) {
  # Windows PowerShell oder PowerShell Core: Verwende Compress-Archive
  Compress-Archive -Path "$outputDir/*" -DestinationPath $zipName
} else {
  # macOS/Linux
  if (Get-Command zip -ErrorAction SilentlyContinue) {
    & zip -r $zipName $outputDir
  } elseif (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
    Compress-Archive -Path "$outputDir/*" -DestinationPath $zipName
  } else {
    Write-ErrorAndExit "Kein Zip-Tool gefunden (zip oder Compress-Archive)"
  }
}

Write-Info "Build und Packaging abgeschlossen!"
Write-Info "Output ZIP: $zipName"
