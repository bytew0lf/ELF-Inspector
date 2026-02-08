#!/bin/bash
set -e

echo ">>> Building ELF-Inspector for macOS..."

# Clean
dotnet clean -c Release

# Restore
dotnet restore

# Build
dotnet build -c Release

# Publish
dotnet publish -c Release -o publish

# ZIP
echo "Creating ZIP package..."
zip -r ELF-Inspector-macOS.zip publish

echo "Build & package complete!"
