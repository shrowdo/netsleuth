# Build loop-finder.exe and netsleuth.exe into .\dist
# Usage: powershell -ExecutionPolicy Bypass -File build.ps1 [-Python path\to\python.exe]
param([string]$Python = "python")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

& $Python -m pip install --quiet pyinstaller pytest ./packages/netsleuth-core ./packages/netsleuth-loopfinder ./packages/netsleuth
& $Python -m pytest -q packages
if ($LASTEXITCODE -ne 0) { throw "Tests failed - not building." }

$common = @(
    "--noconfirm", "--onefile",
    "--collect-all", "netmiko", "--collect-all", "rich", "--collect-all", "networkx",
    "--collect-all", "textual", "--collect-all", "scapy",
    "--add-data", "$PSScriptRoot\packages\netsleuth-loopfinder\netsleuth_loopfinder\topologies;topologies",
    "--workpath", "build", "--specpath", "build", "--distpath", "dist"
)
& $Python -m PyInstaller @common --name loop-finder packages/netsleuth-loopfinder/netsleuth_loopfinder/entry.py
& $Python -m PyInstaller @common --name netsleuth packages/netsleuth/netsleuth/entry.py
Get-ChildItem dist\*.exe | Select-Object Name, Length
