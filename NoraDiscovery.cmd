@echo off
rem Nora Discovery: doble clic para abrir.
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0NoraDiscovery.ps1"
