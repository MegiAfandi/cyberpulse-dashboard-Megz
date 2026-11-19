@echo off
cd /d "%~dp0"
set PORT=3002
echo CyberPulse v2.3 - Date Sort + Timeout Recovery
echo Open http://localhost:%PORT% after the server starts.
echo Published sorting loads only the requested page. Keep this window open.
node "%~dp0server.mjs"
pause
