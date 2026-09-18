@echo off
title Share
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo   Node.js is required. Install it from https://nodejs.org and run Share again.
  echo.
  pause
  exit /b 1
)

if not exist "node_modules\qrcode" (
  echo   Installing dependencies, one moment...
  call npm install --no-audit --no-fund
  if errorlevel 1 (
    pause
    exit /b 1
  )
)

node app.js %*
echo.
pause
