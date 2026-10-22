@echo off
rem Double-click launcher for the WebCrawler desktop app.
cd /d "%~dp0"
title WebCrawler

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause
  exit /b 1
)

python -c "import playwright, tkinter" >nul 2>nul
if errorlevel 1 (
  echo First run: installing Playwright...
  python -m pip install -r requirements.txt
  if errorlevel 1 (
    echo Install failed. Tkinter also has to be part of your Python install.
    pause
    exit /b 1
  )
)

where pythonw >nul 2>nul
if errorlevel 1 (
  python webcrawler_gui.py
) else (
  start "" pythonw webcrawler_gui.py
)
