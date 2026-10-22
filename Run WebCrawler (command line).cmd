@echo off
rem Double-click launcher for webcrawler.py. Asks what to crawl, then keeps the window open so you can read the results.
cd /d "%~dp0"
title WebCrawler

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause
  exit /b 1
)

python -c "import playwright" >nul 2>nul
if errorlevel 1 (
  echo First run: installing Playwright...
  python -m pip install -r requirements.txt
  if errorlevel 1 ( echo Install failed. & pause & exit /b 1 )
)

echo.
echo  WebCrawler
echo  ----------
set "URL="
set /p URL=Page to crawl (URL, or press Enter for the built-in test site):
if "%URL%"=="" set "URL=test-site\index.html"

echo.
echo  1 = I scroll, the crawler captures   (close the browser window to finish)
echo  2 = The crawler scrolls by itself and follows links
echo  3 = Quick scan: no browser at all, fast (cannot run JavaScript)
set "MODE=1"
set /p MODE=Mode [1]:
if "%MODE%"=="3" goto quick

set "BROWSER=auto"
set /p BROWSER=Browser: auto, chrome, edge, firefox, chromium, webkit [auto]:

set "SKIN=sentinel"
set /p SKIN=Look: sentinel, hacker, spider, packet, lock, drone, radar, bot [sentinel]:

echo.
if "%MODE%"=="2" (
  python webcrawler.py "%URL%" --auto --depth 2 --browser %BROWSER% --skin %SKIN%
) else (
  python webcrawler.py "%URL%" --browser %BROWSER% --skin %SKIN%
)
goto done

:quick
set "PRESET=balanced"
set /p PRESET=Pace: stealth, polite, balanced, fast, blitz [balanced]:
echo.
python webcrawler.py "%URL%" --quick --preset %PRESET%

:done

echo.
echo Done. Results are in the crawl-results folder next to this file.
pause
