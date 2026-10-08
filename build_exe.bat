@echo off
setlocal
cd /d "%~dp0"

rem  build_exe.bat          -> team build: includes YOUR cucm_clusters.json (real hosts)
rem  build_exe.bat public   -> public build: includes only cucm_clusters.example.json

set MODE=team
if /i "%~1"=="public" set MODE=public

echo ============================================================
echo  Building DN Scout (%MODE% build)
echo ============================================================

if "%MODE%"=="team" if not exist cucm_clusters.json (
    echo cucm_clusters.json not found. Copy cucm_clusters.example.json to cucm_clusters.json,
    echo fill in your publishers, or run:  build_exe.bat public
    goto :fail
)

echo [1/4] Installing build tools...
python -m pip install --upgrade pyinstaller requests sv-ttk || goto :fail

echo [2/4] Building DNScout.exe ...
python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --collect-data sv_ttk --name DNScout dn_scout.py || goto :fail

echo [3/4] Building AXLDiag.exe ...
python -m PyInstaller --noconfirm --clean --onefile --console ^
    --name AXLDiag axl_diag.py || goto :fail

echo [4/4] Assembling release folder...
if exist release rmdir /s /q release
mkdir release
copy /y dist\DNScout.exe release\ >nul
copy /y dist\AXLDiag.exe release\ >nul
copy /y README.md release\ >nul
copy /y LICENSE release\ >nul
copy /y NOTICE release\ >nul
copy /y SECURITY.md release\ >nul
copy /y THIRD_PARTY_NOTICES.md release\ >nul
copy /y cucm_clusters.example.json release\ >nul
rem Team build: copy your config WITHOUT any saved username/password
if "%MODE%"=="team" python -c "import json;c=json.load(open('cucm_clusters.json',encoding='utf-8'));[c.pop(k,None) for k in ('saved_username','saved_password')];json.dump(c,open(r'release\cucm_clusters.json','w',encoding='utf-8'),indent=2)" || goto :fail

set ZIP=DNScout_%MODE%.zip
powershell -NoProfile -Command "Compress-Archive -Path 'release\*' -DestinationPath '%ZIP%' -Force" >nul 2>nul
powershell -NoProfile -Command "$f='%ZIP%'; $h=(Get-FileHash -Algorithm SHA256 $f).Hash.ToLower(); ('{0}  {1}' -f $h,$f) | Set-Content -Encoding ascii SHA256SUMS.txt" || goto :fail

echo.
echo Done.  Folder: %cd%\release    Zip: %cd%\%ZIP%
echo SHA-256: %cd%\SHA256SUMS.txt
if "%MODE%"=="team" echo NOTE: this zip contains your real cluster hosts - share it internally only.
if "%MODE%"=="public" echo This zip is safe to attach to a public GitHub release.
pause
exit /b 0

:fail
echo.
echo Build FAILED - see the messages above.
pause
exit /b 1
