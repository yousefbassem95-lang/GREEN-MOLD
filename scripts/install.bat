@echo off
REM Green Mold Cure - Windows Installer
REM This script installs Green Mold Cure and its dependencies

echo ╔═══════════════════════════════════════════════════════════╗
echo ║              GREEN MOLD CURE INSTALLER                    ║
echo ║                    Windows Version                        ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

REM Check Python version
echo Checking Python version...
python --version > nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.10 or higher from https://python.org
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python %PYTHON_VERSION% detected

REM Check pip
echo Checking pip...
pip --version > nul 2>&1
if errorlevel 1 (
    echo ERROR: pip is not installed
    pause
    exit /b 1
)

REM Get script directory
set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..

REM Install dependencies
echo.
echo Installing Python dependencies...
cd /d %PROJECT_DIR%
pip install -r requirements.txt

REM Create application directory
echo.
echo Setting up application directory...
set APP_DIR=%USERPROFILE%\.green_mold_cure
if not exist "%APP_DIR%" mkdir "%APP_DIR%"
if not exist "%APP_DIR%\quarantine" mkdir "%APP_DIR%\quarantine"
if not exist "%APP_DIR%\logs" mkdir "%APP_DIR%\logs"
if not exist "%APP_DIR%\config" mkdir "%APP_DIR%\config"

echo Application directory created: %APP_DIR%

REM Create launcher batch file
echo.
echo Creating launcher script...
set LAUNCHER_DIR=%APP_DIR%
cat > "%LAUNCHER_DIR%\green-mold-cure.bat" << 'EOF'
@echo off
REM Green Mold Cure Launcher
cd /d "%~dp0..\..\..\Projects\J0J0\Elixirs_and_Cures_projects\Green_Mold_Cure_project"
python src/main.py %*
EOF

echo Launcher script created: %LAUNCHER_DIR%\green-mold-cure.bat

REM Create .env template
echo.
echo Creating .env template...
if not exist "%PROJECT_DIR%.env" (
    (
        echo # Green Mold Cure - Environment Variables
        echo # Copy this file to .env and fill in your API keys
        echo.
        echo # VirusTotal API Key ^(optional - get from virustotal.com^)
        echo VIRUSTOTAL_API_KEY=
        echo.
        echo # Hybrid Analysis API Key ^(optional - get from hybrid-analysis.com^)
        echo HYBRID_ANALYSIS_API_KEY=
        echo.
        echo # Any.run API Key ^(optional - get from any.run^)
        echo ANYRUN_API_KEY=
        echo.
        echo # AlienVault OTX API Key ^(optional - get from otx.alienvault.com^)
        echo ALIENVAULT_API_KEY=
        echo.
        echo # Tor Proxy Settings ^(optional - for .onion feeds^)
        echo TOR_PROXY_HOST=127.0.0.1
        echo TOR_PROXY_PORT=9050
    ) > "%PROJECT_DIR%.env"
    echo .env template created
) else (
    echo .env file already exists
)

REM Final instructions
echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║                  INSTALLATION COMPLETE                    ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.
echo Green Mold Cure has been installed successfully!
echo.
echo To run the application:
echo   1. Navigate to the project directory:
echo      cd %PROJECT_DIR%
echo.
echo   2. Run the application:
echo      python src\main.py
echo.
echo Optional Setup:
echo   - Configure API keys in .env file for enhanced threat intelligence
echo   - Install Tor for .onion feed support
echo   - Run as Administrator for full system scan capabilities
echo.
echo Documentation:
echo   - See README.md for usage instructions
echo   - See system_constraints.md for platform limitations
echo.
pause
