@echo off
title Infinite AI Security - Windows
color 0A

echo.
echo 🛡️ INFINITE AI SECURITY - WINDOWS EDITION
echo ==========================================
echo.

echo 🔍 Checking system...
python --version
if %errorlevel% neq 0 (
    echo ❌ Python not found!
    echo Please install Python 3.9+ from python.org
    pause
    exit /b 1
)

echo ✅ Python detected
echo.

echo 🚀 Starting API server...
echo 📍 URL: http://127.0.0.1:8080
echo 📚 Docs: http://127.0.0.1:8080/docs
echo 🔑 Login: admin/admin123
echo.
echo Press Ctrl+C to stop the server
echo ==========================================
echo.

python api\main_windows.py

echo.
echo 🛑 Server stopped
pause