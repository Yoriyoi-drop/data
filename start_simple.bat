@echo off
title Infinite AI Security - Simple Edition
color 0A

echo.
echo 🛡️ INFINITE AI SECURITY - SIMPLE EDITION
echo =========================================
echo ✅ No bcrypt dependency issues
echo ✅ Windows compatible
echo ✅ Simple authentication
echo.

echo 🚀 Installing minimal dependencies...
pip install fastapi==0.115.6 uvicorn[standard]==0.32.1 pydantic==2.10.3

echo.
echo 🌐 Starting API server...
echo 📍 URL: http://127.0.0.1:8000
echo 📚 Docs: http://127.0.0.1:8000/docs
echo 🔑 Login: admin/admin123
echo.
echo Press Ctrl+C to stop
echo =========================================
echo.

python api\main_simple.py

echo.
echo 🛑 Server stopped
pause