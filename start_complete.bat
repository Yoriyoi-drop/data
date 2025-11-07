@echo off
title Infinite AI Security - Complete Dashboard
color 0A

echo.
echo 🛡️ INFINITE AI SECURITY - COMPLETE DASHBOARD
echo =============================================
echo ✅ Full-featured web interface
echo ✅ Real-time threat monitoring  
echo ✅ Advanced analytics dashboard
echo ✅ Detailed threat history
echo ✅ Interactive security testing
echo.

echo 🚀 Installing dependencies...
pip install fastapi uvicorn pydantic

echo.
echo 🌐 Starting Complete Dashboard...
echo 📍 URL: http://127.0.0.1:8000
echo 🔑 Login: admin/admin123
echo.
echo Features:
echo - Real-time statistics
echo - Threat analysis engine
echo - Security monitoring
echo - Interactive dashboard
echo - Threat history tracking
echo.
echo Press Ctrl+C to stop
echo =============================================
echo.

python api\main_complete_ui.py

echo.
echo 🛑 Dashboard stopped
pause