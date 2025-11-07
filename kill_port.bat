@echo off
echo 🔍 Checking what's using port 8080...
netstat -ano | findstr :8080

echo.
echo 🛑 Killing processes on port 8080...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8080') do (
    echo Killing process %%a
    taskkill /PID %%a /F
)

echo.
echo ✅ Port 8080 should now be free
pause