@echo off
echo 🛡️ Infinite AI Security - Windows Setup
echo =======================================

echo Checking Python version...
python --version
if %errorlevel% neq 0 (
    echo ❌ Python not found. Please install Python 3.9+
    pause
    exit /b 1
)

echo.
echo 🚀 Installing Production Dependencies...
echo.

pip install fastapi==0.115.6
pip install uvicorn[standard]==0.32.1
pip install pydantic==2.10.3
pip install cryptography==42.0.8
pip install python-jose[cryptography]==3.3.0
pip install passlib[bcrypt]==1.7.4
pip install bcrypt==4.2.1
pip install sqlalchemy==2.0.36
pip install redis==5.2.1
pip install scikit-learn==1.6.0
pip install numpy==2.2.0
pip install prometheus-client==0.21.1
pip install structlog==24.5.0
pip install slowapi==0.1.9
pip install python-dotenv==1.0.1

echo.
echo 🔧 Setting up environment...
if not exist .env (
    copy .env.example .env
    echo ✅ Created .env file
) else (
    echo ✅ .env file already exists
)

echo.
echo 📁 Creating directories...
if not exist logs mkdir logs
if not exist data mkdir data
if not exist backups mkdir backups
echo ✅ Directories created

echo.
echo 🎉 Windows setup completed!
echo.
echo Next steps:
echo 1. Edit .env file with your settings
echo 2. Run: python api\main_production.py
echo 3. Visit: http://127.0.0.1:8080/docs
echo 4. Login: admin/admin123
echo.
pause