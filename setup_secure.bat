@echo off
title SECURE SETUP - Phase 1 Stabilization
color 0A

echo.
echo 🔐 INFINITE AI SECURITY - SECURE SETUP
echo ======================================
echo 🎯 Phase 1: Stabilization (Critical Fixes)
echo 🛡️ Implementing proper JWT + BCrypt security
echo.

echo 📦 Installing secure dependencies...
pip install PyJWT==2.10.1 bcrypt==4.2.1 python-dotenv==1.0.1

echo.
echo 🔧 Setting up environment...
if not exist .env (
    copy .env.secure .env
    echo ✅ Created .env file - PLEASE EDIT IT!
    echo ⚠️ CRITICAL: Change JWT_SECRET_KEY in .env file
) else (
    echo ⚠️ .env exists - please verify JWT_SECRET_KEY is set
)

echo.
echo 🧪 Testing secure authentication...
python auth_secure.py

echo.
echo 🎉 PHASE 1 SETUP COMPLETE!
echo.
echo ⚠️ CRITICAL NEXT STEPS:
echo 1. Edit .env file and change JWT_SECRET_KEY
echo 2. Update your main API to use auth_secure.py
echo 3. Test login with new secure system
echo.
pause