@echo off
title DDoS Testing Suite
color 0E

echo.
echo 💥 INFINITE AI SECURITY - DDoS TESTING
echo ======================================
echo ⚠️ WARNING: This will stress test your system
echo 🎯 Testing DDoS resilience and rate limiting
echo.

echo 📋 Available Tests:
echo    1. Stress Test (100 requests)
echo    2. Heavy Load (500 requests) 
echo    3. Volumetric Attack (30 seconds)
echo    4. All Tests
echo.

echo ⚠️ Make sure your API is running on http://127.0.0.1:8000
echo 📊 This test will show if your system can handle attacks
echo.
pause

echo 🚀 Starting DDoS tests...
python ddos_test.py

echo.
echo 📊 Check results above for system resilience
pause