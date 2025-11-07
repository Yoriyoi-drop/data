@echo off
title Security Testing Suite
color 0C

echo.
echo 🛡️ INFINITE AI SECURITY - SECURITY TESTING
echo ===========================================
echo 🔍 Testing system against real attacks
echo 📊 Comprehensive security assessment
echo 🎯 Vulnerability detection
echo.

echo 📋 Test Categories:
echo    • SQL Injection (7 payloads)
echo    • XSS Attacks (7 payloads)  
echo    • Command Injection (7 payloads)
echo    • Path Traversal (5 payloads)
echo    • LDAP Injection (4 payloads)
echo.

echo ⚠️ Make sure your API is running on http://127.0.0.1:8000
echo.
pause

echo 🚀 Starting security tests...
python security_test.py

echo.
echo 📄 Check security_report.json for detailed results
pause