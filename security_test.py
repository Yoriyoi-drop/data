"""
Security Testing Suite - Test if system is secure against attacks
"""
import requests
import time
import json
from datetime import datetime

# Test payloads for different attack types
ATTACK_PAYLOADS = {
    "sql_injection": [
        "admin' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM passwords --",
        "admin'--",
        "' OR 1=1 --",
        "1' OR '1'='1' /*",
        "'; EXEC xp_cmdshell('dir'); --"
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "';alert('XSS');//",
        "<body onload=alert('XSS')>"
    ],
    "command_injection": [
        "; dir",
        "&& whoami",
        "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "; net user hacker password123 /add",
        "&& powershell -c Get-Process",
        "| cmd.exe /c dir",
        "; del /f /q *.*"
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\boot.ini"
    ],
    "ldap_injection": [
        "*)(uid=*))(|(uid=*",
        "*)(|(password=*))",
        "admin)(&(password=*))",
        "*))%00"
    ]
}

class SecurityTester:
    def __init__(self, base_url="http://127.0.0.1:8000"):
        self.base_url = base_url
        self.token = None
        self.results = {
            "total_tests": 0,
            "blocked": 0,
            "allowed": 0,
            "errors": 0,
            "security_score": 0,
            "vulnerabilities": [],
            "test_results": []
        }
    
    def login(self, username="admin", password="admin123"):
        """Login to get authentication token"""
        try:
            response = requests.post(
                f"{self.base_url}/auth/login",
                json={"username": username, "password": password},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("access_token")
                print("✅ Login successful")
                return True
            else:
                print(f"❌ Login failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def test_payload(self, payload, attack_type):
        """Test a single payload against the system"""
        try:
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            
            response = requests.post(
                f"{self.base_url}/api/analyze",
                json={"input": payload},
                headers=headers,
                timeout=10
            )
            
            self.results["total_tests"] += 1
            
            if response.status_code == 200:
                data = response.json()
                analysis = data.get("analysis", {})
                
                threat_detected = analysis.get("threat", False)
                blocked = analysis.get("blocked", False)
                confidence = analysis.get("confidence", 0)
                
                result = {
                    "payload": payload[:50] + "..." if len(payload) > 50 else payload,
                    "attack_type": attack_type,
                    "detected": threat_detected,
                    "blocked": blocked,
                    "confidence": confidence,
                    "status": "SECURE" if blocked else "VULNERABLE" if threat_detected else "UNDETECTED"
                }
                
                if blocked:
                    self.results["blocked"] += 1
                    print(f"🛡️ BLOCKED: {attack_type} - {payload[:30]}...")
                elif threat_detected:
                    self.results["allowed"] += 1
                    self.results["vulnerabilities"].append(result)
                    print(f"⚠️ DETECTED BUT NOT BLOCKED: {attack_type} - {payload[:30]}...")
                else:
                    self.results["allowed"] += 1
                    self.results["vulnerabilities"].append(result)
                    print(f"❌ NOT DETECTED: {attack_type} - {payload[:30]}...")
                
                self.results["test_results"].append(result)
                return result
                
            else:
                self.results["errors"] += 1
                print(f"❌ HTTP Error {response.status_code}: {payload[:30]}...")
                return None
                
        except Exception as e:
            self.results["errors"] += 1
            print(f"❌ Request error: {e}")
            return None
    
    def run_security_tests(self):
        """Run comprehensive security tests"""
        print("🛡️ SECURITY TESTING SUITE")
        print("=" * 50)
        print(f"Target: {self.base_url}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # Login first
        if not self.login():
            print("❌ Cannot proceed without authentication")
            return
        
        print("\n🚀 Starting security tests...\n")
        
        # Test each attack type
        for attack_type, payloads in ATTACK_PAYLOADS.items():
            print(f"\n📋 Testing {attack_type.upper().replace('_', ' ')}:")
            print("-" * 30)
            
            for payload in payloads:
                self.test_payload(payload, attack_type)
                time.sleep(0.5)  # Small delay between tests
        
        # Calculate security score
        if self.results["total_tests"] > 0:
            blocked_rate = (self.results["blocked"] / self.results["total_tests"]) * 100
            self.results["security_score"] = round(blocked_rate, 1)
        
        self.print_results()
    
    def print_results(self):
        """Print comprehensive test results"""
        print("\n" + "=" * 60)
        print("🔍 SECURITY TEST RESULTS")
        print("=" * 60)
        
        print(f"📊 SUMMARY:")
        print(f"   Total Tests: {self.results['total_tests']}")
        print(f"   🛡️ Blocked: {self.results['blocked']}")
        print(f"   ⚠️ Allowed: {self.results['allowed']}")
        print(f"   ❌ Errors: {self.results['errors']}")
        print(f"   🏆 Security Score: {self.results['security_score']}%")
        
        # Security rating
        score = self.results['security_score']
        if score >= 90:
            rating = "🟢 EXCELLENT"
        elif score >= 75:
            rating = "🟡 GOOD"
        elif score >= 50:
            rating = "🟠 MODERATE"
        else:
            rating = "🔴 POOR"
        
        print(f"   📈 Security Rating: {rating}")
        
        # Vulnerabilities found
        if self.results["vulnerabilities"]:
            print(f"\n⚠️ VULNERABILITIES FOUND ({len(self.results['vulnerabilities'])}):")
            print("-" * 40)
            
            for vuln in self.results["vulnerabilities"][:10]:  # Show top 10
                status_icon = "⚠️" if vuln["detected"] else "❌"
                print(f"   {status_icon} {vuln['attack_type']}: {vuln['payload']}")
                print(f"      Status: {vuln['status']}")
                if vuln["confidence"] > 0:
                    print(f"      Confidence: {vuln['confidence']:.1%}")
                print()
        
        # Recommendations
        print("💡 SECURITY RECOMMENDATIONS:")
        print("-" * 30)
        
        if self.results['security_score'] < 100:
            print("   • Enable automatic blocking for detected threats")
            print("   • Implement rate limiting to prevent brute force")
            print("   • Add input validation and sanitization")
            print("   • Configure Web Application Firewall (WAF)")
            print("   • Enable real-time alerting for security events")
        
        if self.results['security_score'] < 75:
            print("   • Update threat detection patterns")
            print("   • Implement additional security layers")
            print("   • Consider professional security audit")
        
        if self.results['security_score'] >= 90:
            print("   ✅ System shows good security posture")
            print("   • Continue monitoring and updating threat patterns")
            print("   • Regular security testing recommended")
        
        print("\n" + "=" * 60)
    
    def save_report(self, filename="security_report.json"):
        """Save detailed report to file"""
        report = {
            "test_date": datetime.now().isoformat(),
            "target_url": self.base_url,
            "results": self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Detailed report saved to: {filename}")

def main():
    """Main testing function"""
    print("🛡️ Infinite AI Security - Security Testing Suite")
    print("Testing system security against common attacks...")
    print()
    
    # Initialize tester
    tester = SecurityTester()
    
    # Run comprehensive tests
    tester.run_security_tests()
    
    # Save report
    tester.save_report()
    
    print("\n🎯 QUICK SECURITY CHECK:")
    score = tester.results['security_score']
    
    if score >= 90:
        print("✅ Your system is SECURE against common attacks!")
    elif score >= 75:
        print("⚠️ Your system has GOOD security but needs improvement")
    elif score >= 50:
        print("🟠 Your system has MODERATE security - action needed")
    else:
        print("🔴 Your system is VULNERABLE - immediate action required!")
    
    print(f"\nSecurity Score: {score}% ({tester.results['blocked']}/{tester.results['total_tests']} attacks blocked)")

if __name__ == "__main__":
    main()