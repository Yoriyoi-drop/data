"""
Simple Attack Test - Test serangan tanpa emoji
"""
import requests
import threading
import time
import json

class SimpleAttackTester:
    def __init__(self, target_url="http://127.0.0.1:8000"):
        self.target_url = target_url
        self.token = None
        self.results = {
            "total": 0,
            "blocked": 0,
            "passed": 0,
            "failed": 0
        }
    
    def login(self):
        try:
            response = requests.post(
                f"{self.target_url}/auth/login",
                json={"username": "admin", "password": "admin123"},
                timeout=10
            )
            if response.status_code == 200:
                self.token = response.json().get("access_token")
                print(f"[OK] Login successful")
                return True
            else:
                print(f"[ERROR] Login failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[ERROR] Login error: {e}")
            return False
    
    def send_attack(self, attack_type, payload):
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
            
            self.results["total"] += 1
            
            if response.status_code == 200:
                result = response.json()
                analysis = result.get("analysis", {})
                
                if analysis.get("blocked", False):
                    self.results["blocked"] += 1
                    print(f"[BLOCKED] {attack_type}: {payload[:50]}...")
                else:
                    self.results["passed"] += 1
                    print(f"[PASSED] {attack_type}: {payload[:50]}...")
                    
            elif response.status_code == 429:
                print(f"[RATE_LIMITED] {attack_type}")
                self.results["blocked"] += 1
            else:
                print(f"[ERROR] {response.status_code}: {attack_type}")
                self.results["failed"] += 1
                
        except Exception as e:
            print(f"[EXCEPTION] {attack_type}: {str(e)}")
            self.results["failed"] += 1
    
    def test_sql_injection(self):
        print("\n[TEST] SQL Injection Attacks")
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "' OR 1=1 --"
        ]
        
        for payload in payloads:
            self.send_attack("SQL_INJECTION", payload)
    
    def test_xss(self):
        print("\n[TEST] XSS Attacks")
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<script>document.cookie='stolen'</script>"
        ]
        
        for payload in payloads:
            self.send_attack("XSS", payload)
    
    def test_command_injection(self):
        print("\n[TEST] Command Injection Attacks")
        payloads = [
            "; dir",
            "&& whoami",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "; del /f /q *.*",
            "&& net user hacker password /add"
        ]
        
        for payload in payloads:
            self.send_attack("COMMAND_INJECTION", payload)
    
    def ddos_test(self, duration=15, threads=10):
        print(f"\n[DDOS] Starting DDoS test - {duration}s with {threads} threads")
        
        start_time = time.time()
        request_count = 0
        blocked_count = 0
        
        def ddos_worker():
            nonlocal request_count, blocked_count
            
            payloads = [
                "' OR '1'='1",
                "<script>alert('ddos')</script>",
                "; whoami",
                "normal request"
            ]
            
            while time.time() - start_time < duration:
                try:
                    payload = payloads[request_count % len(payloads)]
                    headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
                    
                    response = requests.post(
                        f"{self.target_url}/api/analyze",
                        json={"input": f"ddos_{request_count}_{payload}"},
                        headers=headers,
                        timeout=5
                    )
                    
                    request_count += 1
                    
                    if response.status_code == 429:
                        blocked_count += 1
                    elif response.status_code == 200:
                        result = response.json()
                        if result.get("analysis", {}).get("blocked", False):
                            blocked_count += 1
                    
                except:
                    pass
                
                time.sleep(0.05)
        
        # Start threads
        threads_list = []
        for _ in range(threads):
            thread = threading.Thread(target=ddos_worker)
            thread.start()
            threads_list.append(thread)
        
        # Monitor
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            rps = request_count / elapsed if elapsed > 0 else 0
            block_rate = (blocked_count / request_count * 100) if request_count > 0 else 0
            
            print(f"[DDOS] Progress: {elapsed:.1f}s | Requests: {request_count} | RPS: {rps:.1f} | Blocked: {block_rate:.1f}%")
            time.sleep(3)
        
        # Wait for completion
        for thread in threads_list:
            thread.join()
        
        total_time = time.time() - start_time
        final_rps = request_count / total_time
        final_block_rate = (blocked_count / request_count * 100) if request_count > 0 else 0
        
        print(f"\n[DDOS_RESULTS]")
        print(f"Duration: {total_time:.2f}s")
        print(f"Total Requests: {request_count}")
        print(f"Requests/Second: {final_rps:.2f}")
        print(f"Blocked: {blocked_count} ({final_block_rate:.1f}%)")
        
        if final_block_rate > 50:
            print("[SECURITY] EXCELLENT - Strong DDoS protection")
        elif final_block_rate > 20:
            print("[SECURITY] GOOD - Moderate protection")
        else:
            print("[SECURITY] WEAK - Limited protection")
    
    def run_all_tests(self):
        print("[START] INFINITE AI SECURITY - ATTACK TESTING")
        print("=" * 50)
        
        if not self.login():
            print("[ERROR] Cannot proceed without authentication")
            return
        
        # Run tests
        self.test_sql_injection()
        self.test_xss()
        self.test_command_injection()
        
        # DDoS test
        self.ddos_test(duration=10, threads=5)
        
        # Results
        print("\n" + "=" * 50)
        print("[RESULTS] ATTACK TEST SUMMARY")
        print("=" * 50)
        
        total = self.results["total"]
        blocked = self.results["blocked"]
        passed = self.results["passed"]
        failed = self.results["failed"]
        
        print(f"Total Attacks: {total}")
        print(f"Blocked: {blocked} ({blocked/total*100:.1f}%)")
        print(f"Passed: {passed} ({passed/total*100:.1f}%)")
        print(f"Failed: {failed} ({failed/total*100:.1f}%)")
        
        block_rate = (blocked / total * 100) if total > 0 else 0
        
        if block_rate > 80:
            print("[ASSESSMENT] EXCELLENT security")
        elif block_rate > 60:
            print("[ASSESSMENT] GOOD security")
        elif block_rate > 40:
            print("[ASSESSMENT] MODERATE security")
        else:
            print("[ASSESSMENT] WEAK security")

if __name__ == "__main__":
    tester = SimpleAttackTester()
    tester.run_all_tests()