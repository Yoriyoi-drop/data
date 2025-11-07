"""
DDoS Testing - Test system resilience against Distributed Denial of Service attacks
"""
import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class DDoSTester:
    def __init__(self, target_url="http://127.0.0.1:8007"):
        self.target_url = target_url
        self.token = None
        self.results = {
            "total_requests": 0,
            "successful": 0,
            "failed": 0,
            "blocked": 0,
            "response_times": [],
            "status_codes": {}
        }
    
    def login(self):
        """Get authentication token"""
        try:
            response = requests.post(
                f"{self.target_url}/auth/login",
                json={"username": "admin", "password": "admin123"},
                timeout=5
            )
            if response.status_code == 200:
                self.token = response.json().get("access_token")
                return True
        except:
            pass
        return False
    
    def single_request(self, request_id):
        """Send single request to target"""
        start_time = time.time()
        
        try:
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            
            # Random payloads to simulate real traffic
            payloads = [
                "test request",
                "admin' OR '1'='1",
                "<script>alert('test')</script>",
                "; whoami",
                "normal user input"
            ]
            
            payload = payloads[request_id % len(payloads)]
            
            response = requests.post(
                f"{self.target_url}/api/analyze",
                json={"input": payload},
                headers=headers,
                timeout=10
            )
            
            response_time = time.time() - start_time
            
            return {
                "id": request_id,
                "status_code": response.status_code,
                "response_time": response_time,
                "success": response.status_code == 200,
                "blocked": response.status_code == 429  # Too Many Requests
            }
            
        except requests.exceptions.Timeout:
            return {
                "id": request_id,
                "status_code": 408,  # Request Timeout
                "response_time": time.time() - start_time,
                "success": False,
                "blocked": False
            }
        except Exception as e:
            return {
                "id": request_id,
                "status_code": 0,
                "response_time": time.time() - start_time,
                "success": False,
                "blocked": False,
                "error": str(e)
            }
    
    def stress_test(self, num_requests=100, max_workers=20):
        """Perform stress test with concurrent requests"""
        print(f"🚀 Starting DDoS stress test...")
        print(f"📊 Requests: {num_requests}")
        print(f"🔄 Concurrent workers: {max_workers}")
        print(f"🎯 Target: {self.target_url}")
        print("-" * 50)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all requests
            futures = [executor.submit(self.single_request, i) for i in range(num_requests)]
            
            # Process results as they complete
            completed = 0
            for future in as_completed(futures):
                result = future.result()
                completed += 1
                
                # Update statistics
                self.results["total_requests"] += 1
                
                if result["success"]:
                    self.results["successful"] += 1
                else:
                    self.results["failed"] += 1
                
                if result["blocked"]:
                    self.results["blocked"] += 1
                
                self.results["response_times"].append(result["response_time"])
                
                status_code = result["status_code"]
                self.results["status_codes"][status_code] = self.results["status_codes"].get(status_code, 0) + 1
                
                # Progress indicator
                if completed % 10 == 0:
                    progress = (completed / num_requests) * 100
                    print(f"Progress: {progress:.1f}% ({completed}/{num_requests})")
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        avg_response_time = sum(self.results["response_times"]) / len(self.results["response_times"])
        requests_per_second = num_requests / total_time
        
        print("\n" + "=" * 60)
        print("📊 DDoS TEST RESULTS")
        print("=" * 60)
        
        print(f"⏱️ Total Time: {total_time:.2f} seconds")
        print(f"🚀 Requests/Second: {requests_per_second:.2f}")
        print(f"⚡ Average Response Time: {avg_response_time:.3f} seconds")
        
        print(f"\n📈 REQUEST STATISTICS:")
        print(f"   Total Requests: {self.results['total_requests']}")
        print(f"   ✅ Successful: {self.results['successful']}")
        print(f"   ❌ Failed: {self.results['failed']}")
        print(f"   🛡️ Blocked (Rate Limited): {self.results['blocked']}")
        
        print(f"\n📋 STATUS CODES:")
        for code, count in sorted(self.results["status_codes"].items()):
            percentage = (count / num_requests) * 100
            status_name = {
                200: "OK",
                400: "Bad Request", 
                401: "Unauthorized",
                429: "Too Many Requests",
                500: "Internal Server Error",
                408: "Request Timeout",
                0: "Connection Error"
            }.get(code, f"HTTP {code}")
            
            print(f"   {code} ({status_name}): {count} ({percentage:.1f}%)")
        
        # Security assessment
        print(f"\n🛡️ SECURITY ASSESSMENT:")
        
        if self.results["blocked"] > 0:
            block_rate = (self.results["blocked"] / num_requests) * 100
            print(f"   ✅ Rate limiting active: {block_rate:.1f}% requests blocked")
            
            if block_rate > 50:
                print("   🟢 EXCELLENT: Strong DDoS protection")
            elif block_rate > 20:
                print("   🟡 GOOD: Moderate DDoS protection")
            else:
                print("   🟠 WEAK: Limited DDoS protection")
        else:
            print("   ❌ NO RATE LIMITING: Vulnerable to DDoS attacks")
        
        # Response time analysis
        if avg_response_time > 5.0:
            print("   ⚠️ HIGH LATENCY: System may be overloaded")
        elif avg_response_time > 2.0:
            print("   🟡 MODERATE LATENCY: System handling load")
        else:
            print("   ✅ LOW LATENCY: System performing well")
        
        # Failure rate analysis
        failure_rate = (self.results["failed"] / num_requests) * 100
        if failure_rate > 50:
            print("   🔴 HIGH FAILURE RATE: System unstable under load")
        elif failure_rate > 20:
            print("   🟠 MODERATE FAILURE RATE: System stressed")
        else:
            print("   ✅ LOW FAILURE RATE: System stable")
        
        return self.results
    
    def volumetric_attack(self, duration=30, requests_per_second=50):
        """Simulate volumetric DDoS attack"""
        print(f"🌊 VOLUMETRIC ATTACK SIMULATION")
        print(f"⏱️ Duration: {duration} seconds")
        print(f"🚀 Rate: {requests_per_second} requests/second")
        print("-" * 50)
        
        start_time = time.time()
        request_count = 0
        
        def attack_worker():
            nonlocal request_count
            while time.time() - start_time < duration:
                try:
                    headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
                    requests.post(
                        f"{self.target_url}/api/analyze",
                        json={"input": f"attack_{request_count}"},
                        headers=headers,
                        timeout=1
                    )
                    request_count += 1
                except:
                    pass
                
                time.sleep(1 / requests_per_second)
        
        # Launch attack threads
        threads = []
        for _ in range(min(10, requests_per_second)):
            thread = threading.Thread(target=attack_worker)
            thread.start()
            threads.append(thread)
        
        # Monitor attack
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            current_rate = request_count / elapsed if elapsed > 0 else 0
            print(f"⚡ Attack progress: {elapsed:.1f}s | Rate: {current_rate:.1f} req/s | Total: {request_count}")
            time.sleep(2)
        
        # Wait for threads to finish
        for thread in threads:
            thread.join()
        
        actual_duration = time.time() - start_time
        actual_rate = request_count / actual_duration
        
        print(f"\n📊 VOLUMETRIC ATTACK RESULTS:")
        print(f"   Duration: {actual_duration:.2f} seconds")
        print(f"   Total Requests: {request_count}")
        print(f"   Actual Rate: {actual_rate:.2f} req/s")
        
        if actual_rate < requests_per_second * 0.5:
            print("   🛡️ GOOD: System successfully limited attack rate")
        else:
            print("   ⚠️ WARNING: System may be vulnerable to volumetric attacks")

def main():
    print("💥 DDoS TESTING SUITE")
    print("=" * 50)
    print("⚠️ WARNING: This will stress test your system")
    print("🎯 Testing DDoS resilience and rate limiting")
    print("=" * 50)
    
    tester = DDoSTester()
    
    # Login
    if tester.login():
        print("✅ Authentication successful")
    else:
        print("⚠️ Authentication failed - testing without token")
    
    print("\n" + "=" * 50)
    
    # Test menu
    print("Select DDoS test type:")
    print("1. Stress Test (100 concurrent requests)")
    print("2. Heavy Load Test (500 concurrent requests)")
    print("3. Volumetric Attack Simulation")
    print("4. All Tests")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        tester.stress_test(100, 20)
    elif choice == "2":
        tester.stress_test(500, 50)
    elif choice == "3":
        tester.volumetric_attack(30, 100)
    elif choice == "4":
        print("\n🚀 Running all DDoS tests...\n")
        tester.stress_test(100, 20)
        print("\n" + "="*50 + "\n")
        tester.stress_test(500, 50)
        print("\n" + "="*50 + "\n")
        tester.volumetric_attack(30, 100)
    else:
        print("❌ Invalid choice")
        return
    
    print("\n💡 RECOMMENDATIONS:")
    if tester.results.get("blocked", 0) == 0:
        print("   • Implement rate limiting (e.g., 100 requests/minute)")
        print("   • Add DDoS protection (Cloudflare, AWS Shield)")
        print("   • Configure load balancing")
        print("   • Set up monitoring and alerting")
    else:
        print("   ✅ Rate limiting is working")
        print("   • Monitor for attack patterns")
        print("   • Consider additional DDoS protection layers")

if __name__ == "__main__":
    main()