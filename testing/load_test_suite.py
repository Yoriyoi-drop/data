"""
Comprehensive Load Testing Suite
Tests system performance under 100M+ logs/day load
"""
import asyncio
import time
import json
import statistics
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import asyncpg
from kafka import KafkaProducer
import psutil
import logging

logger = logging.getLogger(__name__)

class PerformanceMetrics:
    """Collects and analyzes performance metrics"""
    
    def __init__(self):
        self.response_times = []
        self.throughput_data = []
        self.error_count = 0
        self.success_count = 0
        self.start_time = None
        self.end_time = None
    
    def add_response_time(self, response_time_ms: float):
        """Add response time measurement"""
        self.response_times.append(response_time_ms)
    
    def add_result(self, success: bool):
        """Add test result"""
        if success:
            self.success_count += 1
        else:
            self.error_count += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Calculate performance statistics"""
        if not self.response_times:
            return {}
        
        total_requests = self.success_count + self.error_count
        duration = (self.end_time - self.start_time) if self.end_time and self.start_time else 0
        
        return {
            "total_requests": total_requests,
            "successful_requests": self.success_count,
            "failed_requests": self.error_count,
            "success_rate": (self.success_count / max(1, total_requests)) * 100,
            "duration_seconds": duration,
            "requests_per_second": total_requests / max(1, duration),
            "response_times": {
                "min_ms": min(self.response_times),
                "max_ms": max(self.response_times),
                "avg_ms": statistics.mean(self.response_times),
                "median_ms": statistics.median(self.response_times),
                "p95_ms": self._percentile(self.response_times, 95),
                "p99_ms": self._percentile(self.response_times, 99)
            }
        }
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile"""
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        return sorted_data[min(index, len(sorted_data) - 1)]

class DatabaseLoadTest:
    """Database performance testing"""
    
    def __init__(self, db_pool: asyncpg.Pool):
        self.db_pool = db_pool
        self.metrics = PerformanceMetrics()
    
    async def test_insert_performance(self, num_records: int = 10000) -> Dict[str, Any]:
        """Test database insert performance"""
        print(f"🔄 Testing database insert performance ({num_records:,} records)...")
        
        self.metrics.start_time = time.time()
        
        # Generate test data
        test_records = []
        for i in range(num_records):
            record = {
                "timestamp": time.time(),
                "source_id": f"test_agent_{i % 100}",
                "source_ip": f"192.168.{(i // 256) % 256}.{i % 256}",
                "attack_type": ["sql_injection", "xss", "ddos"][i % 3],
                "severity": ["low", "medium", "high", "critical"][i % 4],
                "score": (i % 100) / 100.0,
                "raw_data": {"test": True, "id": i},
                "agent_votes": {"agent1": 0.8, "agent2": 0.9}
            }
            test_records.append(record)
        
        # Batch insert test
        batch_size = 1000
        tasks = []
        
        for i in range(0, len(test_records), batch_size):
            batch = test_records[i:i + batch_size]
            task = asyncio.create_task(self._insert_batch(batch))
            tasks.append(task)
        
        # Execute all batches
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        self.metrics.end_time = time.time()
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.metrics.add_result(False)
            else:
                self.metrics.add_result(True)
                self.metrics.add_response_time(result)
        
        return self.metrics.get_statistics()
    
    async def _insert_batch(self, records: List[Dict[str, Any]]) -> float:
        """Insert batch of records"""
        start_time = time.time()
        
        try:
            async with self.db_pool.acquire() as conn:
                # Simulate time-series insert
                for record in records:
                    await conn.execute("""
                        INSERT INTO ai_hub.telemetry (source, event_type, data)
                        VALUES ($1, $2, $3)
                    """, record["source_id"], record["attack_type"], json.dumps(record))
            
            return (time.time() - start_time) * 1000  # Convert to ms
        
        except Exception as e:
            logger.error(f"Batch insert failed: {e}")
            raise
    
    async def test_query_performance(self, num_queries: int = 1000) -> Dict[str, Any]:
        """Test database query performance"""
        print(f"🔍 Testing database query performance ({num_queries:,} queries)...")
        
        query_metrics = PerformanceMetrics()
        query_metrics.start_time = time.time()
        
        # Test various query patterns
        queries = [
            "SELECT COUNT(*) FROM ai_hub.telemetry WHERE event_type = 'sql_injection'",
            "SELECT * FROM ai_hub.telemetry WHERE source = 'test_agent_1' ORDER BY event_time DESC LIMIT 100",
            "SELECT event_type, COUNT(*) FROM ai_hub.telemetry GROUP BY event_type",
            "SELECT * FROM ai_hub.telemetry WHERE event_time > NOW() - INTERVAL '1 hour'"
        ]
        
        tasks = []
        for i in range(num_queries):
            query = queries[i % len(queries)]
            task = asyncio.create_task(self._execute_query(query))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        query_metrics.end_time = time.time()
        
        for result in results:
            if isinstance(result, Exception):
                query_metrics.add_result(False)
            else:
                query_metrics.add_result(True)
                query_metrics.add_response_time(result)
        
        return query_metrics.get_statistics()
    
    async def _execute_query(self, query: str) -> float:
        """Execute single query"""
        start_time = time.time()
        
        try:
            async with self.db_pool.acquire() as conn:
                await conn.fetch(query)
            
            return (time.time() - start_time) * 1000
        
        except Exception as e:
            logger.error(f"Query failed: {e}")
            raise

class APILoadTest:
    """API endpoint performance testing"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.metrics = PerformanceMetrics()
    
    async def test_threat_analysis_endpoint(self, num_requests: int = 5000) -> Dict[str, Any]:
        """Test threat analysis API performance"""
        print(f"🌐 Testing API performance ({num_requests:,} requests)...")
        
        self.metrics.start_time = time.time()
        
        # Create test payloads
        test_payloads = [
            {"input": "' OR 1=1 --", "source_ip": "192.168.1.100"},
            {"input": "<script>alert('xss')</script>", "source_ip": "192.168.1.101"},
            {"input": "admin'; DROP TABLE users; --", "source_ip": "192.168.1.102"},
            {"input": "normal user input", "source_ip": "192.168.1.103"}
        ]
        
        # Create concurrent requests
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            
            for i in range(num_requests):
                payload = test_payloads[i % len(test_payloads)]
                task = asyncio.create_task(self._make_api_request(session, payload))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        self.metrics.end_time = time.time()
        
        for result in results:
            if isinstance(result, Exception):
                self.metrics.add_result(False)
            else:
                self.metrics.add_result(True)
                self.metrics.add_response_time(result)
        
        return self.metrics.get_statistics()
    
    async def _make_api_request(self, session: aiohttp.ClientSession, payload: Dict[str, Any]) -> float:
        """Make single API request"""
        start_time = time.time()
        
        try:
            async with session.post(f"{self.base_url}/api/analyze", json=payload) as response:
                await response.json()
                return (time.time() - start_time) * 1000
        
        except Exception as e:
            logger.error(f"API request failed: {e}")
            raise

class KafkaLoadTest:
    """Kafka throughput testing"""
    
    def __init__(self, bootstrap_servers: List[str]):
        self.bootstrap_servers = bootstrap_servers
        self.metrics = PerformanceMetrics()
    
    def test_producer_throughput(self, num_messages: int = 100000) -> Dict[str, Any]:
        """Test Kafka producer throughput"""
        print(f"📨 Testing Kafka producer throughput ({num_messages:,} messages)...")
        
        producer = KafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda x: json.dumps(x).encode('utf-8'),
            batch_size=16384,
            linger_ms=10,
            compression_type='snappy'
        )
        
        self.metrics.start_time = time.time()
        
        # Generate and send messages
        for i in range(num_messages):
            message = {
                "id": f"msg_{i}",
                "timestamp": time.time(),
                "data": f"test_data_{i}",
                "source": f"producer_{i % 10}"
            }
            
            try:
                start_time = time.time()
                future = producer.send('threat-logs', value=message)
                future.get(timeout=10)  # Wait for confirmation
                
                response_time = (time.time() - start_time) * 1000
                self.metrics.add_response_time(response_time)
                self.metrics.add_result(True)
                
            except Exception as e:
                logger.error(f"Kafka send failed: {e}")
                self.metrics.add_result(False)
        
        producer.flush()
        producer.close()
        
        self.metrics.end_time = time.time()
        return self.metrics.get_statistics()

class SystemResourceMonitor:
    """Monitor system resources during load testing"""
    
    def __init__(self):
        self.cpu_usage = []
        self.memory_usage = []
        self.disk_io = []
        self.network_io = []
        self.monitoring = False
    
    async def start_monitoring(self):
        """Start resource monitoring"""
        self.monitoring = True
        
        while self.monitoring:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_usage.append(cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_usage.append(memory.percent)
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                self.disk_io.append({
                    "read_bytes": disk_io.read_bytes,
                    "write_bytes": disk_io.write_bytes
                })
            
            # Network I/O
            network_io = psutil.net_io_counters()
            if network_io:
                self.network_io.append({
                    "bytes_sent": network_io.bytes_sent,
                    "bytes_recv": network_io.bytes_recv
                })
            
            await asyncio.sleep(1)
    
    def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return statistics"""
        self.monitoring = False
        
        return {
            "cpu": {
                "avg_percent": statistics.mean(self.cpu_usage) if self.cpu_usage else 0,
                "max_percent": max(self.cpu_usage) if self.cpu_usage else 0
            },
            "memory": {
                "avg_percent": statistics.mean(self.memory_usage) if self.memory_usage else 0,
                "max_percent": max(self.memory_usage) if self.memory_usage else 0
            },
            "samples_collected": len(self.cpu_usage)
        }

class ComprehensiveLoadTest:
    """Main load testing orchestrator"""
    
    def __init__(self):
        self.results = {}
    
    async def run_full_test_suite(self) -> Dict[str, Any]:
        """Run complete load testing suite"""
        print("🚀 Starting Comprehensive Load Test Suite")
        print("=" * 60)
        
        # System resource monitoring
        monitor = SystemResourceMonitor()
        monitor_task = asyncio.create_task(monitor.start_monitoring())
        
        try:
            # Database tests
            db_pool = await asyncpg.create_pool(
                "postgresql://user:pass@localhost/infinite_labyrinth",
                min_size=10, max_size=50
            )
            
            db_test = DatabaseLoadTest(db_pool)
            self.results["database_insert"] = await db_test.test_insert_performance(50000)
            self.results["database_query"] = await db_test.test_query_performance(5000)
            
            # API tests
            api_test = APILoadTest()
            self.results["api_performance"] = await api_test.test_threat_analysis_endpoint(10000)
            
            # Kafka tests
            kafka_test = KafkaLoadTest(['localhost:9092', 'localhost:9093', 'localhost:9094'])
            self.results["kafka_throughput"] = kafka_test.test_producer_throughput(50000)
            
        finally:
            # Stop monitoring
            self.results["system_resources"] = monitor.stop_monitoring()
            monitor_task.cancel()
        
        # Generate report
        self.generate_report()
        return self.results
    
    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("📊 LOAD TEST RESULTS SUMMARY")
        print("=" * 60)
        
        # Database results
        if "database_insert" in self.results:
            db_insert = self.results["database_insert"]
            print(f"\n🗄️  DATABASE INSERT PERFORMANCE:")
            print(f"   Total Records: {db_insert.get('total_requests', 0):,}")
            print(f"   Success Rate: {db_insert.get('success_rate', 0):.1f}%")
            print(f"   Throughput: {db_insert.get('requests_per_second', 0):.0f} records/sec")
            
            if "response_times" in db_insert:
                rt = db_insert["response_times"]
                print(f"   Avg Response: {rt.get('avg_ms', 0):.1f}ms")
                print(f"   P99 Response: {rt.get('p99_ms', 0):.1f}ms")
        
        # API results
        if "api_performance" in self.results:
            api = self.results["api_performance"]
            print(f"\n🌐 API PERFORMANCE:")
            print(f"   Total Requests: {api.get('total_requests', 0):,}")
            print(f"   Success Rate: {api.get('success_rate', 0):.1f}%")
            print(f"   Throughput: {api.get('requests_per_second', 0):.0f} req/sec")
            
            if "response_times" in api:
                rt = api["response_times"]
                print(f"   Avg Response: {rt.get('avg_ms', 0):.1f}ms")
                print(f"   P99 Response: {rt.get('p99_ms', 0):.1f}ms")
        
        # Kafka results
        if "kafka_throughput" in self.results:
            kafka = self.results["kafka_throughput"]
            print(f"\n📨 KAFKA THROUGHPUT:")
            print(f"   Total Messages: {kafka.get('total_requests', 0):,}")
            print(f"   Success Rate: {kafka.get('success_rate', 0):.1f}%")
            print(f"   Throughput: {kafka.get('requests_per_second', 0):.0f} msg/sec")
        
        # System resources
        if "system_resources" in self.results:
            sys_res = self.results["system_resources"]
            print(f"\n💻 SYSTEM RESOURCES:")
            print(f"   Avg CPU Usage: {sys_res.get('cpu', {}).get('avg_percent', 0):.1f}%")
            print(f"   Max CPU Usage: {sys_res.get('cpu', {}).get('max_percent', 0):.1f}%")
            print(f"   Avg Memory Usage: {sys_res.get('memory', {}).get('avg_percent', 0):.1f}%")
            print(f"   Max Memory Usage: {sys_res.get('memory', {}).get('max_percent', 0):.1f}%")
        
        print("\n✅ Load testing completed successfully!")

# Run load tests
async def main():
    load_test = ComprehensiveLoadTest()
    results = await load_test.run_full_test_suite()
    
    # Save results to file
    with open("load_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📄 Detailed results saved to: load_test_results.json")

if __name__ == "__main__":
    asyncio.run(main())