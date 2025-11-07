import json
import time
import random
from datetime import datetime
from kafka import KafkaProducer
import threading

class ThreatLogProducer:
    def __init__(self, kafka_brokers, topic):
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_brokers,
            value_serializer=lambda x: json.dumps(x).encode('utf-8'),
            batch_size=16384,
            linger_ms=10,
            compression_type='snappy'
        )
        self.topic = topic
        
    def generate_threat_log(self, source_id):
        attack_types = ['sql_injection', 'xss', 'ddos', 'malware', 'phishing', 'brute_force']
        severities = ['low', 'medium', 'high', 'critical']
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'source_id': source_id,
            'source_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'attack_type': random.choice(attack_types),
            'severity': random.choice(severities),
            'score': random.uniform(0.1, 1.0),
            'raw': {
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'request_path': f'/api/v1/{random.choice(["users", "orders", "products"])}',
                'payload_size': random.randint(100, 5000),
                'response_code': random.choice([200, 400, 401, 403, 500])
            },
            'agent_votes': {
                'agent_1': random.uniform(0.0, 1.0),
                'agent_2': random.uniform(0.0, 1.0),
                'agent_3': random.uniform(0.0, 1.0)
            }
        }
    
    def produce_logs(self, rate_per_second, duration_seconds, source_id_prefix="agent"):
        """Produce logs at specified rate"""
        total_logs = rate_per_second * duration_seconds
        interval = 1.0 / rate_per_second
        
        print(f"Producing {total_logs} logs over {duration_seconds}s at {rate_per_second}/sec")
        
        start_time = time.time()
        for i in range(total_logs):
            source_id = f"{source_id_prefix}-{i % 100:03d}"  # 100 different agents
            log_data = self.generate_threat_log(source_id)
            
            self.producer.send(self.topic, value=log_data, key=source_id.encode())
            
            # Rate limiting
            elapsed = time.time() - start_time
            expected_time = i * interval
            if elapsed < expected_time:
                time.sleep(expected_time - elapsed)
            
            if (i + 1) % 1000 == 0:
                print(f"Produced {i + 1}/{total_logs} logs")
        
        self.producer.flush()
        print(f"Completed producing {total_logs} logs")

def load_test_scenario():
    """Run various load test scenarios"""
    producer = ThreatLogProducer(
        kafka_brokers=['localhost:9092', 'localhost:9093', 'localhost:9094'],
        topic='threat-logs'
    )
    
    scenarios = [
        # (rate_per_second, duration_seconds, description)
        (100, 60, "Baseline: 100/sec for 1 minute"),
        (1000, 30, "Medium load: 1K/sec for 30 seconds"),
        (5000, 10, "High load: 5K/sec for 10 seconds"),
        (10000, 5, "Peak load: 10K/sec for 5 seconds"),
    ]
    
    for rate, duration, description in scenarios:
        print(f"\n🚀 Starting scenario: {description}")
        producer.produce_logs(rate, duration, f"test-{rate}")
        print("✅ Scenario completed, waiting 30s before next...")
        time.sleep(30)

def sustained_load_test():
    """Simulate sustained 100M logs/day load"""
    target_daily = 100_000_000
    target_per_second = target_daily // 86400  # ~1,157/sec
    
    producer = ThreatLogProducer(
        kafka_brokers=['localhost:9092', 'localhost:9093', 'localhost:9094'],
        topic='threat-logs'
    )
    
    print(f"🎯 Sustained load test: {target_per_second}/sec (100M/day equivalent)")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            producer.produce_logs(target_per_second, 60, "sustained")
            print("📊 Completed 1-minute batch, continuing...")
    except KeyboardInterrupt:
        print("\n🛑 Stopping sustained load test")

def multi_threaded_producer(threads=4, rate_per_thread=250):
    """Multi-threaded producer for higher throughput"""
    def worker(thread_id):
        producer = ThreatLogProducer(
            kafka_brokers=['localhost:9092', 'localhost:9093', 'localhost:9094'],
            topic='threat-logs'
        )
        
        print(f"Thread {thread_id} starting at {rate_per_thread}/sec")
        try:
            while True:
                producer.produce_logs(rate_per_thread, 60, f"thread-{thread_id}")
        except KeyboardInterrupt:
            print(f"Thread {thread_id} stopping")
    
    print(f"🔥 Multi-threaded test: {threads} threads × {rate_per_thread}/sec = {threads * rate_per_thread}/sec total")
    
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=worker, args=(i,))
        t.daemon = True
        t.start()
        thread_list.append(t)
    
    try:
        for t in thread_list:
            t.join()
    except KeyboardInterrupt:
        print("\n🛑 Stopping all threads")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python test_producer.py load_test     # Run load test scenarios")
        print("  python test_producer.py sustained     # Run sustained 100M/day test")
        print("  python test_producer.py multi         # Run multi-threaded test")
        print("  python test_producer.py quick         # Quick 1000 logs test")
        sys.exit(1)
    
    mode = sys.argv[1]
    
    if mode == "load_test":
        load_test_scenario()
    elif mode == "sustained":
        sustained_load_test()
    elif mode == "multi":
        multi_threaded_producer()
    elif mode == "quick":
        producer = ThreatLogProducer(['localhost:9092'], 'threat-logs')
        producer.produce_logs(100, 10, "quick-test")
    else:
        print(f"Unknown mode: {mode}")