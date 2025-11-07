"""
Prometheus Metrics - Monitoring dan observability
"""
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import time
from functools import wraps

# Metrics
threat_counter = Counter('threats_detected_total', 'Total threats detected', ['threat_type', 'severity'])
response_time = Histogram('api_response_time_seconds', 'API response time', ['endpoint'])
active_agents = Gauge('active_agents_count', 'Number of active AI agents')
labyrinth_nodes = Gauge('labyrinth_nodes_total', 'Total labyrinth nodes')
trapped_intruders = Gauge('trapped_intruders_count', 'Number of trapped intruders')

def track_response_time(endpoint_name):
    """Decorator untuk track response time"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                response_time.labels(endpoint=endpoint_name).observe(time.time() - start_time)
        return wrapper
    return decorator

def record_threat(threat_type: str, severity: str):
    """Record threat detection"""
    threat_counter.labels(threat_type=threat_type, severity=severity).inc()

def update_agent_count(count: int):
    """Update active agent count"""
    active_agents.set(count)

def update_labyrinth_stats(nodes: int, intruders: int):
    """Update labyrinth statistics"""
    labyrinth_nodes.set(nodes)
    trapped_intruders.set(intruders)

def get_metrics():
    """Get Prometheus metrics"""
    return generate_latest()