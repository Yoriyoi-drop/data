"""
Database Connection Pool Manager
Security Enhancement - Prevents connection exhaustion attacks
"""
import threading
import time
from contextlib import contextmanager
from typing import Optional, List
import sqlite3

try:
    import pg8000
    PG8000_AVAILABLE = True
except ImportError:
    PG8000_AVAILABLE = False
    print("⚠️  pg8000 not available")


class ConnectionPool:
    """
    Database connection pool to prevent connection exhaustion
    
    Features:
    - Connection reuse
    - Max connections limit
    - Connection health checking
    - Automatic cleanup of stale connections
    - Thread-safe operations
    """
    
    def __init__(self, db_type: str = "sqlite", pool_size: int = 20, 
                 max_overflow: int = 10, **db_config):
        """
        Initialize connection pool
        
        Args:
            db_type: Database type ('sqlite' or 'postgres')
            pool_size: Number of connections to maintain
            max_overflow: Maximum additional connections allowed
            **db_config: Database configuration parameters
        """
        self.db_type = db_type
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.db_config = db_config
        
        # Connection pool
        self.pool: List = []
        self.pool_lock = threading.Lock()
        
        # Overflow connections (temporary)
        self.overflow_connections = 0
        self.overflow_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            "total_created": 0,
            "total_reused": 0,
            "total_closed": 0,
            "pool_hits": 0,
            "pool_misses": 0,
            "overflow_used": 0
        }
        self.stats_lock = threading.Lock()
        
        # Initialize pool
        self._initialize_pool()
        
        print(f"✅ Connection pool initialized: {pool_size} connections ({db_type})")
    
    def _initialize_pool(self):
        """Initialize connection pool with connections"""
        with self.pool_lock:
            for _ in range(self.pool_size):
                try:
                    conn = self._create_connection()
                    self.pool.append(conn)
                    with self.stats_lock:
                        self.stats["total_created"] += 1
                except Exception as e:
                    print(f"❌ Failed to create connection: {e}")
    
    def _create_connection(self):
        """Create a new database connection"""
        if self.db_type == "sqlite":
            db_path = self.db_config.get("db_path", "infinite_security_v2.db")
            conn = sqlite3.connect(db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            return conn
        
        elif self.db_type == "postgres":
            if not PG8000_AVAILABLE:
                raise RuntimeError("pg8000 not available for PostgreSQL connections")
            
            conn = pg8000.connect(
                host=self.db_config.get("host", "127.0.0.1"),
                port=self.db_config.get("port", 5432),
                user=self.db_config.get("user", "postgres"),
                password=self.db_config.get("password", "postgres"),
                database=self.db_config.get("database", "infinite_ai")
            )
            return conn
        
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")
    
    def _is_connection_healthy(self, conn) -> bool:
        """Check if connection is healthy"""
        try:
            if self.db_type == "sqlite":
                cursor = conn.execute("SELECT 1")
                cursor.fetchone()
                return True
            elif self.db_type == "postgres":
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                return True
        except Exception:
            return False
        
        return False
    
    @contextmanager
    def get_connection(self):
        """
        Get a connection from the pool
        
        Yields:
            Database connection
        """
        conn = None
        is_overflow = False
        
        # Try to get connection from pool
        with self.pool_lock:
            if self.pool:
                conn = self.pool.pop()
                with self.stats_lock:
                    self.stats["pool_hits"] += 1
                    self.stats["total_reused"] += 1
        
        # If pool is empty, create overflow connection
        if conn is None:
            with self.overflow_lock:
                if self.overflow_connections < self.max_overflow:
                    try:
                        conn = self._create_connection()
                        self.overflow_connections += 1
                        is_overflow = True
                        with self.stats_lock:
                            self.stats["pool_misses"] += 1
                            self.stats["overflow_used"] += 1
                            self.stats["total_created"] += 1
                    except Exception as e:
                        raise RuntimeError(f"Failed to create overflow connection: {e}")
                else:
                    # Wait for connection to become available
                    max_wait = 30  # seconds
                    waited = 0
                    while waited < max_wait:
                        time.sleep(0.1)
                        waited += 0.1
                        
                        with self.pool_lock:
                            if self.pool:
                                conn = self.pool.pop()
                                with self.stats_lock:
                                    self.stats["pool_hits"] += 1
                                    self.stats["total_reused"] += 1
                                break
                    
                    if conn is None:
                        raise RuntimeError("Connection pool exhausted - timeout waiting for connection")
        
        # Check connection health
        if conn and not self._is_connection_healthy(conn):
            # Connection is stale, create new one
            try:
                conn.close()
            except:
                pass
            
            conn = self._create_connection()
            with self.stats_lock:
                self.stats["total_created"] += 1
        
        try:
            yield conn
        finally:
            # Return connection to pool or close if overflow
            if conn:
                if is_overflow:
                    # Close overflow connection
                    try:
                        conn.close()
                        with self.overflow_lock:
                            self.overflow_connections -= 1
                        with self.stats_lock:
                            self.stats["total_closed"] += 1
                    except Exception as e:
                        print(f"❌ Error closing overflow connection: {e}")
                else:
                    # Return to pool
                    with self.pool_lock:
                        if len(self.pool) < self.pool_size:
                            self.pool.append(conn)
                        else:
                            # Pool is full, close connection
                            try:
                                conn.close()
                                with self.stats_lock:
                                    self.stats["total_closed"] += 1
                            except Exception as e:
                                print(f"❌ Error closing connection: {e}")
    
    def cleanup_stale_connections(self):
        """Remove stale connections from pool"""
        with self.pool_lock:
            healthy_connections = []
            stale_count = 0
            
            for conn in self.pool:
                if self._is_connection_healthy(conn):
                    healthy_connections.append(conn)
                else:
                    try:
                        conn.close()
                        stale_count += 1
                        with self.stats_lock:
                            self.stats["total_closed"] += 1
                    except:
                        pass
            
            self.pool = healthy_connections
            
            # Refill pool if needed
            while len(self.pool) < self.pool_size:
                try:
                    conn = self._create_connection()
                    self.pool.append(conn)
                    with self.stats_lock:
                        self.stats["total_created"] += 1
                except Exception as e:
                    print(f"❌ Failed to create connection during cleanup: {e}")
                    break
            
            if stale_count > 0:
                print(f"🧹 Cleaned up {stale_count} stale connections")
    
    def get_stats(self) -> dict:
        """Get connection pool statistics"""
        with self.stats_lock:
            stats = self.stats.copy()
        
        with self.pool_lock:
            stats["pool_size"] = len(self.pool)
        
        with self.overflow_lock:
            stats["overflow_connections"] = self.overflow_connections
        
        stats["max_pool_size"] = self.pool_size
        stats["max_overflow"] = self.max_overflow
        
        # Calculate efficiency
        total_requests = stats["pool_hits"] + stats["pool_misses"]
        if total_requests > 0:
            stats["pool_hit_rate"] = (stats["pool_hits"] / total_requests) * 100
        else:
            stats["pool_hit_rate"] = 0.0
        
        return stats
    
    def close_all(self):
        """Close all connections in pool"""
        with self.pool_lock:
            for conn in self.pool:
                try:
                    conn.close()
                    with self.stats_lock:
                        self.stats["total_closed"] += 1
                except:
                    pass
            self.pool.clear()
        
        print("✅ All connections closed")
    
    def health_check(self) -> bool:
        """Check if pool is healthy"""
        try:
            with self.get_connection() as conn:
                return self._is_connection_healthy(conn)
        except Exception:
            return False


# Background cleanup task
class PoolCleanupTask:
    """Background task to cleanup stale connections"""
    
    def __init__(self, pool: ConnectionPool, interval: int = 300):
        """
        Initialize cleanup task
        
        Args:
            pool: Connection pool to clean
            interval: Cleanup interval in seconds (default 5 minutes)
        """
        self.pool = pool
        self.interval = interval
        self.running = False
        self.thread = None
    
    def start(self):
        """Start cleanup task"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.thread.start()
        print(f"✅ Pool cleanup task started (interval: {self.interval}s)")
    
    def stop(self):
        """Stop cleanup task"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("✅ Pool cleanup task stopped")
    
    def _cleanup_loop(self):
        """Cleanup loop"""
        while self.running:
            time.sleep(self.interval)
            if self.running:
                try:
                    self.pool.cleanup_stale_connections()
                except Exception as e:
                    print(f"❌ Error in cleanup task: {e}")
