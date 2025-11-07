#!/usr/bin/env python3
"""
Secure System Starter - Launch all components with security hardening
"""
import subprocess
import sys
import os
import time
import threading
import logging
import signal
from pathlib import Path
from typing import List, Dict
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/system_startup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SecureSystemManager:
    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}
        self.running = True
        
    def validate_environment(self) -> bool:
        """Validate system environment and dependencies"""
        logger.info("🔍 Validating environment...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            logger.error("❌ Python 3.8+ required")
            return False
        
        # Check required directories
        required_dirs = ['api', 'dashboard', 'security_engine', 'logs']
        for dir_name in required_dirs:
            if not os.path.exists(dir_name):
                logger.error(f"❌ Missing directory: {dir_name}")
                return False
        
        # Check if ports are available
        if not self.check_port_availability():
            return False
        
        logger.info("✅ Environment validation passed")
        return True
    
    def check_port_availability(self) -> bool:
        """Check if required ports are available"""
        required_ports = [8000, 5173, 8080, 3030]
        
        for port in required_ports:
            if self.is_port_in_use(port):
                logger.error(f"❌ Port {port} is already in use")
                return False
        
        logger.info("✅ All required ports are available")
        return True
    
    def is_port_in_use(self, port: int) -> bool:
        """Check if a port is in use"""
        for conn in psutil.net_connections():
            if conn.laddr.port == port:
                return True
        return False
    
    def start_component(self, name: str, cmd: List[str], cwd: str = None) -> bool:
        """Start a system component securely"""
        try:
            logger.info(f"🚀 Starting {name}...")
            
            # Set secure environment
            env = os.environ.copy()
            env['PYTHONPATH'] = os.getcwd()
            
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            self.processes[name] = process
            
            # Start output monitoring thread
            threading.Thread(
                target=self.monitor_process_output,
                args=(name, process),
                daemon=True
            ).start()
            
            # Wait a moment to check if process started successfully
            time.sleep(2)
            
            if process.poll() is None:
                logger.info(f"✅ {name} started successfully (PID: {process.pid})")
                return True
            else:
                logger.error(f"❌ {name} failed to start")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error starting {name}: {e}")
            return False
    
    def monitor_process_output(self, name: str, process: subprocess.Popen):
        """Monitor process output and log it"""
        try:
            for line in iter(process.stdout.readline, ''):
                if line.strip():
                    logger.info(f"[{name}] {line.strip()}")
        except Exception as e:
            logger.error(f"Error monitoring {name}: {e}")
    
    def start_python_api(self) -> bool:
        """Start secure Python API"""
        return self.start_component(
            "Python API",
            [sys.executable, "api/secure_main.py"],
            cwd=None
        )
    
    def start_dashboard(self) -> bool:
        """Start React dashboard"""
        return self.start_component(
            "Dashboard",
            ["npm", "run", "dev"],
            cwd="dashboard"
        )
    
    def start_go_scanner(self) -> bool:
        """Start Go security scanner"""
        return self.start_component(
            "Go Scanner",
            ["go", "run", "secure_scanner.go"],
            cwd="security_engine/scanner_go"
        )
    
    def start_rust_labyrinth(self) -> bool:
        """Start Rust labyrinth"""
        return self.start_component(
            "Rust Labyrinth",
            ["cargo", "run", "--release"],
            cwd="security_engine/labyrinth_rust"
        )
    
    def health_check(self) -> Dict[str, bool]:
        """Check health of all components"""
        health_status = {}
        
        for name, process in self.processes.items():
            if process.poll() is None:
                health_status[name] = True
            else:
                health_status[name] = False
                logger.warning(f"⚠️ {name} is not running")
        
        return health_status
    
    def stop_all(self):
        """Stop all components gracefully"""
        logger.info("🛑 Stopping all components...")
        self.running = False
        
        for name, process in self.processes.items():
            try:
                logger.info(f"Stopping {name}...")
                process.terminate()
                
                # Wait for graceful shutdown
                try:
                    process.wait(timeout=10)
                    logger.info(f"✅ {name} stopped gracefully")
                except subprocess.TimeoutExpired:
                    logger.warning(f"⚠️ Force killing {name}")
                    process.kill()
                    process.wait()
                    
            except Exception as e:
                logger.error(f"Error stopping {name}: {e}")
        
        logger.info("🏁 All components stopped")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop_all()
        sys.exit(0)
    
    def start_monitoring_loop(self):
        """Start monitoring loop for component health"""
        while self.running:
            time.sleep(30)  # Check every 30 seconds
            
            health = self.health_check()
            failed_components = [name for name, status in health.items() if not status]
            
            if failed_components:
                logger.warning(f"⚠️ Failed components: {failed_components}")
                # Could implement restart logic here
            
            # Log system stats
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            
            if cpu_percent > 80 or memory_percent > 80:
                logger.warning(f"⚠️ High resource usage - CPU: {cpu_percent}%, Memory: {memory_percent}%")

def main():
    """Main startup function"""
    print("🛡️ Infinite AI Security Platform - Secure System Startup")
    print("=" * 60)
    
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    manager = SecureSystemManager()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, manager.signal_handler)
    signal.signal(signal.SIGTERM, manager.signal_handler)
    
    try:
        # Validate environment
        if not manager.validate_environment():
            logger.error("❌ Environment validation failed")
            return 1
        
        # Start components in order
        components = [
            ("Python API", manager.start_python_api),
            ("Go Scanner", manager.start_go_scanner),
            ("Rust Labyrinth", manager.start_rust_labyrinth),
            ("Dashboard", manager.start_dashboard),
        ]
        
        failed_components = []
        
        for name, start_func in components:
            if not start_func():
                failed_components.append(name)
                logger.error(f"❌ Failed to start {name}")
            else:
                time.sleep(3)  # Stagger startup
        
        if failed_components:
            logger.error(f"❌ Failed to start: {failed_components}")
            logger.info("💡 Check logs and try starting components individually")
            return 1
        
        # All components started successfully
        logger.info("🎉 All components started successfully!")
        print("\n" + "=" * 60)
        print("🌐 Access Points:")
        print("📊 Dashboard: http://localhost:5173")
        print("🔌 API: http://localhost:8000")
        print("🔍 Go Scanner: http://localhost:8080")
        print("🦀 Rust Labyrinth: http://localhost:3030")
        print("📈 Metrics: http://localhost:8000/metrics")
        print("\n🔒 System is running in secure mode")
        print("Press Ctrl+C to stop all services...")
        print("=" * 60)
        
        # Start monitoring
        manager.start_monitoring_loop()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1
    finally:
        manager.stop_all()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())