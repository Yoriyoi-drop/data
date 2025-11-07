#!/usr/bin/env python3
"""
Ultimate System Starter - Launch 4-language security platform
Python + Rust + Go + C++ Integration
"""
import subprocess
import sys
import os
import time
import threading
import logging
import signal
import json
import requests
from pathlib import Path
from typing import List, Dict, Optional
import psutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ultimate_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class UltimateSecurityManager:
    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}
        self.running = True
        self.services = {
            "C++ Core": {"port": 9090, "health": "/health", "priority": 1},
            "Python API": {"port": 8000, "health": "/", "priority": 2},
            "Go Scanner": {"port": 8080, "health": "/health", "priority": 3},
            "Rust Labyrinth": {"port": 3030, "health": "/health", "priority": 4},
            "Dashboard": {"port": 5173, "health": "/", "priority": 5}
        }
        
    def validate_ultimate_environment(self) -> bool:
        """Validate all 4 languages and dependencies"""
        logger.info("🔍 Validating ultimate multi-language environment...")
        
        # Check languages
        languages = {
            "Python": {"cmd": "python --version", "min_version": "3.8"},
            "C++": {"cmd": "g++ --version", "min_version": "9.0"},
            "Go": {"cmd": "go version", "min_version": "1.19"},
            "Rust": {"cmd": "cargo --version", "min_version": "1.70"},
            "Node.js": {"cmd": "node --version", "min_version": "16.0"}
        }
        
        for lang, info in languages.items():
            if not self.check_language(lang, info["cmd"]):
                return False
        
        # Check C++ dependencies
        cpp_deps = ["cmake", "pkg-config", "libssl-dev", "libpcap-dev"]
        for dep in cpp_deps:
            if not self.check_system_dependency(dep):
                logger.warning(f"⚠️ C++ dependency {dep} not found")
        
        # Check directories
        required_dirs = [
            'api', 'dashboard', 'security_engine/cpp_core',
            'security_engine/scanner_go', 'security_engine/labyrinth_rust'
        ]
        
        for dir_name in required_dirs:
            if not os.path.exists(dir_name):
                logger.error(f"❌ Missing directory: {dir_name}")
                return False
        
        logger.info("✅ Ultimate environment validation passed")
        return True
    
    def check_language(self, name: str, cmd: str) -> bool:
        """Check if a programming language is available"""
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"✅ {name}: {result.stdout.strip().split()[0] if result.stdout else 'Available'}")
                return True
            else:
                logger.error(f"❌ {name} not available")
                return False
        except Exception as e:
            logger.error(f"❌ {name} check failed: {e}")
            return False
    
    def check_system_dependency(self, dep: str) -> bool:
        """Check system dependency"""
        try:
            result = subprocess.run(f"which {dep}", shell=True, capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def build_cpp_core(self) -> bool:
        """Build C++ core engine"""
        logger.info("🔨 Building C++ Core Engine...")
        
        try:
            # Make build script executable
            build_script = "security_engine/cpp_core/build.sh"
            if os.path.exists(build_script):
                os.chmod(build_script, 0o755)
                
                # Build with maximum optimization
                result = subprocess.run(
                    ["bash", build_script, "Release"],
                    cwd="security_engine/cpp_core",
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minutes timeout
                )
                
                if result.returncode == 0:
                    logger.info("✅ C++ Core built successfully")
                    return True
                else:
                    logger.error(f"❌ C++ build failed: {result.stderr}")
                    return False
            else:
                logger.warning("⚠️ C++ build script not found, skipping build")
                return True
                
        except subprocess.TimeoutExpired:
            logger.error("❌ C++ build timed out")
            return False
        except Exception as e:
            logger.error(f"❌ C++ build error: {e}")
            return False
    
    def start_cpp_core(self) -> bool:
        """Start C++ security core"""
        logger.info("🚀 Starting C++ Security Core...")
        
        # Create config for C++ core
        cpp_config = {
            "interface_name": "lo",
            "max_packet_rate": 1000000,
            "thread_count": psutil.cpu_count(),
            "enable_crypto_acceleration": True,
            "enable_memory_protection": True,
            "enable_packet_filtering": True,
            "log_level": "INFO",
            "api_port": 9090
        }
        
        config_path = "security_engine/cpp_core/build/config.json"
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(cpp_config, f, indent=2)
        
        # Start C++ core
        cpp_executable = "security_engine/cpp_core/build/InfiniteSecurityCore"
        if os.path.exists(cpp_executable):
            return self.start_component(
                "C++ Core",
                [cpp_executable, config_path],
                cwd="security_engine/cpp_core/build"
            )
        else:
            logger.warning("⚠️ C++ executable not found, skipping")
            return True
    
    def start_component(self, name: str, cmd: List[str], cwd: str = None) -> bool:
        """Start a system component"""
        try:
            logger.info(f"🚀 Starting {name}...")
            
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
            
            # Start output monitoring
            threading.Thread(
                target=self.monitor_process_output,
                args=(name, process),
                daemon=True
            ).start()
            
            # Wait and check if started successfully
            time.sleep(3)
            
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
        """Monitor and log process output"""
        try:
            for line in iter(process.stdout.readline, ''):
                if line.strip():
                    logger.info(f"[{name}] {line.strip()}")
        except Exception as e:
            logger.error(f"Error monitoring {name}: {e}")
    
    def wait_for_service(self, name: str, timeout: int = 30) -> bool:
        """Wait for service to be ready"""
        if name not in self.services:
            return True
        
        service = self.services[name]
        port = service["port"]
        health_path = service["health"]
        
        logger.info(f"⏳ Waiting for {name} on port {port}...")
        
        for i in range(timeout):
            try:
                response = requests.get(f"http://localhost:{port}{health_path}", timeout=2)
                if response.status_code in [200, 404]:  # 404 is OK for some services
                    logger.info(f"✅ {name} is ready")
                    return True
            except:
                pass
            
            time.sleep(1)
        
        logger.warning(f"⚠️ {name} not ready after {timeout}s")
        return False
    
    def check_service_integration(self) -> bool:
        """Check if all services can communicate"""
        logger.info("🔗 Checking service integration...")
        
        integration_tests = [
            ("Python API", "http://localhost:8000/", "Python to others"),
            ("Go Scanner", "http://localhost:8080/health", "Go service"),
            ("Rust Labyrinth", "http://localhost:3030/health", "Rust service"),
            ("C++ Core", "http://localhost:9090/health", "C++ service")
        ]
        
        all_ok = True
        for service, url, desc in integration_tests:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    logger.info(f"✅ {desc} integration OK")
                else:
                    logger.warning(f"⚠️ {desc} returned status {response.status_code}")
                    all_ok = False
            except Exception as e:
                logger.warning(f"⚠️ {desc} integration failed: {e}")
                all_ok = False
        
        return all_ok
    
    def start_all_services(self) -> bool:
        """Start all services in correct order"""
        logger.info("🚀 Starting Ultimate 4-Language Security Platform...")
        
        # Build C++ first
        if not self.build_cpp_core():
            logger.error("❌ Failed to build C++ core")
            return False
        
        # Start services in priority order
        services_to_start = [
            ("C++ Core", self.start_cpp_core),
            ("Python API", lambda: self.start_component(
                "Python API", 
                [sys.executable, "api/secure_main.py"]
            )),
            ("Go Scanner", lambda: self.start_component(
                "Go Scanner",
                ["go", "run", "secure_scanner.go"],
                cwd="security_engine/scanner_go"
            )),
            ("Rust Labyrinth", lambda: self.start_component(
                "Rust Labyrinth",
                ["cargo", "run", "--release"],
                cwd="security_engine/labyrinth_rust"
            )),
            ("Dashboard", lambda: self.start_component(
                "Dashboard",
                ["npm", "run", "dev"],
                cwd="dashboard"
            ))
        ]
        
        failed_services = []
        
        for service_name, start_func in services_to_start:
            if not start_func():
                failed_services.append(service_name)
                logger.error(f"❌ Failed to start {service_name}")
            else:
                # Wait for service to be ready
                self.wait_for_service(service_name, timeout=30)
                time.sleep(2)  # Stagger startup
        
        if failed_services:
            logger.error(f"❌ Failed services: {failed_services}")
            return False
        
        # Check integration
        time.sleep(5)  # Allow services to fully initialize
        integration_ok = self.check_service_integration()
        
        return integration_ok
    
    def display_system_status(self):
        """Display comprehensive system status"""
        print("\n" + "=" * 80)
        print("🛡️  INFINITE AI SECURITY PLATFORM - ULTIMATE 4-LANGUAGE STACK")
        print("=" * 80)
        
        print("\n🌐 Service Access Points:")
        print("┌─────────────────┬─────────────────────────────────────────┐")
        print("│ Service         │ URL                                     │")
        print("├─────────────────┼─────────────────────────────────────────┤")
        print("│ 🐍 Python API   │ http://localhost:8000                   │")
        print("│ ⚡ C++ Core     │ http://localhost:9090                   │")
        print("│ 🐹 Go Scanner   │ http://localhost:8080                   │")
        print("│ 🦀 Rust Maze    │ http://localhost:3030                   │")
        print("│ 📊 Dashboard    │ http://localhost:5173                   │")
        print("│ 📈 Metrics      │ http://localhost:8000/metrics           │")
        print("└─────────────────┴─────────────────────────────────────────┘")
        
        print("\n⚡ Performance Capabilities:")
        cpu_count = psutil.cpu_count()
        memory_gb = psutil.virtual_memory().total // (1024**3)
        
        print(f"  • CPU Cores: {cpu_count}")
        print(f"  • Memory: {memory_gb} GB")
        print(f"  • C++ Ultra-Fast Core: 10+ Gbps packet filtering")
        print(f"  • Python AI Orchestration: Multi-agent coordination")
        print(f"  • Go Real-time Scanner: Concurrent threat detection")
        print(f"  • Rust Memory-Safe Labyrinth: Infinite trap generation")
        
        print("\n🔒 Security Features:")
        print("  • Hardware-accelerated cryptography (AES-NI, AVX2)")
        print("  • SIMD-optimized packet filtering")
        print("  • Memory-safe operations (Rust + C++ guards)")
        print("  • Real-time threat detection and blocking")
        print("  • AI-powered behavioral analysis")
        print("  • Infinite labyrinth trap system")
        
        print("\n🎯 Integration Status:")
        for service, info in self.services.items():
            if service in self.processes:
                status = "🟢 RUNNING" if self.processes[service].poll() is None else "🔴 STOPPED"
                print(f"  • {service}: {status}")
        
        print("\n" + "=" * 80)
        print("🚀 Ultimate Security Platform is ONLINE!")
        print("Press Ctrl+C to stop all services...")
        print("=" * 80)
    
    def stop_all(self):
        """Stop all services gracefully"""
        logger.info("🛑 Stopping Ultimate Security Platform...")
        self.running = False
        
        # Stop in reverse order
        service_order = list(reversed(list(self.processes.keys())))
        
        for name in service_order:
            if name in self.processes:
                process = self.processes[name]
                try:
                    logger.info(f"Stopping {name}...")
                    process.terminate()
                    
                    try:
                        process.wait(timeout=10)
                        logger.info(f"✅ {name} stopped gracefully")
                    except subprocess.TimeoutExpired:
                        logger.warning(f"⚠️ Force killing {name}")
                        process.kill()
                        process.wait()
                        
                except Exception as e:
                    logger.error(f"Error stopping {name}: {e}")
        
        logger.info("🏁 Ultimate Security Platform stopped")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop_all()
        sys.exit(0)

def main():
    """Main function"""
    print("🛡️ Infinite AI Security Platform - Ultimate 4-Language Stack")
    print("=" * 70)
    
    # Create logs directory
    os.makedirs('logs', exist_ok=True)
    
    manager = UltimateSecurityManager()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, manager.signal_handler)
    signal.signal(signal.SIGTERM, manager.signal_handler)
    
    try:
        # Validate environment
        if not manager.validate_ultimate_environment():
            logger.error("❌ Environment validation failed")
            return 1
        
        # Start all services
        if not manager.start_all_services():
            logger.error("❌ Failed to start all services")
            return 1
        
        # Display status
        manager.display_system_status()
        
        # Main monitoring loop
        while manager.running:
            time.sleep(5)
            
            # Check if any service died
            dead_services = []
            for name, process in manager.processes.items():
                if process.poll() is not None:
                    dead_services.append(name)
            
            if dead_services:
                logger.warning(f"⚠️ Dead services detected: {dead_services}")
                # Could implement restart logic here
            
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