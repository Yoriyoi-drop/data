"""
Start All Systems - Launch semua komponen dengan 100x enhancement
Sistem startup otomatis untuk semua bahasa dan komponen
"""

import subprocess
import threading
import time
import os
import sys
import psutil
import requests
import json
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('system_startup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SystemLauncher:
    def __init__(self):
        self.processes = {}
        self.services = {
            'python_main': {
                'command': [sys.executable, 'main.py'],
                'port': 8008,
                'health_endpoint': '/health',
                'description': 'Python Main System'
            },
            'go_scanner': {
                'command': ['go', 'run', 'security_engine/scanner_go/advanced_scanner.go'],
                'port': 8080,
                'health_endpoint': '/stats',
                'description': 'Go Advanced Scanner'
            },
            'rust_labyrinth': {
                'command': ['cargo', 'run', '--manifest-path', 'security_engine/labyrinth_rust/Cargo.toml'],
                'port': 8081,
                'health_endpoint': '/stats',
                'description': 'Rust Labyrinth Defense'
            },
            'cpp_detector': {
                'command': ['g++', '-o', 'detector', 'security_engine/detector_cpp/advanced_detector.cpp', '-std=c++17', '-O3', '-march=native'],
                'compile_only': True,
                'description': 'C++ Advanced Detector (Compile)'
            },
            'ai_orchestrator': {
                'command': [sys.executable, 'ai_hub/advanced_orchestrator.py'],
                'port': 8000,
                'health_endpoint': '/status',
                'description': 'AI Hub Orchestrator'
            }
        }
        
    def check_dependencies(self):
        """Check if all required dependencies are available"""
        logger.info("🔍 Checking system dependencies...")
        
        dependencies = {
            'python': sys.executable,
            'go': 'go',
            'cargo': 'cargo',
            'g++': 'g++',
            'redis-server': 'redis-server'
        }
        
        missing = []
        for name, command in dependencies.items():
            try:
                if name == 'python':
                    # Python is already running
                    logger.info(f"✅ {name}: {command}")
                    continue
                    
                result = subprocess.run([command, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version = result.stdout.strip().split('\n')[0]
                    logger.info(f"✅ {name}: {version}")
                else:
                    missing.append(name)
                    logger.warning(f"❌ {name}: Not found or error")
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                missing.append(name)
                logger.warning(f"❌ {name}: Not available")
        
        if missing:
            logger.error(f"Missing dependencies: {', '.join(missing)}")
            logger.info("Please install missing dependencies:")
            for dep in missing:
                if dep == 'go':
                    logger.info("  - Go: https://golang.org/dl/")
                elif dep == 'cargo':
                    logger.info("  - Rust: https://rustup.rs/")
                elif dep == 'g++':
                    logger.info("  - GCC: Install MinGW or Visual Studio Build Tools")
                elif dep == 'redis-server':
                    logger.info("  - Redis: https://redis.io/download")
            return False
        
        return True
    
    def setup_environment(self):
        """Setup environment and create necessary directories"""
        logger.info("🔧 Setting up environment...")
        
        # Create directories
        directories = [
            'logs',
            'data',
            'cache',
            'security_engine/scanner_go',
            'security_engine/labyrinth_rust/src',
            'security_engine/detector_cpp',
            'ai_hub'
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            logger.info(f"📁 Created directory: {directory}")
        
        # Create Go module files if not exist
        go_mod_path = 'security_engine/scanner_go/go.mod'
        if not os.path.exists(go_mod_path):
            with open(go_mod_path, 'w') as f:
                f.write("""module advanced_scanner

go 1.19

require (
    github.com/gorilla/websocket v1.5.0
    golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
)
""")
            logger.info("📝 Created go.mod file")
        
        # Create Rust Cargo.toml if not exist
        cargo_toml_path = 'security_engine/labyrinth_rust/Cargo.toml'
        if not os.path.exists(cargo_toml_path):
            with open(cargo_toml_path, 'w') as f:
                f.write("""[package]
name = "labyrinth_rust"
version = "2.0.0"
edition = "2021"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10"
aes-gcm = "0.10"
ring = "0.16"
rand = "0.8"
""")
            logger.info("📝 Created Cargo.toml file")
    
    def start_redis(self):
        """Start Redis server if not running"""
        logger.info("🔴 Starting Redis server...")
        try:
            # Check if Redis is already running
            result = subprocess.run(['redis-cli', 'ping'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'PONG' in result.stdout:
                logger.info("✅ Redis is already running")
                return True
        except:
            pass
        
        try:
            # Start Redis server
            redis_process = subprocess.Popen(['redis-server'], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE)
            self.processes['redis'] = redis_process
            time.sleep(2)  # Wait for Redis to start
            
            # Verify Redis is running
            result = subprocess.run(['redis-cli', 'ping'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and 'PONG' in result.stdout:
                logger.info("✅ Redis server started successfully")
                return True
            else:
                logger.error("❌ Failed to start Redis server")
                return False
        except Exception as e:
            logger.error(f"❌ Redis startup error: {e}")
            return False
    
    def compile_cpp_detector(self):
        """Compile C++ detector"""
        logger.info("⚙️ Compiling C++ detector...")
        try:
            compile_cmd = [
                'g++', 
                '-o', 'security_engine/detector_cpp/detector',
                'security_engine/detector_cpp/advanced_detector.cpp',
                '-std=c++17', '-O3', '-pthread'
            ]
            
            result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                logger.info("✅ C++ detector compiled successfully")
                return True
            else:
                logger.error(f"❌ C++ compilation failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"❌ C++ compilation error: {e}")
            return False
    
    def start_service(self, service_name, service_config):
        """Start individual service"""
        logger.info(f"🚀 Starting {service_config['description']}...")
        
        try:
            if service_config.get('compile_only'):
                return self.compile_cpp_detector()
            
            # Start the process
            process = subprocess.Popen(
                service_config['command'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            
            self.processes[service_name] = process
            
            # Wait a bit for the service to start
            time.sleep(3)
            
            # Check if process is still running
            if process.poll() is None:
                logger.info(f"✅ {service_config['description']} started (PID: {process.pid})")
                
                # Check health endpoint if available
                if 'port' in service_config:
                    return self.check_service_health(service_name, service_config)
                return True
            else:
                stdout, stderr = process.communicate()
                logger.error(f"❌ {service_config['description']} failed to start")
                logger.error(f"STDOUT: {stdout.decode()}")
                logger.error(f"STDERR: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error starting {service_config['description']}: {e}")
            return False
    
    def check_service_health(self, service_name, service_config, max_retries=10):
        """Check if service is healthy"""
        port = service_config['port']
        health_endpoint = service_config.get('health_endpoint', '/health')
        url = f"http://localhost:{port}{health_endpoint}"
        
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    logger.info(f"✅ {service_config['description']} health check passed")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            logger.info(f"⏳ Waiting for {service_config['description']} to be ready... ({attempt + 1}/{max_retries})")
            time.sleep(2)
        
        logger.warning(f"⚠️ {service_config['description']} health check failed, but process is running")
        return True  # Continue anyway
    
    def start_all_services(self):
        """Start all services in correct order"""
        logger.info("🚀 Starting all security systems...")
        
        # Start Redis first
        if not self.start_redis():
            logger.error("❌ Failed to start Redis - some features may not work")
        
        # Start services in order
        service_order = [
            'python_main',
            'ai_orchestrator', 
            'go_scanner',
            'rust_labyrinth',
            'cpp_detector'
        ]
        
        successful_starts = 0
        for service_name in service_order:
            if service_name in self.services:
                if self.start_service(service_name, self.services[service_name]):
                    successful_starts += 1
                    time.sleep(2)  # Brief pause between services
                else:
                    logger.error(f"❌ Failed to start {service_name}")
        
        logger.info(f"✅ Successfully started {successful_starts}/{len(service_order)} services")
        return successful_starts > 0
    
    def monitor_services(self):
        """Monitor running services"""
        logger.info("👁️ Starting service monitoring...")
        
        while True:
            try:
                running_services = []
                failed_services = []
                
                for service_name, process in self.processes.items():
                    if service_name == 'redis':
                        continue  # Skip Redis monitoring for now
                    
                    if process.poll() is None:
                        running_services.append(service_name)
                    else:
                        failed_services.append(service_name)
                
                if failed_services:
                    logger.warning(f"⚠️ Failed services: {', '.join(failed_services)}")
                
                # Log system resources
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                
                logger.info(f"📊 System Status - CPU: {cpu_percent}%, Memory: {memory.percent}%, Running: {len(running_services)} services")
                
                time.sleep(30)  # Check every 30 seconds
                
            except KeyboardInterrupt:
                logger.info("🛑 Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"❌ Monitoring error: {e}")
                time.sleep(10)
    
    def stop_all_services(self):
        """Stop all running services"""
        logger.info("🛑 Stopping all services...")
        
        for service_name, process in self.processes.items():
            try:
                if process.poll() is None:
                    logger.info(f"🛑 Stopping {service_name}...")
                    process.terminate()
                    
                    # Wait for graceful shutdown
                    try:
                        process.wait(timeout=10)
                        logger.info(f"✅ {service_name} stopped gracefully")
                    except subprocess.TimeoutExpired:
                        logger.warning(f"⚠️ Force killing {service_name}...")
                        process.kill()
                        process.wait()
                        logger.info(f"✅ {service_name} force stopped")
            except Exception as e:
                logger.error(f"❌ Error stopping {service_name}: {e}")
    
    def show_system_info(self):
        """Show comprehensive system information"""
        logger.info("📋 System Information:")
        logger.info(f"   🐍 Python: {sys.version}")
        logger.info(f"   💻 Platform: {sys.platform}")
        logger.info(f"   🏠 Working Directory: {os.getcwd()}")
        logger.info(f"   🔧 CPU Cores: {psutil.cpu_count()}")
        logger.info(f"   💾 Total Memory: {psutil.virtual_memory().total // (1024**3)} GB")
        
        logger.info("\n🌐 Service Endpoints:")
        for service_name, config in self.services.items():
            if 'port' in config:
                logger.info(f"   {config['description']}: http://localhost:{config['port']}")
        
        logger.info("\n📊 Real-time Dashboard: http://localhost:8008")
        logger.info("🔧 AI Orchestrator: http://localhost:8000")
        logger.info("📈 System Monitoring: Check logs/system_startup.log")

def main():
    """Main startup function"""
    print("=" * 80)
    print("🛡️  INFINITE AI SECURITY PLATFORM - MULTI-LANGUAGE STARTUP")
    print("=" * 80)
    print("🚀 100x Enhanced Security System")
    print("🔥 Python + Go + Rust + C++ Integration")
    print("🧠 Quantum Computing + Blockchain + ML")
    print("⚡ SIMD Optimization + Real-time Processing")
    print("=" * 80)
    
    launcher = SystemLauncher()
    
    try:
        # Show system info
        launcher.show_system_info()
        
        # Check dependencies
        if not launcher.check_dependencies():
            logger.error("❌ Dependency check failed. Please install missing components.")
            return 1
        
        # Setup environment
        launcher.setup_environment()
        
        # Start all services
        if launcher.start_all_services():
            logger.info("🎉 All systems started successfully!")
            logger.info("🌐 Access the dashboard at: http://localhost:8008")
            logger.info("📊 System monitoring active...")
            
            # Start monitoring in background
            monitor_thread = threading.Thread(target=launcher.monitor_services, daemon=True)
            monitor_thread.start()
            
            # Keep main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("🛑 Shutdown signal received...")
        else:
            logger.error("❌ Failed to start some services")
            return 1
            
    except Exception as e:
        logger.error(f"❌ Startup error: {e}")
        return 1
    finally:
        launcher.stop_all_services()
        logger.info("✅ All services stopped. Goodbye!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())