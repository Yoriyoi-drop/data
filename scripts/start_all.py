#!/usr/bin/env python3
"""
Start All Services - One-click startup untuk PoC
"""
import subprocess
import sys
import time
import os
import signal
from pathlib import Path

class ServiceManager:
    def __init__(self):
        self.processes = []
        self.root_dir = Path(__file__).parent.parent
        
    def run_service(self, name, cmd, cwd=None, wait=2):
        """Start service dan track process"""
        print(f"🚀 Starting {name}...")
        
        if cwd:
            full_cwd = self.root_dir / cwd
        else:
            full_cwd = self.root_dir
            
        try:
            if sys.platform == "win32":
                proc = subprocess.Popen(cmd, shell=True, cwd=full_cwd, 
                                      creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            else:
                proc = subprocess.Popen(cmd, shell=True, cwd=full_cwd)
                
            self.processes.append((name, proc))
            print(f"✅ {name} started (PID: {proc.pid})")
            time.sleep(wait)
            return True
            
        except Exception as e:
            print(f"❌ Failed to start {name}: {e}")
            return False
    
    def check_dependencies(self):
        """Check if required tools are installed"""
        deps = {
            "python": "python --version",
            "node": "node --version", 
            "go": "go version",
            "cargo": "cargo --version"
        }
        
        missing = []
        for tool, cmd in deps.items():
            try:
                subprocess.run(cmd, shell=True, check=True, 
                             capture_output=True, text=True)
                print(f"✅ {tool} available")
            except:
                missing.append(tool)
                print(f"❌ {tool} not found")
        
        return len(missing) == 0
    
    def start_all(self):
        """Start semua services dalam urutan yang benar"""
        print("🛡️  Starting Infinite AI Security Platform...")
        
        if not self.check_dependencies():
            print("❌ Missing dependencies. Please install required tools.")
            return False
        
        # 1. Install dependencies
        print("\n📦 Installing dependencies...")
        subprocess.run("pip install -r requirements.txt", shell=True, cwd=self.root_dir)
        
        if (self.root_dir / "dashboard" / "node_modules").exists():
            print("✅ Node modules already installed")
        else:
            subprocess.run("npm install", shell=True, cwd=self.root_dir / "dashboard")
        
        # 2. Start Go Scanner
        self.run_service("Go Scanner", "go run scanner.go", "security_engine/scanner_go", 3)
        
        # 3. Start Rust Labyrinth  
        self.run_service("Rust Labyrinth", "cargo run", "security_engine/labyrinth_rust", 3)
        
        # 4. Start API
        self.run_service("FastAPI", "python api/main.py", wait=3)
        
        # 5. Start Dashboard
        self.run_service("Dashboard", "npm run dev", "dashboard", 3)
        
        print("\n🎉 All services started!")
        print("📊 Dashboard: http://localhost:3000")
        print("🔌 API: http://localhost:8000")
        print("🛡️  Scanner: http://localhost:8080")
        
        return True
    
    def stop_all(self):
        """Stop semua services"""
        print("\n🛑 Stopping all services...")
        for name, proc in self.processes:
            try:
                if sys.platform == "win32":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.terminate()
                print(f"✅ Stopped {name}")
            except:
                print(f"❌ Failed to stop {name}")
    
    def run_demo(self):
        """Run automated demo"""
        print("\n🎬 Running automated demo...")
        time.sleep(5)  # Wait for services to be ready
        
        # Run simulation
        try:
            subprocess.run("python scripts/run_simulation.py", shell=True, cwd=self.root_dir)
            print("✅ Demo simulation completed")
        except Exception as e:
            print(f"❌ Demo failed: {e}")

def main():
    manager = ServiceManager()
    
    try:
        if manager.start_all():
            print("\n⏳ Services running... Press Ctrl+C to stop")
            
            # Run demo after startup
            manager.run_demo()
            
            # Keep running
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested...")
    finally:
        manager.stop_all()

if __name__ == "__main__":
    main()