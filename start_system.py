#!/usr/bin/env python3
"""
System Starter - Launch semua komponen Infinite AI Security Platform
"""
import subprocess
import sys
import os
import time
import threading
from pathlib import Path

def run_command(cmd, cwd=None, name="Process"):
    """Run command in subprocess"""
    try:
        print(f"🚀 Starting {name}...")
        process = subprocess.Popen(
            cmd, 
            shell=True, 
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        
        # Print output in real-time
        for line in iter(process.stdout.readline, ''):
            print(f"[{name}] {line.strip()}")
            
        process.wait()
        
    except Exception as e:
        print(f"❌ Error starting {name}: {e}")

def start_api():
    """Start FastAPI backend"""
    os.chdir("api")
    run_command("python main.py", name="API")

def start_dashboard():
    """Start React dashboard"""
    os.chdir("dashboard")
    run_command("npm run dev", name="Dashboard")

def start_go_scanner():
    """Start Go security scanner"""
    os.chdir("security_engine/scanner_go")
    run_command("go run scanner.go", name="Go Scanner")

def start_rust_labyrinth():
    """Start Rust labyrinth"""
    os.chdir("security_engine/labyrinth_rust")
    run_command("cargo run", name="Rust Labyrinth")

def main():
    print("🛡️ Infinite AI Security Platform - System Startup")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists("api/main.py"):
        print("❌ Please run this script from the project root directory")
        sys.exit(1)
    
    # Start all components in separate threads
    components = [
        ("API Server", start_api),
        ("Dashboard", start_dashboard),
        ("Go Scanner", start_go_scanner),
        ("Rust Labyrinth", start_rust_labyrinth)
    ]
    
    threads = []
    
    for name, func in components:
        thread = threading.Thread(target=func, daemon=True)
        thread.start()
        threads.append(thread)
        time.sleep(2)  # Stagger startup
    
    print("\n🎯 All components started!")
    print("📊 Dashboard: http://localhost:5173")
    print("🔌 API: http://localhost:8000")
    print("🔍 Scanner: http://localhost:8080")
    print("\nPress Ctrl+C to stop all services...")
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down all services...")
        sys.exit(0)

if __name__ == "__main__":
    main()