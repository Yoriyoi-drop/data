#!/usr/bin/env python3
"""
Quick Start - Setup dan jalankan sistem dengan satu command
"""
import subprocess
import sys
import os
import time

def run_cmd(cmd, cwd=None):
    """Run command and return success status"""
    try:
        result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Error: {result.stderr}")
            return False
        return True
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

def check_dependencies():
    """Check if required tools are installed"""
    print("🔍 Checking dependencies...")
    
    deps = {
        "python": "python --version",
        "node": "node --version", 
        "npm": "npm --version",
        "go": "go version",
        "cargo": "cargo --version"
    }
    
    missing = []
    for name, cmd in deps.items():
        if not run_cmd(cmd):
            missing.append(name)
        else:
            print(f"✅ {name} found")
    
    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        return False
    
    return True

def install_python_deps():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    return run_cmd("pip install -r requirements.txt")

def install_node_deps():
    """Install Node.js dependencies"""
    print("📦 Installing Node.js dependencies...")
    return run_cmd("npm install", cwd="dashboard")

def install_go_deps():
    """Install Go dependencies"""
    print("📦 Installing Go dependencies...")
    return run_cmd("go mod tidy", cwd="security_engine/scanner_go")

def build_rust():
    """Build Rust project"""
    print("🦀 Building Rust project...")
    return run_cmd("cargo build", cwd="security_engine/labyrinth_rust")

def start_api_only():
    """Start only the API for quick testing"""
    print("🚀 Starting API server...")
    os.chdir("api")
    subprocess.run([sys.executable, "main.py"])

def main():
    print("🛡️ Infinite AI Security Platform - Quick Start")
    print("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        print("\n💡 Please install missing dependencies and try again")
        return
    
    # Install dependencies
    steps = [
        ("Python packages", install_python_deps),
        ("Node.js packages", install_node_deps), 
        ("Go modules", install_go_deps),
        ("Rust build", build_rust)
    ]
    
    for name, func in steps:
        print(f"\n📋 {name}...")
        if not func():
            print(f"❌ Failed to setup {name}")
            print("🔧 Try running individual setup commands manually")
            return
        print(f"✅ {name} completed")
    
    print("\n🎉 Setup completed successfully!")
    print("\n🚀 Starting API server...")
    print("📊 Dashboard will be available at: http://localhost:5173")
    print("🔌 API will be available at: http://localhost:8000")
    
    # Start API
    start_api_only()

if __name__ == "__main__":
    main()