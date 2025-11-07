#!/usr/bin/env python3
"""
Installation script for Infinite AI Security Platform
"""
import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} - Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - Failed: {e.stderr}")
        return False

def main():
    print("\n" + "="*60)
    print("🚀 INFINITE AI SECURITY - INSTALLATION")
    print("="*60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        return 1
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Install core dependencies
    core_packages = [
        "fastapi>=0.100.0",
        "uvicorn[standard]>=0.20.0", 
        "pydantic>=2.0.0",
        "python-multipart",
        "websockets",
        "aiofiles",
        "requests",
        "python-jose[cryptography]",
        "passlib[bcrypt]"
    ]
    
    print("\n📦 Installing core packages...")
    for package in core_packages:
        if not run_command(f"pip install {package}", f"Installing {package}"):
            print(f"⚠️  Failed to install {package}, continuing...")
    
    # Create necessary directories
    directories = [
        "logs",
        "data", 
        "temp",
        "uploads"
    ]
    
    print("\n📁 Creating directories...")
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created {directory}/")
    
    # Create environment file
    if not os.path.exists(".env"):
        print("\n🔧 Creating environment file...")
        with open(".env", "w") as f:
            f.write("JWT_SECRET_KEY=dev-secret-change-in-production\n")
            f.write("DEBUG=true\n")
            f.write("LOG_LEVEL=INFO\n")
        print("✅ Created .env file")
    
    print("\n" + "="*60)
    print("✅ INSTALLATION COMPLETE!")
    print("="*60)
    print("🚀 To start the system:")
    print("   python run_system.py")
    print("\n🧪 To test the system:")
    print("   python quick_test.py")
    print("="*60 + "\n")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())