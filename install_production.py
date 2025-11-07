"""
Production Installation Script
Installs all required libraries and sets up the environment
"""
import subprocess
import sys
import os
from pathlib import Path

def run_command(command):
    """Run shell command and handle errors"""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {command}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {command}")
        print(f"Error: {e.stderr}")
        return False

def install_requirements():
    """Install all required packages"""
    print("🚀 Installing Production Dependencies...")
    
    # Essential packages
    packages = [
        "fastapi==0.115.6",
        "uvicorn[standard]==0.32.1", 
        "pydantic==2.10.3",
        "cryptography==42.0.8",
        "python-jose[cryptography]==3.3.0",
        "passlib[bcrypt]==1.7.4",
        "bcrypt==4.2.1",
        "sqlalchemy==2.0.36",
        "databases[postgresql]==0.9.0",
        "asyncpg==0.30.0",
        "redis==5.2.1",
        "scikit-learn==1.6.0",
        "numpy==2.2.0",
        "prometheus-client==0.21.1",
        "structlog==24.5.0",
        "slowapi==0.1.9",
        "python-dotenv==1.0.1"
    ]
    
    success_count = 0
    for package in packages:
        if run_command(f"pip install {package}"):
            success_count += 1
    
    print(f"\n📊 Installation Summary: {success_count}/{len(packages)} packages installed")
    return success_count == len(packages)

def setup_environment():
    """Setup environment files"""
    print("\n🔧 Setting up environment...")
    
    env_file = Path(".env")
    if not env_file.exists():
        env_example = Path(".env.example")
        if env_example.exists():
            env_file.write_text(env_example.read_text())
            print("✅ Created .env file from template")
        else:
            print("❌ .env.example not found")
            return False
    else:
        print("✅ .env file already exists")
    
    return True

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        "logs",
        "data",
        "backups",
        "certificates"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created {directory}/ directory")
    
    return True

def test_installation():
    """Test if installation works"""
    print("\n🧪 Testing installation...")
    
    try:
        # Test imports
        import fastapi
        import uvicorn
        import cryptography
        import jose
        import passlib
        import sqlalchemy
        import redis
        import sklearn
        import numpy
        import prometheus_client
        import structlog
        import slowapi
        import dotenv
        
        print("✅ All imports successful")
        
        # Test FastAPI creation
        from fastapi import FastAPI
        app = FastAPI()
        print("✅ FastAPI app creation successful")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Test error: {e}")
        return False

def main():
    """Main installation process"""
    print("🛡️ Infinite AI Security - Production Setup")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ required")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Install packages
    if not install_requirements():
        print("❌ Package installation failed")
        return False
    
    # Setup environment
    if not setup_environment():
        print("❌ Environment setup failed")
        return False
    
    # Create directories
    if not create_directories():
        print("❌ Directory creation failed")
        return False
    
    # Test installation
    if not test_installation():
        print("❌ Installation test failed")
        return False
    
    print("\n🎉 Production setup completed successfully!")
    print("\nNext steps:")
    print("1. Edit .env file with your configuration")
    print("2. Run: python api/main_production.py")
    print("3. Visit: http://127.0.0.1:8080/docs")
    print("4. Login with: admin/admin123")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)