"""
Production Deployment Script - One-click deployment
"""
import os
import subprocess
import sys
from pathlib import Path

def check_prerequisites():
    """Check if all prerequisites are met"""
    print("🔍 Checking prerequisites...")
    
    required_tools = ["docker", "docker-compose"]
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.run([tool, "--version"], capture_output=True, check=True)
            print(f"  ✅ {tool} installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_tools.append(tool)
            print(f"  ❌ {tool} not found")
    
    if missing_tools:
        print(f"\n❌ Missing tools: {', '.join(missing_tools)}")
        print("Please install Docker and Docker Compose first.")
        return False
    
    return True

def setup_environment():
    """Setup production environment"""
    print("\n🔧 Setting up environment...")
    
    env_file = Path(".env")
    env_template = Path(".env.production")
    
    if not env_template.exists():
        print("❌ .env.production template not found")
        print("Run 'python phase3_production.py' first to create templates")
        return False
    
    if not env_file.exists():
        print("  📝 Creating .env from template...")
        import shutil
        shutil.copy(env_template, env_file)
        
        print("  ⚠️  IMPORTANT: Edit .env file with your production values!")
        print("     - Change default passwords")
        print("     - Add your API keys")
        print("     - Set your domain name")
        
        response = input("\n  Have you updated .env with production values? (y/N): ")
        if response.lower() != 'y':
            print("  ❌ Please update .env file first")
            return False
    
    print("  ✅ Environment configured")
    return True

def build_and_deploy():
    """Build and deploy the application"""
    print("\n🚀 Building and deploying...")
    
    try:
        # Build images
        print("  📦 Building Docker images...")
        subprocess.run([
            "docker-compose", "-f", "docker-compose.prod.yml", "build"
        ], check=True)
        
        # Start services
        print("  🔄 Starting services...")
        subprocess.run([
            "docker-compose", "-f", "docker-compose.prod.yml", "up", "-d"
        ], check=True)
        
        print("  ✅ Deployment completed")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Deployment failed: {e}")
        return False

def verify_deployment():
    """Verify deployment is working"""
    print("\n🔍 Verifying deployment...")
    
    import time
    import requests
    
    # Wait for services to start
    print("  ⏳ Waiting for services to start...")
    time.sleep(10)
    
    # Check health endpoint
    try:
        response = requests.get("http://localhost/health", timeout=10)
        if response.status_code == 200:
            print("  ✅ Health check passed")
            return True
        else:
            print(f"  ❌ Health check failed: HTTP {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"  ❌ Health check failed: {e}")
        return False

def show_deployment_info():
    """Show deployment information"""
    print("\n🎉 DEPLOYMENT SUCCESSFUL!")
    print("=" * 50)
    print("📊 Application URLs:")
    print("   🌐 Main App: http://localhost")
    print("   ❤️  Health: http://localhost/health")
    print("   📈 Metrics: http://localhost:9090 (Prometheus)")
    print("   📊 Dashboard: http://localhost:3000 (Grafana)")
    print()
    print("🔐 Default Credentials:")
    print("   App: admin/admin123")
    print("   Grafana: admin/admin")
    print()
    print("📋 Management Commands:")
    print("   View logs: docker-compose -f docker-compose.prod.yml logs -f")
    print("   Stop: docker-compose -f docker-compose.prod.yml down")
    print("   Restart: docker-compose -f docker-compose.prod.yml restart")
    print()
    print("⚠️  SECURITY REMINDERS:")
    print("   - Change default passwords")
    print("   - Setup SSL certificates")
    print("   - Configure firewall")
    print("   - Enable monitoring alerts")

def main():
    """Main deployment function"""
    print("🚀 INFINITE AI SECURITY - PRODUCTION DEPLOYMENT")
    print("=" * 60)
    
    # Step 1: Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Step 2: Setup environment
    if not setup_environment():
        sys.exit(1)
    
    # Step 3: Build and deploy
    if not build_and_deploy():
        print("\n❌ Deployment failed!")
        print("Check logs: docker-compose -f docker-compose.prod.yml logs")
        sys.exit(1)
    
    # Step 4: Verify deployment
    if not verify_deployment():
        print("\n⚠️  Deployment completed but verification failed")
        print("Check if services are starting: docker-compose -f docker-compose.prod.yml ps")
    else:
        show_deployment_info()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Deployment cancelled by user")
    except Exception as e:
        print(f"\n❌ Deployment error: {e}")
        sys.exit(1)