#!/usr/bin/env python3
"""
System Test - Test semua komponen sistem
"""
import requests
import json
import time

def test_api():
    """Test API endpoints"""
    print("🔌 Testing API...")
    
    try:
        # Test root endpoint
        response = requests.get('http://localhost:8000/')
        if response.status_code == 200:
            print("✅ API root endpoint working")
        else:
            print("❌ API root endpoint failed")
            return False
            
        # Test agents status
        response = requests.get('http://localhost:8000/api/agents/status')
        if response.status_code == 200:
            agents = response.json()
            print(f"✅ Agents endpoint working - {len(agents)} agents found")
        else:
            print("❌ Agents endpoint failed")
            
        # Test threat analysis
        threat_data = {
            "type": "SQL Injection",
            "severity": "high",
            "source": "192.168.1.100"
        }
        response = requests.post('http://localhost:8000/api/threats/analyze', json=threat_data)
        if response.status_code == 200:
            print("✅ Threat analysis endpoint working")
        else:
            print("❌ Threat analysis endpoint failed")
            
        return True
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to API - is it running?")
        return False
    except Exception as e:
        print(f"❌ API test error: {e}")
        return False

def test_go_scanner():
    """Test Go scanner"""
    print("🔍 Testing Go Scanner...")
    
    try:
        response = requests.get('http://localhost:8080/health')
        if response.status_code == 200:
            print("✅ Go Scanner working")
            return True
        else:
            print("❌ Go Scanner health check failed")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Go Scanner - is it running?")
        return False
    except Exception as e:
        print(f"❌ Go Scanner test error: {e}")
        return False

def test_dashboard():
    """Test dashboard availability"""
    print("📊 Testing Dashboard...")
    
    try:
        response = requests.get('http://localhost:5173/')
        if response.status_code == 200:
            print("✅ Dashboard accessible")
            return True
        else:
            print("❌ Dashboard not accessible")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to Dashboard - is it running?")
        return False
    except Exception as e:
        print(f"❌ Dashboard test error: {e}")
        return False

def main():
    print("🛡️ Infinite AI Security Platform - System Test")
    print("=" * 50)
    
    tests = [
        ("API Server", test_api),
        ("Go Scanner", test_go_scanner), 
        ("Dashboard", test_dashboard)
    ]
    
    results = {}
    
    for name, test_func in tests:
        print(f"\n🧪 Testing {name}...")
        results[name] = test_func()
        time.sleep(1)
    
    print("\n📋 Test Results:")
    print("=" * 30)
    
    all_passed = True
    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{name}: {status}")
        if not passed:
            all_passed = False
    
    if all_passed:
        print("\n🎉 All tests passed! System is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Check the components and try again.")
        print("\n💡 Make sure all services are running:")
        print("   - python api/main.py")
        print("   - cd dashboard && npm run dev") 
        print("   - cd security_engine/scanner_go && go run scanner.go")

if __name__ == "__main__":
    main()