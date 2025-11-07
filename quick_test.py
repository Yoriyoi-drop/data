#!/usr/bin/env python3
"""
Quick test script untuk memastikan sistem berjalan
"""
import requests
import json
import time

def test_endpoints():
    base_url = "http://localhost:8000"
    
    print("\n" + "="*50)
    print("🧪 QUICK SYSTEM TEST")
    print("="*50)
    
    # Test 1: Root endpoint
    print("1️⃣ Testing root endpoint...")
    try:
        response = requests.get(f"{base_url}/")
        if response.status_code == 200:
            print("   ✅ Root endpoint: OK")
            print(f"   📄 Response: {response.json()}")
        else:
            print(f"   ❌ Root endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Connection error: {e}")
        print("   💡 Make sure server is running: python start_server.py")
        return
    
    # Test 2: Health check
    print("\n2️⃣ Testing health endpoint...")
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            print("   ✅ Health check: OK")
            data = response.json()
            print(f"   🤖 Agents online: {data.get('agents_online', 0)}")
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Health check error: {e}")
    
    # Test 3: Agents status
    print("\n3️⃣ Testing agents endpoint...")
    try:
        response = requests.get(f"{base_url}/api/agents/status")
        if response.status_code == 200:
            print("   ✅ Agents endpoint: OK")
            data = response.json()
            print(f"   🤖 Active agents: {len(data.get('agents', {}))}")
        else:
            print(f"   ❌ Agents endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Agents endpoint error: {e}")
    
    # Test 4: Dashboard data
    print("\n4️⃣ Testing dashboard endpoint...")
    try:
        response = requests.get(f"{base_url}/api/dashboard/data")
        if response.status_code == 200:
            print("   ✅ Dashboard endpoint: OK")
            data = response.json()
            print(f"   📊 Total agents: {data.get('agents', {}).get('total', 0)}")
            print(f"   🛡️ Threats processed: {data.get('threats', {}).get('total', 0)}")
        else:
            print(f"   ❌ Dashboard endpoint failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Dashboard endpoint error: {e}")
    
    print("\n" + "="*50)
    print("✅ SYSTEM TEST COMPLETE")
    print("🌐 Access dashboard at: http://localhost:8000")
    print("📚 API docs at: http://localhost:8000/docs")
    print("="*50 + "\n")

if __name__ == "__main__":
    test_endpoints()