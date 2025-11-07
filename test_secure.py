"""
Test Secure Implementation - Verify Phase 1 fixes
"""
import requests
import json

def test_secure_system():
    base_url = "http://127.0.0.1:8000"
    
    print("🧪 TESTING SECURE IMPLEMENTATION")
    print("=" * 40)
    
    # Test 1: Login with secure authentication
    print("1. Testing secure login...")
    try:
        response = requests.post(f"{base_url}/auth/login", 
                               json={"username": "admin", "password": "admin123"})
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("access_token")
            print("   ✅ Secure login successful")
            print(f"   🔑 JWT Token: {token[:50]}...")
            
            # Test 2: Verify token format (should be proper JWT)
            if "." in token and len(token) > 100:
                print("   ✅ JWT format valid")
            else:
                print("   ❌ JWT format invalid")
                return False
            
            # Test 3: Use token for authenticated request
            print("\n2. Testing authenticated request...")
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.post(f"{base_url}/api/analyze",
                                   json={"input": "admin' OR '1'='1"},
                                   headers=headers)
            
            if response.status_code == 200:
                print("   ✅ Authenticated request successful")
                data = response.json()
                if "security" in data and data["security"] == "enhanced":
                    print("   ✅ Enhanced security confirmed")
                else:
                    print("   ❌ Enhanced security not confirmed")
            else:
                print(f"   ❌ Authenticated request failed: {response.status_code}")
                return False
            
            # Test 4: Security status
            print("\n3. Testing security status...")
            response = requests.get(f"{base_url}/api/security-status", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                print("   ✅ Security status accessible")
                print(f"   🔐 Authentication: {data.get('authentication')}")
                print(f"   🔒 Password Hashing: {data.get('password_hashing')}")
                print(f"   🛡️ Security Level: {data.get('security_level')}")
                
                # Verify security improvements
                if (data.get('authentication') == 'JWT + BCrypt' and 
                    data.get('password_hashing') == 'BCrypt'):
                    print("   ✅ All security improvements confirmed")
                    return True
                else:
                    print("   ❌ Security improvements not fully implemented")
                    return False
            else:
                print(f"   ❌ Security status failed: {response.status_code}")
                return False
                
        else:
            print(f"   ❌ Login failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Test error: {e}")
        return False

def test_invalid_token():
    """Test that invalid tokens are rejected"""
    print("\n4. Testing invalid token rejection...")
    base_url = "http://127.0.0.1:8000"
    
    # Test with fake token
    fake_token = "fake.jwt.token"
    headers = {"Authorization": f"Bearer {fake_token}"}
    
    try:
        response = requests.post(f"{base_url}/api/analyze",
                               json={"input": "test"},
                               headers=headers)
        
        if response.status_code == 401:
            print("   ✅ Invalid token properly rejected")
            return True
        else:
            print(f"   ❌ Invalid token not rejected: {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Test error: {e}")
        return False

if __name__ == "__main__":
    print("🔐 PHASE 1 SECURITY TEST")
    print("Testing JWT + BCrypt implementation")
    print("Make sure main_secure.py is running on port 8000")
    print()
    
    # Run tests
    test1_passed = test_secure_system()
    test2_passed = test_invalid_token()
    
    print("\n" + "=" * 40)
    print("📊 TEST RESULTS")
    print("=" * 40)
    
    if test1_passed and test2_passed:
        print("🎉 ALL TESTS PASSED!")
        print("✅ Phase 1 Stabilization: COMPLETE")
        print("🛡️ Security Level: ENHANCED")
        print("\n💡 Ready for Phase 2: Database Migration")
    else:
        print("❌ SOME TESTS FAILED")
        print("🔧 Please check implementation and try again")
    
    print("=" * 40)