#!/usr/bin/env python3
"""
Test script to verify credentials and blocking fixes
"""

import sys
import subprocess
import os

def test_sudo_access():
    """Test if sudo access works"""
    print("🔐 Testing Sudo Access...")
    
    try:
        # Test basic sudo access
        result = subprocess.run(['sudo', '-n', 'whoami'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and 'root' in result.stdout:
            print("✅ Sudo access works (password cached)")
            return True
        else:
            print("⚠️ Sudo access requires password")
            return False
            
    except Exception as e:
        print(f"❌ Sudo test failed: {e}")
        return False

def test_credentials_verification():
    """Test credentials verification"""
    print("\n🔑 Testing Credentials Verification...")
    
    try:
        from nimda_tkinter import PrivilegeManager
        
        pm = PrivilegeManager()
        
        # Test with wrong password
        wrong_password = "wrong_password"
        result = pm.verify_credentials(wrong_password)
        
        if not result:
            print("✅ Wrong password correctly rejected")
        else:
            print("❌ Wrong password was accepted")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Credentials test failed: {e}")
        return False

def test_firewall_commands():
    """Test firewall commands"""
    print("\n🛡️ Testing Firewall Commands...")
    
    try:
        # Test pfctl status
        result = subprocess.run(['sudo', '-n', 'pfctl', '-s', 'info'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✅ Firewall commands work")
            return True
        else:
            print("⚠️ Firewall commands require privileges")
            return False
            
    except Exception as e:
        print(f"❌ Firewall test failed: {e}")
        return False

def test_privilege_manager():
    """Test PrivilegeManager functionality"""
    print("\n👤 Testing PrivilegeManager...")
    
    try:
        from nimda_tkinter import PrivilegeManager
        
        pm = PrivilegeManager()
        
        # Check current user
        current_user = os.getenv('USER', 'dev')
        if pm.username == current_user:
            print(f"✅ Correct user: {pm.username}")
        else:
            print(f"❌ Wrong user: {pm.username} (should be {current_user})")
            return False
        
        # Check status
        status = pm.get_privilege_status()
        print(f"✅ Status: {status}")
        
        return True
        
    except Exception as e:
        print(f"❌ PrivilegeManager test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 NIMDA Privileges and Blocking Fix Test")
    print("=" * 50)
    
    tests = [
        ("Sudo Access", test_sudo_access),
        ("Credentials Verification", test_credentials_verification),
        ("Firewall Commands", test_firewall_commands),
        ("PrivilegeManager", test_privilege_manager)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! System is ready.")
        return True
    else:
        print("⚠️ Some tests failed. Check the issues above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 