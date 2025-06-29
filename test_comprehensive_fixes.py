#!/usr/bin/env python3
"""
Comprehensive test script to verify all fixes:
1. Port display in UI
2. Security policy execution
3. Credentials management
4. DEBUG logging
"""

import sys
import os
import time
import subprocess
from datetime import datetime

def test_credentials_fix():
    """Test credentials management fix"""
    print("🔐 Testing Credentials Management Fix...")
    
    try:
        # Check if os module is imported
        import os
        current_user = os.getenv('USER', 'dev')
        print(f"✅ Current user detected: {current_user}")
        
        # Test PrivilegeManager import
        from nimda_tkinter import PrivilegeManager
        pm = PrivilegeManager()
        
        # Check if username is set correctly
        if pm.username == current_user:
            print(f"✅ PrivilegeManager uses correct user: {pm.username}")
            return True
        else:
            print(f"❌ PrivilegeManager uses wrong user: {pm.username} (should be {current_user})")
            return False
            
    except Exception as e:
        print(f"❌ Credentials test failed: {e}")
        return False

def test_port_display():
    """Test port display functionality"""
    print("\n🔍 Testing Port Display...")
    
    try:
        from nimda_tkinter import NetworkScanner
        
        # Test port scanning
        scanner = NetworkScanner()
        ports = scanner.scan_local_ports()
        
        print(f"✅ Port scanner found {len(ports)} ports")
        
        # Check port structure
        if ports and len(ports) > 0:
            port = ports[0]
            required_keys = ['port', 'service', 'status', 'risk', 'timestamp']
            
            if all(key in port for key in required_keys):
                print(f"✅ Port structure correct: {list(port.keys())}")
                return True
            else:
                print(f"❌ Port structure missing keys: {[k for k in required_keys if k not in port]}")
                return False
        else:
            print("⚠️ No ports found - this might be normal")
            return True
            
    except Exception as e:
        print(f"❌ Port display test failed: {e}")
        return False

def test_security_policy():
    """Test security policy execution"""
    print("\n🛡️ Testing Security Policy...")
    
    try:
        from nimda_tkinter import SecurityPolicy, ThreatAnalyzer, ThreatLevel
        
        # Test policy loading
        policy = SecurityPolicy()
        policy.load_policy()
        print("✅ Security policy loaded")
        
        # Test threat analyzer
        analyzer = ThreatAnalyzer(policy)
        
        # Test port threat analysis
        threat = analyzer.analyze_port_threat(22, "ssh")
        print(f"✅ Port threat analysis: SSH port = {threat.name}")
        
        # Test address threat analysis
        threat = analyzer.analyze_address_threat("8.8.8.8")
        print(f"✅ Address threat analysis: 8.8.8.8 = {threat.name}")
        
        return True
        
    except Exception as e:
        print(f"❌ Security policy test failed: {e}")
        return False

def test_debug_logging():
    """Test DEBUG logging functionality"""
    print("\n🐛 Testing DEBUG Logging...")
    
    try:
        # Check if DEBUG code exists in file
        with open('nimda_tkinter.py', 'r') as f:
            content = f.read()
            
        debug_patterns = [
            '[DEBUG] update_ports_tree',
            '[DEBUG] on_security_update',
            '[DEBUG] load_initial_data'
        ]
        
        for pattern in debug_patterns:
            if pattern in content:
                print(f"✅ DEBUG pattern found: {pattern}")
            else:
                print(f"❌ DEBUG pattern missing: {pattern}")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ DEBUG logging test failed: {e}")
        return False

def test_system_integration():
    """Test overall system integration"""
    print("\n🔧 Testing System Integration...")
    
    try:
        # Test imports
        from nimda_tkinter import (
            ThreatLevel, SecurityAction, SecurityPolicy, 
            ThreatAnalyzer, NetworkScanner, AnomalyDetector,
            PrivilegeManager, TranslationManager
        )
        print("✅ All core modules import successfully")
        
        # Test enum values
        threat_levels = list(ThreatLevel)
        print(f"✅ Threat levels: {[t.name for t in threat_levels]}")
        
        # Test security actions
        actions = list(SecurityAction)
        print(f"✅ Security actions: {[a.value for a in actions]}")
        
        return True
        
    except Exception as e:
        print(f"❌ System integration test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 NIMDA Comprehensive Fixes Test")
    print("=" * 50)
    
    tests = [
        ("Credentials Management", test_credentials_fix),
        ("Port Display", test_port_display),
        ("Security Policy", test_security_policy),
        ("DEBUG Logging", test_debug_logging),
        ("System Integration", test_system_integration)
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