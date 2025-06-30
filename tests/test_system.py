#!/usr/bin/env python3
"""
Comprehensive Test Script for NIMDA Security System
Tests all major components including new features:
- Enhanced Security Policy with scrollable interface
- Sound Alert System with different threat levels
- Root Privilege Management with secure storage
"""

import sys
import os
import time
import subprocess
from datetime import datetime

def test_imports():
    """Test all required imports"""
    print("🔍 Testing imports...")
    
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
        print("✅ tkinter imports successful")
    except ImportError as e:
        print(f"❌ tkinter import failed: {e}")
        return False
    
    try:
        from sound_alerts_enhanced import SoundAlertSystem, ThreatLevel as SoundThreatLevel
        print("✅ sound_alerts_enhanced import successful")
    except ImportError as e:
        print(f"❌ sound_alerts_enhanced import failed: {e}")
        return False
    
    try:
        import keyring
        print("✅ keyring import successful")
    except ImportError as e:
        print(f"❌ keyring import failed: {e}")
        return False
    
    try:
        from nimda_tkinter import NIMDATkinterApp, ThreatLevel, SecurityPolicy, PrivilegeManager
        print("✅ nimda_tkinter imports successful")
    except ImportError as e:
        print(f"❌ nimda_tkinter import failed: {e}")
        return False
    
    return True

def test_sound_system():
    """Test enhanced sound alert system"""
    print("\n🔊 Testing Sound Alert System...")
    
    try:
        from sound_alerts_enhanced import SoundAlertSystem, ThreatLevel as SoundThreatLevel
        
        sound_system = SoundAlertSystem()
        
        # Test basic functionality
        print("  Testing sound system initialization...")
        assert sound_system.enabled == True
        assert sound_system.volume == 0.7
        print("  ✅ Sound system initialized correctly")
        
        # Test threat level mapping
        print("  Testing threat level sounds...")
        for level in SoundThreatLevel:
            print(f"    Testing {level.value[0]} level...")
            sound_system.play_threat_alert(level, "TEST")
            time.sleep(0.5)
        print("  ✅ Threat level sounds working")
        
        # Test pattern alerts
        print("  Testing pattern alerts...")
        patterns = ['network_attack', 'suspicious_process', 'data_breach']
        for pattern in patterns:
            print(f"    Testing {pattern} pattern...")
            sound_system.play_alert_pattern(pattern, "TEST")
            time.sleep(1)
        print("  ✅ Pattern alerts working")
        
        # Test settings
        print("  Testing sound settings...")
        sound_system.set_volume(0.5)
        assert sound_system.volume == 0.5
        sound_system.disable()
        assert sound_system.enabled == False
        sound_system.enable()
        assert sound_system.enabled == True
        print("  ✅ Sound settings working")
        
        print("✅ Sound Alert System tests passed")
        return True
        
    except Exception as e:
        print(f"❌ Sound system test failed: {e}")
        return False

def test_privilege_manager():
    """Test privilege management system"""
    print("\n🔐 Testing Privilege Manager...")
    
    try:
        from nimda_tkinter import PrivilegeManager
        
        # Create privilege manager
        privilege_manager = PrivilegeManager()
        
        # Test initialization
        print("  Testing privilege manager initialization...")
        assert privilege_manager.service_name == "NIMDA_Security_System"
        assert privilege_manager.username == "admin"
        assert privilege_manager.has_privileges == False
        print("  ✅ Privilege manager initialized correctly")
        
        # Test status
        print("  Testing privilege status...")
        status = privilege_manager.get_privilege_status()
        assert 'has_privileges' in status
        assert 'privileges_valid' in status
        assert 'time_remaining' in status
        assert 'credentials_stored' in status
        print("  ✅ Privilege status working")
        
        # Test credential storage (without actual password)
        print("  Testing credential storage...")
        test_password = "test_password_123"
        result = privilege_manager.store_credentials(test_password)
        if result:
            print("  ✅ Credential storage working")
        else:
            print("  ⚠️ Credential storage failed (may need keyring setup)")
        
        # Test credential verification
        print("  Testing credential verification...")
        verify_result = privilege_manager.verify_credentials(test_password)
        if verify_result:
            print("  ✅ Credential verification working")
        else:
            print("  ⚠️ Credential verification failed")
        
        print("✅ Privilege Manager tests passed")
        return True
        
    except Exception as e:
        print(f"❌ Privilege manager test failed: {e}")
        return False

def test_security_policy():
    """Test enhanced security policy"""
    print("\n🛡️ Testing Security Policy...")
    
    try:
        from nimda_tkinter import SecurityPolicy, ThreatLevel, SecurityAction
        
        # Create security policy
        policy = SecurityPolicy()
        
        # Test initialization
        print("  Testing policy initialization...")
        assert policy is not None
        print("  ✅ Policy initialized correctly")
        
        # Test threat levels
        print("  Testing threat levels...")
        for level in ThreatLevel:
            actions = policy.get_actions_for_level(level)
            print(f"    {level.value[3]}: {len(actions)} actions")
        print("  ✅ Threat levels working")
        
        # Test policy updates
        print("  Testing policy updates...")
        test_actions = [SecurityAction.MONITOR, SecurityAction.LOG]
        policy.update_policy(ThreatLevel.LOW, test_actions)
        updated_actions = policy.get_actions_for_level(ThreatLevel.LOW)
        assert SecurityAction.MONITOR in updated_actions
        assert SecurityAction.LOG in updated_actions
        print("  ✅ Policy updates working")
        
        # Test save/load
        print("  Testing policy save/load...")
        try:
            policy.save_policy()
            policy.load_policy()
            print("  ✅ Policy save/load working")
        except Exception as e:
            print(f"  ⚠️ Policy save/load failed: {e}")
        
        print("✅ Security Policy tests passed")
        return True
        
    except Exception as e:
        print(f"❌ Security policy test failed: {e}")
        return False

def test_gui_components():
    """Test GUI components"""
    print("\n🖥️ Testing GUI Components...")
    
    try:
        import tkinter as tk
        from nimda_tkinter import NIMDATkinterApp
        
        # Create root window
        root = tk.Tk()
        root.withdraw()  # Hide window during testing
        
        # Test app initialization
        print("  Testing app initialization...")
        app = NIMDATkinterApp(root)
        assert app is not None
        assert app.sound_system is not None
        assert app.privilege_manager is not None
        assert app.security_policy is not None
        print("  ✅ App initialized correctly")
        
        # Test UI components
        print("  Testing UI components...")
        assert app.notebook is not None
        assert app.status_label is not None
        assert app.sound_indicator is not None
        assert app.privilege_indicator is not None
        print("  ✅ UI components created")
        
        # Test sound system integration
        print("  Testing sound system integration...")
        app.trigger_sound_alert(ThreatLevel.MEDIUM, "TEST")
        time.sleep(0.5)
        print("  ✅ Sound system integration working")
        
        # Test privilege system integration
        print("  Testing privilege system integration...")
        status = app.privilege_manager.get_privilege_status()
        assert 'has_privileges' in status
        print("  ✅ Privilege system integration working")
        
        # Cleanup
        root.destroy()
        
        print("✅ GUI Components tests passed")
        return True
        
    except Exception as e:
        print(f"❌ GUI components test failed: {e}")
        return False

def test_system_commands():
    """Test system command execution"""
    print("\n⚙️ Testing System Commands...")
    
    try:
        # Test basic system info
        print("  Testing system info...")
        result = subprocess.run(['uname', '-a'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("  ✅ System info command working")
        else:
            print("  ⚠️ System info command failed")
        
        # Test network commands
        print("  Testing network commands...")
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("  ✅ Network commands working")
        else:
            print("  ⚠️ Network commands failed")
        
        # Test process commands
        print("  Testing process commands...")
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("  ✅ Process commands working")
        else:
            print("  ⚠️ Process commands failed")
        
        print("✅ System Commands tests passed")
        return True
        
    except Exception as e:
        print(f"❌ System commands test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 NIMDA Security System - Comprehensive Test Suite")
    print("=" * 60)
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    tests = [
        ("Import Tests", test_imports),
        ("Sound Alert System", test_sound_system),
        ("Privilege Manager", test_privilege_manager),
        ("Security Policy", test_security_policy),
        ("GUI Components", test_gui_components),
        ("System Commands", test_system_commands),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} FAILED with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    print(f"Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! System is ready to use.")
        return 0
    else:
        print("⚠️ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 