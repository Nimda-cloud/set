#!/usr/bin/env python3
"""
Test script to verify fixes for sound alerts and status bar issues
"""

import sys
import time
from sound_alerts_enhanced import get_sound_system, ThreatLevel, emergency_alert, stop_emergency

def test_sound_system():
    """Test the sound alert system"""
    print("🔊 Testing Sound Alert System...")
    
    try:
        # Get sound system
        sound_system = get_sound_system()
        print("✅ Sound system initialized successfully")
        
        # Test different threat levels
        print("\nTesting threat level alerts...")
        for threat_level in ThreatLevel:
            print(f"Testing {threat_level.name} level...")
            sound_system.play_threat_alert(threat_level, "TEST")
            time.sleep(0.5)
        
        # Test emergency alert
        print("\nTesting emergency alert...")
        emergency_alert("TEST EMERGENCY")
        time.sleep(1)
        
        # Test cleanup
        print("\nTesting cleanup...")
        stop_emergency()
        
        print("✅ All sound tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Sound test failed: {e}")
        return False

def test_imports():
    """Test that all imports work correctly"""
    print("🔍 Testing imports...")
    
    try:
        # Test main imports
        from nimda_tkinter import NIMDATkinterApp, ThreatLevel, SecurityPolicy
        print("✅ Main imports successful")
        
        # Test sound system imports
        from sound_alerts_enhanced import SoundAlertSystem, get_sound_system
        print("✅ Sound system imports successful")
        
        # Test security modules
        from security_monitor import SecurityMonitor
        print("✅ Security monitor import successful")
        
        # Test AI providers
        from ai_providers import AIProviderManager
        print("✅ AI providers import successful")
        
        # Test task scheduler
        from task_scheduler import TaskScheduler
        print("✅ Task scheduler import successful")
        
        print("✅ All imports successful!")
        return True
        
    except Exception as e:
        print(f"❌ Import test failed: {e}")
        return False

def test_no_legacy_code():
    """Test that no legacy AlertType code remains"""
    print("🔍 Checking for legacy code...")
    
    try:
        # Try to import AlertType - should fail
        try:
            from sound_alerts_enhanced import AlertType
            print("❌ AlertType still exists in sound_alerts_enhanced.py")
            return False
        except ImportError:
            print("✅ AlertType properly removed from sound_alerts_enhanced.py")
        
        # Check that trigger_alert method doesn't exist
        sound_system = get_sound_system()
        if hasattr(sound_system, 'trigger_alert'):
            print("❌ trigger_alert method still exists")
            return False
        else:
            print("✅ trigger_alert method properly removed")
        
        # Check that play_threat_alert method exists
        if hasattr(sound_system, 'play_threat_alert'):
            print("✅ play_threat_alert method exists")
        else:
            print("❌ play_threat_alert method missing")
            return False
        
        print("✅ No legacy code found!")
        return True
        
    except Exception as e:
        print(f"❌ Legacy code check failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 Running NIMDA Fix Tests...")
    print("=" * 50)
    
    tests = [
        ("Import Test", test_imports),
        ("Legacy Code Check", test_no_legacy_code),
        ("Sound System Test", test_sound_system),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name}...")
        if test_func():
            print(f"✅ {test_name} PASSED")
            passed += 1
        else:
            print(f"❌ {test_name} FAILED")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! System is ready to use.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 