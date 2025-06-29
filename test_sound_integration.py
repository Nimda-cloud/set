#!/usr/bin/env python3
"""
Test Sound System Integration
Перевірка, чи працюють звукові сповіщення в реальному NIMDA
"""

import sys
import os
sys.path.append('/Users/dev/Documents/NIMDA/set')

try:
    from nimda_tkinter import NIMDATkinterApp, ThreatLevel
    from sound_alerts_enhanced import SoundAlertSystem, ThreatLevel as SoundThreatLevel
    import tkinter as tk
    import threading
    import time
    
    def test_sound_integration():
        """Test the sound system integration with NIMDA"""
        print("🔊 Starting NIMDA Sound Integration Test...")
        
        # Create minimal NIMDA app for testing
        root = tk.Tk()
        root.withdraw()  # Hide the main window for testing
        
        app = NIMDATkinterApp(root)
        
        # Initialize the enhanced threat detection system
        app.init_enhanced_threat_detection()
        
        print("✅ NIMDA app initialized")
        
        # Test 1: Direct sound system test
        print("\n🧪 Test 1: Direct sound system test")
        if hasattr(app, 'sound_system') and app.sound_system:
            print("✅ Sound system found")
            app.sound_system.play_threat_alert(SoundThreatLevel.MEDIUM, "Test Alert")
            print("✅ Direct sound test completed")
        else:
            print("❌ Sound system not found")
        
        # Test 2: Trigger sound alert method
        print("\n🧪 Test 2: trigger_sound_alert method test")
        app.trigger_sound_alert(ThreatLevel.HIGH, "Port 7000 Test")
        print("✅ trigger_sound_alert test completed")
        
        # Test 3: Reset and force threat detection 
        print("\n🧪 Test 3: Forced threat detection with sounds")
        app.reset_threat_counters()
        app.force_threat_detection()
        print("✅ Forced detection test completed")
        
        # Test 4: Specific threat scenarios with sounds
        print("\n🧪 Test 4: Specific threat scenarios")
        
        # Dangerous port detection
        dangerous_port_data = {
            'port': 7000,
            'service': 'IRC',
            'status': 'OPEN',
            'risk': 'HIGH'
        }
        response = app.smart_threat_response('port_scan', dangerous_port_data, ThreatLevel.CRITICAL)
        print(f"Port threat response: {response}")
        
        time.sleep(1)
        
        # Unknown IP connection  
        unknown_ip_data = {
            'remote_address': '192.168.1.100',
            'port': 7000,
            'service': 'unknown'
        }
        response = app.smart_threat_response('ip_connection', unknown_ip_data, ThreatLevel.HIGH)
        print(f"IP threat response: {response}")
        
        time.sleep(1)
        
        # Anomaly detection
        anomaly_data = {
            'type': 'unusual_network_traffic',
            'severity': 'high',
            'description': 'Suspicious traffic pattern'
        }
        response = app.smart_threat_response('anomaly', anomaly_data, ThreatLevel.MEDIUM)
        print(f"Anomaly response: {response}")
        
        print("\n✅ All sound integration tests completed!")
        print("🎵 If you heard sounds during the tests, the integration is working correctly.")
        
        root.destroy()
        
    if __name__ == "__main__":
        test_sound_integration()
        
except Exception as e:
    print(f"❌ Error during sound integration test: {e}")
    import traceback
    traceback.print_exc()
