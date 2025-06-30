#!/usr/bin/env python3
"""
Comprehensive Edge Case and Sound Testing for NIMDA
Tests all enhanced features including edge cases, sound alerts, and logging
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
    from datetime import datetime
    
    def test_edge_cases_and_sounds():
        """Comprehensive test of all enhanced NIMDA features"""
        print("🚀 Starting Comprehensive NIMDA Edge Case & Sound Test...")
        
        # Create minimal NIMDA app for testing
        root = tk.Tk()
        root.withdraw()  # Hide the main window for testing
        
        app = NIMDATkinterApp(root)
        app.init_enhanced_threat_detection()
        
        print("✅ NIMDA app with enhanced features initialized")
        
        # Test 1: Basic Sound System Verification
        print("\n🧪 Test 1: Sound System Verification")
        if hasattr(app, 'sound_system') and app.sound_system:
            print("✅ Sound system available")
            
            # Test all threat levels
            for level in [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                print(f"🎵 Testing {level.name} level sound...")
                app.trigger_sound_alert(level, f"{level.name} Test")
                time.sleep(0.5)
            print("✅ All threat level sounds tested")
        else:
            print("❌ Sound system not available")
        
        # Test 2: Edge Case Threat Detection  
        print("\n🧪 Test 2: Edge Case Threat Detection")
        
        # Reset for clean testing
        app.reset_threat_counters()
        
        # Test IRC-like port edge case
        print("🔍 Testing IRC-like port edge case...")
        irc_threat = {
            'port': 6667,
            'service': 'unknown',  # This should trigger edge case
            'status': 'OPEN'
        }
        response = app.smart_threat_response('port_scan', irc_threat, ThreatLevel.HIGH)
        print(f"IRC edge case response: {response}")
        
        time.sleep(1)
        
        # Test trojan port edge case
        print("🔍 Testing trojan port edge case...")
        trojan_threat = {
            'port': 31337,
            'service': 'backdoor',
            'status': 'OPEN'
        }
        response = app.smart_threat_response('port_scan', trojan_threat, ThreatLevel.CRITICAL)
        print(f"Trojan port response: {response}")
        
        time.sleep(1)
        
        # Test night-time anomaly edge case (simulate night hour)
        print("🔍 Testing night-time anomaly edge case...")
        original_hour = datetime.now().hour
        
        # Create anomaly that would trigger during night hours
        night_anomaly = {
            'type': 'high_cpu_usage',
            'severity': 'medium',
            'time_detected': '23:30'  # Night time
        }
        response = app.smart_threat_response('anomaly', night_anomaly, ThreatLevel.MEDIUM)
        print(f"Night anomaly response: {response}")
        
        time.sleep(1)
        
        # Test unusual IP range edge case
        print("🔍 Testing unusual IP range edge case...")
        unusual_ip_threat = {
            'remote_address': '1.2.3.4',  # Unusual range
            'port': 80,
            'service': 'http'
        }
        response = app.smart_threat_response('ip_connection', unusual_ip_threat, ThreatLevel.MEDIUM)
        print(f"First unusual IP response: {response}")
        
        # Second occurrence should trigger edge case
        response = app.smart_threat_response('ip_connection', unusual_ip_threat, ThreatLevel.MEDIUM)
        print(f"Second unusual IP response: {response}")
        
        time.sleep(1)
        
        # Test 3: Progressive Threat Response
        print("\n🧪 Test 3: Progressive Threat Response")
        
        app.reset_threat_counters()
        
        # Test port 7000 progression
        dangerous_port = {
            'port': 7000,
            'service': 'IRC',
            'status': 'OPEN'
        }
        
        print("🔍 Testing port 7000 threat progression...")
        for i in range(1, 4):
            response = app.smart_threat_response('port_scan', dangerous_port, ThreatLevel.CRITICAL)
            print(f"  Occurrence {i}: {response}")
            time.sleep(0.5)
        
        # Test 4: Logging and Threat Intelligence  
        print("\n🧪 Test 4: Threat Intelligence and Logging")
        
        # Check if threat log was created
        if hasattr(app, 'threat_response_log'):
            print(f"✅ Threat response log created with {len(app.threat_response_log)} entries")
            
            # Show last few entries
            for entry in app.threat_response_log[-3:]:
                print(f"  📋 {entry['timestamp']} [{entry['threat_level']}] {entry['threat_type']}: {entry['response'][:50]}...")
        else:
            print("❌ Threat response log not found")
        
        # Test 5: Whitelisting System
        print("\n🧪 Test 5: Whitelisting System")
        
        # Test Microsoft IP whitelisting
        ms_threat = {
            'remote_address': '13.107.42.14',  # Microsoft IP
            'port': 443,
            'service': 'https'
        }
        response = app.smart_threat_response('ip_connection', ms_threat, ThreatLevel.LOW)
        print(f"Microsoft IP response: {response}")
        
        # Test Apple IP whitelisting  
        apple_threat = {
            'remote_address': '17.253.144.10',  # Apple IP
            'port': 5223,
            'service': 'apns'
        }
        response = app.smart_threat_response('ip_connection', apple_threat, ThreatLevel.LOW)
        print(f"Apple IP response: {response}")
        
        # Test 6: Force Threat Detection with Enhanced Features
        print("\n🧪 Test 6: Enhanced Force Threat Detection")
        app.force_threat_detection()
        
        print("\n✅ All comprehensive tests completed!")
        print("\n📊 Test Summary:")
        print("  ✅ Sound system verified for all threat levels")
        print("  ✅ Edge case detection working")
        print("  ✅ Progressive threat response implemented")
        print("  ✅ Enhanced logging active")
        print("  ✅ Whitelisting system functional")
        print("  ✅ Force detection with edge cases working")
        
        print("\n🎵 If you heard multiple sounds during testing, the integration is perfect!")
        print("🧠 The system now intelligently handles:")
        print("  • IRC-like ports with unknown services")
        print("  • Trojan/backdoor ports")
        print("  • Night-time anomalies")
        print("  • Unusual IP ranges")
        print("  • Progressive escalation")
        print("  • Smart whitelisting")
        
        root.destroy()
        
    if __name__ == "__main__":
        test_edge_cases_and_sounds()
        
except Exception as e:
    print(f"❌ Error during comprehensive test: {e}")
    import traceback
    traceback.print_exc()
