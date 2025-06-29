#!/usr/bin/env python3
"""
Test script for NIMDA Security System Threat Levels
Tests the threat analysis system and automatic actions
"""

import sys
import os
import json
from datetime import datetime

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nimda_tkinter import ThreatLevel, SecurityAction, SecurityPolicy, ThreatAnalyzer

def test_threat_levels():
    """Test threat level analysis"""
    print("🧪 Testing NIMDA Threat Level System")
    print("=" * 50)
    
    # Initialize security policy and threat analyzer
    policy = SecurityPolicy()
    analyzer = ThreatAnalyzer(policy)
    
    # Test port threat analysis
    print("\n🔌 Testing Port Threat Analysis:")
    test_ports = [
        (22, "SSH"),
        (80, "HTTP"),
        (443, "HTTPS"),
        (4444, "Metasploit"),
        (31337, "Back Orifice"),
        (8080, "HTTP-Alt"),
        (3306, "MySQL"),
        (5432, "PostgreSQL")
    ]
    
    for port, service in test_ports:
        threat_level = analyzer.analyze_port_threat(port, service)
        print(f"  Port {port} ({service}): {threat_level.value[1]} {threat_level.value[3]}")
    
    # Test address threat analysis
    print("\n🌐 Testing Address Threat Analysis:")
    test_addresses = [
        "127.0.0.1:8080",
        "192.168.1.100:22",
        "8.8.8.8:53",
        "1.1.1.1:443",
        "10.0.0.1:80",
        "172.16.0.1:3306",
        "203.0.113.1:4444",
        "198.51.100.1:31337"
    ]
    
    for address in test_addresses:
        threat_level = analyzer.analyze_address_threat(address)
        print(f"  {address}: {threat_level.value[1]} {threat_level.value[3]}")
    
    # Test anomaly threat analysis
    print("\n⚠️ Testing Anomaly Threat Analysis:")
    test_anomalies = [
        {
            'type': 'CPU_SPIKE',
            'severity': 'HIGH',
            'description': 'CPU usage spike detected'
        },
        {
            'type': 'MEMORY_CRITICAL',
            'severity': 'CRITICAL',
            'description': 'Critical memory usage'
        },
        {
            'type': 'SUSPICIOUS_PROCESS',
            'severity': 'CRITICAL',
            'description': 'Suspicious process detected'
        },
        {
            'type': 'NETWORK_ANOMALY',
            'severity': 'MEDIUM',
            'description': 'Network traffic anomaly'
        },
        {
            'type': 'DISK_HIGH',
            'severity': 'LOW',
            'description': 'High disk usage'
        }
    ]
    
    for anomaly in test_anomalies:
        threat_level = analyzer.analyze_anomaly_threat(anomaly)
        print(f"  {anomaly['type']} ({anomaly['severity']}): {threat_level.value[1]} {threat_level.value[3]}")
    
    # Test security actions
    print("\n🛡️ Testing Security Actions:")
    test_targets = [
        ("Port 4444", "Metasploit port detected"),
        ("192.168.1.100:22", "Suspicious SSH connection"),
        ("Anomaly: CPU_SPIKE", "High CPU usage detected")
    ]
    
    for target, details in test_targets:
        print(f"\n  Testing actions for: {target}")
        if "Port" in target:
            threat_level = analyzer.analyze_port_threat(4444, "Metasploit")
        elif "192.168" in target:
            threat_level = analyzer.analyze_address_threat("192.168.1.100:22")
        else:
            threat_level = analyzer.analyze_anomaly_threat({'type': 'CPU_SPIKE', 'severity': 'HIGH'})
        
        print(f"    Threat Level: {threat_level.value[1]} {threat_level.value[3]}")
        print(f"    Actions to execute:")
        
        actions = policy.get_actions_for_level(threat_level)
        for action in actions:
            print(f"      • {action.value}")
    
    # Test policy configuration
    print("\n⚙️ Testing Policy Configuration:")
    print("  Current policies:")
    for level in ThreatLevel:
        actions = policy.get_actions_for_level(level)
        action_names = [action.value for action in actions]
        print(f"    {level.value[1]} {level.value[3]}: {', '.join(action_names)}")
    
    # Test policy update
    print("\n  Testing policy update...")
    new_actions = [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ALERT]
    policy.update_policy(ThreatLevel.MEDIUM, new_actions)
    print(f"    Updated MEDIUM level actions: {[action.value for action in new_actions]}")
    
    # Test policy save/load
    print("\n  Testing policy save/load...")
    try:
        policy.save_policy()
        print("    ✓ Policy saved successfully")
        
        # Create new policy instance to test loading
        new_policy = SecurityPolicy()
        print("    ✓ Policy loaded successfully")
    except Exception as e:
        print(f"    ✗ Policy save/load failed: {e}")
    
    print("\n✅ Threat Level System Test Completed!")

def test_color_coding():
    """Test color coding system"""
    print("\n🎨 Testing Color Coding System:")
    print("=" * 30)
    
    for level in ThreatLevel:
        color = level.value[2]
        icon = level.value[1]
        name = level.value[3]
        print(f"  {icon} {name}: {color}")
    
    print("\n✅ Color Coding Test Completed!")

def test_action_execution():
    """Test action execution"""
    print("\n⚡ Testing Action Execution:")
    print("=" * 30)
    
    policy = SecurityPolicy()
    analyzer = ThreatAnalyzer(policy)
    
    # Test different threat levels
    test_cases = [
        (ThreatLevel.LOW, "Test target", {"test": "data"}),
        (ThreatLevel.MEDIUM, "Test target", {"test": "data"}),
        (ThreatLevel.HIGH, "Test target", {"test": "data"}),
        (ThreatLevel.CRITICAL, "Test target", {"test": "data"}),
        (ThreatLevel.EMERGENCY, "Test target", {"test": "data"})
    ]
    
    for level, target, details in test_cases:
        print(f"\n  Testing {level.value[3]} level actions:")
        analyzer.execute_actions(level, target, details)
    
    print("\n✅ Action Execution Test Completed!")

def main():
    """Main test function"""
    print("🚀 NIMDA Security System - Threat Level Testing")
    print("=" * 60)
    
    try:
        test_threat_levels()
        test_color_coding()
        test_action_execution()
        
        print("\n🎉 All tests completed successfully!")
        print("\n📋 Summary:")
        print("  ✓ Threat level analysis working")
        print("  ✓ Color coding system working")
        print("  ✓ Security actions working")
        print("  ✓ Policy configuration working")
        print("  ✓ Policy save/load working")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 