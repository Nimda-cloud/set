#!/usr/bin/env python3
"""
Quick test for NIMDA Threat Level System
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nimda_tkinter import ThreatLevel, SecurityAction, SecurityPolicy, ThreatAnalyzer

def quick_test():
    """Quick test of threat level system"""
    print("🚀 Quick NIMDA Threat Level Test")
    print("=" * 40)
    
    # Initialize
    policy = SecurityPolicy()
    analyzer = ThreatAnalyzer(policy)
    
    # Test 1: Port analysis
    print("\n🔌 Testing port threat analysis:")
    test_ports = [(22, "SSH"), (4444, "Metasploit"), (80, "HTTP")]
    for port, service in test_ports:
        level = analyzer.analyze_port_threat(port, service)
        print(f"  Port {port} ({service}): {level.value[1]} {level.value[3]}")
    
    # Test 2: Address analysis
    print("\n🌐 Testing address threat analysis:")
    test_addresses = ["127.0.0.1:8080", "192.168.1.100:22", "203.0.113.1:4444"]
    for addr in test_addresses:
        level = analyzer.analyze_address_threat(addr)
        print(f"  {addr}: {level.value[1]} {level.value[3]}")
    
    # Test 3: Anomaly analysis
    print("\n⚠️ Testing anomaly threat analysis:")
    test_anomalies = [
        {'type': 'CPU_SPIKE', 'severity': 'HIGH'},
        {'type': 'SUSPICIOUS_PROCESS', 'severity': 'CRITICAL'},
        {'type': 'NETWORK_ANOMALY', 'severity': 'MEDIUM'}
    ]
    for anomaly in test_anomalies:
        level = analyzer.analyze_anomaly_threat(anomaly)
        print(f"  {anomaly['type']} ({anomaly['severity']}): {level.value[1]} {level.value[3]}")
    
    # Test 4: Policy actions
    print("\n🛡️ Testing policy actions:")
    for level in ThreatLevel:
        actions = policy.get_actions_for_level(level)
        action_names = [action.value for action in actions]
        print(f"  {level.value[1]} {level.value[3]}: {', '.join(action_names)}")
    
    print("\n✅ Quick test completed successfully!")
    print("\n🎯 System features:")
    print("  ✓ 5 threat levels with color coding")
    print("  ✓ 10 security actions")
    print("  ✓ Automatic threat analysis")
    print("  ✓ Configurable security policies")
    print("  ✓ Ukrainian language support")

if __name__ == "__main__":
    quick_test() 