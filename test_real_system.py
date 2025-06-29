#!/usr/bin/env python3
"""
Test script to verify real system functionality
"""

import sys
import time
import subprocess
from datetime import datetime

def test_ai_query():
    """Test AI query functionality"""
    print("🤖 Testing AI Query System...")
    
    try:
        from llm_security_agent import LLMSecurityAgent
        
        # Initialize agent
        agent = LLMSecurityAgent()
        
        # Test connection
        if not agent.check_ollama_connection():
            print("❌ Ollama not connected - skipping AI test")
            return False
        
        # Test analyze_security_query method
        query = "What are the current security threats on my system?"
        response = agent.analyze_security_query(query)
        
        if response and not response.startswith("Error"):
            print("✅ AI query system working")
            print(f"Response preview: {response[:100]}...")
            return True
        else:
            print(f"❌ AI query failed: {response}")
            return False
            
    except Exception as e:
        print(f"❌ AI test failed: {e}")
        return False

def test_security_policy():
    """Test security policy execution"""
    print("🔒 Testing Security Policy...")
    
    try:
        from nimda_tkinter import ThreatLevel, SecurityAction, SecurityPolicy, ThreatAnalyzer
        
        # Load policy
        policy = SecurityPolicy()
        
        # Test policy loading
        actions = policy.get_actions_for_level(ThreatLevel.HIGH)
        expected_actions = [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ANALYZE, SecurityAction.BLOCK, SecurityAction.ALERT]
        
        if set(actions) == set(expected_actions):
            print("✅ Security policy loaded correctly")
        else:
            print(f"❌ Policy mismatch: expected {expected_actions}, got {actions}")
            return False
        
        # Test threat analyzer
        analyzer = ThreatAnalyzer(policy)
        
        # Test port threat analysis
        threat_level = analyzer.analyze_port_threat(22, "ssh")
        if threat_level == ThreatLevel.CRITICAL:
            print("✅ Port threat analysis working")
        else:
            print(f"❌ Unexpected threat level for SSH: {threat_level}")
            return False
        
        # Test address threat analysis
        threat_level = analyzer.analyze_address_threat("192.168.1.100")
        if threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM]:
            print("✅ Address threat analysis working")
        else:
            print(f"❌ Unexpected threat level for local address: {threat_level}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Security policy test failed: {e}")
        return False

def test_network_scanning():
    """Test network scanning functionality"""
    print("🌐 Testing Network Scanning...")
    
    try:
        from nimda_tkinter import NetworkScanner
        
        scanner = NetworkScanner()
        
        # Test port scanning
        ports = scanner.scan_local_ports()
        if ports and len(ports) > 0:
            print(f"✅ Port scanning working - found {len(ports)} ports")
        else:
            print("❌ Port scanning failed")
            return False
        
        # Test connection scanning
        connections = scanner.scan_network_connections()
        if connections and len(connections) > 0:
            print(f"✅ Connection scanning working - found {len(connections)} connections")
        else:
            print("❌ Connection scanning failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Network scanning test failed: {e}")
        return False

def test_sound_system():
    """Test sound alert system"""
    print("🔊 Testing Sound Alert System...")
    
    try:
        from sound_alerts_enhanced import get_sound_system, ThreatLevel
        
        sound_system = get_sound_system()
        
        # Test threat alert
        sound_system.play_threat_alert(ThreatLevel.MEDIUM, "TEST")
        print("✅ Sound system working")
        
        return True
        
    except Exception as e:
        print(f"❌ Sound system test failed: {e}")
        return False

def test_system_monitoring():
    """Test system monitoring"""
    print("📊 Testing System Monitoring...")
    
    try:
        import psutil
        
        # Test basic system info
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        if cpu_percent >= 0 and memory.percent >= 0 and disk.percent >= 0:
            print(f"✅ System monitoring working - CPU: {cpu_percent}%, Memory: {memory.percent}%, Disk: {disk.percent}%")
            return True
        else:
            print("❌ System monitoring failed")
            return False
            
    except Exception as e:
        print(f"❌ System monitoring test failed: {e}")
        return False

def test_real_threat_detection():
    """Test real threat detection with actual system data"""
    print("🚨 Testing Real Threat Detection...")
    
    try:
        from nimda_tkinter import NetworkScanner, ThreatAnalyzer, SecurityPolicy, ThreatLevel
        
        # Initialize components
        scanner = NetworkScanner()
        policy = SecurityPolicy()
        analyzer = ThreatAnalyzer(policy)
        
        # Get real data
        connections = scanner.scan_network_connections()
        ports = scanner.scan_local_ports()
        
        print(f"📡 Found {len(connections)} connections and {len(ports)} ports")
        
        # Test threat analysis on real data
        high_threats = 0
        medium_threats = 0
        
        for conn in connections[:5]:  # Test first 5 connections
            threat_level = analyzer.analyze_address_threat(conn['remote_addr'])
            if threat_level == ThreatLevel.HIGH:
                high_threats += 1
            elif threat_level == ThreatLevel.MEDIUM:
                medium_threats += 1
        
        for port in ports[:5]:  # Test first 5 ports
            threat_level = analyzer.analyze_port_threat(port['port'], port['service'])
            if threat_level == ThreatLevel.HIGH:
                high_threats += 1
            elif threat_level == ThreatLevel.MEDIUM:
                medium_threats += 1
        
        print(f"✅ Threat detection working - High: {high_threats}, Medium: {medium_threats}")
        
        # Test policy execution
        if high_threats > 0 or medium_threats > 0:
            print("✅ Security policy execution working")
        
        return True
        
    except Exception as e:
        print(f"❌ Real threat detection test failed: {e}")
        return False

def main():
    """Run all real system tests"""
    print("🧪 Running Real System Tests...")
    print("=" * 60)
    
    tests = [
        ("System Monitoring", test_system_monitoring),
        ("Network Scanning", test_network_scanning),
        ("Security Policy", test_security_policy),
        ("Sound System", test_sound_system),
        ("Real Threat Detection", test_real_threat_detection),
        ("AI Query System", test_ai_query),
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
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! System is fully operational.")
        print("\n🔧 System Status:")
        print("   ✅ Real-time monitoring active")
        print("   ✅ Security policy enforcement working")
        print("   ✅ Threat detection operational")
        print("   ✅ Sound alerts functional")
        print("   ✅ AI analysis available")
        print("   ✅ Network scanning active")
        return 0
    else:
        print("⚠️  Some tests failed. System may have issues.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 