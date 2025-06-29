#!/usr/bin/env python3
"""
Test script for NIMDA Security System
Tests all security monitoring components
"""

import time
import subprocess
import sys
import os

def test_ollama_connection():
    """Test Ollama connection"""
    print("🔍 Testing Ollama connection...")
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get('models', [])
            print(f"✅ Ollama connected successfully")
            print(f"📋 Available models: {len(models)}")
            for model in models[:3]:
                print(f"  - {model.get('name', 'Unknown')}")
            return True
        else:
            print(f"❌ Ollama connection failed: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Ollama connection failed: {e}")
        return False

def test_security_monitor():
    """Test security monitor"""
    print("\n🔒 Testing Security Monitor...")
    try:
        from security_monitor import SecurityMonitor
        
        monitor = SecurityMonitor()
        print("✅ Security Monitor initialized")
        
        # Test system info
        system_info = monitor.get_system_info()
        if system_info:
            print("✅ System info retrieved")
        else:
            print("❌ Failed to get system info")
            return False
        
        # Test device extraction
        devices = monitor.extract_devices(system_info)
        print(f"✅ Device extraction: {len(devices)} devices found")
        
        # Test database
        monitor.init_database()
        print("✅ Database initialized")
        
        return True
    except Exception as e:
        print(f"❌ Security Monitor test failed: {e}")
        return False

def test_security_display():
    """Test security display"""
    print("\n📊 Testing Security Display...")
    try:
        from security_display import SecurityDisplay
        
        display = SecurityDisplay()
        print("✅ Security Display initialized")
        
        # Test getting events
        events = display.get_recent_events(5)
        print(f"✅ Recent events: {len(events)} found")
        
        # Test getting devices
        devices = display.get_current_devices()
        print(f"✅ Current devices: {len(devices)} found")
        
        # Test getting summary
        summary = display.get_security_summary()
        print("✅ Security summary generated")
        
        return True
    except Exception as e:
        print(f"❌ Security Display test failed: {e}")
        return False

def test_llm_agent():
    """Test LLM agent"""
    print("\n🤖 Testing LLM Security Agent...")
    try:
        from llm_security_agent import LLMSecurityAgent
        
        agent = LLMSecurityAgent()
        print("✅ LLM Agent initialized")
        
        # Test connection
        if agent.check_ollama_connection():
            print("✅ Ollama connection verified")
            
            # Test getting models
            models = agent.get_available_models()
            print(f"✅ Available models: {len(models)}")
            
            # Test context generation
            context = agent.get_security_context(1)
            print("✅ Security context generated")
            
            return True
        else:
            print("❌ Ollama not available")
            return False
    except Exception as e:
        print(f"❌ LLM Agent test failed: {e}")
        return False

def test_system_commands():
    """Test system commands used by security monitor"""
    print("\n🖥️ Testing System Commands...")
    
    commands = [
        ("system_profiler SPUSBDataType -json", "USB devices"),
        ("system_profiler SPThunderboltDataType -json", "Thunderbolt devices"),
        ("system_profiler SPBluetoothDataType -json", "Bluetooth devices"),
        ("system_profiler SPAudioDataType -json", "Audio devices"),
        ("networksetup -listallhardwareports", "Network interfaces"),
        ("pmset -g batt", "Battery info"),
        ("ps aux", "Process list"),
        ("netstat -an", "Network connections")
    ]
    
    all_passed = True
    for command, description in commands:
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✅ {description}: OK")
            else:
                print(f"❌ {description}: Failed (return code {result.returncode})")
                all_passed = False
        except Exception as e:
            print(f"❌ {description}: Error - {e}")
            all_passed = False
    
    return all_passed

def test_integration():
    """Test integration with main NIMDA system"""
    print("\n🔗 Testing Integration...")
    try:
        # Test importing main system
        sys.path.append(os.getcwd())
        from nimda_integrated import NIMDAIntegrated
        
        nimda = NIMDAIntegrated()
        print("✅ NIMDA integration successful")
        
        # Check if security modules are available
        if hasattr(nimda, 'port_security_monitor'):
            print("✅ Security modules integrated")
        else:
            print("⚠️ Security modules not integrated")
        
        return True
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 NIMDA Security System Test Suite")
    print("=" * 50)
    
    tests = [
        ("Ollama Connection", test_ollama_connection),
        ("System Commands", test_system_commands),
        ("Security Monitor", test_security_monitor),
        ("Security Display", test_security_display),
        ("LLM Agent", test_llm_agent),
        ("Integration", test_integration)
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
    print("📋 Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<20} {status}")
        if result:
            passed += 1
    
    print("=" * 50)
    print(f"Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Security system is ready.")
    elif passed >= total * 0.8:
        print("⚠️ Most tests passed. Some features may not work.")
    else:
        print("❌ Many tests failed. Please check your setup.")
    
    # Recommendations
    print("\n💡 Recommendations:")
    if not any(name == "Ollama Connection" and result for name, result in results):
        print("  • Start Ollama: ollama serve")
        print("  • Pull a model: ollama pull llama3:latest")
    
    if not any(name == "System Commands" and result for name, result in results):
        print("  • Check system permissions")
        print("  • Ensure macOS system_profiler is available")
    
    if not any(name == "Security Monitor" and result for name, result in results):
        print("  • Check Python dependencies: pip install -r requirements.txt")
        print("  • Verify file permissions")

if __name__ == "__main__":
    main() 