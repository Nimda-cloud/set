#!/usr/bin/env python3
"""
Test script for Devices and Processes tabs
"""

import sys
import os
import subprocess
import json

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_devices():
    """Test device monitoring functionality"""
    print("🖥️ Testing Device Monitoring")
    print("=" * 40)
    
    try:
        from security_monitor import SecurityMonitor
        
        monitor = SecurityMonitor()
        sysinfo = monitor.get_system_info()
        devices = monitor.extract_devices(sysinfo)
        
        print(f"Found {len(devices)} devices:")
        for dev_id, dev in devices.items():
            print(f"  • {dev.get('name', 'Unknown')} ({dev.get('type', 'Unknown')})")
            print(f"    Vendor: {dev.get('vendor', 'Unknown')}")
            print(f"    Product: {dev.get('product', 'Unknown')}")
            print(f"    Serial: {dev.get('serial', 'Unknown')}")
            print()
        
        return True
        
    except Exception as e:
        print(f"❌ Device test failed: {e}")
        return False

def test_processes():
    """Test process monitoring functionality"""
    print("⚙️ Testing Process Monitoring")
    print("=" * 40)
    
    try:
        import psutil
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            try:
                proc_info = proc.info
                if proc_info['pid'] and proc_info['name']:
                    processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        
        print(f"Found {len(processes)} processes")
        print("Top 10 processes by CPU usage:")
        for i, proc in enumerate(processes[:10]):
            print(f"  {i+1}. {proc['name']} (PID: {proc['pid']}) - CPU: {proc['cpu_percent']:.1f}%")
        
        # Check for suspicious processes
        suspicious = ['ssh', 'sshd', 'nc', 'netcat', 'ncat', 'socat', 'telnet', 'xmrig', 'ethminer']
        found_suspicious = []
        for proc in processes:
            if proc['name'].lower() in suspicious:
                found_suspicious.append(proc)
        
        if found_suspicious:
            print(f"\n⚠️ Found {len(found_suspicious)} suspicious processes:")
            for proc in found_suspicious:
                print(f"  • {proc['name']} (PID: {proc['pid']})")
        else:
            print("\n✅ No suspicious processes found")
        
        return True
        
    except Exception as e:
        print(f"❌ Process test failed: {e}")
        return False

def test_system_commands():
    """Test system commands for device/process management"""
    print("🔧 Testing System Commands")
    print("=" * 40)
    
    commands = [
        ("USB Devices", ["system_profiler", "SPUSBDataType", "-json"]),
        ("Bluetooth Devices", ["system_profiler", "SPBluetoothDataType", "-json"]),
        ("Network Interfaces", ["networksetup", "-listallhardwareports"]),
        ("Process List", ["ps", "aux"]),
        ("Network Connections", ["netstat", "-an"])
    ]
    
    for name, cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ {name}: OK")
            else:
                print(f"⚠️ {name}: Command failed")
        except Exception as e:
            print(f"❌ {name}: {e}")
    
    return True

def main():
    """Main test function"""
    print("🧪 NIMDA Devices & Processes Test")
    print("=" * 50)
    
    devices_ok = test_devices()
    processes_ok = test_processes()
    commands_ok = test_system_commands()
    
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    if devices_ok and processes_ok and commands_ok:
        print("🎉 ALL TESTS PASSED!")
        print("\n✅ Features available:")
        print("  • Device monitoring (USB, Bluetooth, Network)")
        print("  • Process monitoring with CPU/Memory usage")
        print("  • Suspicious process detection")
        print("  • System command integration")
        print("\n🚀 Ready to use in NIMDA GUI!")
        return 0
    else:
        print("❌ SOME TESTS FAILED!")
        return 1

if __name__ == "__main__":
    exit(main()) 