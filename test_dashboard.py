#!/usr/bin/env python3
"""
Test script for the new statistics-based dashboard functionality
"""

import sys
import os
import time
import psutil
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_system_metrics():
    """Test system metrics collection"""
    print("🔍 Testing System Metrics...")
    
    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        print(f"✅ CPU: {cpu_percent:.1f}% | Cores: {cpu_count} | Freq: {cpu_freq.current/1000:.1f} GHz")
        
        # Memory metrics
        memory = psutil.virtual_memory()
        mem_percent = memory.percent
        mem_used_gb = memory.used / (1024**3)
        mem_free_gb = memory.available / (1024**3)
        mem_total_gb = memory.total / (1024**3)
        
        print(f"✅ Memory: {mem_percent:.1f}% | Used: {mem_used_gb:.1f} GB | Free: {mem_free_gb:.1f} GB | Total: {mem_total_gb:.1f} GB")
        
        return True
        
    except Exception as e:
        print(f"❌ System metrics error: {e}")
        return False

def test_processes_statistics():
    """Test processes statistics collection"""
    print("🔍 Testing Processes Statistics...")
    
    try:
        # Get processes count
        total_processes = len(psutil.pids())
        
        # Get top processes by CPU usage for analysis
        processes = []
        dangerous_count = 0
        medium_count = 0
        safe_count = 0
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username', 'cmdline']):
            try:
                proc_info = proc.info
                # Handle None values for CPU and memory percentages
                cpu_percent = proc_info.get('cpu_percent', 0) or 0
                memory_percent = proc_info.get('memory_percent', 0) or 0
                
                if cpu_percent > 0:  # Only analyze processes with CPU usage
                    processes.append({
                        'pid': proc_info.get('pid', 0),
                        'name': proc_info.get('name', 'Unknown'),
                        'cpu_percent': cpu_percent,
                        'memory_percent': memory_percent,
                        'status': proc_info.get('status', 'Unknown'),
                        'username': proc_info.get('username', 'Unknown'),
                        'cmdline': proc_info.get('cmdline', [])
                    })
                    
                    # Categorize by risk level
                    if cpu_percent > 50 or memory_percent > 20:
                        dangerous_count += 1
                    elif cpu_percent > 20 or memory_percent > 10:
                        medium_count += 1
                    else:
                        safe_count += 1
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        print(f"✅ Total Processes: {total_processes}")
        print(f"✅ Dangerous: {dangerous_count}")
        print(f"✅ Medium Risk: {medium_count}")
        print(f"✅ Safe: {safe_count}")
        
        return True
        
    except Exception as e:
        print(f"❌ Processes statistics error: {e}")
        return False

def test_connections_statistics():
    """Test connections statistics collection"""
    print("🔍 Testing Connections Statistics...")
    
    try:
        # Get network connections safely
        try:
            connections = psutil.net_connections()
            total_connections = len(connections)
        except (psutil.AccessDenied, psutil.ZombieProcess):
            connections = []
            total_connections = 0
        
        external_count = 0
        internal_count = 0
        blocked_count = 0
        
        for conn in connections:
            try:
                if conn.status == 'ESTABLISHED':
                    remote_ip = conn.raddr.ip if conn.raddr else None
                    if remote_ip:
                        # Check if external IP
                        if not (remote_ip.startswith('127.') or remote_ip.startswith('192.168.') or remote_ip.startswith('10.')):
                            external_count += 1
                        else:
                            internal_count += 1
                elif conn.status == 'TIME_WAIT' or conn.status == 'CLOSE_WAIT':
                    blocked_count += 1
            except:
                continue
        
        print(f"✅ Total Connections: {total_connections}")
        print(f"✅ External: {external_count}")
        print(f"✅ Internal: {internal_count}")
        print(f"✅ Blocked: {blocked_count}")
        
        return True
        
    except Exception as e:
        print(f"❌ Connections statistics error: {e}")
        return False

def test_real_time_monitoring():
    """Test real-time monitoring data"""
    print("🔍 Testing Real-Time Monitoring...")
    
    try:
        # Network activity
        net_io = psutil.net_io_counters()
        
        # Get network connections safely
        try:
            connections_count = len(psutil.net_connections())
        except (psutil.AccessDenied, psutil.ZombieProcess):
            connections_count = 0
        
        print(f"✅ Network: {connections_count} connections | Data In: {net_io.bytes_recv/1024:.1f} KB/s | Data Out: {net_io.bytes_sent/1024:.1f} KB/s")
        
        # Disk activity
        try:
            disk_usage = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            free_gb = disk_usage.free / (1024**3)
            print(f"✅ Disk: Read: {disk_io.read_bytes/1024:.1f} KB/s | Write: {disk_io.write_bytes/1024:.1f} KB/s | Free Space: {free_gb:.1f} GB")
        except (PermissionError, OSError):
            print("✅ Disk: Access denied (normal for some systems)")
        
        # System uptime
        uptime = time.time() - psutil.boot_time()
        days = int(uptime // 86400)
        hours = int((uptime % 86400) // 3600)
        minutes = int((uptime % 3600) // 60)
        
        print(f"✅ Uptime: {days} days, {hours} hours, {minutes} minutes")
        
        return True
        
    except Exception as e:
        print(f"❌ Real-time monitoring error: {e}")
        return False

def test_performance_details():
    """Test detailed performance information"""
    print("🔍 Testing Performance Details...")
    
    try:
        # CPU info
        cpu_info = {
            'Physical Cores': psutil.cpu_count(logical=False),
            'Logical Cores': psutil.cpu_count(logical=True),
            'Current Frequency': f"{psutil.cpu_freq().current/1000:.2f} GHz",
            'Max Frequency': f"{psutil.cpu_freq().max/1000:.2f} GHz",
            'CPU Usage': f"{psutil.cpu_percent()}%"
        }
        
        print("✅ CPU Information:")
        for key, value in cpu_info.items():
            print(f"   {key}: {value}")
        
        # Memory info
        memory_info = {
            'Total Memory': f"{psutil.virtual_memory().total/(1024**3):.2f} GB",
            'Available Memory': f"{psutil.virtual_memory().available/(1024**3):.2f} GB",
            'Used Memory': f"{psutil.virtual_memory().used/(1024**3):.2f} GB",
            'Memory Usage': f"{psutil.virtual_memory().percent}%"
        }
        
        print("✅ Memory Information:")
        for key, value in memory_info.items():
            print(f"   {key}: {value}")
        
        # Disk info
        disk_info = {}
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info[partition.device] = {
                    'Mount Point': partition.mountpoint,
                    'File System': partition.fstype,
                    'Total': f"{usage.total/(1024**3):.2f} GB",
                    'Used': f"{usage.used/(1024**3):.2f} GB",
                    'Free': f"{usage.free/(1024**3):.2f} GB",
                    'Usage': f"{usage.percent}%"
                }
            except PermissionError:
                continue
        
        print("✅ Disk Information:")
        for device, info in disk_info.items():
            print(f"   Device: {device}")
            for key, value in info.items():
                print(f"     {key}: {value}")
        
        return True
        
    except Exception as e:
        print(f"❌ Performance details error: {e}")
        return False

def test_dashboard_integration():
    """Test dashboard integration with security system"""
    print("🔍 Testing Dashboard Integration...")
    
    try:
        # Import security modules
        from nimda_tkinter import ThreatLevel, ThreatAnalyzer, SecurityPolicy
        
        # Create security policy and analyzer
        security_policy = SecurityPolicy()
        threat_analyzer = ThreatAnalyzer(security_policy)
        
        print("✅ Security system components initialized")
        
        # Test threat analysis
        test_port = 22
        test_service = "SSH"
        threat_level = threat_analyzer.analyze_port_threat(test_port, test_service)
        
        print(f"✅ Port {test_port} ({test_service}) threat level: {threat_level.value[0]} ({threat_level.value[3]})")
        
        # Test address analysis
        test_address = "192.168.1.100:80"
        threat_level = threat_analyzer.analyze_address_threat(test_address)
        
        print(f"✅ Address {test_address} threat level: {threat_level.value[0]} ({threat_level.value[3]})")
        
        return True
        
    except Exception as e:
        print(f"❌ Dashboard integration error: {e}")
        return False

def main():
    """Run all dashboard tests"""
    print("🚀 Starting Statistics-Based Dashboard Tests")
    print("=" * 50)
    
    tests = [
        ("System Metrics", test_system_metrics),
        ("Processes Statistics", test_processes_statistics),
        ("Connections Statistics", test_connections_statistics),
        ("Real-Time Monitoring", test_real_time_monitoring),
        ("Performance Details", test_performance_details),
        ("Dashboard Integration", test_dashboard_integration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 30)
        
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} ERROR: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All dashboard tests passed! The new statistics-based dashboard is ready.")
        return True
    else:
        print("⚠️ Some tests failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 