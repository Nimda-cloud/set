#!/usr/bin/env python3
"""
NIMDA Monitor Test - Тестування окремих моніторів
"""

import sys
import time
import signal
import os

# Додати поточну директорію до шляху
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nimda_integrated import (
    NetworkMonitor, ProcessMonitor, GPUMonitor,
    SecurityMonitor, LogMonitor, SystemMonitor,
    Fore, Style
)

class MonitorTester:
    def __init__(self):
        self.running = True
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        print(f"\n{Fore.YELLOW}🛑 Stopping monitor test...{Style.RESET_ALL}")
        self.running = False
    
    def test_monitor(self, monitor_class, name, duration=10):
        print(f"{Fore.CYAN}🔍 Testing {name} for {duration} seconds...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Press Ctrl+C to stop early{Style.RESET_ALL}\n")
        
        monitor = monitor_class()
        
        # Patch run method to add timeout
        original_run = monitor.run
        
        def timed_run():
            start_time = time.time()
            count = 0
            while self.running and (time.time() - start_time) < duration:
                try:
                    # Run one iteration of the monitor
                    if hasattr(monitor, 'run_once'):
                        monitor.run_once()
                    else:
                        # Simulate monitor iteration
                        print(f"\033[H{Fore.CYAN}📊 {name} - Iteration {count + 1}{Style.RESET_ALL}")
                        if name == "NetworkMonitor":
                            self.test_network_iteration()
                        elif name == "ProcessMonitor":
                            self.test_process_iteration()
                        elif name == "GPUMonitor":
                            self.test_gpu_iteration()
                        elif name == "SecurityMonitor":
                            self.test_security_iteration()
                        elif name == "LogMonitor":
                            self.test_log_iteration()
                        elif name == "SystemMonitor":
                            self.test_system_iteration()
                    
                    count += 1
                    time.sleep(2)
                    
                except Exception as e:
                    print(f"{Fore.RED}❌ Error in {name}: {e}{Style.RESET_ALL}")
                    break
            
            print(f"\n{Fore.GREEN}✅ {name} test completed ({count} iterations){Style.RESET_ALL}")
        
        try:
            timed_run()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}🛑 {name} test interrupted{Style.RESET_ALL}")
    
    def test_network_iteration(self):
        import psutil
        connections = psutil.net_connections(kind='inet')
        active = sum(1 for c in connections if c.status == 'ESTABLISHED')
        print(f"Active connections: {active}, Total: {len(connections)}")
    
    def test_process_iteration(self):
        import psutil
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                processes.append(proc.info)
            except:
                pass
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        top3 = processes[:3]
        for proc in top3:
            print(f"PID {proc['pid']}: {proc['name']} - {proc['cpu_percent']:.1f}%")
    
    def test_gpu_iteration(self):
        print("Apple Silicon GPU - Checking high CPU processes...")
        import psutil
        high_cpu = [p for p in psutil.process_iter(['name', 'cpu_percent']) 
                   if p.info['cpu_percent'] and p.info['cpu_percent'] > 20]
        print(f"High CPU processes: {len(high_cpu)}")
    
    def test_security_iteration(self):
        import psutil
        suspicious_ports = {22, 2222, 4444, 5555, 8080, 9999, 31337, 1337}
        connections = psutil.net_connections(kind='inet')
        suspicious = [c for c in connections if c.laddr and c.laddr.port in suspicious_ports]
        print(f"Suspicious connections: {len(suspicious)}")
    
    def test_log_iteration(self):
        print("Checking system logs...")
        if os.path.exists('security_monitor.log'):
            with open('security_monitor.log', 'r') as f:
                lines = f.readlines()
                print(f"Log entries: {len(lines)}")
        else:
            print("No log file found")
    
    def test_system_iteration(self):
        import psutil
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        print(f"CPU: {cpu:.1f}%, Memory: {memory.percent:.1f}%")

def main():
    print(f"{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗")
    print("║                    NIMDA MONITOR TESTER                       ║")
    print("║                Тестування окремих моніторів                   ║")
    print(f"╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    monitors = [
        (NetworkMonitor, "NetworkMonitor"),
        (ProcessMonitor, "ProcessMonitor"),
        (GPUMonitor, "GPUMonitor"),
        (SecurityMonitor, "SecurityMonitor"),
        (LogMonitor, "LogMonitor"),
        (SystemMonitor, "SystemMonitor")
    ]
    
    print("\nДоступні монітори:")
    for i, (_, name) in enumerate(monitors, 1):
        print(f"  {i}. {name}")
    
    tester = MonitorTester()
    
    while True:
        try:
            choice = input(f"\n{Fore.YELLOW}Виберіть монітор (1-6) або 'q' для виходу: {Style.RESET_ALL}").strip().lower()
            
            if choice == 'q':
                print(f"{Fore.GREEN}👋 До побачення!{Style.RESET_ALL}")
                break
            
            if choice.isdigit() and 1 <= int(choice) <= 6:
                monitor_class, name = monitors[int(choice) - 1]
                duration = input(f"Тривалість тесту в секундах (за замовчуванням 10): ").strip()
                duration = int(duration) if duration.isdigit() else 10
                
                tester.test_monitor(monitor_class, name, duration)
            else:
                print(f"{Fore.RED}❌ Невірний вибір{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.GREEN}👋 До побачення!{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}❌ Помилка: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
