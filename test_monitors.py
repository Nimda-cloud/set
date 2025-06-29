#!/usr/bin/env python3
"""
NIMDA Monitor Test - Тестування окремих моніторів
"""

import sys
import time
import signal
import os
import subprocess

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
        print(f"\n{Fore.YELLOW}🛑 Зупинення тесту монітора...{Style.RESET_ALL}")
        self.running = False
    
    def test_monitor(self, monitor_class, name, duration=30):
        """Тестувати монітор протягом вказаного часу"""
        print(f"{Fore.CYAN}🔍 Тестування {name} протягом {duration} секунд...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Натисніть Ctrl+C для раннього зупинення{Style.RESET_ALL}\n")
        
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
                        print(f"\033[H{Fore.CYAN}📊 {name} - Ітерація {count + 1}{Style.RESET_ALL}")
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
                    
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"{Fore.RED}❌ Помилка в {name}: {e}{Style.RESET_ALL}")
                    time.sleep(5)
            
            print(f"\n{Fore.GREEN}✅ Тест {name} завершено ({count} ітерацій){Style.RESET_ALL}")
        
        try:
            timed_run()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}🛑 Тест {name} перервано{Style.RESET_ALL}")
    
    def test_network_iteration(self):
        """Тестувати монітор мережі"""
        try:
            connections = psutil.net_connections(kind='inet')
            active = len([c for c in connections if c.status == 'ESTABLISHED'])
            print(f"Активні з'єднання: {active}, Всього: {len(connections)}")
        except Exception as e:
            print(f"Помилка мережевого монітора: {e}")
    
    def test_process_iteration(self):
        """Тестувати монітор процесів"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    info = proc.info
                    if info['cpu_percent'] and info['cpu_percent'] > 5:
                        processes.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            
            for proc in processes[:5]:
                print(f"PID {proc['pid']}: {proc['name']} - {proc['cpu_percent']:.1f}%")
            
        except Exception as e:
            print(f"Помилка монітора процесів: {e}")
    
    def test_gpu_iteration(self):
        """Тестувати монітор GPU"""
        print("Apple Silicon GPU - Перевірка процесів з високим CPU...")
        try:
            high_cpu = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    info = proc.info
                    if info['cpu_percent'] and info['cpu_percent'] > 10:
                        high_cpu.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            print(f"Процеси з високим CPU: {len(high_cpu)}")
            
        except Exception as e:
            print(f"Помилка монітора GPU: {e}")
    
    def test_security_iteration(self):
        """Тестувати монітор безпеки"""
        try:
            suspicious_ports = {22, 2222, 4444, 5555, 8080, 9999, 31337, 1337}
            connections = psutil.net_connections(kind='inet')
            suspicious = [c for c in connections if c.laddr and c.laddr.port in suspicious_ports]
            print(f"Підозрілі з'єднання: {len(suspicious)}")
            
        except Exception as e:
            print(f"Помилка монітора безпеки: {e}")
    
    def test_log_iteration(self):
        """Тестувати монітор логів"""
        try:
            print("Перевірка системних логів...")
            cmd = ['log', 'show', '--last', '1m', '--predicate', 'category == "security"', '--style', 'compact']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                print(f"Записи логів: {len(lines)}")
            else:
                print("Файл логу не знайдено")
            
        except Exception as e:
            print(f"Помилка монітора логів: {e}")
    
    def test_system_iteration(self):
        """Тестувати системний монітор"""
        try:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            print(f"CPU: {cpu:.1f}%, Пам'ять: {memory.percent:.1f}%")
            
        except Exception as e:
            print(f"Помилка системного монітора: {e}")

def main():
    """Головна функція тестування"""
    print(f"{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗")
    print("║                    ТЕСТЕР МОНІТОРІВ NIMDA                       ║")
    print("║                    Система тестування моніторів                ║")
    print(f"╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    monitors = {
        "1": ("Монітор мережі", NetworkMonitor),
        "2": ("Монітор процесів", ProcessMonitor),
        "3": ("Монітор GPU", GPUMonitor),
        "4": ("Монітор безпеки", SecurityMonitor),
        "5": ("Монітор логів", LogMonitor),
        "6": ("Системний монітор", SystemMonitor)
    }
    
    print("\nДоступні монітори:")
    for key, (name, _) in monitors.items():
        print(f"  {key}. {name}")
    
    print("  0. Вихід")
    
    tester = MonitorTester()
    
    while True:
        try:
            choice = input(f"\n{Fore.YELLOW}Виберіть монітор для тестування (0-6): {Style.RESET_ALL}").strip()
            
            if choice == "0":
                print(f"{Fore.GREEN}👋 До побачення!{Style.RESET_ALL}")
                break
            
            if choice in monitors:
                name, monitor_class = monitors[choice]
                duration = int(input(f"Тривалість тесту в секундах (за замовчуванням 30): ") or "30")
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
