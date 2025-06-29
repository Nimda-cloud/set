#!/usr/bin/env python3
"""
NIMDA Demo - Демонстраційний запуск системи без TMUX
Показує як працює кожен монітор окремо
"""

import sys
import os

# Додати поточну директорію до шляху
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nimda_integrated import (
    NIMDAIntegrated, NetworkMonitor, ProcessMonitor, GPUMonitor,
    SecurityMonitor, LogMonitor, SystemMonitor, LockdownSystem, 
    SecureEnclaveKey, Fore, Style
)

def demo_monitors():
    """Демонстрація роботи моніторів"""
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗")
    print("║                      NIMDA DEMO MODE                            ║")
    print("║              Демонстрація роботи моніторів                      ║") 
    print(f"╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    
    monitors = [
        ("Network Monitor", NetworkMonitor),
        ("Process Monitor", ProcessMonitor), 
        ("GPU Monitor", GPUMonitor),
        ("Security Monitor", SecurityMonitor),
        ("Log Monitor", LogMonitor),
        ("System Monitor", SystemMonitor)
    ]
    
    print("Доступні монітори:")
    for i, (name, _) in enumerate(monitors, 1):
        print(f"  {i}. {name}")
    
    print(f"\n{Fore.YELLOW}Введіть номер монітора для демонстрації (1-6) або 'q' для виходу:{Style.RESET_ALL}")
    
    while True:
        try:
            choice = input("> ").strip().lower()
            
            if choice == 'q':
                print("👋 До побачення!")
                break
                
            if choice.isdigit() and 1 <= int(choice) <= 6:
                name, monitor_class = monitors[int(choice) - 1]
                print(f"\n🚀 Запуск {name}...")
                print(f"{Fore.YELLOW}Натисніть Ctrl+C для повернення до меню{Style.RESET_ALL}\n")
                
                try:
                    monitor = monitor_class()
                    monitor.run()
                except KeyboardInterrupt:
                    print(f"\n{Fore.CYAN}📋 Повернення до меню...{Style.RESET_ALL}\n")
                    continue
                except Exception as e:
                    print(f"\n{Fore.RED}❌ Помилка: {e}{Style.RESET_ALL}\n")
                    continue
            else:
                print(f"{Fore.RED}❌ Невірний вибір. Введіть число від 1 до 6 або 'q'{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}👋 До побачення!{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}❌ Помилка: {e}{Style.RESET_ALL}")

def demo_lockdown():
    """Демонстрація lockdown системи"""
    print(f"\n{Fore.RED}🔒 LOCKDOWN DEMO{Style.RESET_ALL}")
    print("=" * 50)
    
    lockdown = LockdownSystem()
    secure_key = SecureEnclaveKey()
    
    print(f"Key exists: {secure_key.key_exists}")
    print(f"Lockdown active: {lockdown.active}")
    
    print(f"\n{Fore.YELLOW}Команди:{Style.RESET_ALL}")
    print("  'enable' - увімкнути lockdown")
    print("  'disable' - вимкнути lockdown") 
    print("  'status' - показати статус")
    print("  'back' - повернутися до головного меню")
    
    while True:
        try:
            cmd = input("\nLockdown> ").strip().lower()
            
            if cmd == 'enable':
                if not secure_key.key_exists:
                    print("🔑 Створення ключа безпеки...")
                    secure_key.create_key()
                
                print("🔒 Увімкнення lockdown...")
                if lockdown.enable_lockdown():
                    print(f"{Fore.GREEN}✅ Lockdown активний{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Не вдалося активувати lockdown{Style.RESET_ALL}")
                    
            elif cmd == 'disable':
                print("🔓 Вимкнення lockdown...")
                if lockdown.disable_lockdown():
                    print(f"{Fore.GREEN}✅ Lockdown вимкнений{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ Не вдалося вимкнути lockdown{Style.RESET_ALL}")
                    
            elif cmd == 'status':
                print(f"Key exists: {secure_key.key_exists}")
                print(f"Lockdown active: {lockdown.active}")
                print(f"Blocked services: {lockdown.blocked_services}")
                
            elif cmd == 'back':
                break
                
            else:
                print(f"{Fore.RED}❌ Невідома команда{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            break

def main():
    """Головне меню демо"""
    while True:
        print(f"\n{Fore.CYAN}🎯 NIMDA DEMO - ГОЛОВНЕ МЕНЮ{Style.RESET_ALL}")
        print("=" * 40)
        print("1. Демонстрація моніторів")
        print("2. Демонстрація lockdown системи")
        print("3. Запустити повний інтерфейс TMUX")
        print("4. Вихід")
        
        try:
            choice = input(f"\n{Fore.YELLOW}Ваш вибір (1-4): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                demo_monitors()
            elif choice == '2':
                demo_lockdown()
            elif choice == '3':
                print(f"{Fore.CYAN}🚀 Запуск повного інтерфейсу...{Style.RESET_ALL}")
                nimda = NIMDAIntegrated()
                nimda.run()
            elif choice == '4':
                print(f"{Fore.GREEN}👋 До побачення!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}❌ Невірний вибір{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.GREEN}👋 До побачення!{Style.RESET_ALL}")
            break

if __name__ == "__main__":
    main()
