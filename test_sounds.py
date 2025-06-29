#!/usr/bin/env python3
"""
NIMDA Sound Test - Тестування звукової системи
"""

import sys
import time
import os

# Додати поточну директорію до шляху
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nimda_integrated import SoundAlertSystem, ThreatLevel, AlertType, Fore, Style

def test_basic_sounds():
    """Тестування базових звуків"""
    print(f"{Fore.CYAN}🎵 Testing basic sound levels...{Style.RESET_ALL}")
    
    sound_system = SoundAlertSystem()
    
    tests = [
        (AlertType.SYSTEM_ERROR, ThreatLevel.LOW, "Low level test"),
        (AlertType.PERIPHERAL_DETECTED, ThreatLevel.MEDIUM, "Medium level test"),
        (AlertType.SUSPICIOUS_PROCESS, ThreatLevel.HIGH, "High level test"),
        (AlertType.NETWORK_INTRUSION, ThreatLevel.CRITICAL, "Critical level test"),
    ]
    
    for i, (alert_type, threat_level, message) in enumerate(tests, 1):
        print(f"\n{i}/4: Testing {threat_level.name} level...")
        sound_system.trigger_alert(alert_type, threat_level, message)
        time.sleep(4)  # Пауза між тестами

def test_emergency_siren():
    """Тестування аварійної сирени"""
    print(f"\n{Fore.RED}🚨 Testing emergency siren (5 seconds)...{Style.RESET_ALL}")
    
    sound_system = SoundAlertSystem()
    sound_system.trigger_alert(AlertType.LOCKDOWN_BREACH, ThreatLevel.EMERGENCY, "TEST EMERGENCY")
    
    # Зупинити сирену через 5 секунд
    time.sleep(5)
    sound_system.stop_emergency_siren()
    print(f"{Fore.GREEN}✅ Emergency test completed{Style.RESET_ALL}")

def test_threat_scenarios():
    """Тестування реальних сценаріїв загроз"""
    print(f"\n{Fore.YELLOW}⚠️ Testing real threat scenarios...{Style.RESET_ALL}")
    
    sound_system = SoundAlertSystem()
    
    scenarios = [
        (AlertType.SSH_CONNECTION, ThreatLevel.HIGH, "SSH connection from unknown IP 192.168.1.100"),
        (AlertType.PORT_SCAN, ThreatLevel.MEDIUM, "Port scanning detected from external source"),
        (AlertType.GPU_MINING, ThreatLevel.CRITICAL, "Cryptocurrency mining process detected: xmrig"),
        (AlertType.LOCKDOWN_BREACH, ThreatLevel.CRITICAL, "Lockdown system breach detected"),
    ]
    
    for i, (alert_type, threat_level, message) in enumerate(scenarios, 1):
        print(f"\n{i}/4: {alert_type.value} scenario...")
        sound_system.trigger_alert(alert_type, threat_level, message)
        time.sleep(5)

def main():
    """Головне меню тестування"""
    print(f"{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗")
    print("║                    NIMDA SOUND TEST SUITE                     ║")
    print("║                 Тестування звукової системи                   ║")
    print(f"╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    print("\nТести:")
    print("1. Базові рівні звуків (LOW → CRITICAL)")
    print("2. Аварійна сирена (EMERGENCY)")
    print("3. Реальні сценарії загроз")
    print("4. Всі тести підряд")
    print("0. Вихід")
    
    while True:
        try:
            choice = input(f"\n{Fore.YELLOW}Виберіть тест (1-4, 0 для виходу): {Style.RESET_ALL}").strip()
            
            if choice == '0':
                print(f"{Fore.GREEN}👋 До побачення!{Style.RESET_ALL}")
                break
            elif choice == '1':
                test_basic_sounds()
            elif choice == '2':
                test_emergency_siren()
            elif choice == '3':
                test_threat_scenarios()
            elif choice == '4':
                print(f"{Fore.CYAN}🎵 Running all tests...{Style.RESET_ALL}")
                test_basic_sounds()
                time.sleep(2)
                test_threat_scenarios()
                time.sleep(2)
                test_emergency_siren()
            else:
                print(f"{Fore.RED}❌ Невірний вибір{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}👋 Тестування перервано{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}❌ Помилка: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
