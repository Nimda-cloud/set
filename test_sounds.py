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
    """Тестувати базові звуки"""
    print(f"{Fore.CYAN}🔊 Тестування базових звуків...{Style.RESET_ALL}")
    
    sound_system = SoundAlertSystem()
    
    for level in ThreatLevel:
        print(f"Тестування {level.name} рівня...")
        sound_system.trigger_alert(AlertType.SYSTEM_ERROR, level, f"Тест {level.name}")
        time.sleep(2)
    
    print(f"{Fore.GREEN}✅ Базові звуки протестовано{Style.RESET_ALL}")

def test_alert_types():
    """Тестувати різні типи сповіщень"""
    print(f"{Fore.CYAN}🔊 Тестування типів сповіщень...{Style.RESET_ALL}")
    
    for alert_type in AlertType:
        print(f"Тестування {alert_type.value}...")
        sound_system.trigger_alert(alert_type, ThreatLevel.HIGH, f"Тест {alert_type.value}")
        time.sleep(1.5)
    
    print(f"{Fore.GREEN}✅ Типи сповіщень протестовано{Style.RESET_ALL}")

def test_emergency_siren():
    """Тестувати аварійну сирену"""
    print(f"{Fore.RED}🚨 Тестування аварійної сирени...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}⚠️  Це буде гучно! Натисніть Ctrl+C для зупинення{Style.RESET_ALL}")
    
    try:
        sound_system = SoundAlertSystem()
        sound_system.start_emergency_siren()
        time.sleep(5)
        sound_system.stop_emergency_siren()
        print(f"{Fore.GREEN}✅ Аварійна сирена протестована{Style.RESET_ALL}")
    except KeyboardInterrupt:
        sound_system.stop_emergency_siren()
        print(f"{Fore.YELLOW}Тестування сирени перервано{Style.RESET_ALL}")

def test_threat_scenarios():
    """Тестувати реальні сценарії загроз"""
    print(f"\n{Fore.YELLOW}⚠️ Тестування реальних сценаріїв загроз...{Style.RESET_ALL}")
    
    sound_system = SoundAlertSystem()
    
    scenarios = [
        (AlertType.PORT_SCAN, ThreatLevel.MEDIUM, "Виявлено сканування портів"),
        (AlertType.SSH_CONNECTION, ThreatLevel.HIGH, "Підозріле SSH з'єднання"),
        (AlertType.NETWORK_INTRUSION, ThreatLevel.CRITICAL, "Вторгнення в мережу"),
        (AlertType.LOCKDOWN_BREACH, ThreatLevel.EMERGENCY, "Порушення системи блокування")
    ]
    
    for i, (alert_type, threat_level, message) in enumerate(scenarios, 1):
        print(f"\n{i}/4: {alert_type.value} сценарій...")
        sound_system.trigger_alert(alert_type, threat_level, message)
        time.sleep(3)
    
    print(f"{Fore.GREEN}✅ Сценарії загроз протестовано{Style.RESET_ALL}")

def main():
    """Головна функція тестування звуків"""
    print(f"{Fore.CYAN}🔊 Тестування звукових сповіщень NIMDA{Style.RESET_ALL}")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        test_type = sys.argv[1].lower()
        
        if test_type == "basic":
            test_basic_sounds()
        elif test_type == "types":
            test_alert_types()
        elif test_type == "emergency":
            test_emergency_siren()
        elif test_type == "all":
            test_basic_sounds()
            time.sleep(1)
            test_alert_types()
            time.sleep(1)
            test_emergency_siren()
        else:
            print(f"{Fore.RED}Невідомий тип тесту: {test_type}{Style.RESET_ALL}")
    else:
        print("Використання:")
        print("  python3 test_sounds.py basic    - Тестувати базові звуки")
        print("  python3 test_sounds.py types    - Тестувати типи сповіщень")
        print("  python3 test_sounds.py emergency - Тестувати аварійну сирену")
        print("  python3 test_sounds.py all      - Тестувати все")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Тестування перервано{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Помилка: {e}{Style.RESET_ALL}")
    finally:
        print(f"{Fore.GREEN}Тестування завершено{Style.RESET_ALL}")
