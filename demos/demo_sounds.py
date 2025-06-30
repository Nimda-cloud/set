#!/usr/bin/env python3
"""
NIMDA Sound Alert System - Demo Script
Демонстрація можливостей системи звукових сповіщень
"""

import time
import sys
from sound_alerts_enhanced import (
    SoundAlertSystem, ThreatLevel, AlertType,
    emergency_alert, stop_emergency
)
from colorama import Fore, Style

def run_basic_demo():
    """Базове демо рівнів сповіщень"""
    print(f"\n{Fore.CYAN}=== ДЕМО: Базові рівні сповіщень ==={Style.RESET_ALL}")
    
    scenarios = [
        {
            'level': ThreatLevel.LOW,
            'description': 'Низький рівень - простий звуковий сигнал',
            'emoji': '🔊'
        },
        {
            'level': ThreatLevel.MEDIUM,
            'description': 'Середній рівень - подвійний сигнал',
            'emoji': '🔊🔊'
        },
        {
            'level': ThreatLevel.HIGH,
            'description': 'Високий рівень - потрійний сигнал + голос',
            'emoji': '🔊🔊🔊'
        },
        {
            'level': ThreatLevel.CRITICAL,
            'description': 'Критичний рівень - складний сигнал + голос',
            'emoji': '🚨'
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n[{i}/4] {scenario['emoji']} Тестування {scenario['level'].name} рівня")
        print(f"      {scenario['description']}")
        
        sound_system.trigger_alert(
            AlertType.SYSTEM_ERROR,
            scenario['level'],
            f"Тест {scenario['level'].name} рівня"
        )
        
        print("      Очікування 3 секунди...")
        time.sleep(3)
    
    print(f"\n{Fore.GREEN}✅ Базове демо завершено{Style.RESET_ALL}")


def run_sound_types_demo():
    """Демо різних типів звуків"""
    print(f"\n{Fore.CYAN}=== ДЕМО: Різні типи звуків ==={Style.RESET_ALL}")
    
    sound_configs = [
        {'name': 'Системна помилка', 'type': AlertType.SYSTEM_ERROR},
        {'name': 'Підозрілий процес', 'type': AlertType.SUSPICIOUS_PROCESS},
        {'name': 'Мережеве вторгнення', 'type': AlertType.NETWORK_INTRUSION},
        {'name': 'Активність майнінгу', 'type': AlertType.GPU_MINING}
    ]
    
    for i, config in enumerate(sound_configs, 1):
        print(f"\n[{i}/4] Тестування: {config['name']}")
        
        sound_system.trigger_alert(
            config['type'],
            ThreatLevel.HIGH,
            f"Тест {config['name']}"
        )
        
        time.sleep(2)
    
    print(f"\n{Fore.GREEN}✅ Демо типів звуків завершено{Style.RESET_ALL}")


def run_threat_scenarios_demo():
    """Демо реальних сценаріїв загроз"""
    print(f"\n{Fore.CYAN}=== ДЕМО: Реальні сценарії загроз ==={Style.RESET_ALL}")
    
    scenarios = [
        {
            'name': 'Ескалація загрози',
            'steps': [
                (ThreatLevel.LOW, "Виявлено підозрілу активність"),
                (ThreatLevel.MEDIUM, "Активність підтверджена"),
                (ThreatLevel.HIGH, "Критична загроза виявлена"),
                (ThreatLevel.CRITICAL, "Система під атакою")
            ]
        },
        {
            'name': 'Мережева атака',
            'steps': [
                (ThreatLevel.MEDIUM, "Виявлено сканування портів"),
                (ThreatLevel.HIGH, "SSH з'єднання з підозрілої адреси"),
                (ThreatLevel.CRITICAL, "Спроба вторгнення в систему"),
                (ThreatLevel.EMERGENCY, "Критичне порушення безпеки")
            ]
        }
    ]
    
    for scenario in scenarios:
        print(f"\n{Fore.YELLOW}Сценарій: {scenario['name']}{Style.RESET_ALL}")
        print("Це симулює ескалацію інциденту безпеки...")
        
        for i, (threat_level, message) in enumerate(scenario['steps'], 1):
            emoji = "🔴" if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY] else "🟡"
            print(f"  {emoji} Крок {i}: {threat_level.name} - {message}")
            
            sound_system.trigger_alert(
                AlertType.NETWORK_INTRUSION,
                threat_level,
                message
            )
            
            time.sleep(3)
        
        print(f"  {Fore.GREEN}Сценарій завершено{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}✅ Демо сценаріїв загроз завершено{Style.RESET_ALL}")


def run_emergency_demo():
    """Демо аварійної сирени"""
    print(f"\n{Fore.RED}=== ДЕМО: Аварійна сирена ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}⚠️  Це буде ГУЧНО! Натисніть Ctrl+C для раннього зупинення{Style.RESET_ALL}")
    
    try:
        print("\nЗапуск аварійної сирени через 3 секунди...")
        for i in range(3, 0, -1):
            print(f"  {i}...")
            time.sleep(1)
        
        print(f"\n{Fore.RED}🚨 АВАРІЙНА СИРЕНА АКТИВОВАНА 🚨{Style.RESET_ALL}")
        sound_system.start_emergency_siren()
        
        print("Сирена буде працювати 8 секунд...")
        time.sleep(8)
        
        print(f"\n{Fore.YELLOW}Зупинення аварійної сирени...{Style.RESET_ALL}")
        sound_system.stop_emergency_siren()
        
        print(f"\n{Fore.GREEN}✅ Демо аварійної сирени завершено{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Демо аварійної сирени перервано користувачем{Style.RESET_ALL}")
        sound_system.stop_emergency_siren()


def run_interactive_demo():
    """Інтерактивне тестування звуків"""
    print(f"\n{Fore.CYAN}=== ІНТЕРАКТИВНЕ ТЕСТУВАННЯ ЗВУКІВ ==={Style.RESET_ALL}")
    
    while True:
        try:
            print(f"\n{Fore.CYAN}Виберіть опцію тестування:{Style.RESET_ALL}")
            print("1. Тестувати конкретний рівень загрози")
            print("2. Тестувати конкретний тип сповіщення")
            print("3. Перемкнути голосові сповіщення")
            print("4. Перемкнути beep сигнали")
            print("5. Показати статус системи")
            print("6. Тест аварійної сирени")
            print("7. Запустити повне демо")
            print("0. Вихід")
            
            choice = input("\nВаш вибір: ").strip()
            
            if choice == "0":
                break
            elif choice == "1":
                print("\nРівні загроз:")
                for i, level in enumerate(ThreatLevel, 1):
                    emoji = "🔴" if level in [ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY] else "🟡"
                    print(f"  {i}. {emoji} {level.name}")
                
                try:
                    level_choice = int(input("Виберіть рівень (1-5): ")) - 1
                    if 0 <= level_choice < len(ThreatLevel):
                        threat_level = list(ThreatLevel)[level_choice]
                        sound_system.trigger_alert(AlertType.SYSTEM_ERROR, threat_level, f"Тест {threat_level.name}")
                    else:
                        print(f"{Fore.RED}Невірний вибір{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}Невірний вибір{Style.RESET_ALL}")
                    
            elif choice == "2":
                print("\nТипи сповіщень:")
                for i, alert_type in enumerate(AlertType, 1):
                    print(f"  {i}. {alert_type.value}")
                
                try:
                    type_choice = int(input("Виберіть тип (1-8): ")) - 1
                    if 0 <= type_choice < len(AlertType):
                        alert_type = list(AlertType)[type_choice]
                        sound_system.trigger_alert(alert_type, ThreatLevel.HIGH, f"Тест {alert_type.value}")
                    else:
                        print(f"{Fore.RED}Невірний вибір{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}Невірний вибір{Style.RESET_ALL}")
                    
            elif choice == "3":
                if sound_system.sound_enabled:
                    sound_system.disable_sound()
                else:
                    sound_system.enable_sound()
                    
            elif choice == "4":
                print("Beep сигнали завжди активні")
                
            elif choice == "5":
                print(f"Статус звуку: {'Увімкнено' if sound_system.sound_enabled else 'Вимкнено'}")
                print(f"Аварійна сирена: {'Активна' if sound_system.emergency_active else 'Неактивна'}")
                
            elif choice == "6":
                print(f"{Fore.RED}Запуск тесту аварійної сирени...{Style.RESET_ALL}")
                sound_system.start_emergency_siren()
                time.sleep(3)
                sound_system.stop_emergency_siren()
                
            elif choice == "7":
                print(f"{Fore.CYAN}Запуск повного демо...{Style.RESET_ALL}")
                run_basic_demo()
                run_sound_types_demo()
                run_threat_scenarios_demo()
                
            else:
                print(f"{Fore.RED}Невірний вибір{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"{Fore.RED}Помилка: {e}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}Інтерактивна сесія завершена{Style.RESET_ALL}")


def main():
    """Головна функція демо"""
    print(f"{Fore.CYAN}🔊 Демо системи звукових сповіщень NIMDA{Style.RESET_ALL}")
    print("=" * 60)
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "basic":
            run_basic_demo()
        elif command == "types":
            run_sound_types_demo()
        elif command == "scenarios":
            run_threat_scenarios_demo()
        elif command == "emergency":
            run_emergency_demo()
        elif command == "interactive":
            run_interactive_demo()
        elif command == "full":
            print(f"{Fore.CYAN}Запуск повного демо...{Style.RESET_ALL}")
            run_basic_demo()
            run_sound_types_demo()
            run_threat_scenarios_demo()
            print(f"\n{Fore.GREEN}🎉 Повне демо завершено!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Примітка: Аварійна сирена не включена (використовуйте команду 'emergency'){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Невідома команда: {command}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}Доступні режими демо:{Style.RESET_ALL}")
        print("  python3 demo_sounds.py basic       - Базові рівні сповіщень")
        print("  python3 demo_sounds.py types       - Різні типи звуків")
        print("  python3 demo_sounds.py scenarios   - Реальні сценарії загроз")
        print("  python3 demo_sounds.py emergency   - Тест аварійної сирени")
        print("  python3 demo_sounds.py interactive - Інтерактивне тестування")
        print("  python3 demo_sounds.py full        - Повне демо (без аварійної сирени)")
        print(f"\n{Fore.YELLOW}Рекомендовано: Почніть з 'basic' для тестування налаштувань аудіо{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Демо перервано користувачем{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Помилка демо: {e}{Style.RESET_ALL}")
    finally:
        print(f"{Fore.GREEN}До побачення!{Style.RESET_ALL}")
