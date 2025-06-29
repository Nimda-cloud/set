#!/usr/bin/env python3
"""
NIMDA Enhanced Sound Alert System
Розширена система звукових сповіщень з інтуїтивними налаштуваннями

Підтримує:
- 5 рівнів загроз (від LOW до EMERGENCY)
- 8 типів загроз (мережа, процеси, GPU, peripherals, тощо)
- Розумні інтервали між сповіщеннями
- Комбіновані звуки: системні + beep + голос
- Аварійна сирена для критичних ситуацій
"""

import sys
import time
import threading
import subprocess
from datetime import datetime
from enum import Enum
from colorama import Fore, Style, init

# Ініціалізація colorama
init()

class ThreatLevel(Enum):
    """
    Рівні загроз безпеки
    
    LOW: Низький рівень - інформаційні повідомлення
    MEDIUM: Середній рівень - потребує уваги
    HIGH: Високий рівень - потребує негайної уваги
    CRITICAL: Критичний рівень - серйозна загроза
    EMERGENCY: Аварійний рівень - негайне втручання
    """
    LOW = 1       # 🟢 Інформація
    MEDIUM = 2    # 🟡 Увага
    HIGH = 3      # 🟠 Небезпека
    CRITICAL = 4  # 🔴 Критично
    EMERGENCY = 5 # 🚨 Аварія

class AlertType(Enum):
    """
    Типи загроз безпеки
    
    Кожен тип має свої характерні звуки та повідомлення
    """
    NETWORK_INTRUSION = "network_intrusion"      # Мережеві вторгнення
    SUSPICIOUS_PROCESS = "suspicious_process"    # Підозрілі процеси
    GPU_MINING = "gpu_mining"                    # Майнінг на GPU
    LOCKDOWN_BREACH = "lockdown_breach"          # Порушення lockdown
    SYSTEM_ERROR = "system_error"                # Системні помилки
    PERIPHERAL_DETECTED = "peripheral_detected"  # Зовнішні пристрої
    SSH_CONNECTION = "ssh_connection"            # SSH підключення
    PORT_SCAN = "port_scan"                      # Сканування портів

class SoundAlertSystem:
    """
    Розширена система звукових сповіщень NIMDA
    
    Основні можливості:
    - Багаторівневі звукові сигнали
    - Розумні інтервали між повідомленнями
    - Комбіновані типи звуків (системні + beep + голос)
    - Аварійна сирена для критичних ситуацій
    - Детальна конфігурація для кожного типу загрози
    """
    
    def __init__(self, enable_voice=True, enable_beeps=True, enable_system_sounds=True):
        """
        Ініціалізація системи звукових сповіщень
        
        Args:
            enable_voice: Увімкнути голосові повідомлення
            enable_beeps: Увімкнути beep сигнали
            enable_system_sounds: Увімкнути системні звуки macOS
        """
        self.sound_enabled = True
        self.voice_enabled = enable_voice
        self.beeps_enabled = enable_beeps
        self.system_sounds_enabled = enable_system_sounds
        
        # Стан аварійної сирени
        self.emergency_active = False
        self.emergency_thread = None
        
        # Контроль частоти повідомлень
        self.last_alert_time = {}
        
        # НАЛАШТУВАННЯ ІНТЕРВАЛІВ МІЖ СПОВІЩЕННЯМИ
        # Час у секундах між повторними сповіщеннями того ж типу
        self.alert_intervals = {
            ThreatLevel.LOW: 60,       # 1 хвилина - рідко
            ThreatLevel.MEDIUM: 30,    # 30 секунд - помірно
            ThreatLevel.HIGH: 10,      # 10 секунд - часто
            ThreatLevel.CRITICAL: 5,   # 5 секунд - дуже часто
            ThreatLevel.EMERGENCY: 2   # 2 секунди - постійно
        }
        
        # СИСТЕМНІ ЗВУКИ macOS
        # Кожен рівень загрози має свій характерний звук
        self.system_sounds = {
            ThreatLevel.LOW: "Tink",        # М'який тихий звук
            ThreatLevel.MEDIUM: "Pop",      # Помітний звук
            ThreatLevel.HIGH: "Sosumi",     # Різкий увага-звук
            ThreatLevel.CRITICAL: "Basso",  # Глибокий серйозний звук
            ThreatLevel.EMERGENCY: "Funk"   # Найгучніший тривожний звук
        }
        
        # ПАТЕРНИ BEEP СИГНАЛІВ
        # Кожен рівень має унікальну послідовність
        self.beep_patterns = {
            ThreatLevel.LOW: [1],              # • (один короткий)
            ThreatLevel.MEDIUM: [1, 1],        # •• (два коротких)
            ThreatLevel.HIGH: [1, 1, 1],       # ••• (три коротких)
            ThreatLevel.CRITICAL: [2, 1, 2],   # -•- (довгий-короткий-довгий)
            ThreatLevel.EMERGENCY: [3, 3, 3]   # --- (три довгих - SOS стиль)
        }
        
        # ГОЛОСОВІ НАЛАШТУВАННЯ
        # Різні голоси та швидкість для кожного рівня
        self.voice_settings = {
            ThreatLevel.LOW: {"voice": "Alex", "rate": "180"},        # Спокійний
            ThreatLevel.MEDIUM: {"voice": "Victoria", "rate": "200"}, # Нейтральний
            ThreatLevel.HIGH: {"voice": "Daniel", "rate": "230"},     # Енергійний
            ThreatLevel.CRITICAL: {"voice": "Fiona", "rate": "250"},  # Серйозний
            ThreatLevel.EMERGENCY: {"voice": "Alex", "rate": "280"}   # Швидкий
        }
        
        # ПОВІДОМЛЕННЯ ДЛЯ КОЖНОГО ТИПУ ЗАГРОЗИ
        self.alert_messages = {
            AlertType.NETWORK_INTRUSION: {
                "short": "Network intrusion detected",
                "detailed": "Suspicious network activity detected. Check connections."
            },
            AlertType.SUSPICIOUS_PROCESS: {
                "short": "Suspicious process detected",
                "detailed": "Unknown or suspicious process is running. Investigate immediately."
            },
            AlertType.GPU_MINING: {
                "short": "GPU mining activity detected",
                "detailed": "High GPU usage detected. Possible cryptocurrency mining."
            },
            AlertType.LOCKDOWN_BREACH: {
                "short": "Lockdown system breach",
                "detailed": "Security lockdown has been breached. System compromised."
            },
            AlertType.SYSTEM_ERROR: {
                "short": "Critical system error",
                "detailed": "System error detected. Check logs for details."
            },
            AlertType.PERIPHERAL_DETECTED: {
                "short": "Unauthorized peripheral detected",
                "detailed": "New USB or peripheral device connected without authorization."
            },
            AlertType.SSH_CONNECTION: {
                "short": "Suspicious SSH connection",
                "detailed": "Incoming SSH connection from unknown source."
            },
            AlertType.PORT_SCAN: {
                "short": "Port scanning detected",
                "detailed": "Network port scanning activity detected from external source."
            }
        }
        
        # EMOJI ДЛЯ РІЗНИХ РІВНІВ
        self.threat_emoji = {
            ThreatLevel.LOW: "🟢",
            ThreatLevel.MEDIUM: "🟡", 
            ThreatLevel.HIGH: "🟠",
            ThreatLevel.CRITICAL: "🔴",
            ThreatLevel.EMERGENCY: "🚨"
        }
        
        print(f"{Fore.GREEN}🔊 Система звукових сповіщень NIMDA ініціалізована{Style.RESET_ALL}")
        self._print_configuration()
    
    def _print_configuration(self):
        """Показати поточну конфігурацію системи"""
        print(f"{Fore.CYAN}Конфігурація:{Style.RESET_ALL}")
        print(f"  Голосові сповіщення: {'✅' if self.voice_enabled else '❌'}")
        print(f"  Beep сигнали: {'✅' if self.beeps_enabled else '❌'}")
        print(f"  Системні звуки: {'✅' if self.system_sounds_enabled else '❌'}")
        print(f"  Інтервали сповіщень: {dict((k.name, f'{v}с') for k, v in self.alert_intervals.items())}")
    
    def can_play_alert(self, alert_type, threat_level):
        """
        Перевірити чи можна відтворити сповіщення
        
        Система контролює частоту повідомлень, щоб не спамити
        """
        if not self.sound_enabled:
            return False
        
        current_time = time.time()
        key = f"{alert_type.value}_{threat_level.name}"
        
        if key in self.last_alert_time:
            interval = self.alert_intervals[threat_level]
            time_passed = current_time - self.last_alert_time[key]
            
            if time_passed < interval:
                remaining = interval - time_passed
                print(f"{Fore.YELLOW}⏱️  Охолодження сповіщення: залишилося {remaining:.1f}с{Style.RESET_ALL}")
                return False
        
        self.last_alert_time[key] = current_time
        return True
    
    def play_system_sound(self, sound_name):
        """Відтворити системний звук macOS"""
        if not self.system_sounds_enabled:
            return
        
        try:
            # Спробувати відтворити системний звук
            result = subprocess.run(
                ['afplay', f'/System/Library/Sounds/{sound_name}.aiff'], 
                check=False, capture_output=True, timeout=3
            )
            if result.returncode != 0:
                # Fallback на базовий системний звук
                subprocess.run(['osascript', '-e', 'beep'], check=False, timeout=1)
        except Exception:
            # Останній fallback
            subprocess.run(['osascript', '-e', 'beep'], check=False)
    
    def generate_beep_sequence(self, threat_level):
        """Генерувати послідовність beep сигналів"""
        if not self.beeps_enabled:
            return
        
        pattern = self.beep_patterns.get(threat_level, [1])
        
        for i, duration in enumerate(pattern):
            try:
                if duration == 1:  # Короткий beep
                    subprocess.run(['osascript', '-e', 'beep 1'], 
                                 check=False, timeout=1)
                    time.sleep(0.1)
                elif duration == 2:  # Середній beep
                    subprocess.run(['osascript', '-e', 'beep 2'], 
                                 check=False, timeout=1)
                    time.sleep(0.2)
                else:  # Довгий beep
                    subprocess.run(['osascript', '-e', 'beep 3'], 
                                 check=False, timeout=1)
                    time.sleep(0.3)
                
                # Пауза між сигналами (крім останнього)
                if i < len(pattern) - 1:
                    time.sleep(0.2)
                    
            except Exception:
                # Простий fallback beep
                subprocess.run(['osascript', '-e', 'beep'], check=False)
    
    def play_voice_alert(self, message, threat_level):
        """Відтворити голосове сповіщення"""
        if not self.voice_enabled:
            return
        
        try:
            settings = self.voice_settings.get(threat_level, 
                                             {"voice": "Alex", "rate": "200"})
            
            # Використовувати say команду з налаштуваннями
            subprocess.run([
                'say', 
                '-v', settings["voice"], 
                '-r', settings["rate"], 
                message
            ], check=False, timeout=10)
            
        except Exception:
            # Fallback - простий beep замість голосу
            subprocess.run(['osascript', '-e', 'beep'], check=False)
    
    def emergency_siren(self):
        """
        Аварійна сирена для найвищого рівня загрози
        
        Працює у циклі до зупинки:
        - Швидка послідовність звуків (сирена)
        - Голосові повідомлення різними мовами
        - Короткі паузи між циклами
        """
        emergency_messages = [
            "НАДЗВИЧАЙНА СИТУАЦІЯ! ВИЯВЛЕНО ПОРУШЕННЯ БЕЗПЕКИ!",
            "УВАГА! ПОРУШЕННЯ БЕЗПЕКИ!",
            "АКТИВОВАНО КРИТИЧНИЙ РІВЕНЬ ЗАГРОЗИ!",
            "СИСТЕМА ПІД ЗАГРОЗОЮ!",
            "ПОТРІБНЕ НЕВІДКЛАДНЕ ВТРУЧАННЯ!",
            "НЕВІДКЛАДНІ ЗАХОДИ ПОТРІБНІ!"
        ]
        
        cycle_count = 0
        
        while self.emergency_active:
            cycle_count += 1
            
            # Сирена - швидка послідовність різних тонів
            siren_pattern = [1, 2, 3, 2, 1, 3, 2, 1]
            for tone in siren_pattern:
                if not self.emergency_active:
                    break
                    
                try:
                    subprocess.run(['osascript', '-e', f'beep {tone}'], 
                                 check=False, timeout=0.5)
                    time.sleep(0.1)
                except Exception:
                    pass
            
            # Голосове повідомлення кожні 2 цикли
            if self.emergency_active and cycle_count % 2 == 0:
                message_idx = (cycle_count // 2) % len(emergency_messages)
                message = emergency_messages[message_idx]
                
                try:
                    subprocess.run([
                        'say', '-v', 'Alex', '-r', '300', message
                    ], check=False, timeout=5)
                except Exception:
                    pass
            
            # Коротка пауза між циклами сирени
            if self.emergency_active:
                time.sleep(1.5)
    
    def start_emergency_siren(self):
        """Запустити аварійну сирену"""
        if not self.emergency_active:
            self.emergency_active = True
            self.emergency_thread = threading.Thread(
                target=self.emergency_siren, 
                daemon=True,
                name="EmergencySiren"
            )
            self.emergency_thread.start()
            print(f"{Fore.RED}🚨 АВАРІЙНА СИРЕНА АКТИВОВАНА 🚨{Style.RESET_ALL}")
    
    def stop_emergency_siren(self):
        """Зупинити аварійну сирену"""
        if self.emergency_active:
            self.emergency_active = False
            if self.emergency_thread and self.emergency_thread.is_alive():
                self.emergency_thread.join(timeout=2)
            print(f"{Fore.YELLOW}🔇 Аварійна сирена зупинена{Style.RESET_ALL}")
    
    def trigger_alert(self, alert_type, threat_level, custom_message=None, details=None):
        """
        Головна функція для запуску звукового сповіщення
        
        Args:
            alert_type: Тип загрози (AlertType)
            threat_level: Рівень загрози (ThreatLevel)
            custom_message: Власне повідомлення (опціонально)
            details: Додаткові деталі (опціонально)
        """
        # Перевірити чи можна відтворити сповіщення
        if not self.can_play_alert(alert_type, threat_level):
            return
        
        # Підготувати повідомлення
        emoji = self.threat_emoji[threat_level]
        alert_info = self.alert_messages.get(alert_type, {})
        
        if custom_message:
            voice_message = custom_message
        else:
            voice_message = alert_info.get("short", "Security alert")
        
        if details:
            voice_message += f". {details}"
        elif not custom_message and "detailed" in alert_info:
            voice_message = alert_info["detailed"]
        
        # Показати інформацію про сповіщення
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n{emoji} {Fore.YELLOW}[{timestamp}] SOUND ALERT{Style.RESET_ALL}")
        print(f"   Type: {alert_type.value}")
        print(f"   Level: {threat_level.name}")
        print(f"   Message: {voice_message}")
        
        # Для EMERGENCY рівня - запустити сирену
        if threat_level == ThreatLevel.EMERGENCY:
            self.start_emergency_siren()
            return
        
        # Відтворити звуки у окремому потоці
        def play_alert_sequence():
            try:
                # 1. Системний звук
                if self.system_sounds_enabled:
                    sound_name = self.system_sounds[threat_level]
                    self.play_system_sound(sound_name)
                    time.sleep(0.4)
                
                # 2. Beep послідовність
                if self.beeps_enabled:
                    self.generate_beep_sequence(threat_level)
                    time.sleep(0.6)
                
                # 3. Голосове повідомлення (для HIGH та CRITICAL)
                if (self.voice_enabled and 
                    threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]):
                    self.play_voice_alert(voice_message, threat_level)
                
            except Exception as e:
                print(f"{Fore.RED}❌ Помилка звукового сповіщення: {e}{Style.RESET_ALL}")
        
        # Запустити в окремому потоці щоб не блокувати основний процес
        alert_thread = threading.Thread(
            target=play_alert_sequence, 
            daemon=True,
            name=f"Alert_{alert_type.value}_{threat_level.name}"
        )
        alert_thread.start()
    
    def enable_sound(self):
        """Увімкнути всі звукові сповіщення"""
        self.sound_enabled = True
        print(f"{Fore.GREEN}🔊 Звукові сповіщення увімкнено{Style.RESET_ALL}")
    
    def disable_sound(self):
        """Вимкнути всі звукові сповіщення"""
        self.sound_enabled = False
        self.stop_emergency_siren()
        print(f"{Fore.YELLOW}🔇 Звукові сповіщення вимкнено{Style.RESET_ALL}")
    
    def toggle_voice(self):
        """Переключити голосові повідомлення"""
        self.voice_enabled = not self.voice_enabled
        status = "увімкнено" if self.voice_enabled else "вимкнено"
        print(f"{Fore.CYAN}🗣️  Голосові сповіщення {status}{Style.RESET_ALL}")
    
    def toggle_beeps(self):
        """Переключити beep сигнали"""
        self.beeps_enabled = not self.beeps_enabled
        status = "увімкнено" if self.beeps_enabled else "вимкнено"
        print(f"{Fore.CYAN}📢 Beep сповіщення {status}{Style.RESET_ALL}")
    
    def test_alert_level(self, threat_level):
        """Тестувати конкретний рівень загрози"""
        print(f"{Fore.CYAN}🎵 Тестування {threat_level.name} рівня...{Style.RESET_ALL}")
        
        test_alert_type = AlertType.SYSTEM_ERROR
        test_message = f"Це тестовий сповіщення {threat_level.name} рівня"
        
        self.trigger_alert(test_alert_type, threat_level, test_message)
    
    def test_all_alerts(self):
        """Тестувати всі рівні загроз"""
        print(f"{Fore.CYAN}🎵 Тестування всіх рівнів сповіщень...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Примітка: Кожен тест буде очікувати відповідний інтервал{Style.RESET_ALL}\n")
        
        test_cases = [
            (AlertType.SYSTEM_ERROR, ThreatLevel.LOW, "Інформація низького пріоритету"),
            (AlertType.PERIPHERAL_DETECTED, ThreatLevel.MEDIUM, "Попередження середнього пріоритету"),
            (AlertType.SUSPICIOUS_PROCESS, ThreatLevel.HIGH, "Сповіщення високого пріоритету"),
            (AlertType.NETWORK_INTRUSION, ThreatLevel.CRITICAL, "Критична загроза безпеки"),
        ]
        
        for i, (alert_type, threat_level, message) in enumerate(test_cases, 1):
            print(f"[{i}/4] Тестування {threat_level.name} рівня...")
            self.trigger_alert(alert_type, threat_level, message)
            
            # Пауза між тестами
            if i < len(test_cases):
                wait_time = 4
                print(f"   Очікування {wait_time}с перед наступним тестом...")
                time.sleep(wait_time)
        
        print(f"\n{Fore.GREEN}✅ Тестування сповіщень завершено{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Примітка: EMERGENCY рівень не протестовано (використовуйте команду 'emergency'){Style.RESET_ALL}")
    
    def show_status(self):
        """Показати статус системи"""
        print(f"\n{Fore.CYAN}🔊 Статус системи звукових сповіщень NIMDA{Style.RESET_ALL}")
        print("=" * 40)
        print(f"Звукова система: {'🟢 Увімкнено' if self.sound_enabled else '🔴 Вимкнено'}")
        print(f"Голосові сповіщення: {'🟢 Увімкнено' if self.voice_enabled else '🔴 Вимкнено'}")
        print(f"Beep сигнали: {'🟢 Увімкнено' if self.beeps_enabled else '🔴 Вимкнено'}")
        print(f"Системні звуки: {'🟢 Увімкнено' if self.system_sounds_enabled else '🔴 Вимкнено'}")
        print(f"Аварійна сирена: {'🚨 АКТИВНА' if self.emergency_active else '🔇 Неактивна'}")
        print()
        
        print("Інтервали сповіщень:")
        for level, interval in self.alert_intervals.items():
            emoji = self.threat_emoji[level]
            print(f"  {emoji} {level.name}: {interval}с")
        print()
        
        if self.last_alert_time:
            print("Останні сповіщення:")
            for key, timestamp in list(self.last_alert_time.items())[-5:]:
                time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
                print(f"  {time_str}: {key}")
        else:
            print("Немає останніх сповіщень")


# Глобальний екземпляр системи
sound_system = None

def get_sound_system():
    """Отримати глобальний екземпляр системи звуків"""
    global sound_system
    if sound_system is None:
        sound_system = SoundAlertSystem()
    return sound_system

def play_alert(alert_type, threat_level, message=None, details=None):
    """Зручна функція для запуску сповіщень"""
    system = get_sound_system()
    system.trigger_alert(alert_type, threat_level, message, details)

def emergency_alert(message="НАДЗВИЧАЙНА СИТУАЦІЯ"):
    """Запустити аварійне сповіщення"""
    system = get_sound_system()
    system.trigger_alert(AlertType.LOCKDOWN_BREACH, ThreatLevel.EMERGENCY, message)

def stop_emergency():
    """Зупинити аварійну сирену"""
    system = get_sound_system()
    system.stop_emergency_siren()

if __name__ == "__main__":
    print(f"{Fore.CYAN}Розширена система звукових сповіщень NIMDA{Style.RESET_ALL}")
    print("=" * 50)
    
    # Створити систему
    system = SoundAlertSystem()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "test":
            system.test_all_alerts()
        elif command == "emergency":
            print(f"{Fore.RED}Тестування EMERGENCY рівня...{Style.RESET_ALL}")
            emergency_alert("ТЕСТ НАДЗВИЧАЙНОЇ СИТУАЦІЇ")
            print("Аварійна сирена буде працювати 10 секунд...")
            time.sleep(10)
            stop_emergency()
        elif command == "status":
            system.show_status()
        elif command in ["low", "medium", "high", "critical"]:
            level = ThreatLevel[command.upper()]
            system.test_alert_level(level)
        elif command == "interactive":
            # Інтерактивний режим
            print(f"\n{Fore.GREEN}Інтерактивний режим - введіть команди:{Style.RESET_ALL}")
            print("Команди: test, status, low, medium, high, critical, emergency, voice, beeps, enable, disable, quit")
            
            while True:
                try:
                    cmd = input(f"\n{Fore.CYAN}nimda-sound>{Style.RESET_ALL} ").strip().lower()
                    
                    if cmd in ["quit", "exit", "q"]:
                        break
                    elif cmd == "test":
                        system.test_all_alerts()
                    elif cmd == "status":
                        system.show_status()
                    elif cmd == "emergency":
                        emergency_alert("Інтерактивний тест аварійної ситуації")
                        time.sleep(3)
                        stop_emergency()
                    elif cmd == "voice":
                        system.toggle_voice()
                    elif cmd == "beeps":
                        system.toggle_beeps()
                    elif cmd == "enable":
                        system.enable_sound()
                    elif cmd == "disable":
                        system.disable_sound()
                    elif cmd in ["low", "medium", "high", "critical"]:
                        level = ThreatLevel[cmd.upper()]
                        system.test_alert_level(level)
                    else:
                        print(f"{Fore.YELLOW}Невідома команда: {cmd}{Style.RESET_ALL}")
                        
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"{Fore.RED}Помилка: {e}{Style.RESET_ALL}")
            
            print(f"\n{Fore.GREEN}До побачення!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Невідома команда: {sys.argv[1]}{Style.RESET_ALL}")
    else:
        print("\nВикористання:")
        print("  python3 sound_alerts_enhanced.py test         - Тестувати всі рівні сповіщень")
        print("  python3 sound_alerts_enhanced.py emergency   - Тестувати аварійну сирену")
        print("  python3 sound_alerts_enhanced.py status      - Показати статус системи")
        print("  python3 sound_alerts_enhanced.py low         - Тестувати LOW рівень")
        print("  python3 sound_alerts_enhanced.py medium      - Тестувати MEDIUM рівень") 
        print("  python3 sound_alerts_enhanced.py high        - Тестувати HIGH рівень")
        print("  python3 sound_alerts_enhanced.py critical    - Тестувати CRITICAL рівень")
        print("  python3 sound_alerts_enhanced.py interactive - Інтерактивний режим")
        print(f"\n{Fore.GREEN}Приклад:{Style.RESET_ALL}")
        print("  python3 sound_alerts_enhanced.py test")
