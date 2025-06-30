#!/usr/bin/env python3
"""
Enhanced Sound Alert System for NIMDA Security
Different sounds for different threat levels using macOS system sounds

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
from enum import Enum
from colorama import Fore, Style, init

# Ініціалізація colorama
init()

# Імпорт ThreatLevel з основного модуля
try:
    from nimda_integrated import ThreatLevel
except ImportError:
    # Fallback якщо файл запускається окремо
    class ThreatLevel(Enum):
        """Threat levels with corresponding sound types"""
        LOW = ("low", "Ping")
        MEDIUM = ("medium", "Sosumi") 
        HIGH = ("high", "Basso")
        CRITICAL = ("critical", "Frog")
        EMERGENCY = ("emergency", "Glass")

class SoundAlertSystem:
    """Enhanced sound alert system with different sounds for threat levels"""
    
    def __init__(self):
        self.enabled = True
        self.volume = 0.7
        self.sound_threads = []
        self.last_alert_time = {}
        self.alert_cooldown = 2.0  # seconds between same alerts
        
        # System sound mappings for different threat levels
        self.threat_sounds = {
            ThreatLevel.LOW: {
                'system': 'Ping',
                'description': 'Gentle ping for low threats',
                'volume': 0.3
            },
            ThreatLevel.MEDIUM: {
                'system': 'Sosumi', 
                'description': 'Warning sound for medium threats',
                'volume': 0.5
            },
            ThreatLevel.HIGH: {
                'system': 'Basso',
                'description': 'Alert sound for high threats',
                'volume': 0.7
            },
            ThreatLevel.CRITICAL: {
                'system': 'Frog',
                'description': 'Critical alert sound',
                'volume': 0.8
            },
            ThreatLevel.EMERGENCY: {
                'system': 'Glass',
                'description': 'Emergency break glass sound',
                'volume': 1.0
            }
        }
        
        # Custom alert patterns
        self.alert_patterns = {
            'network_attack': {
                'sounds': [ThreatLevel.HIGH, ThreatLevel.CRITICAL],
                'pattern': [0.5, 1.0, 0.5, 1.0],  # delays between sounds
                'description': 'Network attack detected'
            },
            'suspicious_process': {
                'sounds': [ThreatLevel.MEDIUM, ThreatLevel.HIGH],
                'pattern': [0.3, 0.8, 0.3],
                'description': 'Suspicious process detected'
            },
            'data_breach': {
                'sounds': [ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY, ThreatLevel.CRITICAL],
                'pattern': [0.2, 0.5, 0.2, 0.5, 0.2],
                'description': 'Data breach detected'
            },
            'system_compromise': {
                'sounds': [ThreatLevel.EMERGENCY, ThreatLevel.EMERGENCY, ThreatLevel.EMERGENCY],
                'pattern': [0.1, 0.1, 0.1, 0.5, 0.1, 0.1, 0.1],
                'description': 'System compromise detected'
            }
        }
        
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
        print(f"  Інтервали сповіщень: {dict((k.name, f'{v}с') for k, v in self.alert_intervals.items())}")
    
    def can_play_alert(self, alert_type, threat_level):
        """
        Перевірити чи можна відтворити сповіщення
        
        Система контролює частоту повідомлень, щоб не спамити
        """
        if not self.enabled:
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
    
    def play_system_sound(self, sound_name: str, volume: float = 0.7):
        """Play macOS system sound"""
        try:
            # Use afplay to play system sounds
            cmd = ['afplay', '-v', str(volume), f'/System/Library/Sounds/{sound_name}.aiff']
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception as e:
            print(f"Failed to play system sound {sound_name}: {e}")
    
    def play_threat_alert(self, threat_level: ThreatLevel, target: str = ""):
        """Play sound alert for specific threat level"""
        if not self.enabled:
            return
            
        # Check cooldown
        alert_key = f"{threat_level.value[0]}_{target}"
        current_time = time.time()
        if alert_key in self.last_alert_time:
            if current_time - self.last_alert_time[alert_key] < self.alert_cooldown:
                return
        
        self.last_alert_time[alert_key] = current_time
        
        # Get sound configuration
        sound_config = self.threat_sounds.get(threat_level)
        if not sound_config:
            return
        
        # Play sound in separate thread
        def play_sound():
            try:
                self.play_system_sound(sound_config['system'], sound_config['volume'])
                print(f"🔊 {threat_level.value[0].upper()} ALERT: {sound_config['description']} - {target}")
            except Exception as e:
                print(f"Sound alert error: {e}")
        
        thread = threading.Thread(target=play_sound, daemon=True)
        thread.start()
        self.sound_threads.append(thread)
    
    def play_alert_pattern(self, pattern_name: str, target: str = ""):
        """Play complex alert pattern for specific events"""
        if not self.enabled:
            return
            
        pattern = self.alert_patterns.get(pattern_name)
        if not pattern:
            return
        
        def play_pattern():
            try:
                for i, sound_level in enumerate(pattern['sounds']):
                    sound_config = self.threat_sounds.get(sound_level)
                    if sound_config:
                        self.play_system_sound(sound_config['system'], sound_config['volume'])
                    
                    # Wait for next sound
                    if i < len(pattern['pattern']):
                        time.sleep(pattern['pattern'][i])
                
                print(f"🔊 PATTERN ALERT: {pattern['description']} - {target}")
            except Exception as e:
                print(f"Pattern alert error: {e}")
        
        thread = threading.Thread(target=play_pattern, daemon=True)
        thread.start()
        self.sound_threads.append(thread)
    
    def play_custom_sequence(self, sounds: list, delays: list, description: str = ""):
        """Play custom sequence of sounds"""
        if not self.enabled:
            return
        
        def play_sequence():
            try:
                for i, sound_level in enumerate(sounds):
                    sound_config = self.threat_sounds.get(sound_level)
                    if sound_config:
                        self.play_system_sound(sound_config['system'], sound_config['volume'])
                    
                    # Wait for next sound
                    if i < len(delays):
                        time.sleep(delays[i])
                
                if description:
                    print(f"🔊 CUSTOM ALERT: {description}")
            except Exception as e:
                print(f"Custom sequence error: {e}")
        
        thread = threading.Thread(target=play_sequence, daemon=True)
        thread.start()
        self.sound_threads.append(thread)
    
    def test_sounds(self):
        """Test all available sounds"""
        print("🔊 Testing Sound Alert System...")
        
        for threat_level in ThreatLevel:
            print(f"\nTesting {threat_level.value[0].upper()} level...")
            self.play_threat_alert(threat_level, "TEST")
            time.sleep(1)
        
        print("\nTesting alert patterns...")
        for pattern_name in self.alert_patterns:
            print(f"\nTesting {pattern_name} pattern...")
            self.play_alert_pattern(pattern_name, "TEST")
            time.sleep(2)
        
        print("\n✅ Sound test completed!")
    
    def set_volume(self, volume: float):
        """Set system volume (0.0 to 1.0)"""
        self.volume = max(0.0, min(1.0, volume))
    
    def enable(self):
        """Enable sound alerts"""
        self.enabled = True
        print("🔊 Sound alerts enabled")
    
    def disable(self):
        """Disable sound alerts"""
        self.enabled = False
        print("🔇 Sound alerts disabled")
    
    def cleanup(self):
        """Clean up sound threads"""
        for thread in self.sound_threads:
            if thread.is_alive():
                thread.join(timeout=1.0)
        self.sound_threads.clear()

# Глобальний екземпляр системи
sound_system = None

def get_sound_system():
    """Отримати глобальний екземпляр системи звуків"""
    global sound_system
    if sound_system is None:
        sound_system = SoundAlertSystem()
    return sound_system

def emergency_alert(message="НАДЗВИЧАЙНА СИТУАЦІЯ"):
    """Запустити аварійне сповіщення"""
    system = get_sound_system()
    system.play_threat_alert(ThreatLevel.EMERGENCY, message)

def stop_emergency():
    """Зупинити аварійну сирену"""
    system = get_sound_system()
    system.cleanup()

if __name__ == "__main__":
    print(f"{Fore.CYAN}Розширена система звукових сповіщень NIMDA{Style.RESET_ALL}")
    print("=" * 50)
    
    # Створити систему
    system = SoundAlertSystem()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "test":
            system.test_sounds()
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
                        system.test_sounds()
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
                        system.enable()
                    elif cmd == "disable":
                        system.disable()
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
