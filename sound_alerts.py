#!/usr/bin/env python3
"""
NIMDA Sound Alert System
Система звукових сповіщень для різних типів загроз
"""

import os
import sys
import time
import threading
import subprocess
from datetime import datetime
from enum import Enum
from colorama import Fore, Style

# Імпорт ThreatLevel з основного модуля
try:
    from nimda_integrated import ThreatLevel
except ImportError:
    # Fallback якщо файл запускається окремо
    class ThreatLevel(Enum):
        """Рівні загроз"""
        LOW = 1
        MEDIUM = 2
        HIGH = 3
        CRITICAL = 4
        EMERGENCY = 5

class AlertType(Enum):
    """Типи сповіщень"""
    NETWORK_INTRUSION = "network_intrusion"
    SUSPICIOUS_PROCESS = "suspicious_process"
    GPU_MINING = "gpu_mining"
    LOCKDOWN_BREACH = "lockdown_breach"
    SYSTEM_ERROR = "system_error"
    PERIPHERAL_DETECTED = "peripheral_detected"
    SSH_CONNECTION = "ssh_connection"
    PORT_SCAN = "port_scan"

class SoundAlertSystem:
    """Система звукових сповіщень"""
    
    def __init__(self):
        self.alert_active = False
        self.sound_enabled = True
        self.last_alert_time = {}
        self.alert_intervals = {
            ThreatLevel.LOW: 30,      # 30 секунд
            ThreatLevel.MEDIUM: 15,   # 15 секунд
            ThreatLevel.HIGH: 5,      # 5 секунд
            ThreatLevel.CRITICAL: 2,  # 2 секунди
            ThreatLevel.EMERGENCY: 1  # 1 секунда (сирена)
        }
        
        # Системні звуки macOS
        self.system_sounds = {
            ThreatLevel.LOW: "Tink",
            ThreatLevel.MEDIUM: "Pop",
            ThreatLevel.HIGH: "Sosumi",
            ThreatLevel.CRITICAL: "Basso",
            ThreatLevel.EMERGENCY: "Funk"  # Найгучніший
        }
        
        # Кастомні звуки (якщо доступні)
        self.custom_sounds = {
            AlertType.NETWORK_INTRUSION: "network_alert.wav",
            AlertType.SUSPICIOUS_PROCESS: "process_alert.wav",
            AlertType.GPU_MINING: "mining_alert.wav",
            AlertType.LOCKDOWN_BREACH: "breach_alert.wav",
            AlertType.SYSTEM_ERROR: "error_alert.wav",
            AlertType.PERIPHERAL_DETECTED: "peripheral_alert.wav",
            AlertType.SSH_CONNECTION: "ssh_alert.wav",
            AlertType.PORT_SCAN: "scan_alert.wav"
        }
        
        self.emergency_active = False
        self.emergency_thread = None
        
    def play_system_sound(self, sound_name):
        """Відтворити системний звук macOS"""
        try:
            subprocess.run(['afplay', f'/System/Library/Sounds/{sound_name}.aiff'], 
                         check=False, capture_output=True)
        except Exception:
            # Fallback для системного звуку
            subprocess.run(['say', 'Alert'], check=False, capture_output=True)
    
    def generate_beep_sequence(self, threat_level):
        """Генерувати послідовність звукових сигналів"""
        beep_patterns = {
            ThreatLevel.LOW: [1],           # Один короткий сигнал
            ThreatLevel.MEDIUM: [1, 1],     # Два коротких сигнали
            ThreatLevel.HIGH: [1, 1, 1],    # Три коротких сигнали
            ThreatLevel.CRITICAL: [2, 1, 2], # Довгий-короткий-довгий
            ThreatLevel.EMERGENCY: [3, 3, 3] # Три довгих сигнали
        }
        
        pattern = beep_patterns.get(threat_level, [1])
        
        for duration in pattern:
            # Використовуємо системний beep
            if duration == 1:  # Короткий
                subprocess.run(['osascript', '-e', 'beep 1'], check=False)
            elif duration == 2:  # Середній
                subprocess.run(['osascript', '-e', 'beep 2'], check=False)
            else:  # Довгий
                subprocess.run(['osascript', '-e', 'beep 3'], check=False)
            
            time.sleep(0.2)  # Пауза між сигналами
    
    def play_voice_alert(self, message, threat_level):
        """Відтворити голосове сповіщення"""
        try:
            voice_settings = {
                ThreatLevel.LOW: "Alex",
                ThreatLevel.MEDIUM: "Victoria", 
                ThreatLevel.HIGH: "Daniel",
                ThreatLevel.CRITICAL: "Fiona",
                ThreatLevel.EMERGENCY: "Alex"
            }
            
            rate_settings = {
                ThreatLevel.LOW: "200",
                ThreatLevel.MEDIUM: "220",
                ThreatLevel.HIGH: "250", 
                ThreatLevel.CRITICAL: "280",
                ThreatLevel.EMERGENCY: "300"
            }
            
            voice = voice_settings.get(threat_level, "Alex")
            rate = rate_settings.get(threat_level, "200")
            
            # Голосове сповіщення
            subprocess.run([
                'say', '-v', voice, '-r', rate, message
            ], check=False)
            
        except Exception:
            # Fallback - простий beep
            subprocess.run(['osascript', '-e', 'beep'], check=False)
    
    def emergency_siren(self):
        """Аварійна сирена для найвищого рівня загрози"""
        siren_messages = [
            "EMERGENCY! SECURITY BREACH DETECTED!",
            "СИСТЕМА ПІД АТАКОЮ!",
            "CRITICAL THREAT LEVEL!",
            "НЕВІДКЛАДНІ ЗАХОДИ БЕЗПЕКИ!"
        ]
        
        while self.emergency_active:
            # Відтворити сирену (швидка послідовність звуків)
            for freq in [800, 1000, 800, 1000, 800]:
                if not self.emergency_active:
                    break
                subprocess.run(['osascript', '-e', f'beep {freq//200}'], check=False)
                time.sleep(0.1)
            
            # Голосове сповіщення
            if self.emergency_active:
                message = siren_messages[int(time.time()) % len(siren_messages)]
                self.play_voice_alert(message, ThreatLevel.EMERGENCY)
            
            time.sleep(2)  # Короткий інтервал між циклами сирени
    
    def start_emergency_siren(self):
        """Запустити аварійну сирену"""
        if not self.emergency_active:
            self.emergency_active = True
            self.emergency_thread = threading.Thread(target=self.emergency_siren, daemon=True)
            self.emergency_thread.start()
            print(f"{Fore.RED}🚨 АВАРІЙНА СИРЕНА АКТИВОВАНА{Style.RESET_ALL}")
    
    def stop_emergency_siren(self):
        """Зупинити аварійну сирену"""
        if self.emergency_active:
            self.emergency_active = False
            if self.emergency_thread:
                self.emergency_thread.join(timeout=1)
            print(f"{Fore.YELLOW}🔇 Аварійна сирена зупинена{Style.RESET_ALL}")
    
    def can_play_alert(self, alert_type, threat_level):
        """Перевірити чи можна відтворити сповіщення (обмеження частоти)"""
        if not self.sound_enabled:
            return False
        
        current_time = time.time()
        key = f"{alert_type}_{threat_level}"
        
        if key in self.last_alert_time:
            interval = self.alert_intervals[threat_level]
            if current_time - self.last_alert_time[key] < interval:
                return False
        
        self.last_alert_time[key] = current_time
        return True
    
    def trigger_alert(self, alert_type, threat_level, message="Сповіщення", details=""):
        """Запустити звукове сповіщення"""
        if not self.can_play_alert(alert_type, threat_level):
            return
        
        print(f"{Fore.YELLOW}🔊 Звукове сповіщення: {alert_type.value} - {threat_level.name}{Style.RESET_ALL}")
        
        # Для найвищого рівня загрози - запустити сирену
        if threat_level == ThreatLevel.EMERGENCY:
            self.start_emergency_siren()
            return
        
        def play_alert():
            try:
                # Системний звук
                sound_name = self.system_sounds[threat_level]
                self.play_system_sound(sound_name)
                time.sleep(0.3)
                
                # Послідовність beep сигналів
                self.generate_beep_sequence(threat_level)
                time.sleep(0.5)
                
                # Голосове сповіщення для високих рівнів загрози
                if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    alert_messages = {
                        AlertType.NETWORK_INTRUSION: "Виявлено вторгнення в мережу",
                        AlertType.SUSPICIOUS_PROCESS: "Виявлено підозрілий процес", 
                        AlertType.GPU_MINING: "Виявлено можливу активність майнінгу",
                        AlertType.LOCKDOWN_BREACH: "Порушення системи блокування",
                        AlertType.SYSTEM_ERROR: "Критична помилка системи",
                        AlertType.PERIPHERAL_DETECTED: "Виявлено неавторизований периферійний пристрій",
                        AlertType.SSH_CONNECTION: "Підозріле SSH з'єднання",
                        AlertType.PORT_SCAN: "Виявлено сканування портів"
                    }
                    
                    voice_message = alert_messages.get(alert_type, message)
                    if details:
                        voice_message += f". {details}"
                    
                    self.play_voice_alert(voice_message, threat_level)
                
            except Exception as e:
                print(f"{Fore.RED}Помилка звукового сповіщення: {e}{Style.RESET_ALL}")
        
        # Запустити в окремому потоці
        alert_thread = threading.Thread(target=play_alert, daemon=True)
        alert_thread.start()
    
    def enable_sound(self):
        """Увімкнути звук"""
        self.sound_enabled = True
        print(f"{Fore.GREEN}🔊 Звукові сповіщення увімкнено{Style.RESET_ALL}")
    
    def disable_sound(self):
        """Вимкнути звук"""
        self.sound_enabled = False
        self.stop_emergency_siren()
        print(f"{Fore.YELLOW}🔇 Звукові сповіщення вимкнено{Style.RESET_ALL}")
    
    def test_all_alerts(self):
        """Тестувати всі рівні сповіщень"""
        print(f"{Fore.CYAN}🎵 Тестування всіх рівнів сповіщень...{Style.RESET_ALL}")
        
        for i, threat_level in enumerate(ThreatLevel, 1):
            print(f"Тестування {threat_level.name}...")
            self.trigger_alert(AlertType.SYSTEM_ERROR, threat_level, f"Тест {threat_level.name}")
            time.sleep(2)
        
        print(f"{Fore.GREEN}✅ Тестування сповіщень завершено{Style.RESET_ALL}")


# Глобальний екземпляр системи сповіщень
sound_system = SoundAlertSystem()

def play_alert(alert_type, threat_level, message="Сповіщення", details=""):
    """Зручна функція для запуску сповіщень"""
    sound_system.trigger_alert(alert_type, threat_level, message, details)

def emergency_alert(message="НАДЗВИЧАЙНА СИТУАЦІЯ"):
    """Аварійне сповіщення"""
    sound_system.trigger_alert(AlertType.LOCKDOWN_BREACH, ThreatLevel.EMERGENCY, message)

def test_sounds():
    """Тестування системи звуків"""
    sound_system.test_all_alerts()

if __name__ == "__main__":
    # Демо системи звуків
    print("Демо системи звукових сповіщень NIMDA")
    print("=" * 40)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "test":
            test_sounds()
        elif sys.argv[1] == "emergency":
            emergency_alert("ТЕСТ НАДЗВИЧАЙНОЇ СИТУАЦІЇ")
            time.sleep(5)
            sound_system.stop_emergency_siren()
    else:
        print("Використання:")
        print("  python3 sound_alerts.py test      - Тестувати всі рівні сповіщень")
        print("  python3 sound_alerts.py emergency - Тестувати аварійну сирену")
