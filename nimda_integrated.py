#!/usr/bin/env python3
"""
NIMDA Integrated Security System
Інтегрована система безпеки з інтерактивним меню та багатоекранним відображенням
"""

import os
import sys
import subprocess
import time
import signal
import psutil
import json
import hmac
import secrets
import threading
from datetime import datetime
from collections import deque
from enum import Enum
from colorama import init, Fore, Style

# Import new security modules
try:
    from security_monitor import SecurityMonitor as PortSecurityMonitor
    from security_display import SecurityDisplay
    from llm_security_agent import LLMSecurityAgent
    SECURITY_MODULES_AVAILABLE = True
except ImportError:
    SECURITY_MODULES_AVAILABLE = False
    print("Warning: Security modules not available")

init()

class NIMDAIntegrated:
    def __init__(self):
        self.running = True
        self.lockdown_active = False
        self.menu_active = True
        self.monitors = {}
        
        # Інформаційні деки для збереження даних
        self.network_data = deque(maxlen=1000)
        self.processes_data = deque(maxlen=500)
        self.gpu_data = deque(maxlen=500)
        self.security_events = deque(maxlen=1000)
        self.anomalies = deque(maxlen=500)
        self.system_logs = deque(maxlen=1000)
        
        # Підозрілі паттерни
        self.suspicious_ports = {22, 2222, 4444, 5555, 8080, 9999, 31337, 1337}
        self.suspicious_processes = {'ssh', 'sshd', 'nc', 'netcat', 'ncat', 'socat', 'telnet'}
        self.mining_processes = {'xmrig', 'ethminer', 'cgminer', 'bfgminer', 'claymore'}
        
        # Ініціалізувати підсистеми
        self.secure_enclave = SecureEnclaveKey()
        self.lockdown_system = LockdownSystem()
        self.sound_alert_system = SoundAlertSystem()
        
        # Initialize security monitoring if available
        if SECURITY_MODULES_AVAILABLE:
            self.port_security_monitor = PortSecurityMonitor()
            self.security_display = SecurityDisplay()
            self.llm_agent = LLMSecurityAgent()
        
        # Налаштувати обробники сигналів
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Обробка сигналів для правильного завершення"""
        print(f"\n{Fore.YELLOW}🛑 Отримано сигнал {signum}, завершення роботи...{Style.RESET_ALL}")
        self.running = False
        self.menu_active = False
        
        # Stop security monitoring
        if SECURITY_MODULES_AVAILABLE:
            self.port_security_monitor.stop_monitoring()
        
    def print_banner(self):
        """Банер системи"""
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║                          NIMDA INTEGRATED SECURITY                          ║")
        print("║                      Інтегрована система безпеки                           ║")
        print("║                                                                            ║")
        print("║    🔐 Система блокування    📊 Багатоекранний моніторинг    🔧 Інтерактивне керування       ║")
        if SECURITY_MODULES_AVAILABLE:
            print("║    🔒 Порт-моніторинг    🤖 LLM-аналіз    🛡️ Розумна безпека                              ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
    def setup_tmux_layout(self):
        print(f"{Fore.CYAN}🚀 Setting up NIMDA integrated interface...{Style.RESET_ALL}")
        subprocess.run(["tmux", "kill-session", "-t", "nimda_integrated"], check=False)
        subprocess.run([
            "tmux", "new-session", "-d", "-s", "nimda_integrated", 
            "-x", "200", "-y", "60"
        ])
        subprocess.run(["tmux", "rename-window", "-t", "nimda_integrated:0", "NIMDA"])
        
        # Enhanced layout with security monitoring
        # Split horizontally: left (Network, Process, GPU, Security, Logs), right (System Info + Menu)
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA", "-h"])
        
        # Left column: split vertically for Network (top) and Process (bottom)
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA.0", "-v"])
        
        # Process pane: split vertically for Process (top) and GPU (bottom)
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA.2", "-v"])
        
        # GPU pane: split vertically for GPU (top) and Security (bottom)
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA.4", "-v"])
        
        # Security pane: split vertically for Security (top) and Logs (bottom)
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA.6", "-v"])
        
        # Rightmost pane: split vertically for System Info (top) and Menu (bottom, 18 lines)
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA.1", "-v", "-l", "18"])
        
        time.sleep(1)
        
        # Define monitors with security modules if available
        monitors = [
            ("nimda_integrated:NIMDA.0", f'python3 -c "import sys; sys.path.append(\'{os.getcwd()}\'); from nimda_integrated import NetworkMonitor; NetworkMonitor().run()"'),
            ("nimda_integrated:NIMDA.2", f'python3 -c "import sys; sys.path.append(\'{os.getcwd()}\'); from nimda_integrated import ProcessMonitor; ProcessMonitor().run()"'),
            ("nimda_integrated:NIMDA.4", f'python3 -c "import sys; sys.path.append(\'{os.getcwd()}\'); from nimda_integrated import GPUMonitor; GPUMonitor().run()"'),
        ]
        
        # Add security monitors if available
        if SECURITY_MODULES_AVAILABLE:
            monitors.extend([
                ("nimda_integrated:NIMDA.6", f'python3 -c "import sys; sys.path.append(\'{os.getcwd()}\'); from security_display import SecurityDisplay; SecurityDisplay().run_simple()"'),
                ("nimda_integrated:NIMDA.8", f'python3 -c "import sys; sys.path.append(\'{os.getcwd()}\'); from nimda_integrated import LogMonitor; LogMonitor().run()"'),
            ])
        else:
            monitors.extend([
                ("nimda_integrated:NIMDA.6", f'python3 -c "import sys; sys.path.append(\'{os.getcwd()}\'); from nimda_integrated import SecurityMonitor; SecurityMonitor().run()"'),
                ("nimda_integrated:NIMDA.8", f'python3 -c "import sys; sys.path.append(\'{os.getcwd()}\'); from nimda_integrated import LogMonitor; LogMonitor().run()"'),
            ])
        
        monitors.extend([
            ("nimda_integrated:NIMDA.1", f'python3 -c "import sys; sys.path.append(\'{os.getcwd()}\'); from nimda_integrated import SystemMonitor; SystemMonitor().run()"'),
            ("nimda_integrated:NIMDA.9", f'python3 -c "import sys; sys.path.append(\'{os.getcwd()}\'); from nimda_integrated import InteractiveMenu; InteractiveMenu().run()"')
        ])
        
        for pane, command in monitors:
            subprocess.run(["tmux", "send-keys", "-t", pane, command, "Enter"])
        
        # Start security monitoring in background if available
        if SECURITY_MODULES_AVAILABLE:
            print(f"{Fore.GREEN}🔒 Starting security monitoring...{Style.RESET_ALL}")
            self.port_security_monitor.start_monitoring()
        
        subprocess.run(["tmux", "select-pane", "-t", "nimda_integrated:NIMDA.9"])
        print(f"{Fore.GREEN}✅ TMUX layout created successfully{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📋 Interface instructions:{Style.RESET_ALL}")
        print("  • Pane 0: Network Monitor")
        print("  • Pane 2: Process Monitor")
        print("  • Pane 4: GPU Monitor")
        if SECURITY_MODULES_AVAILABLE:
            print("  • Pane 6: Security Events & Ports (Enhanced)")
        else:
            print("  • Pane 6: Security Events")
        print("  • Pane 8: System Logs")
        print("  • Pane 1: System Information (rightmost top)")
        print("  • Pane 9: Interactive Menu (rightmost bottom)")
        
        if SECURITY_MODULES_AVAILABLE:
            print(f"\n{Fore.CYAN}🔒 Security Features:{Style.RESET_ALL}")
            print("  • Port monitoring (USB, Thunderbolt, Network, Bluetooth)")
            print("  • LLM-powered security analysis")
            print("  • Real-time device connection tracking")
            print("  • Intelligent threat detection")
        
        print(f"\n{Fore.CYAN}🎮 Navigation:{Style.RESET_ALL}")
        print("  • Ctrl+B + Arrows - move between panes")
        print("  • Ctrl+L - disable lockdown (from menu)")
        print("  • Ctrl+C - exit")
        
    def run(self):
        """Запустити інтегровану систему"""
        self.print_banner()
        
        # Налаштувати TMUX інтерфейс
        self.setup_tmux_layout()
        
        # Підключитися до сесії
        try:
            subprocess.run(["tmux", "attach-session", "-t", "nimda_integrated"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}👋 Вихід з NIMDA...{Style.RESET_ALL}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Очистити ресурси перед виходом"""
        print(f"{Fore.CYAN}🧹 Очищення...{Style.RESET_ALL}")
        
        # Stop security monitoring
        if SECURITY_MODULES_AVAILABLE:
            print(f"{Fore.CYAN}🔒 Stopping security monitoring...{Style.RESET_ALL}")
            self.port_security_monitor.stop_monitoring()
        
        subprocess.run(["tmux", "kill-session", "-t", "nimda_integrated"], check=False)
        
        if self.lockdown_active:
            print(f"{Fore.YELLOW}🔓 Відключення блокування...{Style.RESET_ALL}")
            self.lockdown_system.disable_lockdown()


class SecureEnclaveKey:
    """Система роботи з ключами для lockdown"""
    
    def __init__(self):
        self.key_id = "nimda_lockdown_key"
        self.key_exists = self.check_key_exists()
    
    def check_key_exists(self):
        """Перевірити існування ключа"""
        key_file = os.path.expanduser("~/.nimda_lockdown_key")
        return os.path.exists(key_file)
    
    def create_key(self):
        """Створити новий ключ"""
        try:
            key_data = secrets.token_bytes(32)
            key_file = os.path.expanduser("~/.nimda_lockdown_key")
            
            with open(key_file, 'wb') as f:
                f.write(key_data)
            os.chmod(key_file, 0o600)
            
            self.key_exists = True
            return True
        except Exception as e:
            print(f"Error creating key: {e}")
            return False
    
    def get_key(self):
        """Отримати ключ"""
        try:
            key_file = os.path.expanduser("~/.nimda_lockdown_key")
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    return f.read()
            return None
        except Exception:
            return None
    
    def verify_key(self, provided_key):
        """Перевірити ключ"""
        stored_key = self.get_key()
        if stored_key is None:
            return False
        return hmac.compare_digest(stored_key, provided_key.encode())


class LockdownSystem:
    """Система lockdown для блокування периферії"""
    
    def __init__(self):
        self.active = False
        self.blocked_services = []
        self.sound_system = SoundAlertSystem()
        
    def enable_lockdown(self):
        """Увімкнути lockdown"""
        try:
            print(f"{Fore.RED}🔒 Увімкнення режиму блокування...{Style.RESET_ALL}")
            
            # Звукове сповіщення про активацію lockdown
            self.sound_system.trigger_alert(
                AlertType.LOCKDOWN_BREACH,
                ThreatLevel.CRITICAL,
                "Lockdown mode activated. All external connections blocked."
            )
            
            # Блокуємо WiFi
            subprocess.run(["sudo", "ifconfig", "en0", "down"], check=False)
            self.blocked_services.append("WiFi")
            
            # Блокуємо Bluetooth
            subprocess.run(["sudo", "defaults", "write", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState", "-int", "0"], check=False)
            self.blocked_services.append("Bluetooth")
            
            self.active = True
            print(f"{Fore.GREEN}✅ Lockdown enabled. Blocked: {', '.join(self.blocked_services)}{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}❌ Lockdown failed: {e}{Style.RESET_ALL}")
            self.sound_system.trigger_alert(
                AlertType.SYSTEM_ERROR,
                ThreatLevel.HIGH,
                f"Lockdown activation failed: {str(e)}"
            )
            return False
    
    def disable_lockdown(self):
        """Вимкнути lockdown"""
        try:
            print(f"{Fore.YELLOW}🔓 Відключення режиму блокування...{Style.RESET_ALL}")
            
            # Звукове сповіщення про деактивацію lockdown
            self.sound_system.trigger_alert(
                AlertType.SYSTEM_ERROR,
                ThreatLevel.MEDIUM,
                "Lockdown mode deactivated. External connections restored."
            )
            
            # Відновити WiFi
            if "WiFi" in self.blocked_services:
                subprocess.run(["sudo", "ifconfig", "en0", "up"], check=False)
            
            # Відновити Bluetooth
            if "Bluetooth" in self.blocked_services:
                subprocess.run(["sudo", "defaults", "write", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState", "-int", "1"], check=False)
            
            self.blocked_services.clear()
            self.active = False
            print(f"{Fore.GREEN}✅ Lockdown disabled{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}❌ Lockdown disable failed: {e}{Style.RESET_ALL}")
            self.sound_system.trigger_alert(
                AlertType.SYSTEM_ERROR,
                ThreatLevel.HIGH,
                f"Lockdown deactivation failed: {str(e)}"
            )
            return False


class InteractiveMenu:
    """Інтерактивне меню управління"""
    
    def __init__(self):
        self.running = True
        self.lockdown_system = LockdownSystem()
        self.secure_enclave = SecureEnclaveKey()
        self.sound_system = SoundAlertSystem()
        
        # Initialize security features if available
        if SECURITY_MODULES_AVAILABLE:
            self.llm_agent = LLMSecurityAgent()
        
    def run(self):
        """Запустити інтерактивне меню"""
        # Очистити екран меню
        print("\033[2J\033[H")
        
        while self.running:
            self.show_menu()
            self.handle_input()
            time.sleep(0.1)
    
    def show_menu(self):
        print("\033[2J\033[H")
        print(f"{Fore.CYAN}" + "=" * 60)
        print("         🚨 NIMDA CONTROL PANEL 🚨")  
        print("=" * 60 + f"{Style.RESET_ALL}")
        lockdown_status = f"{Fore.RED}🔒 LOCKED" if self.lockdown_system.active else f"{Fore.GREEN}🔓 UNLOCKED"
        print(f"{Fore.YELLOW}Status: {lockdown_status}{Style.RESET_ALL} | Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"{Fore.CYAN}-" * 60 + f"{Style.RESET_ALL}")
        print(f"[L]ockdown  [U]nlock  [1-6] Focus Panel  [S]can  [C]lear Logs  [R]estart  [I]nfo")
        print(f"[T]est Sound  [M]ute  [E]mergency Siren  [A]lert Demo  [Q]uit  [Ctrl+C] Stop")
        if SECURITY_MODULES_AVAILABLE:
            print(f"[B]Security Analysis  [D]evice Check  [H]Threat Intel  [O]LLM Query")
        print(f"{Fore.CYAN}-" * 60 + f"{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Ready for commands! Use hotkeys above. TMUX: Ctrl+B + Arrows to move.{Style.RESET_ALL}")
    
    def handle_input(self):
        """Обробити введення користувача"""
        try:
            # Неблокуючий ввід
            import select
            import sys
            import termios
            import tty
            
            if select.select([sys.stdin], [], [], 0.1)[0]:
                # Перевірити на Ctrl+L (ASCII 12)
                old_settings = termios.tcgetattr(sys.stdin)
                try:
                    tty.setraw(sys.stdin.fileno())
                    ch = sys.stdin.read(1)
                    if ord(ch) == 12:  # Ctrl+L
                        self.disable_lockdown()
                        return
                finally:
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                
                command = ch.lower()
                
                if command == 'l':
                    self.enable_lockdown()
                elif command == 'u':
                    self.disable_lockdown()
                elif command in '123456':
                    self.focus_panel(int(command) - 1)
                elif command == 's':
                    self.run_system_scan()
                elif command == 'c':
                    self.clear_logs()
                elif command == 'r':
                    self.restart_monitors()
                elif command == 'i':
                    self.show_system_info()
                elif command == 't':
                    self.test_sounds()
                elif command == 'm':
                    self.toggle_sound()
                elif command == 'e':
                    self.test_emergency()
                elif command == 'a':
                    self.demo_alerts()
                elif command == 'q':
                    self.quit_nimda()
                # Security features
                elif command == 'b' and SECURITY_MODULES_AVAILABLE:
                    self.security_analysis()
                elif command == 'd' and SECURITY_MODULES_AVAILABLE:
                    self.device_check()
                elif command == 'h' and SECURITY_MODULES_AVAILABLE:
                    self.threat_intelligence()
                elif command == 'o' and SECURITY_MODULES_AVAILABLE:
                    self.ollama_query()
                    
        except Exception:
            pass
    
    def enable_lockdown(self):
        """Увімкнути lockdown"""
        if not self.secure_enclave.key_exists:
            if not self.secure_enclave.create_key():
                print(f"{Fore.RED}❌ Failed to create security key{Style.RESET_ALL}")
                return
        
        self.lockdown_system.enable_lockdown()
    
    def disable_lockdown(self):
        """Вимкнути lockdown"""
        self.lockdown_system.disable_lockdown()
    
    def focus_panel(self, panel_num):
        """Фокус на панель"""
        subprocess.run(["tmux", "select-pane", "-t", f"nimda_integrated:NIMDA.{panel_num}"], check=False)
    
    def run_system_scan(self):
        """Запустити сканування системи"""
        print(f"{Fore.CYAN}🔍 Запуск сканування системи...{Style.RESET_ALL}")
        # Тут можна додати логіку сканування
    
    def clear_logs(self):
        """Очистити логи"""
        try:
            for log_file in ['security_monitor.log', 'nimda.log']:
                if os.path.exists(log_file):
                    open(log_file, 'w').close()
            print(f"{Fore.GREEN}✅ Логи очищено{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Не вдалося очистити логи: {e}{Style.RESET_ALL}")
    
    def restart_monitors(self):
        """Перезапустити монітори"""
        print(f"{Fore.CYAN}🔄 Перезапуск моніторів...{Style.RESET_ALL}")
        # Логіка перезапуску моніторів
    
    def show_system_info(self):
        """Показати інформацію про систему"""
        print(f"{Fore.CYAN}ℹ️ Інформація про систему відображається в панелі 1{Style.RESET_ALL}")
        self.focus_panel(1)
    
    def test_sounds(self):
        """Тестувати звуки"""
        print(f"{Fore.CYAN}🔊 Тестування звуків...{Style.RESET_ALL}")
        self.sound_system.trigger_alert(
            AlertType.SYSTEM_ERROR,
            ThreatLevel.LOW,
            "Sound test - NIMDA security system"
        )
    
    def toggle_sound(self):
        """Перемикати звук"""
        print(f"{Fore.CYAN}🔇 Перемикання звуку...{Style.RESET_ALL}")
        # Логіка перемикання звуку
    
    def test_emergency(self):
        """Тестувати аварійну сирену"""
        print(f"{Fore.RED}🚨 Тестування аварійної сирени...{Style.RESET_ALL}")
        self.sound_system.emergency_siren()
    
    def demo_alerts(self):
        """Демонстрація сповіщень"""
        print(f"{Fore.CYAN}🎭 Демонстрація сповіщень...{Style.RESET_ALL}")
        alerts = [
            (AlertType.NETWORK_INTRUSION, ThreatLevel.HIGH, "Network intrusion detected"),
            (AlertType.SUSPICIOUS_PROCESS, ThreatLevel.MEDIUM, "Suspicious process detected"),
            (AlertType.GPU_MINING, ThreatLevel.CRITICAL, "GPU mining activity detected"),
            (AlertType.PERIPHERAL_DETECTED, ThreatLevel.LOW, "New peripheral device connected")
        ]
        
        for alert_type, threat_level, message in alerts:
            self.sound_system.trigger_alert(alert_type, threat_level, message)
            time.sleep(2)
    
    def security_analysis(self):
        """Запустити аналіз безпеки"""
        if not SECURITY_MODULES_AVAILABLE:
            print(f"{Fore.RED}❌ Security modules not available{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}🔒 Запуск аналізу безпеки...{Style.RESET_ALL}")
        try:
            events = self.llm_agent.security_monitor.get_recent_events(10)
            if events:
                analysis = self.llm_agent.analyze_security_events(events)
                print(f"{Fore.GREEN}📊 Security Analysis:{Style.RESET_ALL}")
                print(analysis)
            else:
                print(f"{Fore.YELLOW}ℹ️ No recent security events to analyze{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Security analysis failed: {e}{Style.RESET_ALL}")
    
    def device_check(self):
        """Перевірити підключені пристрої"""
        if not SECURITY_MODULES_AVAILABLE:
            print(f"{Fore.RED}❌ Security modules not available{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}🔍 Перевірка підключених пристроїв...{Style.RESET_ALL}")
        try:
            system_info = self.llm_agent.security_monitor.get_system_info()
            devices = self.llm_agent.security_monitor.extract_devices(system_info)
            
            if devices:
                print(f"{Fore.GREEN}📱 Connected Devices:{Style.RESET_ALL}")
                for device_id, device_info in devices.items():
                    print(f"  • {device_info['name']} ({device_info['type']})")
            else:
                print(f"{Fore.YELLOW}ℹ️ No devices currently connected{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Device check failed: {e}{Style.RESET_ALL}")
    
    def threat_intelligence(self):
        """Отримати розвідку загроз"""
        if not SECURITY_MODULES_AVAILABLE:
            print(f"{Fore.RED}❌ Security modules not available{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}🛡️ Отримання розвідки загроз...{Style.RESET_ALL}")
        try:
            query = "current security threats and recommendations"
            intelligence = self.llm_agent.get_threat_intelligence(query)
            print(f"{Fore.GREEN}🛡️ Threat Intelligence:{Style.RESET_ALL}")
            print(intelligence)
        except Exception as e:
            print(f"{Fore.RED}❌ Threat intelligence failed: {e}{Style.RESET_ALL}")
    
    def ollama_query(self):
        """Відправити запит до Ollama"""
        if not SECURITY_MODULES_AVAILABLE:
            print(f"{Fore.RED}❌ Security modules not available{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}🤖 Ollama Query Mode{Style.RESET_ALL}")
        print("Enter your security question (or 'cancel' to exit):")
        
        try:
            query = input("> ").strip()
            if query.lower() == 'cancel':
                return
            
            if query:
                print(f"{Fore.CYAN}🤖 Processing query...{Style.RESET_ALL}")
                context = self.llm_agent.get_security_context(1)
                response = self.llm_agent.query_ollama(query, context)
                print(f"{Fore.GREEN}🤖 Response:{Style.RESET_ALL}")
                print(response)
        except Exception as e:
            print(f"{Fore.RED}❌ Ollama query failed: {e}{Style.RESET_ALL}")
    
    def quit_nimda(self):
        """Вийти з NIMDA"""
        self.running = False
        subprocess.run(["tmux", "kill-session", "-t", "nimda_integrated"], check=False)


class NetworkMonitor:
    """Монітор мережевої активності"""
    
    def __init__(self):
        self.permission_error_shown = False
        self.last_netstat_time = 0
        self.netstat_cache = []
    
    def get_netstat_connections(self):
        """Отримати з'єднання через netstat"""
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            connections = []
            
            for line in lines:
                if 'tcp' in line.lower() or 'udp' in line.lower():
                    parts = line.split()
                    if len(parts) >= 6:
                        proto = parts[0]
                        local = parts[3]
                        remote = parts[4]
                        state = parts[5] if len(parts) > 5 else 'N/A'
                        connections.append({
                            'protocol': proto,
                            'local': local,
                            'remote': remote,
                            'state': state
                        })
            return connections
        except Exception:
            return []
    
    def run(self):
        """Start network monitor"""
        print("\033[2J\033[H")  # Clear the screen at the very start
        print(f"{Fore.CYAN}🌐 NETWORK MONITOR{Style.RESET_ALL}")
        print("=" * 50)
        
        while True:
            try:
                current_time = time.time()
                connections = []
                use_netstat = False
                
                # Try psutil first
                try:
                    connections = psutil.net_connections(kind='inet')
                except (psutil.AccessDenied, PermissionError):
                    if not self.permission_error_shown:
                        print(f"{Fore.YELLOW}⚠️  Access denied for detailed connection information.{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}   Using netstat as fallback...{Style.RESET_ALL}")
                        self.permission_error_shown = True
                    use_netstat = True
                
                if use_netstat:
                    # Cache netstat result for 5 seconds
                    if current_time - self.last_netstat_time > 5:
                        self.netstat_cache = self.get_netstat_connections()
                        self.last_netstat_time = current_time
                    
                    print(f"\033[2J\033[H{Fore.CYAN}🌐 NETWORK CONNECTIONS (netstat){Style.RESET_ALL}")
                    print("=" * 60)
                    print(f"{'Protocol':<8}{'Local Address':<25}{'Remote Address':<25}{'State':<12}")
                    print("-" * 70)
                    
                    for i, conn in enumerate(self.netstat_cache[:15]):
                        if conn['state'] in ['ESTABLISHED', 'CONNECTED']:
                            color = Fore.GREEN
                        elif conn['state'] in ['LISTEN', 'TIME_WAIT']:
                            color = Fore.YELLOW
                        else:
                            color = Fore.WHITE
                        
                        print(f"{color}{conn['protocol']:<8}{conn['local']:<25}{conn['remote']:<25}{conn['state']:<12}{Style.RESET_ALL}")
                    
                    established = len([c for c in self.netstat_cache if c['state'] == 'ESTABLISHED'])
                    print(f"\n{Fore.GREEN}Established: {established}{Style.RESET_ALL} | {Fore.YELLOW}Total: {len(self.netstat_cache)}{Style.RESET_ALL}")
                
                else:
                    # Use psutil
                    print(f"\033[2J\033[H{Fore.CYAN}🌐 NETWORK CONNECTIONS ({len(connections)}){Style.RESET_ALL}")
                    print("=" * 60)
                    print(f"{'PID':<8}{'Local Address':<25}{'Remote Address':<25}{'Status':<12}")
                    print("-" * 70)
                    
                    active_connections = 0
                    for conn in connections[:15]:  # Show only first 15
                        if conn.status == 'ESTABLISHED':
                            active_connections += 1
                            color = Fore.GREEN
                        elif conn.status in ['LISTEN', 'TIME_WAIT']:
                            color = Fore.YELLOW
                        else:
                            color = Fore.WHITE
                        
                        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                        
                        print(f"{color}{conn.pid or 'N/A':<8}{local:<25}{remote:<25}{conn.status:<12}{Style.RESET_ALL}")
                    
                    print(f"\n{Fore.GREEN}Active: {active_connections}{Style.RESET_ALL} | {Fore.YELLOW}Total: {len(connections)}{Style.RESET_ALL}")
                
                # Show network statistics
                net_io = psutil.net_io_counters()
                print(f"\n{Fore.BLUE}📊 Network I/O:{Style.RESET_ALL}")
                print(f"  Bytes sent: {net_io.bytes_sent:,}")
                print(f"  Bytes received: {net_io.bytes_recv:,}")
                print(f"  Packets sent: {net_io.packets_sent:,}")
                print(f"  Packets received: {net_io.packets_recv:,}")
                
                print(f"\n{Fore.CYAN}🕒 Time: {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")
                
                time.sleep(3)
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Network monitor stopped.{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                time.sleep(5)


class ProcessMonitor:
    """Монітор процесів"""
    
    def __init__(self):
        self.sound_system = SoundAlertSystem()
        self.suspicious_processes = {'ssh', 'sshd', 'nc', 'netcat', 'ncat', 'socat', 'telnet'}
        self.mining_processes = {'xmrig', 'ethminer', 'cgminer', 'bfgminer', 'claymore'}
    
    def run(self):
        print("\033[2J\033[H")  # Clear the screen at the very start
        """Start process monitor"""
        print(f"{Fore.GREEN}⚙️ PROCESS MONITOR{Style.RESET_ALL}")
        error_count = 0
        
        while True:
            try:
                processes = []
                access_denied_count = 0
                
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        proc_info = proc.info
                        # Filter system processes with no access
                        if proc_info['pid'] and proc_info['name']:
                            processes.append(proc_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        access_denied_count += 1
                        continue
                    except Exception:
                        # Ignore other errors
                        continue
                
                # Sort by CPU
                processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
                
                print(f"\033[H{Fore.GREEN}⚙️ TOP PROCESSES (CPU){Style.RESET_ALL}")
                print("=" * 50)
                print(f"{'PID':<8}{'Name':<20}{'CPU%':<8}{'Mem%':<8}")
                print("-" * 44)
                
                displayed_count = 0
                for proc in processes:
                    if displayed_count >= 12:  # Top 12 processes
                        break
                        
                    cpu_percent = proc['cpu_percent'] or 0
                    mem_percent = proc['memory_percent'] or 0
                    proc_name = proc['name'].lower() if proc['name'] else 'unknown'
                    
                    # Check for suspicious processes
                    if proc_name in self.suspicious_processes:
                        self.sound_system.trigger_alert(
                            AlertType.SUSPICIOUS_PROCESS,
                            ThreatLevel.HIGH,
                            f"Suspicious process detected: {proc['name']}"
                        )
                        color = Fore.RED
                    elif proc_name in self.mining_processes:
                        self.sound_system.trigger_alert(
                            AlertType.GPU_MINING,
                            ThreatLevel.CRITICAL,
                            f"Mining process detected: {proc['name']}"
                        )
                        color = Fore.RED
                    elif cpu_percent > 80:  # High CPU usage
                        self.sound_system.trigger_alert(
                            AlertType.SYSTEM_ERROR,
                            ThreatLevel.MEDIUM,
                            f"High CPU usage: {proc['name']} ({cpu_percent:.1f}%)"
                        )
                        color = Fore.RED
                    elif cpu_percent > 50:
                        color = Fore.YELLOW
                    elif cpu_percent > 20:
                        color = Fore.YELLOW
                    else:
                        color = Fore.WHITE
                    
                    safe_name = (proc['name'] or 'unknown')[:19]
                    print(f"{color}{proc['pid']:<8}{safe_name:<20}{cpu_percent:<8.1f}{mem_percent:<8.1f}{Style.RESET_ALL}")
                    displayed_count += 1
                
                # Show statistics at bottom
                if access_denied_count > 0:
                    print(f"\n{Fore.YELLOW}Note: {access_denied_count} system processes hidden{Style.RESET_ALL}")
                
                print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
                error_count = 0  # Reset error counter on successful execution
                time.sleep(3)
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Process monitor stopped.{Style.RESET_ALL}")
                break
            except Exception as e:
                error_count += 1
                if error_count <= 3:  # Show only first 3 errors
                    print(f"{Fore.RED}Process monitor error: {str(e)[:50]}...{Style.RESET_ALL}")
                time.sleep(5)


class GPUMonitor:
    """Монітор GPU для Apple Silicon"""
    
    def run(self):
        print("\033[2J\033[H")  # Clear the screen at the very start
        """Start GPU monitor"""
        print(f"{Fore.MAGENTA}🎮 GPU MONITOR APPLE SILICON{Style.RESET_ALL}")
        
        while True:
            try:
                # Get GPU information via system_profiler
                cmd = ['system_profiler', 'SPDisplaysDataType', '-json']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                print(f"\033[H{Fore.MAGENTA}🎮 GPU APPLE SILICON{Style.RESET_ALL}")
                print("=" * 50)
                
                if result.returncode == 0:
                    try:
                        data = json.loads(result.stdout)
                        displays = data.get('SPDisplaysDataType', [])
                        
                        for display in displays:
                            vendor = display.get('spdisplays_vendor', 'Unknown')
                            if 'Apple' in vendor:
                                model = display.get('spdisplays_device-id', 'Unknown')
                                vram = display.get('spdisplays_vram', 'Unified Memory')
                                
                                print(f"Vendor: {vendor}")
                                print(f"Model: {model}")
                                print(f"Video Memory: {vram}")
                                break
                    except json.JSONDecodeError:
                        print("Apple Silicon GPU detected")
                
                # Show processes with high CPU (as GPU load approximation)
                print(f"\n{Fore.YELLOW}PROCESSES WITH HIGH CPU (similar to GPU):{Style.RESET_ALL}")
                print("-" * 40)
                
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        info = proc.info
                        if info['cpu_percent'] and info['cpu_percent'] > 10:
                            processes.append(info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
                
                for proc in processes[:8]:
                    cpu = proc['cpu_percent']
                    color = Fore.RED if cpu > 50 else Fore.YELLOW if cpu > 25 else Fore.WHITE
                    print(f"{color}{proc['pid']:<8}{proc['name'][:15]:<16}{cpu:>6.1f}%{Style.RESET_ALL}")
                
                print(f"\nTime: {datetime.now().strftime('%H:%M:%S')}")
                time.sleep(4)
                
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                time.sleep(5)


class SecurityMonitor:
    """Монітор подій безпеки"""
    
    def __init__(self):
        self.events = deque(maxlen=100)
        self.suspicious_ports = {22, 2222, 4444, 5555, 8080, 9999, 31337, 1337}
        self.sound_system = SoundAlertSystem()
        self.permission_error_shown = False
        self.last_netstat_time = 0
        self.netstat_cache = []
    
    def get_netstat_connections(self):
        """Отримати з'єднання через netstat для SecurityMonitor"""
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            connections = []
            
            for line in lines:
                if 'tcp' in line.lower() or 'udp' in line.lower():
                    parts = line.split()
                    if len(parts) >= 4:
                        local = parts[3]
                        if '.' in local and ':' in local:
                            try:
                                port = int(local.split(':')[-1])
                                connections.append({
                                    'port': port,
                                    'address': local,
                                    'state': parts[5] if len(parts) > 5 else 'UNKNOWN'
                                })
                            except (ValueError, IndexError):
                                continue
            return connections
        except Exception:
            return []
    
    def run(self):
        print("\033[2J\033[H")  # Clear the screen at the very start
        """Start security monitor"""
        print(f"{Fore.RED}🛡️ SECURITY MONITOR{Style.RESET_ALL}")
        
        while True:
            try:
                # Clear screen properly for TMUX
                print(f"\033[2J\033[H{Fore.RED}🛡️ SECURITY EVENTS{Style.RESET_ALL}")
                print("=" * 50)
                
                # Check suspicious connections
                suspicious_found = 0
                connections = []
                use_netstat = False
                
                # Try psutil first
                try:
                    connections = psutil.net_connections(kind='inet')
                    # Process psutil connections
                    for conn in connections:
                        if conn.laddr and conn.laddr.port in self.suspicious_ports:
                            suspicious_found += 1
                            event = {
                                'time': datetime.now().strftime('%H:%M:%S'),
                                'type': 'Suspicious Port',
                                'details': f"Port {conn.laddr.port} ({conn.status})"
                            }
                            self.events.append(event)
                            
                            # Sound alert for suspicious ports
                            self._trigger_port_alert(conn.laddr.port)
                            
                except (psutil.AccessDenied, PermissionError):
                    if not self.permission_error_shown:
                        print(f"{Fore.YELLOW}⚠️  Using netstat for security monitoring...{Style.RESET_ALL}")
                        self.permission_error_shown = True
                    use_netstat = True
                
                if use_netstat:
                    # Cache netstat result for 5 seconds
                    current_time = time.time()
                    if current_time - self.last_netstat_time > 5:
                        self.netstat_cache = self.get_netstat_connections()
                        self.last_netstat_time = current_time
                    
                    # Process netstat connections
                    for conn in self.netstat_cache:
                        if conn['port'] in self.suspicious_ports:
                            suspicious_found += 1
                            event = {
                                'time': datetime.now().strftime('%H:%M:%S'),
                                'type': 'Suspicious Port',
                                'details': f"Port {conn['port']} ({conn['state']})"
                            }
                            self.events.append(event)
                            
                            # Sound alert for suspicious ports
                            self._trigger_port_alert(conn['port'])
                
                # Show recent events
                print(f"{'Time':<10}{'Type':<15}{'Details':<25}")
                print("-" * 50)
                
                if not self.events:
                    print(f"{Fore.GREEN}No security events detected{Style.RESET_ALL}")
                else:
                    for event in list(self.events)[-10:]:  # Last 10 events
                        print(f"{Fore.YELLOW}{event['time']:<10}{event['type']:<15}{event['details']:<25}{Style.RESET_ALL}")
                
                print(f"\n{Fore.RED}Active suspicious ports: {suspicious_found}{Style.RESET_ALL}")
                print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
                
                time.sleep(3)
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Security monitor stopped.{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}Security monitor error: {str(e)[:50]}...{Style.RESET_ALL}")
                time.sleep(5)
    
    def _trigger_port_alert(self, port):
        """Запустити звукове сповіщення для підозрілого порту"""
        if port in {22, 2222}:  # SSH порти
            self.sound_system.trigger_alert(
                AlertType.SSH_CONNECTION, 
                ThreatLevel.HIGH,
                f"SSH connection on port {port}"
            )
        elif port in {4444, 5555, 31337, 1337}:  # Hacker ports
            self.sound_system.trigger_alert(
                AlertType.NETWORK_INTRUSION,
                ThreatLevel.CRITICAL,
                f"Active suspicious port {port}"
            )
        else:
            self.sound_system.trigger_alert(
                AlertType.PORT_SCAN,
                ThreatLevel.MEDIUM,
                f"Unusual activity on port {port}"
            )


class LogMonitor:
    """Монітор системних логів"""
    
    def run(self):
        print("\033[2J\033[H")  # Clear the screen at the very start
        while True:
            try:
                print(f"\033[H{Fore.BLUE}📋 SYSTEM LOGS [RECENT MODE]{Style.RESET_ALL}")
                print("=" * 50)
                cmd = ['log', 'show', '--last', '1m', '--predicate', 'category == "security"', '--style', 'compact']
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.stdout:
                        lines = result.stdout.strip().split('\n')[-10:]
                        for line in lines:
                            if 'error' in line.lower() or 'fail' in line.lower():
                                print(f"{Fore.RED}{line[:70]}{Style.RESET_ALL}")
                            elif 'warn' in line.lower():
                                print(f"{Fore.YELLOW}{line[:70]}{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.WHITE}{line[:70]}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}No security logs found in this period{Style.RESET_ALL}")
                except subprocess.TimeoutExpired:
                    if os.path.exists('security_monitor.log'):
                        with open('security_monitor.log', 'r') as f:
                            lines = f.readlines()[-10:]
                            for line in lines:
                                print(f"{Fore.WHITE}{line.strip()[:70]}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}Logs unavailable{Style.RESET_ALL}")
                print(f"\nTime: {datetime.now().strftime('%H:%M:%S')}")
                time.sleep(5)
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                time.sleep(5)


class SystemMonitor:
    """System information monitor"""
    
    def run(self):
        print("\033[2J\033[H")  # Clear the screen at the very start
        """Start system monitor"""
        print(f"{Fore.WHITE}💻 SYSTEM MONITOR{Style.RESET_ALL}")
        
        while True:
            try:
                print(f"\033[H{Fore.WHITE}💻 SYSTEM INFORMATION{Style.RESET_ALL}")
                print("=" * 50)
                
                # CPU information
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_count = psutil.cpu_count()
                
                # Memory
                memory = psutil.virtual_memory()
                
                # Disk
                disk = psutil.disk_usage('/')
                
                # Network
                net_io = psutil.net_io_counters()
                
                print(f"{'CPU Usage:':<15} {cpu_percent:>6.1f}% ({cpu_count} cores)")
                print(f"{'Memory:':<15} {memory.percent:>6.1f}% ({memory.used//1024//1024//1024}GB/{memory.total//1024//1024//1024}GB)")
                print(f"{'Disk Usage:':<15} {disk.percent:>6.1f}% ({disk.used//1024//1024//1024}GB/{disk.total//1024//1024//1024}GB)")
                
                print(f"\n{Fore.CYAN}Network I/O:{Style.RESET_ALL}")
                print(f"{'Bytes sent:':<15} {net_io.bytes_sent//1024//1024:>6}MB")
                print(f"{'Bytes received:':<15} {net_io.bytes_recv//1024//1024:>6}MB")
                
                # System
                boot_time = datetime.fromtimestamp(psutil.boot_time())
                uptime = datetime.now() - boot_time
                
                print(f"\n{Fore.GREEN}System:{Style.RESET_ALL}")
                print(f"{'Boot time:':<15} {boot_time.strftime('%Y-%m-%d %H:%M')}")
                print(f"{'Uptime:':<15} {str(uptime).split('.')[0]}")
                print(f"{'Load average:':<15} {os.getloadavg()[0]:.2f}")
                
                print(f"\nTime: {datetime.now().strftime('%H:%M:%S')}")
                time.sleep(4)
                
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                time.sleep(5)


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
            ThreatLevel.LOW: 30,      # 30 seconds
            ThreatLevel.MEDIUM: 15,   # 15 seconds
            ThreatLevel.HIGH: 5,      # 5 seconds
            ThreatLevel.CRITICAL: 2,  # 2 seconds
            ThreatLevel.EMERGENCY: 1  # 1 second (siren)
        }
        
        # Системні звуки macOS
        self.system_sounds = {
            ThreatLevel.LOW: "Tink",
            ThreatLevel.MEDIUM: "Pop",
            ThreatLevel.HIGH: "Sosumi",
            ThreatLevel.CRITICAL: "Basso",
            ThreatLevel.EMERGENCY: "Funk"
        }
        
        self.emergency_active = False
        self.emergency_thread = None
        
    def play_system_sound(self, sound_name):
        """Відтворити системний звук macOS"""
        try:
            subprocess.run(['afplay', f'/System/Library/Sounds/{sound_name}.aiff'], 
                         check=False, capture_output=True)
        except Exception:
            subprocess.run(['say', 'Alert'], check=False, capture_output=True)
    
    def generate_beep_sequence(self, threat_level):
        """Генерувати послідовність звукових сигналів"""
        beep_patterns = {
            ThreatLevel.LOW: [1],           
            ThreatLevel.MEDIUM: [1, 1],     
            ThreatLevel.HIGH: [1, 1, 1],    
            ThreatLevel.CRITICAL: [2, 1, 2], 
            ThreatLevel.EMERGENCY: [3, 3, 3] 
        }
        
        pattern = beep_patterns.get(threat_level, [1])
        
        for duration in pattern:
            if duration == 1:
                subprocess.run(['osascript', '-e', 'beep 1'], check=False)
            elif duration == 2:
                subprocess.run(['osascript', '-e', 'beep 2'], check=False)
            else:
                subprocess.run(['osascript', '-e', 'beep 3'], check=False)
            time.sleep(0.2)
    
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
            
            subprocess.run(['say', '-v', voice, '-r', rate, message], check=False)
            
        except Exception:
            subprocess.run(['osascript', '-e', 'beep'], check=False)
    
    def emergency_siren(self):
        """Emergency siren for highest threat level"""
        siren_messages = [
            "EMERGENCY SITUATION! SECURITY BREACH DETECTED!",
            "SYSTEM UNDER ATTACK!",
            "CRITICAL THREAT LEVEL!",
            "IMMEDIATE SECURITY MEASURES REQUIRED!"
        ]
        
        while self.emergency_active:
            for freq in [800, 1000, 800, 1000, 800]:
                if not self.emergency_active:
                    break
                subprocess.run(['osascript', '-e', f'beep {freq//200}'], check=False)
                time.sleep(0.1)
            
            if self.emergency_active:
                message = siren_messages[int(time.time()) % len(siren_messages)]
                self.play_voice_alert(message, ThreatLevel.EMERGENCY)
            
            time.sleep(2)
    
    def start_emergency_siren(self):
        """Start emergency siren"""
        if not self.emergency_active:
            self.emergency_active = True
            self.emergency_thread = threading.Thread(target=self.emergency_siren, daemon=True)
            self.emergency_thread.start()
            print(f"{Fore.RED}🚨 EMERGENCY SIREN ACTIVATED{Style.RESET_ALL}")
    
    def stop_emergency_siren(self):
        """Stop emergency siren"""
        if self.emergency_active:
            self.emergency_active = False
            if self.emergency_thread:
                self.emergency_thread.join(timeout=1)
            print(f"{Fore.YELLOW}🔇 Emergency siren stopped{Style.RESET_ALL}")
    
    def can_play_alert(self, alert_type, threat_level):
        """Перевірити чи можна відтворити сповіщення"""
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
    
    def trigger_alert(self, alert_type, threat_level, message="Security alert", details=""):
        """Trigger sound alert"""
        if not self.can_play_alert(alert_type, threat_level):
            return
        
        print(f"{Fore.YELLOW}🔊 Sound alert: {alert_type.value} - {threat_level.name}{Style.RESET_ALL}")
        
        if threat_level == ThreatLevel.EMERGENCY:
            self.start_emergency_siren()
            return
        
        def play_alert():
            try:
                # Play system sound
                sound_name = self.system_sounds.get(threat_level, "Tink")
                self.play_system_sound(sound_name)
                
                # Generate beep sequence
                self.generate_beep_sequence(threat_level)
                
                # Play voice alert for high threat levels
                if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                    self.play_voice_alert(message, threat_level)
                    
            except Exception as e:
                print(f"{Fore.RED}Sound alert error: {e}{Style.RESET_ALL}")
        
        # Run in separate thread to avoid blocking
        threading.Thread(target=play_alert, daemon=True).start()
    
    def enable_sound(self):
        """Увімкнути звук"""
        self.sound_enabled = True
        print(f"{Fore.GREEN}🔊 Звукові сповіщення увімкнено{Style.RESET_ALL}")
    
    def disable_sound(self):
        """Вимкнути звук"""
        self.sound_enabled = False
        self.stop_emergency_siren()
        print(f"{Fore.YELLOW}🔇 Звукові сповіщення вимкнено{Style.RESET_ALL}")


def main():
    """Головна функція"""
    if len(sys.argv) == 1:
        # Запустити повний інтерфейс
        nimda = NIMDAIntegrated()
        nimda.run()
    else:
        # Запустити окремий монітор (для TMUX панелей)
        monitor_type = sys.argv[1]
        
        if monitor_type == "network":
            NetworkMonitor().run()
        elif monitor_type == "process":
            ProcessMonitor().run()
        elif monitor_type == "gpu":
            GPUMonitor().run()
        elif monitor_type == "security":
            SecurityMonitor().run()
        elif monitor_type == "logs":
            LogMonitor().run()
        elif monitor_type == "system":
            SystemMonitor().run()
        elif monitor_type == "menu":
            InteractiveMenu().run()
        else:
            print(f"Невідомий тип монітора: {monitor_type}")


if __name__ == "__main__":
    main()
