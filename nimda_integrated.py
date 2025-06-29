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
        
        # Налаштувати обробники сигналів
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Обробка сигналів для правильного завершення"""
        print(f"\n{Fore.YELLOW}🛑 Received signal {signum}, shutting down...{Style.RESET_ALL}")
        self.running = False
        self.menu_active = False
        
    def print_banner(self):
        """Банер системи"""
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║                          NIMDA INTEGRATED SECURITY                          ║")
        print("║                      Інтегрована система безпеки                           ║")
        print("║                                                                            ║")
        print("║    🔐 Lockdown System    📊 Multi-Monitor    🔧 Interactive Control       ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
    def setup_tmux_layout(self):
        """Налаштувати TMUX з 6 моніторами та інтерактивним меню"""
        print(f"{Fore.CYAN}🚀 Setting up NIMDA integrated interface...{Style.RESET_ALL}")
        
        # Видалити існуючу сесію
        subprocess.run(["tmux", "kill-session", "-t", "nimda_integrated"], check=False)
        
        # Створити нову сесію
        subprocess.run([
            "tmux", "new-session", "-d", "-s", "nimda_integrated", 
            "-x", "200", "-y", "60"  # Великий розмір для 6 панелей
        ])
        
        # Перейменувати вікно
        subprocess.run(["tmux", "rename-window", "-t", "nimda_integrated:0", "NIMDA"])
        
        # Розділити на 6 панелей
        # Верхній ряд: Network | Processes | GPU
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA", "-h"])  # Horizontal split
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA.1", "-h"])  # Split right pane
        
        # Нижній ряд: Security | Logs | System
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA.0", "-v"])  # Vertical split left
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA.2", "-v"])  # Vertical split middle
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA.4", "-v"])  # Vertical split right
        
        # Створити окремий маленький пейн для меню внизу
        subprocess.run(["tmux", "split-window", "-t", "nimda_integrated:NIMDA", "-v", "-l", "12"])  # 12 рядків для меню
        
        time.sleep(1)  # Дати час на створення панелей
        
        # Запустити моніторинг в кожній панелі
        monitors = [
            ("nimda_integrated:NIMDA.0", f"python3 -c \"import sys; sys.path.append('{os.getcwd()}'); from nimda_integrated import NetworkMonitor; NetworkMonitor().run()\""),
            ("nimda_integrated:NIMDA.1", f"python3 -c \"import sys; sys.path.append('{os.getcwd()}'); from nimda_integrated import ProcessMonitor; ProcessMonitor().run()\""),
            ("nimda_integrated:NIMDA.2", f"python3 -c \"import sys; sys.path.append('{os.getcwd()}'); from nimda_integrated import GPUMonitor; GPUMonitor().run()\""),
            ("nimda_integrated:NIMDA.3", f"python3 -c \"import sys; sys.path.append('{os.getcwd()}'); from nimda_integrated import SecurityMonitor; SecurityMonitor().run()\""),
            ("nimda_integrated:NIMDA.4", f"python3 -c \"import sys; sys.path.append('{os.getcwd()}'); from nimda_integrated import LogMonitor; LogMonitor().run()\""),
            ("nimda_integrated:NIMDA.5", f"python3 -c \"import sys; sys.path.append('{os.getcwd()}'); from nimda_integrated import SystemMonitor; SystemMonitor().run()\""),
            ("nimda_integrated:NIMDA.6", f"python3 -c \"import sys; sys.path.append('{os.getcwd()}'); from nimda_integrated import InteractiveMenu; InteractiveMenu().run()\"")
        ]
        
        for pane, command in monitors:
            subprocess.run(["tmux", "send-keys", "-t", pane, command, "Enter"])
        
        # Фокус на меню
        subprocess.run(["tmux", "select-pane", "-t", "nimda_integrated:NIMDA.6"])
        
        print(f"{Fore.GREEN}✅ TMUX layout created successfully{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📋 Interface Guide:{Style.RESET_ALL}")
        print("  • Панель 0: Network Monitor")
        print("  • Панель 1: Process Monitor") 
        print("  • Панель 2: GPU Monitor")
        print("  • Панель 3: Security Events")
        print("  • Панель 4: System Logs")
        print("  • Панель 5: System Info")
        print("  • Панель 6: Interactive Menu (Control Panel)")
        print(f"\n{Fore.CYAN}🎮 Navigation:{Style.RESET_ALL}")
        print("  • Ctrl+B + Arrow Keys - переміщення між панелами")
        print("  • Ctrl+L - відключити lockdown (з меню)")
        print("  • Ctrl+C - вихід")
        
    def run(self):
        """Запустити інтегровану систему"""
        self.print_banner()
        
        # Налаштувати TMUX інтерфейс
        self.setup_tmux_layout()
        
        # Підключитися до сесії
        try:
            subprocess.run(["tmux", "attach-session", "-t", "nimda_integrated"])
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}👋 Exiting NIMDA...{Style.RESET_ALL}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Очистити ресурси перед виходом"""
        print(f"{Fore.CYAN}🧹 Cleaning up...{Style.RESET_ALL}")
        subprocess.run(["tmux", "kill-session", "-t", "nimda_integrated"], check=False)
        
        if self.lockdown_active:
            print(f"{Fore.YELLOW}🔓 Disabling lockdown...{Style.RESET_ALL}")
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
            print(f"{Fore.RED}🔒 Enabling lockdown mode...{Style.RESET_ALL}")
            
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
            print(f"{Fore.YELLOW}🔓 Disabling lockdown mode...{Style.RESET_ALL}")
            
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
        
    def run(self):
        """Запустити інтерактивне меню"""
        # Очистити екран меню
        print("\033[2J\033[H")
        
        while self.running:
            self.show_menu()
            self.handle_input()
            time.sleep(0.1)
    
    def show_menu(self):
        """Показати меню"""
        print("\033[H")  # Перейти до верху
        print(f"{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗")
        print("║                    NIMDA CONTROL PANEL                        ║")
        print(f"╠════════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        
        # Статус lockdown
        lockdown_status = f"{Fore.RED}🔒 ACTIVE" if self.lockdown_system.active else f"{Fore.GREEN}🔓 INACTIVE"
        print(f"║ Lockdown Status: {lockdown_status:<45} ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠════════════════════════════════════════════════════════════════╣{Style.RESET_ALL}")
        
        print(f"║ {Fore.YELLOW}🔒 LOCKDOWN CONTROLS{Style.RESET_ALL}                                       ║")
        print("║   L - Enable Lockdown    │   U - Disable Lockdown           ║")
        print("║                                                              ║")
        print(f"║ {Fore.CYAN}📊 DISPLAY CONTROLS{Style.RESET_ALL}                                       ║")
        print("║   1 - Focus Network      │   2 - Focus Processes            ║")
        print("║   3 - Focus GPU          │   4 - Focus Security             ║")
        print("║   5 - Focus Logs         │   6 - Focus System Info          ║")
        print("║                                                              ║")
        print(f"║ {Fore.MAGENTA}⚡ QUICK ACTIONS{Style.RESET_ALL}                                         ║")
        print("║   S - System Scan        │   C - Clear Logs                 ║")
        print("║   R - Restart Monitors   │   I - System Info                ║")
        print("║                                                              ║")
        print(f"║ {Fore.BLUE}🔊 SOUND CONTROLS{Style.RESET_ALL}                                        ║")
        print("║   T - Test Sounds        │   M - Mute/Unmute Sounds         ║")
        print("║   E - Emergency Test     │   A - Alert Demo                 ║")
        print("║                                                              ║")
        print(f"║ {Fore.RED}❌ EXIT{Style.RESET_ALL}                                                   ║")
        print("║   Q - Quit NIMDA         │   Ctrl+C - Emergency Exit        ║")
        print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Hotkeys: Ctrl+L = Disable Lockdown | Ctrl+C = Exit{Style.RESET_ALL}")
        print(f"Current time: {datetime.now().strftime('%H:%M:%S')}")
    
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
        print(f"{Fore.CYAN}🔍 Running system scan...{Style.RESET_ALL}")
        # Тут можна додати логіку сканування
    
    def clear_logs(self):
        """Очистити логи"""
        try:
            for log_file in ['security_monitor.log', 'nimda.log']:
                if os.path.exists(log_file):
                    open(log_file, 'w').close()
            print(f"{Fore.GREEN}✅ Logs cleared{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to clear logs: {e}{Style.RESET_ALL}")
    
    def restart_monitors(self):
        """Перезапустити монітори"""
        print(f"{Fore.CYAN}🔄 Restarting monitors...{Style.RESET_ALL}")
        # Логіка перезапуску моніторів
    
    def show_system_info(self):
        """Показати інформацію про систему"""
        print(f"{Fore.CYAN}ℹ️ System Info displayed in panel 5{Style.RESET_ALL}")
        self.focus_panel(5)
    
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
        """Запустити монітор мережі"""
        print(f"{Fore.CYAN}🌐 NETWORK MONITOR{Style.RESET_ALL}")
        print("=" * 50)
        
        while True:
            try:
                current_time = time.time()
                connections = []
                use_netstat = False
                
                # Спробувати psutil спочатку
                try:
                    connections = psutil.net_connections(kind='inet')
                except (psutil.AccessDenied, PermissionError):
                    if not self.permission_error_shown:
                        print(f"{Fore.YELLOW}⚠️  Permission denied for detailed connection info.{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}   Using netstat fallback...{Style.RESET_ALL}")
                        self.permission_error_shown = True
                    use_netstat = True
                
                if use_netstat:
                    # Кешувати netstat результат на 5 секунд
                    if current_time - self.last_netstat_time > 5:
                        self.netstat_cache = self.get_netstat_connections()
                        self.last_netstat_time = current_time
                    
                    print(f"\033[H{Fore.CYAN}🌐 NETWORK CONNECTIONS (netstat){Style.RESET_ALL}")
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
                    # Використати psutil
                    print(f"\033[H{Fore.CYAN}🌐 NETWORK CONNECTIONS ({len(connections)}){Style.RESET_ALL}")
                    print("=" * 60)
                    print(f"{'PID':<8}{'Local Address':<25}{'Remote Address':<25}{'Status':<12}")
                    print("-" * 70)
                    
                    active_connections = 0
                    for conn in connections[:15]:  # Показати тільки перші 15
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
                
                # Показати мережеву статистику
                net_io = psutil.net_io_counters()
                print(f"\n{Fore.BLUE}📊 Network I/O:{Style.RESET_ALL}")
                print(f"  Bytes sent: {net_io.bytes_sent:,}")
                print(f"  Bytes recv: {net_io.bytes_recv:,}")
                print(f"  Packets sent: {net_io.packets_sent:,}")
                print(f"  Packets recv: {net_io.packets_recv:,}")
                
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
        """Запустити монітор процесів"""
        print(f"{Fore.GREEN}⚙️ PROCESS MONITOR{Style.RESET_ALL}")
        
        while True:
            try:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        processes.append(proc.info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Сортувати за CPU
                processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
                
                print(f"\033[H{Fore.GREEN}⚙️ TOP PROCESSES (CPU){Style.RESET_ALL}")
                print("=" * 50)
                print(f"{'PID':<8}{'Name':<20}{'CPU%':<8}{'MEM%':<8}")
                print("-" * 44)
                
                for proc in processes[:12]:  # Топ 12 процесів
                    cpu_percent = proc['cpu_percent'] or 0
                    mem_percent = proc['memory_percent'] or 0
                    proc_name = proc['name'].lower()
                    
                    # Перевірка на підозрілі процеси
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
                    elif cpu_percent > 80:  # Високе використання CPU
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
                    
                    print(f"{color}{proc['pid']:<8}{proc['name'][:19]:<20}{cpu_percent:<8.1f}{mem_percent:<8.1f}{Style.RESET_ALL}")
                
                print(f"\nTime: {datetime.now().strftime('%H:%M:%S')}")
                time.sleep(3)
                
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                time.sleep(5)


class GPUMonitor:
    """Монітор GPU для Apple Silicon"""
    
    def run(self):
        """Запустити монітор GPU"""
        print(f"{Fore.MAGENTA}🎮 APPLE SILICON GPU MONITOR{Style.RESET_ALL}")
        
        while True:
            try:
                # Отримати інформацію про GPU через system_profiler
                cmd = ['system_profiler', 'SPDisplaysDataType', '-json']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                print(f"\033[H{Fore.MAGENTA}🎮 APPLE SILICON GPU{Style.RESET_ALL}")
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
                                print(f"VRAM: {vram}")
                                break
                    except json.JSONDecodeError:
                        print("Apple Silicon GPU detected")
                
                # Показати процеси з високим CPU (як наближення GPU навантаження)
                print(f"\n{Fore.YELLOW}HIGH CPU PROCESSES (GPU-like):{Style.RESET_ALL}")
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
    
    def run(self):
        """Запустити монітор безпеки"""
        print(f"{Fore.RED}🛡️ SECURITY MONITOR{Style.RESET_ALL}")
        
        while True:
            try:
                print(f"\033[H{Fore.RED}🛡️ SECURITY EVENTS{Style.RESET_ALL}")
                print("=" * 50)
                
                # Перевірити підозрілі з'єднання
                suspicious_found = 0
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    if conn.laddr and conn.laddr.port in self.suspicious_ports:
                        suspicious_found += 1
                        event = {
                            'time': datetime.now().strftime('%H:%M:%S'),
                            'type': 'Suspicious Port',
                            'details': f"Port {conn.laddr.port} ({conn.status})"
                        }
                        self.events.append(event)
                        
                        # Звукове сповіщення для підозрілих портів
                        if conn.laddr.port in {22, 2222}:  # SSH порти
                            self.sound_system.trigger_alert(
                                AlertType.SSH_CONNECTION, 
                                ThreatLevel.HIGH,
                                f"SSH connection on port {conn.laddr.port}"
                            )
                        elif conn.laddr.port in {4444, 5555, 31337, 1337}:  # Хакерські порти
                            self.sound_system.trigger_alert(
                                AlertType.NETWORK_INTRUSION,
                                ThreatLevel.CRITICAL,
                                f"Suspicious port {conn.laddr.port} active"
                            )
                        else:
                            self.sound_system.trigger_alert(
                                AlertType.PORT_SCAN,
                                ThreatLevel.MEDIUM,
                                f"Unusual port activity {conn.laddr.port}"
                            )
                
                # Показати останні події
                print(f"{'Time':<10}{'Type':<15}{'Details':<25}")
                print("-" * 50)
                
                if not self.events:
                    print(f"{Fore.GREEN}No security events detected{Style.RESET_ALL}")
                else:
                    for event in list(self.events)[-10:]:  # Останні 10 подій
                        print(f"{Fore.YELLOW}{event['time']:<10}{event['type']:<15}{event['details']:<25}{Style.RESET_ALL}")
                
                print(f"\n{Fore.RED}Suspicious ports active: {suspicious_found}{Style.RESET_ALL}")
                print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
                
                time.sleep(3)
                
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                time.sleep(5)


class LogMonitor:
    """Монітор системних логів"""
    
    def run(self):
        """Запустити монітор логів"""
        print(f"{Fore.BLUE}📋 LOG MONITOR{Style.RESET_ALL}")
        
        while True:
            try:
                print(f"\033[H{Fore.BLUE}📋 SYSTEM LOGS{Style.RESET_ALL}")
                print("=" * 50)
                
                # Отримати останні системні логи
                try:
                    cmd = ['log', 'show', '--last', '1m', '--predicate', 'category == "security"', '--style', 'compact']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.stdout:
                        lines = result.stdout.strip().split('\n')[-10:]  # Останні 10 рядків
                        for line in lines:
                            if 'error' in line.lower() or 'fail' in line.lower():
                                print(f"{Fore.RED}{line[:70]}{Style.RESET_ALL}")
                            elif 'warn' in line.lower():
                                print(f"{Fore.YELLOW}{line[:70]}{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.WHITE}{line[:70]}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}No recent security logs{Style.RESET_ALL}")
                        
                except subprocess.TimeoutExpired:
                    # Fallback - показати логи NIMDA
                    if os.path.exists('security_monitor.log'):
                        with open('security_monitor.log', 'r') as f:
                            lines = f.readlines()[-10:]
                            for line in lines:
                                print(f"{Fore.WHITE}{line.strip()[:70]}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}No logs available{Style.RESET_ALL}")
                
                print(f"\nTime: {datetime.now().strftime('%H:%M:%S')}")
                time.sleep(5)
                
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
                time.sleep(5)


class SystemMonitor:
    """Монітор системної інформації"""
    
    def run(self):
        """Запустити системний монітор"""
        print(f"{Fore.WHITE}💻 SYSTEM MONITOR{Style.RESET_ALL}")
        
        while True:
            try:
                print(f"\033[H{Fore.WHITE}💻 SYSTEM INFORMATION{Style.RESET_ALL}")
                print("=" * 50)
                
                # CPU інформація
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_count = psutil.cpu_count()
                
                # Память
                memory = psutil.virtual_memory()
                
                # Диск
                disk = psutil.disk_usage('/')
                
                # Мережа
                net_io = psutil.net_io_counters()
                
                print(f"{'CPU Usage:':<15} {cpu_percent:>6.1f}% ({cpu_count} cores)")
                print(f"{'Memory:':<15} {memory.percent:>6.1f}% ({memory.used//1024//1024//1024}GB/{memory.total//1024//1024//1024}GB)")
                print(f"{'Disk Usage:':<15} {disk.percent:>6.1f}% ({disk.used//1024//1024//1024}GB/{disk.total//1024//1024//1024}GB)")
                
                print(f"\n{Fore.CYAN}Network I/O:{Style.RESET_ALL}")
                print(f"{'Bytes Sent:':<15} {net_io.bytes_sent//1024//1024:>6}MB")
                print(f"{'Bytes Recv:':<15} {net_io.bytes_recv//1024//1024:>6}MB")
                
                # Система
                boot_time = datetime.fromtimestamp(psutil.boot_time())
                uptime = datetime.now() - boot_time
                
                print(f"\n{Fore.GREEN}System:{Style.RESET_ALL}")
                print(f"{'Boot Time:':<15} {boot_time.strftime('%Y-%m-%d %H:%M')}")
                print(f"{'Uptime:':<15} {str(uptime).split('.')[0]}")
                print(f"{'Load Avg:':<15} {os.getloadavg()[0]:.2f}")
                
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
        """Аварійна сирена для найвищого рівня загрози"""
        siren_messages = [
            "EMERGENCY! SECURITY BREACH DETECTED!",
            "СИСТЕМА ПІД АТАКОЮ!",
            "CRITICAL THREAT LEVEL!",
            "НЕВІДКЛАДНІ ЗАХОДИ БЕЗПЕКИ!"
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
        """Запустити аварійну сирену"""
        if not self.emergency_active:
            self.emergency_active = True
            self.emergency_thread = threading.Thread(target=self.emergency_siren, daemon=True)
            self.emergency_thread.start()
            print(f"{Fore.RED}🚨 EMERGENCY SIREN ACTIVATED{Style.RESET_ALL}")
    
    def stop_emergency_siren(self):
        """Зупинити аварійну сирену"""
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
    
    def trigger_alert(self, alert_type, threat_level, message="Security Alert", details=""):
        """Запустити звукове сповіщення"""
        if not self.can_play_alert(alert_type, threat_level):
            return
        
        print(f"{Fore.YELLOW}🔊 Sound Alert: {alert_type.value} - {threat_level.name}{Style.RESET_ALL}")
        
        if threat_level == ThreatLevel.EMERGENCY:
            self.start_emergency_siren()
            return
        
        def play_alert():
            try:
                sound_name = self.system_sounds[threat_level]
                self.play_system_sound(sound_name)
                time.sleep(0.3)
                
                self.generate_beep_sequence(threat_level)
                time.sleep(0.5)
                
                if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    alert_messages = {
                        AlertType.NETWORK_INTRUSION: "Network intrusion detected",
                        AlertType.SUSPICIOUS_PROCESS: "Suspicious process detected", 
                        AlertType.GPU_MINING: "Possible mining activity detected",
                        AlertType.LOCKDOWN_BREACH: "Lockdown system breach",
                        AlertType.SYSTEM_ERROR: "Critical system error",
                        AlertType.PERIPHERAL_DETECTED: "Unauthorized peripheral detected",
                        AlertType.SSH_CONNECTION: "Suspicious SSH connection",
                        AlertType.PORT_SCAN: "Port scanning detected"
                    }
                    
                    voice_message = alert_messages.get(alert_type, message)
                    if details:
                        voice_message += f". {details}"
                    
                    self.play_voice_alert(voice_message, threat_level)
                
            except Exception as e:
                print(f"{Fore.RED}Sound alert error: {e}{Style.RESET_ALL}")
        
        alert_thread = threading.Thread(target=play_alert, daemon=True)
        alert_thread.start()
    
    def enable_sound(self):
        """Увімкнути звук"""
        self.sound_enabled = True
        print(f"{Fore.GREEN}🔊 Sound alerts enabled{Style.RESET_ALL}")
    
    def disable_sound(self):
        """Вимкнути звук"""
        self.sound_enabled = False
        self.stop_emergency_siren()
        print(f"{Fore.YELLOW}🔇 Sound alerts disabled{Style.RESET_ALL}")


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
            print(f"Unknown monitor type: {monitor_type}")


if __name__ == "__main__":
    main()
