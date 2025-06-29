#!/usr/bin/env python3
"""
NIMDA Security System - Comprehensive Tkinter GUI
Full security monitoring with network analysis, port scanning, anomaly detection, and LLM integration
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import time
import json
import sqlite3
import subprocess
import os
import sys
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Tuple
import queue
import requests
import socket
import psutil
import platform
from collections import defaultdict
import re
import getpass
import keyring
import hashlib
import base64

# Import security modules
try:
    from security_monitor import SecurityMonitor, SecurityEvent
    from security_display import SecurityDisplay
    from llm_security_agent import LLMSecurityAgent
    from ai_providers import AIProviderManager
    from task_scheduler import TaskScheduler, TaskType, ScheduleType, ScheduledTask
    SECURITY_MODULES_AVAILABLE = True
except ImportError:
    SECURITY_MODULES_AVAILABLE = False
    print("Warning: Security modules not available")

# Import enhanced sound system
from sound_alerts_enhanced import SoundAlertSystem, ThreatLevel as SoundThreatLevel

class ThreatLevel(Enum):
    """Threat levels with colors and actions"""
    LOW = ("LOW", "🟢", "#28a745", "Низький")
    MEDIUM = ("MEDIUM", "🟡", "#ffc107", "Середній") 
    HIGH = ("HIGH", "🟠", "#fd7e14", "Високий")
    CRITICAL = ("CRITICAL", "🔴", "#dc3545", "Критичний")
    EMERGENCY = ("EMERGENCY", "⚫", "#000000", "Надзвичайний")

class SecurityAction(Enum):
    """Security actions for different threat levels"""
    MONITOR = "monitor"
    LOG = "log"
    ANALYZE = "analyze"
    BLOCK = "block"
    ISOLATE = "isolate"
    TERMINATE = "terminate"
    BACKUP = "backup"
    ALERT = "alert"
    AI_ANALYSIS = "ai_analysis"
    TRACE_ATTACK = "trace_attack"
    DETECT_TROJAN = "detect_trojan"
    ISOLATE_FILE = "isolate_file"
    DEEP_ANALYSIS = "deep_analysis"
    QUARANTINE = "quarantine"
    REMOVE_MALWARE = "remove_malware"
    ANALYZE_ECOSYSTEM = "analyze_ecosystem"
    CLEAN_TEMP = "clean_temp"

class SecurityPolicy:
    """Security policy configuration"""
    
    def __init__(self):
        self.policies = {
            ThreatLevel.LOW: [SecurityAction.MONITOR, SecurityAction.LOG],
            ThreatLevel.MEDIUM: [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ANALYZE, SecurityAction.DETECT_TROJAN],
            ThreatLevel.HIGH: [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ANALYZE, SecurityAction.BLOCK, SecurityAction.ALERT, SecurityAction.DETECT_TROJAN, SecurityAction.DEEP_ANALYSIS],
            ThreatLevel.CRITICAL: [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ANALYZE, SecurityAction.BLOCK, SecurityAction.ISOLATE, SecurityAction.AI_ANALYSIS, SecurityAction.ALERT, SecurityAction.DETECT_TROJAN, SecurityAction.ISOLATE_FILE, SecurityAction.ANALYZE_ECOSYSTEM],
            ThreatLevel.EMERGENCY: [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ANALYZE, SecurityAction.BLOCK, SecurityAction.ISOLATE, SecurityAction.TERMINATE, SecurityAction.BACKUP, SecurityAction.AI_ANALYSIS, SecurityAction.TRACE_ATTACK, SecurityAction.ALERT, SecurityAction.DETECT_TROJAN, SecurityAction.ISOLATE_FILE, SecurityAction.DEEP_ANALYSIS, SecurityAction.QUARANTINE, SecurityAction.REMOVE_MALWARE, SecurityAction.ANALYZE_ECOSYSTEM, SecurityAction.CLEAN_TEMP]
        }
        self.load_policy()
    
    def load_policy(self):
        """Load policy from file"""
        try:
            if os.path.exists("security_policy.json"):
                with open("security_policy.json", 'r') as f:
                    data = json.load(f)
                    for level_str, actions in data.items():
                        level = ThreatLevel[level_str]
                        self.policies[level] = [SecurityAction(action) for action in actions]
        except Exception as e:
            print(f"Failed to load security policy: {e}")
    
    def save_policy(self):
        """Save policy to file"""
        try:
            data = {}
            for level, actions in self.policies.items():
                data[level.name] = [action.value for action in actions]
            
            with open("security_policy.json", 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to save security policy: {e}")
    
    def get_actions_for_level(self, level: ThreatLevel) -> List[SecurityAction]:
        """Get actions for threat level"""
        return self.policies.get(level, [])
    
    def update_policy(self, level: ThreatLevel, actions: List[SecurityAction]):
        """Update policy for specific level"""
        self.policies[level] = actions
        self.save_policy()

class ThreatAnalyzer:
    """Analyze threats and determine threat levels"""
    
    def __init__(self, security_policy: SecurityPolicy):
        self.policy = security_policy
        
    def analyze_port_threat(self, port: int, service: str) -> ThreatLevel:
        """Analyze port threat level"""
        # Критичні порти
        critical_ports = [22, 23, 3389, 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910]
        if port in critical_ports:
            return ThreatLevel.CRITICAL
        
        # Підозрілі порти
        suspicious_ports = [4444, 5555, 31337, 1337, 6667, 6668, 6669, 7000, 8081, 9090, 8080, 8443]
        if port in suspicious_ports:
            return ThreatLevel.HIGH
        
        # Порти для моніторингу
        monitor_ports = [21, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432]
        if port in monitor_ports:
            return ThreatLevel.MEDIUM
        
        return ThreatLevel.LOW
    
    def analyze_address_threat(self, address: str) -> ThreatLevel:
        """Analyze address threat level"""
        try:
            ip, port = address.split(':') if ':' in address else (address, 'N/A')
            
            # Локальні адреси
            if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
                return ThreatLevel.LOW
            
            # Відомі безпечні IP
            safe_ips = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
            if ip in safe_ips:
                return ThreatLevel.LOW
            
            # Підозрілі IP діапазони
            suspicious_ranges = [
                ('192.168.1.', '192.168.1.255'),
                ('10.0.0.', '10.0.0.255'),
                ('172.16.0.', '172.31.255.255')
            ]
            
            for start, end in suspicious_ranges:
                if ip.startswith(start.split('.')[0] + '.' + start.split('.')[1] + '.' + start.split('.')[2] + '.'):
                    return ThreatLevel.MEDIUM
            
            # Зовнішні IP
            return ThreatLevel.HIGH
            
        except:
            return ThreatLevel.MEDIUM
    
    def analyze_anomaly_threat(self, anomaly: Dict) -> ThreatLevel:
        """Analyze anomaly threat level"""
        anomaly_type = anomaly.get('type', '').upper()
        severity = anomaly.get('severity', 'MEDIUM').upper()
        
        # Критичні аномалії
        if 'CRITICAL' in severity or 'SUSPICIOUS_PROCESS' in anomaly_type:
            return ThreatLevel.CRITICAL
        
        # Високі аномалії
        if 'HIGH' in severity or 'CPU_SPIKE' in anomaly_type or 'MEMORY_CRITICAL' in anomaly_type:
            return ThreatLevel.HIGH
        
        # Середні аномалії
        if 'MEDIUM' in severity or 'NETWORK' in anomaly_type:
            return ThreatLevel.MEDIUM
        
        return ThreatLevel.LOW
    
    def execute_actions(self, threat_level: ThreatLevel, target: str, details: Dict, smart_handler=None):
        """Execute SMART security actions for threat level"""
        # Determine threat type and use smart response
        threat_type = None
        threat_data = details
        
        # Identify threat type from target and details
        if ':' in str(target) and any(c.isdigit() for c in str(target)):
            # IP:Port format
            threat_type = 'ip_connection'
            if '.' in str(target):
                parts = str(target).split('.')
                if len(parts) >= 4:
                    ip_port = str(target).split(':')
                    threat_data = {
                        'remote_address': ip_port[0] if len(ip_port) > 0 else str(target),
                        'port': ip_port[1] if len(ip_port) > 1 else '443',
                        **details
                    }
        elif str(target).startswith('Port '):
            # Port format
            threat_type = 'port_scan'
            port_num = str(target).replace('Port ', '')
            threat_data = {
                'port': port_num,
                'service': details.get('service', 'unknown'),
                **details
            }
        elif 'Anomaly:' in str(target):
            # Anomaly format
            threat_type = 'anomaly'
            anomaly_name = str(target).replace('Anomaly: ', '')
            threat_data = {
                'type': anomaly_name,
                **details
            }
        else:
            # Generic threat
            threat_type = 'generic'
            threat_data = {'target': target, **details}
        
        # Use smart threat response if available
        if threat_type and smart_handler and hasattr(smart_handler, 'smart_threat_response'):
            response = smart_handler.smart_threat_response(threat_type, threat_data, threat_level.name)
            if response:
                print(f"🧠 SMART RESPONSE: {response}")
            else:
                print(f"🔇 Silent handling: {target}")
        else:
            # Fallback to simple logging (MUCH less spam)
            print(f"📝 Simple log: {target} - {threat_level.value[3]}")
    
    def _action_monitor(self, target: str, details: Dict):
        """Monitor target"""
        print(f"🔍 Monitoring: {target}")
    
    def _action_log(self, target: str, details: Dict, level: ThreatLevel):
        """Log security event"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'target': target,
            'threat_level': level.value,
            'details': details
        }
        print(f"📝 Logged: {target} - {level.value}")
    
    def _action_analyze(self, target: str, details: Dict):
        """Analyze target"""
        print(f"🔬 Analyzing: {target}")
    
    def _action_block(self, target: str, details: Dict):
        """Block target with real firewall rules"""
        print(f"🚫 Blocking: {target}")
        
        try:
            # Extract IP address from target
            if target.startswith("Port "):
                # Block port
                port = details.get('port', '')
                if port:
                    # Block port using pfctl (macOS firewall)
                    block_command = f"echo 'block drop in proto tcp from any to any port {port}' | sudo pfctl -ef -"
                    success, output = self.execute_with_privileges(block_command, require_privileges=True)
                    if success:
                        print(f"✅ Port {port} blocked successfully")
                    else:
                        print(f"❌ Failed to block port {port}: {output}")
            else:
                # Block IP address
                # Extract IP from target (e.g., "104.18.19.125.443" -> "104.18.19.125")
                ip_parts = target.split('.')
                if len(ip_parts) >= 4:
                    ip = '.'.join(ip_parts[:4])
                    
                    # Block IP using pfctl
                    block_command = f"echo 'block drop in from {ip} to any' | sudo pfctl -ef -"
                    success, output = self.execute_with_privileges(block_command, require_privileges=True)
                    if success:
                        print(f"✅ IP {ip} blocked successfully")
                    else:
                        print(f"❌ Failed to block IP {ip}: {output}")
                        
        except Exception as e:
            print(f"❌ Block action failed: {e}")
    
    def _action_isolate(self, target: str, details: Dict):
        """Isolate target"""
        print(f"🔒 Isolating: {target}")
    
    def _action_terminate(self, target: str, details: Dict):
        """Terminate target"""
        print(f"💀 Terminating: {target}")
    
    def _action_backup(self, target: str, details: Dict):
        """Backup data"""
        print(f"💾 Backing up: {target}")
    
    def _action_alert(self, target: str, details: Dict, level: ThreatLevel):
        """Send alert"""
        print(f"🚨 Alert: {target} - {level.value}")
    
    def _action_ai_analysis(self, target: str, details: Dict, level: ThreatLevel):
        """AI analysis"""
        print(f"🤖 AI Analysis: {target} - {level.value}")
    
    def _action_trace_attack(self, target: str, details: Dict):
        """Trace attack source"""
        print(f"🔍 Tracing attack: {target}")
    
    def execute_with_privileges(self, command: str, require_privileges: bool = True) -> Tuple[bool, str]:
        """Execute command with privileges"""
        try:
            if require_privileges:
                # Use sudo for privileged commands
                result = subprocess.run(['sudo', '-n'] + command.split(), 
                                      capture_output=True, text=True, timeout=30)
            else:
                # Execute without privileges
                result = subprocess.run(command.split(), 
                                      capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    def _action_clean_temp(self, target: str, details: Dict):
        """Clean temporary files"""
        print(f"🧹 Cleaning temporary files for: {target}")
        try:
            import shutil
            import glob
            import os
            
            removed = []
            errors = []
            
            # Списки директорій та масок файлів
            temp_dirs = [
                '/tmp/nimda_quarantine',
                '/tmp/nimda_analysis',
                os.path.expanduser('~/NIMDA_Emergency_Backup'),
            ]
            temp_files = [
                'isolation_log.json',
                'deep_analysis_*.json',
                '*.log',
                '*.tmp',
                '*.cache',
            ]
            
            # Видалення директорій
            for d in temp_dirs:
                if os.path.exists(d):
                    try:
                        shutil.rmtree(d)
                        removed.append(d)
                    except Exception as e:
                        errors.append(f"{d}: {e}")
            
            # Видалення файлів по масках
            for pattern in temp_files:
                for f in glob.glob(pattern):
                    try:
                        os.remove(f)
                        removed.append(f)
                    except Exception as e:
                        errors.append(f"{f}: {e}")
            
            msg = f"🧹 Cleaned: {', '.join(removed) if removed else 'nothing found'}"
            if errors:
                msg += f"\nErrors: {', '.join(errors)}"
            
            print(msg)
            
        except Exception as e:
            print(f"❌ Clean temp action failed: {e}")

class TranslationManager:
    """Translation manager for Ukrainian language"""
    
    def __init__(self):
        self.current_language = 'en'
        self.translations = {
            'en': {
                'dashboard': 'Dashboard',
                'network': 'Network',
                'ports': 'Ports',
                'anomalies': 'Anomalies',
                'logs': 'Logs',
                'ai_analysis': 'AI Analysis',
                'emergency': 'Emergency',
                'refresh': 'Refresh',
                'analyze': 'Analyze',
                'block': 'Block',
                'close': 'Close',
                'stats': 'Stats',
                'deep_analyze': 'Deep Analyze',
                'all_ports': 'All Ports',
                'all_addresses': 'All Addresses',
                'detect_anomalies': 'Detect Anomalies',
                'clear_anomalies': 'Clear Anomalies',
                'analyze_anomaly': 'Analyze Anomaly',
                'system_status': 'System Status',
                'threat_level': 'Threat Level',
                'cpu_usage': 'CPU Usage',
                'memory_usage': 'Memory Usage',
                'network_activity': 'Network Activity',
                'active_connections': 'Active Connections',
                'open_ports': 'Open Ports',
                'detected_anomalies': 'Detected Anomalies',
                'security_events': 'Security Events',
                'ai_recommendations': 'AI Recommendations',
                'emergency_actions': 'Emergency Actions',
                'lockdown_system': 'Lockdown System',
                'isolate_network': 'Isolate Network',
                'terminate_processes': 'Terminate Processes',
                'backup_data': 'Backup Data',
                'shutdown_system': 'Shutdown System',
                'language': 'Language',
                'ukrainian': 'Ukrainian',
                'english': 'English',
                'switch_language': 'Switch Language',
                'local_address': 'Local Address',
                'remote_address': 'Remote Address',
                'status': 'Status',
                'process': 'Process',
                'port': 'Port',
                'service': 'Service',
                'type': 'Type',
                'severity': 'Severity',
                'description': 'Description',
                'timestamp': 'Timestamp',
                'analysis_results': 'Analysis Results',
                'close_window': 'Close',
                'error': 'Error',
                'info': 'Information',
                'warning': 'Warning',
                'success': 'Success',
                'please_select': 'Please select',
                'analysis_failed': 'Analysis failed',
                'no_data_found': 'No data found',
                'test_data': 'Test data',
                'real_data': 'Real data',
                'monitoring_active': 'Monitoring active',
                'system_secure': 'System secure',
                'threat_detected': 'Threat detected',
                'anomaly_detected': 'Anomaly detected',
                'network_scan_completed': 'Network scan completed',
                'port_scan_completed': 'Port scan completed',
                'anomaly_detection_completed': 'Anomaly detection completed'
            },
            'uk': {
                'dashboard': 'Панель керування',
                'network': 'Мережа',
                'ports': 'Порти',
                'anomalies': 'Аномалії',
                'logs': 'Журнали',
                'ai_analysis': 'ШІ Аналіз',
                'emergency': 'Надзвичайна ситуація',
                'refresh': 'Оновити',
                'analyze': 'Аналізувати',
                'block': 'Блокувати',
                'close': 'Закрити',
                'stats': 'Статистика',
                'deep_analyze': 'Глибокий аналіз',
                'all_ports': 'Всі порти',
                'all_addresses': 'Всі адреси',
                'detect_anomalies': 'Виявити аномалії',
                'clear_anomalies': 'Очистити аномалії',
                'analyze_anomaly': 'Аналізувати аномалію',
                'system_status': 'Статус системи',
                'threat_level': 'Рівень загрози',
                'cpu_usage': 'Використання ЦП',
                'memory_usage': 'Використання пам\'яті',
                'network_activity': 'Мережева активність',
                'active_connections': 'Активні з\'єднання',
                'open_ports': 'Відкриті порти',
                'detected_anomalies': 'Виявлені аномалії',
                'security_events': 'Події безпеки',
                'ai_recommendations': 'Рекомендації ШІ',
                'emergency_actions': 'Надзвичайні дії',
                'lockdown_system': 'Блокувати систему',
                'isolate_network': 'Ізолювати мережу',
                'terminate_processes': 'Завершити процеси',
                'backup_data': 'Резервне копіювання',
                'shutdown_system': 'Виключити систему',
                'language': 'Мова',
                'ukrainian': 'Українська',
                'english': 'Англійська',
                'switch_language': 'Змінити мову',
                'local_address': 'Локальна адреса',
                'remote_address': 'Віддалена адреса',
                'status': 'Статус',
                'process': 'Процес',
                'port': 'Порт',
                'service': 'Сервіс',
                'type': 'Тип',
                'severity': 'Серйозність',
                'description': 'Опис',
                'timestamp': 'Часова мітка',
                'analysis_results': 'Результати аналізу',
                'close_window': 'Закрити',
                'error': 'Помилка',
                'info': 'Інформація',
                'warning': 'Попередження',
                'success': 'Успіх',
                'please_select': 'Будь ласка, виберіть',
                'analysis_failed': 'Аналіз не вдався',
                'no_data_found': 'Дані не знайдено',
                'test_data': 'Тестові дані',
                'real_data': 'Реальні дані',
                'monitoring_active': 'Моніторинг активний',
                'system_secure': 'Система захищена',
                'threat_detected': 'Загроза виявлена',
                'anomaly_detected': 'Аномалія виявлена',
                'network_scan_completed': 'Сканування мережі завершено',
                'port_scan_completed': 'Сканування портів завершено',
                'anomaly_detection_completed': 'Виявлення аномалій завершено'
            }
        }
    
    def get_text(self, key):
        """Get translated text for key"""
        return self.translations.get(self.current_language, self.translations['en']).get(key, key)
    
    def switch_language(self):
        """Switch between English and Ukrainian"""
        self.current_language = 'uk' if self.current_language == 'en' else 'en'
        return self.current_language
    
    def get_current_language(self):
        """Get current language"""
        return self.current_language

class NetworkScanner:
    """Network security scanner"""
    
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080, 8443]
        self.suspicious_ports = [4444, 5555, 31337, 1337, 6667, 6668, 6669, 7000, 8081, 9090]
        self.scan_results = {}
    
    def scan_local_ports(self):
        """Scan local ports for suspicious activity"""
        results = []
        for port in self.common_ports + self.suspicious_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    service = self.get_service_name(port)
                    risk = "HIGH" if port in self.suspicious_ports else "MEDIUM"
                    results.append({
                        'port': port,
                        'service': service,
                        'status': 'OPEN',
                        'risk': risk,
                        'timestamp': datetime.now().isoformat()
                    })
                sock.close()
            except:
                pass
        
        # If no ports found, return empty list instead of test data
        if not results:
            print("No real open ports found")
            return []
        
        return results
    
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 4444: 'Metasploit', 5555: 'Freeciv', 31337: 'Back Orifice',
            1337: 'Leet', 6667: 'IRC', 6668: 'IRC', 6669: 'IRC', 7000: 'IRC',
            8081: 'HTTP-Alt', 9090: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def scan_network_connections(self):
        """Scan active network connections"""
        connections = []
        
        # Спочатку спробуємо через netstat (більш надійно на macOS)
        try:
            import subprocess
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'tcp' in line.lower() and 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0]
                        local = parts[3]
                        remote = parts[4]
                        status = parts[5] if len(parts) > 5 else 'ESTABLISHED'
                        
                        # Фільтруємо тільки реальні з'єднання
                        if remote != '*' and remote != '0.0.0.0' and '127.0.0.1' not in remote:
                            connections.append({
                                'local_addr': local,
                                'remote_addr': remote,
                                'status': status,
                                'pid': 'N/A',
                                'process': proto,
                                'timestamp': datetime.now().isoformat()
                            })
        except Exception as e:
            print(f"Netstat scan failed: {e}")
        
        # Якщо netstat не дав результатів, спробуємо psutil
        if not connections:
            try:
                for conn in psutil.net_connections():
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        process_name = 'Unknown'
                        try:
                            if conn.pid and conn.pid > 0:
                                process = psutil.Process(conn.pid)
                                process_name = process.name()
                        except:
                            process_name = f'PID:{conn.pid}' if conn.pid else 'Unknown'
                        
                        connections.append({
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'status': conn.status,
                            'pid': conn.pid if conn.pid else 'N/A',
                            'process': process_name,
                            'timestamp': datetime.now().isoformat()
                        })
            except Exception as e:
                print(f"Psutil scan failed: {e}")
        
        if not connections:
            print("No real connections found")
            return []
        
        return connections

class AnomalyDetector:
    """Anomaly detection system"""
    
    def __init__(self):
        self.baseline = {}
        self.anomalies = []
        self.establish_baseline()
    
    def establish_baseline(self):
        """Establish system baseline"""
        try:
            # CPU baseline
            cpu_percent = psutil.cpu_percent(interval=1)
            self.baseline['cpu'] = cpu_percent
            
            # Memory baseline
            memory = psutil.virtual_memory()
            self.baseline['memory'] = memory.percent
            
            # Network baseline
            net_io = psutil.net_io_counters()
            self.baseline['network'] = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv
            }
            
            # Process baseline
            processes = len(psutil.pids())
            self.baseline['processes'] = processes
            
        except Exception as e:
            print(f"Baseline error: {e}")
    
    def detect_anomalies(self):
        """Detect system anomalies"""
        anomalies = []
        try:
            # Get current system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # CPU anomalies
            if cpu_percent > 80:
                anomalies.append({
                    'type': 'CPU_SPIKE',
                    'severity': 'HIGH',
                    'description': f'CPU usage spike: {cpu_percent:.1f}%',
                    'timestamp': datetime.now().isoformat()
                })
            elif cpu_percent > 60:
                anomalies.append({
                    'type': 'CPU_HIGH',
                    'severity': 'MEDIUM',
                    'description': f'High CPU usage: {cpu_percent:.1f}%',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Memory anomalies
            if memory.percent > 90:
                anomalies.append({
                    'type': 'MEMORY_CRITICAL',
                    'severity': 'HIGH',
                    'description': f'Critical memory usage: {memory.percent:.1f}%',
                    'timestamp': datetime.now().isoformat()
                })
            elif memory.percent > 80:
                anomalies.append({
                    'type': 'MEMORY_HIGH',
                    'severity': 'MEDIUM',
                    'description': f'High memory usage: {memory.percent:.1f}%',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Disk anomalies
            if disk.percent > 95:
                anomalies.append({
                    'type': 'DISK_CRITICAL',
                    'severity': 'HIGH',
                    'description': f'Critical disk usage: {disk.percent:.1f}%',
                    'timestamp': datetime.now().isoformat()
                })
            elif disk.percent > 85:
                anomalies.append({
                    'type': 'DISK_HIGH',
                    'severity': 'MEDIUM',
                    'description': f'High disk usage: {disk.percent:.1f}%',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Process anomalies
            try:
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        proc_info = proc.info
                        if proc_info['cpu_percent'] and proc_info['cpu_percent'] > 50:
                            processes.append(proc_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Sort by CPU usage
                processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
                
                # Check for suspicious processes
                suspicious_processes = ['ssh', 'sshd', 'nc', 'netcat', 'ncat', 'socat', 'telnet']
                for proc in processes[:5]:  # Check top 5 processes
                    if proc['name'] and proc['name'].lower() in suspicious_processes:
                        anomalies.append({
                            'type': 'SUSPICIOUS_PROCESS',
                            'severity': 'HIGH',
                            'description': f'Suspicious process detected: {proc["name"]} (PID: {proc["pid"]})',
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    # High CPU process anomaly
                    if proc['cpu_percent'] and proc['cpu_percent'] > 80:
                        anomalies.append({
                            'type': 'HIGH_CPU_PROCESS',
                            'severity': 'MEDIUM',
                            'description': f'High CPU process: {proc["name"]} ({proc["cpu_percent"]:.1f}%)',
                            'timestamp': datetime.now().isoformat()
                        })
                        
            except Exception as e:
                # Ignore process access errors
                pass
            
            # Network anomalies (simplified)
            try:
                net_io = psutil.net_io_counters()
                # Check for unusual network activity (simplified check)
                if net_io.bytes_sent > 1000000000 or net_io.bytes_recv > 1000000000:  # 1GB
                    anomalies.append({
                        'type': 'NETWORK_HIGH',
                        'severity': 'MEDIUM',
                        'description': f'High network activity: {net_io.bytes_sent // 1000000}MB sent, {net_io.bytes_recv // 1000000}MB received',
                        'timestamp': datetime.now().isoformat()
                    })
            except:
                pass
            
            # If no anomalies found, return empty list instead of test data
            if not anomalies:
                print("No real anomalies found")
                return []
                
        except Exception as e:
            print(f"Anomaly detection error: {e}")
        
        return anomalies

class SecurityMonitorThread(threading.Thread):
    """Thread for background security monitoring"""
    
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.running = True
        self.daemon = True
        self.network_scanner = NetworkScanner()
        self.anomaly_detector = AnomalyDetector()
        
    def run(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Network scan
                port_scan = self.network_scanner.scan_local_ports()
                connections = self.network_scanner.scan_network_connections()
                
                # Anomaly detection
                anomalies = self.anomaly_detector.detect_anomalies()
                
                # System info
                system_info = self.get_system_info()
                
                # Security status
                security_status = {
                    'port_scan': port_scan,
                    'connections': connections,
                    'anomalies': anomalies,
                    'system_info': system_info,
                    'timestamp': datetime.now().isoformat()
                }
                
                self.callback(security_status)
                time.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(10)
    
    def get_system_info(self):
        """Get current system information"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available': memory.available // (1024**3),  # GB
                'disk_percent': disk.percent,
                'disk_free': disk.free // (1024**3),  # GB
                'network_sent': network.bytes_sent // (1024**2),  # MB
                'network_recv': network.bytes_recv // (1024**2),  # MB
                'processes': len(psutil.pids())
            }
        except:
            return {}
    
    def stop(self):
        """Stop monitoring"""
        self.running = False

class DeepAnalyzer:
    """Deep analysis for ports and network addresses"""
    
    def __init__(self):
        self.port_analysis_cache = {}
        self.address_analysis_cache = {}
    
    def analyze_port(self, port):
        """Deep analysis of a specific port"""
        try:
            analysis = {
                'port': port,
                'service': self.get_service_name(port),
                'risk_level': self.assess_port_risk(port),
                'common_uses': self.get_port_uses(port),
                'security_concerns': self.get_security_concerns(port),
                'recommendations': self.get_port_recommendations(port),
                'scan_result': self.scan_specific_port(port),
                'timestamp': datetime.now().isoformat()
            }
            return analysis
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_address(self, address):
        """Deep analysis of a specific network address"""
        try:
            ip, port = address.split(':') if ':' in address else (address, 'N/A')
            analysis = {
                'address': address,
                'ip': ip,
                'port': port,
                'geolocation': self.get_geolocation(ip),
                'reputation': self.check_reputation(ip),
                'connection_info': self.get_connection_info(address),
                'security_assessment': self.assess_address_security(address),
                'recommendations': self.get_address_recommendations(address),
                'timestamp': datetime.now().isoformat()
            }
            return analysis
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_all_ports(self, ports):
        """Quick analysis of all found ports"""
        try:
            analysis = {
                'total_ports': len(ports),
                'high_risk_ports': [p for p in ports if self.assess_port_risk(p) == 'HIGH'],
                'medium_risk_ports': [p for p in ports if self.assess_port_risk(p) == 'MEDIUM'],
                'low_risk_ports': [p for p in ports if self.assess_port_risk(p) == 'LOW'],
                'suspicious_services': self.find_suspicious_services(ports),
                'recommendations': self.get_bulk_port_recommendations(ports),
                'timestamp': datetime.now().isoformat()
            }
            return analysis
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_all_addresses(self, addresses):
        """Quick analysis of all found addresses"""
        try:
            analysis = {
                'total_addresses': len(addresses),
                'external_addresses': [addr for addr in addresses if self.is_external_address(addr)],
                'internal_addresses': [addr for addr in addresses if not self.is_external_address(addr)],
                'suspicious_addresses': self.find_suspicious_addresses(addresses),
                'recommendations': self.get_bulk_address_recommendations(addresses),
                'timestamp': datetime.now().isoformat()
            }
            return analysis
        except Exception as e:
            return {'error': str(e)}
    
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 4444: 'Metasploit', 5555: 'Freeciv', 31337: 'Back Orifice',
            1337: 'Leet', 6667: 'IRC', 6668: 'IRC', 6669: 'IRC', 7000: 'IRC',
            8081: 'HTTP-Alt', 9090: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def assess_port_risk(self, port):
        """Assess risk level for a port"""
        high_risk_ports = [4444, 5555, 31337, 1337, 6667, 6668, 6669, 7000, 8081, 9090]
        medium_risk_ports = [21, 23, 25, 110, 143, 3306, 5432]
        
        if port in high_risk_ports:
            return 'HIGH'
        elif port in medium_risk_ports:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_port_uses(self, port):
        """Get common uses for a port"""
        uses = {
            22: 'Secure Shell, remote administration',
            80: 'HTTP web traffic',
            443: 'HTTPS secure web traffic',
            21: 'File Transfer Protocol',
            23: 'Telnet remote access',
            25: 'Simple Mail Transfer Protocol',
            53: 'Domain Name System',
            3306: 'MySQL database',
            5432: 'PostgreSQL database',
            8080: 'Alternative HTTP port',
            4444: 'Metasploit framework',
            31337: 'Back Orifice trojan',
            1337: 'Leet speak port'
        }
        return uses.get(port, 'Unknown or uncommon use')
    
    def get_security_concerns(self, port):
        """Get security concerns for a port"""
        concerns = {
            22: 'SSH brute force attacks, weak authentication',
            80: 'HTTP traffic interception, web attacks',
            443: 'SSL/TLS vulnerabilities, certificate issues',
            21: 'FTP data interception, weak authentication',
            23: 'Telnet traffic in plain text, no encryption',
            25: 'Email spoofing, spam relay',
            53: 'DNS poisoning, amplification attacks',
            3306: 'Database injection attacks, weak passwords',
            5432: 'Database injection attacks, weak passwords',
            8080: 'Alternative web server, often overlooked',
            4444: 'Metasploit exploitation, backdoor access',
            31337: 'Back Orifice trojan, remote control',
            1337: 'Hacker tools, suspicious activity'
        }
        return concerns.get(port, 'Unknown security implications')
    
    def get_port_recommendations(self, port):
        """Get recommendations for a port"""
        recommendations = {
            22: 'Use key-based authentication, disable root login, change default port',
            80: 'Redirect to HTTPS, implement security headers, use WAF',
            443: 'Use strong SSL/TLS, regular certificate updates, HSTS',
            21: 'Use SFTP instead, implement strong authentication',
            23: 'Disable telnet, use SSH instead',
            25: 'Implement SPF, DKIM, DMARC, rate limiting',
            53: 'Use DNSSEC, secure DNS server configuration',
            3306: 'Use strong passwords, limit access, enable SSL',
            5432: 'Use strong passwords, limit access, enable SSL',
            8080: 'Monitor for unauthorized web services',
            4444: 'BLOCK THIS PORT - High risk of exploitation',
            31337: 'BLOCK THIS PORT - Known trojan port',
            1337: 'Investigate immediately - suspicious activity'
        }
        return recommendations.get(port, 'Monitor and assess based on usage')
    
    def scan_specific_port(self, port):
        """Scan a specific port for details"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                return f"Port {port} is OPEN and accessible"
            else:
                return f"Port {port} is CLOSED or filtered"
        except:
            return f"Unable to scan port {port}"
    
    def get_geolocation(self, ip):
        """Get geolocation for IP (simplified)"""
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return 'Local/Internal Network'
        elif ip.startswith('8.8.8.8'):
            return 'Google DNS (US)'
        else:
            return 'External Network'
    
    def check_reputation(self, ip):
        """Check IP reputation (simplified)"""
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return 'Internal - Low Risk'
        elif ip == '8.8.8.8':
            return 'Google DNS - Trusted'
        else:
            return 'External - Monitor'
    
    def get_connection_info(self, address):
        """Get connection information"""
        try:
            ip, port = address.split(':') if ':' in address else (address, 'N/A')
            return f"IP: {ip}, Port: {port}, Type: {'External' if not self.is_external_address(address) else 'Internal'}"
        except:
            return "Unable to parse address"
    
    def assess_address_security(self, address):
        """Assess security of an address"""
        if self.is_external_address(address):
            return "External connection - Monitor for suspicious activity"
        else:
            return "Internal connection - Standard network traffic"
    
    def get_address_recommendations(self, address):
        """Get recommendations for an address"""
        if self.is_external_address(address):
            return "Monitor traffic, check for unauthorized access, consider blocking if suspicious"
        else:
            return "Normal internal traffic, ensure proper network segmentation"
    
    def is_external_address(self, address):
        """Check if address is external"""
        try:
            ip = address.split(':')[0] if ':' in address else address
            return not (ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'))
        except:
            return True
    
    def find_suspicious_services(self, ports):
        """Find suspicious services among ports"""
        suspicious = []
        for port in ports:
            if self.assess_port_risk(port) == 'HIGH':
                suspicious.append(f"Port {port} ({self.get_service_name(port)})")
        return suspicious
    
    def find_suspicious_addresses(self, addresses):
        """Find suspicious addresses"""
        suspicious = []
        for addr in addresses:
            if self.is_external_address(addr):
                suspicious.append(addr)
        return suspicious
    
    def get_bulk_port_recommendations(self, ports):
        """Get bulk recommendations for ports"""
        high_risk = [p for p in ports if self.assess_port_risk(p) == 'HIGH']
        if high_risk:
            return f"BLOCK {len(high_risk)} high-risk ports immediately"
        else:
            return "Monitor all ports, implement proper firewall rules"
    
    def get_bulk_address_recommendations(self, addresses):
        """Get bulk recommendations for addresses"""
        external = [addr for addr in addresses if self.is_external_address(addr)]
        if external:
            return f"Monitor {len(external)} external connections carefully"
        else:
            return "All connections are internal - standard monitoring"

class AnomalyAnalyzer:
    """Detailed analysis for anomalies"""
    
    def __init__(self):
        self.anomaly_cache = {}
    
    def analyze_anomaly(self, anomaly):
        """Deep analysis of a specific anomaly"""
        try:
            analysis = {
                'anomaly_type': anomaly.get('type', 'UNKNOWN'),
                'severity': anomaly.get('severity', 'LOW'),
                'description': anomaly.get('description', 'No description'),
                'timestamp': anomaly.get('timestamp', 'Unknown'),
                'root_cause': self.analyze_root_cause(anomaly),
                'impact_assessment': self.assess_impact(anomaly),
                'mitigation_steps': self.get_mitigation_steps(anomaly),
                'prevention_measures': self.get_prevention_measures(anomaly),
                'related_threats': self.get_related_threats(anomaly),
                'system_health': self.assess_system_health(anomaly),
                'recommendations': self.get_anomaly_recommendations(anomaly),
                'analysis_timestamp': datetime.now().isoformat()
            }
            return analysis
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_root_cause(self, anomaly):
        """Analyze root cause of anomaly"""
        anomaly_type = anomaly.get('type', 'UNKNOWN')
        
        root_causes = {
            'CPU_SPIKE': 'High CPU usage due to intensive processes, malware, or resource-intensive applications',
            'MEMORY_HIGH': 'Memory leak, too many applications running, or insufficient RAM',
            'NETWORK_SPIKE': 'Unusual network traffic, potential data exfiltration, or network scanning',
            'PROCESS_SPIKE': 'Malware infection, fork bomb, or system instability',
            'SUSPICIOUS_PROCESS': 'Malware, unauthorized software, or compromised process',
            'DISK_SPACE': 'Disk space exhaustion, log file accumulation, or data overflow',
            'LOGIN_ATTEMPT': 'Brute force attack, unauthorized access attempt, or credential stuffing',
            'FILE_ACCESS': 'Unauthorized file access, data breach, or malware activity'
        }
        
        return root_causes.get(anomaly_type, 'Unknown root cause - requires further investigation')
    
    def assess_impact(self, anomaly):
        """Assess impact of anomaly"""
        severity = anomaly.get('severity', 'LOW')
        anomaly_type = anomaly.get('type', 'UNKNOWN')
        
        impact_levels = {
            'HIGH': {
                'CPU_SPIKE': 'System slowdown, potential service disruption, user experience degradation',
                'NETWORK_SPIKE': 'Data breach risk, bandwidth exhaustion, potential data exfiltration',
                'SUSPICIOUS_PROCESS': 'System compromise, data theft, backdoor installation',
                'LOGIN_ATTEMPT': 'Account compromise, unauthorized access, privilege escalation'
            },
            'MEDIUM': {
                'MEMORY_HIGH': 'System slowdown, application crashes, performance degradation',
                'PROCESS_SPIKE': 'System instability, resource exhaustion, potential malware',
                'DISK_SPACE': 'Application failures, system crashes, data loss risk'
            },
            'LOW': {
                'FILE_ACCESS': 'Minor security concern, potential data exposure',
                'LOGIN_ATTEMPT': 'Failed access attempt, security awareness needed'
            }
        }
        
        return impact_levels.get(severity, {}).get(anomaly_type, 'Impact assessment requires further analysis')
    
    def get_mitigation_steps(self, anomaly):
        """Get immediate mitigation steps"""
        anomaly_type = anomaly.get('type', 'UNKNOWN')
        
        mitigation_steps = {
            'CPU_SPIKE': [
                'Identify and terminate resource-intensive processes',
                'Check for malware or unauthorized applications',
                'Monitor CPU usage trends',
                'Consider process prioritization'
            ],
            'MEMORY_HIGH': [
                'Close unnecessary applications',
                'Check for memory leaks',
                'Restart critical services',
                'Monitor memory usage patterns'
            ],
            'NETWORK_SPIKE': [
                'Block suspicious IP addresses',
                'Monitor network traffic patterns',
                'Check for data exfiltration',
                'Review firewall rules'
            ],
            'PROCESS_SPIKE': [
                'Identify and terminate suspicious processes',
                'Scan for malware',
                'Check system logs',
                'Review process tree'
            ],
            'SUSPICIOUS_PROCESS': [
                'Immediately terminate suspicious process',
                'Isolate affected system',
                'Scan for malware',
                'Review system integrity'
            ],
            'LOGIN_ATTEMPT': [
                'Block source IP address',
                'Review authentication logs',
                'Enable account lockout',
                'Implement rate limiting'
            ]
        }
        
        return mitigation_steps.get(anomaly_type, ['Investigate anomaly type', 'Monitor system behavior', 'Review logs'])
    
    def get_prevention_measures(self, anomaly):
        """Get prevention measures"""
        anomaly_type = anomaly.get('type', 'UNKNOWN')
        
        prevention_measures = {
            'CPU_SPIKE': [
                'Implement resource monitoring',
                'Set up CPU usage alerts',
                'Use process monitoring tools',
                'Regular system maintenance'
            ],
            'MEMORY_HIGH': [
                'Monitor memory usage',
                'Implement memory limits',
                'Regular system cleanup',
                'Optimize applications'
            ],
            'NETWORK_SPIKE': [
                'Implement network monitoring',
                'Use intrusion detection systems',
                'Regular security audits',
                'Network segmentation'
            ],
            'PROCESS_SPIKE': [
                'Process monitoring tools',
                'Regular malware scans',
                'System integrity checks',
                'User access controls'
            ],
            'SUSPICIOUS_PROCESS': [
                'Antivirus software',
                'Process whitelisting',
                'Regular security updates',
                'User education'
            ],
            'LOGIN_ATTEMPT': [
                'Strong authentication',
                'Account lockout policies',
                'Multi-factor authentication',
                'Regular password changes'
            ]
        }
        
        return prevention_measures.get(anomaly_type, ['General security measures', 'Regular monitoring', 'User training'])
    
    def get_related_threats(self, anomaly):
        """Get related security threats"""
        anomaly_type = anomaly.get('type', 'UNKNOWN')
        
        related_threats = {
            'CPU_SPIKE': ['Cryptojacking', 'DDoS attacks', 'Resource exhaustion', 'Malware'],
            'MEMORY_HIGH': ['Memory-based attacks', 'Buffer overflow', 'System crashes', 'Data corruption'],
            'NETWORK_SPIKE': ['Data exfiltration', 'DDoS attacks', 'Network scanning', 'Man-in-the-middle'],
            'PROCESS_SPIKE': ['Fork bombs', 'Malware propagation', 'System instability', 'Resource attacks'],
            'SUSPICIOUS_PROCESS': ['Malware', 'Backdoors', 'Rootkits', 'Trojan horses'],
            'LOGIN_ATTEMPT': ['Brute force attacks', 'Credential stuffing', 'Account takeover', 'Privilege escalation']
        }
        
        return related_threats.get(anomaly_type, ['General security threats', 'System compromise', 'Data breach'])
    
    def assess_system_health(self, anomaly):
        """Assess overall system health"""
        severity = anomaly.get('severity', 'LOW')
        
        if severity == 'HIGH':
            return 'CRITICAL - Immediate attention required'
        elif severity == 'MEDIUM':
            return 'WARNING - Monitor closely'
        else:
            return 'STABLE - Continue monitoring'
    
    def get_anomaly_recommendations(self, anomaly):
        """Get specific recommendations for anomaly"""
        severity = anomaly.get('severity', 'LOW')
        anomaly_type = anomaly.get('type', 'UNKNOWN')
        
        if severity == 'HIGH':
            return f'IMMEDIATE ACTION REQUIRED: {anomaly_type} detected. Isolate system and investigate immediately.'
        elif severity == 'MEDIUM':
            return f'MONITOR CLOSELY: {anomaly_type} requires attention. Implement mitigation steps.'
        else:
            return f'CONTINUE MONITORING: {anomaly_type} detected. Review and document for future reference.'

class NIMDATkinterApp:
    """NIMDA Security System - Tkinter GUI Application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("NIMDA Security System - Enhanced Tkinter GUI")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Initialize sound system
        self.sound_system = SoundAlertSystem()
        
        # Initialize privilege manager
        self.privilege_manager = PrivilegeManager()
        
        # Security system components
        self.security_monitor = None
        self.security_policy = SecurityPolicy()
        self.threat_analyzer = ThreatAnalyzer(self.security_policy)
        self.network_scanner = NetworkScanner()
        self.anomaly_detector = AnomalyDetector()
        self.deep_analyzer = DeepAnalyzer()
        self.anomaly_analyzer = AnomalyAnalyzer()
        self.translation_manager = TranslationManager()
        
        # AI components
        self.ai_provider_manager = None
        self.task_scheduler = None
        
        # UI components
        self.notebook = None
        self.status_label = None
        self.threat_level_label = None
        self.connections_tree = None
        self.ports_tree = None
        self.anomalies_tree = None
        self.logs_text = None
        self.devices_tree = None
        self.processes_tree = None
        
        # Data storage with threat tracking
        self.security_status = {
            'threat_level': ThreatLevel.LOW,
            'connections': [],
            'ports': [],
            'anomalies': [],
            'last_update': datetime.now()
        }
        
        # Enhanced threat tracking for automated response
        self.threat_history = {}  # Track recurring threats
        self.threat_counters = defaultdict(int)  # Count threat occurrences
        self.automated_actions = []  # Log of automated actions taken
        self.threat_patterns = {}  # Pattern analysis for threats
        self.last_automated_action = None  # Track last automated action time
        
        # Threading
        self.monitor_thread = None
        self.running = True

        # --- Enhanced threat detection system initialization ---
        self.init_enhanced_threat_detection()
        
        # Initialize UI
        self.init_ui()
        self.setup_dark_theme()
        
        # Initialize security system
        self.init_security_system()
        
        # Load initial data
        self.load_initial_data()
        
        # Start monitoring
        self.start_monitoring()
        
        # Setup closing handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def generate_threat_report(self):
        """Generate comprehensive threat intelligence report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_threats': len(self.threat_counters),
                    'whitelisted_skipped': len([a for a in self.automated_actions if 'Whitelisted' in a.get('action', '')]),
                    'recently_handled': len([a for a in self.automated_actions if 'Recently handled' in a.get('action', '')]),
                    'active_responses': len([a for a in self.automated_actions if 'CRITICAL' in a.get('action', '')])
                },
                'top_threats': self.get_top_threats(),
                'threat_patterns': self.analyze_threat_patterns(),
                'recommendations': self.generate_security_recommendations()
            }
            
            # Save report
            report_file = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            return report
        except Exception as e:
            return {'error': f"Failed to generate report: {str(e)}"}

    def get_top_threats(self):
        """Get top threats by frequency"""
        try:
            sorted_threats = sorted(self.threat_counters.items(), key=lambda x: x[1], reverse=True)
            return [{'threat_id': threat_id, 'frequency': freq} for threat_id, freq in sorted_threats[:10]]
        except:
            return []

    def analyze_threat_patterns(self):
        """Analyze patterns in threat data"""
        try:
            patterns = {
                'port_threats': len([t for t in self.threat_counters.keys() if t.startswith('port_')]),
                'ip_threats': len([t for t in self.threat_counters.keys() if t.startswith('ip_')]),
                'anomaly_threats': len([t for t in self.threat_counters.keys() if t.startswith('anomaly_')]),
                'most_common_ports': self.get_most_common_ports(),
                'most_active_ips': self.get_most_active_ips()
            }
            return patterns
        except:
            return {}

    def get_most_common_ports(self):
        """Get most commonly detected ports"""
        try:
            ports = [t.split('_')[1] for t in self.threat_counters.keys() if t.startswith('port_')]
            port_counts = {}
            for port in ports:
                port_counts[port] = port_counts.get(port, 0) + 1
            return sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        except:
            return []

    def get_most_active_ips(self):
        """Get most active IP addresses"""
        try:
            ips = [t.split('_')[1] for t in self.threat_counters.keys() if t.startswith('ip_')]
            ip_counts = {}
            for ip in ips:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        except:
            return []

    def generate_security_recommendations(self):
        """Generate security recommendations based on threat patterns"""
        try:
            recommendations = []
            
            # Check for persistent port threats
            dangerous_ports = [t for t in self.threat_counters.keys() if t.startswith('port_7000') or t.startswith('port_1337')]
            if dangerous_ports:
                recommendations.append("Consider blocking dangerous ports (7000, 1337) at firewall level")
            
            # Check for high-frequency threats
            high_freq_threats = [t for t, freq in self.threat_counters.items() if freq > 10]
            if high_freq_threats:
                recommendations.append("Investigate high-frequency threats for potential false positives")
            
            # Check for new threat types
            recent_threats = [a for a in self.automated_actions if (datetime.now() - a.get('timestamp', datetime.now())).seconds < 3600]
            if len(recent_threats) > 20:
                recommendations.append("High threat activity detected - consider enabling additional monitoring")
            
            return recommendations
        except:
            return ["Unable to generate recommendations"]

    def update_threat_intelligence(self):
        """Update threat intelligence database"""
        try:
            if not hasattr(self, 'threat_intelligence'):
                self.threat_intelligence = {
                    'whitelisted_ips': set(['8.8.8.8', '8.8.4.4', '1.1.1.1']),
                    'known_bad_ips': set(),
                    'suspicious_ports': set([7000, 1337, 31337, 4444]),
                    'blocked_ranges': set(),
                    'last_updated': datetime.now()
                }
            
            # Automatically whitelist frequent legitimate services
            frequent_legitimate = []
            for threat_id, freq in self.threat_counters.items():
                if threat_id.startswith('ip_') and freq > 5:
                    ip = threat_id.split('_')[1]
                    if any(ip.startswith(prefix) for prefix in ['13.', '17.', '20.', '52.', '140.82.']):
                        frequent_legitimate.append(ip)
            
            # Add to whitelist
            self.threat_intelligence['whitelisted_ips'].update(frequent_legitimate)
            self.threat_intelligence['last_updated'] = datetime.now()
            
            return f"Updated threat intelligence: {len(frequent_legitimate)} IPs auto-whitelisted"
        except Exception as e:
            return f"Failed to update threat intelligence: {str(e)}"

    def reset_threat_counters(self):
        """Reset threat counters for testing purposes"""
        try:
            if hasattr(self, 'threat_counters'):
                old_count = len(self.threat_counters)
                self.threat_counters.clear()
                print(f"🔄 Reset {old_count} threat counters")
            
            if hasattr(self, 'recent_responses'):
                old_count = len(self.recent_responses)
                self.recent_responses.clear()
                print(f"🔄 Reset {old_count} recent responses")
            
            if hasattr(self, 'automated_actions'):
                old_count = len(self.automated_actions)
                self.automated_actions.clear()
                print(f"🔄 Reset {old_count} automated actions")
            
            print("✅ All threat data reset - system will treat all threats as new")
            
        except Exception as e:
            print(f"❌ Failed to reset threat counters: {e}")

    def force_threat_detection(self):
        """Force immediate threat detection with sound alerts"""
        try:
            print("🔍 Forcing immediate threat detection...")
            
            # Reset counters first
            self.reset_threat_counters()
            
            # Force clear recent responses with unique timestamp
            current_time = datetime.now()
            if hasattr(self, 'recent_responses'):
                self.recent_responses.clear()
            
            # Simulate discovering port 7000 as new threat with unique data
            threat_data = {
                'port': 7000,
                'service': 'IRC', 
                'status': 'OPEN',
                'risk': 'HIGH',
                'force_test': current_time.timestamp()  # Make it unique
            }
            
            # Call smart response as if it's a new threat
            response = self.smart_threat_response('port_scan', threat_data, ThreatLevel.CRITICAL)
            print(f"🧠 FORCED RESPONSE: {response}")
            
            # Test with a different unknown IP to avoid whitelist
            ip_threat_data = {
                'remote_address': '1.2.3.4',  # Clearly external, non-whitelisted IP
                'port': 7000,
                'service': 'unknown',
                'force_test': current_time.timestamp()  # Make it unique
            }
            
            response = self.smart_threat_response('ip_connection', ip_threat_data, ThreatLevel.HIGH)
            print(f"🧠 FORCED IP RESPONSE: {response}")
            
            # Force anomaly detection
            anomaly_data = {
                'type': 'suspicious_network_behavior',
                'severity': 'high',
                'description': 'Forced test anomaly',
                'force_test': current_time.timestamp()
            }
            
            response = self.smart_threat_response('anomaly', anomaly_data, ThreatLevel.MEDIUM)
            print(f"🧠 FORCED ANOMALY RESPONSE: {response}")
            
            print("✅ Forced threat detection completed")
            
        except Exception as e:
            print(f"❌ Force threat detection failed: {e}")

    def handle_edge_case_threats(self, threat_type, threat_data, frequency):
        """Handle edge case threats that might not be caught by main logic"""
        try:
            # Handle unknown services on dangerous ports
            if threat_type == 'port_scan':
                port = int(threat_data.get('port', 0))
                service = threat_data.get('service', 'unknown').lower()
                
                # IRC-like ports but unknown service
                if port in [6667, 6668, 6669, 7000] and service == 'unknown':
                    self.trigger_sound_alert(ThreatLevel.CRITICAL, f"Suspicious IRC-like port {port}")
                    return f"🚨 IRC-like port {port} with unknown service - INVESTIGATING"
                
                # Backdoor/trojan common ports
                trojan_ports = [1337, 31337, 12345, 54321, 9999]
                if port in trojan_ports:
                    self.trigger_sound_alert(ThreatLevel.EMERGENCY, f"Trojan port {port}")
                    return f"🚨 EMERGENCY: Known trojan port {port} detected - IMMEDIATE ACTION REQUIRED"
            
            # Handle anomalies that occur outside business hours
            elif threat_type == 'anomaly':
                current_hour = datetime.now().hour
                anomaly_type = threat_data.get('type', 'unknown')
                
                # High activity during night hours (11 PM - 6 AM)
                if current_hour >= 23 or current_hour <= 6:
                    self.trigger_sound_alert(ThreatLevel.HIGH, f"Night-time {anomaly_type}")
                    return f"🌙 SUSPICIOUS: {anomaly_type} during off-hours ({current_hour}:00)"
                
                # Weekend unusual activity
                if datetime.now().weekday() >= 5:  # Saturday=5, Sunday=6
                    if frequency > 1:
                        self.trigger_sound_alert(ThreatLevel.MEDIUM, f"Weekend {anomaly_type}")
                        return f"📅 Weekend anomaly: {anomaly_type} - worth investigating"
            
            # Handle IP connections from unexpected geographic regions
            elif threat_type == 'ip_connection':
                ip = threat_data.get('remote_address', '')
                
                # Non-standard IP ranges that might be suspicious
                suspicious_ranges = ['1.', '2.', '5.', '14.', '27.', '41.', '42.']
                if any(ip.startswith(prefix) for prefix in suspicious_ranges):
                    if frequency >= 2:
                        self.trigger_sound_alert(ThreatLevel.MEDIUM, f"Unusual IP range {ip}")
                        return f"🌍 Unusual geographic IP {ip} - analyzing origin"
            
            return None  # No edge case detected
            
        except Exception as e:
            return f"Edge case analysis error: {str(e)}"

    def log_threat_response(self, threat_type, threat_data, response, threat_level, frequency):
        """Enhanced logging for threat responses"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            threat_id = self.generate_threat_id(threat_type, threat_data)
            
            # Create detailed log entry
            log_entry = {
                'timestamp': timestamp,
                'threat_id': threat_id,
                'threat_type': threat_type,
                'threat_level': threat_level.name if hasattr(threat_level, 'name') else str(threat_level),
                'frequency': frequency,
                'response': response,
                'threat_data': threat_data,
                'sound_triggered': 'Skipped' not in response and '🚨' in response
            }
            
            # Log to console with appropriate color/emoji
            if hasattr(threat_level, 'name'):
                level_name = threat_level.name
            else:
                level_name = str(threat_level)
            
            if level_name in ['CRITICAL', 'EMERGENCY']:
                print(f"🚨 {timestamp} [{level_name}] {threat_type}: {response}")
            elif level_name == 'HIGH':
                print(f"⚠️  {timestamp} [{level_name}] {threat_type}: {response}")
            else:
                print(f"ℹ️  {timestamp} [{level_name}] {threat_type}: {response}")
            
            # Add to actions log (if GUI is available) - combine level and type into single message
            try:
                self.add_action_to_log(f"[{level_name}] {threat_type}: {response}")
            except Exception as log_err:
                print(f"Log GUI error: {log_err}")
                
            # Store in threat log for analysis
            if not hasattr(self, 'threat_response_log'):
                self.threat_response_log = []
            
            self.threat_response_log.append(log_entry)
            
            # Keep only last 100 entries
            if len(self.threat_response_log) > 100:
                self.threat_response_log = self.threat_response_log[-100:]
            
        except Exception as e:
            print(f"❌ Logging error: {e}")

    # ...existing code...

    def init_enhanced_threat_detection(self):
        """Initialize enhanced threat detection with smart response"""
        try:
            # Initialize threat intelligence database first (inline)
            if not hasattr(self, 'threat_intelligence'):
                self.threat_intelligence = {
                    'whitelisted_ips': set([
                        '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',  # DNS servers
                        '127.0.0.1', 'localhost'  # Local
                    ]),
                    'known_bad_ips': set(),
                    'suspicious_ports': set([7000, 1337, 31337, 4444, 5555, 6666]),
                    'blocked_ranges': set(),
                    'service_fingerprints': {
                        'microsoft': ['13.', '20.', '40.', '52.', '104.', '168.'],
                        'apple': ['17.', '23.', '199.47.'],
                        'github': ['140.82.', '192.30.', '185.199.'],
                        'google': ['8.8.', '74.125.', '172.217.', '216.58.'],
                        'cloudflare': ['104.16.', '104.17.', '104.18.', '104.19.'],
                        'aws': ['3.', '18.', '52.', '54.']
                    },
                    'last_updated': datetime.now()
                }
                
            # Initialize counters and tracking
            if not hasattr(self, 'threat_counters'):
                self.threat_counters = {}
            if not hasattr(self, 'automated_actions'):
                self.automated_actions = []
            if not hasattr(self, 'recent_responses'):
                self.recent_responses = {}
            
            # Initialize adaptive response thresholds
            self.adaptive_thresholds = {
                'ip_frequency_limit': 3,      # Block IP after 3 occurrences
                'port_frequency_limit': 2,    # Block port after 2 occurrences  
                'anomaly_frequency_limit': 5, # Investigate anomaly after 5 occurrences
                'escalation_time_window': 300 # 5 minutes
            }
            
            # Initialize learning system
            self.threat_learning = {
                'false_positives': set(),
                'confirmed_threats': set(),
                'learning_enabled': True
            }
            
            # Start enhanced monitoring after a delay to ensure all methods are loaded
            def delayed_start():
                time.sleep(5)  # Wait for full initialization
                try:
                    self.start_enhanced_monitoring()
                except Exception as e:
                    print(f"Background monitoring start failed: {e}")
            
            threading.Thread(target=delayed_start, daemon=True).start()
            
            self.log_message("🧠 Enhanced threat detection initialized")
            
        except Exception as e:
            print(f"Error initializing enhanced threat detection: {e}")

    def smart_threat_response(self, threat_type, threat_data, threat_level):
        """Intelligent threat response that learns and adapts"""
        try:
            threat_id = self.generate_threat_id(threat_type, threat_data)
            current_time = datetime.now()
            
            # Check if this is a known false positive or whitelisted
            if self.is_whitelisted_threat(threat_data):
                return f"Skipped - Whitelisted service ({self.identify_service(threat_data)})"
            
            # Check if we already handled this threat recently (last 5 minutes)
            if hasattr(self, 'recent_responses'):
                if threat_id in self.recent_responses:
                    time_since = (current_time - self.recent_responses[threat_id]).seconds
                    if time_since < 300:  # 5 minutes
                        return f"Skipped - Recently handled ({time_since}s ago)"
            else:
                self.recent_responses = {}
            
            # Update threat frequency tracking
            if threat_id not in self.threat_counters:
                self.threat_counters[threat_id] = 0
            self.threat_counters[threat_id] += 1
            
            frequency = self.threat_counters[threat_id]
            
            # Determine intelligent response based on threat type and frequency
            response = None
            
            # First check for edge cases
            edge_case_response = self.handle_edge_case_threats(threat_type, threat_data, frequency)
            if edge_case_response:
                response = edge_case_response
            else:
                # Standard threat handling
                if threat_type == 'ip_connection':
                    response = self.handle_ip_threat_smart(threat_data, frequency, threat_level)
                elif threat_type == 'port_scan':
                    response = self.handle_port_threat_smart(threat_data, frequency, threat_level)
                elif threat_type == 'anomaly':
                    response = self.handle_anomaly_threat_smart(threat_data, frequency, threat_level)
            
            # Enhanced logging for all responses
            if response:
                self.log_threat_response(threat_type, threat_data, response, threat_level, frequency)
            
            # Record that we handled this threat
            if response and "Skipped" not in response:
                self.recent_responses[threat_id] = current_time
                
                # Also record in automated actions
                self.automated_actions.append({
                    'timestamp': current_time,
                    'threat_key': threat_id,
                    'threat_type': threat_type,
                    'action': response,
                    'threat_data': threat_data,
                    'frequency': frequency
                })
                
                # Keep only last 50 automated actions
                if len(self.automated_actions) > 50:
                    self.automated_actions = self.automated_actions[-50:]
            
            return response
            
        except Exception as e:
            return f"Error in smart response: {str(e)}"

    def identify_service(self, threat_data):
        """Identify legitimate services"""
        if isinstance(threat_data, dict):
            ip = threat_data.get('remote_address', threat_data.get('remote_addr', ''))
            if isinstance(ip, str):
                # Microsoft/Azure IPs
                if any(ip.startswith(prefix) for prefix in ['20.', '13.', '52.', '40.']):
                    return "Microsoft/Azure"
                # Apple IPs  
                elif ip.startswith('17.'):
                    return "Apple"
                # GitHub IPs
                elif ip.startswith('140.82.'):
                    return "GitHub"
                # Google IPs
                elif any(ip.startswith(prefix) for prefix in ['8.8.', '74.125.', '172.217.']):
                    return "Google"
        return "Unknown"

    def is_whitelisted_threat(self, threat_data):
        """Check if threat should be whitelisted (trusted source)"""
        try:
            if isinstance(threat_data, dict):
                ip = threat_data.get('remote_address', threat_data.get('remote_addr', ''))
                port = threat_data.get('port')
                
                # Whitelist major cloud services on HTTPS ports
                if isinstance(ip, str) and str(port) == '443':
                    trusted_prefixes = ['20.', '13.', '52.', '40.', '17.', '140.82.', '8.8.', '74.125.', '172.217.']
                    if any(ip.startswith(prefix) for prefix in trusted_prefixes):
                        return True
                
                # Whitelist Apple services on port 5223 (Apple Push Notification)
                if isinstance(ip, str) and str(port) == '5223' and ip.startswith('17.'):
                    return True
            
            return False
        except:
            return False

    def handle_ip_threat_smart(self, threat_data, frequency, threat_level):
        """Smart handling of IP-based threats"""
        try:
            ip = threat_data.get('remote_address', threat_data.get('remote_addr', 'unknown'))
            port = threat_data.get('port', '')
            
            service = self.identify_service(threat_data)
            
            # Progressive response based on frequency and legitimacy
            if frequency == 1:
                return f"Monitoring {service} connection to {ip}:{port}"
            elif frequency <= 3:
                return f"Analyzed {service} connection pattern from {ip} - appears legitimate"
            else:
                # Only for truly suspicious IPs after multiple occurrences
                if service == "Unknown":
                    # Trigger sound for unknown high-frequency connections
                    self.trigger_sound_alert(ThreatLevel.HIGH, f"Unknown IP {ip}")
                    return f"High-frequency unknown connection from {ip} - added to monitoring list"
                else:
                    return f"Frequent {service} activity from {ip} - marked as normal business traffic"
        
        except Exception as e:
            return f"Error handling IP threat: {str(e)}"

    def handle_port_threat_smart(self, threat_data, frequency, threat_level):
        """Smart handling of port-based threats"""
        try:
            port = threat_data.get('port', 'unknown')
            service = threat_data.get('service', 'unknown')
            
            # Focus on truly dangerous ports
            dangerous_ports = [7000, 1337, 31337, 4444, 5555, 6666, 8080, 9999]
            
            if int(port) in dangerous_ports:
                # Trigger sound alert for dangerous ports
                if frequency == 1:
                    self.trigger_sound_alert(ThreatLevel.CRITICAL, f"Dangerous Port {port}")
                    return f"🚨 CRITICAL: Dangerous port {port} ({service}) detected - investigating processes"
                elif frequency == 2:
                    processes = self.get_processes_using_port(port)
                    if processes:
                        self.trigger_sound_alert(ThreatLevel.CRITICAL, f"Port {port} Active Process")
                        return f"🚨 CRITICAL: Port {port} used by processes: {processes} - RECOMMEND MANUAL REVIEW"
                    else:
                        self.trigger_sound_alert(ThreatLevel.EMERGENCY, f"Port {port} Stealth Activity")
                        return f"🚨 CRITICAL: Port {port} ({service}) active - no accessible process info"
                else:
                    self.trigger_sound_alert(ThreatLevel.EMERGENCY, f"Port {port} Persistent Threat")
                    return f"🚨 CRITICAL: Port {port} ({service}) PERSISTENT THREAT - IMMEDIATE ACTION REQUIRED"
            else:
                # Common legitimate ports
                if frequency <= 2:
                    return f"Standard port {port} ({service}) activity - monitoring"
                else:
                    return f"Port {port} ({service}) - established as normal system activity"
        
        except Exception as e:
            return f"Error handling port threat: {str(e)}"

    def handle_anomaly_threat_smart(self, threat_data, frequency, threat_level):
        """Smart handling of anomaly-based threats"""
        try:
            anomaly_type = threat_data.get('type', 'unknown')
            
            if frequency <= 2:
                return f"Detected {anomaly_type} anomaly - collecting baseline data"
            elif frequency <= 4:
                # Trigger sound for recurring anomalies
                self.trigger_sound_alert(ThreatLevel.MEDIUM, f"Recurring {anomaly_type}")
                return f"Recurring {anomaly_type} pattern - analyzing root cause"
            else:
                # After multiple occurrences, take corrective action
                self.trigger_sound_alert(ThreatLevel.HIGH, f"Persistent {anomaly_type}")
                corrective_action = self.take_corrective_action_for_anomaly(anomaly_type, threat_data)
                return f"PERSISTENT {anomaly_type} - {corrective_action}"
        
        except Exception as e:
            return f"Error handling anomaly: {str(e)}"

    def generate_threat_id(self, threat_type, threat_data):
        """Generate unique threat identifier"""
        try:
            if threat_type == 'ip_connection':
                return f"ip_{threat_data.get('remote_address', 'unknown')}"
            elif threat_type == 'port_scan':
                return f"port_{threat_data.get('port', 'unknown')}"
            elif threat_type == 'anomaly':
                return f"anomaly_{threat_data.get('type', 'unknown')}"
            else:
                return f"unknown_{str(threat_data)[:20]}"
        except:
            return f"error_{str(threat_data)[:20]}"

    def is_whitelisted_threat(self, threat_data):
        """Check if threat should be whitelisted (trusted source)"""
        try:
            if isinstance(threat_data, dict):
                # Check IP whitelist
                ip = threat_data.get('remote_address', '') or threat_data.get('remote_addr', '')
                if hasattr(self, 'threat_intelligence') and ip in self.threat_intelligence.get('whitelisted_ips', set()):
                    return True
                
                # Check for local network ranges
                if ip and ip.startswith(('127.', '192.168.', '10.', '172.')):
                    return True
                
                # Check for common safe services
                port = threat_data.get('port', 0)
                service = threat_data.get('service', '').lower()
                
                # Whitelist common safe services
                safe_services = ['http', 'https', 'ssh', 'dns', 'ntp']
                if service in safe_services and port in [22, 53, 80, 123, 443]:
                    return True
            
            return False
        except:
            return False

    def handle_ip_threat_smart(self, threat_data, frequency, threat_level):
        """Smart handling of IP-based threats"""
        try:
            ip = threat_data.get('remote_address', threat_data.get('remote_addr', 'unknown'))
            
            # Progressive response based on frequency
            if frequency == 1:
                # First occurrence - just monitor
                return f"Monitoring IP {ip} (first detection)"
            
            elif frequency == 2:
                # Second occurrence - add to watch list
                if hasattr(self, 'threat_intelligence'):
                    self.threat_intelligence['known_bad_ips'].add(ip)
                return f"Added IP {ip} to watch list (2nd detection)"
            
            elif frequency >= 3:
                # Third+ occurrence - escalate response
                if frequency == 3:
                    # Try to block IP (but don't spam if sudo fails)
                    try:
                        if not hasattr(self, '_failed_sudo_ips'):
                            self._failed_sudo_ips = set()
                        
                        if ip not in self._failed_sudo_ips:
                            # Try blocking without sudo first (user-level blocking)
                            self.soft_block_ip(ip)
                            return f"Soft-blocked IP {ip} (3rd detection)"
                        else:
                            return f"IP {ip} marked for manual blocking (sudo required)"
                    except:
                        if not hasattr(self, '_failed_sudo_ips'):
                            self._failed_sudo_ips = set()
                        self._failed_sudo_ips.add(ip)
                        return f"IP {ip} requires manual blocking"
                
                elif frequency >= 5:
                    # High frequency - add to permanent block list
                    if hasattr(self, 'threat_intelligence'):
                        self.threat_intelligence['blocked_ranges'].add(f"{ip}/32")
                    return f"IP {ip} added to permanent block list ({frequency}x detected)"
                
                else:
                    return f"Continued monitoring IP {ip} ({frequency}x detected)"
            
        except Exception as e:
            return f"Error handling IP threat: {str(e)}"

    def handle_port_threat_smart(self, threat_data, frequency, threat_level):
        """Smart handling of port-based threats"""
        try:
            port = threat_data.get('port', 'unknown')
            service = threat_data.get('service', 'unknown')
            
            # Progressive response based on frequency and risk
            if frequency == 1:
                return f"Detected service {service} on port {port} (monitoring)"
            
            elif frequency == 2:
                # Second occurrence - investigate processes
                processes = self.get_processes_using_port(port)
                if processes:
                    return f"Port {port}: Found processes {processes} (investigating)"
                else:
                    return f"Port {port}: No processes found (suspicious)"
            
            elif frequency >= 3:
                # Third+ occurrence - take action
                if threat_level in ['HIGH', 'CRITICAL']:
                    # Try to identify and terminate malicious process
                    action = self.terminate_malicious_process_on_port(port)
                    if action:
                        return f"Port {port}: {action}"
                    else:
                        if hasattr(self, 'threat_intelligence'):
                            self.threat_intelligence['suspicious_ports'].add(port)
                        return f"Port {port} marked as persistent threat"
                else:
                    return f"Port {port} under continued observation ({frequency}x)"
        
        except Exception as e:
            return f"Error handling port threat: {str(e)}"

    def handle_anomaly_threat_smart(self, threat_data, frequency, threat_level):
        """Smart handling of anomaly-based threats"""
        try:
            anomaly_type = threat_data.get('type', 'unknown')
            
            if frequency <= 2:
                return f"Anomaly {anomaly_type} detected (collecting data)"
            
            elif frequency <= 4:
                # Investigate root cause
                root_cause = self.investigate_anomaly_root_cause(anomaly_type, threat_data)
                return f"Anomaly {anomaly_type}: {root_cause}"
            
            else:
                # High frequency anomaly - take corrective action
                corrective_action = self.take_corrective_action_for_anomaly(anomaly_type, threat_data)
                return f"Anomaly {anomaly_type}: {corrective_action}"
        
        except Exception as e:
            return f"Error handling anomaly: {str(e)}"

    def soft_block_ip(self, ip):
        """Implement soft IP blocking without requiring sudo"""
        try:
            # Create user-level block list
            blocked_file = os.path.expanduser("~/.nimda_blocked_ips.txt")
            with open(blocked_file, 'a') as f:
                f.write(f"{ip}	{datetime.now().isoformat()}\n")
            
            # Add to runtime block list
            if hasattr(self, 'threat_intelligence'):
                self.threat_intelligence['known_bad_ips'].add(ip)
            
        except:
            pass

    def get_processes_using_port(self, port):
        """Get list of processes using a specific port"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    for conn in proc.connections():
                        if conn.laddr.port == int(port):
                            processes.append(f"{proc.info['name']}({proc.info['pid']})")
                except:
                    continue
            return processes[:3]  # Limit to first 3
        except:
            return []

    def terminate_malicious_process_on_port(self, port):
        """Attempt to terminate malicious processes on a port"""
        try:
            terminated = []
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    for conn in proc.connections():
                        if conn.laddr.port == int(port):
                            proc_name = proc.info['name']
                            
                            # Don't terminate critical system processes
                            safe_processes = ['kernel_task', 'launchd', 'systemd', 'sshd', 'nginx', 'apache2']
                            if proc_name.lower() not in safe_processes:
                                try:
                                    proc.terminate()
                                    terminated.append(proc_name)
                                except:
                                    pass
                except:
                    continue
            
            if terminated:
                return f"Terminated processes: {', '.join(terminated)}"
            else:
                return "No unsafe processes found to terminate"
                
        except:
            return "Could not investigate processes"

    def investigate_anomaly_root_cause(self, anomaly_type, anomaly_data):
        """Investigate the root cause of an anomaly"""
        try:
            if 'cpu' in anomaly_type.lower():
                # Investigate high CPU usage
                top_cpu = []
                for proc in psutil.process_iter(['name', 'cpu_percent']):
                    try:
                        if proc.cpu_percent() > 20:
                            top_cpu.append(f"{proc.info['name']}({proc.cpu_percent():.1f}%)")
                    except:
                        continue
                return f"High CPU from: {', '.join(top_cpu[:3])}"
            
            elif 'memory' in anomaly_type.lower():
                # Investigate high memory usage
                top_mem = []
                for proc in psutil.process_iter(['name', 'memory_percent']):
                    try:
                        if proc.memory_percent() > 10:
                            top_mem.append(f"{proc.info['name']}({proc.memory_percent():.1f}%)")
                    except:
                        continue
                return f"High memory from: {', '.join(top_mem[:3])}"
            
            elif 'network' in anomaly_type.lower():
                # Investigate network anomaly
                conn_count = len(psutil.net_connections())
                return f"Network anomaly: {conn_count} active connections"
            
            else:
                return f"Investigating {anomaly_type} anomaly"
                
        except:
            return f"Could not investigate {anomaly_type}"

    def take_corrective_action_for_anomaly(self, anomaly_type, anomaly_data):
        """Take corrective action for persistent anomalies"""
        try:
            if 'cpu' in anomaly_type.lower():
                # Try to limit high CPU processes
                limited = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        if proc.cpu_percent() > 80:
                            # Lower process priority
                            proc.nice(10)  # Lower priority
                            limited.append(proc.info['name'])
                    except:
                        continue
                return f"Limited CPU for: {', '.join(limited[:3])}"
            
            elif 'memory' in anomaly_type.lower():
                # Memory pressure - suggest cleanup
                return "Memory pressure detected - consider restarting memory-heavy processes"
            
            elif 'network' in anomaly_type.lower():
                # Network anomaly - increase monitoring
                return "Increased network monitoring activated"
            
            else:
                return f"Applied general mitigation for {anomaly_type}"
                
        except:
            return f"Could not mitigate {anomaly_type}"
    
    def init_ui(self):
        """Initialize user interface"""
        # Configure dark theme
        self.setup_dark_theme()
        
        # Create main notebook (tabbed interface)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_network_tab()
        self.create_ports_tab()
        self.create_anomalies_tab()
        self.create_llm_tab()
        self.create_logs_tab()
        self.create_emergency_tab()
        self.create_ai_providers_tab()
        self.create_task_scheduler_tab()
        self.create_security_policy_tab()
        self.create_devices_tab()
        self.create_processes_tab()
        
        # Create menu bar
        self.create_menu()
        
        # Status bar
        self.create_status_bar()
    
    def setup_dark_theme(self):
        """Setup dark theme for the entire application"""
        # Configure main window
        self.root.configure(bg='#1a1a1a')
        
        # Configure ttk style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Dark theme colors
        bg_color = '#1a1a1a'          # Dark background
        fg_color = '#ffffff'          # White text
        accent_color = '#2d2d2d'      # Slightly lighter background
        border_color = '#404040'      # Border color
        highlight_color = '#007acc'   # Blue highlight
        success_color = '#28a745'     # Green for success
        warning_color = '#ffc107'     # Yellow for warning
        danger_color = '#dc3545'      # Red for danger
        
        # Configure common elements
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, foreground=fg_color)
        style.configure('TButton', 
                       background=accent_color, 
                       foreground=fg_color,
                       borderwidth=1,
                       focuscolor=highlight_color)
        style.map('TButton',
                 background=[('active', highlight_color), ('pressed', accent_color)],
                 foreground=[('active', fg_color), ('pressed', fg_color)])
        
        # Configure notebook
        style.configure('TNotebook', background=bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background=accent_color, 
                       foreground=fg_color,
                       padding=[10, 5],
                       borderwidth=1)
        style.map('TNotebook.Tab',
                 background=[('selected', highlight_color), ('active', accent_color)],
                 foreground=[('selected', fg_color), ('active', fg_color)])
        
        # Configure treeview
        style.configure('Treeview', 
                       background=accent_color, 
                       foreground=fg_color,
                       fieldbackground=accent_color,
                       borderwidth=1)
        style.configure('Treeview.Heading', 
                       background=bg_color, 
                       foreground=fg_color,
                       borderwidth=1)
        style.map('Treeview',
                 background=[('selected', highlight_color)],
                 foreground=[('selected', fg_color)])
        
        # Configure entry
        style.configure('TEntry', 
                       fieldbackground=accent_color, 
                       foreground=fg_color,
                       borderwidth=1,
                       insertcolor=fg_color)
        
        # Configure combobox
        style.configure('TCombobox', 
                       fieldbackground=accent_color, 
                       background=accent_color,
                       foreground=fg_color,
                       borderwidth=1,
                       arrowcolor=fg_color)
        style.map('TCombobox',
                 fieldbackground=[('readonly', accent_color)],
                 selectbackground=[('readonly', highlight_color)])
        
        # Configure progressbar
        style.configure('Horizontal.TProgressbar', 
                       background=highlight_color, 
                       troughcolor=accent_color,
                       borderwidth=0)
        
        # Configure scrollbar
        style.configure('Vertical.TScrollbar', 
                       background=accent_color, 
                       troughcolor=bg_color,
                       borderwidth=0,
                       arrowcolor=fg_color)
        style.map('Vertical.TScrollbar',
                 background=[('active', highlight_color)])
        
        # Configure labelframe
        style.configure('TLabelframe', 
                       background=bg_color, 
                       foreground=fg_color,
                       borderwidth=1)
        style.configure('TLabelframe.Label', 
                       background=bg_color, 
                       foreground=fg_color)
        
        # Configure checkbutton
        style.configure('TCheckbutton', 
                       background=bg_color, 
                       foreground=fg_color)
        style.map('TCheckbutton',
                 background=[('active', bg_color)],
                 foreground=[('active', fg_color)])
        
        # Configure radiobutton
        style.configure('TRadiobutton', 
                       background=bg_color, 
                       foreground=fg_color)
        style.map('TRadiobutton',
                 background=[('active', bg_color)],
                 foreground=[('active', fg_color)])
        
        # Configure menubar
        style.configure('TMenubutton', 
                       background=accent_color, 
                       foreground=fg_color,
                       borderwidth=1)
        style.map('TMenubutton',
                 background=[('active', highlight_color)])
        
        # Configure separator
        style.configure('TSeparator', background=border_color)
        
        # Configure spinbox
        style.configure('TSpinbox', 
                       fieldbackground=accent_color, 
                       background=accent_color,
                       foreground=fg_color,
                       borderwidth=1,
                       arrowcolor=fg_color)
        
        # Configure scale
        style.configure('Horizontal.TScale', 
                       background=bg_color, 
                       troughcolor=accent_color,
                       borderwidth=0)
        
        # Configure listbox (for tk widgets)
        self.root.option_add('*Listbox.background', accent_color)
        self.root.option_add('*Listbox.foreground', fg_color)
        self.root.option_add('*Listbox.selectBackground', highlight_color)
        self.root.option_add('*Listbox.selectForeground', fg_color)
        
        # Configure text widget (for tk widgets)
        self.root.option_add('*Text.background', accent_color)
        self.root.option_add('*Text.foreground', fg_color)
        self.root.option_add('*Text.insertBackground', fg_color)
        self.root.option_add('*Text.selectBackground', highlight_color)
        
        # Configure entry widget (for tk widgets)
        self.root.option_add('*Entry.background', accent_color)
        self.root.option_add('*Entry.foreground', fg_color)
        self.root.option_add('*Entry.insertBackground', fg_color)
        self.root.option_add('*Entry.selectBackground', highlight_color)
        
        # Configure canvas
        self.root.option_add('*Canvas.background', bg_color)
        
        # Configure menu
        self.root.option_add('*Menu.background', accent_color)
        self.root.option_add('*Menu.foreground', fg_color)
        self.root.option_add('*Menu.selectBackground', highlight_color)
        self.root.option_add('*Menu.selectForeground', fg_color)
        
        # Configure messagebox
        self.root.option_add('*Dialog.background', bg_color)
        self.root.option_add('*Dialog.foreground', fg_color)
        
        # Store colors for later use
        self.dark_colors = {
            'bg': bg_color,
            'fg': fg_color,
            'accent': accent_color,
            'border': border_color,
            'highlight': highlight_color,
            'success': success_color,
            'warning': warning_color,
            'danger': danger_color
        }
    
    def apply_dark_theme_to_text_widget(self, text_widget):
        """Apply dark theme to a text widget"""
        if hasattr(self, 'dark_colors'):
            text_widget.configure(
                background=self.dark_colors['accent'],
                foreground=self.dark_colors['fg'],
                insertbackground=self.dark_colors['fg'],
                selectbackground=self.dark_colors['highlight'],
                selectforeground=self.dark_colors['fg']
            )
    
    def apply_dark_theme_to_entry_widget(self, entry_widget):
        """Apply dark theme to an entry widget"""
        if hasattr(self, 'dark_colors'):
            # For ttk.Entry, only configure supported options
            if isinstance(entry_widget, ttk.Entry):
                # ttk.Entry doesn't support insertbackground and selectbackground
                pass  # ttk.Entry is already styled by the theme
            else:
                # For tk.Entry, configure all options
                entry_widget.configure(
                    background=self.dark_colors['accent'],
                    foreground=self.dark_colors['fg'],
                    insertbackground=self.dark_colors['fg'],
                    selectbackground=self.dark_colors['highlight'],
                    selectforeground=self.dark_colors['fg']
                )
    
    def create_dashboard_tab(self):
        """Create comprehensive main dashboard tab with detailed system monitoring"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")
        
        # Main dashboard container that fills the entire tab
        main_dashboard_frame = ttk.Frame(dashboard_frame)
        main_dashboard_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create a two-column layout with left column taking more space
        left_column = ttk.Frame(main_dashboard_frame)
        left_column.pack(side='left', fill='both', expand=True, padx=(0, 5))
        
        # Add scrollbar for left column if needed
        left_canvas = tk.Canvas(left_column, bg='#2b2b2b')
        left_scrollbar = ttk.Scrollbar(left_column, orient="vertical", command=left_canvas.yview)
        left_scrollable_frame = ttk.Frame(left_canvas)
        
        left_scrollable_frame.bind(
            "<Configure>",
            lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all"))
        )
        
        left_canvas.create_window((0, 0), window=left_scrollable_frame, anchor="nw")
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        
        left_canvas.pack(side="left", fill="both", expand=True)
        left_scrollbar.pack(side="right", fill="y")
        
        # Right column with fixed width (narrower)
        right_column = ttk.Frame(main_dashboard_frame, width=300)  
        right_column.pack(side='right', fill='y', padx=(5, 0))
        right_column.pack_propagate(False)  # Prevent resizing based on content
        
        # ===== SYSTEM METRICS SECTION =====
        metrics_frame = ttk.LabelFrame(left_scrollable_frame, text="🖥️ System Metrics", padding=15)
        metrics_frame.pack(fill='x', padx=10, pady=5)
        
        # CPU and Memory with detailed info
        cpu_mem_frame = ttk.Frame(metrics_frame)
        cpu_mem_frame.pack(fill='x', pady=10)
        
        # CPU Section
        cpu_section = ttk.Frame(cpu_mem_frame)
        cpu_section.pack(fill='x', pady=5)
        
        ttk.Label(cpu_section, text="💻 CPU Usage:", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        cpu_details_frame = ttk.Frame(cpu_section)
        cpu_details_frame.pack(fill='x', pady=5)
        
        self.cpu_bar = ttk.Progressbar(cpu_details_frame, length=300, mode='determinate', style='TProgressbar')
        self.cpu_bar.pack(side='left', padx=(0, 10))
        
        self.cpu_label = ttk.Label(cpu_details_frame, text="0%", font=('Arial', 9, 'bold'))
        self.cpu_label.pack(side='left', padx=(0, 20))
        
        self.cpu_details_label = ttk.Label(cpu_details_frame, text="Cores: 0 | Load: 0.0 | Temp: N/A", font=('Arial', 8))
        self.cpu_details_label.pack(side='left')
        
        # Memory Section
        mem_section = ttk.Frame(cpu_mem_frame)
        mem_section.pack(fill='x', pady=5)
        
        ttk.Label(mem_section, text="🧠 Memory Usage:", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        mem_details_frame = ttk.Frame(mem_section)
        mem_details_frame.pack(fill='x', pady=5)
        
        self.mem_bar = ttk.Progressbar(mem_details_frame, length=300, mode='determinate', style='TProgressbar')
        self.mem_bar.pack(side='left', padx=(0, 10))
        
        self.mem_label = ttk.Label(mem_details_frame, text="0%", font=('Arial', 9, 'bold'))
        self.mem_label.pack(side='left', padx=(0, 20))
        
        self.mem_details_label = ttk.Label(mem_details_frame, text="Used: 0 GB | Free: 0 GB | Total: 0 GB", font=('Arial', 8))
        self.mem_details_label.pack(side='left')
        
        # ===== SECURITY STATUS SECTION =====
        security_frame = ttk.LabelFrame(left_scrollable_frame, text="🛡️ Security Status", padding=15)
        security_frame.pack(fill='x', padx=10, pady=5)
        
        # Threat Level Display
        threat_display_frame = ttk.Frame(security_frame)
        threat_display_frame.pack(fill='x', pady=5)
        
        self.threat_level_label = ttk.Label(threat_display_frame, text="🟢 LOW", font=('Arial', 12, 'bold'))
        self.threat_level_label.pack(side='left', padx=(0, 20))
        
        self.security_status_label = ttk.Label(threat_display_frame, text="Status: Initializing...", font=('Arial', 10))
        self.security_status_label.pack(side='left')
        
        # Security Metrics
        security_metrics_frame = ttk.Frame(security_frame)
        security_metrics_frame.pack(fill='x', pady=10)
        
        # Create metrics grid
        self.active_threats_label = ttk.Label(security_metrics_frame, text="Active Threats: 0", font=('Arial', 9))
        self.active_threats_label.grid(row=0, column=0, padx=10, pady=2, sticky='w')
        
        self.blocked_ips_label = ttk.Label(security_metrics_frame, text="Blocked IPs: 0", font=('Arial', 9))
        self.blocked_ips_label.grid(row=0, column=1, padx=10, pady=2, sticky='w')
        
        self.suspicious_processes_label = ttk.Label(security_metrics_frame, text="Suspicious Processes: 0", font=('Arial', 9))
        self.suspicious_processes_label.grid(row=0, column=2, padx=10, pady=2, sticky='w')
        
        self.open_ports_label = ttk.Label(security_metrics_frame, text="Open Ports: 0", font=('Arial', 9))
        self.open_ports_label.grid(row=1, column=0, padx=10, pady=2, sticky='w')
        
        self.anomalies_label = ttk.Label(security_metrics_frame, text="Anomalies: 0", font=('Arial', 9))
        self.anomalies_label.grid(row=1, column=1, padx=10, pady=2, sticky='w')
        
        self.last_scan_label = ttk.Label(security_metrics_frame, text="Last Scan: Never", font=('Arial', 9))
        self.last_scan_label.grid(row=1, column=2, padx=10, pady=2, sticky='w')
        
        # Add automated actions indicator
        self.automated_actions_label = ttk.Label(security_metrics_frame, text="Automated Actions: 0", font=('Arial', 9, 'bold'))
        self.automated_actions_label.grid(row=2, column=0, padx=10, pady=2, sticky='w')
        
        self.threat_patterns_label = ttk.Label(security_metrics_frame, text="Recurring Threats: 0", font=('Arial', 9))
        self.threat_patterns_label.grid(row=2, column=1, padx=10, pady=2, sticky='w')
        
        self.last_automated_action_label = ttk.Label(security_metrics_frame, text="Last Auto Action: Never", font=('Arial', 9))
        self.last_automated_action_label.grid(row=2, column=2, padx=10, pady=2, sticky='w')
        
        # ===== PROCESSES STATISTICS SECTION =====
        processes_frame = ttk.LabelFrame(right_column, text="⚙️ Processes Statistics", padding=15)
        processes_frame.pack(fill='x', padx=10, pady=5)
        
        # Process counts
        process_counts_frame = ttk.Frame(processes_frame)
        process_counts_frame.pack(fill='x', pady=5)
        
        self.total_processes_label = ttk.Label(process_counts_frame, text="Total Processes: 0", font=('Arial', 10, 'bold'))
        self.total_processes_label.pack(anchor='w', pady=2)
        
        self.dangerous_processes_label = ttk.Label(process_counts_frame, text="Dangerous: 0", font=('Arial', 9))
        self.dangerous_processes_label.pack(anchor='w', pady=1)
        
        self.medium_processes_label = ttk.Label(process_counts_frame, text="Medium Risk: 0", font=('Arial', 9))
        self.medium_processes_label.pack(anchor='w', pady=1)
        
        self.safe_processes_label = ttk.Label(process_counts_frame, text="Safe: 0", font=('Arial', 9))
        self.safe_processes_label.pack(anchor='w', pady=1)
        
        # ===== CONNECTIONS STATISTICS SECTION =====
        connections_frame = ttk.LabelFrame(right_column, text="🌐 Network Connections", padding=15)
        connections_frame.pack(fill='x', padx=10, pady=5)
        
        # Connection counts
        connection_counts_frame = ttk.Frame(connections_frame)
        connection_counts_frame.pack(fill='x', pady=5)
        
        self.total_connections_label = ttk.Label(connection_counts_frame, text="Total Connections: 0", font=('Arial', 10, 'bold'))
        self.total_connections_label.pack(anchor='w', pady=2)
        
        self.external_connections_label = ttk.Label(connection_counts_frame, text="External: 0", font=('Arial', 9))
        self.external_connections_label.pack(anchor='w', pady=1)
        
        self.internal_connections_label = ttk.Label(connection_counts_frame, text="Internal: 0", font=('Arial', 9))
        self.internal_connections_label.pack(anchor='w', pady=1)
        
        self.blocked_connections_label = ttk.Label(connection_counts_frame, text="Blocked: 0", font=('Arial', 9))
        self.blocked_connections_label.pack(anchor='w', pady=1)
        
        # ===== SECURITY ACTIONS SECTION =====
        actions_frame = ttk.LabelFrame(left_scrollable_frame, text="🛡️ Security Actions", padding=15)
        actions_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Actions log
        actions_log_frame = ttk.Frame(actions_frame)
        actions_log_frame.pack(fill='x', pady=5)
        
        self.actions_text = scrolledtext.ScrolledText(actions_log_frame, height=12, wrap='word', font=('Arial', 9))
        self.actions_text.pack(fill='both', expand=True)
        
        # Apply dark theme to text widget
        self.apply_dark_theme_to_text_widget(self.actions_text)
        
        # ===== QUICK ACTIONS SECTION =====
        quick_actions_frame = ttk.LabelFrame(right_column, text="⚡ Quick Actions", padding=15)
        quick_actions_frame.pack(fill='x', padx=10, pady=5)
        
        # Quick actions buttons arranged vertically
        ttk.Button(quick_actions_frame, text="🔍 Full System Scan", command=self.full_scan, style='TButton').pack(fill='x', pady=2)
        ttk.Button(quick_actions_frame, text="🛡️ Emergency Lockdown", command=self.emergency_lockdown, style='TButton').pack(fill='x', pady=2)
        ttk.Button(quick_actions_frame, text="📊 System Information", command=self.show_system_info).pack(fill='x', pady=2)
        ttk.Button(quick_actions_frame, text=" Test AI Analysis", command=self.test_llm).pack(fill='x', pady=2)
        ttk.Button(quick_actions_frame, text="🔄 Refresh All", command=self.refresh_dashboard).pack(fill='x', pady=2)
        ttk.Button(quick_actions_frame, text="📈 Performance", command=self.show_performance_details).pack(fill='x', pady=2)
        ttk.Button(quick_actions_frame, text="🗑️ Clear Actions Log", command=self.clear_actions_log).pack(fill='x', pady=2)
        ttk.Button(quick_actions_frame, text="📋 Export Report", command=self.export_dashboard_report).pack(fill='x', pady=2)
        
        # Sound testing buttons
        ttk.Button(quick_actions_frame, text="🔊 Test Sound System", command=self.test_sound_system, style='TButton').pack(fill='x', pady=2)
        ttk.Button(quick_actions_frame, text="🚨 Force Threat Detection", command=self.force_threat_detection, style='TButton').pack(fill='x', pady=2)
        
        # ===== REAL-TIME MONITORING SECTION =====
        monitoring_frame = ttk.LabelFrame(right_column, text="📡 Real-Time Monitoring", padding=15)
        monitoring_frame.pack(fill='x', padx=10, pady=5)
        
        # Network activity
        network_frame = ttk.Frame(monitoring_frame)
        network_frame.pack(fill='x', pady=5)
        
        ttk.Label(network_frame, text="🌐 Network Activity:", font=('Arial', 9, 'bold')).pack(anchor='w')
        self.network_activity_label = ttk.Label(network_frame, text="Connections: 0 | Data In: 0 KB/s | Data Out: 0 KB/s", font=('Arial', 8))
        self.network_activity_label.pack(anchor='w', pady=2)
        
        # Disk activity
        disk_frame = ttk.Frame(monitoring_frame)
        disk_frame.pack(fill='x', pady=5)
        
        ttk.Label(disk_frame, text="💾 Disk Activity:", font=('Arial', 9, 'bold')).pack(anchor='w')
        self.disk_activity_label = ttk.Label(disk_frame, text="Read: 0 KB/s | Write: 0 KB/s | Free Space: 0 GB", font=('Arial', 8))
        self.disk_activity_label.pack(anchor='w', pady=2)
        
        # System uptime
        uptime_frame = ttk.Frame(monitoring_frame)
        uptime_frame.pack(fill='x', pady=5)
        
        ttk.Label(uptime_frame, text="⏰ System Uptime:", font=('Arial', 9, 'bold')).pack(anchor='w')
        self.uptime_label = ttk.Label(uptime_frame, text="Uptime: 0 days, 0 hours, 0 minutes", font=('Arial', 8))
        self.uptime_label.pack(anchor='w', pady=2)
        
        # Store references for updates
        self.dashboard_elements = {
            'cpu_bar': self.cpu_bar,
            'cpu_label': self.cpu_label,
            'cpu_details_label': self.cpu_details_label,
            'mem_bar': self.mem_bar,
            'mem_label': self.mem_label,
            'mem_details_label': self.mem_details_label,
            'threat_level_label': self.threat_level_label,
            'security_status_label': self.security_status_label,
            'active_threats_label': self.active_threats_label,
            'blocked_ips_label': self.blocked_ips_label,
            'suspicious_processes_label': self.suspicious_processes_label,
            'open_ports_label': self.open_ports_label,
            'anomalies_label': self.anomalies_label,
            'last_scan_label': self.last_scan_label,
            'automated_actions_label': self.automated_actions_label,
            'threat_patterns_label': self.threat_patterns_label,
            'last_automated_action_label': self.last_automated_action_label,
            'total_processes_label': self.total_processes_label,
            'dangerous_processes_label': self.dangerous_processes_label,
            'medium_processes_label': self.medium_processes_label,
            'safe_processes_label': self.safe_processes_label,
            'total_connections_label': self.total_connections_label,
            'external_connections_label': self.external_connections_label,
            'internal_connections_label': self.internal_connections_label,
            'blocked_connections_label': self.blocked_connections_label,
            'actions_text': self.actions_text,
            'network_activity_label': self.network_activity_label,
            'disk_activity_label': self.disk_activity_label,
            'uptime_label': self.uptime_label
        }
    
    def create_network_tab(self):
        """Create network monitoring tab"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="🌐 Network")
        
        # Network connections
        conn_frame = ttk.LabelFrame(network_frame, text="Active Connections", padding=10)
        conn_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Connections treeview
        columns = ('Local Address', 'Remote Address', 'Status', 'PID', 'Process', 'Threat Level')
        self.connections_tree = ttk.Treeview(conn_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.connections_tree.heading(col, text=col)
            self.connections_tree.column(col, width=150)
        
        # Scrollbar
        conn_scrollbar = ttk.Scrollbar(conn_frame, orient='vertical', command=self.connections_tree.yview)
        self.connections_tree.configure(yscrollcommand=conn_scrollbar.set)
        
        self.connections_tree.pack(side='left', fill='both', expand=True)
        conn_scrollbar.pack(side='right', fill='y')
        
        # Control buttons
        button_frame = ttk.Frame(network_frame)
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="🔄 Refresh", command=self.refresh_network).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔍 Analyze", command=self.analyze_network).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🚫 Block IP", command=self.block_ip).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔬 Deep Analyze", command=self.deep_analyze_address).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📊 All Addresses", command=self.analyze_all_addresses).pack(side='left', padx=5)
    
    def create_ports_tab(self):
        """Create port scanning tab"""
        ports_frame = ttk.Frame(self.notebook)
        self.notebook.add(ports_frame, text="🔌 Ports")
        
        # Port scan results
        ports_scan_frame = ttk.LabelFrame(ports_frame, text="Port Scan Results", padding=10)
        ports_scan_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Ports treeview
        columns = ('Port', 'Service', 'Status', 'Risk', 'Timestamp', 'Threat Level')
        self.ports_tree = ttk.Treeview(ports_scan_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.ports_tree.heading(col, text=col)
            self.ports_tree.column(col, width=120)
        
        # Scrollbar
        ports_scrollbar = ttk.Scrollbar(ports_scan_frame, orient='vertical', command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=ports_scrollbar.set)
        
        self.ports_tree.pack(side='left', fill='both', expand=True)
        ports_scrollbar.pack(side='right', fill='y')
        
        # Control buttons
        button_frame = ttk.Frame(ports_frame)
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="🔍 Scan Ports", command=self.scan_ports).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🚫 Close Port", command=self.close_port).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📊 Port Stats", command=self.port_stats).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔬 Deep Analyze", command=self.deep_analyze_port).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📊 All Ports", command=self.analyze_all_ports).pack(side='left', padx=5)
    
    def create_anomalies_tab(self):
        """Create anomaly detection tab"""
        anomalies_frame = ttk.Frame(self.notebook)
        self.notebook.add(anomalies_frame, text="⚠️ Anomalies")
        
        # Anomalies list
        anomalies_list_frame = ttk.LabelFrame(anomalies_frame, text="Detected Anomalies", padding=10)
        anomalies_list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Anomalies treeview
        columns = ('Type', 'Severity', 'Description', 'Timestamp', 'Threat Level')
        self.anomalies_tree = ttk.Treeview(anomalies_list_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.anomalies_tree.heading(col, text=col)
            self.anomalies_tree.column(col, width=150)
        
        # Scrollbar
        anomalies_scrollbar = ttk.Scrollbar(anomalies_list_frame, orient='vertical', command=self.anomalies_tree.yview)
        self.anomalies_tree.configure(yscrollcommand=anomalies_scrollbar.set)
        
        self.anomalies_tree.pack(side='left', fill='both', expand=True)
        anomalies_scrollbar.pack(side='right', fill='y')
        
        # Control buttons
        button_frame = ttk.Frame(anomalies_frame)
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="🔍 Detect", command=self.detect_anomalies).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🗑️ Clear", command=self.clear_anomalies).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📊 Baseline", command=self.show_baseline).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔬 Analyze", command=self.analyze_selected_anomaly).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🌐 Language", command=self.switch_language).pack(side='right', padx=5)
    
    def create_llm_tab(self):
        """Create LLM agent tab"""
        llm_frame = ttk.Frame(self.notebook)
        self.notebook.add(llm_frame, text="🤖 AI Analysis")
        
        # Status
        status_frame = ttk.LabelFrame(llm_frame, text="Ollama Status", padding=10)
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.ollama_status_label = ttk.Label(status_frame, text="Status: Checking...")
        self.ollama_status_label.pack(anchor='w')
        
        # AI Language indicator
        self.ai_language_label = ttk.Label(status_frame, text="AI Language: English")
        self.ai_language_label.pack(anchor='w')
        
        # Language toggle button
        self.ai_language_btn = ttk.Button(status_frame, text="🌐 Switch AI Language", command=self.switch_ai_language)
        self.ai_language_btn.pack(anchor='w', pady=5)
        
        # Query input
        query_frame = ttk.LabelFrame(llm_frame, text="Security Analysis", padding=10)
        query_frame.pack(fill='x', padx=10, pady=5)
        
        self.query_entry = ttk.Entry(query_frame, width=60)
        self.query_entry.pack(fill='x', pady=5)
        self.query_entry.insert(0, "Ask about security threats, analyze connections, or get recommendations...")
        
        # Quick actions
        actions_frame = ttk.Frame(query_frame)
        actions_frame.pack(fill='x', pady=5)
        
        ttk.Button(actions_frame, text="🔍 Analyze Threats", command=self.analyze_threats).pack(side='left', padx=5)
        ttk.Button(actions_frame, text="💡 Get Recommendations", command=self.get_recommendations).pack(side='left', padx=5)
        ttk.Button(actions_frame, text="🛡️ Security Report", command=self.security_report).pack(side='left', padx=5)
        ttk.Button(actions_frame, text="🚨 Emergency Analysis", command=self.emergency_analysis).pack(side='left', padx=5)
        
        # Response area
        response_frame = ttk.LabelFrame(llm_frame, text="AI Response", padding=10)
        response_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.response_text = scrolledtext.ScrolledText(response_frame, height=20, wrap='word')
        self.response_text.pack(fill='both', expand=True)
        
        # Apply dark theme to text widgets
        self.apply_dark_theme_to_text_widget(self.response_text)
        self.apply_dark_theme_to_entry_widget(self.query_entry)
        
        # Send button
        send_btn = ttk.Button(llm_frame, text="🚀 Send Query", command=self.send_query)
        send_btn.pack(pady=10)
    
    def create_logs_tab(self):
        """Create security logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📋 Logs")
        
        # Logs area
        logs_area_frame = ttk.LabelFrame(logs_frame, text="Security Logs", padding=10)
        logs_area_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.logs_text = scrolledtext.ScrolledText(logs_area_frame, height=25, wrap='word')
        self.logs_text.pack(fill='both', expand=True)
        
        # Apply dark theme to text widget
        self.apply_dark_theme_to_text_widget(self.logs_text)
        
        # Control buttons
        button_frame = ttk.Frame(logs_frame)
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="🔄 Refresh", command=self.refresh_logs).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🗑️ Clear", command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(button_frame, text="💾 Save", command=self.save_logs).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📊 Export", command=self.export_logs).pack(side='left', padx=5)
    
    def create_menu(self):
        """Create application menu"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Security menu
        security_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Security", menu=security_menu)
        security_menu.add_command(label="Full Scan", command=self.full_scan)
        security_menu.add_command(label="Threat Assessment", command=self.threat_assessment)
        security_menu.add_command(label="Emergency Lockdown", command=self.emergency_lockdown)
        security_menu.add_separator()
        security_menu.add_command(label="System Info", command=self.show_system_info)
        
        # Privileges menu
        privileges_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Privileges", menu=privileges_menu)
        privileges_menu.add_command(label="Request Privileges", command=self.show_privilege_dialog)
        privileges_menu.add_command(label="Privilege Status", command=self.show_privilege_status)
        privileges_menu.add_separator()
        privileges_menu.add_command(label="Revoke Privileges", command=self.privilege_manager.revoke_privileges)
        
        # Sound menu
        sound_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Sound", menu=sound_menu)
        sound_menu.add_command(label="Test Sound System", command=self.test_sound_system)
        sound_menu.add_command(label="Sound Settings", command=self.show_sound_settings)
        sound_menu.add_separator()
        sound_menu.add_command(label="Toggle Sound Alerts", command=self.toggle_sound_alerts)
        
        # AI menu
        ai_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="AI", menu=ai_menu)
        ai_menu.add_command(label="Test LLM", command=self.test_llm)
        ai_menu.add_command(label="Switch Language", command=self.switch_ai_language)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_status_bar(self):
        """Create status bar"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side='bottom', fill='x')
        
        # Status information
        self.status_label = ttk.Label(status_frame, text="Ready", relief='sunken')
        self.status_label.pack(side='left', fill='x', expand=True)
        
        # Privilege indicator
        self.privilege_indicator = ttk.Label(status_frame, text="🔒", relief='sunken', width=3)
        self.privilege_indicator.pack(side='right')
        
        # Sound indicator
        self.sound_indicator = ttk.Label(status_frame, text="🔊", relief='sunken', width=3)
        self.sound_indicator.pack(side='right')
        
        # Update sound indicator
        self.update_sound_indicator()
    
    def update_sound_indicator(self):
        """Update sound indicator in status bar"""
        if hasattr(self, 'sound_system') and self.sound_system.enabled:
            self.sound_indicator.config(text="🔊")
        else:
            self.sound_indicator.config(text="🔇")
    
    def init_security_system(self):
        """Initialize security monitoring system"""
        if not SECURITY_MODULES_AVAILABLE:
            if hasattr(self, 'log_message'):
                self.log_message("WARNING: Security modules not available!")
            return
        
        try:
            # Initialize security monitor
            self.security_monitor = SecurityMonitor()
            self.security_monitor.start_monitoring()
            
            # Initialize LLM agent
            self.llm_agent = LLMSecurityAgent()
            
            # Initialize AI provider manager
            self.ai_provider_manager = AIProviderManager()
            
            # Initialize task scheduler
            self.task_scheduler = TaskScheduler()
            
            # Start monitoring thread
            self.monitor_thread = SecurityMonitorThread(self.on_security_update)
            self.monitor_thread.start()
            
            # Check Ollama status (only if UI is ready)
            if hasattr(self, 'ollama_status_label'):
                self.check_ollama_status()
            
            # Update AI language indicator (only if UI is ready)
            if hasattr(self, 'ai_language_label'):
                self.update_ai_language_indicator()
            
            # Load initial data immediately
            self.load_initial_data()
            
            if hasattr(self, 'log_message'):
                self.log_message("Security system initialized successfully")
            
        except Exception as e:
            if hasattr(self, 'log_message'):
                self.log_message(f"ERROR: Failed to initialize security system: {str(e)}")
            print(f"ERROR: Failed to initialize security system: {str(e)}")
    
    def check_ollama_status(self):
        """Check Ollama connection status"""
        if not SECURITY_MODULES_AVAILABLE:
            return
        
        try:
            if self.llm_agent and self.llm_agent.check_ollama_connection():
                models = self.llm_agent.get_available_models()
                if hasattr(self, 'ollama_status_label') and self.ollama_status_label:
                    self.ollama_status_label.config(text=f"Status: ✅ Connected ({len(models)} models)")
                self.log_message(f"Ollama connected with {len(models)} models")
            else:
                if hasattr(self, 'ollama_status_label') and self.ollama_status_label:
                    self.ollama_status_label.config(text="Status: ❌ Not connected")
                self.log_message("WARNING: Ollama not connected")
        except Exception as e:
            if hasattr(self, 'ollama_status_label') and self.ollama_status_label:
                self.ollama_status_label.config(text="Status: ❌ Error")
            self.log_message(f"ERROR: Ollama connection failed: {e}")
    
    def load_initial_data(self):
        """Load initial data immediately"""
        try:
            # Get initial network data
            network_scanner = NetworkScanner()
            connections = network_scanner.scan_network_connections()
            port_scan = network_scanner.scan_local_ports()
            print(f"[DEBUG] load_initial_data: port_scan={port_scan}")
            
            # Get initial system info
            system_info = self.get_initial_system_info()
            
            # Get initial anomalies
            anomaly_detector = AnomalyDetector()
            anomalies = anomaly_detector.detect_anomalies()
            
            # Update UI with initial data
            security_status = {
                'port_scan': port_scan,
                'connections': connections,
                'anomalies': anomalies,
                'system_info': system_info,
                'timestamp': datetime.now().isoformat()
            }
            
            # Update UI components immediately
            self.update_connections_tree(connections)
            self.update_ports_tree(port_scan)
            self.update_anomalies_tree(anomalies)
            self.update_threat_level(security_status)
            
            self.on_security_update(security_status)
            self.log_message(f"Initial data loaded: {len(connections)} connections, {len(port_scan)} ports")
            
        except Exception as e:
            self.log_message(f"ERROR: Failed to load initial data: {str(e)}")
    
    def get_initial_system_info(self):
        """Get initial system information"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available': memory.available // (1024**3),  # GB
                'disk_percent': disk.percent,
                'disk_free': disk.free // (1024**3),  # GB
                'network_sent': network.bytes_sent // (1024**2),  # MB
                'network_recv': network.bytes_recv // (1024**2),  # MB
                'processes': len(psutil.pids())
            }
        except:
            return {}
    
    def update_ui(self):
        """Update UI elements"""
        # Update system metrics
        self.update_system_metrics()
        
        # Update processes statistics
        self.update_processes_statistics()
        
        # Update connections statistics
        self.update_connections_statistics()
        
        # Update threats and security metrics
        self.update_threats_dashboard()
        
        # Update real-time monitoring
        self.update_real_time_monitoring()
        
        # Schedule next update
        self.root.after(2000, self.update_ui)
    
    def update_system_metrics(self):
        """Update CPU and memory metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            mem_percent = memory.percent
            mem_used_gb = memory.used / (1024**3)
            mem_free_gb = memory.available / (1024**3)
            mem_total_gb = memory.total / (1024**3)
            
            # Update UI elements
            if hasattr(self, 'cpu_bar'):
                self.cpu_bar['value'] = cpu_percent
                self.cpu_label.config(text=f"{cpu_percent:.1f}%")
                self.cpu_details_label.config(text=f"Cores: {cpu_count} | Load: {cpu_percent/100:.2f} | Freq: {cpu_freq.current/1000:.1f} GHz")
            
            if hasattr(self, 'mem_bar'):
                self.mem_bar['value'] = mem_percent
                self.mem_label.config(text=f"{mem_percent:.1f}%")
                self.mem_details_label.config(text=f"Used: {mem_used_gb:.1f} GB | Free: {mem_free_gb:.1f} GB | Total: {mem_total_gb:.1f} GB")
                
        except Exception as e:
            print(f"Error updating system metrics: {e}")
    
    def update_processes_statistics(self):
        """Update processes statistics instead of full list"""
        try:
            # Get processes count
            total_processes = len(psutil.pids())
            
            # Get top processes by CPU usage for analysis
            processes = []
            dangerous_count = 0
            medium_count = 0
            safe_count = 0
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username', 'cmdline']):
                try:
                    proc_info = proc.info
                    # Handle None values for CPU and memory percentages
                    cpu_percent = proc_info.get('cpu_percent', 0) or 0
                    memory_percent = proc_info.get('memory_percent', 0) or 0
                    
                    if cpu_percent > 0:  # Only analyze processes with CPU usage
                        processes.append({
                            'pid': proc_info.get('pid', 0),
                            'name': proc_info.get('name', 'Unknown'),
                            'cpu_percent': cpu_percent,
                            'memory_percent': memory_percent,
                            'status': proc_info.get('status', 'Unknown'),
                            'username': proc_info.get('username', 'Unknown'),
                            'cmdline': proc_info.get('cmdline', [])
                        })
                        
                        # Categorize by risk level
                        if cpu_percent > 50 or memory_percent > 20:
                            dangerous_count += 1
                        elif cpu_percent > 20 or memory_percent > 10:
                            medium_count += 1
                        else:
                            safe_count += 1
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Update labels
            if hasattr(self, 'total_processes_label'):
                self.total_processes_label.config(text=f"Total Processes: {total_processes}")
            
            if hasattr(self, 'dangerous_processes_label'):
                self.dangerous_processes_label.config(text=f"Dangerous: {dangerous_count}")
            
            if hasattr(self, 'medium_processes_label'):
                self.medium_processes_label.config(text=f"Medium Risk: {medium_count}")
            
            if hasattr(self, 'safe_processes_label'):
                self.safe_processes_label.config(text=f"Safe: {safe_count}")
                    
        except Exception as e:
            print(f"Error updating processes statistics: {e}")
    
    def update_connections_statistics(self):
        """Update connections statistics instead of full list"""
        try:
            # Get network connections safely
            try:
                connections = psutil.net_connections()
                total_connections = len(connections)
            except (psutil.AccessDenied, psutil.ZombieProcess):
                connections = []
                total_connections = 0
            
            external_count = 0
            internal_count = 0
            blocked_count = 0
            
            for conn in connections:
                try:
                    if conn.status == 'ESTABLISHED':
                        remote_ip = conn.raddr.ip if conn.raddr else None
                        if remote_ip:
                            # Check if external IP
                            if not (remote_ip.startswith('127.') or remote_ip.startswith('192.168.') or remote_ip.startswith('10.')):
                                external_count += 1
                            else:
                                internal_count += 1
                    elif conn.status == 'TIME_WAIT' or conn.status == 'CLOSE_WAIT':
                        blocked_count += 1
                except:
                    continue
            
            # Update labels
            if hasattr(self, 'total_connections_label'):
                self.total_connections_label.config(text=f"Total Connections: {total_connections}")
            
            if hasattr(self, 'external_connections_label'):
                self.external_connections_label.config(text=f"External: {external_count}")
            
            if hasattr(self, 'internal_connections_label'):
                self.internal_connections_label.config(text=f"Internal: {internal_count}")
            
            if hasattr(self, 'blocked_connections_label'):
                self.blocked_connections_label.config(text=f"Blocked: {blocked_count}")
                
        except Exception as e:
            print(f"Error updating connections statistics: {e}")
    
    def update_threats_dashboard(self):
        """Enhanced threat dashboard with intelligent analysis and adaptive response"""
        try:
            # Get current security data
            connections = getattr(self, 'current_connections', [])
            port_scan = getattr(self, 'current_port_scan', [])
            anomalies = getattr(self, 'current_anomalies', [])
            
            # Perform adaptive threat intelligence analysis
            self.perform_adaptive_threat_analysis(port_scan, connections, anomalies)
            
            # Update security metrics with enhanced information
            self.update_security_metrics_enhanced(connections, port_scan, anomalies)
            
            # Generate intelligent threat summary
            self.generate_intelligent_threat_summary(connections, port_scan, anomalies)
                
        except Exception as e:
            print(f"Error updating enhanced threats dashboard: {e}")

    def update_security_metrics_enhanced(self, connections, port_scan, anomalies):
        """Enhanced security metrics with intelligent threat analysis"""
        try:
            # Basic threat counts
            active_threats = len(connections) + len(port_scan) + len(anomalies)
            
            # Advanced threat analysis
            threat_analysis = {
                'critical_threats': 0,
                'coordinated_attacks': 0,
                'blocked_sources': 0,
                'adaptive_actions': 0
            }
            
            # Analyze threat levels with context
            for conn in connections:
                if isinstance(conn, dict):
                    threat_level = self.threat_analyzer.analyze_address_threat(conn.get('remote_addr', ''))
                    if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        threat_analysis['critical_threats'] += 1
                    
                    # Check if source is blocked
                    ip = conn.get('remote_addr', '')
                    if ip in getattr(self, 'threat_intelligence', {}).get('known_bad_ips', set()):
                        threat_analysis['blocked_sources'] += 1
            
            for port in port_scan:
                if isinstance(port, dict):
                    threat_level = self.threat_analyzer.analyze_port_threat(port.get('port', 0), port.get('service', ''))
                    if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        threat_analysis['critical_threats'] += 1
            
            for anomaly in anomalies:
                if isinstance(anomaly, dict):
                    threat_level = self.threat_analyzer.analyze_anomaly_threat(anomaly)
                    if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        threat_analysis['critical_threats'] += 1
            
            # Count adaptive actions taken
            recent_actions = [a for a in self.automated_actions if 
                            (datetime.now() - a['timestamp']).seconds < 300]  # Last 5 minutes
            threat_analysis['adaptive_actions'] = len(recent_actions)
            
            # Update enhanced labels
            if hasattr(self, 'active_threats_label'):
                self.active_threats_label.config(text=f"Active Threats: {active_threats}")
            
            if hasattr(self, 'blocked_ips_label'):
                self.blocked_ips_label.config(text=f"Critical Threats: {threat_analysis['critical_threats']}")
            
            if hasattr(self, 'open_ports_label'):
                self.open_ports_label.config(text=f"Open Ports: {len(port_scan)}")
            
            if hasattr(self, 'anomalies_label'):
                self.anomalies_label.config(text=f"Anomalies: {len(anomalies)}")
            
            if hasattr(self, 'last_scan_label'):
                self.last_scan_label.config(text=f"Last Scan: {datetime.now().strftime('%H:%M:%S')}")
            
            # Enhanced automated actions metrics
            if hasattr(self, 'automated_actions_label'):
                self.automated_actions_label.config(text=f"Smart Actions: {len(self.automated_actions)}")
            
            if hasattr(self, 'threat_patterns_label'):
                intelligent_threats = sum(1 for count in self.threat_counters.values() if count >= 2)
                self.threat_patterns_label.config(text=f"Intelligence Patterns: {intelligent_threats}")
            
            if hasattr(self, 'last_automated_action_label'):
                if self.last_automated_action:
                    last_action_time = self.last_automated_action.strftime('%H:%M:%S')
                    self.last_automated_action_label.config(text=f"Last Smart Action: {last_action_time}")
                else:
                    self.last_automated_action_label.config(text="Last Smart Action: Never")
                
        except Exception as e:
            print(f"Error updating enhanced security metrics: {e}")
    
    def generate_intelligent_threat_summary(self, connections, port_scan, anomalies):
        """Generate intelligent threat summary for the actions log"""
        try:
            if not hasattr(self, 'actions_text'):
                return
            
            # Generate summary every 30 seconds to avoid spam
            current_time = datetime.now()
            if (hasattr(self, '_last_summary_time') and 
                (current_time - self._last_summary_time).seconds < 30):
                return
            
            self._last_summary_time = current_time
            
            # Analyze threat landscape
            summary_data = {
                'total_threats': len(connections) + len(port_scan) + len(anomalies),
                'high_risk_connections': 0,
                'suspicious_ports': 0,
                'critical_anomalies': 0,
                'adaptive_responses': 0,
                'learning_insights': []
            }
            
            # Count threat types
            for conn in connections:
                if isinstance(conn, dict):
                    threat_level = self.threat_analyzer.analyze_address_threat(conn.get('remote_addr', ''))
                    if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        summary_data['high_risk_connections'] += 1
            
            for port in port_scan:
                if isinstance(port, dict):
                    if port.get('risk') in ['HIGH', 'CRITICAL']:
                        summary_data['suspicious_ports'] += 1
            
            for anomaly in anomalies:
                if isinstance(anomaly, dict):
                    threat_level = self.threat_analyzer.analyze_anomaly_threat(anomaly)
                    if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        summary_data['critical_anomalies'] += 1
            
            # Count recent adaptive responses
            recent_actions = [a for a in self.automated_actions if 
                            (current_time - a['timestamp']).seconds < 60]  # Last minute
            summary_data['adaptive_responses'] = len(recent_actions)
            
            # Generate learning insights
            if hasattr(self, 'threat_intelligence'):
                known_bad_count = len(self.threat_intelligence.get('known_bad_ips', set()))
                if known_bad_count > 0:
                    summary_data['learning_insights'].append(f"Tracking {known_bad_count} known bad IPs")
                
                blocked_count = len(self.threat_intelligence.get('blocked_ranges', set()))
                if blocked_count > 0:
                    summary_data['learning_insights'].append(f"{blocked_count} IP ranges blocked")
            
            # Only log if there's significant activity
            if summary_data['total_threats'] > 0 or summary_data['adaptive_responses'] > 0:
                timestamp = current_time.strftime('%H:%M:%S')
                summary_text = f"[{timestamp}] 📊 INTELLIGENT THREAT SUMMARY:\n"
                summary_text += f"  • Total Threats: {summary_data['total_threats']}\n"
                
                if summary_data['high_risk_connections'] > 0:
                    summary_text += f"  • High-Risk Connections: {summary_data['high_risk_connections']}\n"
                
                if summary_data['suspicious_ports'] > 0:
                    summary_text += f"  • Suspicious Ports: {summary_data['suspicious_ports']}\n"
                
                if summary_data['critical_anomalies'] > 0:
                    summary_text += f"  • Critical Anomalies: {summary_data['critical_anomalies']}\n"
                
                if summary_data['adaptive_responses'] > 0:
                    summary_text += f"  • Adaptive Responses (1m): {summary_data['adaptive_responses']}\n"
                
                for insight in summary_data['learning_insights']:
                    summary_text += f"  • {insight}\n"
                
                summary_text += "\n"
                
                self.add_action_to_log(summary_text)
                
        except Exception as e:
            print(f"Error generating intelligent threat summary: {e}")
    
    def perform_adaptive_threat_analysis(self, port_scan, connections, anomalies):
        """Perform adaptive threat analysis that learns from patterns"""
        try:
            current_time = datetime.now()
            
            # Analyze threat patterns across all types
            threat_correlation = self.analyze_threat_correlations(port_scan, connections, anomalies)
            
            # Adaptive thresholds based on current threat landscape
            self.adjust_adaptive_thresholds(threat_correlation)
            
            # Smart threat prioritization
            prioritized_threats = self.prioritize_threats_intelligently(port_scan, connections, anomalies)
            
            # Process prioritized threats with context-aware responses
            for threat in prioritized_threats[:5]:  # Handle top 5 threats
                response = self.context_aware_threat_response(threat)
                if response and "Skipped" not in response:
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    self.add_action_to_log(f"[{timestamp}] 🎯 PRIORITY ACTION: {response}\n")
                
        except Exception as e:
            print(f"Error in adaptive threat analysis: {e}")
    
    def analyze_threat_correlations(self, port_scan, connections, anomalies):
        """Analyze correlations between different threat types"""
        try:
            correlations = {
                'coordinated_attack': False,
                'port_scanning_activity': False,
                'data_exfiltration_attempt': False,
                'system_compromise_indicators': False
            }
            
            # Check for coordinated attacks (multiple threat types from same source)
            source_threats = {}
            
            for conn in connections:
                if isinstance(conn, dict):
                    source = conn.get('remote_address', '')
                    if source:
                        if source not in source_threats:
                            source_threats[source] = {'types': set(), 'count': 0}
                        source_threats[source]['types'].add('connection')
                        source_threats[source]['count'] += 1
            
            for port in port_scan:
                if isinstance(port, dict) and port.get('risk') in ['HIGH', 'CRITICAL']:
                    source = f"port_{port.get('port')}"
                    if source not in source_threats:
                        source_threats[source] = {'types': set(), 'count': 0}
                    source_threats[source]['types'].add('port_scan')
                    source_threats[source]['count'] += 1
            
            # Detect coordinated attacks
            for source, data in source_threats.items():
                if len(data['types']) > 1 and data['count'] >= 3:
                    correlations['coordinated_attack'] = True
                    break
            
            # Detect port scanning activity
            high_risk_ports = [p for p in port_scan if isinstance(p, dict) and p.get('risk') in ['HIGH', 'CRITICAL']]
            if len(high_risk_ports) >= 3:
                correlations['port_scanning_activity'] = True
            
            # Detect anomaly patterns
            critical_anomalies = [a for a in anomalies if isinstance(a, dict) and 'critical' in str(a).lower()]
            if len(critical_anomalies) >= 2:
                correlations['system_compromise_indicators'] = True
            
            return correlations
            
        except Exception as e:
            print(f"Error analyzing threat correlations: {e}")
            return {}
    
    def adjust_adaptive_thresholds(self, threat_correlation):
        """Adjust threat response thresholds based on current threat landscape"""
        try:
            if not hasattr(self, 'adaptive_thresholds'):
                return
            
            # Lower thresholds if coordinated attack detected
            if threat_correlation.get('coordinated_attack'):
                self.adaptive_thresholds['ip_frequency_limit'] = max(1, self.adaptive_thresholds['ip_frequency_limit'] - 1)
                self.adaptive_thresholds['port_frequency_limit'] = max(1, self.adaptive_thresholds['port_frequency_limit'] - 1)
            
            # Raise thresholds if too many false positives
            if hasattr(self, 'threat_learning') and len(self.threat_learning['false_positives']) > 10:
                self.adaptive_thresholds['ip_frequency_limit'] = min(5, self.adaptive_thresholds['ip_frequency_limit'] + 1)
            
        except Exception as e:
            print(f"Error adjusting adaptive thresholds: {e}")
    
    def prioritize_threats_intelligently(self, port_scan, connections, anomalies):
        """Intelligently prioritize threats based on risk and context"""
        try:
            threats = []
            
            # Score and prioritize threats
            for conn in connections:
                if isinstance(conn, dict):
                    threat_level = self.threat_analyzer.analyze_address_threat(conn.get('remote_addr', ''))
                    score = self.calculate_threat_score(conn, threat_level, 'connection')
                    threats.append({
                        'type': 'connection',
                        'data': conn,
                        'level': threat_level,
                        'score': score,
                        'description': f"Connection to {conn.get('remote_addr', 'unknown')}"
                    })
            
            for port in port_scan:
                if isinstance(port, dict):
                    threat_level = self.threat_analyzer.analyze_port_threat(port.get('port', 0), port.get('service', ''))
                    score = self.calculate_threat_score(port, threat_level, 'port')
                    threats.append({
                        'type': 'port',
                        'data': port,
                        'level': threat_level,
                        'score': score,
                        'description': f"Port {port.get('port', 'unknown')} ({port.get('service', 'unknown')})"
                    })
            
            for anomaly in anomalies:
                if isinstance(anomaly, dict):
                    threat_level = self.threat_analyzer.analyze_anomaly_threat(anomaly)
                    score = self.calculate_threat_score(anomaly, threat_level, 'anomaly')
                    threats.append({
                        'type': 'anomaly',
                        'data': anomaly,
                        'level': threat_level,
                        'score': score,
                        'description': f"Anomaly: {anomaly.get('type', 'unknown')}"
                    })
            
            # Sort by score (highest first)
            threats.sort(key=lambda x: x['score'], reverse=True)
            
            return threats
            
        except Exception as e:
            print(f"Error prioritizing threats: {e}")
            return []
    
    def calculate_threat_score(self, threat_data, threat_level, threat_type):
        """Calculate a threat score for prioritization"""
        try:
            base_score = {
                ThreatLevel.LOW: 1,
                ThreatLevel.MEDIUM: 3,
                ThreatLevel.HIGH: 7,
                ThreatLevel.CRITICAL: 15,
                ThreatLevel.EMERGENCY: 25
            }.get(threat_level, 1)
            
            # Add frequency multiplier
            threat_id = self.generate_threat_id(threat_type, threat_data)
            frequency = self.threat_counters.get(threat_id, 0)
            frequency_multiplier = min(3.0, 1.0 + (frequency * 0.5))
            
            # Add type-specific modifiers
            type_modifier = 1.0
            if threat_type == 'port' and isinstance(threat_data, dict):
                # Higher priority for suspicious ports
                suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389]
                if threat_data.get('port') in suspicious_ports:
                    type_modifier = 1.5
            
            elif threat_type == 'connection' and isinstance(threat_data, dict):
                # Higher priority for external connections
                remote_addr = threat_data.get('remote_addr', '')
                if remote_addr and not remote_addr.startswith(('127.', '192.168.', '10.')):
                    type_modifier = 1.3
            
            final_score = base_score * frequency_multiplier * type_modifier
            return final_score
            
        except Exception as e:
            return 1.0
    
    def context_aware_threat_response(self, threat):
        """Context-aware threat response based on threat characteristics"""
        try:
            threat_type = threat['type']
            threat_data = threat['data']
            threat_level = threat['level']
            threat_score = threat['score']
            
            # Different response strategies based on context
            if threat_score >= 20:  # Critical threats
                response = self.critical_threat_response(threat_type, threat_data, threat_level)
            elif threat_score >= 10:  # High priority threats
                response = self.high_priority_threat_response(threat_type, threat_data, threat_level)
            else:  # Standard threats
                response = self.smart_threat_response(threat_type, threat_data, threat_level.name)
            
            return response
            
        except Exception as e:
            return f"Error in context-aware response: {str(e)}"
    
    def critical_threat_response(self, threat_type, threat_data, threat_level):
        """Immediate response for critical threats"""
        try:
            if threat_type == 'connection':
                ip = threat_data.get('remote_addr', 'unknown')
                # Immediate blocking
                self.soft_block_ip(ip)
                return f"CRITICAL: Immediately blocked IP {ip}"
            
            elif threat_type == 'port':
                port = threat_data.get('port', 'unknown')
                # Immediate process termination
                terminated = self.terminate_malicious_process_on_port(port)
                return f"CRITICAL: Port {port} - {terminated}"
            
            elif threat_type == 'anomaly':
                anomaly_type = threat_data.get('type', 'unknown')
                # Immediate system protection
                return f"CRITICAL: Activated protection for {anomaly_type} anomaly"
            
        except Exception as e:
            return f"Critical response error: {str(e)}"
    
    def high_priority_threat_response(self, threat_type, threat_data, threat_level):
        """Enhanced response for high priority threats"""
        try:
            if threat_type == 'connection':
                ip = threat_data.get('remote_addr', 'unknown')
                # Enhanced monitoring and conditional blocking
                self.threat_intelligence['known_bad_ips'].add(ip)
                return f"HIGH: Enhanced monitoring for IP {ip}"
            
            elif threat_type == 'port':
                port = threat_data.get('port', 'unknown')
                processes = self.get_processes_using_port(port)
                return f"HIGH: Port {port} processes investigated: {processes}"
            
            elif threat_type == 'anomaly':
                anomaly_type = threat_data.get('type', 'unknown')
                root_cause = self.investigate_anomaly_root_cause(anomaly_type, threat_data)
                return f"HIGH: {anomaly_type} - {root_cause}"
            
        except Exception as e:
            return f"High priority response error: {str(e)}"
    
    def analyze_recurring_threats(self, port_scan, connections, anomalies):
        """Analyze recurring threats and take automated action"""
        try:
            current_time = datetime.now()
            
            # Analyze port threats with lower threshold for faster response
            for port in port_scan:
                if isinstance(port, dict):
                    port_key = f"port_{port.get('port', 'unknown')}"
                    risk_level = port.get('risk', 'LOW')
                    
                    # Track recurring high-risk ports
                    if risk_level in ['HIGH', 'CRITICAL']:
                        self.threat_counters[port_key] += 1
                        
                        # If port appears repeatedly, take automated action (reduced threshold)
                        if self.threat_counters[port_key] >= 2:  # Faster response
                            self.take_automated_action(port_key, port, 'recurring_high_risk_port')
            
            # Analyze connection threats with pattern recognition
            for conn in connections:
                if isinstance(conn, dict):
                    remote_addr = conn.get('remote_address', 'unknown')
                    if remote_addr and remote_addr != 'unknown':
                        conn_key = f"connection_{remote_addr}"
                        self.threat_counters[conn_key] += 1
                        
                        # If same connection appears repeatedly, investigate (reduced threshold)
                        if self.threat_counters[conn_key] >= 3:  # Faster response
                            self.take_automated_action(conn_key, conn, 'recurring_suspicious_connection')
            
            # Analyze anomaly patterns with intelligence
            for anomaly in anomalies:
                if isinstance(anomaly, dict):
                    anomaly_type = anomaly.get('type', 'unknown')
                    anomaly_key = f"anomaly_{anomaly_type}"
                    self.threat_counters[anomaly_key] += 1
                    
                    # If same anomaly type repeats, investigate deeper (reduced threshold)
                    if self.threat_counters[anomaly_key] >= 2:  # Faster response
                        self.take_automated_action(anomaly_key, anomaly, 'recurring_anomaly_pattern')
            
            # Run enhanced automated response system
            self.enhance_automated_response_system()
                        
        except Exception as e:
            print(f"Error in recurring threat analysis: {e}")
    
    def take_automated_action(self, threat_key, threat_data, threat_type):
        """Take intelligent automated action against recurring threats"""
        try:
            current_time = datetime.now()
            
            # Prevent spam actions - wait at least 30 seconds between automated actions
            if (self.last_automated_action and 
                (current_time - self.last_automated_action).seconds < 30):
                return
            
            action_taken = None
            
            if threat_type == 'recurring_high_risk_port':
                action_taken = self.handle_recurring_port_threat(threat_data)
            elif threat_type == 'recurring_suspicious_connection':
                action_taken = self.handle_recurring_connection_threat(threat_data)
            elif threat_type == 'recurring_anomaly_pattern':
                action_taken = self.handle_recurring_anomaly_threat(threat_data)
            
            if action_taken:
                self.last_automated_action = current_time
                self.automated_actions.append({
                    'timestamp': current_time,
                    'threat_key': threat_key,
                    'threat_type': threat_type,
                    'action': action_taken,
                    'threat_data': threat_data
                })
                
                # Reset counter after taking action
                self.threat_counters[threat_key] = 0
                
                # Log the automated action
                self.add_action_to_log(f"🤖 AUTOMATED ACTION: {action_taken}\n")
                
        except Exception as e:
            print(f"Error taking automated action: {e}")
    
    def handle_recurring_port_threat(self, port_data):
        """Handle recurring port threats with escalating responses"""
        try:
            port_num = port_data.get('port', 'unknown')
            service = port_data.get('service', 'unknown')
            
            # Try to get the process using this port and terminate it
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name', 'connections']):
                    try:
                        for conn in proc.connections():
                            if conn.laddr.port == port_num:
                                proc_name = proc.info['name']
                                
                                # Don't kill critical system processes
                                critical_processes = ['kernel_task', 'launchd', 'systemd', 'init']
                                if proc_name.lower() not in critical_processes:
                                    proc.terminate()
                                    return f"Terminated process '{proc_name}' (PID: {proc.pid}) using port {port_num}"
                                else:
                                    return f"Blocked port {port_num} (critical process '{proc_name}' detected)"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                # If no process found, try to block the port using firewall rules
                return self.block_port_with_firewall(port_num, service)
                
            except Exception as e:
                return f"Attempted to handle port {port_num} threat, but encountered: {str(e)}"
                
        except Exception as e:
            return f"Error handling port threat: {str(e)}"
    
    def handle_recurring_connection_threat(self, conn_data):
        """Handle recurring suspicious connections"""
        try:
            remote_addr = conn_data.get('remote_address', 'unknown')
            
            if remote_addr and remote_addr != 'unknown':
                # Add to blocked IPs list
                blocked_file = "blocked_ips.txt"
                try:
                    with open(blocked_file, 'a') as f:
                        f.write(f"{remote_addr}\n")
                except:
                    pass
                
                # Try to block using firewall (macOS pfctl or iptables on Linux)
                try:
                    if platform.system() == "Darwin":  # macOS
                        # Add to pfctl block list
                        subprocess.run(['sudo', 'pfctl', '-t', 'nimda_blocked', '-T', 'add', remote_addr], 
                                     capture_output=True, timeout=5)
                    elif platform.system() == "Linux":
                        # Add iptables rule
                        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', remote_addr, '-j', 'DROP'], 
                                     capture_output=True, timeout=5)
                except:
                    pass
                
                return f"Blocked suspicious IP address: {remote_addr}"
            
            return "Unable to identify IP address for blocking"
            
        except Exception as e:
            return f"Error blocking connection: {str(e)}"
    
    def handle_recurring_anomaly_threat(self, anomaly_data):
        """Handle recurring anomaly patterns with deep analysis"""
        try:
            anomaly_type = anomaly_data.get('type', 'unknown')
            description = anomaly_data.get('description', '')
            
            action_description = f"Deep analysis initiated for recurring anomaly: {anomaly_type}"
            
            # Perform specific actions based on anomaly type
            if 'cpu' in anomaly_type.lower():
                # CPU anomaly - look for resource-heavy processes
                try:
                    import psutil
                    high_cpu_procs = []
                    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                        try:
                            if proc.cpu_percent() > 80:
                                high_cpu_procs.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
                        except:
                            continue
                    
                    if high_cpu_procs:
                        action_description += f". High CPU processes detected: {', '.join(high_cpu_procs[:3])}"
                except:
                    pass
                    
            elif 'network' in anomaly_type.lower():
                # Network anomaly - analyze network connections
                try:
                    import psutil
                    external_conns = 0
                    for conn in psutil.net_connections():
                        if conn.raddr and not conn.raddr.ip.startswith(('127.', '192.168.', '10.')):
                            external_conns += 1
                    
                    action_description += f". External connections: {external_conns}"
                except:
                    pass
            
            elif 'memory' in anomaly_type.lower():
                # Memory anomaly - identify memory-heavy processes
                try:
                    import psutil
                    high_mem_procs = []
                    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
                        try:
                            if proc.memory_percent() > 10:
                                high_mem_procs.append(f"{proc.info['name']} ({proc.memory_percent():.1f}%)")
                        except:
                            continue
                    
                    if high_mem_procs:
                        action_description += f". High memory processes: {', '.join(high_mem_procs[:3])}"
                except:
                    pass
            
            return action_description
            
        except Exception as e:
            return f"Error analyzing anomaly: {str(e)}"
    
    def block_port_with_firewall(self, port_num, service):
        """Attempt to block a port using system firewall"""
        try:
            if platform.system() == "Darwin":  # macOS
                # Try to add pfctl rule
                rule = f"block in proto tcp from any to any port {port_num}"
                subprocess.run(['sudo', 'pfctl', '-a', 'nimda', '-f', '-'], 
                             input=rule.encode(), timeout=5)
                return f"Added firewall rule to block port {port_num} ({service})"
            elif platform.system() == "Linux":
                # Try to add iptables rule
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port_num), '-j', 'DROP'], 
                             timeout=5)
                return f"Added iptables rule to block port {port_num} ({service})"
            else:
                return f"Logged recurring threat on port {port_num} ({service}) - manual intervention recommended"
                
        except Exception as e:
            return f"Attempted to block port {port_num}, but firewall configuration failed: {str(e)}"
    
    def update_security_metrics(self, connections, port_scan, anomalies):
        """Update security metrics labels"""
        try:
            # Count active threats
            active_threats = len(connections) + len(port_scan) + len(anomalies)
            
            # Count high/critical threats
            high_threats = 0
            for conn in connections:
                if isinstance(conn, dict):
                    threat_level = self.threat_analyzer.analyze_address_threat(conn.get('remote_addr', ''))
                    if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        high_threats += 1
            
            for port in port_scan:
                if isinstance(port, dict):
                    threat_level = self.threat_analyzer.analyze_port_threat(port.get('port', 0), port.get('service', ''))
                    if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        high_threats += 1
            
            for anomaly in anomalies:
                if isinstance(anomaly, dict):
                    threat_level = self.threat_analyzer.analyze_anomaly_threat(anomaly)
                    if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        high_threats += 1
            
            # Update labels
            if hasattr(self, 'active_threats_label'):
                self.active_threats_label.config(text=f"Active Threats: {active_threats}")
            
            if hasattr(self, 'blocked_ips_label'):
                self.blocked_ips_label.config(text=f"High/Critical Threats: {high_threats}")
            
            if hasattr(self, 'open_ports_label'):
                self.open_ports_label.config(text=f"Open Ports: {len(port_scan)}")
            
            if hasattr(self, 'anomalies_label'):
                self.anomalies_label.config(text=f"Anomalies: {len(anomalies)}")
            
            if hasattr(self, 'last_scan_label'):
                self.last_scan_label.config(text=f"Last Scan: {datetime.now().strftime('%H:%M:%S')}")
            
            # Update automated actions metrics
            if hasattr(self, 'automated_actions_label'):
                self.automated_actions_label.config(text=f"Automated Actions: {len(self.automated_actions)}")
            
            if hasattr(self, 'threat_patterns_label'):
                recurring_count = sum(1 for count in self.threat_counters.values() if count >= 2)
                self.threat_patterns_label.config(text=f"Recurring Threats: {recurring_count}")
            
            if hasattr(self, 'last_automated_action_label'):
                if self.last_automated_action:
                    last_action_time = self.last_automated_action.strftime('%H:%M:%S')
                    self.last_automated_action_label.config(text=f"Last Auto Action: {last_action_time}")
                else:
                    self.last_automated_action_label.config(text="Last Auto Action: Never")
                
        except Exception as e:
            print(f"Error updating security metrics: {e}")
    
    def log_security_actions(self, connections, port_scan, anomalies):
        """Log security actions to the actions text widget"""
        try:
            if not hasattr(self, 'actions_text'):
                return
                
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            # Check for new threats and log actions
            for conn in connections:
                if isinstance(conn, dict):
                    threat_level = self.threat_analyzer.analyze_address_threat(conn.get('remote_addr', ''))
                    if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        action = f"[{timestamp}] 🚫 Blocked connection to {conn.get('remote_addr', 'Unknown')} (Level: {threat_level.value[3]})\n"
                        self.add_action_to_log(action)
            
            for port in port_scan:
                if isinstance(port, dict):
                    threat_level = self.threat_analyzer.analyze_port_threat(port.get('port', 0), port.get('service', ''))
                    if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        action = f"[{timestamp}] 🔒 Monitored port {port.get('port', 'Unknown')} ({port.get('service', 'Unknown')}) (Level: {threat_level.value[3]})\n"
                        self.add_action_to_log(action)
            
            for anomaly in anomalies:
                if isinstance(anomaly, dict):
                    threat_level = self.threat_analyzer.analyze_anomaly_threat(anomaly)
                    if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL, ThreatLevel.EMERGENCY]:
                        action = f"[{timestamp}] ⚠️ Detected anomaly: {anomaly.get('type', 'Unknown')} (Level: {threat_level.value[3]})\n"
                        self.add_action_to_log(action)
                        
        except Exception as e:
            print(f"Error logging security actions: {e}")
    
    def add_action_to_log(self, action):
        """Add action to the actions log"""
        try:
            if hasattr(self, 'actions_text'):
                self.actions_text.insert(tk.END, action)
                self.actions_text.see(tk.END)
                
                # Limit log size to last 100 entries
                lines = self.actions_text.get(1.0, tk.END).split('\n')
                if len(lines) > 100:
                    self.actions_text.delete(1.0, tk.END)
                    self.actions_text.insert(1.0, '\n'.join(lines[-100:]))
                    
        except Exception as e:
            print(f"Error adding action to log: {e}")
    
    def clear_actions_log(self):
        """Clear the actions log"""
        try:
            if hasattr(self, 'actions_text'):
                self.actions_text.delete(1.0, tk.END)
                self.log_message("🗑️ Actions log cleared")
        except Exception as e:
            print(f"Error clearing actions log: {e}")
    
    def export_dashboard_report(self):
        """Export dashboard report"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"nimda_dashboard_report_{timestamp}.txt"
            
            report = "=== NIMDA SECURITY DASHBOARD REPORT ===\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            
            # System metrics
            report += "SYSTEM METRICS:\n"
            if hasattr(self, 'cpu_label'):
                report += f"CPU Usage: {self.cpu_label.cget('text')}\n"
            if hasattr(self, 'mem_label'):
                report += f"Memory Usage: {self.mem_label.cget('text')}\n"
            
            # Security status
            report += "\nSECURITY STATUS:\n"
            if hasattr(self, 'threat_level_label'):
                report += f"Threat Level: {self.threat_level_label.cget('text')}\n"
            if hasattr(self, 'active_threats_label'):
                report += f"{self.active_threats_label.cget('text')}\n"
            if hasattr(self, 'blocked_ips_label'):
                report += f"{self.blocked_ips_label.cget('text')}\n"
            
            # Processes statistics
            report += "\nPROCESSES STATISTICS:\n"
            if hasattr(self, 'total_processes_label'):
                report += f"{self.total_processes_label.cget('text')}\n"
            if hasattr(self, 'dangerous_processes_label'):
                report += f"{self.dangerous_processes_label.cget('text')}\n"
            if hasattr(self, 'medium_processes_label'):
                report += f"{self.medium_processes_label.cget('text')}\n"
            if hasattr(self, 'safe_processes_label'):
                report += f"{self.safe_processes_label.cget('text')}\n"
            
            # Connections statistics
            report += "\nNETWORK CONNECTIONS:\n"
            if hasattr(self, 'total_connections_label'):
                report += f"{self.total_connections_label.cget('text')}\n"
            if hasattr(self, 'external_connections_label'):
                report += f"{self.external_connections_label.cget('text')}\n"
            if hasattr(self, 'internal_connections_label'):
                report += f"{self.internal_connections_label.cget('text')}\n"
            if hasattr(self, 'blocked_connections_label'):
                report += f"{self.blocked_connections_label.cget('text')}\n"
            
            # Actions log
            report += "\nSECURITY ACTIONS:\n"
            if hasattr(self, 'actions_text'):
                actions = self.actions_text.get(1.0, tk.END).strip()
                if actions:
                    report += actions
                else:
                    report += "No actions logged\n"
            
            # Save report
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            
            self.log_message(f"📋 Dashboard report exported: {filename}")
            messagebox.showinfo("Export", f"Dashboard report exported to:\n{filename}")
            
        except Exception as e:
            print(f"Error exporting dashboard report: {e}")
            messagebox.showerror("Error", f"Failed to export report: {e}")
    
    def update_real_time_monitoring(self):
        """Update real-time monitoring information"""
        try:
            # Network activity
            net_io = psutil.net_io_counters()
            
            # Get network connections safely
            try:
                connections_count = len(psutil.net_connections())
            except (psutil.AccessDenied, psutil.ZombieProcess):
                connections_count = 0
            
            if hasattr(self, 'network_activity_label'):
                self.network_activity_label.config(text=f"Connections: {connections_count} | Data In: {net_io.bytes_recv/1024:.1f} KB/s | Data Out: {net_io.bytes_sent/1024:.1f} KB/s")
            
            # Disk activity
            try:
                disk_usage = psutil.disk_usage('/')
                disk_io = psutil.disk_io_counters()
                
                if hasattr(self, 'disk_activity_label'):
                    free_gb = disk_usage.free / (1024**3)
                    self.disk_activity_label.config(text=f"Read: {disk_io.read_bytes/1024:.1f} KB/s | Write: {disk_io.write_bytes/1024:.1f} KB/s | Free Space: {free_gb:.1f} GB")
            except (PermissionError, OSError):
                if hasattr(self, 'disk_activity_label'):
                    self.disk_activity_label.config(text="Disk: Access denied (normal for some systems)")
            
            # System uptime
            uptime = time.time() - psutil.boot_time()
            days = int(uptime // 86400)
            hours = int((uptime % 86400) // 3600)
            minutes = int((uptime % 3600) // 60)
            
            if hasattr(self, 'uptime_label'):
                self.uptime_label.config(text=f"Uptime: {days} days, {hours} hours, {minutes} minutes")
                
        except Exception as e:
            print(f"Error updating real-time monitoring: {e}")
    
    def refresh_dashboard(self):
        """Refresh all dashboard data"""
        try:
            # Refresh network connections
            if hasattr(self, 'network_scanner'):
                connections = self.network_scanner.scan_network_connections()
                self.current_connections = connections
            
            # Refresh port scan
            if hasattr(self, 'network_scanner'):
                port_scan = self.network_scanner.scan_local_ports()
                self.current_port_scan = port_scan
            
            # Refresh anomalies
            if hasattr(self, 'anomaly_detector'):
                anomalies = self.anomaly_detector.detect_anomalies()
                self.current_anomalies = anomalies
            
            # Update all dashboard elements
            self.update_system_metrics()
            self.update_processes_statistics()
            self.update_connections_statistics()
            self.update_threats_dashboard()
            self.update_real_time_monitoring()
            
            self.log_message("🔄 Dashboard refreshed")
            
        except Exception as e:
            print(f"Error refreshing dashboard: {e}")
            self.log_message(f"❌ Dashboard refresh error: {e}")
    
    def show_performance_details(self):
        """Show detailed performance information"""
        try:
            # Get detailed system information
            cpu_info = {
                'Physical Cores': psutil.cpu_count(logical=False),
                'Logical Cores': psutil.cpu_count(logical=True),
                'Current Frequency': f"{psutil.cpu_freq().current/1000:.2f} GHz",
                'Max Frequency': f"{psutil.cpu_freq().max/1000:.2f} GHz",
                'CPU Usage': f"{psutil.cpu_percent()}%"
            }
            
            memory_info = {
                'Total Memory': f"{psutil.virtual_memory().total/(1024**3):.2f} GB",
                'Available Memory': f"{psutil.virtual_memory().available/(1024**3):.2f} GB",
                'Used Memory': f"{psutil.virtual_memory().used/(1024**3):.2f} GB",
                'Memory Usage': f"{psutil.virtual_memory().percent}%"
            }
            
            disk_info = {}
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info[partition.device] = {
                        'Mount Point': partition.mountpoint,
                        'File System': partition.fstype,
                        'Total': f"{usage.total/(1024**3):.2f} GB",
                        'Used': f"{usage.used/(1024**3):.2f} GB",
                        'Free': f"{usage.free/(1024**3):.2f} GB",
                        'Usage': f"{usage.percent}%"
                    }
                except PermissionError:
                    continue
            
            # Create detailed report
            report = "=== SYSTEM PERFORMANCE DETAILS ===\n\n"
            
            report += "CPU Information:\n"
            for key, value in cpu_info.items():
                report += f"  {key}: {value}\n"
            
            report += "\nMemory Information:\n"
            for key, value in memory_info.items():
                report += f"  {key}: {value}\n"
            
            report += "\nDisk Information:\n"
            for device, info in disk_info.items():
                report += f"  Device: {device}\n"
                for key, value in info.items():
                    report += f"    {key}: {value}\n"
                report += "\n"
            
            # Show in analysis window
            self.show_analysis_window("System Performance Details", report)
            
        except Exception as e:
            print(f"Error showing performance details: {e}")
            messagebox.showerror("Error", f"Failed to get performance details: {e}")
    
    def on_security_update(self, security_status):
        """Enhanced security status update with intelligent response"""
        try:
            print(f"[DEBUG] on_security_update: port_scan={security_status.get('port_scan')}")
            
            # Store current security data for dashboard
            self.current_connections = security_status.get('connections', [])
            self.current_port_scan = security_status.get('port_scan', [])
            self.current_anomalies = security_status.get('anomalies', [])
            
            # Apply smart threat response to each type
            connections_processed = []
            for conn in self.current_connections:
                if isinstance(conn, dict):
                    threat_level = self.threat_analyzer.analyze_address_threat(conn.get('remote_addr', ''))
                    if threat_level not in [ThreatLevel.LOW]:
                        response = self.smart_threat_response('ip_connection', conn, threat_level.name)
                        if response and "Skipped" not in response:
                            connections_processed.append(f"IP {conn.get('remote_addr', 'unknown')}: {response}")
            
            ports_processed = []
            for port in self.current_port_scan:
                if isinstance(port, dict):
                    threat_level = self.threat_analyzer.analyze_port_threat(port.get('port', 0), port.get('service', ''))
                    if threat_level not in [ThreatLevel.LOW]:
                        response = self.smart_threat_response('port_scan', port, threat_level.name)
                        if response and "Skipped" not in response:
                            ports_processed.append(f"Port {port.get('port', 'unknown')}: {response}")
            
            anomalies_processed = []
            for anomaly in self.current_anomalies:
                if isinstance(anomaly, dict):
                    threat_level = self.threat_analyzer.analyze_anomaly_threat(anomaly)
                    if threat_level not in [ThreatLevel.LOW]:
                        response = self.smart_threat_response('anomaly', anomaly, threat_level.name)
                        if response and "Skipped" not in response:
                            anomalies_processed.append(f"Anomaly {anomaly.get('type', 'unknown')}: {response}")
            
            # Log processed threats summary
            if connections_processed or ports_processed or anomalies_processed:
                summary = []
                if connections_processed:
                    summary.extend(connections_processed[:2])  # Limit to 2 per type
                if ports_processed:
                    summary.extend(ports_processed[:2])
                if anomalies_processed:
                    summary.extend(anomalies_processed[:2])
                
                if summary:
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    self.add_action_to_log(f"[{timestamp}] 🧠 INTELLIGENT RESPONSE:\n")
                    for item in summary[:3]:  # Limit total to 3 items
                        self.add_action_to_log(f"  • {item}\n")
                    self.add_action_to_log("\n")
            
            # Update security status
            self.security_status.update(security_status)
            
            # Update UI elements
            self.root.after(0, lambda: self.update_ui())
            
            # Update specific UI components
            if 'connections' in security_status:
                self.root.after(0, lambda: self.update_connections_tree(security_status['connections']))
            
            if 'port_scan' in security_status:
                self.root.after(0, lambda: self.update_ports_tree(security_status['port_scan']))
            
            if 'anomalies' in security_status:
                self.root.after(0, lambda: self.update_anomalies_tree(security_status['anomalies']))
            
            # Update threat level
            self.root.after(0, lambda: self.update_threat_level(security_status))
            
            # Check for threat level changes and trigger sound alerts
            if 'threat_level' in security_status:
                threat_level = security_status['threat_level']
                if hasattr(self, 'last_threat_level') and self.last_threat_level != threat_level:
                    # Threat level changed - trigger sound alert
                    self.trigger_sound_alert(threat_level, "Threat Level Change")
                    
                    # Trigger pattern alerts for specific threat levels
                    if threat_level == ThreatLevel.CRITICAL:
                        self.trigger_pattern_alert('data_breach', "Critical Threat Detected")
                    elif threat_level == ThreatLevel.EMERGENCY:
                        self.trigger_pattern_alert('system_compromise', "Emergency Situation")
                
                self.last_threat_level = threat_level
            
            # Check for specific security events
            if 'connections' in security_status:
                connections = security_status['connections']
                for conn in connections:
                    if isinstance(conn, dict) and conn.get('threat_level') in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                        target = f"{conn.get('remote_address', 'Unknown')}:{conn.get('remote_port', 'Unknown')}"
                        self.trigger_sound_alert(conn['threat_level'], f"Network Threat: {target}")
            
            if 'anomalies' in security_status:
                anomalies = security_status['anomalies']
                for anomaly in anomalies:
                    if isinstance(anomaly, dict) and anomaly.get('severity') in ['HIGH', 'CRITICAL']:
                        anomaly_type = anomaly.get('type', 'Unknown')
                        self.trigger_pattern_alert('suspicious_process', f"Anomaly: {anomaly_type}")
            
        except Exception as e:
            print(f"Error in security update: {e}")
            self.log_message(f"❌ Security update error: {e}")
    
    def update_connections_tree(self, connections):
        """Update connections treeview with threat level analysis"""
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        for conn in connections:
            # Analyze threat level for this connection
            threat_level = self.threat_analyzer.analyze_address_threat(conn['remote_addr'])
            
            # Execute security actions based on threat level
            details = {
                'local_addr': conn['local_addr'],
                'remote_addr': conn['remote_addr'],
                'status': conn['status'],
                'pid': conn['pid'],
                'process': conn['process']
            }
            self.threat_analyzer.execute_actions(threat_level, conn['remote_addr'], details, self)
            
            # Get threat level info
            threat_info = threat_level.value[0]  # Get the enum value
            threat_icon = threat_level.value[1]  # Get the emoji
            threat_color = threat_level.value[2]  # Get the color
            threat_name = threat_level.value[3]  # Get the Ukrainian name
            
            self.connections_tree.insert('', 'end', values=(
                conn['local_addr'],
                conn['remote_addr'],
                conn['status'],
                conn['pid'],
                conn['process'],
                f"{threat_icon} {threat_name}"
            ), tags=(threat_color,))
        
        # Configure tag colors for threat levels
        for level in ThreatLevel:
            self.connections_tree.tag_configure(level.value[2], background=level.value[2], foreground='white')
    
    def update_ports_tree(self, port_scan):
        print(f"[DEBUG] update_ports_tree called with {len(port_scan)} ports: {port_scan}")
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
        
        for port in port_scan:
            # Analyze threat level for this port
            threat_level = self.threat_analyzer.analyze_port_threat(port['port'], port['service'])
            
            # Execute security actions based on threat level
            details = {
                'port': port['port'],
                'service': port['service'],
                'status': port['status'],
                'risk': port['risk'],
                'timestamp': port['timestamp']
            }
            self.threat_analyzer.execute_actions(threat_level, f"Port {port['port']}", details, self)
            
            # Get threat level info
            threat_info = threat_level.value[0]  # Get the enum value
            threat_icon = threat_level.value[1]  # Get the emoji
            threat_color = threat_level.value[2]  # Get the color
            threat_name = threat_level.value[3]  # Get the Ukrainian name
            
            self.ports_tree.insert('', 'end', values=(
                port['port'],
                port['service'],
                port['status'],
                f"{threat_icon} {threat_name}",
                port['timestamp'][:19]  # Truncate timestamp
            ), tags=(threat_color,))
        
        # Configure tag colors for threat levels
        for level in ThreatLevel:
            self.ports_tree.tag_configure(level.value[2], background=level.value[2], foreground='white')
    
    def update_anomalies_tree(self, anomalies):
        """Update anomalies tree with threat level analysis"""
        # Clear existing items
        for item in self.anomalies_tree.get_children():
            self.anomalies_tree.delete(item)
        
        # Add new anomalies with threat level analysis
        for anomaly in anomalies:
            # Analyze threat level for this anomaly
            threat_level = self.threat_analyzer.analyze_anomaly_threat(anomaly)
            
            # Execute security actions based on threat level
            self.threat_analyzer.execute_actions(threat_level, f"Anomaly: {anomaly.get('type', 'UNKNOWN')}", anomaly, self)
            
            # Get threat level info
            threat_info = threat_level.value[0]  # Get the enum value
            threat_icon = threat_level.value[1]  # Get the emoji
            threat_color = threat_level.value[2]  # Get the color
            threat_name = threat_level.value[3]  # Get the Ukrainian name
            
            self.anomalies_tree.insert('', 'end', values=(
                anomaly.get('type', 'UNKNOWN'),
                f"{threat_icon} {threat_name}",
                anomaly.get('description', 'No description'),
                anomaly.get('timestamp', 'Unknown')
            ), tags=(threat_color,))
        
        # Configure tag colors for threat levels
        for level in ThreatLevel:
            self.anomalies_tree.tag_configure(level.value[2], background=level.value[2], foreground='white')
    
    def update_threat_level(self, security_status):
        """Update threat level based on security status using new threat analysis system"""
        max_threat_level = ThreatLevel.LOW
        
        # Check for high-risk ports
        port_scan = security_status.get('port_scan', [])
        for port in port_scan:
            threat_level = self.threat_analyzer.analyze_port_threat(port['port'], port['service'])
            if threat_level.value[0] > max_threat_level.value[0]:
                max_threat_level = threat_level
        
        # Check for anomalies
        anomalies = security_status.get('anomalies', [])
        for anomaly in anomalies:
            threat_level = self.threat_analyzer.analyze_anomaly_threat(anomaly)
            if threat_level.value[0] > max_threat_level.value[0]:
                max_threat_level = threat_level
        
        # Check for suspicious connections
        connections = security_status.get('connections', [])
        for conn in connections:
            threat_level = self.threat_analyzer.analyze_address_threat(conn['remote_addr'])
            if threat_level.value[0] > max_threat_level.value[0]:
                max_threat_level = threat_level
        
        # Update threat level
        self.threat_level = max_threat_level
        
        # Update UI with threat level info
        threat_icon = max_threat_level.value[1]
        threat_color = max_threat_level.value[2]
        threat_name = max_threat_level.value[3]
        
        # Update dashboard threat level display
        if hasattr(self, 'threat_level_label'):
            self.threat_level_label.config(
                text=f"{threat_icon} {threat_name}",
                foreground=threat_color,
                font=('Arial', 12, 'bold')
            )
        
        # Update security status
        total_items = len(port_scan) + len(anomalies) + len(connections)
        if hasattr(self, 'security_status_label'):
            self.security_status_label.config(
                text=f"Status: Active | Items: {total_items} | Level: {max_threat_level.value[0]}",
                font=('Arial', 10)
            )
        
        # Execute actions for the current threat level
        if max_threat_level != ThreatLevel.LOW:
            details = {
                'port_scan': port_scan,
                'anomalies': anomalies,
                'connections': connections,
                'total_items': total_items
            }
            self.threat_analyzer.execute_actions(max_threat_level, "System-wide threat", details)
    
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Check if logs_text exists before using it
        if hasattr(self, 'logs_text') and self.logs_text:
            self.logs_text.insert(tk.END, log_entry)
            self.logs_text.see(tk.END)
        
        # Also print to console for debugging
        print(log_entry.strip())
    
    # Action methods
    def full_scan(self):
        """Perform full system scan"""
        self.log_message("Starting full system scan...")
        # This would trigger a comprehensive scan
        messagebox.showinfo("Scan", "Full system scan completed")
    
    def emergency_lockdown(self):
        """Emergency lockdown"""
        if messagebox.askyesno("Emergency", "Are you sure you want to activate emergency lockdown?"):
            self.log_message("EMERGENCY LOCKDOWN ACTIVATED")
            # This would implement actual lockdown measures
            messagebox.showwarning("Lockdown", "Emergency lockdown activated")
    
    def show_system_info(self):
        """Show detailed system information"""
        try:
            info = f"""
System Information:
CPU: {psutil.cpu_percent()}%
Memory: {psutil.virtual_memory().percent}%
Disk: {psutil.disk_usage('/').percent}%
Processes: {len(psutil.pids())}
Uptime: {time.time() - psutil.boot_time():.0f} seconds
            """
            messagebox.showinfo("System Info", info)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get system info: {str(e)}")
    
    def test_llm(self):
        """Test LLM connection"""
        if not SECURITY_MODULES_AVAILABLE:
            messagebox.showwarning("Warning", "LLM agent not available")
            return
        
        try:
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(1.0, "Testing LLM connection...")
            
            if self.llm_agent.check_ollama_connection():
                response = self.llm_agent.query_ollama("Hello, are you working?", "")
                self.response_text.delete(1.0, tk.END)
                self.response_text.insert(1.0, f"LLM Test Response:\n\n{response}")
                self.log_message("LLM test successful")
            else:
                self.response_text.delete(1.0, tk.END)
                self.response_text.insert(1.0, "LLM connection failed")
                self.log_message("LLM test failed")
        except Exception as e:
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(1.0, f"LLM test error: {str(e)}")
            self.log_message(f"LLM test error: {str(e)}")
    
    def refresh_network(self):
        """Refresh network connections"""
        try:
            network_scanner = NetworkScanner()
            connections = network_scanner.scan_network_connections()
            self.update_connections_tree(connections)
            
            if hasattr(self, 'status_label'):
                self.status_label.config(text=f"Network refreshed: {len(connections)} connections | {datetime.now().strftime('%H:%M:%S')}")
            
            self.log_message(f"Network refreshed: {len(connections)} connections")
        except Exception as e:
            self.log_message(f"ERROR: Network refresh failed: {str(e)}")
    
    def analyze_network(self):
        """Analyze network traffic"""
        self.log_message("Analyzing network traffic...")
        messagebox.showinfo("Analysis", "Network analysis completed")
    
    def block_ip(self):
        """Block selected IP"""
        selection = self.connections_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a connection to block")
            return
        
        item = self.connections_tree.item(selection[0])
        remote_addr = item['values'][1]
        if messagebox.askyesno("Block IP", f"Block IP address {remote_addr}?"):
            self.log_message(f"Blocking IP: {remote_addr}")
            messagebox.showinfo("Blocked", f"IP {remote_addr} has been blocked")
    
    def scan_ports(self):
        """Scan ports"""
        self.log_message("Starting port scan...")
        messagebox.showinfo("Scan", "Port scan completed")
    
    def close_port(self):
        """Close selected port"""
        selection = self.ports_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a port to close")
            return
        
        item = self.ports_tree.item(selection[0])
        port = item['values'][0]
        if messagebox.askyesno("Close Port", f"Close port {port}?"):
            self.log_message(f"Closing port: {port}")
            messagebox.showinfo("Closed", f"Port {port} has been closed")
    
    def port_stats(self):
        """Show port statistics"""
        messagebox.showinfo("Stats", "Port statistics displayed")
    
    def deep_analyze_port(self):
        """Deep analyze selected port"""
        selection = self.ports_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a port to analyze")
            return
        
        item = self.ports_tree.item(selection[0])
        port = item['values'][0]
        
        try:
            analysis = self.deep_analyzer.analyze_port(port)
            
            # Display analysis in a new window
            self.show_analysis_window(f"Deep Port Analysis - Port {port}", analysis)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
    
    def analyze_all_ports(self):
        """Analyze all found ports"""
        try:
            # Get all ports from the tree
            ports = []
            for item in self.ports_tree.get_children():
                port_data = self.ports_tree.item(item)['values']
                ports.append(port_data[0])  # Port number
            
            if not ports:
                messagebox.showinfo("Info", "No ports found to analyze")
                return
            
            analysis = self.deep_analyzer.analyze_all_ports(ports)
            
            # Display analysis in a new window
            self.show_analysis_window("All Ports Analysis", analysis)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
    
    def deep_analyze_address(self):
        """Deep analyze selected address"""
        selection = self.connections_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select an address to analyze")
            return
        
        item = self.connections_tree.item(selection[0])
        address = item['values'][1]  # Remote address
        
        try:
            analysis = self.deep_analyzer.analyze_address(address)
            
            # Display analysis in a new window
            self.show_analysis_window(f"Deep Address Analysis - {address}", analysis)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
    
    def analyze_all_addresses(self):
        """Analyze all found addresses"""
        try:
            # Get all addresses from the tree
            addresses = []
            for item in self.connections_tree.get_children():
                addr_data = self.connections_tree.item(item)['values']
                addresses.append(addr_data[1])  # Remote address
            
            if not addresses:
                messagebox.showinfo("Info", "No addresses found to analyze")
                return
            
            analysis = self.deep_analyzer.analyze_all_addresses(addresses)
            
            # Display analysis in a new window
            self.show_analysis_window("All Addresses Analysis", analysis)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
    
    def show_analysis_window(self, title, analysis):
        """Show analysis results in a new window"""
        # Create new window
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title(title)
        analysis_window.geometry("800x600")
        
        # Create text widget
        text_widget = scrolledtext.ScrolledText(analysis_window, wrap='word', font=('Courier', 10))
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Format and display analysis
        if isinstance(analysis, dict):
            formatted_text = "=== ANALYSIS RESULTS ===\n\n"
            for key, value in analysis.items():
                if key == 'timestamp':
                    continue
                if isinstance(value, list):
                    formatted_text += f"{key.upper()}:\n"
                    for item in value:
                        formatted_text += f"  - {item}\n"
                else:
                    formatted_text += f"{key.upper()}: {value}\n"
                formatted_text += "\n"
        else:
            formatted_text = str(analysis)
        
        text_widget.insert('1.0', formatted_text)
        text_widget.config(state='disabled')
        
        # Add close button
        close_btn = ttk.Button(analysis_window, text="Close", command=analysis_window.destroy)
        close_btn.pack(pady=10)
    
    def detect_anomalies(self):
        """Detect system anomalies"""
        try:
            anomaly_detector = AnomalyDetector()
            anomalies = anomaly_detector.detect_anomalies()
            self.update_anomalies_tree(anomalies)
            
            if hasattr(self, 'status_label'):
                self.status_label.config(text=f"Anomaly detection completed: {len(anomalies)} anomalies found | {datetime.now().strftime('%H:%M:%S')}")
            
            self.log_message(f"Anomaly detection completed: {len(anomalies)} anomalies found")
        except Exception as e:
            self.log_message(f"ERROR: Anomaly detection failed: {str(e)}")
    
    def clear_anomalies(self):
        """Clear anomalies"""
        for item in self.anomalies_tree.get_children():
            self.anomalies_tree.delete(item)
        self.log_message("Anomalies cleared")
    
    def show_baseline(self):
        """Show baseline information"""
        messagebox.showinfo("Baseline", "Baseline information displayed")
    
    def analyze_selected_anomaly(self):
        """Analyze selected anomaly in detail"""
        selection = self.anomalies_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select an anomaly to analyze")
            return
        
        item = self.anomalies_tree.item(selection[0])
        values = item['values']
        
        # Create anomaly object from tree values
        anomaly = {
            'type': values[0],
            'severity': values[1],
            'description': values[2],
            'timestamp': values[3]
        }
        
        try:
            analysis = self.anomaly_analyzer.analyze_anomaly(anomaly)
            
            # Display analysis in a new window
            self.show_analysis_window(f"Anomaly Analysis - {anomaly['type']}", analysis)
            
        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
    
    def switch_language(self):
        """Switch application language"""
        new_lang = self.translation_manager.switch_language()
        
        # Update language indicator
        if new_lang == 'uk':
            self.language_label.config(text="Language: Українська")
        else:
            self.language_label.config(text="Language: English")
        
        # Update status
        lang_text = "Українська" if new_lang == 'uk' else "English"
        if hasattr(self, 'status_label'):
            self.status_label.config(text=f"Language switched to {lang_text} | {datetime.now().strftime('%H:%M:%S')}")
        
        # Show confirmation
        messagebox.showinfo("Language", f"Application language switched to {lang_text}")
    
    def analyze_threats(self):
        """Analyze current security threats"""
        try:
            current_lang = self.translation_manager.get_current_language()
            
            if current_lang == 'uk':
                query = "Відповідай українською мовою. Проаналізуй поточні загрози безпеки системи та надай рекомендації."
            else:
                query = "Answer in English. Analyze current system security threats and provide recommendations."
            
            response = self.llm_agent.analyze_security_query(query)
            
            self.response_text.delete('1.0', tk.END)
            self.response_text.insert('1.0', response)
            
            self.log_message("Threat analysis completed")
            
        except Exception as e:
            error_msg = f"Помилка аналізу загроз: {str(e)}" if current_lang == 'uk' else f"Threat analysis error: {str(e)}"
            messagebox.showerror("Error", error_msg)
    
    def get_recommendations(self):
        """Get AI security recommendations"""
        try:
            current_lang = self.translation_manager.get_current_language()
            
            if current_lang == 'uk':
                query = "Відповідай українською мовою. Надай детальні рекомендації щодо покращення безпеки системи."
            else:
                query = "Answer in English. Provide detailed recommendations for improving system security."
            
            response = self.llm_agent.analyze_security_query(query)
            
            self.response_text.delete('1.0', tk.END)
            self.response_text.insert('1.0', response)
            
            self.log_message("Security recommendations generated")
            
        except Exception as e:
            error_msg = f"Помилка генерації рекомендацій: {str(e)}" if current_lang == 'uk' else f"Recommendations error: {str(e)}"
            messagebox.showerror("Error", error_msg)
    
    def security_report(self):
        """Generate comprehensive security report"""
        try:
            current_lang = self.translation_manager.get_current_language()
            
            if current_lang == 'uk':
                query = "Відповідай українською мовою. Створи комплексний звіт про безпеку системи з детальним аналізом."
            else:
                query = "Answer in English. Generate a comprehensive system security report with detailed analysis."
            
            response = self.llm_agent.analyze_security_query(query)
            
            self.response_text.delete('1.0', tk.END)
            self.response_text.insert('1.0', response)
            
            self.log_message("Security report generated")
            
        except Exception as e:
            error_msg = f"Помилка генерації звіту: {str(e)}" if current_lang == 'uk' else f"Report generation error: {str(e)}"
            messagebox.showerror("Error", error_msg)
    
    def emergency_analysis(self):
        """Perform emergency security analysis"""
        try:
            current_lang = self.translation_manager.get_current_language()
            
            if current_lang == 'uk':
                query = "Відповідай українською мовою. Виконай екстрений аналіз безпеки системи та надай негайні дії."
            else:
                query = "Answer in English. Perform emergency system security analysis and provide immediate actions."
            
            response = self.llm_agent.analyze_security_query(query)
            
            self.response_text.delete('1.0', tk.END)
            self.response_text.insert('1.0', response)
            
            self.log_message("Emergency analysis completed")
            
        except Exception as e:
            error_msg = f"Помилка екстренного аналізу: {str(e)}" if current_lang == 'uk' else f"Emergency analysis error: {str(e)}"
            messagebox.showerror("Error", error_msg)
    
    def send_query(self):
        """Send query to AI"""
        query = self.query_entry.get().strip()
        if not query:
            messagebox.showwarning("Warning", "Please enter a query")
            return
        
        try:
            # Get response from AI
            response = self.llm_agent.analyze_security_query(query)
            
            # Display response
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(1.0, response)
            
            # Update status
            lang_text = "Українська" if self.translation_manager.get_current_language() == 'uk' else "English"
            if hasattr(self, 'status_label'):
                self.status_label.config(text=f"AI analysis completed in {lang_text} | {datetime.now().strftime('%H:%M:%S')}")
            
            self.log_message(f"AI query processed: {query[:50]}...")
        except Exception as e:
            self.log_message(f"ERROR: AI query failed: {str(e)}")
            messagebox.showerror("Error", f"Failed to process query: {str(e)}")
    
    def refresh_logs(self):
        """Refresh security logs"""
        self.log_message("Logs refreshed")
    
    def clear_logs(self):
        """Clear security logs"""
        self.logs_text.delete(1.0, tk.END)
        self.log_message("Logs cleared")
    
    def save_logs(self):
        """Save logs to file"""
        try:
            filename = f"nimda_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(self.logs_text.get(1.0, tk.END))
            messagebox.showinfo("Saved", f"Logs saved to {filename}")
            self.log_message(f"Logs saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save logs: {str(e)}")
    
    def export_logs(self):
        """Export logs in different formats"""
        messagebox.showinfo("Export", "Log export functionality")
    
    def export_report(self):
        """Export security report"""
        messagebox.showinfo("Export", "Report export functionality")
    
    def threat_assessment(self):
        """Perform threat assessment"""
        messagebox.showinfo("Assessment", "Threat assessment completed")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """NIMDA Security System v2.0

Comprehensive security monitoring for Mac M1 Max
with advanced network analysis, port scanning,
anomaly detection, and AI-powered threat analysis.

Features:
• Real-time network monitoring
• Port scanning and analysis
• Anomaly detection
• LLM-powered security analysis
• Comprehensive logging
• Emergency response capabilities

Author: NIMDA Team
License: MIT"""
        
        messagebox.showinfo("About NIMDA", about_text)
    
    def on_closing(self):
        """Handle application closing"""
        if self.monitor_thread:
            self.monitor_thread.stop()
        
        if self.security_monitor:
            self.security_monitor.stop_monitoring()
        
        self.log_message("NIMDA Security System shutting down")
        self.root.destroy()
    
    def switch_ai_language(self):
        """Switch AI language and update indicator"""
        new_lang = self.translation_manager.switch_language()
        
        # Update AI language indicator
        if new_lang == 'uk':
            self.ai_language_label.config(text="AI Language: Українська")
            self.ai_language_btn.config(text="🌐 Переключити мову ШІ")
        else:
            self.ai_language_label.config(text="AI Language: English")
            self.ai_language_btn.config(text="🌐 Switch AI Language")
        
        # Update status
        lang_text = "Українська" if new_lang == 'uk' else "English"
        if hasattr(self, 'status_label'):
            self.status_label.config(text=f"AI language switched to {lang_text} | {datetime.now().strftime('%H:%M:%S')}")
        
        # Show confirmation
        messagebox.showinfo("AI Language", f"AI will now respond in {lang_text}")
    
    def update_ai_language_indicator(self):
        """Update AI language indicator based on current language"""
        current_lang = self.translation_manager.get_current_language()
        
        if current_lang == 'uk':
            self.ai_language_label.config(text="AI Language: Українська")
            self.ai_language_btn.config(text="🌐 Переключити мову ШІ")
        else:
            self.ai_language_label.config(text="AI Language: English")
            self.ai_language_btn.config(text="🌐 Switch AI Language")
    
    def create_emergency_tab(self):
        """Create emergency actions tab"""
        emergency_frame = ttk.Frame(self.notebook)
        self.notebook.add(emergency_frame, text="🚨 Emergency")
        
        # Emergency actions
        actions_frame = ttk.LabelFrame(emergency_frame, text="Emergency Actions", padding=10)
        actions_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(actions_frame, text="🔒 Lockdown System", command=self.emergency_lockdown).pack(fill='x', pady=2)
        ttk.Button(actions_frame, text="🌐 Isolate Network", command=self.isolate_network).pack(fill='x', pady=2)
        ttk.Button(actions_frame, text="⚡ Terminate Processes", command=self.terminate_processes).pack(fill='x', pady=2)
        ttk.Button(actions_frame, text="💾 Backup Data", command=self.backup_data).pack(fill='x', pady=2)
        ttk.Button(actions_frame, text="🔄 Shutdown System", command=self.shutdown_system).pack(fill='x', pady=2)
    
    def create_ai_providers_tab(self):
        """Create AI providers management tab"""
        providers_frame = ttk.Frame(self.notebook)
        self.notebook.add(providers_frame, text="🤖 AI Providers")
        
        # Provider status
        status_frame = ttk.LabelFrame(providers_frame, text="Provider Status", padding=10)
        status_frame.pack(fill='x', padx=10, pady=5)
        
        # Provider status tree
        self.providers_tree = ttk.Treeview(status_frame, columns=('Status', 'Models', 'Last Check'), show='tree headings', height=6)
        self.providers_tree.heading('#0', text='Provider')
        self.providers_tree.heading('Status', text='Status')
        self.providers_tree.heading('Models', text='Available Models')
        self.providers_tree.heading('Last Check', text='Last Check')
        self.providers_tree.pack(fill='x', pady=5)
        
        # Provider controls
        controls_frame = ttk.Frame(providers_frame)
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(controls_frame, text="🔄 Refresh Status", command=self.refresh_provider_status).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="⚙️ Set Active", command=self.set_active_provider).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="🔧 Configure", command=self.configure_provider).pack(side='left', padx=5)
        
        # Initial status update
        self.refresh_provider_status()
    
    def create_task_scheduler_tab(self):
        """Create task scheduler tab"""
        scheduler_frame = ttk.Frame(self.notebook)
        self.notebook.add(scheduler_frame, text="📅 Task Scheduler")
        
        # Task list
        tasks_frame = ttk.LabelFrame(scheduler_frame, text="Scheduled Tasks", padding=10)
        tasks_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Task tree
        self.tasks_tree = ttk.Treeview(tasks_frame, columns=('Type', 'Schedule', 'Status', 'Next Run', 'Last Run'), show='tree headings', height=8)
        self.tasks_tree.heading('#0', text='Task Name')
        self.tasks_tree.heading('Type', text='Type')
        self.tasks_tree.heading('Schedule', text='Schedule')
        self.tasks_tree.heading('Status', text='Status')
        self.tasks_tree.heading('Next Run', text='Next Run')
        self.tasks_tree.heading('Last Run', text='Last Run')
        self.tasks_tree.pack(fill='both', expand=True, pady=5)
        
        # Task controls
        controls_frame = ttk.Frame(scheduler_frame)
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(controls_frame, text="➕ Add Task", command=self.add_scheduled_task).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="▶️ Run Now", command=self.run_task_now).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="⏸️ Enable/Disable", command=self.toggle_task).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="🗑️ Delete Task", command=self.delete_scheduled_task).pack(side='left', padx=5)
        ttk.Button(controls_frame, text="🔄 Refresh", command=self.refresh_tasks).pack(side='left', padx=5)
        
        # Initialize scheduler
        self.init_task_scheduler()
        self.refresh_tasks()
    
    def init_task_scheduler(self):
        """Initialize task scheduler with callback functions"""
        if self.task_scheduler is None:
            self.log_message("WARNING: Task scheduler not initialized")
            return
            
        # Register callback functions
        self.task_scheduler.register_function("full_security_scan", self.full_scan)
        self.task_scheduler.register_function("analyze_network", self.analyze_network)
        self.task_scheduler.register_function("ai_analysis", self.scheduled_ai_analysis)
        
        # Start scheduler
        self.task_scheduler.start()
    
    def refresh_provider_status(self):
        """Refresh AI provider status"""
        # Clear existing items
        for item in self.providers_tree.get_children():
            self.providers_tree.delete(item)
        
        # Check if ai_provider_manager is initialized
        if self.ai_provider_manager is None:
            # Add placeholder message
            self.providers_tree.insert('', 'end', text="AI Providers", 
                                     values=("⚠️ Not initialized", "Please restart", "N/A"))
            return
        
        # Get provider status
        try:
            status = self.ai_provider_manager.get_provider_status()
            
            # Add providers to tree
            for name, info in status.items():
                status_text = "✅ Available" if info["available"] else "❌ Unavailable"
                models_text = ", ".join(info["models"][:3]) + ("..." if len(info["models"]) > 3 else "")
                last_check = info["last_check"].strftime("%H:%M:%S") if info["last_check"] else "Never"
                
                self.providers_tree.insert('', 'end', text=name, values=(status_text, models_text, last_check))
        except Exception as e:
            # Add error message
            self.providers_tree.insert('', 'end', text="Error", 
                                     values=(f"❌ Error: {str(e)}", "Check configuration", "N/A"))
    
    def set_active_provider(self):
        """Set active AI provider"""
        if self.ai_provider_manager is None:
            messagebox.showerror("Error", "AI provider manager not initialized")
            return
            
        selection = self.providers_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a provider")
            return
        
        provider_name = self.providers_tree.item(selection[0])['text']
        if self.ai_provider_manager.set_active_provider(provider_name):
            messagebox.showinfo("Success", f"Active provider set to {provider_name}")
            if hasattr(self, 'status_label'):
                self.status_label.config(text=f"Active AI provider: {provider_name} | {datetime.now().strftime('%H:%M:%S')}")
        else:
            messagebox.showerror("Error", f"Failed to set {provider_name} as active provider")
    
    def configure_provider(self):
        """Configure AI provider settings"""
        try:
            # Create configuration dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("AI Provider Configuration")
            dialog.geometry("600x500")
            
            # Main frame
            main_frame = ttk.Frame(dialog)
            main_frame.pack(fill='both', expand=True, padx=20, pady=20)
            
            ttk.Label(main_frame, text="AI Provider Configuration", 
                     font=('Arial', 16, 'bold')).pack(pady=10)
            
            # Create notebook for different providers
            notebook = ttk.Notebook(main_frame)
            notebook.pack(fill='both', expand=True, pady=10)
            
            # Provider configurations
            provider_configs = {}
            
            def create_context_menu(entry_widget):
                """Create context menu for entry widget"""
                context_menu = tk.Menu(entry_widget, tearoff=0)
                
                def paste():
                    try:
                        entry_widget.event_generate("<<Paste>>")
                    except:
                        pass
                
                def copy():
                    try:
                        entry_widget.event_generate("<<Copy>>")
                    except:
                        pass
                
                def cut():
                    try:
                        entry_widget.event_generate("<<Cut>>")
                    except:
                        pass
                
                def select_all():
                    try:
                        entry_widget.select_range(0, tk.END)
                    except:
                        pass
                
                context_menu.add_command(label="Вставити", command=paste)
                context_menu.add_command(label="Копіювати", command=copy)
                context_menu.add_command(label="Вирізати", command=cut)
                context_menu.add_separator()
                context_menu.add_command(label="Вибрати все", command=select_all)
                
                def show_context_menu(event):
                    context_menu.post(event.x_root, event.y_root)
                
                entry_widget.bind("<Button-3>", show_context_menu)  # Right click
                entry_widget.bind("<Control-v>", lambda e: paste())  # Ctrl+V
                entry_widget.bind("<Command-v>", lambda e: paste())  # Cmd+V
                entry_widget.bind("<Control-c>", lambda e: copy())   # Ctrl+C
                entry_widget.bind("<Command-c>", lambda e: copy())   # Cmd+C
                entry_widget.bind("<Control-x>", lambda e: cut())    # Ctrl+X
                entry_widget.bind("<Command-x>", lambda e: cut())    # Cmd+X
                entry_widget.bind("<Control-a>", lambda e: select_all())  # Ctrl+A
                entry_widget.bind("<Command-a>", lambda e: select_all())  # Cmd+A
                
                return context_menu
            
            def create_api_key_entry(parent, text_var, show_char="*", help_text=""):
                """Create API key entry with show/hide toggle and help text"""
                frame = ttk.Frame(parent)
                
                ttk.Label(frame, text="API Key:").pack(anchor='w')
                
                entry_frame = ttk.Frame(frame)
                entry_frame.pack(fill='x', pady=5)
                
                entry = tk.Entry(entry_frame, textvariable=text_var, width=50, show=show_char, font=('Arial', 11))
                entry.pack(side='left', fill='x', expand=True)
                
                # Створюємо контекстне меню для tk.Entry
                context_menu = tk.Menu(entry, tearoff=0)
                context_menu.add_command(label="Вставити", command=lambda: entry.event_generate('<<Paste>>'))
                context_menu.add_command(label="Копіювати", command=lambda: entry.event_generate('<<Copy>>'))
                context_menu.add_command(label="Вирізати", command=lambda: entry.event_generate('<<Cut>>'))
                context_menu.add_separator()
                context_menu.add_command(label="Вибрати все", command=lambda: entry.select_range(0, tk.END))
                
                def show_context_menu(event):
                    context_menu.tk_popup(event.x_root, event.y_root)
                
                entry.bind('<Button-3>', show_context_menu)  # Правий клік
                entry.bind('<Button-2>', show_context_menu)  # Для Mac
                
                # Підтримка Cmd/Ctrl+V
                entry.bind('<Control-v>', lambda e: entry.event_generate('<<Paste>>'))
                entry.bind('<Command-v>', lambda e: entry.event_generate('<<Paste>>'))
                entry.bind('<Control-c>', lambda e: entry.event_generate('<<Copy>>'))
                entry.bind('<Command-c>', lambda e: entry.event_generate('<<Copy>>'))
                entry.bind('<Control-x>', lambda e: entry.event_generate('<<Cut>>'))
                entry.bind('<Command-x>', lambda e: entry.event_generate('<<Cut>>'))
                entry.bind('<Control-a>', lambda e: entry.select_range(0, tk.END))
                entry.bind('<Command-a>', lambda e: entry.select_range(0, tk.END))
                
                def toggle_visibility():
                    if entry.cget('show') == show_char:
                        entry.config(show='')
                        toggle_btn.config(text="🙈 Сховати")
                    else:
                        entry.config(show=show_char)
                        toggle_btn.config(text="👁️ Показати")
                
                toggle_btn = ttk.Button(entry_frame, text="👁️ Показати", 
                                      command=toggle_visibility, width=10)
                toggle_btn.pack(side='right', padx=(5, 0))
                
                # Add help text if provided
                if help_text:
                    help_label = ttk.Label(frame, text=help_text, 
                                         font=('Arial', 8), foreground='gray')
                    help_label.pack(anchor='w', pady=(2, 0))
                
                return entry, frame
            
            # Ollama Configuration
            ollama_frame = ttk.Frame(notebook)
            notebook.add(ollama_frame, text="🤖 Ollama")
            
            ttk.Label(ollama_frame, text="Ollama Configuration", 
                     font=('Arial', 12, 'bold')).pack(pady=10)
            
            # Ollama instructions
            instructions_text = """Для використання Ollama:
1. Встановіть Ollama: https://ollama.ai
2. Запустіть: ollama serve
3. Завантажте модель: ollama pull llama2
4. Переконайтеся, що сервер працює на localhost:11434"""
            
            instructions_label = ttk.Label(ollama_frame, text=instructions_text, 
                                         font=('Arial', 9), foreground='blue', 
                                         wraplength=500, justify='left')
            instructions_label.pack(pady=5, padx=10)
            
            # Ollama settings
            ollama_config = {}
            
            ttk.Label(ollama_frame, text="Server URL:").pack(anchor='w', padx=10)
            ollama_url_var = tk.StringVar(value="http://localhost:11434")
            ollama_url_entry = tk.Entry(ollama_frame, textvariable=ollama_url_var, width=50, font=('Arial', 11))
            ollama_url_entry.pack(fill='x', padx=10, pady=5)
            
            # Контекстне меню для URL
            url_context_menu = tk.Menu(ollama_url_entry, tearoff=0)
            url_context_menu.add_command(label="Вставити", command=lambda: ollama_url_entry.event_generate('<<Paste>>'))
            url_context_menu.add_command(label="Копіювати", command=lambda: ollama_url_entry.event_generate('<<Copy>>'))
            url_context_menu.add_command(label="Вирізати", command=lambda: ollama_url_entry.event_generate('<<Cut>>'))
            url_context_menu.add_separator()
            url_context_menu.add_command(label="Вибрати все", command=lambda: ollama_url_entry.select_range(0, tk.END))
            
            def show_url_context_menu(event):
                url_context_menu.tk_popup(event.x_root, event.y_root)
            
            ollama_url_entry.bind('<Button-3>', show_url_context_menu)
            ollama_url_entry.bind('<Button-2>', show_url_context_menu)
            ollama_url_entry.bind('<Control-v>', lambda e: ollama_url_entry.event_generate('<<Paste>>'))
            ollama_url_entry.bind('<Command-v>', lambda e: ollama_url_entry.event_generate('<<Paste>>'))
            
            ollama_config['url'] = ollama_url_var
            
            ttk.Label(ollama_frame, text="Default Model:").pack(anchor='w', padx=10)
            ollama_model_var = tk.StringVar(value="llama2")
            ollama_model_entry = tk.Entry(ollama_frame, textvariable=ollama_model_var, width=50, font=('Arial', 11))
            ollama_model_entry.pack(fill='x', padx=10, pady=5)
            
            # Контекстне меню для моделі
            model_context_menu = tk.Menu(ollama_model_entry, tearoff=0)
            model_context_menu.add_command(label="Вставити", command=lambda: ollama_model_entry.event_generate('<<Paste>>'))
            model_context_menu.add_command(label="Копіювати", command=lambda: ollama_model_entry.event_generate('<<Copy>>'))
            model_context_menu.add_command(label="Вирізати", command=lambda: ollama_model_entry.event_generate('<<Cut>>'))
            model_context_menu.add_separator()
            model_context_menu.add_command(label="Вибрати все", command=lambda: ollama_model_entry.select_range(0, tk.END))
            
            def show_model_context_menu(event):
                model_context_menu.tk_popup(event.x_root, event.y_root)
            
            ollama_model_entry.bind('<Button-3>', show_model_context_menu)
            ollama_model_entry.bind('<Button-2>', show_model_context_menu)
            ollama_model_entry.bind('<Control-v>', lambda e: ollama_model_entry.event_generate('<<Paste>>'))
            ollama_model_entry.bind('<Command-v>', lambda e: ollama_model_entry.event_generate('<<Paste>>'))
            
            ollama_config['model'] = ollama_model_var
            
            provider_configs['ollama'] = ollama_config
            
            # Gemini Configuration
            gemini_frame = ttk.Frame(notebook)
            notebook.add(gemini_frame, text="🔷 Gemini")
            
            ttk.Label(gemini_frame, text="Google Gemini Configuration", 
                     font=('Arial', 12, 'bold')).pack(pady=10)
            
            gemini_config = {}
            
            gemini_key_var = tk.StringVar()
            gemini_help = "Отримати ключ: https://makersuite.google.com/app/apikey"
            gemini_key_entry, gemini_key_frame = create_api_key_entry(gemini_frame, gemini_key_var, help_text=gemini_help)
            gemini_key_frame.pack(fill='x', padx=10)
            gemini_config['api_key'] = gemini_key_var
            
            ttk.Label(gemini_frame, text="Model:").pack(anchor='w', padx=10)
            gemini_model_var = tk.StringVar(value="gemini-pro")
            gemini_model_entry = tk.Entry(gemini_frame, textvariable=gemini_model_var, width=50, font=('Arial', 11))
            gemini_model_entry.pack(fill='x', padx=10, pady=5)
            
            # Контекстне меню для моделі Gemini
            gemini_model_context_menu = tk.Menu(gemini_model_entry, tearoff=0)
            gemini_model_context_menu.add_command(label="Вставити", command=lambda: gemini_model_entry.event_generate('<<Paste>>'))
            gemini_model_context_menu.add_command(label="Копіювати", command=lambda: gemini_model_entry.event_generate('<<Copy>>'))
            gemini_model_context_menu.add_command(label="Вирізати", command=lambda: gemini_model_entry.event_generate('<<Cut>>'))
            gemini_model_context_menu.add_separator()
            gemini_model_context_menu.add_command(label="Вибрати все", command=lambda: gemini_model_entry.select_range(0, tk.END))
            
            def show_gemini_model_context_menu(event):
                gemini_model_context_menu.tk_popup(event.x_root, event.y_root)
            
            gemini_model_entry.bind('<Button-3>', show_gemini_model_context_menu)
            gemini_model_entry.bind('<Button-2>', show_gemini_model_context_menu)
            gemini_model_entry.bind('<Control-v>', lambda e: gemini_model_entry.event_generate('<<Paste>>'))
            gemini_model_entry.bind('<Command-v>', lambda e: gemini_model_entry.event_generate('<<Paste>>'))
            
            gemini_config['model'] = gemini_model_var
            
            provider_configs['gemini'] = gemini_config
            
            # Groq Configuration
            groq_frame = ttk.Frame(notebook)
            notebook.add(groq_frame, text="⚡ Groq")
            
            ttk.Label(groq_frame, text="Groq Configuration", 
                     font=('Arial', 12, 'bold')).pack(pady=10)
            
            groq_config = {}
            
            groq_key_var = tk.StringVar()
            groq_help = "Отримати ключ: https://console.groq.com/keys"
            groq_key_entry, groq_key_frame = create_api_key_entry(groq_frame, groq_key_var, help_text=groq_help)
            groq_key_frame.pack(fill='x', padx=10)
            groq_config['api_key'] = groq_key_var
            
            ttk.Label(groq_frame, text="Model:").pack(anchor='w', padx=10)
            groq_model_var = tk.StringVar(value="llama3-8b-8192")
            groq_model_entry = tk.Entry(groq_frame, textvariable=groq_model_var, width=50, font=('Arial', 11))
            groq_model_entry.pack(fill='x', padx=10, pady=5)
            
            # Контекстне меню для моделі Groq
            groq_model_context_menu = tk.Menu(groq_model_entry, tearoff=0)
            groq_model_context_menu.add_command(label="Вставити", command=lambda: groq_model_entry.event_generate('<<Paste>>'))
            groq_model_context_menu.add_command(label="Копіювати", command=lambda: groq_model_entry.event_generate('<<Copy>>'))
            groq_model_context_menu.add_command(label="Вирізати", command=lambda: groq_model_entry.event_generate('<<Cut>>'))
            groq_model_context_menu.add_separator()
            groq_model_context_menu.add_command(label="Вибрати все", command=lambda: groq_model_entry.select_range(0, tk.END))
            
            def show_groq_model_context_menu(event):
                groq_model_context_menu.tk_popup(event.x_root, event.y_root)
            
            groq_model_entry.bind('<Button-3>', show_groq_model_context_menu)
            groq_model_entry.bind('<Button-2>', show_groq_model_context_menu)
            groq_model_entry.bind('<Control-v>', lambda e: groq_model_entry.event_generate('<<Paste>>'))
            groq_model_entry.bind('<Command-v>', lambda e: groq_model_entry.event_generate('<<Paste>>'))
            
            groq_config['model'] = groq_model_var
            
            provider_configs['groq'] = groq_config
            
            # Mistral Configuration
            mistral_frame = ttk.Frame(notebook)
            notebook.add(mistral_frame, text="🌪️ Mistral")
            
            ttk.Label(mistral_frame, text="Mistral AI Configuration", 
                     font=('Arial', 12, 'bold')).pack(pady=10)
            
            mistral_config = {}
            
            mistral_key_var = tk.StringVar()
            mistral_help = "Отримати ключ: https://console.mistral.ai/api-keys/"
            mistral_key_entry, mistral_key_frame = create_api_key_entry(mistral_frame, mistral_key_var, help_text=mistral_help)
            mistral_key_frame.pack(fill='x', padx=10)
            mistral_config['api_key'] = mistral_key_var
            
            ttk.Label(mistral_frame, text="Model:").pack(anchor='w', padx=10)
            mistral_model_var = tk.StringVar(value="mistral-large-latest")
            mistral_model_entry = tk.Entry(mistral_frame, textvariable=mistral_model_var, width=50, font=('Arial', 11))
            mistral_model_entry.pack(fill='x', padx=10, pady=5)
            
            # Контекстне меню для моделі Mistral
            mistral_model_context_menu = tk.Menu(mistral_model_entry, tearoff=0)
            mistral_model_context_menu.add_command(label="Вставити", command=lambda: mistral_model_entry.event_generate('<<Paste>>'))
            mistral_model_context_menu.add_command(label="Копіювати", command=lambda: mistral_model_entry.event_generate('<<Copy>>'))
            mistral_model_context_menu.add_command(label="Вирізати", command=lambda: mistral_model_entry.event_generate('<<Cut>>'))
            mistral_model_context_menu.add_separator()
            mistral_model_context_menu.add_command(label="Вибрати все", command=lambda: mistral_model_entry.select_range(0, tk.END))
            
            def show_mistral_model_context_menu(event):
                mistral_model_context_menu.tk_popup(event.x_root, event.y_root)
            
            mistral_model_entry.bind('<Button-3>', show_mistral_model_context_menu)
            mistral_model_entry.bind('<Button-2>', show_mistral_model_context_menu)
            mistral_model_entry.bind('<Control-v>', lambda e: mistral_model_entry.event_generate('<<Paste>>'))
            mistral_model_entry.bind('<Command-v>', lambda e: mistral_model_entry.event_generate('<<Paste>>'))
            
            mistral_config['model'] = mistral_model_var
            
            provider_configs['mistral'] = mistral_config
            
            # Load existing configuration
            self.load_provider_config(provider_configs)
            
            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill='x', pady=20)
            
            def save_configuration():
                try:
                    # Save configuration for each provider
                    config_data = {}
                    
                    for provider_name, config in provider_configs.items():
                        provider_data = {}
                        for key, var in config.items():
                            provider_data[key] = var.get()
                        config_data[provider_name] = provider_data
                    
                    # Save to file
                    config_file = "ai_providers_config.json"
                    with open(config_file, 'w') as f:
                        json.dump(config_data, f, indent=2)
                    
                    # Update provider manager
                    self.ai_provider_manager.load_configuration(config_data)
                    
                    messagebox.showinfo("Success", "Provider configuration saved successfully!")
                    dialog.destroy()
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save configuration: {e}")
            
            def test_configuration():
                try:
                    # Test current configuration
                    test_results = []
                    
                    for provider_name, config in provider_configs.items():
                        provider_data = {}
                        for key, var in config.items():
                            provider_data[key] = var.get()
                        
                        # Test provider
                        try:
                            if provider_name == 'ollama':
                                # Test Ollama connection
                                import requests
                                response = requests.get(f"{provider_data['url']}/api/tags", timeout=5)
                                if response.status_code == 200:
                                    test_results.append(f"✅ {provider_name}: Connected")
                                else:
                                    test_results.append(f"❌ {provider_name}: Connection failed")
                            else:
                                # Test other providers with API key
                                if provider_data.get('api_key'):
                                    test_results.append(f"✅ {provider_name}: API key configured")
                                else:
                                    test_results.append(f"⚠️ {provider_name}: No API key")
                        except Exception as e:
                            test_results.append(f"❌ {provider_name}: {str(e)}")
                    
                    # Show test results
                    result_text = "Configuration Test Results:\n\n" + "\n".join(test_results)
                    messagebox.showinfo("Test Results", result_text)
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Test failed: {e}")
            
            def reset_configuration():
                if messagebox.askyesno("Confirm", "Reset all provider configurations?"):
                    # Clear all entries
                    for config in provider_configs.values():
                        for var in config.values():
                            var.set("")
                    
                    # Set defaults
                    ollama_url_var.set("http://localhost:11434")
                    ollama_model_var.set("llama2")
                    gemini_model_var.set("gemini-pro")
                    groq_model_var.set("llama3-8b-8192")
                    mistral_model_var.set("mistral-large-latest")
            
            ttk.Button(button_frame, text="Test Configuration", 
                      command=test_configuration).pack(side='left', padx=5)
            ttk.Button(button_frame, text="Reset", 
                      command=reset_configuration).pack(side='left', padx=5)
            ttk.Button(button_frame, text="Save", 
                      command=save_configuration).pack(side='right', padx=5)
            ttk.Button(button_frame, text="Cancel", 
                      command=dialog.destroy).pack(side='right', padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Configuration dialog failed: {e}")
    
    def load_provider_config(self, provider_configs):
        """Load existing provider configuration"""
        try:
            config_file = "ai_providers_config.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Apply loaded configuration
                for provider_name, config in provider_configs.items():
                    if provider_name in config_data:
                        provider_data = config_data[provider_name]
                        for key, var in config.items():
                            if key in provider_data:
                                var.set(provider_data[key])
        except Exception as e:
            print(f"Failed to load provider configuration: {e}")
    
    def test_all_providers(self):
        """Test all AI providers"""
        test_prompt = "Test connection - respond with 'OK' if working"
        results = {}
        
        for name, provider in self.ai_provider_manager.providers.items():
            try:
                response = provider.query(test_prompt)
                results[name] = "✅ Working" if not response.startswith("Error") else "❌ Failed"
            except:
                results[name] = "❌ Failed"
        
        # Show results
        result_text = "Provider Test Results:\n\n"
        for name, status in results.items():
            result_text += f"{name}: {status}\n"
        
        messagebox.showinfo("Test Results", result_text)
    
    def test_active_provider(self):
        """Test active AI provider"""
        active_provider = self.ai_provider_manager.get_active_provider()
        if not active_provider:
            messagebox.showwarning("Warning", "No active provider")
            return
        
        test_prompt = "Test connection - respond with 'OK' if working"
        try:
            response = active_provider.query(test_prompt)
            if not response.startswith("Error"):
                messagebox.showinfo("Test Result", f"✅ {active_provider.name} is working\n\nResponse: {response}")
            else:
                messagebox.showerror("Test Result", f"❌ {active_provider.name} failed\n\nError: {response}")
        except Exception as e:
            messagebox.showerror("Test Result", f"❌ {active_provider.name} failed\n\nError: {str(e)}")
    
    def refresh_tasks(self):
        """Refresh scheduled tasks list"""
        # Clear existing items
        for item in self.tasks_tree.get_children():
            self.tasks_tree.delete(item)
        
        # Check if task_scheduler is initialized
        if self.task_scheduler is None:
            # Add placeholder message
            self.tasks_tree.insert('', 'end', text="Task Scheduler", 
                                 values=("⚠️ Not initialized", "Please restart", "N/A", "N/A"))
            return
        
        # Get tasks
        try:
            tasks = self.task_scheduler.get_tasks()
            
            # Add tasks to tree
            for task in tasks:
                status = "✅ Enabled" if task.enabled else "⏸️ Disabled"
                next_run = task.next_run.strftime("%Y-%m-%d %H:%M") if task.next_run else "N/A"
                last_run = task.last_run.strftime("%Y-%m-%d %H:%M") if task.last_run else "Never"
                
                self.tasks_tree.insert('', 'end', text=task.name, values=(
                    task.task_type.value,
                    f"{task.schedule_type.value}",
                    status,
                    next_run,
                    last_run
                ))
        except Exception as e:
            # Add error message
            self.tasks_tree.insert('', 'end', text="Error", 
                                 values=(f"❌ Error: {str(e)}", "Check configuration", "N/A", "N/A"))
    
    def add_scheduled_task(self):
        """Add new scheduled task"""
        if self.task_scheduler is None:
            messagebox.showerror("Error", "Task scheduler not initialized")
            return
            
        # Create simple task dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Scheduled Task")
        dialog.geometry("400x300")
        
        # Task name
        ttk.Label(dialog, text="Task Name:").pack(pady=5)
        name_entry = ttk.Entry(dialog, width=40)
        name_entry.pack(pady=5)
        
        # Task type
        ttk.Label(dialog, text="Task Type:").pack(pady=5)
        task_type_var = tk.StringVar(value="security_scan")
        task_type_combo = ttk.Combobox(dialog, textvariable=task_type_var, 
                                      values=["security_scan", "network_analysis", "ai_analysis"])
        task_type_combo.pack(pady=5)
        
        # Schedule type
        ttk.Label(dialog, text="Schedule Type:").pack(pady=5)
        schedule_type_var = tk.StringVar(value="minutes")
        schedule_combo = ttk.Combobox(dialog, textvariable=schedule_type_var,
                                     values=["once", "daily", "hourly", "minutes", "weekly"])
        schedule_combo.pack(pady=5)
        
        # Schedule parameters
        ttk.Label(dialog, text="Schedule Parameters (JSON):").pack(pady=5)
        params_entry = ttk.Entry(dialog, width=40)
        params_entry.insert(0, '{"minutes": 30}')
        params_entry.pack(pady=5)
        
        def create_task():
            try:
                name = name_entry.get()
                task_type = TaskType(task_type_var.get())
                schedule_type = ScheduleType(schedule_type_var.get())
                schedule_params = json.loads(params_entry.get())
                
                if task_type == TaskType.SECURITY_SCAN:
                    task = self.task_scheduler.create_security_scan_task(name, schedule_type, schedule_params)
                elif task_type == TaskType.NETWORK_ANALYSIS:
                    task = self.task_scheduler.create_network_analysis_task(name, schedule_type, schedule_params)
                elif task_type == TaskType.AI_ANALYSIS:
                    task = self.task_scheduler.create_ai_analysis_task(name, schedule_type, schedule_params, "Analyze system security")
                else:
                    messagebox.showerror("Error", "Unsupported task type")
                    return
                
                if self.task_scheduler.add_task(task):
                    messagebox.showinfo("Success", f"Task '{name}' created successfully")
                    self.refresh_tasks()
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to create task")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid parameters: {str(e)}")
        
        ttk.Button(dialog, text="Create Task", command=create_task).pack(pady=10)
    
    def run_task_now(self):
        """Run selected task immediately"""
        if self.task_scheduler is None:
            messagebox.showerror("Error", "Task scheduler not initialized")
            return
            
        selection = self.tasks_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a task")
            return
        
        task_name = self.tasks_tree.item(selection[0])['text']
        task = self.task_scheduler.get_task(task_name)
        
        if task:
            result = self.task_scheduler.run_task_now(task.id)
            if result is not None:
                messagebox.showinfo("Success", f"Task '{task_name}' executed successfully")
            else:
                messagebox.showerror("Error", f"Failed to execute task '{task_name}'")
            self.refresh_tasks()
    
    def toggle_task(self):
        """Enable/disable selected task"""
        if self.task_scheduler is None:
            messagebox.showerror("Error", "Task scheduler not initialized")
            return
            
        selection = self.tasks_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a task")
            return
        
        task_name = self.tasks_tree.item(selection[0])['text']
        task = self.task_scheduler.get_task(task_name)
        
        if task:
            if task.enabled:
                self.task_scheduler.disable_task(task.id)
                messagebox.showinfo("Info", f"Task '{task_name}' disabled")
            else:
                self.task_scheduler.enable_task(task.id)
                messagebox.showinfo("Info", f"Task '{task_name}' enabled")
            self.refresh_tasks()
    
    def delete_scheduled_task(self):
        """Delete selected task"""
        if self.task_scheduler is None:
            messagebox.showerror("Error", "Task scheduler not initialized")
            return
            
        selection = self.tasks_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a task")
            return
        
        task_name = self.tasks_tree.item(selection[0])['text']
        
        if messagebox.askyesno("Confirm", f"Delete task '{task_name}'?"):
            self.task_scheduler.delete_task(task_name)
            self.refresh_tasks()
            messagebox.showinfo("Success", f"Task '{task_name}' deleted")
    
    def create_quick_task(self, task_type: str, schedule_type: ScheduleType, schedule_params: Dict):
        """Create a quick scheduled task"""
        task_name = f"{task_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if task_type == "security_scan":
            task = self.task_scheduler.create_security_scan_task(task_name, schedule_type, schedule_params)
        elif task_type == "network_analysis":
            task = self.task_scheduler.create_network_analysis_task(task_name, schedule_type, schedule_params)
        elif task_type == "ai_analysis":
            task = self.task_scheduler.create_ai_analysis_task(task_name, schedule_type, schedule_params, "Analyze system security")
        else:
            messagebox.showerror("Error", "Unknown task type")
            return
        
        if self.task_scheduler.add_task(task):
            messagebox.showinfo("Success", f"Quick task '{task_name}' created")
            self.refresh_tasks()
        else:
            messagebox.showerror("Error", "Failed to create quick task")
    
    def scheduled_ai_analysis(self, prompt: str = "Analyze system security"):
        """Scheduled AI analysis function"""
        try:
            response = self.ai_provider_manager.query(prompt)
            self.log_message(f"Scheduled AI analysis completed: {response[:100]}...")
            return response
        except Exception as e:
            self.log_message(f"Scheduled AI analysis failed: {str(e)}")
            return None
    
    def isolate_network(self):
        """Isolate the system from the network"""
        try:
            # Create confirmation dialog
            if not messagebox.askyesno("Network Isolation", 
                "This will disconnect all network interfaces.\n\n"
                "Are you sure you want to isolate the system from the network?"):
                return
            
            self.log_message("🚨 EMERGENCY: Starting network isolation...")
            
            # Disable Wi-Fi
            try:
                subprocess.run(['networksetup', '-setairportpower', 'en0', 'off'], 
                             capture_output=True, text=True)
                self.log_message("✓ Wi-Fi disabled")
            except Exception as e:
                self.log_message(f"⚠️ Failed to disable Wi-Fi: {e}")
            
            # Disable Ethernet
            try:
                subprocess.run(['networksetup', '-setnetworkserviceenabled', 'Ethernet', 'off'], 
                             capture_output=True, text=True)
                self.log_message("✓ Ethernet disabled")
            except Exception as e:
                self.log_message(f"⚠️ Failed to disable Ethernet: {e}")
            
            # Block all incoming connections
            try:
                subprocess.run(['sudo', 'pfctl', '-e'], capture_output=True, text=True)
                subprocess.run(['sudo', 'pfctl', '-f', '/etc/pf.conf'], capture_output=True, text=True)
                self.log_message("✓ Firewall rules applied")
            except Exception as e:
                self.log_message(f"⚠️ Failed to apply firewall rules: {e}")
            
            messagebox.showinfo("Network Isolation", 
                "Network isolation completed!\n\n"
                "✓ Wi-Fi disabled\n"
                "✓ Ethernet disabled\n"
                "✓ Firewall rules applied\n\n"
                "System is now isolated from the network.")
            
            self.log_message("🚨 EMERGENCY: Network isolation completed successfully")
            
        except Exception as e:
            self.log_message(f"❌ Network isolation failed: {e}")
            messagebox.showerror("Error", f"Network isolation failed: {e}")

    def terminate_processes(self):
        """Terminate suspicious or dangerous processes"""
        try:
            # Get list of running processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu': proc.info['cpu_percent'],
                        'memory': proc.info['memory_percent']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage (most suspicious first)
            processes.sort(key=lambda x: x['cpu'], reverse=True)
            
            # Create process selection dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("Terminate Processes")
            dialog.geometry("600x400")
            
            # Process list
            ttk.Label(dialog, text="Select processes to terminate:").pack(pady=5)
            
            # Create treeview for processes
            columns = ('PID', 'Name', 'CPU %', 'Memory %')
            process_tree = ttk.Treeview(dialog, columns=columns, show='headings', height=15)
            
            for col in columns:
                process_tree.heading(col, text=col)
                process_tree.column(col, width=120)
            
            # Add processes to tree
            for proc in processes[:50]:  # Show top 50 processes
                process_tree.insert('', 'end', values=(
                    proc['pid'],
                    proc['name'],
                    f"{proc['cpu']:.1f}",
                    f"{proc['memory']:.1f}"
                ))
            
            process_tree.pack(fill='both', expand=True, padx=10, pady=5)
            
            # Buttons
            button_frame = ttk.Frame(dialog)
            button_frame.pack(fill='x', padx=10, pady=5)
            
            def terminate_selected():
                selected = process_tree.selection()
                if not selected:
                    messagebox.showinfo("Info", "Please select processes to terminate")
                    return
                
                if not messagebox.askyesno("Confirm", 
                    f"Terminate {len(selected)} selected process(es)?"):
                    return
                
                terminated = 0
                for item in selected:
                    values = process_tree.item(item)['values']
                    pid = int(values[0])
                    name = values[1]
                    
                    try:
                        proc = psutil.Process(pid)
                        proc.terminate()
                        terminated += 1
                        self.log_message(f"✓ Terminated process: {name} (PID: {pid})")
                    except Exception as e:
                        self.log_message(f"❌ Failed to terminate {name} (PID: {pid}): {e}")
                
                messagebox.showinfo("Termination Complete", 
                    f"Successfully terminated {terminated} process(es)")
                dialog.destroy()
            
            def terminate_suspicious():
                # Auto-terminate processes with high CPU usage
                suspicious = []
                for proc in processes:
                    if proc['cpu'] > 50 or proc['memory'] > 20:
                        suspicious.append(proc)
                
                if not suspicious:
                    messagebox.showinfo("Info", "No suspicious processes found")
                    return
                
                if not messagebox.askyesno("Confirm", 
                    f"Terminate {len(suspicious)} suspicious process(es)?"):
                    return
                
                terminated = 0
                for proc in suspicious:
                    try:
                        psutil.Process(proc['pid']).terminate()
                        terminated += 1
                        self.log_message(f"✓ Terminated suspicious process: {proc['name']} (PID: {proc['pid']})")
                    except Exception as e:
                        self.log_message(f"❌ Failed to terminate {proc['name']}: {e}")
                
                messagebox.showinfo("Termination Complete", 
                    f"Successfully terminated {terminated} suspicious process(es)")
                dialog.destroy()
            
            ttk.Button(button_frame, text="Terminate Selected", 
                      command=terminate_selected).pack(side='left', padx=5)
            ttk.Button(button_frame, text="Terminate Suspicious", 
                      command=terminate_suspicious).pack(side='left', padx=5)
            ttk.Button(button_frame, text="Cancel", 
                      command=dialog.destroy).pack(side='right', padx=5)
            
        except Exception as e:
            self.log_message(f"❌ Process termination failed: {e}")
            messagebox.showerror("Error", f"Process termination failed: {e}")

    def backup_data(self):
        """Create emergency backup of important data"""
        try:
            # Create backup dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("Emergency Data Backup")
            dialog.geometry("500x400")
            
            ttk.Label(dialog, text="Emergency Data Backup", 
                     font=('Arial', 14, 'bold')).pack(pady=10)
            
            # Backup options
            options_frame = ttk.LabelFrame(dialog, text="Backup Options", padding=10)
            options_frame.pack(fill='x', padx=10, pady=5)
            
            # Checkboxes for backup locations
            backup_vars = {}
            backup_locations = {
                'desktop': '~/Desktop',
                'documents': '~/Documents', 
                'downloads': '~/Downloads',
                'pictures': '~/Pictures',
                'system_logs': '/var/log',
                'application_logs': '~/Library/Logs'
            }
            
            for key, path in backup_locations.items():
                var = tk.BooleanVar(value=True)
                backup_vars[key] = var
                ttk.Checkbutton(options_frame, text=f"Backup {path}", 
                              variable=var).pack(anchor='w')
            
            # Backup destination
            dest_frame = ttk.Frame(dialog)
            dest_frame.pack(fill='x', padx=10, pady=5)
            
            ttk.Label(dest_frame, text="Backup Destination:").pack(anchor='w')
            dest_var = tk.StringVar(value="~/NIMDA_Backup")
            dest_entry = ttk.Entry(dest_frame, textvariable=dest_var, width=50)
            dest_entry.pack(fill='x', pady=2)
            
            def start_backup():
                try:
                    # Get selected locations
                    selected = [key for key, var in backup_vars.items() if var.get()]
                    if not selected:
                        messagebox.showinfo("Info", "Please select at least one location to backup")
                        return
                    
                    backup_dest = os.path.expanduser(dest_var.get())
                    
                    # Create backup directory
                    os.makedirs(backup_dest, exist_ok=True)
                    
                    self.log_message("🚨 EMERGENCY: Starting data backup...")
                    
                    # Create backup with timestamp
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_file = os.path.join(backup_dest, f"emergency_backup_{timestamp}.tar.gz")
                    
                    # Build tar command
                    tar_cmd = ['tar', '-czf', backup_file]
                    
                    for location in selected:
                        source_path = os.path.expanduser(backup_locations[location])
                        if os.path.exists(source_path):
                            tar_cmd.append(source_path)
                    
                    # Execute backup
                    result = subprocess.run(tar_cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        size = os.path.getsize(backup_file) / (1024*1024)  # MB
                        self.log_message(f"✓ Emergency backup completed: {backup_file} ({size:.1f} MB)")
                        messagebox.showinfo("Backup Complete", 
                            f"Emergency backup completed successfully!\n\n"
                            f"Location: {backup_file}\n"
                            f"Size: {size:.1f} MB\n"
                            f"Timestamp: {timestamp}")
                    else:
                        raise Exception(f"Tar command failed: {result.stderr}")
                    
                    dialog.destroy()
                    
                except Exception as e:
                    self.log_message(f"❌ Backup failed: {e}")
                    messagebox.showerror("Backup Error", f"Backup failed: {e}")
            
            # Buttons
            button_frame = ttk.Frame(dialog)
            button_frame.pack(fill='x', padx=10, pady=10)
            
            ttk.Button(button_frame, text="Start Backup", 
                      command=start_backup).pack(side='left', padx=5)
            ttk.Button(button_frame, text="Cancel", 
                      command=dialog.destroy).pack(side='right', padx=5)
            
        except Exception as e:
            self.log_message(f"❌ Backup dialog failed: {e}")
            messagebox.showerror("Error", f"Backup dialog failed: {e}")

    def shutdown_system(self):
        """Emergency system shutdown"""
        try:
            # Create shutdown confirmation dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("Emergency System Shutdown")
            dialog.geometry("400x300")
            
            ttk.Label(dialog, text="🚨 EMERGENCY SHUTDOWN", 
                     font=('Arial', 16, 'bold'), foreground='red').pack(pady=20)
            
            ttk.Label(dialog, text="This will shut down the system immediately.\n\n"
                     "All unsaved work will be lost.\n\n"
                     "Are you absolutely sure?", 
                     justify='center').pack(pady=10)
            
            # Shutdown options
            options_frame = ttk.LabelFrame(dialog, text="Shutdown Options", padding=10)
            options_frame.pack(fill='x', padx=20, pady=10)
            
            shutdown_type = tk.StringVar(value="normal")
            ttk.Radiobutton(options_frame, text="Normal Shutdown", 
                          variable=shutdown_type, value="normal").pack(anchor='w')
            ttk.Radiobutton(options_frame, text="Force Shutdown", 
                          variable=shutdown_type, value="force").pack(anchor='w')
            ttk.Radiobutton(options_frame, text="Restart System", 
                          variable=shutdown_type, value="restart").pack(anchor='w')
            
            def execute_shutdown():
                try:
                    shutdown_mode = shutdown_type.get()
                    
                    self.log_message(f"🚨 EMERGENCY: System {shutdown_mode} initiated...")
                    
                    if shutdown_mode == "normal":
                        subprocess.run(['sudo', 'shutdown', '-h', 'now'])
                    elif shutdown_mode == "force":
                        subprocess.run(['sudo', 'shutdown', '-h', '-f', 'now'])
                    elif shutdown_mode == "restart":
                        subprocess.run(['sudo', 'shutdown', '-r', 'now'])
                    
                    # If we get here, shutdown command failed
                    messagebox.showerror("Error", "Shutdown command failed. Try using Force Shutdown.")
                    
                except Exception as e:
                    self.log_message(f"❌ Shutdown failed: {e}")
                    messagebox.showerror("Error", f"Shutdown failed: {e}")
            
            # Buttons
            button_frame = ttk.Frame(dialog)
            button_frame.pack(fill='x', padx=20, pady=20)
            
            ttk.Button(button_frame, text="🚨 SHUTDOWN", 
                      command=execute_shutdown).pack(side='left', padx=5)
            ttk.Button(button_frame, text="Cancel", 
                      command=dialog.destroy).pack(side='right', padx=5)
            
        except Exception as e:
            self.log_message(f"❌ Shutdown dialog failed: {e}")
            messagebox.showerror("Error", f"Shutdown dialog failed: {e}")

    def emergency_lockdown(self):
        """Activate emergency lockdown mode"""
        try:
            # Create lockdown confirmation dialog
            if not messagebox.askyesno("Emergency Lockdown", 
                "🚨 EMERGENCY LOCKDOWN\n\n"
                "This will activate maximum security measures:\n"
                "• Disconnect from network\n"
                "• Lock screen\n"
                "• Terminate suspicious processes\n"
                "• Enable strict firewall rules\n"
                "• Create emergency backup\n\n"
                "Are you sure you want to activate lockdown?"):
                return
            
            self.log_message("🚨 EMERGENCY: Lockdown mode activated!")
            
            # Step 1: Network isolation
            self.log_message("Step 1/5: Isolating network...")
            try:
                subprocess.run(['networksetup', '-setairportpower', 'en0', 'off'], 
                             capture_output=True, text=True)
                subprocess.run(['networksetup', '-setnetworkserviceenabled', 'Ethernet', 'off'], 
                             capture_output=True, text=True)
                self.log_message("✓ Network isolated")
            except Exception as e:
                self.log_message(f"⚠️ Network isolation failed: {e}")
            
            # Step 2: Lock screen
            self.log_message("Step 2/5: Locking screen...")
            try:
                subprocess.run(['pmset', 'displaysleepnow'], capture_output=True, text=True)
                self.log_message("✓ Screen locked")
            except Exception as e:
                self.log_message(f"⚠️ Screen lock failed: {e}")
            
            # Step 3: Terminate suspicious processes
            self.log_message("Step 3/5: Terminating suspicious processes...")
            try:
                terminated = 0
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        if proc.info['cpu_percent'] > 50:
                            proc.terminate()
                            terminated += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                self.log_message(f"✓ Terminated {terminated} suspicious processes")
            except Exception as e:
                self.log_message(f"⚠️ Process termination failed: {e}")
            
            # Step 4: Enable strict firewall
            self.log_message("Step 4/5: Enabling strict firewall...")
            try:
                subprocess.run(['sudo', 'pfctl', '-e'], capture_output=True, text=True)
                # Create strict firewall rules
                strict_rules = """
# Emergency lockdown firewall rules
block drop all
"""
                with open('/tmp/emergency_pf.conf', 'w') as f:
                    f.write(strict_rules)
                subprocess.run(['sudo', 'pfctl', '-f', '/tmp/emergency_pf.conf'], 
                             capture_output=True, text=True)
                self.log_message("✓ Strict firewall enabled")
            except Exception as e:
                self.log_message(f"⚠️ Firewall configuration failed: {e}")
            
            # Step 5: Create emergency backup
            self.log_message("Step 5/5: Creating emergency backup...")
            try:
                backup_dir = os.path.expanduser("~/NIMDA_Emergency_Backup")
                os.makedirs(backup_dir, exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = os.path.join(backup_dir, f"lockdown_backup_{timestamp}.tar.gz")
                
                # Backup critical directories
                subprocess.run(['tar', '-czf', backup_file, 
                              os.path.expanduser('~/Desktop'),
                              os.path.expanduser('~/Documents')], 
                             capture_output=True, text=True)
                
                size = os.path.getsize(backup_file) / (1024*1024)  # MB
                self.log_message(f"✓ Emergency backup created: {backup_file} ({size:.1f} MB)")
            except Exception as e:
                self.log_message(f"⚠️ Emergency backup failed: {e}")
            
            # Final confirmation
            messagebox.showinfo("Lockdown Complete", 
                "🚨 EMERGENCY LOCKDOWN ACTIVATED\n\n"
                "✓ Network isolated\n"
                "✓ Screen locked\n"
                "✓ Suspicious processes terminated\n"
                "✓ Strict firewall enabled\n"
                "✓ Emergency backup created\n\n"
                "System is now in maximum security mode.")
            
            self.log_message("🚨 EMERGENCY: Lockdown mode completed successfully")
            
        except Exception as e:
            self.log_message(f"❌ Lockdown failed: {e}")
            messagebox.showerror("Error", f"Lockdown failed: {e}")

    def create_security_policy_tab(self):
        """Create security policy configuration tab"""
        policy_frame = ttk.Frame(self.notebook)
        self.notebook.add(policy_frame, text="🛡️ Security Policy")
        
        # Create scrollable frame
        canvas = tk.Canvas(policy_frame)
        scrollbar = ttk.Scrollbar(policy_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Policy overview
        overview_frame = ttk.LabelFrame(scrollable_frame, text="Security Policy Overview", padding=10)
        overview_frame.pack(fill='x', padx=10, pady=5)
        
        overview_text = """Security Policy allows you to configure automatic actions for different threat levels:

🟢 LOW: Basic monitoring and logging
🟡 MEDIUM: Enhanced monitoring, logging, and analysis  
🟠 HIGH: Active monitoring, logging, analysis, blocking, and alerts
🔴 CRITICAL: Full monitoring, blocking, isolation, AI analysis, and alerts
⚫ EMERGENCY: Complete lockdown with all security measures

Select actions for each threat level below:"""
        
        overview_label = ttk.Label(overview_frame, text=overview_text, justify='left')
        overview_label.pack(anchor='w')
        
        # Threat level configuration - make it more compact
        for level in ThreatLevel:
            level_frame = ttk.LabelFrame(scrollable_frame, text=f"{level.value[1]} {level.value[3]} ({level.value[0]})", padding=5)
            level_frame.pack(fill='x', padx=10, pady=2)
            
            # Get current actions for this level
            current_actions = self.security_policy.get_actions_for_level(level)
            
            # Create checkboxes in a grid layout
            action_vars = {}
            row = 0
            col = 0
            max_cols = 2  # 2 columns for better layout
            
            for action in SecurityAction:
                var = tk.BooleanVar(value=action in current_actions)
                action_vars[action] = var
                
                # Create action description
                action_descriptions = {
                    SecurityAction.MONITOR: "🔍 Monitor",
                    SecurityAction.LOG: "📝 Log", 
                    SecurityAction.ANALYZE: "🔬 Analyze",
                    SecurityAction.BLOCK: "🚫 Block",
                    SecurityAction.ISOLATE: "🔒 Isolate",
                    SecurityAction.TERMINATE: "💀 Terminate",
                    SecurityAction.BACKUP: "💾 Backup",
                    SecurityAction.ALERT: "🚨 Alert",
                    SecurityAction.AI_ANALYSIS: "🤖 AI Analysis",
                    SecurityAction.TRACE_ATTACK: "🔍 Trace Attack",
                    SecurityAction.DETECT_TROJAN: "🦠 Detect Trojan",
                    SecurityAction.ISOLATE_FILE: "📁 Isolate File",
                    SecurityAction.DEEP_ANALYSIS: "🔬 Deep Analysis",
                    SecurityAction.QUARANTINE: "🏥 Quarantine",
                    SecurityAction.REMOVE_MALWARE: "🧹 Remove Malware",
                    SecurityAction.ANALYZE_ECOSYSTEM: "🌐 Analyze Ecosystem",
                    SecurityAction.CLEAN_TEMP: "🧹 Clean Temp Files"  # Додано
                }
                
                cb = ttk.Checkbutton(level_frame, text=action_descriptions[action], variable=var)
                cb.grid(row=row, column=col, sticky='w', padx=5, pady=1)
                
                col += 1
                if col >= max_cols:
                    col = 0
                    row += 1
            
            # Save button for this level
            def save_level_policy(level=level, action_vars=action_vars):
                selected_actions = [action for action, var in action_vars.items() if var.get()]
                self.security_policy.update_policy(level, selected_actions)
                messagebox.showinfo("Success", f"Policy updated for {level.value[3]} level")
            
            save_btn = ttk.Button(level_frame, text="💾 Save", 
                                command=lambda l=level, av=action_vars: save_level_policy(l, av))
            save_btn.grid(row=row+1, column=0, columnspan=max_cols, pady=5)
        
        # Global policy controls
        global_frame = ttk.LabelFrame(scrollable_frame, text="Global Policy Controls", padding=10)
        global_frame.pack(fill='x', padx=10, pady=5)
        
        button_frame = ttk.Frame(global_frame)
        button_frame.pack(fill='x')
        
        ttk.Button(button_frame, text="🔄 Reset", command=self.reset_security_policy).pack(side='left', padx=5)
        ttk.Button(button_frame, text="💾 Save All", command=self.save_all_policies).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📂 Load", command=self.load_security_policies).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📊 Report", command=self.show_policy_report).pack(side='left', padx=5)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def reset_security_policy(self):
        """Reset security policy to defaults"""
        if messagebox.askyesno("Reset Policy", "Are you sure you want to reset all security policies to defaults?"):
            self.security_policy = SecurityPolicy()
            messagebox.showinfo("Success", "Security policies reset to defaults")
    
    def save_all_policies(self):
        """Save all security policies"""
        try:
            self.security_policy.save_policy()
            messagebox.showinfo("Success", "All security policies saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save policies: {str(e)}")
    
    def load_security_policies(self):
        """Load security policies from file"""
        try:
            self.security_policy.load_policy()
            messagebox.showinfo("Success", "Security policies loaded successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load policies: {str(e)}")
    
    def show_policy_report(self):
        """Show security policy report"""
        report = "Security Policy Report\n" + "="*50 + "\n\n"
        
        for level in ThreatLevel:
            actions = self.security_policy.get_actions_for_level(level)
            report += f"{level.value[1]} {level.value[3]} ({level.value[0]}):\n"
            
            if actions:
                for action in actions:
                    report += f"  • {action.value}\n"
            else:
                report += f"  • No actions configured\n"
            
            report += "\n"
        
        # Show report in new window
        report_window = tk.Toplevel(self.root)
        report_window.title("Security Policy Report")
        report_window.geometry("500x400")
        
        text_widget = scrolledtext.ScrolledText(report_window, wrap=tk.WORD)
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', report)
        text_widget.config(state='disabled')

    def create_devices_tab(self):
        """Create devices monitoring tab"""
        devices_frame = ttk.Frame(self.notebook)
        self.notebook.add(devices_frame, text="🖥️ Devices")

        # Devices list
        devices_list_frame = ttk.LabelFrame(devices_frame, text="Connected Devices", padding=10)
        devices_list_frame.pack(fill='both', expand=True, padx=10, pady=5)

        columns = ('Name', 'Type', 'Vendor', 'Product', 'Serial/ID', 'Status')
        self.devices_tree = ttk.Treeview(devices_list_frame, columns=columns, show='headings', height=15)
        for col in columns:
            self.devices_tree.heading(col, text=col)
            self.devices_tree.column(col, width=140)
        devices_scrollbar = ttk.Scrollbar(devices_list_frame, orient='vertical', command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=devices_scrollbar.set)
        self.devices_tree.pack(side='left', fill='both', expand=True)
        devices_scrollbar.pack(side='right', fill='y')

        # Control buttons
        button_frame = ttk.Frame(devices_frame)
        button_frame.pack(fill='x', padx=10, pady=5)
        ttk.Button(button_frame, text="🔄 Refresh", command=self.refresh_devices).pack(side='left', padx=5)
        ttk.Button(button_frame, text="❌ Disconnect Device", command=self.disconnect_device).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🚫 Block New Devices", command=self.block_new_devices).pack(side='left', padx=5)

        # Initial load
        self.refresh_devices()

    def refresh_devices(self):
        """Refresh the list of connected devices"""
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        try:
            monitor = SecurityMonitor()
            sysinfo = monitor.get_system_info()
            devices = monitor.extract_devices(sysinfo)
            for dev_id, dev in devices.items():
                self.devices_tree.insert('', 'end', values=(
                    dev.get('name', 'Unknown'),
                    dev.get('type', 'Unknown'),
                    dev.get('vendor', dev.get('device_id', 'Unknown')),
                    dev.get('product', ''),
                    dev.get('serial', dev.get('device_id', '')),
                    'Connected' if dev.get('connected', True) else 'Disconnected'
                ))
        except Exception as e:
            self.devices_tree.insert('', 'end', values=(f'Error: {e}', '', '', '', '', ''))

    def disconnect_device(self):
        """Attempt to disconnect selected device (where possible)"""
        selection = self.devices_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a device")
            return
        dev_name = self.devices_tree.item(selection[0])['values'][0]
        dev_type = self.devices_tree.item(selection[0])['values'][1]
        # На MacOS відключення USB/Bluetooth програмно обмежене
        messagebox.showinfo("Disconnect Device", f"Disconnecting {dev_type} devices is not supported on macOS via user-space. Please physically disconnect the device or use system settings.")

    def block_new_devices(self):
        """Block new USB/Bluetooth devices (show instructions)"""
        msg = (
            "⚠️ Blocking new USB/Bluetooth devices on macOS потребує root-доступу та спеціальних розширень (наприклад, Endpoint Security, USBGuard для Linux).\n\n"
            "Для підвищення безпеки рекомендується:\n"
            "• Вимкнути USB-порти вручну (або фізично)\n"
            "• Вимкнути Bluetooth у системних налаштуваннях\n"
            "• Використовувати MDM/Endpoint Management для корпоративних Mac\n\n"
            "Автоматичне блокування буде доступне у майбутніх версіях."
        )
        messagebox.showinfo("Block New Devices", msg)

    def create_processes_tab(self):
        """Create processes monitoring tab"""
        processes_frame = ttk.Frame(self.notebook)
        self.notebook.add(processes_frame, text="⚙️ Processes")

        # Processes list
        processes_list_frame = ttk.LabelFrame(processes_frame, text="Running Processes", padding=10)
        processes_list_frame.pack(fill='both', expand=True, padx=10, pady=5)

        columns = ('PID', 'Name', 'User', 'CPU %', 'Memory %', 'Status', 'Path')
        self.processes_tree = ttk.Treeview(processes_list_frame, columns=columns, show='headings', height=15)
        for col in columns:
            self.processes_tree.heading(col, text=col)
            self.processes_tree.column(col, width=120)
        processes_scrollbar = ttk.Scrollbar(processes_list_frame, orient='vertical', command=self.processes_tree.yview)
        self.processes_tree.configure(yscrollcommand=processes_scrollbar.set)
        self.processes_tree.pack(side='left', fill='both', expand=True)
        processes_scrollbar.pack(side='right', fill='y')

        # Control buttons
        button_frame = ttk.Frame(processes_frame)
        button_frame.pack(fill='x', padx=10, pady=5)
        ttk.Button(button_frame, text="🔄 Refresh", command=self.refresh_processes).pack(side='left', padx=5)
        ttk.Button(button_frame, text="❌ Kill Process", command=self.kill_process).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🚫 Block Process", command=self.block_process).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🔍 Find Suspicious", command=self.find_suspicious_processes).pack(side='left', padx=5)

        # Initial load
        self.refresh_processes()

    def refresh_processes(self):
        """Refresh the list of running processes"""
        for item in self.processes_tree.get_children():
            self.processes_tree.delete(item)
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status', 'exe']):
                try:
                    proc_info = proc.info
                    if proc_info['pid'] and proc_info['name']:
                        processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
            for proc in processes[:100]:  # Show top 100 processes
                self.processes_tree.insert('', 'end', values=(
                    proc['pid'],
                    proc['name'][:20],
                    proc.get('username', 'Unknown')[:15],
                    f"{proc['cpu_percent']:.1f}" if proc['cpu_percent'] else "0.0",
                    f"{proc['memory_percent']:.1f}" if proc['memory_percent'] else "0.0",
                    proc.get('status', 'Unknown'),
                    proc.get('exe', 'Unknown')[:30] if proc.get('exe') else 'Unknown'
                ))
        except Exception as e:
            self.processes_tree.insert('', 'end', values=(f'Error: {e}', '', '', '', '', '', ''))

    def kill_process(self):
        """Kill selected process"""
        selection = self.processes_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a process")
            return
        pid = int(self.processes_tree.item(selection[0])['values'][0])
        name = self.processes_tree.item(selection[0])['values'][1]
        if messagebox.askyesno("Confirm", f"Kill process {name} (PID: {pid})?"):
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                self.log_message(f"✓ Killed process: {name} (PID: {pid})")
                self.refresh_processes()
            except Exception as e:
                self.log_message(f"❌ Failed to kill {name} (PID: {pid}): {e}")

    def block_process(self):
        """Block process from running (add to blacklist)"""
        selection = self.processes_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a process")
            return
        name = self.processes_tree.item(selection[0])['values'][1]
        # На macOS блокування процесів потребує root-доступу
        msg = (
            f"⚠️ Blocking process '{name}' on macOS потребує root-доступу та спеціальних розширень.\n\n"
            "Для підвищення безпеки рекомендується:\n"
            "• Використовувати Gatekeeper та SIP\n"
            "• Налаштувати Parental Controls\n"
            "• Використовувати MDM/Endpoint Management\n\n"
            "Автоматичне блокування буде доступне у майбутніх версіях."
        )
        messagebox.showinfo("Block Process", msg)

    def find_suspicious_processes(self):
        """Find and highlight suspicious processes"""
        suspicious = ['ssh', 'sshd', 'nc', 'netcat', 'ncat', 'socat', 'telnet', 'xmrig', 'ethminer']
        found = []
        for item in self.processes_tree.get_children():
            values = self.processes_tree.item(item)['values']
            name = values[1].lower()
            if any(susp in name for susp in suspicious):
                found.append(values)
                self.processes_tree.selection_add(item)
        if found:
            msg = f"Found {len(found)} suspicious processes:\n" + "\n".join([f"• {p[1]} (PID: {p[0]})" for p in found])
            messagebox.showwarning("Suspicious Processes", msg)
        else:
            messagebox.showinfo("Suspicious Processes", "No suspicious processes found.")

    def start_monitoring(self):
        """Start security monitoring"""
        try:
            # Start UI update cycle
            self.update_ui()
            
            # Initialize enhanced threat detection
            self.init_enhanced_threat_detection()
            
            self.log_message("Security monitoring started")
        except Exception as e:
            self.log_message(f"ERROR: Failed to start monitoring: {str(e)}")

    def show_automated_actions_report(self):
        """Show detailed report of automated actions taken by the system"""
        try:
            # Create automated actions report dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("🤖 Automated Actions Report")
            dialog.geometry("800x600")
            dialog.configure(bg='#2b2b2b')
            
            # Title
            title_frame = ttk.Frame(dialog)
            title_frame.pack(fill='x', padx=10, pady=5)
            
            ttk.Label(title_frame, text="🤖 Automated Security Actions", 
                     font=('Arial', 16, 'bold')).pack(side='left')
            
            # Statistics frame
            stats_frame = ttk.LabelFrame(dialog, text="Statistics", padding=10)
            stats_frame.pack(fill='x', padx=10, pady=5)
            
            stats_left = ttk.Frame(stats_frame)
            stats_left.pack(side='left', fill='both', expand=True)
            
            stats_right = ttk.Frame(stats_frame)
            stats_right.pack(side='right', fill='both', expand=True)
            
            # Left stats
            total_actions = len(self.automated_actions)
            ttk.Label(stats_left, text=f"Total Automated Actions: {total_actions}", 
                     font=('Arial', 10, 'bold')).pack(anchor='w')
            
            recurring_threats = sum(1 for count in self.threat_counters.values() if count >= 2)
            ttk.Label(stats_left, text=f"Recurring Threats Detected: {recurring_threats}").pack(anchor='w')
            
            # Right stats
            if self.last_automated_action:
                last_action_str = self.last_automated_action.strftime('%Y-%m-%d %H:%M:%S')
                ttk.Label(stats_right, text=f"Last Action: {last_action_str}").pack(anchor='w')
            else:
                ttk.Label(stats_right, text="Last Action: Never").pack(anchor='w')
            
            # Actions by type
            action_types = {}
            for action in self.automated_actions:
                action_type = action.get('threat_type', 'unknown')
                action_types[action_type] = action_types.get(action_type, 0) + 1
            
            ttk.Label(stats_right, text=f"Unique Threat Types: {len(action_types)}").pack(anchor='w')
            
            # Actions list
            list_frame = ttk.LabelFrame(dialog, text="Detailed Actions History", padding=10)
            list_frame.pack(fill='both', expand=True, padx=10, pady=5)
            
            # Create treeview for actions
            columns = ('Time', 'Type', 'Action', 'Target')
            actions_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
            
            # Configure columns
            actions_tree.heading('Time', text='Timestamp')
            actions_tree.heading('Type', text='Threat Type')
            actions_tree.heading('Action', text='Action Taken')
            actions_tree.heading('Target', text='Target/Details')
            
            actions_tree.column('Time', width=150)
            actions_tree.column('Type', width=200)
            actions_tree.column('Action', width=250)
            actions_tree.column('Target', width=200)
            
            # Scrollbar for treeview
            scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=actions_tree.yview)
            actions_tree.configure(yscrollcommand=scrollbar.set)
            
            actions_tree.pack(side='left', fill='both', expand=True)
            scrollbar.pack(side='right', fill='y')
            
            # Populate actions list (show most recent first)
            sorted_actions = sorted(self.automated_actions, key=lambda x: x['timestamp'], reverse=True)
            
            for action in sorted_actions:
                timestamp = action['timestamp'].strftime('%H:%M:%S')
                threat_type = action.get('threat_type', 'Unknown')
                action_taken = action.get('action', 'Unknown')
                
                # Extract target info
                threat_data = action.get('threat_data', {})
                target = ""
                if isinstance(threat_data, dict):
                    if 'port' in threat_data:
                        target = f"Port {threat_data['port']}"
                    elif 'remote_address' in threat_data:
                        target = f"IP {threat_data['remote_address']}"
                    elif 'type' in threat_data:
                        target = threat_data['type']
                    else:
                        target = str(threat_data)[:50]
                
                # Clean up threat type for display
                display_type = threat_type.replace('recurring_', '').replace('_', ' ').title()
                
                actions_tree.insert('', 'end', values=(timestamp, display_type, action_taken[:50], target))
            
            # Buttons frame
            buttons_frame = ttk.Frame(dialog)
            buttons_frame.pack(fill='x', padx=10, pady=5)
            
            def clear_actions_history():
                if messagebox.askyesno("Confirm", "Clear all automated actions history?"):
                    self.automated_actions.clear()
                    self.threat_counters.clear()
                    self.last_automated_action = None
                    dialog.destroy()
                    self.log_message("🗑️ Automated actions history cleared")
            
            def export_actions_report():
                try:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"nimda_automated_actions_{timestamp}.txt"
                    
                    with open(filename, 'w') as f:
                        f.write("=== NIMDA AUTOMATED ACTIONS REPORT ===\n")
                        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        f.write(f"Total Actions: {total_actions}\n")
                        f.write(f"Recurring Threats: {recurring_threats}\n\n")
                        
                        f.write("ACTIONS BY TYPE:\n")
                        for action_type, count in action_types.items():
                            f.write(f"  {action_type}: {count}\n")
                        f.write("\n")
                        
                        f.write("DETAILED ACTIONS:\n")
                        for action in sorted_actions:
                            f.write(f"[{action['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}] ")
                            f.write(f"{action.get('threat_type', 'Unknown')}: ")
                            f.write(f"{action.get('action', 'Unknown')}\n")
                            if action.get('threat_data'):
                                f.write(f"  Details: {action['threat_data']}\n")
                            f.write("\n")
                    
                    messagebox.showinfo("Export Complete", f"Report saved as: {filename}")
                    
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export report: {e}")
            
            def refresh_display():
                dialog.destroy()
                self.show_automated_actions_report()
            
            ttk.Button(buttons_frame, text="🔄 Refresh", command=refresh_display).pack(side='left', padx=5)
            ttk.Button(buttons_frame, text="📄 Export Report", command=export_actions_report).pack(side='left', padx=5)
            ttk.Button(buttons_frame, text="🗑️ Clear History", command=clear_actions_history).pack(side='left', padx=5)
            ttk.Button(buttons_frame, text="❌ Close", command=dialog.destroy).pack(side='right', padx=5)
            
            # If no actions yet, show helpful message
            if not self.automated_actions:
                no_actions_frame = ttk.Frame(list_frame)
                no_actions_frame.pack(fill='both', expand=True)
                
                ttk.Label(no_actions_frame, text="🤖 No automated actions have been taken yet.", 
                         font=('Arial', 12), justify='center').pack(expand=True)
                ttk.Label(no_actions_frame, text="The system will automatically respond to recurring threats\n"
                                                "when they are detected multiple times.", 
                         justify='center').pack(expand=True)
            
        except Exception as e:
            self.log_message(f"❌ Failed to show automated actions report: {e}")
            messagebox.showerror("Error", f"Failed to show automated actions report: {e}")

    def enhance_automated_response_system(self):
        """Enhance the automated response system with more intelligent actions"""
        try:
            # Add more sophisticated threat pattern recognition
            current_time = datetime.now()
            
            # Check for coordinated attacks (multiple threat types from same source)
            threat_sources = {}
            
            # Analyze recent threats by source
            for threat_key, count in self.threat_counters.items():
                if count >= 2:  # Recurring threat
                    # Extract source information
                    source = None
                    if ':' in threat_key:  # IP-based threats
                        source = threat_key.split(':')[0]
                    elif 'port_' in threat_key:  # Port-based threats
                        source = f"port_{threat_key.split('_')[1]}"
                    elif 'anomaly_' in threat_key:  # Anomaly-based threats
                        source = "system_anomaly"
                    
                    if source:
                        if source not in threat_sources:
                            threat_sources[source] = []
                        threat_sources[source].append(threat_key)
            
            # Take enhanced actions for coordinated attacks
            for source, threats in threat_sources.items():
                if len(threats) >= 3:  # Multiple threat types from same source
                    self.take_coordinated_attack_action(source, threats)
            
            # Implement time-based threat escalation
            self.implement_threat_escalation()
            
            # Add predictive threat blocking
            self.implement_predictive_blocking()
            
        except Exception as e:
            print(f"Error enhancing automated response: {e}")

    def take_coordinated_attack_action(self, source, threat_keys):
        """Take action against coordinated attacks from a single source"""
        try:
            action_description = f"Coordinated attack detected from {source} - {len(threat_keys)} threat types"
            
            # More aggressive response for coordinated attacks
            if source.startswith('port_'):
                port_num = source.split('_')[1]
                self.implement_port_quarantine(port_num)
                action_description += f". Port {port_num} quarantined."
            elif '.' in source:  # IP address
                self.implement_ip_complete_ban(source)
                action_description += f". IP {source} completely banned."
            else:
                self.implement_system_lockdown_mode()
                action_description += ". System lockdown mode activated."
            
            # Log coordinated attack response
            self.automated_actions.append({
                'timestamp': datetime.now(),
                'threat_key': f"coordinated_{source}",
                'threat_type': 'coordinated_attack',
                'action': action_description,
                'threat_data': {'source': source, 'threat_count': len(threat_keys)}
            })
            
            self.add_action_to_log(f"🚨 COORDINATED ATTACK: {action_description}\n")
            
        except Exception as e:
            print(f"Error taking coordinated attack action: {e}")

    def implement_threat_escalation(self):
        """Implement time-based threat escalation"""
        try:
            current_time = datetime.now()
            
            for threat_key, count in self.threat_counters.items():
                # Check for rapid escalation (multiple occurrences in short time)
                if count >= 5:  # High frequency threat
                    # Implement immediate response escalation
                    escalation_action = f"High-frequency threat escalation for {threat_key}"
                    
                    # Take immediate blocking action
                    if 'port_' in threat_key:
                        port_num = threat_key.split('_')[1]
                        self.emergency_port_shutdown(port_num)
                        escalation_action += f". Emergency port {port_num} shutdown."
                    elif ':' in threat_key:  # IP-based
                        ip_addr = threat_key.split(':')[0]
                        self.emergency_ip_block(ip_addr)
                        escalation_action += f". Emergency IP {ip_addr} block."
                    
                    # Log escalation
                    self.automated_actions.append({
                        'timestamp': current_time,
                        'threat_key': f"escalation_{threat_key}",
                        'threat_type': 'threat_escalation',
                        'action': escalation_action,
                        'threat_data': {'original_threat': threat_key, 'frequency': count}
                    })
                    
                    self.add_action_to_log(f"🚨 ESCALATION: {escalation_action}\n")
                    
                    # Reset counter after escalation
                    self.threat_counters[threat_key] = 0
            
        except Exception as e:
            print(f"Error implementing threat escalation: {e}")

    def implement_predictive_blocking(self):
        """Implement predictive threat blocking based on patterns"""
        try:
            # Analyze threat patterns for prediction
            threat_patterns = {}
            
            # Group threats by type and look for patterns
            for action in self.automated_actions[-20:]:  # Look at last 20 actions
                threat_type = action.get('threat_type', '')
                threat_data = action.get('threat_data', {})
                
                if threat_type not in threat_patterns:
                    threat_patterns[threat_type] = []
                threat_patterns[threat_type].append(threat_data)
            
            # Predict and pre-emptively block similar threats
            for threat_type, patterns in threat_patterns.items():
                if len(patterns) >= 3:  # Pattern detected
                    self.implement_preemptive_blocking(threat_type, patterns)
            
        except Exception as e:
            print(f"Error implementing predictive blocking: {e}")

    def implement_preemptive_blocking(self, threat_type, patterns):
        """Implement pre-emptive blocking based on detected patterns"""
        try:
            prediction_action = f"Predictive blocking for {threat_type} pattern"
            
            # Analyze patterns and create preventive rules
            if 'port' in threat_type and patterns:
                # Block similar port ranges
                ports = [p.get('port') for p in patterns if isinstance(p, dict) and 'port' in p]
                if ports:
                    port_ranges = self.identify_port_ranges(ports)
                    for port_range in port_ranges:
                        self.preemptive_port_block(port_range)
                    prediction_action += f". Blocked port ranges: {port_ranges}"
            
            elif 'connection' in threat_type and patterns:
                # Block similar IP ranges
                ips = [p.get('remote_address') for p in patterns if isinstance(p, dict) and 'remote_address' in p]
                if ips:
                    ip_ranges = self.identify_ip_ranges(ips)
                    for ip_range in ip_ranges:
                        self.preemptive_ip_block(ip_range)
                    prediction_action += f". Blocked IP ranges: {ip_ranges}"
            
            # Log predictive action
            self.automated_actions.append({
                'timestamp': datetime.now(),
                'threat_key': f"predictive_{threat_type}",
                'threat_type': 'predictive_blocking',
                'action': prediction_action,
                'threat_data': {'pattern_type': threat_type, 'pattern_count': len(patterns)}
            })
            
            self.add_action_to_log(f"🔮 PREDICTIVE: {prediction_action}\n")
            
        except Exception as e:
            print(f"Error implementing preemptive blocking: {e}")

    def identify_port_ranges(self, ports):
        """Identify potentially dangerous port ranges from attack patterns"""
        try:
            ranges = []
            sorted_ports = sorted([int(p) for p in ports if str(p).isdigit()])
            
            if len(sorted_ports) >= 2:
                min_port = min(sorted_ports)
                max_port = max(sorted_ports)
                
                # Create range around detected ports
                start_range = max(min_port - 10, 1)
                end_range = min(max_port + 10, 65535)
                ranges.append(f"{start_range}-{end_range}")
            
            return ranges
        except:
            return []

    def identify_ip_ranges(self, ips):
        """Identify potentially dangerous IP ranges from attack patterns"""
        try:
            ranges = []
            ip_parts = []
            
            for ip in ips:
                if ip and '.' in str(ip):
                    parts = str(ip).split('.')
                    if len(parts) == 4:
                        ip_parts.append(parts)
            
            if len(ip_parts) >= 2:
                # Find common subnet
                common_parts = []
                for i in range(3):  # First 3 octets
                    values = set(parts[i] for parts in ip_parts)
                    if len(values) == 1:
                        common_parts.append(list(values)[0])
                    else:
                        break
                
                if len(common_parts) >= 2:
                    subnet = '.'.join(common_parts + ['0'] * (3 - len(common_parts))) + '/24'
                    ranges.append(subnet)
            
            return ranges
        except:
            return []

    def emergency_port_shutdown(self, port_num):
        """Emergency shutdown of a specific port"""
        try:
            # More aggressive port blocking
            if platform.system() == "Darwin":
                subprocess.run(['sudo', 'pfctl', '-t', 'nimda_emergency', '-T', 'add', f'0.0.0.0/0 port {port_num}'], timeout=5)
            elif platform.system() == "Linux":
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port_num), '-j', 'REJECT'], timeout=5)
                subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', str(port_num), '-j', 'REJECT'], timeout=5)
        except:
            pass

    def emergency_ip_block(self, ip_addr):
        """Emergency blocking of an IP address"""
        try:
            # More aggressive IP blocking
            if platform.system() == "Darwin":
                subprocess.run(['sudo', 'pfctl', '-t', 'nimda_emergency', '-T', 'add', ip_addr], timeout=5)
            elif platform.system() == "Linux":
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_addr, '-j', 'REJECT'], timeout=5)
                subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip_addr, '-j', 'REJECT'], timeout=5)
        except:
            pass
    
    def trigger_sound_alert(self, threat_level: ThreatLevel, target: str = ""):
        """Trigger sound alert for threat level"""
        try:
            print(f"🔊 ЗВУК: Отримано запит на звук для {threat_level} - {target}")
            
            # Map ThreatLevel to SoundThreatLevel
            sound_level_mapping = {
                ThreatLevel.LOW: SoundThreatLevel.LOW,
                ThreatLevel.MEDIUM: SoundThreatLevel.MEDIUM,
                ThreatLevel.HIGH: SoundThreatLevel.HIGH,
                ThreatLevel.CRITICAL: SoundThreatLevel.CRITICAL,
                ThreatLevel.EMERGENCY: SoundThreatLevel.EMERGENCY
            }
            
            sound_level = sound_level_mapping.get(threat_level, SoundThreatLevel.MEDIUM)
            print(f"🔊 ЗВУК: Мапинг {threat_level} -> {sound_level}")
            
            if hasattr(self, 'sound_system') and self.sound_system:
                print(f"🔊 ЗВУК: Викликаємо play_threat_alert({sound_level}, {target})")
                self.sound_system.play_threat_alert(sound_level, target)
                print(f"🔊 ЗВУК: play_threat_alert викликано успішно")
            else:
                print(f"❌ ЗВУК: sound_system недоступний")
            
        except Exception as e:
            print(f"❌ Sound alert error: {e}")
            import traceback
            traceback.print_exc()
    
    def trigger_pattern_alert(self, pattern_name: str, target: str = ""):
        """Trigger pattern alert for specific events"""
        try:
            self.sound_system.play_alert_pattern(pattern_name, target)
        except Exception as e:
            print(f"Pattern alert error: {e}")
    
    def test_sound_system(self):
        """Comprehensive test of the sound alert system"""
        try:
            print("🔊 Starting comprehensive sound system test...")
            
            # Test basic sound system
            if hasattr(self, 'sound_system') and self.sound_system:
                print("✅ Sound system available")
                
                # Test all threat levels
                threat_levels = [
                    (ThreatLevel.LOW, "Low Priority Test"),
                    (ThreatLevel.MEDIUM, "Medium Priority Test"),
                    (ThreatLevel.HIGH, "High Priority Test"),
                    (ThreatLevel.CRITICAL, "Critical Priority Test"),
                    (ThreatLevel.EMERGENCY, "Emergency Priority Test")
                ]
                
                for level, description in threat_levels:
                    print(f"🎵 Testing {level.name} level...")
                    self.trigger_sound_alert(level, description)
                    time.sleep(1)  # Pause between tests
                
                # Test the built-in test suite
                self.sound_system.test_sounds()
                
                # Add to actions log
                self.add_action_to_log("🔊 Sound System Test", "All threat level sounds tested successfully")
                
                messagebox.showinfo("Sound Test Complete", 
                    "Sound system test completed!\n\n"
                    "You should have heard 5 different sounds:\n"
                    "• Low: Gentle ping\n"
                    "• Medium: Warning tone\n" 
                    "• High: Alert sound\n"
                    "• Critical: Urgent tone\n"
                    "• Emergency: Alarm sound\n\n"
                    "If you didn't hear sounds, check your volume settings.")
                
            else:
                print("❌ Sound system not available")
                messagebox.showerror("Sound Test Error", "Sound system not initialized!")
                
        except Exception as e:
            print(f"❌ Sound test error: {e}")
            messagebox.showerror("Sound Test Error", f"Failed to test sound system: {e}")
    
    def toggle_sound_alerts(self):
        """Toggle sound alerts on/off"""
        if self.sound_system.enabled:
            self.sound_system.disable()
            messagebox.showinfo("Sound Alerts", "Sound alerts disabled")
        else:
            self.sound_system.enable()
            messagebox.showinfo("Sound Alerts", "Sound alerts enabled")
    
    def show_sound_settings(self):
        """Show sound settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Sound Alert Settings")
        settings_window.geometry("400x300")
        settings_window.configure(bg='#2b2b2b')
        
        # Apply dark theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')
        style.configure('TButton', background='#404040', foreground='#ffffff')
        style.configure('TCheckbutton', background='#2b2b2b', foreground='#ffffff')
        
        # Settings frame
        settings_frame = ttk.LabelFrame(settings_window, text="Sound Alert Settings", padding=10)
        settings_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Enable/disable sound
        sound_var = tk.BooleanVar(value=self.sound_system.enabled)
        ttk.Checkbutton(settings_frame, text="Enable Sound Alerts", variable=sound_var).pack(anchor='w', pady=5)
        
        # Volume control
        volume_frame = ttk.Frame(settings_frame)
        volume_frame.pack(fill='x', pady=5)
        ttk.Label(volume_frame, text="Volume:").pack(side='left')
        volume_scale = ttk.Scale(volume_frame, from_=0.0, to=1.0, value=self.sound_system.volume, 
                                orient='horizontal', command=lambda v: setattr(self.sound_system, 'volume', float(v)))
        volume_scale.pack(side='left', fill='x', expand=True, padx=5)
        
        # Cooldown control
        cooldown_frame = ttk.Frame(settings_frame)
        cooldown_frame.pack(fill='x', pady=5)
        ttk.Label(cooldown_frame, text="Alert Cooldown (seconds):").pack(side='left')
        cooldown_var = tk.StringVar(value=str(self.sound_system.alert_cooldown))
        cooldown_entry = ttk.Entry(cooldown_frame, textvariable=cooldown_var, width=10)
        cooldown_entry.pack(side='left', padx=5)
        
        # Buttons
        button_frame = ttk.Frame(settings_frame)
        button_frame.pack(fill='x', pady=10)
        
        ttk.Button(button_frame, text="Test Sounds", command=self.test_sound_system).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Save Settings", 
                  command=lambda: self.save_sound_settings(sound_var.get(), float(cooldown_var.get()), settings_window)).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=settings_window.destroy).pack(side='right', padx=5)
    
    def save_sound_settings(self, enabled: bool, cooldown: float, window):
        """Save sound settings"""
        self.sound_system.enabled = enabled
        self.sound_system.alert_cooldown = cooldown
        messagebox.showinfo("Settings Saved", "Sound alert settings saved successfully!")
        window.destroy()
    
    def show_privilege_dialog(self, title: str = "Root Privileges Required"):
        """Show dialog to request root privileges"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x250")
        dialog.configure(bg='#2b2b2b')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        # Apply dark theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')
        style.configure('TButton', background='#404040', foreground='#ffffff')
        style.configure('TEntry', fieldbackground='#404040', foreground='#ffffff')
        
        # Main frame
        main_frame = ttk.Frame(dialog, padding=20)
        main_frame.pack(fill='both', expand=True)
        
        # Status info
        status = self.privilege_manager.get_privilege_status()
        if status['has_privileges'] and status['privileges_valid']:
            status_text = f"✅ Privileges active (expires in {int(status['time_remaining'])}s)"
        elif status['credentials_stored']:
            status_text = "🔐 Credentials stored - enter password to activate"
        else:
            status_text = "🔑 No credentials stored - enter password to setup"
        
        ttk.Label(main_frame, text=status_text, font=('Arial', 10, 'bold')).pack(pady=10)
        
        # Password entry
        ttk.Label(main_frame, text="Enter your password:").pack(anchor='w', pady=5)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=password_var, show="*", width=40)
        password_entry.pack(fill='x', pady=5)
        password_entry.focus()
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=20)
        
        def submit_password():
            password = password_var.get()
            if not password:
                messagebox.showerror("Error", "Please enter a password")
                return
            
            if self.privilege_manager.request_privileges(password):
                if self.privilege_manager.test_privileges():
                    messagebox.showinfo("Success", "Root privileges activated successfully!")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to verify privileges. Check your password.")
            else:
                messagebox.showerror("Error", "Invalid password")
        
        def cancel():
            dialog.destroy()
        
        ttk.Button(button_frame, text="Activate", command=submit_password).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side='right', padx=5)
        
        # Bind Enter key
        password_entry.bind('<Return>', lambda e: submit_password())
        
        # Wait for dialog to close
        dialog.wait_window()
        return self.privilege_manager.check_privileges()
    
    def check_privileges_required(self, operation: str = "this operation") -> bool:
        """Check if privileges are required and available"""
        if not self.privilege_manager.check_privileges():
            result = messagebox.askyesno("Privileges Required", 
                                       f"Root privileges are required for {operation}.\n\n"
                                       "Would you like to enter your password now?")
            if result:
                return self.show_privilege_dialog(f"Privileges for {operation}")
            return False
        return True
    
    def execute_privileged_command(self, command: str, description: str = "") -> Tuple[bool, str]:
        """Execute command with privileges"""
        if not self.check_privileges_required(description):
            return False, "Privileges not available"
        
        return self.privilege_manager.execute_with_privileges(command, require_privileges=True)
    
    def show_privilege_status(self):
        """Show current privilege status"""
        status = self.privilege_manager.get_privilege_status()
        
        status_window = tk.Toplevel(self.root)
        status_window.title("Privilege Status")
        status_window.geometry("400x300")
        status_window.configure(bg='#2b2b2b')
        
        # Apply dark theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#2b2b2b', foreground='#ffffff')
        style.configure('TButton', background='#404040', foreground='#ffffff')
        
        # Status frame
        status_frame = ttk.LabelFrame(status_window, text="Current Status", padding=15)
        status_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Status information
        info_text = f"""
Privileges Active: {'✅ Yes' if status['privileges_valid'] else '❌ No'}
Credentials Stored: {'✅ Yes' if status['credentials_stored'] else '❌ No'}
Time Remaining: {int(status['time_remaining'])} seconds
        """
        
        ttk.Label(status_frame, text=info_text, justify='left').pack(anchor='w')
        
        # Buttons
        button_frame = ttk.Frame(status_frame)
        button_frame.pack(fill='x', pady=15)
        
        ttk.Button(button_frame, text="Request Privileges", 
                  command=lambda: [status_window.destroy(), self.show_privilege_dialog()]).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Revoke Privileges", 
                  command=lambda: [self.privilege_manager.revoke_privileges(), status_window.destroy()]).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Close", command=status_window.destroy).pack(side='right', padx=5)
    
    def update_privilege_indicator(self):
        """Update privilege indicator in status bar"""
        if hasattr(self, 'privilege_indicator'):
            status = self.privilege_manager.get_privilege_status()
            if status['privileges_valid']:
                self.privilege_indicator.config(text="🔓")
            elif status['credentials_stored']:
                self.privilege_indicator.config(text="🔐")
            else:
                self.privilege_indicator.config(text="🔒")

class PrivilegeManager:
    """Manage root privileges and secure storage of passwords/keys"""
    
    def __init__(self):
        self.service_name = "NIMDA_Security_System"
        # Use current user instead of "admin"
        self.username = os.getenv('USER', 'dev')  # Get current user
        self.has_privileges = False
        self.privilege_timeout = 300  # 5 minutes
        self.privilege_start_time = None
        
        # Try to load existing credentials
        self.load_credentials()
    
    def load_credentials(self):
        """Load stored credentials from secure storage"""
        try:
            stored_key = keyring.get_password(self.service_name, self.username)
            if stored_key:
                self.stored_key_hash = stored_key
                return True
        except Exception as e:
            print(f"Failed to load credentials: {e}")
        return False
    
    def store_credentials(self, password: str):
        """Store credentials securely"""
        try:
            # Hash the password before storing
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            keyring.set_password(self.service_name, self.username, password_hash)
            self.stored_key_hash = password_hash
            return True
        except Exception as e:
            print(f"Failed to store credentials: {e}")
            return False
    
    def verify_credentials(self, password: str) -> bool:
        """Verify provided credentials by testing sudo access"""
        try:
            # Test sudo access with the provided password
            test_command = "echo 'test'"
            
            # Ensure password is string and encode properly
            if isinstance(password, bytes):
                password_str = password.decode('utf-8')
            else:
                password_str = str(password)
            
            result = subprocess.run(['sudo', '-S', 'sh', '-c', test_command], 
                                  input=password_str.encode('utf-8'), 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=10)
            
            if result.returncode == 0:
                print("✅ Credentials verified successfully")
                return True
            else:
                print(f"❌ Credentials verification failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print("❌ Credentials verification timed out")
            return False
        except Exception as e:
            print(f"❌ Credentials verification error: {e}")
            return False
    
    def request_privileges(self, password: str) -> bool:
        """Request root privileges with password verification"""
        if self.verify_credentials(password):
            self.has_privileges = True
            self.privilege_start_time = time.time()
            
            # Store credentials if not already stored
            if not hasattr(self, 'stored_key_hash'):
                self.store_credentials(password)
            
            return True
        return False
    
    def check_privileges(self) -> bool:
        """Check if privileges are still valid"""
        if not self.has_privileges:
            return False
        
        # Check timeout
        if self.privilege_start_time and time.time() - self.privilege_start_time > self.privilege_timeout:
            self.has_privileges = False
            return False
        
        return True
    
    def revoke_privileges(self):
        """Revoke current privileges"""
        self.has_privileges = False
        self.privilege_start_time = None
    
    def execute_with_privileges(self, command: str, require_privileges: bool = True) -> Tuple[bool, str]:
        """Execute command with privileges if required"""
        if require_privileges and not self.check_privileges():
            return False, "Privileges required but not available"
        
        try:
            if require_privileges:
                # Use sudo with current user for privileged commands
                # The password should already be cached by sudo
                result = subprocess.run(['sudo', '-n'] + command.split(), 
                                      capture_output=True, text=True, timeout=30)
            else:
                # Execute without privileges
                result = subprocess.run(command.split(), 
                                      capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    def test_privileges(self) -> bool:
        """Test if current privileges work"""
        success, output = self.execute_with_privileges("whoami", require_privileges=True)
        return success and "root" in output
    
    def get_privilege_status(self) -> Dict:
        """Get current privilege status"""
        return {
            'has_privileges': self.has_privileges,
            'privileges_valid': self.check_privileges(),
            'time_remaining': max(0, self.privilege_timeout - (time.time() - self.privilege_start_time)) if self.privilege_start_time else 0,
            'credentials_stored': hasattr(self, 'stored_key_hash')
        }

def main():
    """Main application entry point"""
    root = tk.Tk()
    app = NIMDATkinterApp(root)
    
    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main() 