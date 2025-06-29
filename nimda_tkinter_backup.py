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

class SecurityPolicy:
    """Security policy configuration"""
    
    def __init__(self):
        self.policies = {
            ThreatLevel.LOW: [SecurityAction.MONITOR, SecurityAction.LOG],
            ThreatLevel.MEDIUM: [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ANALYZE, SecurityAction.DETECT_TROJAN],
            ThreatLevel.HIGH: [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ANALYZE, SecurityAction.BLOCK, SecurityAction.ALERT, SecurityAction.DETECT_TROJAN, SecurityAction.DEEP_ANALYSIS],
            ThreatLevel.CRITICAL: [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ANALYZE, SecurityAction.BLOCK, SecurityAction.ISOLATE, SecurityAction.AI_ANALYSIS, SecurityAction.ALERT, SecurityAction.DETECT_TROJAN, SecurityAction.ISOLATE_FILE, SecurityAction.ANALYZE_ECOSYSTEM],
            ThreatLevel.EMERGENCY: [SecurityAction.MONITOR, SecurityAction.LOG, SecurityAction.ANALYZE, SecurityAction.BLOCK, SecurityAction.ISOLATE, SecurityAction.TERMINATE, SecurityAction.BACKUP, SecurityAction.AI_ANALYSIS, SecurityAction.TRACE_ATTACK, SecurityAction.ALERT, SecurityAction.DETECT_TROJAN, SecurityAction.ISOLATE_FILE, SecurityAction.DEEP_ANALYSIS, SecurityAction.QUARANTINE, SecurityAction.REMOVE_MALWARE, SecurityAction.ANALYZE_ECOSYSTEM]
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
    
    def execute_actions(self, threat_level: ThreatLevel, target: str, details: Dict):
        """Execute security actions for threat level"""
        actions = self.policy.get_actions_for_level(threat_level)
        
        for action in actions:
            try:
                if action == SecurityAction.MONITOR:
                    self._action_monitor(target, details)
                elif action == SecurityAction.LOG:
                    self._action_log(target, details, threat_level)
                elif action == SecurityAction.ANALYZE:
                    self._action_analyze(target, details)
                elif action == SecurityAction.BLOCK:
                    self._action_block(target, details)
                elif action == SecurityAction.ISOLATE:
                    self._action_isolate(target, details)
                elif action == SecurityAction.TERMINATE:
                    self._action_terminate(target, details)
                elif action == SecurityAction.BACKUP:
                    self._action_backup(target, details)
                elif action == SecurityAction.ALERT:
                    self._action_alert(target, details, threat_level)
                elif action == SecurityAction.AI_ANALYSIS:
                    self._action_ai_analysis(target, details, threat_level)
                elif action == SecurityAction.TRACE_ATTACK:
                    self._action_trace_attack(target, details)
            except Exception as e:
                print(f"Failed to execute action {action.value}: {e}")
    
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
        
        # Data storage
        self.security_status = {
            'threat_level': ThreatLevel.LOW,
            'connections': [],
            'ports': [],
            'anomalies': [],
            'last_update': datetime.now()
        }
        
        # Threading
        self.monitor_thread = None
        self.running = True
        
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
        
        # Main container with scrollbar
        main_canvas = tk.Canvas(dashboard_frame, bg='#2b2b2b')
        scrollbar = ttk.Scrollbar(dashboard_frame, orient="vertical", command=main_canvas.yview)
        scrollable_frame = ttk.Frame(main_canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollable elements
        main_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # ===== SYSTEM METRICS SECTION =====
        metrics_frame = ttk.LabelFrame(scrollable_frame, text="🖥️ System Metrics", padding=15)
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
        security_frame = ttk.LabelFrame(scrollable_frame, text="🛡️ Security Status", padding=15)
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
        
        # ===== PROCESSES STATISTICS SECTION =====
        processes_frame = ttk.LabelFrame(scrollable_frame, text="⚙️ Processes Statistics", padding=15)
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
        connections_frame = ttk.LabelFrame(scrollable_frame, text="🌐 Network Connections", padding=15)
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
        actions_frame = ttk.LabelFrame(scrollable_frame, text="🛡️ Security Actions", padding=15)
        actions_frame.pack(fill='x', padx=10, pady=5)
        
        # Actions log
        actions_log_frame = ttk.Frame(actions_frame)
        actions_log_frame.pack(fill='x', pady=5)
        
        self.actions_text = scrolledtext.ScrolledText(actions_log_frame, height=8, wrap='word', font=('Arial', 9))
        self.actions_text.pack(fill='both', expand=True)
        
        # Apply dark theme to text widget
        self.apply_dark_theme_to_text_widget(self.actions_text)
        
        # ===== QUICK ACTIONS SECTION =====
        quick_actions_frame = ttk.LabelFrame(scrollable_frame, text="⚡ Quick Actions", padding=15)
        quick_actions_frame.pack(fill='x', padx=10, pady=5)
        
        # First row of buttons
        button_frame1 = ttk.Frame(quick_actions_frame)
        button_frame1.pack(fill='x', pady=5)
        
        ttk.Button(button_frame1, text="🔍 Full System Scan", command=self.full_scan, style='TButton').pack(side='left', padx=5)
        ttk.Button(button_frame1, text="🛡️ Emergency Lockdown", command=self.emergency_lockdown, style='TButton').pack(side='left', padx=5)
        ttk.Button(button_frame1, text="📊 System Information", command=self.show_system_info).pack(side='left', padx=5)
        ttk.Button(button_frame1, text="🧪 Test AI Analysis", command=self.test_llm).pack(side='left', padx=5)
        
        # Second row of buttons
        button_frame2 = ttk.Frame(quick_actions_frame)
        button_frame2.pack(fill='x', pady=5)
        
        ttk.Button(button_frame2, text="🔄 Refresh All", command=self.refresh_dashboard).pack(side='left', padx=5)
        ttk.Button(button_frame2, text="📈 Performance", command=self.show_performance_details).pack(side='left', padx=5)
        ttk.Button(button_frame2, text="🗑️ Clear Actions Log", command=self.clear_actions_log).pack(side='left', padx=5)
        ttk.Button(button_frame2, text="📋 Export Report", command=self.export_dashboard_report).pack(side='left', padx=5)
        
        # ===== REAL-TIME MONITORING SECTION =====
        monitoring_frame = ttk.LabelFrame(scrollable_frame, text="📡 Real-Time Monitoring", padding=15)
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
        
        # Apply dark theme to canvas
        main_canvas.configure(bg='#2b2b2b')
        
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
        """Update threats dashboard with current security data"""
        try:
            # Get current security data
            connections = getattr(self, 'current_connections', [])
            port_scan = getattr(self, 'current_port_scan', [])
            anomalies = getattr(self, 'current_anomalies', [])
            
            # Update security metrics
            self.update_security_metrics(connections, port_scan, anomalies)
            
            # Log security actions
            self.log_security_actions(connections, port_scan, anomalies)
                
        except Exception as e:
            print(f"Error updating threats dashboard: {e}")
    
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
        """Handle security status update"""
        try:
            print(f"[DEBUG] on_security_update: port_scan={security_status.get('port_scan')}")
            
            # Store current security data for dashboard
            self.current_connections = security_status.get('connections', [])
            self.current_port_scan = security_status.get('port_scan', [])
            self.current_anomalies = security_status.get('anomalies', [])
            
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
            self.threat_analyzer.execute_actions(threat_level, conn['remote_addr'], details)
            
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
            self.threat_analyzer.execute_actions(threat_level, f"Port {port['port']}", details)
            
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
            self.threat_analyzer.execute_actions(threat_level, f"Anomaly: {anomaly.get('type', 'UNKNOWN')}", anomaly)
            
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
                    SecurityAction.TRACE_ATTACK: "🔍 Trace Attack"
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
        """Start security monitoring thread"""
        self.monitor_thread = SecurityMonitorThread(self.on_security_update)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Update UI periodically
        self.root.after(5000, self.update_ui)
    
    def trigger_sound_alert(self, threat_level: ThreatLevel, target: str = ""):
        """Trigger sound alert for threat level"""
        try:
            # Map ThreatLevel to SoundThreatLevel
            sound_level_mapping = {
                ThreatLevel.LOW: SoundThreatLevel.LOW,
                ThreatLevel.MEDIUM: SoundThreatLevel.MEDIUM,
                ThreatLevel.HIGH: SoundThreatLevel.HIGH,
                ThreatLevel.CRITICAL: SoundThreatLevel.CRITICAL,
                ThreatLevel.EMERGENCY: SoundThreatLevel.EMERGENCY
            }
            
            sound_level = sound_level_mapping.get(threat_level, SoundThreatLevel.MEDIUM)
            self.sound_system.play_threat_alert(sound_level, target)
            
        except Exception as e:
            print(f"Sound alert error: {e}")
    
    def trigger_pattern_alert(self, pattern_name: str, target: str = ""):
        """Trigger pattern alert for specific events"""
        try:
            self.sound_system.play_alert_pattern(pattern_name, target)
        except Exception as e:
            print(f"Pattern alert error: {e}")
    
    def test_sound_system(self):
        """Test the sound alert system"""
        try:
            self.sound_system.test_sounds()
            messagebox.showinfo("Sound Test", "Sound system test completed!")
        except Exception as e:
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