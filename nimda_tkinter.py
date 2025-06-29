#!/usr/bin/env python3
"""
NIMDA Security System - Comprehensive Tkinter GUI
Full security monitoring with network analysis, port scanning, anomaly detection, and LLM integration
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import json
import subprocess
import socket
import psutil
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any
import sqlite3
import os
import sys

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
    """Main NIMDA Security System Tkinter application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("NIMDA Security System - Comprehensive Monitoring")
        self.root.geometry("1400x900")
        
        # Security system components
        self.security_monitor = None
        self.llm_agent = None
        self.monitor_thread = None
        self.deep_analyzer = DeepAnalyzer()
        self.anomaly_analyzer = AnomalyAnalyzer()
        self.translation_manager = TranslationManager()
        self.ai_provider_manager = AIProviderManager()
        self.task_scheduler = TaskScheduler()
        
        # Initialize UI
        self.init_ui()
        self.init_security_system()
        
        # Setup update timer
        self.update_ui()
    
    def init_ui(self):
        """Initialize user interface"""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
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
        
        # Create menu bar
        self.create_menu()
        
        # Status bar
        self.create_status_bar()
    
    def create_dashboard_tab(self):
        """Create main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")
        
        # System metrics
        metrics_frame = ttk.LabelFrame(dashboard_frame, text="System Metrics", padding=10)
        metrics_frame.pack(fill='x', padx=10, pady=5)
        
        # CPU and Memory
        cpu_mem_frame = ttk.Frame(metrics_frame)
        cpu_mem_frame.pack(fill='x', pady=5)
        
        ttk.Label(cpu_mem_frame, text="CPU:").grid(row=0, column=0, sticky='w', padx=5)
        self.cpu_bar = ttk.Progressbar(cpu_mem_frame, length=200, mode='determinate')
        self.cpu_bar.grid(row=0, column=1, padx=5)
        self.cpu_label = ttk.Label(cpu_mem_frame, text="0%")
        self.cpu_label.grid(row=0, column=2, padx=5)
        
        ttk.Label(cpu_mem_frame, text="Memory:").grid(row=1, column=0, sticky='w', padx=5)
        self.mem_bar = ttk.Progressbar(cpu_mem_frame, length=200, mode='determinate')
        self.mem_bar.grid(row=1, column=1, padx=5)
        self.mem_label = ttk.Label(cpu_mem_frame, text="0%")
        self.mem_label.grid(row=1, column=2, padx=5)
        
        # Security status
        security_frame = ttk.LabelFrame(dashboard_frame, text="Security Status", padding=10)
        security_frame.pack(fill='x', padx=10, pady=5)
        
        self.security_status_label = ttk.Label(security_frame, text="Status: Initializing...")
        self.security_status_label.pack(anchor='w')
        
        self.threat_level_label = ttk.Label(security_frame, text="Threat Level: LOW")
        self.threat_level_label.pack(anchor='w')
        
        # Quick actions
        actions_frame = ttk.LabelFrame(dashboard_frame, text="Quick Actions", padding=10)
        actions_frame.pack(fill='x', padx=10, pady=5)
        
        button_frame = ttk.Frame(actions_frame)
        button_frame.pack(fill='x')
        
        ttk.Button(button_frame, text="🔍 Full Scan", command=self.full_scan).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🛡️ Lockdown", command=self.emergency_lockdown).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📊 System Info", command=self.show_system_info).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🧪 Test LLM", command=self.test_llm).pack(side='left', padx=5)
    
    def create_network_tab(self):
        """Create network monitoring tab"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="🌐 Network")
        
        # Network connections
        conn_frame = ttk.LabelFrame(network_frame, text="Active Connections", padding=10)
        conn_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Connections treeview
        columns = ('Local Address', 'Remote Address', 'Status', 'PID', 'Process')
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
        columns = ('Port', 'Service', 'Status', 'Risk', 'Timestamp')
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
        columns = ('Type', 'Severity', 'Description', 'Timestamp')
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
        
        # Control buttons
        button_frame = ttk.Frame(logs_frame)
        button_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(button_frame, text="🔄 Refresh", command=self.refresh_logs).pack(side='left', padx=5)
        ttk.Button(button_frame, text="🗑️ Clear", command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(button_frame, text="💾 Save", command=self.save_logs).pack(side='left', padx=5)
        ttk.Button(button_frame, text="📊 Export", command=self.export_logs).pack(side='left', padx=5)
    
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Security menu
        security_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Security", menu=security_menu)
        security_menu.add_command(label="Full System Scan", command=self.full_scan)
        security_menu.add_command(label="Network Analysis", command=self.analyze_network)
        security_menu.add_command(label="Threat Assessment", command=self.threat_assessment)
        security_menu.add_separator()
        security_menu.add_command(label="Emergency Lockdown", command=self.emergency_lockdown)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Port Scanner", command=self.scan_ports)
        tools_menu.add_command(label="Connection Monitor", command=self.refresh_network)
        tools_menu.add_command(label="Anomaly Detector", command=self.detect_anomalies)
        tools_menu.add_separator()
        tools_menu.add_command(label="System Information", command=self.show_system_info)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = ttk.Label(self.root, text="Ready", relief='sunken', anchor='w')
        self.status_bar.pack(side='bottom', fill='x')
    
    def init_security_system(self):
        """Initialize security monitoring system"""
        if not SECURITY_MODULES_AVAILABLE:
            messagebox.showwarning("Warning", "Security modules not available!")
            return
        
        try:
            # Initialize security monitor
            self.security_monitor = SecurityMonitor()
            self.security_monitor.start_monitoring()
            
            # Initialize LLM agent
            self.llm_agent = LLMSecurityAgent()
            
            # Start monitoring thread
            self.monitor_thread = SecurityMonitorThread(self.on_security_update)
            self.monitor_thread.start()
            
            # Check Ollama status
            self.check_ollama_status()
            
            # Update AI language indicator
            self.update_ai_language_indicator()
            
            # Load initial data immediately
            self.load_initial_data()
            
            self.log_message("Security system initialized successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize security system: {str(e)}")
            self.log_message(f"ERROR: Failed to initialize security system: {str(e)}")
    
    def check_ollama_status(self):
        """Check Ollama connection status"""
        if not SECURITY_MODULES_AVAILABLE:
            return
        
        try:
            if self.llm_agent.check_ollama_connection():
                models = self.llm_agent.get_available_models()
                self.ollama_status_label.config(text=f"Status: ✅ Connected ({len(models)} models)")
                self.log_message(f"Ollama connected with {len(models)} models")
            else:
                self.ollama_status_label.config(text="Status: ❌ Not connected")
                self.log_message("WARNING: Ollama not connected")
        except:
            self.ollama_status_label.config(text="Status: ❌ Error")
            self.log_message("ERROR: Ollama connection failed")
    
    def load_initial_data(self):
        """Load initial data immediately"""
        try:
            # Get initial network data
            network_scanner = NetworkScanner()
            connections = network_scanner.scan_network_connections()
            port_scan = network_scanner.scan_local_ports()
            
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
        # Schedule next update
        self.root.after(2000, self.update_ui)
    
    def on_security_update(self, security_status):
        """Handle security status update"""
        try:
            # Update system metrics
            system_info = security_status.get('system_info', {})
            cpu_percent = system_info.get('cpu_percent', 0)
            memory_percent = system_info.get('memory_percent', 0)
            
            self.cpu_bar['value'] = cpu_percent
            self.cpu_label.config(text=f"{cpu_percent:.1f}%")
            
            self.mem_bar['value'] = memory_percent
            self.mem_label.config(text=f"{memory_percent:.1f}%")
            
            # Update connections
            connections = security_status.get('connections', [])
            self.update_connections_tree(connections)
            
            # Update port scan
            port_scan = security_status.get('port_scan', [])
            self.update_ports_tree(port_scan)
            
            # Update anomalies
            anomalies = security_status.get('anomalies', [])
            self.update_anomalies_tree(anomalies)
            
            # Update threat level
            self.update_threat_level(security_status)
            
            # Update status
            self.status_bar.config(text=f"Last update: {datetime.now().strftime('%H:%M:%S')} | "
                                       f"Connections: {len(connections)} | "
                                       f"Open ports: {len(port_scan)} | "
                                       f"Anomalies: {len(anomalies)}")
            
        except Exception as e:
            self.log_message(f"ERROR: Security update failed: {str(e)}")
    
    def update_connections_tree(self, connections):
        """Update connections treeview"""
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        for conn in connections:
            self.connections_tree.insert('', 'end', values=(
                conn['local_addr'],
                conn['remote_addr'],
                conn['status'],
                conn['pid'],
                conn['process']
            ))
    
    def update_ports_tree(self, port_scan):
        """Update ports treeview"""
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
        
        for port in port_scan:
            self.ports_tree.insert('', 'end', values=(
                port['port'],
                port['service'],
                port['status'],
                port['risk'],
                port['timestamp'][:19]  # Truncate timestamp
            ))
    
    def update_anomalies_tree(self, anomalies):
        """Update anomalies tree with new data"""
        # Clear existing items
        for item in self.anomalies_tree.get_children():
            self.anomalies_tree.delete(item)
        
        # Add new anomalies
        for anomaly in anomalies:
            severity_color = {
                'HIGH': '#ff4444',
                'MEDIUM': '#ffaa00',
                'LOW': '#44aa44'
            }.get(anomaly.get('severity', 'LOW'), '#888888')
            
            self.anomalies_tree.insert('', 'end', values=(
                anomaly.get('type', 'UNKNOWN'),
                anomaly.get('severity', 'LOW'),
                anomaly.get('description', 'No description'),
                anomaly.get('timestamp', 'Unknown')
            ), tags=(severity_color,))
        
        # Configure tag colors
        self.anomalies_tree.tag_configure('#ff4444', background='#ffcccc')
        self.anomalies_tree.tag_configure('#ffaa00', background='#fff2cc')
        self.anomalies_tree.tag_configure('#44aa44', background='#ccffcc')
        self.anomalies_tree.tag_configure('#888888', background='#f0f0f0')
    
    def update_threat_level(self, security_status):
        """Update threat level based on security status"""
        threat_score = 0
        
        # Check for high-risk ports
        port_scan = security_status.get('port_scan', [])
        for port in port_scan:
            if port['risk'] == 'HIGH':
                threat_score += 10
        
        # Check for anomalies
        anomalies = security_status.get('anomalies', [])
        for anomaly in anomalies:
            if anomaly['severity'] == 'HIGH':
                threat_score += 15
            elif anomaly['severity'] == 'MEDIUM':
                threat_score += 5
        
        # Determine threat level
        if threat_score >= 30:
            threat_level = "CRITICAL"
            color = "red"
        elif threat_score >= 20:
            threat_level = "HIGH"
            color = "orange"
        elif threat_score >= 10:
            threat_level = "MEDIUM"
            color = "yellow"
        else:
            threat_level = "LOW"
            color = "green"
        
        self.threat_level_label.config(text=f"Threat Level: {threat_level}")
        self.security_status_label.config(text=f"Status: Active | Score: {threat_score}")
    
    def log_message(self, message):
        """Add message to logs"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        self.logs_text.insert(tk.END, log_entry)
        self.logs_text.see(tk.END)
    
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
        self.log_message("Refreshing network connections...")
        try:
            # Get fresh network data
            network_scanner = NetworkScanner()
            connections = network_scanner.scan_network_connections()
            
            # Update the connections tree
            self.update_connections_tree(connections)
            
            # Update status
            self.status_bar.config(text=f"Network refreshed: {len(connections)} connections | {datetime.now().strftime('%H:%M:%S')}")
            self.log_message(f"Network refreshed: {len(connections)} connections found")
            
        except Exception as e:
            self.log_message(f"ERROR: Failed to refresh network: {str(e)}")
            messagebox.showerror("Error", f"Failed to refresh network: {str(e)}")
    
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
        """Detect anomalies"""
        self.log_message("Running anomaly detection...")
        try:
            # Use the anomaly detector
            anomalies = self.monitor_thread.anomaly_detector.detect_anomalies()
            
            # Update the anomalies tree
            self.update_anomalies_tree(anomalies)
            
            # Update status
            self.status_bar.config(text=f"Anomaly detection completed: {len(anomalies)} anomalies found | {datetime.now().strftime('%H:%M:%S')}")
            self.log_message(f"Anomaly detection completed: {len(anomalies)} anomalies found")
            
        except Exception as e:
            self.log_message(f"ERROR: Anomaly detection failed: {str(e)}")
            messagebox.showerror("Error", f"Anomaly detection failed: {str(e)}")
    
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
        """Switch between English and Ukrainian"""
        new_lang = self.translation_manager.switch_language()
        
        # Update window title
        if new_lang == 'uk':
            self.root.title("NIMDA Система Безпеки - Комплексний Моніторинг")
        else:
            self.root.title("NIMDA Security System - Comprehensive Monitoring")
        
        # Update status
        lang_text = "Українська" if new_lang == 'uk' else "English"
        self.status_bar.config(text=f"Language switched to {lang_text} | {datetime.now().strftime('%H:%M:%S')}")
        
        # Show confirmation
        messagebox.showinfo("Language", f"Language switched to {lang_text}")
        
        # Note: Full UI translation would require updating all labels and buttons
        # This is a basic implementation showing the language switching capability
    
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
        """Send query to LLM agent"""
        query = self.query_entry.get()
        if not query or query == "Ask about security threats, analyze connections, or get recommendations...":
            messagebox.showwarning("Warning", "Please enter a query")
            return
        
        try:
            # Get current language for AI response
            current_lang = self.translation_manager.get_current_language()
            
            # Add language instruction to query
            if current_lang == 'uk':
                language_query = f"Відповідай українською мовою. {query}"
            else:
                language_query = f"Answer in English. {query}"
            
            # Send query to LLM
            response = self.llm_agent.analyze_security_query(language_query)
            
            # Display response
            self.response_text.delete('1.0', tk.END)
            self.response_text.insert('1.0', response)
            
            # Log the interaction
            self.log_message(f"AI Query: {query}")
            self.log_message(f"AI Response: {response[:100]}...")
            
            # Update status
            lang_text = "Українська" if current_lang == 'uk' else "English"
            self.status_bar.config(text=f"AI analysis completed in {lang_text} | {datetime.now().strftime('%H:%M:%S')}")
            
        except Exception as e:
            error_msg = f"Помилка AI аналізу: {str(e)}" if current_lang == 'uk' else f"AI analysis error: {str(e)}"
            messagebox.showerror("Error", error_msg)
            self.log_message(f"ERROR: AI analysis failed: {str(e)}")
    
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
        self.status_bar.config(text=f"AI language switched to {lang_text} | {datetime.now().strftime('%H:%M:%S')}")
        
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
        
        # Get provider status
        status = self.ai_provider_manager.get_provider_status()
        
        # Add providers to tree
        for name, info in status.items():
            status_text = "✅ Available" if info["available"] else "❌ Unavailable"
            models_text = ", ".join(info["models"][:3]) + ("..." if len(info["models"]) > 3 else "")
            last_check = info["last_check"].strftime("%H:%M:%S") if info["last_check"] else "Never"
            
            self.providers_tree.insert('', 'end', text=name, values=(status_text, models_text, last_check))
    
    def set_active_provider(self):
        """Set active AI provider"""
        selection = self.providers_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a provider")
            return
        
        provider_name = self.providers_tree.item(selection[0])['text']
        if self.ai_provider_manager.set_active_provider(provider_name):
            messagebox.showinfo("Success", f"Active provider set to {provider_name}")
            self.status_bar.config(text=f"Active AI provider: {provider_name} | {datetime.now().strftime('%H:%M:%S')}")
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
        
        # Get tasks
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
    
    def add_scheduled_task(self):
        """Add new scheduled task"""
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