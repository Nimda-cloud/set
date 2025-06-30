#!/usr/bin/env python3
"""
NIMDA Security Monitor for Mac M1 Max
Comprehensive monitoring of all security-relevant ports, connections, and devices
with Ollama integration for intelligent security analysis
"""

import subprocess
import json
import time
import threading
import requests
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any
import os
import re
import sqlite3
from dataclasses import dataclass
import logging
import psutil

@dataclass
class SecurityEvent:
    timestamp: str
    event_type: str
    device_name: str
    device_id: str
    port_type: str
    action: str  # connected, disconnected, activity, anomaly
    details: Dict[str, Any]
    risk_level: str  # low, medium, high, critical
    hash: str

class SecurityMonitor:
    def __init__(self, ollama_host="http://localhost:11434", ollama_model="llama3:latest"):
        self.ollama_host = ollama_host
        self.ollama_model = ollama_model
        self.previous_state = {}
        self.event_history = []
        self.anomaly_patterns = []
        self.risk_thresholds = {
            'new_usb_device': 'medium',
            'new_network': 'high',
            'vpn_connection': 'low',
            'ssh_tunnel': 'medium',
            'bluetooth_device': 'low',
            'thunderbolt_device': 'high',
            'unknown_device': 'high',
            'mass_storage': 'medium',
            'network_interface': 'medium'
        }
        
        # Initialize database
        self.init_database()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Threading
        self.running = False
        self.monitor_thread = None
        
    def init_database(self):
        """Initialize SQLite database for event storage"""
        self.db_path = "security_events.db"
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                device_name TEXT,
                device_id TEXT,
                port_type TEXT,
                action TEXT,
                details TEXT,
                risk_level TEXT,
                hash TEXT UNIQUE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                first_seen TEXT,
                last_seen TEXT,
                connection_count INTEGER,
                total_activity_time INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information"""
        try:
            # Get USB devices
            usb_info = subprocess.check_output([
                "system_profiler", "SPUSBDataType", "-json"
            ], text=True)
            
            # Get Thunderbolt devices
            thunderbolt_info = subprocess.check_output([
                "system_profiler", "SPThunderboltDataType", "-json"
            ], text=True)
            
            # Get network interfaces
            network_info = subprocess.check_output([
                "networksetup", "-listallhardwareports"
            ], text=True)
            
            # Get Bluetooth devices
            bluetooth_info = subprocess.check_output([
                "system_profiler", "SPBluetoothDataType", "-json"
            ], text=True)
            
            # Get audio devices
            audio_info = subprocess.check_output([
                "system_profiler", "SPAudioDataType", "-json"
            ], text=True)
            
            # Get power/battery info
            power_info = subprocess.check_output([
                "pmset", "-g", "batt"
            ], text=True)
            
            # Get process list for suspicious activity
            process_info = subprocess.check_output([
                "ps", "aux"
            ], text=True)
            
            # Get network connections
            network_connections = subprocess.check_output([
                "netstat", "-an"
            ], text=True)
            
            return {
                'usb': json.loads(usb_info) if usb_info.strip() else {},
                'thunderbolt': json.loads(thunderbolt_info) if thunderbolt_info.strip() else {},
                'network': network_info,
                'bluetooth': json.loads(bluetooth_info) if bluetooth_info.strip() else {},
                'audio': json.loads(audio_info) if audio_info.strip() else {},
                'power': power_info,
                'processes': process_info,
                'connections': network_connections,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            return {}
    
    def extract_devices(self, system_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and normalize device information"""
        devices = {}
        
        # Extract USB devices
        if 'usb' in system_info and 'SPUSBDataType' in system_info['usb']:
            for usb_bus in system_info['usb']['SPUSBDataType']:
                if '_items' in usb_bus:
                    for device in usb_bus['_items']:
                        device_id = f"usb_{device.get('_name', 'unknown')}_{device.get('serial_num', 'unknown')}"
                        devices[device_id] = {
                            'name': device.get('_name', 'Unknown USB Device'),
                            'type': 'usb',
                            'vendor': device.get('vendor_id', 'Unknown'),
                            'product': device.get('product_id', 'Unknown'),
                            'serial': device.get('serial_num', 'Unknown'),
                            'connected': True,
                            'details': device
                        }
        
        # Extract Thunderbolt devices
        if 'thunderbolt' in system_info and 'SPThunderboltDataType' in system_info['thunderbolt']:
            for tb_bus in system_info['thunderbolt']['SPThunderboltDataType']:
                if '_items' in tb_bus:
                    for device in tb_bus['_items']:
                        device_id = f"thunderbolt_{device.get('_name', 'unknown')}_{device.get('device_id', 'unknown')}"
                        devices[device_id] = {
                            'name': device.get('_name', 'Unknown Thunderbolt Device'),
                            'type': 'thunderbolt',
                            'device_id': device.get('device_id', 'Unknown'),
                            'connected': True,
                            'details': device
                        }
        
        # Extract network interfaces
        if 'network' in system_info:
            network_lines = system_info['network'].split('\n')
            current_interface = None
            for line in network_lines:
                if 'Hardware Port:' in line:
                    current_interface = line.split('Hardware Port:')[1].strip()
                elif 'Device:' in line and current_interface:
                    device_name = line.split('Device:')[1].strip()
                    device_id = f"network_{device_name}"
                    devices[device_id] = {
                        'name': f"{current_interface} ({device_name})",
                        'type': 'network',
                        'interface': device_name,
                        'port': current_interface,
                        'connected': True,
                        'details': {'interface': device_name, 'port': current_interface}
                    }
        
        # Extract Bluetooth devices
        if 'bluetooth' in system_info and 'SPBluetoothDataType' in system_info['bluetooth']:
            for bt_device in system_info['bluetooth']['SPBluetoothDataType']:
                if '_items' in bt_device:
                    for device in bt_device['_items']:
                        device_id = f"bluetooth_{device.get('_name', 'unknown')}_{device.get('address', 'unknown')}"
                        devices[device_id] = {
                            'name': device.get('_name', 'Unknown Bluetooth Device'),
                            'type': 'bluetooth',
                            'address': device.get('address', 'Unknown'),
                            'connected': device.get('is_connected', False),
                            'details': device
                        }
        
        # Extract audio devices
        if 'audio' in system_info and 'SPAudioDataType' in system_info['audio']:
            for audio_device in system_info['audio']['SPAudioDataType']:
                if '_items' in audio_device:
                    for device in audio_device['_items']:
                        device_id = f"audio_{device.get('_name', 'unknown')}_{device.get('manufacturer', 'unknown')}"
                        devices[device_id] = {
                            'name': device.get('_name', 'Unknown Audio Device'),
                            'type': 'audio',
                            'manufacturer': device.get('manufacturer', 'Unknown'),
                            'connected': True,
                            'details': device
                        }
        
        return devices
    
    def detect_changes(self, current_devices: Dict[str, Any], previous_devices: Dict[str, Any]) -> List[SecurityEvent]:
        """Detect changes between current and previous device states"""
        events = []
        
        # Check for new devices
        for device_id, device_info in current_devices.items():
            if device_id not in previous_devices:
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="device_connected",
                    device_name=device_info['name'],
                    device_id=device_id,
                    port_type=device_info['type'],
                    action="connected",
                    details=device_info['details'],
                    risk_level=self.risk_thresholds.get(f"new_{device_info['type']}_device", "medium"),
                    hash=self.generate_event_hash(device_id, "connected")
                )
                events.append(event)
        
        # Check for disconnected devices
        for device_id, device_info in previous_devices.items():
            if device_id not in current_devices:
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="device_disconnected",
                    device_name=device_info['name'],
                    device_id=device_id,
                    port_type=device_info['type'],
                    action="disconnected",
                    details=device_info['details'],
                    risk_level="low",
                    hash=self.generate_event_hash(device_id, "disconnected")
                )
                events.append(event)
        
        return events
    
    def generate_event_hash(self, device_id: str, action: str) -> str:
        """Generate unique hash for event"""
        content = f"{device_id}_{action}_{datetime.now().isoformat()}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def analyze_with_ollama(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Analyze security events using Ollama LLM"""
        if not events:
            return []
        
        try:
            # Prepare context for LLM
            context = self.prepare_llm_context(events)
            
            # Query Ollama
            response = requests.post(
                f"{self.ollama_host}/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": self.create_security_prompt(context),
                    "stream": False
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis = self.parse_llm_response(result.get('response', ''))
                return analysis
            else:
                self.logger.error(f"Ollama API error: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error analyzing with Ollama: {e}")
            return []
    
    def prepare_llm_context(self, events: List[SecurityEvent]) -> str:
        """Prepare context string for LLM analysis"""
        context_lines = ["Recent security events:"]
        
        for event in events[-10:]:  # Last 10 events
            context_lines.append(
                f"- {event.timestamp}: {event.event_type} - {event.device_name} "
                f"({event.port_type}) - Risk: {event.risk_level}"
            )
        
        return "\n".join(context_lines)
    
    def create_security_prompt(self, context: str) -> str:
        """Create security analysis prompt for LLM"""
        return f"""
You are a cybersecurity expert analyzing device connections on a Mac M1 Max system.

Context:
{context}

Please analyze these events and provide:
1. Risk assessment for each event (low/medium/high/critical)
2. Potential security implications
3. Recommended actions
4. Any suspicious patterns

Format your response as JSON with the following structure:
{{
    "analysis": [
        {{
            "event_type": "device_connected",
            "risk_assessment": "medium",
            "security_implications": "description",
            "recommended_actions": ["action1", "action2"],
            "suspicious_patterns": ["pattern1", "pattern2"]
        }}
    ],
    "overall_risk": "medium",
    "summary": "brief summary"
}}

Focus on security implications and provide actionable recommendations.
"""
    
    def parse_llm_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse LLM response and extract analysis"""
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                return analysis.get('analysis', [])
            else:
                # Fallback: create basic analysis
                return [{
                    'event_type': 'unknown',
                    'risk_assessment': 'medium',
                    'security_implications': 'Unable to parse LLM response',
                    'recommended_actions': ['Monitor system activity'],
                    'suspicious_patterns': []
                }]
        except Exception as e:
            self.logger.error(f"Error parsing LLM response: {e}")
            return []
    
    def save_event(self, event: SecurityEvent):
        """Save event to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO security_events 
                (timestamp, event_type, device_name, device_id, port_type, action, details, risk_level, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.timestamp, event.event_type, event.device_name, event.device_id,
                event.port_type, event.action, json.dumps(event.details), event.risk_level, event.hash
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Error saving event: {e}")
    
    def get_recent_events(self, hours: int = 24) -> List[SecurityEvent]:
        """Get recent events from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since = (datetime.now() - timedelta(hours=hours)).isoformat()
            
            cursor.execute('''
                SELECT timestamp, event_type, device_name, device_id, port_type, action, details, risk_level, hash
                FROM security_events 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 100
            ''', (since,))
            
            events = []
            for row in cursor.fetchall():
                event = SecurityEvent(
                    timestamp=row[0],
                    event_type=row[1],
                    device_name=row[2],
                    device_id=row[3],
                    port_type=row[4],
                    action=row[5],
                    details=json.loads(row[6]),
                    risk_level=row[7],
                    hash=row[8]
                )
                events.append(event)
            
            conn.close()
            return events
        except Exception as e:
            self.logger.error(f"Error getting recent events: {e}")
            return []
    
    def monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Get current system state
                system_info = self.get_system_info()
                current_devices = self.extract_devices(system_info)
                
                # Detect changes
                if self.previous_state:
                    events = self.detect_changes(current_devices, self.previous_state)
                    
                    # Save events
                    for event in events:
                        self.save_event(event)
                    
                    # Analyze with Ollama if there are events
                    if events:
                        analysis = self.analyze_with_ollama(events)
                        self.logger.info(f"Security analysis completed: {len(analysis)} insights")
                
                # Update previous state
                self.previous_state = current_devices
                
                # Sleep for monitoring interval
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)
    
    def start_monitoring(self):
        """Start security monitoring"""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
            self.monitor_thread.start()
            self.logger.info("Security monitoring started")
    
    def stop_monitoring(self):
        """Stop security monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()
        self.logger.info("Security monitoring stopped")
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get current status summary"""
        try:
            system_info = self.get_system_info()
            current_devices = self.extract_devices(system_info)
            
            # Count devices by type
            device_counts = {}
            for device in current_devices.values():
                device_type = device['type']
                device_counts[device_type] = device_counts.get(device_type, 0) + 1
            
            # Get recent events
            recent_events = self.get_recent_events(hours=1)
            
            # Count events by risk level
            risk_counts = {}
            for event in recent_events:
                risk_level = event.risk_level
                risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
            
            return {
                'timestamp': datetime.now().isoformat(),
                'active_devices': device_counts,
                'recent_events': len(recent_events),
                'risk_distribution': risk_counts,
                'monitoring_active': self.running
            }
        except Exception as e:
            self.logger.error(f"Error getting status summary: {e}")
            return {}
    
    def get_file_hash(self, filepath):
        """Розраховує SHA-256 хеш файлу."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                # Читаємо файл частинами, щоб не завантажувати великі файли в пам'ять
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return None
        except Exception as e:
            self.logger.error(f"Помилка при хешуванні файлу {filepath}: {e}")
            return None

    def monitor_suspicious_downloads(self):
        """
        Моніторить папку Downloads і хешує нові файли.
        Цю функцію можна викликати періодично.
        """
        downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
        if not os.path.exists(downloads_path):
            self.logger.warning(f"Downloads папка не знайдена: {downloads_path}")
            return
            
        suspicious_extensions = ['.sh', '.py', '.pl', '.rb', '.jar', '.dmg', '.pkg', '.app']
        new_files = []
        
        try:
            for filename in os.listdir(downloads_path):
                filepath = os.path.join(downloads_path, filename)
                if os.path.isfile(filepath):
                    # Перевіряємо час створення файлу (нові файли за останню годину)
                    file_mtime = os.path.getmtime(filepath)
                    current_time = time.time()
                    if current_time - file_mtime < 3600:  # 1 година
                        file_hash = self.get_file_hash(filepath)
                        if file_hash:
                            file_info = {
                                'filename': filename,
                                'filepath': filepath,
                                'hash': file_hash,
                                'size': os.path.getsize(filepath),
                                'modified_time': datetime.fromtimestamp(file_mtime).isoformat(),
                                'suspicious': any(filename.lower().endswith(ext) for ext in suspicious_extensions)
                            }
                            new_files.append(file_info)
                            
                            # Логуємо подію
                            self.log_security_event(
                                event_type="new_file_download",
                                device_name=filename,
                                device_id=file_hash[:16],
                                port_type="filesystem",
                                action="detected",
                                details=file_info,
                                risk_level="medium" if file_info['suspicious'] else "low"
                            )
                            
                            self.logger.info(f"Новий файл: {filename}, Хеш: {file_hash}, Підозрілий: {file_info['suspicious']}")
                            
        except Exception as e:
            self.logger.error(f"Помилка моніторингу завантажень: {e}")
        
        return new_files

    def get_shell_history(self, limit=20):
        """Отримує останні команди з історії shell."""
        history_files = {
            'bash': os.path.expanduser('~/.bash_history'),
            'zsh': os.path.expanduser('~/.zsh_history')
        }
        history = []
        
        for shell, path in history_files.items():
            if os.path.exists(path):
                try:
                    with open(path, 'r', errors='ignore') as f:
                        lines = f.readlines()
                        # Беремо останні N команд
                        for line in lines[-limit:]:
                            cleaned_line = line.strip()
                            if cleaned_line:
                                # Для zsh історії, очищуємо timestamp якщо є
                                if shell == 'zsh' and cleaned_line.startswith(':'):
                                    # Формат zsh: ": timestamp:duration;command"
                                    parts = cleaned_line.split(';', 1)
                                    if len(parts) > 1:
                                        cleaned_line = parts[1]
                                
                                history.append({
                                    'shell': shell,
                                    'command': cleaned_line,
                                    'timestamp': datetime.now().isoformat()  # Approximation
                                })
                except Exception as e:
                    self.logger.error(f"Не вдалося прочитати історію {shell}: {e}")
        
        return history[-limit:] if history else []

    def analyze_command_history_for_threats(self):
        """
        Аналізує історію команд на предмет підозрілої активності.
        """
        history = self.get_shell_history(50)  # Беремо останні 50 команд
        suspicious_patterns = [
            r'curl\s+.*\|\s*(bash|sh)',  # Завантаження та виконання скриптів
            r'wget\s+.*\|\s*(bash|sh)', 
            r'nc\s+-l',  # Netcat listener
            r'python.*-c.*exec',  # Виконання Python коду
            r'chmod\s+\+x.*\.sh',  # Надання прав виконання скриптам
            r'sudo\s+.*(/tmp|/var/tmp)',  # Виконання команд з тимчасових папок
            r'rm\s+.*\.(log|history)',  # Видалення логів/історії
            r'pkill.*-f.*python',  # Завершення Python процесів
            r'launchctl\s+(load|unload)',  # Управління системними сервісами
            r'/System/Library/.*plist'  # Маніпуляції з системними plist файлами
        ]
        
        suspicious_commands = []
        
        for entry in history:
            command = entry['command']
            for pattern in suspicious_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    suspicious_commands.append({
                        'command': command,
                        'pattern': pattern,
                        'shell': entry['shell'],
                        'timestamp': entry['timestamp'],
                        'risk_level': self._assess_command_risk(command)
                    })
                    
                    # Логуємо підозрілу команду
                    self.log_security_event(
                        event_type="suspicious_command",
                        device_name=entry['shell'],
                        device_id=hashlib.md5(command.encode()).hexdigest()[:16],
                        port_type="shell",
                        action="executed",
                        details={'command': command, 'pattern': pattern},
                        risk_level=self._assess_command_risk(command)
                    )
                    break
        
        return suspicious_commands

    def _assess_command_risk(self, command):
        """Оцінює рівень ризику команди"""
        high_risk_indicators = [
            'rm -rf /',
            'dd if=',
            'wget.*malware',
            'curl.*malware',
            'nc -l',
            'python -c "exec',
            'sudo rm',
            '/tmp/.*\.sh'
        ]
        
        medium_risk_indicators = [
            'chmod +x',
            'curl.*|.*bash',
            'wget.*|.*sh',
            'launchctl',
            'sudo',
            'pkill',
            'killall'
        ]
        
        command_lower = command.lower()
        
        for indicator in high_risk_indicators:
            if re.search(indicator, command_lower):
                return "high"
        
        for indicator in medium_risk_indicators:
            if re.search(indicator, command_lower):
                return "medium"
        
        return "low"

    def monitor_file_integrity(self, watch_paths=None):
        """
        Моніторить цілісність важливих системних файлів.
        """
        if watch_paths is None:
            watch_paths = [
                '/etc/hosts',
                '/etc/passwd',
                '/System/Library/LaunchDaemons',
                '~/.ssh/authorized_keys',
                '~/.bash_profile',
                '~/.zshrc'
            ]
        
        integrity_data = {}
        
        for path in watch_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                if os.path.isfile(expanded_path):
                    file_hash = self.get_file_hash(expanded_path)
                    if file_hash:
                        integrity_data[expanded_path] = {
                            'hash': file_hash,
                            'size': os.path.getsize(expanded_path),
                            'modified': os.path.getmtime(expanded_path),
                            'checked_at': datetime.now().isoformat()
                        }
                elif os.path.isdir(expanded_path):
                    # Для директорій рахуємо кількість файлів та загальний розмір
                    try:
                        files_count = len([f for f in os.listdir(expanded_path) if os.path.isfile(os.path.join(expanded_path, f))])
                        integrity_data[expanded_path] = {
                            'type': 'directory',
                            'files_count': files_count,
                            'checked_at': datetime.now().isoformat()
                        }
                    except PermissionError:
                        self.logger.warning(f"Немає доступу до директорії: {expanded_path}")
        
        return integrity_data

    def get_enhanced_system_state(self):
        """
        Розширена функція отримання стану системи з додатковими даними безпеки.
        """
        base_info = self.get_system_info()
        
        # Додаємо розширену інформацію
        enhanced_info = {
            **base_info,
            'file_downloads': self.monitor_suspicious_downloads(),
            'command_history_threats': self.analyze_command_history_for_threats(),
            'file_integrity': self.monitor_file_integrity(),
            'active_connections_detailed': self._get_detailed_network_connections(),
            'running_services': self._get_system_services(),
            'timestamp': datetime.now().isoformat()
        }
        
        return enhanced_info

    def _get_detailed_network_connections(self):
        """Отримує детальну інформацію про мережеві з'єднання"""
        connections = []
        try:
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    conn_info = {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'pid': conn.pid,
                        'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                        'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                    }
                    
                    # Додаємо інформацію про процес
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            conn_info['process_name'] = proc.name()
                            conn_info['process_exe'] = proc.exe()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    connections.append(conn_info)
        except Exception as e:
            self.logger.error(f"Помилка отримання детальних з'єднань: {e}")
        
        return connections

    def _get_system_services(self):
        """Отримує список активних системних сервісів"""
        services = []
        try:
            # Використовуємо launchctl для отримання списку сервісів
            result = subprocess.run(['launchctl', 'list'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]  # Пропускаємо заголовок
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            services.append({
                                'pid': parts[0] if parts[0] != '-' else None,
                                'status': parts[1],
                                'label': parts[2]
                            })
        except Exception as e:
            self.logger.error(f"Помилка отримання сервісів: {e}")
        
        return services

    def log_security_event(self, event_type: str, device_name: str, device_id: str, 
                          port_type: str, action: str, details: Dict[str, Any], 
                          risk_level: str):
        """
        Логує події безпеки в базу даних
        """
        try:
            conn = sqlite3.connect('data/security_events.db')
            cursor = conn.cursor()
            
            # Створюємо хеш для унікальності події
            event_data = f"{event_type}_{device_name}_{device_id}_{action}_{datetime.now().date()}"
            event_hash = hashlib.md5(event_data.encode()).hexdigest()
            
            cursor.execute('''
                INSERT OR REPLACE INTO security_events 
                (timestamp, event_type, device_name, device_id, port_type, action, details, risk_level, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                event_type,
                device_name,
                device_id,
                port_type,
                action,
                json.dumps(details),
                risk_level,
                event_hash
            ))
            
            conn.commit()
            conn.close()
            
            # Логуємо також в файл
            self.logger.info(f"Security event: {event_type} - {device_name} ({risk_level})")
            
        except Exception as e:
            self.logger.error(f"Помилка логування події: {e}")

    def get_security_events(self, limit: int = 100, event_type: str = None, 
                           risk_level: str = None) -> List[Dict[str, Any]]:
        """
        Отримує події безпеки з бази даних
        """
        try:
            conn = sqlite3.connect('data/security_events.db')
            cursor = conn.cursor()
            
            query = "SELECT * FROM security_events"
            params = []
            
            conditions = []
            if event_type:
                conditions.append("event_type = ?")
                params.append(event_type)
            if risk_level:
                conditions.append("risk_level = ?")
                params.append(risk_level)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            events = []
            for row in rows:
                events.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'event_type': row[2],
                    'device_name': row[3],
                    'device_id': row[4],
                    'port_type': row[5],
                    'action': row[6],
                    'details': json.loads(row[7]) if row[7] else {},
                    'risk_level': row[8],
                    'hash': row[9]
                })
            
            conn.close()
            return events
            
        except Exception as e:
            self.logger.error(f"Помилка отримання подій: {e}")
            return []

def main():
    """Test the security monitor"""
    monitor = SecurityMonitor()
    
    try:
        print("Starting security monitor...")
        monitor.start_monitoring()
        
        # Run for a few seconds to test
        time.sleep(10)
        
        # Get status
        status = monitor.get_status_summary()
        print("Status:", json.dumps(status, indent=2))
        
        # Get recent events
        events = monitor.get_recent_events(hours=1)
        print(f"Recent events: {len(events)}")
        
    except KeyboardInterrupt:
        print("\nStopping security monitor...")
    finally:
        monitor.stop_monitoring()

if __name__ == "__main__":
    main()
