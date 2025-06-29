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
from typing import Dict, List, Set, Optional, Any
import os
import re
import sqlite3
from dataclasses import dataclass, asdict
import logging

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
