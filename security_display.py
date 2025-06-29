#!/usr/bin/env python3
"""
NIMDA Security Display Monitor
Displays security events, device connections, and Ollama analysis in tmux pane
"""

import time
import json
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Any
import os
import sys
from security_monitor import SecurityMonitor, SecurityEvent

class SecurityDisplay:
    def __init__(self, db_path="security_events.db"):
        self.db_path = db_path
        self.security_monitor = SecurityMonitor()
        self.display_mode = "recent"  # recent, devices, analysis
        self.refresh_interval = 2
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear')
        
    def get_color_code(self, risk_level: str) -> str:
        """Get color code for risk level"""
        colors = {
            'low': '\033[92m',      # Green
            'medium': '\033[93m',   # Yellow
            'high': '\033[91m',     # Red
            'critical': '\033[95m'  # Magenta
        }
        return colors.get(risk_level, '\033[0m')
    
    def reset_color(self) -> str:
        """Reset color formatting"""
        return '\033[0m'
    
    def format_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display"""
        try:
            dt = datetime.fromisoformat(timestamp)
            return dt.strftime("%H:%M:%S")
        except:
            return timestamp[:8]
    
    def get_recent_events(self, limit: int = 20) -> List[SecurityEvent]:
        """Get recent security events"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, event_type, device_name, device_id, port_type, action, details, risk_level, hash
                FROM security_events 
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
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
            return []
    
    def get_current_devices(self) -> Dict[str, Any]:
        """Get current connected devices"""
        try:
            system_info = self.security_monitor.get_system_info()
            return self.security_monitor.extract_devices(system_info)
        except Exception as e:
            return {}
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security summary statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get total events
            cursor.execute('SELECT COUNT(*) FROM security_events')
            total_events = cursor.fetchone()[0]
            
            # Get events in last hour
            since = (datetime.now() - timedelta(hours=1)).isoformat()
            cursor.execute('SELECT COUNT(*) FROM security_events WHERE timestamp > ?', (since,))
            recent_events = cursor.fetchone()[0]
            
            # Get risk distribution
            cursor.execute('''
                SELECT risk_level, COUNT(*) 
                FROM security_events 
                WHERE timestamp > ? 
                GROUP BY risk_level
            ''', (since,))
            risk_distribution = dict(cursor.fetchall())
            
            # Get device types
            cursor.execute('''
                SELECT port_type, COUNT(*) 
                FROM security_events 
                WHERE timestamp > ? 
                GROUP BY port_type
            ''', (since,))
            device_types = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                'total_events': total_events,
                'recent_events': recent_events,
                'risk_distribution': risk_distribution,
                'device_types': device_types
            }
        except Exception as e:
            return {
                'total_events': 0,
                'recent_events': 0,
                'risk_distribution': {},
                'device_types': {}
            }
    
    def display_header(self):
        """Display header information"""
        print(f"{'='*80}")
        print(f"{'🔒 NIMDA SECURITY MONITOR':^80}")
        print(f"{'='*80}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Mode: {self.display_mode.upper()}")
        print(f"{'='*80}")
    
    def display_recent_events(self):
        """Display recent security events"""
        events = self.get_recent_events(15)
        
        if not events:
            print("No recent security events found.")
            return
        
        print(f"{'Time':<8} {'Event':<12} {'Device':<25} {'Port':<10} {'Risk':<8}")
        print("-" * 80)
        
        for event in events:
            color = self.get_color_code(event.risk_level)
            time_str = self.format_timestamp(event.timestamp)
            device_name = event.device_name[:24] if len(event.device_name) > 24 else event.device_name
            
            print(f"{time_str:<8} {event.event_type:<12} {device_name:<25} {event.port_type:<10} {color}{event.risk_level:<8}{self.reset_color()}")
    
    def display_current_devices(self):
        """Display currently connected devices"""
        devices = self.get_current_devices()
        
        if not devices:
            print("No devices currently connected.")
            return
        
        # Group devices by type
        device_groups = {}
        for device_id, device_info in devices.items():
            device_type = device_info['type']
            if device_type not in device_groups:
                device_groups[device_type] = []
            device_groups[device_type].append(device_info)
        
        for device_type, device_list in device_groups.items():
            print(f"\n{device_type.upper()} DEVICES ({len(device_list)}):")
            print("-" * 40)
            
            for device in device_list:
                name = device['name'][:35] if len(device['name']) > 35 else device['name']
                print(f"  {name}")
                
                # Show additional details
                if 'vendor' in device:
                    print(f"    Vendor: {device['vendor']}")
                if 'serial' in device:
                    print(f"    Serial: {device['serial']}")
                if 'address' in device:
                    print(f"    Address: {device['address']}")
    
    def display_security_summary(self):
        """Display security summary"""
        summary = self.get_security_summary()
        
        print(f"SECURITY SUMMARY:")
        print("-" * 40)
        print(f"Total Events: {summary['total_events']}")
        print(f"Recent Events (1h): {summary['recent_events']}")
        
        if summary['risk_distribution']:
            print(f"\nRisk Distribution (1h):")
            for risk_level, count in summary['risk_distribution'].items():
                color = self.get_color_code(risk_level)
                print(f"  {color}{risk_level}: {count}{self.reset_color()}")
        
        if summary['device_types']:
            print(f"\nDevice Types (1h):")
            for device_type, count in summary['device_types'].items():
                print(f"  {device_type}: {count}")
    
    def display_ollama_status(self):
        """Display Ollama connection status"""
        try:
            import requests
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                print(f"\nOLLAMA STATUS: ✅ Connected")
                print(f"Available Models: {len(models)}")
                for model in models[:3]:  # Show first 3 models
                    print(f"  - {model.get('name', 'Unknown')}")
                if len(models) > 3:
                    print(f"  ... and {len(models) - 3} more")
            else:
                print(f"\nOLLAMA STATUS: ❌ Error ({response.status_code})")
        except Exception as e:
            print(f"\nOLLAMA STATUS: ❌ Not Connected")
    
    def display_help(self):
        """Display help information"""
        print("KEYBOARD SHORTCUTS:")
        print("-" * 40)
        print("  r - Recent Events")
        print("  d - Current Devices")
        print("  s - Security Summary")
        print("  o - Ollama Status")
        print("  h - This Help")
        print("  q - Quit")
        print("\nPress any key to continue...")
    
    def handle_input(self, key: str):
        """Handle keyboard input"""
        key = key.lower()
        
        if key == 'r':
            self.display_mode = "recent"
        elif key == 'd':
            self.display_mode = "devices"
        elif key == 's':
            self.display_mode = "summary"
        elif key == 'o':
            self.display_mode = "ollama"
        elif key == 'h':
            self.display_mode = "help"
        elif key == 'q':
            return False
        
        return True
    
    def run(self):
        """Main display loop"""
        import select
        import tty
        import termios
        
        # Set up terminal for non-blocking input
        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setcbreak(sys.stdin.fileno())
            
            while True:
                self.clear_screen()
                self.display_header()
                
                if self.display_mode == "recent":
                    self.display_recent_events()
                elif self.display_mode == "devices":
                    self.display_current_devices()
                elif self.display_mode == "summary":
                    self.display_security_summary()
                elif self.display_mode == "ollama":
                    self.display_ollama_status()
                elif self.display_mode == "help":
                    self.display_help()
                
                # Check for input (non-blocking)
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    key = sys.stdin.read(1)
                    if not self.handle_input(key):
                        break
                
                time.sleep(self.refresh_interval)
                
        except KeyboardInterrupt:
            pass
        finally:
            # Restore terminal settings
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    
    def run_simple(self):
        """Simple display mode without interactive input"""
        while True:
            self.clear_screen()
            self.display_header()
            
            if self.display_mode == "recent":
                self.display_recent_events()
            elif self.display_mode == "devices":
                self.display_current_devices()
            elif self.display_mode == "summary":
                self.display_security_summary()
            elif self.display_mode == "ollama":
                self.display_ollama_status()
            
            time.sleep(self.refresh_interval)

def main():
    """Main function"""
    display = SecurityDisplay()
    
    # Check if running in tmux (simple mode) or interactive
    if 'TMUX' in os.environ:
        display.run_simple()
    else:
        display.run()

if __name__ == "__main__":
    main() 