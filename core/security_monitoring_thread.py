#!/usr/bin/env python3
"""
Security Monitoring Thread for NIMDA Security System
Non-blocking background monitoring with event queue for GUI communication
"""

import threading
import queue
import time
import os
import sys
import logging
import json
import psutil
import hashlib
import re
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add path to root directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.enhanced_threat_analyzer import EnhancedThreatAnalyzer
from core.optimized_rule_manager import OptimizedRuleManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class SecurityMonitoringThread(threading.Thread):
    """
    Background thread for security monitoring with non-blocking event queue
    """
    
    def __init__(self, event_queue, interval=2, db_path="security_events.db"):
        """Initialize monitoring thread
        
        Args:
            event_queue (Queue): Thread-safe queue for passing events to the GUI
            interval (int): Time between monitoring checks in seconds
            db_path (str): Path to the security events database
        """
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.event_queue = event_queue
        self.interval = interval
        self.db_path = db_path
        self.running = False
        self.daemon = True
        
        # Initialize security components
        self.rule_manager = OptimizedRuleManager()
        self.threat_analyzer = EnhancedThreatAnalyzer(db_path=db_path)
        
        # Tracked states for change detection
        self.previous_state = {
            'network': {},
            'processes': {},
            'usb': {},
            'files': {}
        }
        
        # Counter for staggering intensive operations
        self.cycle_counter = 0
        
        # Create data directory if it doesn't exist
        data_dir = os.path.dirname(db_path)
        if data_dir and not os.path.exists(data_dir):
            os.makedirs(data_dir)
    
    def run(self):
        """Main monitoring loop"""
        self.running = True
        self.logger.info("Security monitoring thread started")
        
        # Send initial status update
        self.event_queue.put({
            "type": "monitoring_status",
            "data": {"status": "active", "message": "Security monitoring active"},
            "timestamp": datetime.now().isoformat()
        })
        
        while self.running:
            try:
                # Using time.time() for internal operations
                self.cycle_counter += 1
                
                # Always monitor network and processes (basic info)
                self.check_network_connections()
                self.check_running_processes()
                
                # Staggered checks to avoid performance impact
                # These operations are more intensive so we don't run them every cycle
                if self.cycle_counter % 5 == 0:  # Every 5 cycles
                    self.check_system_info()
                    self.check_file_changes()
                    
                if self.cycle_counter % 10 == 0:  # Every 10 cycles
                    self.check_security_events()
                    
                if self.cycle_counter % 30 == 0:  # Every 30 cycles
                    self.check_threat_status()
                    self.check_shell_history()
                    
                if self.cycle_counter >= 60:
                    self.cycle_counter = 0  # Reset counter
                
                # Sleep for the monitoring interval
                time.sleep(self.interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring thread: {e}")
                # Put error event in the queue
                self.event_queue.put({
                    "type": "monitoring_error",
                    "data": {"error": str(e)},
                    "timestamp": datetime.now().isoformat()
                })
                time.sleep(5)  # Sleep longer on error
    
    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        self.logger.info("Security monitoring thread stopping")
        
        # Send status update
        self.event_queue.put({
            "type": "monitoring_status",
            "data": {"status": "stopped", "message": "Security monitoring stopped"},
            "timestamp": datetime.now().isoformat()
        })
    
    def check_network_connections(self):
        """Monitor network connections and detect changes"""
        try:
            connections = []
            # Get network connections with proper error handling
            try:
                net_connections = psutil.net_connections(kind='inet')
            except (psutil.AccessDenied, PermissionError):
                self.logger.warning("Access denied when checking network connections")
                return
            
            for conn in net_connections:
                try:
                    if conn.status == 'ESTABLISHED':
                        connection_info = {
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                            'status': conn.status,
                            'pid': conn.pid if conn.pid else 0
                        }
                        
                        # Add process name if PID is available and valid
                        if conn.pid:
                            try:
                                proc = psutil.Process(conn.pid)
                                connection_info['process_name'] = proc.name()
                                connection_info['process_path'] = proc.exe()
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                connection_info['process_name'] = 'Unknown'
                                connection_info['process_path'] = 'Unknown'
                        else:
                            connection_info['process_name'] = 'System'
                            connection_info['process_path'] = 'System'
                        
                        connections.append(connection_info)
                except (AttributeError, OSError) as e:
                    # Skip individual connections that cause issues
                    self.logger.debug(f"Skipping problematic connection: {e}")
                    continue
            
            # Detect new connections
            new_connections = []
            # Use safe key generation that handles None PID values
            current_conn_map = {}
            for c in connections:
                # Create a safe key, handling None PIDs
                pid = c.get('pid', 0)
                if pid is None:
                    pid = 0
                key = f"{c['local_address']}-{c['remote_address']}-{pid}"
                current_conn_map[key] = c
                
            prev_conn_map = self.previous_state.get('network', {})
            
            for key, conn in current_conn_map.items():
                if key not in prev_conn_map:
                    new_connections.append(conn)
                    
                    # Analyze new connections for security threats
                    if conn.get('process_name') and conn.get('remote_address') != 'N/A':
                        log_entry = f"New network connection: {conn['process_name']} (PID {conn.get('pid', 0)}) connected to {conn['remote_address']}"
                        self.analyze_security_event(log_entry, event_type="new_connection", 
                                                  source=conn.get('process_name', 'unknown'), 
                                                  target=conn.get('remote_address', 'unknown'))
            
            # Update the connection map
            self.previous_state['network'] = current_conn_map
            
            # Send network update to the GUI
            self.event_queue.put({
                "type": "network_update", 
                "data": connections,
                "timestamp": datetime.now().isoformat(),
                "new_connections": new_connections
            })
            
        except Exception as e:
            self.logger.error(f"Error monitoring network connections: {e}")
    
    def check_running_processes(self):
        """Monitor running processes and detect new ones"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline', 'create_time', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    info = proc.info
                    if info['pid'] is not None:
                        # Ensure cmdline is always a list (can be None for some processes)
                        if info.get('cmdline') is None:
                            info['cmdline'] = []
                        processes.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Detect new processes
            new_processes = []
            current_process_map = {p['pid']: p for p in processes if p['pid'] is not None}
            prev_process_map = self.previous_state.get('processes', {})
            
            for pid, proc in current_process_map.items():
                if pid not in prev_process_map:
                    new_processes.append(proc)
                    
                    # Analyze new process for security threats if it's not a system process
                    if proc.get('username') and proc.get('name'):
                        suspicious = self._is_suspicious_process(proc)
                        if suspicious or not self._is_common_system_process(proc):
                            log_entry = f"New process: {proc['name']} (PID {proc['pid']}) started by user {proc['username']}"
                            self.analyze_security_event(log_entry, event_type="new_process", 
                                                      source=proc.get('username', 'unknown'), 
                                                      target=proc.get('name', 'unknown'))
            
            # Update the process map
            self.previous_state['processes'] = current_process_map
            
            # Send process update to the GUI
            self.event_queue.put({
                "type": "process_update",
                "data": processes,
                "timestamp": datetime.now().isoformat(),
                "new_processes": new_processes
            })
            
        except Exception as e:
            self.logger.error(f"Error monitoring processes: {e}")
    
    def check_system_info(self):
        """Monitor system information and resource usage"""
        try:
            # Get CPU, memory, disk info
            cpu_percent = psutil.cpu_percent(interval=0.5)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Network I/O counters
            net_io = psutil.net_io_counters()
            
            system_info = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used': memory.used,
                'memory_total': memory.total,
                'disk_percent': disk.percent,
                'disk_free': disk.free,
                'disk_total': disk.total,
                'network_bytes_sent': net_io.bytes_sent,
                'network_bytes_recv': net_io.bytes_recv,
                'boot_time': psutil.boot_time()
            }
            
            # Send system info update to the GUI
            self.event_queue.put({
                "type": "system_info_update",
                "data": system_info,
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
    
    def check_file_changes(self):
        """Monitor important file changes"""
        try:
            # Check downloads directory for new files
            downloads_dir = os.path.expanduser('~/Downloads')
            if os.path.exists(downloads_dir):
                new_files = []
                suspicious_files = []
                
                # Get current state of directory
                files = {}
                for filename in os.listdir(downloads_dir):
                    filepath = os.path.join(downloads_dir, filename)
                    if os.path.isfile(filepath):
                        file_stat = os.stat(filepath)
                        files[filename] = {
                            'size': file_stat.st_size,
                            'modified': file_stat.st_mtime,
                            'path': filepath
                        }
                
                # Compare with previous state
                prev_files = self.previous_state.get('files', {}).get('downloads', {})
                for filename, file_info in files.items():
                    if filename not in prev_files:
                        new_files.append(filename)
                        
                        # Check if file is suspicious
                        if self._is_suspicious_file(filename, file_info['path']):
                            suspicious_files.append(filename)
                            
                            # Analyze suspicious file
                            log_entry = f"Suspicious file downloaded: {filename} in Downloads directory"
                            self.analyze_security_event(log_entry, event_type="suspicious_file", 
                                                      source="download", 
                                                      target=filename)
                
                # Update file state
                if 'files' not in self.previous_state:
                    self.previous_state['files'] = {}
                self.previous_state['files']['downloads'] = files
                
                # Send file update to the GUI if there are new files
                if new_files:
                    self.event_queue.put({
                        "type": "file_update",
                        "data": {
                            "new_files": new_files,
                            "suspicious_files": suspicious_files,
                            "directory": "downloads"
                        },
                        "timestamp": datetime.now().isoformat()
                    })
            
            # Monitor other important directories or files
            # This can be expanded based on requirements
            
        except Exception as e:
            self.logger.error(f"Error checking file changes: {e}")
    
    def check_security_events(self):
        """Get recent security events from the database"""
        try:
            events = self.threat_analyzer.get_recent_security_events(hours=1, limit=20)
            
            if events:
                # Send security events to the GUI
                self.event_queue.put({
                    "type": "security_events",
                    "data": events,
                    "timestamp": datetime.now().isoformat()
                })
        except Exception as e:
            self.logger.error(f"Error getting security events: {e}")
    
    def check_threat_status(self):
        """Get current threat status summary"""
        try:
            threat_summary = self.threat_analyzer.get_threat_summary()
            
            # Send threat status to the GUI
            self.event_queue.put({
                "type": "threat_status",
                "data": threat_summary,
                "timestamp": datetime.now().isoformat()
            })
        except Exception as e:
            self.logger.error(f"Error getting threat status: {e}")
    
    def check_shell_history(self):
        """Monitor shell history for suspicious commands"""
        try:
            history_files = {
                'bash': os.path.expanduser('~/.bash_history'),
                'zsh': os.path.expanduser('~/.zsh_history')
            }
            
            for shell, path in history_files.items():
                if os.path.exists(path):
                    # Get file hash to detect changes
                    current_hash = self._get_file_hash(path)
                    prev_hash = self.previous_state.get('shell_history', {}).get(shell)
                    
                    if current_hash != prev_hash:
                        # History has changed, check the new commands
                        suspicious_commands = self._check_suspicious_commands(path, shell)
                        
                        if suspicious_commands:
                            for cmd in suspicious_commands:
                                log_entry = f"Suspicious {shell} command: {cmd}"
                                self.analyze_security_event(log_entry, event_type="suspicious_command", 
                                                          source=shell, 
                                                          target=cmd)
                            
                            # Send alert to the GUI
                            self.event_queue.put({
                                "type": "suspicious_commands",
                                "data": {
                                    "shell": shell,
                                    "commands": suspicious_commands
                                },
                                "timestamp": datetime.now().isoformat()
                            })
                        
                        # Update the hash
                        if 'shell_history' not in self.previous_state:
                            self.previous_state['shell_history'] = {}
                        self.previous_state['shell_history'][shell] = current_hash
            
        except Exception as e:
            self.logger.error(f"Error checking shell history: {e}")
    
    def analyze_security_event(self, log_entry, event_type="unknown", source="unknown", target="unknown"):
        """Analyze a security event using the threat analyzer"""
        try:
            # Run analysis in a separate thread to avoid blocking the monitoring thread
            threading.Thread(
                target=self._run_analysis,
                args=(log_entry, event_type, source, target),
                daemon=True
            ).start()
        except Exception as e:
            self.logger.error(f"Error starting analysis thread: {e}")
    
    def _run_analysis(self, log_entry, event_type, source, target):
        """Run threat analysis in separate thread"""
        try:
            # Analyze the log entry
            result = self.threat_analyzer.analyze_log_entry(log_entry)
            
            # If it's a significant threat, send alert to the GUI
            if result and result.get('threat_level') in ('medium', 'high', 'critical'):
                self.event_queue.put({
                    "type": "security_alert",
                    "data": {
                        "timestamp": result.get('timestamp', datetime.now().isoformat()),
                        "log_entry": log_entry,
                        "event_type": event_type,
                        "source": source,
                        "target": target,
                        "threat_level": result.get('threat_level'),
                        "rule_violations": result.get('rule_violations', []),
                        "ai_analysis": result.get('ai_analysis'),
                        "suggested_actions": result.get('suggested_actions', [])
                    },
                    "timestamp": datetime.now().isoformat()
                })
        except Exception as e:
            self.logger.error(f"Error analyzing security event: {e}")
    
    def _is_suspicious_process(self, proc_info):
        """Check if a process is suspicious"""
        suspicious = False
        process_name = proc_info.get('name', '').lower()
        # Safely handle cmdline which can be None or a list
        cmdline = proc_info.get('cmdline', [])
        if cmdline is None:
            cmdline = []
        cmd_line = ' '.join(cmdline).lower()
        
        # Check suspicious process names
        suspicious_names = ['nc', 'netcat', 'nmap', 'tcpdump', 'wireshark', 'socat']
        if process_name in suspicious_names:
            suspicious = True
        
        # Check suspicious command line patterns
        suspicious_patterns = [
            r'curl.*\|\s*(bash|sh)',
            r'wget.*\|\s*(bash|sh)',
            r'nc\s+-l',
            r'rm\s+.*/(\.bash_history|\.zsh_history)',
            r'chmod\s+\+x\s+\S+\.sh'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, cmd_line):
                suspicious = True
                break
        
        # Suspicious paths
        if any(p in str(proc_info.get('exe', '')) for p in ['/tmp/', '/var/tmp/']):
            suspicious = True
        
        return suspicious
    
    def _is_common_system_process(self, proc_info):
        """Check if this is a common system process to reduce noise"""
        process_name = proc_info.get('name', '').lower()
        common_processes = [
            'launchd', 'kernel_task', 'systemd', 'system', 'WindowServer', 'Dock', 'Finder',
            'sshd', 'cron', 'mdnsresponder', 'mds', 'spotlight', 'loginwindow', 'distnoted',
            'launchservicesd', 'securityd', 'cfprefsd', 'SystemUIServer', 'taskgated', 'notifyd'
        ]
        
        return process_name in common_processes
    
    def _is_suspicious_file(self, filename, filepath):
        """Check if a file is suspicious"""
        filename_lower = filename.lower()
        
        # Suspicious extensions
        suspicious_exts = ['.sh', '.py', '.rb', '.pl', '.exe', '.dmg', '.pkg', '.app', '.jar', '.scr', '.bat', '.vbs']
        if any(filename_lower.endswith(ext) for ext in suspicious_exts):
            return True
        
        # Check file size (very small executables can be suspicious)
        try:
            size = os.path.getsize(filepath)
            if size < 1000 and any(filename_lower.endswith(ext) for ext in ['.sh', '.py', '.rb', '.pl', '.exe']):
                return True
        except Exception as e:
            self.logger.debug(f"Error checking file size {filepath}: {e}")
            pass
        
        return False
    
    def _get_file_hash(self, filepath):
        """Get SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.debug(f"Error hashing file {filepath}: {e}")
            return None
    
    def _check_suspicious_commands(self, history_path, shell):
        """Check shell history for suspicious commands"""
        suspicious_commands = []
        suspicious_patterns = [
            r'curl.*\|\s*(bash|sh)',
            r'wget.*\|\s*(bash|sh)', 
            r'nc\s+-l',
            r'python.*-c.*exec',
            r'chmod\s+\+x.*\.sh',
            r'sudo\s+.*(/tmp|/var/tmp)',
            r'rm\s+.*\.(log|history)',
            r'pkill.*-f.*python',
            r'launchctl\s+(load|unload)',
            r'/System/Library/.*plist'
        ]
        
        try:
            with open(history_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                # Get the last 20 commands
                recent_lines = lines[-20:]
                
                for line in recent_lines:
                    cleaned_line = line.strip()
                    if cleaned_line:
                        # For zsh history, clean timestamp if present
                        if shell == 'zsh' and cleaned_line.startswith(':'):
                            # Format: ": timestamp:duration;command"
                            parts = cleaned_line.split(';', 1)
                            if len(parts) > 1:
                                cleaned_line = parts[1]
                        
                        # Check against suspicious patterns
                        for pattern in suspicious_patterns:
                            if re.search(pattern, cleaned_line, re.IGNORECASE):
                                suspicious_commands.append(cleaned_line)
                                break
        except Exception as e:
            self.logger.error(f"Error reading {shell} history: {e}")
        
        return suspicious_commands


if __name__ == "__main__":
    # Test the monitoring thread
    print("Testing SecurityMonitoringThread")
    
    # Create event queue
    event_queue = queue.Queue()
    
    # Create and start monitoring thread
    monitor = SecurityMonitoringThread(event_queue, interval=3)
    monitor.start()
    
    try:
        # Process events from queue
        print("Processing events (press Ctrl+C to stop)...")
        while True:
            try:
                event = event_queue.get(timeout=1)
                print(f"Event: {event['type']}")
                if event['type'] == 'security_alert':
                    print(f"  Alert: {event['data']['threat_level']} - {event['data']['log_entry']}")
                elif event['type'] == 'monitoring_error':
                    print(f"  Error: {event['data']['error']}")
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        monitor.stop()
        monitor.join(timeout=1.0)
        print("Monitoring thread stopped")
