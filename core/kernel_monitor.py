#!/usr/bin/env python3
"""
NIMDA Kernel Monitor - macOS Endpoint Security Framework Integration
High-integrity monitoring using kernel-level events
"""

import subprocess
import threading
import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class KernelMonitor:
    """
    Subscribes to macOS Endpoint Security Framework events for high-integrity monitoring.
    
    This implementation uses multiple approaches since direct ES access requires entitlements:
    1. System log monitoring via log stream
    2. Process monitoring via system events  
    3. File system monitoring via fswatch
    4. Network monitoring via netstat and lsof
    """
    
    def __init__(self, event_queue):
        """Initialize the kernel monitor with an event queue for communication"""
        self.event_queue = event_queue
        self.running = False
        self.monitor_threads = []
        
        # Initialize monitoring threads
        self.log_monitor_thread = threading.Thread(target=self._monitor_system_log, daemon=True)
        self.process_monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        self.file_monitor_thread = threading.Thread(target=self._monitor_file_system, daemon=True)
        self.network_monitor_thread = threading.Thread(target=self._monitor_network, daemon=True)

    def start(self):
        """Starts the kernel event monitoring in background threads."""
        if self.running:
            logging.warning("Kernel monitor is already running")
            return
            
        self.running = True
        
        # Start all monitoring threads
        self.log_monitor_thread.start()
        self.process_monitor_thread.start()
        self.file_monitor_thread.start()
        self.network_monitor_thread.start()
        
        self.monitor_threads = [
            self.log_monitor_thread,
            self.process_monitor_thread, 
            self.file_monitor_thread,
            self.network_monitor_thread
        ]
        
        logging.info("Kernel-level monitoring started with multiple threads")

    def stop(self):
        """Stops the kernel event monitoring."""
        if not self.running:
            return
            
        self.running = False
        logging.info("Kernel monitoring stopping...")
        
        # Wait for threads to complete
        for thread in self.monitor_threads:
            if thread.is_alive():
                thread.join(timeout=2.0)

    def _monitor_system_log(self):
        """
        Monitor system log for security-relevant events using 'log stream'
        """
        logging.info("Starting system log monitoring")
        
        try:
            # Monitor specific subsystems for security events
            command = [
                'log', 'stream', '--style', 'json',
                '--predicate', 'subsystem contains "com.apple.securityd" OR subsystem contains "com.apple.kernel" OR eventMessage contains "suspicious"',
                '--level', 'info'
            ]
            
            process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            while self.running and process.poll() is None:
                try:
                    line = process.stdout.readline()
                    if line:
                        try:
                            log_data = json.loads(line.strip())
                            self._process_log_event(log_data)
                        except json.JSONDecodeError:
                            # Skip non-JSON lines
                            continue
                except Exception as e:
                    logging.warning(f"Error reading log line: {e}")
                    continue
                    
        except Exception as e:
            logging.error(f"Error in system log monitoring: {e}")
        finally:
            if process and process.poll() is None:
                process.terminate()
            logging.info("System log monitoring stopped")

    def _process_log_event(self, log_data: Dict[str, Any]):
        """Process a system log event and extract security-relevant information"""
        try:
            event_data = {
                'timestamp': log_data.get('timestamp', datetime.now().isoformat()),
                'event_type': 'system_log',
                'subsystem': log_data.get('subsystem', 'unknown'),
                'category': log_data.get('category', 'unknown'),
                'event_message': log_data.get('eventMessage', ''),
                'process': {
                    'name': log_data.get('processImagePath', 'unknown'),
                    'pid': log_data.get('processID', 0)
                },
                'severity': log_data.get('messageType', 'info')
            }
            
            # Filter for security-relevant events
            if self._is_security_relevant(event_data):
                self.event_queue.put({
                    "type": "kernel_event", 
                    "data": event_data,
                    "timestamp": datetime.now().isoformat()
                })
                
        except Exception as e:
            logging.warning(f"Error processing log event: {e}")

    def _is_security_relevant(self, event_data: Dict[str, Any]) -> bool:
        """Determine if a log event is security-relevant"""
        message = event_data.get('event_message', '').lower()
        subsystem = event_data.get('subsystem', '').lower()
        
        # Security keywords to look for
        security_keywords = [
            'authentication', 'authorization', 'denied', 'blocked', 'suspicious',
            'malware', 'virus', 'threat', 'intrusion', 'unauthorized',
            'privilege', 'escalation', 'exploit', 'attack'
        ]
        
        # Security subsystems
        security_subsystems = [
            'com.apple.securityd',
            'com.apple.kernel.proc',
            'com.apple.kernel.file',
            'com.apple.network'
        ]
        
        return (any(keyword in message for keyword in security_keywords) or
                any(subsys in subsystem for subsys in security_subsystems))

    def _monitor_processes(self):
        """Monitor process creation and termination events"""
        logging.info("Starting process monitoring")
        
        last_processes = set()
        
        while self.running:
            try:
                # Get current processes
                result = subprocess.run(
                    ['ps', 'axo', 'pid,ppid,user,command'], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                
                if result.returncode == 0:
                    current_processes = set()
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    
                    for line in lines:
                        try:
                            parts = line.strip().split(None, 3)
                            if len(parts) >= 4:
                                pid, ppid, user, command = parts
                                process_info = f"{pid}:{command}"
                                current_processes.add(process_info)
                                
                                # Check for new processes
                                if process_info not in last_processes:
                                    self._report_process_event('created', {
                                        'pid': int(pid),
                                        'ppid': int(ppid),
                                        'user': user,
                                        'command': command
                                    })
                        except (ValueError, IndexError):
                            continue
                    
                    # Check for terminated processes
                    for process_info in last_processes - current_processes:
                        pid = process_info.split(':')[0]
                        self._report_process_event('terminated', {'pid': int(pid)})
                    
                    last_processes = current_processes
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logging.warning(f"Error in process monitoring: {e}")
                time.sleep(5)

    def _report_process_event(self, action: str, process_data: Dict[str, Any]):
        """Report a process event"""
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'process',
            'action': action,
            'process': process_data
        }
        
        self.event_queue.put({
            "type": "kernel_event",
            "data": event_data,
            "timestamp": datetime.now().isoformat()
        })

    def _monitor_file_system(self):
        """Monitor file system events for suspicious activity"""
        logging.info("Starting file system monitoring")
        
        # Monitor critical directories
        critical_paths = [
            '/usr/bin',
            '/usr/sbin',
            '/bin',
            '/sbin',
            '/Applications',
            '/System/Library',
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Desktop'),
            '/tmp',
            '/var/tmp'
        ]
        
        # Use fswatch if available, otherwise fall back to periodic scanning
        try:
            # Check if fswatch is available
            subprocess.run(['which', 'fswatch'], check=True, capture_output=True)
            self._monitor_with_fswatch(critical_paths)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logging.info("fswatch not available, using periodic file scanning")
            self._monitor_with_scanning(critical_paths)

    def _monitor_with_fswatch(self, paths: list):
        """Monitor file system with fswatch"""
        try:
            cmd = ['fswatch', '-x', '-r'] + paths
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            while self.running and process.poll() is None:
                try:
                    line = process.stdout.readline()
                    if line:
                        self._process_file_event(line.strip())
                except Exception as e:
                    logging.warning(f"Error reading fswatch output: {e}")
                    
        except Exception as e:
            logging.error(f"Error with fswatch monitoring: {e}")
        finally:
            if process and process.poll() is None:
                process.terminate()

    def _monitor_with_scanning(self, paths: list):
        """Monitor file system with periodic scanning"""
        while self.running:
            try:
                for path in paths:
                    if os.path.exists(path):
                        self._scan_directory(path)
                        
                time.sleep(30)  # Scan every 30 seconds
                
            except Exception as e:
                logging.warning(f"Error in file system scanning: {e}")
                time.sleep(60)

    def _scan_directory(self, directory: str):
        """Scan a directory for recent changes"""
        try:
            current_time = time.time()
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        # Check if file was modified in last 5 minutes
                        if current_time - stat.st_mtime < 300:
                            self._report_file_event('modified', file_path, stat)
                    except (OSError, PermissionError):
                        continue
                        
                # Don't scan too deeply
                if len(root.split(os.sep)) > len(directory.split(os.sep)) + 2:
                    dirs.clear()
                    
        except Exception as e:
            logging.warning(f"Error scanning directory {directory}: {e}")

    def _process_file_event(self, event_line: str):
        """Process a file system event from fswatch"""
        try:
            # Parse fswatch XML-style output
            if 'path=' in event_line:
                path = event_line.split('path=')[1].split()[0].strip('"')
                self._report_file_event('changed', path)
        except Exception as e:
            logging.warning(f"Error processing file event: {e}")

    def _report_file_event(self, action: str, file_path: str, stat_info=None):
        """Report a file system event"""
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'file',
            'action': action,
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'directory': os.path.dirname(file_path)
        }
        
        if stat_info:
            event_data.update({
                'size': stat_info.st_size,
                'modified_time': stat_info.st_mtime,
                'permissions': oct(stat_info.st_mode)[-3:]
            })
        
        self.event_queue.put({
            "type": "kernel_event",
            "data": event_data,
            "timestamp": datetime.now().isoformat()
        })

    def _monitor_network(self):
        """Monitor network connections and activities"""
        logging.info("Starting network monitoring")
        
        last_connections = set()
        
        while self.running:
            try:
                # Monitor active network connections
                result = subprocess.run(
                    ['netstat', '-an'], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                
                if result.returncode == 0:
                    current_connections = set()
                    lines = result.stdout.strip().split('\n')
                    
                    for line in lines:
                        if 'ESTABLISHED' in line or 'LISTEN' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                protocol = parts[0]
                                local_addr = parts[3]
                                remote_addr = parts[4] if len(parts) > 4 else ''
                                state = parts[5] if len(parts) > 5 else ''
                                
                                conn_info = f"{protocol}:{local_addr}:{remote_addr}:{state}"
                                current_connections.add(conn_info)
                                
                                # Report new connections
                                if conn_info not in last_connections and state == 'ESTABLISHED':
                                    self._report_network_event('connection_established', {
                                        'protocol': protocol,
                                        'local_address': local_addr,
                                        'remote_address': remote_addr,
                                        'state': state
                                    })
                    
                    last_connections = current_connections
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logging.warning(f"Error in network monitoring: {e}")
                time.sleep(10)

    def _report_network_event(self, action: str, network_data: Dict[str, Any]):
        """Report a network event"""
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'network',
            'action': action,
            'network': network_data
        }
        
        self.event_queue.put({
            "type": "kernel_event",
            "data": event_data,
            "timestamp": datetime.now().isoformat()
        })

    def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of the current system status for AI analysis"""
        try:
            # Get process count
            ps_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            process_count = len(ps_result.stdout.strip().split('\n')) - 1 if ps_result.returncode == 0 else 0
            
            # Get connection count
            netstat_result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
            connection_count = len([line for line in netstat_result.stdout.split('\n') if 'ESTABLISHED' in line]) if netstat_result.returncode == 0 else 0
            
            # Get system load
            uptime_result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
            load_avg = uptime_result.stdout.strip() if uptime_result.returncode == 0 else "unknown"
            
            return {
                'timestamp': datetime.now().isoformat(),
                'process_count': process_count,
                'connection_count': connection_count,
                'system_load': load_avg,
                'monitoring_status': 'active' if self.running else 'inactive'
            }
            
        except Exception as e:
            logging.error(f"Error getting status summary: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'monitoring_status': 'error'
            }
