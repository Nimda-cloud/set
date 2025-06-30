#!/usr/bin/env python3
"""
NIMDA Deception Manager
Honeypot and counter-intelligence capabilities for trapping malware
"""

import os
import socket
import threading
import logging
import time
import random
from datetime import datetime
from typing import Dict, Any, Callable

class DeceptionManager:
    """
    Manages honeypots and deception strategies to trap and analyze malware.
    Creates decoy resources that are attractive to attackers.
    """
    
    def __init__(self, alert_callback: Callable[[str, Dict[str, Any]], None]):
        """
        Initialize the deception manager.
        
        Args:
            alert_callback: Function to call when honeypot is triggered
        """
        self.alert_callback = alert_callback
        self.active_honeypots = {}
        self.logger = logging.getLogger(__name__)
        self.running = True
        
        # Honeypot file paths to monitor
        self.honeypot_files = []
        self.honeypot_ports = []
        self.honeypot_processes = {}

    def deploy_honeypot_file(self, path: str = None, file_type: str = "credentials") -> str:
        """
        Creates a decoy file and monitors it for access.
        
        Args:
            path: Custom path for the honeypot file
            file_type: Type of honeypot file to create
            
        Returns:
            Path to the created honeypot file
        """
        if path is None:
            if file_type == "credentials":
                path = os.path.join(os.path.expanduser("~"), "Documents", "private_credentials.docx")
            elif file_type == "wallet":
                path = os.path.join(os.path.expanduser("~"), "Documents", "crypto_wallet.dat")
            elif file_type == "backup":
                path = os.path.join(os.path.expanduser("~"), "Documents", "backup_keys.txt")
            elif file_type == "database":
                path = os.path.join(os.path.expanduser("~"), "Documents", "users_database.db")
            else:
                path = os.path.join(os.path.expanduser("~"), "Documents", f"honeypot_{file_type}.txt")
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            # Create decoy content based on file type
            content = self._generate_decoy_content(file_type)
            
            with open(path, "w") as f:
                f.write(content)
            
            # Set file permissions to make it look legitimate but still accessible
            os.chmod(path, 0o644)
            
            # Record the honeypot file
            honeypot_info = {
                'path': path,
                'type': file_type,
                'created_time': datetime.now().isoformat(),
                'access_count': 0
            }
            
            self.honeypot_files.append(honeypot_info)
            self.active_honeypots[path] = honeypot_info
            
            self.logger.info(f"Deployed honeypot file at: {path}")
            
            # Start monitoring this file
            self._start_file_monitoring(path)
            
            return path
            
        except Exception as e:
            self.logger.error(f"Error deploying honeypot file: {e}")
            raise

    def _generate_decoy_content(self, file_type: str) -> str:
        """Generate realistic decoy content for different file types"""
        if file_type == "credentials":
            return """PRIVATE CREDENTIALS - DO NOT SHARE

Email: admin@company.com
Password: Sup3rS3cur3P@ssw0rd!
API Key: sk_test_1234567890abcdef

Server Access:
- SSH: ssh admin@production-server.com
- Database: mysql://user:password@db.company.com:3306/main

Last updated: 2024-01-15
"""
        elif file_type == "wallet":
            return """# Cryptocurrency Wallet Backup
# WARNING: This file contains private keys!

Wallet Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Private Key: 5JQQqy8a5c2bVqX6MRdEr1wK8c7vK4pL9mN3bF7gH2jK8dW5A6B
Seed Phrase: abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve

Balance: 2.5 BTC
Last Transaction: 2024-01-10 14:30:22
"""
        elif file_type == "backup":
            return """BACKUP ENCRYPTION KEYS

Primary Key: aGVsbG93b3JsZA==
Secondary Key: dGhpc2lzYXRlc3Q=
Master Password: MyS3cur3BackupP@ss

Backup Schedule:
- Daily: 02:00 AM
- Weekly: Sunday 03:00 AM
- Monthly: 1st of month 04:00 AM

Recovery Contact: backup-admin@company.com
"""
        elif file_type == "database":
            return """# Database Configuration
# Production Environment

DB_HOST=prod-db.company.com
DB_USER=root
DB_PASS=Pr0d_DB_P@ssw0rd_2024
DB_NAME=main_production

REDIS_URL=redis://prod-cache.company.com:6379/0
REDIS_PASS=R3d1s_P@ssw0rd

API_ENDPOINTS=https://api.company.com/v1/
API_SECRET=sk_live_1234567890abcdef1234567890abcdef
"""
        else:
            return f"This is a decoy {file_type} file created by NIMDA honeypot system.\nAccess to this file is monitored and logged.\nTimestamp: {datetime.now().isoformat()}"

    def _start_file_monitoring(self, file_path: str):
        """Start monitoring a honeypot file for access"""
        def monitor_file():
            last_access_time = os.path.getatime(file_path)
            last_modify_time = os.path.getmtime(file_path)
            
            while self.running and file_path in self.active_honeypots:
                try:
                    current_access_time = os.path.getatime(file_path)
                    current_modify_time = os.path.getmtime(file_path)
                    
                    # Check if file was accessed
                    if current_access_time > last_access_time:
                        self._file_accessed(file_path, 'read')
                        last_access_time = current_access_time
                    
                    # Check if file was modified
                    if current_modify_time > last_modify_time:
                        self._file_accessed(file_path, 'write')
                        last_modify_time = current_modify_time
                    
                    time.sleep(1)  # Check every second
                    
                except (OSError, FileNotFoundError):
                    # File was deleted - this is also suspicious!
                    self._file_accessed(file_path, 'delete')
                    break
                except Exception as e:
                    self.logger.warning(f"Error monitoring file {file_path}: {e}")
                    time.sleep(5)
        
        # Start monitoring in background thread
        monitor_thread = threading.Thread(target=monitor_file, daemon=True)
        monitor_thread.start()
        self.honeypot_processes[file_path] = monitor_thread

    def _file_accessed(self, file_path: str, action: str):
        """Handle honeypot file access"""
        if file_path in self.active_honeypots:
            self.active_honeypots[file_path]['access_count'] += 1
            self.active_honeypots[file_path]['last_access'] = datetime.now().isoformat()
            self.active_honeypots[file_path]['last_action'] = action
            
            # Get process information that accessed the file
            process_info = self._get_accessing_process(file_path)
            
            alert_data = {
                "file_path": file_path,
                "file_type": self.active_honeypots[file_path]['type'],
                "action": action,
                "access_count": self.active_honeypots[file_path]['access_count'],
                "process_info": process_info,
                "timestamp": datetime.now().isoformat()
            }
            
            self.logger.critical(f"HONEYPOT TRIGGERED: {action} access to {file_path}")
            self.alert_callback("honeypot_file_access", alert_data)

    def _get_accessing_process(self, file_path: str) -> Dict[str, Any]:
        """Try to determine which process accessed the file"""
        try:
            # Use lsof to find processes with the file open
            import subprocess
            result = subprocess.run(
                ['lsof', file_path], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                processes = []
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        processes.append({
                            'command': parts[0],
                            'pid': parts[1],
                            'user': parts[2] if len(parts) > 2 else 'unknown'
                        })
                return {'processes': processes}
            
        except Exception as e:
            self.logger.warning(f"Error getting process info for {file_path}: {e}")
        
        return {'processes': [], 'error': 'Could not determine accessing process'}

    def deploy_honeypot_port(self, port: int = None, service_type: str = "ssh") -> int:
        """
        Opens a TCP port and listens for any incoming connection attempts.
        
        Args:
            port: Port number to listen on (random if None)
            service_type: Type of service to emulate
            
        Returns:
            Port number that was opened
        """
        if port is None:
            # Choose a random high port
            port = random.randint(31337, 65000)
            
        def listener():
            server_socket = None
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', port))
                server_socket.listen(5)
                
                self.logger.info(f"Deployed honeypot listener on port {port} (service: {service_type})")
                
                while self.running:
                    try:
                        server_socket.settimeout(1.0)  # Non-blocking accept
                        conn, addr = server_socket.accept()
                        
                        # A connection was made! This is a high-severity event.
                        alert_data = {
                            "port": port,
                            "service_type": service_type,
                            "source_ip": addr[0],
                            "source_port": addr[1],
                            "timestamp": datetime.now().isoformat()
                        }
                        
                        self.logger.critical(f"HONEYPOT TRIGGERED: Connection to port {port} from {addr[0]}:{addr[1]}")
                        self.alert_callback("honeypot_port_access", alert_data)
                        
                        # Send fake response based on service type
                        fake_response = self._generate_service_response(service_type)
                        try:
                            conn.sendall(fake_response.encode())
                            # Try to read what the attacker sends
                            data = conn.recv(1024)
                            if data:
                                alert_data['attacker_data'] = data.decode('utf-8', errors='ignore')
                                self.logger.info(f"Received data from attacker: {data}")
                        except Exception:
                            pass
                        finally:
                            conn.close()
                            
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            self.logger.warning(f"Error in honeypot listener on port {port}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Honeypot listener on port {port} failed: {e}")
            finally:
                if server_socket:
                    server_socket.close()
                self.logger.info(f"Honeypot listener on port {port} stopped")
        
        # Start listener in background thread
        listener_thread = threading.Thread(target=listener, daemon=True)
        listener_thread.start()
        
        # Record the honeypot port
        honeypot_info = {
            'port': port,
            'service_type': service_type,
            'created_time': datetime.now().isoformat(),
            'connection_count': 0,
            'thread': listener_thread
        }
        
        self.honeypot_ports.append(honeypot_info)
        self.active_honeypots[f"port_{port}"] = honeypot_info
        
        return port

    def _generate_service_response(self, service_type: str) -> str:
        """Generate fake service banner/response"""
        if service_type == "ssh":
            return "SSH-2.0-OpenSSH_8.1\r\n"
        elif service_type == "ftp":
            return "220 Welcome to FTP server\r\n"
        elif service_type == "telnet":
            return "Welcome to Telnet Server\r\nLogin: "
        elif service_type == "smtp":
            return "220 mail.server.com ESMTP Sendmail 8.14.4\r\n"
        elif service_type == "http":
            return "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Welcome</h1></body></html>"
        else:
            return f"Welcome to {service_type} service\r\n"

    def deploy_honeypot_network_share(self, share_name: str = "SharedDocs") -> str:
        """Deploy a fake network share honeypot"""
        try:
            share_path = os.path.join(os.path.expanduser("~"), "FakeShare", share_name)
            os.makedirs(share_path, exist_ok=True)
            
            # Create some enticing fake files
            fake_files = [
                ("passwords.txt", "credentials"),
                ("financial_data.xlsx", "database"),
                ("private_keys.pem", "backup"),
                ("user_accounts.csv", "database")
            ]
            
            for filename, file_type in fake_files:
                file_path = os.path.join(share_path, filename)
                content = self._generate_decoy_content(file_type)
                with open(file_path, "w") as f:
                    f.write(content)
                
                # Monitor each file
                self._start_file_monitoring(file_path)
            
            self.logger.info(f"Deployed network share honeypot at: {share_path}")
            return share_path
            
        except Exception as e:
            self.logger.error(f"Error deploying network share honeypot: {e}")
            raise

    def deploy_fake_wifi_network(self, network_name: str = "Free_WiFi_Corporate") -> Dict[str, Any]:
        """Deploy a fake WiFi network honeypot (conceptual - requires additional tools)"""
        # This would require tools like hostapd in a real implementation
        # For now, we'll just log the intent and return info
        
        honeypot_info = {
            'type': 'fake_wifi',
            'network_name': network_name,
            'created_time': datetime.now().isoformat(),
            'status': 'simulated',
            'note': 'Requires external tools like hostapd for real implementation'
        }
        
        self.logger.info(f"Fake WiFi network '{network_name}' registered (simulated)")
        return honeypot_info

    def create_decoy_process(self, process_name: str = "DatabaseBackup") -> Dict[str, Any]:
        """Create a decoy process that looks attractive to attackers"""
        def decoy_process():
            self.logger.info(f"Started decoy process: {process_name}")
            
            # Simulate a process doing something interesting
            while self.running:
                time.sleep(random.randint(30, 120))  # Random activity intervals
                
                # Log fake activity
                activities = [
                    "Processing financial records...",
                    "Backing up user credentials...",
                    "Synchronizing with remote database...",
                    "Encrypting sensitive files...",
                    "Transferring data to secure storage..."
                ]
                
                activity = random.choice(activities)
                self.logger.info(f"[{process_name}] {activity}")
        
        # Start decoy process
        decoy_thread = threading.Thread(target=decoy_process, daemon=True, name=process_name)
        decoy_thread.start()
        
        process_info = {
            'name': process_name,
            'thread': decoy_thread,
            'created_time': datetime.now().isoformat(),
            'type': 'decoy_process'
        }
        
        self.active_honeypots[f"process_{process_name}"] = process_info
        return process_info

    def get_honeypot_status(self) -> Dict[str, Any]:
        """Get status of all active honeypots"""
        status = {
            'active_count': len(self.active_honeypots),
            'files': len(self.honeypot_files),
            'ports': len(self.honeypot_ports),
            'total_alerts': sum(hp.get('access_count', 0) for hp in self.active_honeypots.values()),
            'honeypots': []
        }
        
        for key, honeypot in self.active_honeypots.items():
            status['honeypots'].append({
                'id': key,
                'type': honeypot.get('type', 'unknown'),
                'created_time': honeypot.get('created_time'),
                'access_count': honeypot.get('access_count', 0),
                'last_access': honeypot.get('last_access', 'never')
            })
        
        return status

    def remove_honeypot(self, honeypot_id: str) -> bool:
        """Remove a specific honeypot"""
        try:
            if honeypot_id in self.active_honeypots:
                honeypot = self.active_honeypots[honeypot_id]
                
                # If it's a file honeypot, delete the file
                if 'path' in honeypot:
                    try:
                        os.remove(honeypot['path'])
                    except OSError:
                        pass
                
                # If it has a thread, we'll let it naturally stop when self.running becomes False
                
                del self.active_honeypots[honeypot_id]
                self.logger.info(f"Removed honeypot: {honeypot_id}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error removing honeypot {honeypot_id}: {e}")
            return False

    def shutdown(self):
        """Shutdown all honeypots"""
        self.running = False
        
        # Clean up files
        for honeypot in self.honeypot_files:
            try:
                if os.path.exists(honeypot['path']):
                    os.remove(honeypot['path'])
            except OSError:
                pass
        
        self.logger.info("Deception manager shutdown complete")
