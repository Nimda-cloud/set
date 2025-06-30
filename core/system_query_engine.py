#!/usr/bin/env python3
"""
NIMDA System Query Engine
Translates natural language queries from AI into actual system checks
"""

import subprocess
import psutil
import os
import logging
import time
from datetime import datetime
from typing import Dict, Any, List
import requests
import hashlib

class SystemQueryEngine:
    """
    Executes natural language queries by mapping them to system functions.
    This serves as the "tool" interface for the AI agent to interact with the system.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Cache for expensive operations
        self._process_cache = {}
        self._cache_timeout = 30  # 30 seconds
        
    def execute_query(self, query_text: str) -> Dict[str, Any]:
        """
        Executes a natural language query by mapping it to a function.
        Returns results in a structured format for AI analysis.
        """
        query_text = query_text.lower().strip()
        
        try:
            # Process signature queries
            if "processes that are not signed" in query_text or "unsigned processes" in query_text:
                return self.find_unsigned_processes()
            elif "processes" in query_text and ("suspicious" in query_text or "unknown" in query_text):
                return self.find_suspicious_processes()
            
            # Network queries
            elif "network traffic" in query_text and "country" in query_text:
                return self.check_traffic_by_country()
            elif "network connections" in query_text and ("suspicious" in query_text or "external" in query_text):
                return self.find_suspicious_connections()
            
            # File system queries
            elif "recently created" in query_text and ("executable" in query_text or "files" in query_text):
                return self.find_recent_executables()
            elif "temporary" in query_text and ("files" in query_text or "directory" in query_text):
                return self.scan_temporary_directories()
            
            # System queries
            elif "high cpu" in query_text or "resource usage" in query_text:
                return self.find_high_resource_processes()
            elif "startup" in query_text and ("items" in query_text or "programs" in query_text):
                return self.check_startup_items()
            elif "system modifications" in query_text or "system changes" in query_text:
                return self.check_system_modifications()
            
            # Security queries
            elif "failed login" in query_text or "authentication" in query_text:
                return self.check_authentication_events()
            elif "privilege escalation" in query_text or "sudo" in query_text:
                return self.check_privilege_escalation()
            
            else:
                return {"error": f"Query not understood: {query_text}", "suggestions": self.get_query_suggestions()}
                
        except Exception as e:
            self.logger.error(f"Error executing query '{query_text}': {e}")
            return {"error": str(e), "query": query_text}

    def find_unsigned_processes(self) -> Dict[str, Any]:
        """Find processes that are not code signed by Apple or known developers"""
        try:
            unsigned_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if proc.info['exe']:
                        # Check code signature using codesign
                        result = subprocess.run(
                            ['codesign', '-dv', proc.info['exe']], 
                            capture_output=True, 
                            text=True, 
                            timeout=5
                        )
                        
                        if result.returncode != 0:
                            # Not signed or invalid signature
                            unsigned_processes.append({
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'path': proc.info['exe'],
                                'reason': 'unsigned_or_invalid'
                            })
                        else:
                            # Check if it's signed by Apple
                            authority_result = subprocess.run(
                                ['codesign', '-dv', '--verbose=4', proc.info['exe']], 
                                capture_output=True, 
                                text=True, 
                                timeout=5
                            )
                            
                            if "Apple" not in authority_result.stderr:
                                unsigned_processes.append({
                                    'pid': proc.info['pid'],
                                    'name': proc.info['name'],
                                    'path': proc.info['exe'],
                                    'reason': 'third_party_signed'
                                })
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied, subprocess.TimeoutExpired):
                    continue
                except Exception as e:
                    self.logger.warning(f"Error checking signature for {proc.info.get('name', 'unknown')}: {e}")
                    continue
            
            return {
                "status": "success",
                "unsigned_processes": unsigned_processes,
                "count": len(unsigned_processes),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def find_suspicious_processes(self) -> Dict[str, Any]:
        """Find processes that exhibit suspicious characteristics"""
        try:
            suspicious_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    suspicion_reasons = []
                    
                    # Check for high CPU usage
                    if proc.info['cpu_percent'] and proc.info['cpu_percent'] > 80:
                        suspicion_reasons.append('high_cpu_usage')
                    
                    # Check for suspicious names
                    if proc.info['name']:
                        suspicious_names = ['miner', 'crypto', 'coin', 'hash', 'bot', 'trojan', 'malware']
                        if any(name in proc.info['name'].lower() for name in suspicious_names):
                            suspicion_reasons.append('suspicious_name')
                    
                    # Check for processes running from temporary directories
                    if proc.info['exe']:
                        temp_dirs = ['/tmp', '/var/tmp', os.path.expanduser('~/Downloads')]
                        if any(proc.info['exe'].startswith(temp_dir) for temp_dir in temp_dirs):
                            suspicion_reasons.append('temp_directory_execution')
                    
                    # Check for processes with unusual command lines
                    if proc.info['cmdline']:
                        cmdline = ' '.join(proc.info['cmdline']).lower()
                        suspicious_patterns = ['base64', 'curl', 'wget', 'nc ', 'netcat', 'python -c', 'bash -c']
                        if any(pattern in cmdline for pattern in suspicious_patterns):
                            suspicion_reasons.append('suspicious_command_line')
                    
                    if suspicion_reasons:
                        suspicious_processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'path': proc.info['exe'],
                            'cmdline': proc.info['cmdline'],
                            'cpu_percent': proc.info['cpu_percent'],
                            'memory_percent': proc.info['memory_percent'],
                            'reasons': suspicion_reasons
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                "status": "success",
                "suspicious_processes": suspicious_processes,
                "count": len(suspicious_processes),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def check_traffic_by_country(self) -> Dict[str, Any]:
        """Check network traffic and determine country origins"""
        try:
            suspicious_connections = []
            
            # Get all network connections
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.raddr and conn.raddr.ip:
                    # Skip local/private IPs
                    if self._is_private_ip(conn.raddr.ip):
                        continue
                    
                    # Try to get geolocation info (simplified - in production use MaxMind GeoIP)
                    country_info = self._get_ip_country(conn.raddr.ip)
                    
                    # Flag connections to high-risk countries
                    high_risk_countries = ['CN', 'RU', 'KP', 'IR']  # Example list
                    if country_info.get('country_code') in high_risk_countries:
                        try:
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            suspicious_connections.append({
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                                'status': conn.status,
                                'process_name': proc.name() if proc else 'unknown',
                                'pid': conn.pid,
                                'country': country_info.get('country', 'unknown'),
                                'country_code': country_info.get('country_code', 'unknown')
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            
            return {
                "status": "success",
                "suspicious_connections": suspicious_connections,
                "count": len(suspicious_connections),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private/local"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except Exception:
            return False

    def _get_ip_country(self, ip: str) -> Dict[str, str]:
        """Get country information for IP address (simplified implementation)"""
        try:
            # Using ipapi.co for demo - in production use local MaxMind database
            response = requests.get(f"http://ipapi.co/{ip}/json/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name', 'unknown'),
                    'country_code': data.get('country_code', 'unknown')
                }
        except Exception:
            pass
        return {'country': 'unknown', 'country_code': 'unknown'}

    def find_suspicious_connections(self) -> Dict[str, Any]:
        """Find suspicious network connections"""
        try:
            suspicious_connections = []
            
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.raddr:
                    suspicion_reasons = []
                    
                    # Check for unusual ports
                    suspicious_ports = [1337, 31337, 4444, 5555, 6666, 9999]
                    if conn.raddr.port in suspicious_ports:
                        suspicion_reasons.append('suspicious_port')
                    
                    # Check for external connections
                    if not self._is_private_ip(conn.raddr.ip):
                        suspicion_reasons.append('external_connection')
                    
                    # Check for high port numbers (possible backdoor)
                    if conn.raddr.port > 50000:
                        suspicion_reasons.append('high_port_number')
                    
                    if suspicion_reasons:
                        try:
                            proc = psutil.Process(conn.pid) if conn.pid else None
                            suspicious_connections.append({
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                                'status': conn.status,
                                'process_name': proc.name() if proc else 'unknown',
                                'pid': conn.pid,
                                'reasons': suspicion_reasons
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            
            return {
                "status": "success",
                "suspicious_connections": suspicious_connections,
                "count": len(suspicious_connections),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def find_recent_executables(self) -> Dict[str, Any]:
        """Find recently created executable files"""
        try:
            recent_executables = []
            current_time = time.time()
            time_threshold = current_time - (24 * 3600)  # Last 24 hours
            
            # Directories to scan
            scan_dirs = [
                os.path.expanduser('~/Downloads'),
                os.path.expanduser('~/Desktop'),
                '/tmp',
                '/var/tmp',
                '/Applications'
            ]
            
            for scan_dir in scan_dirs:
                if not os.path.exists(scan_dir):
                    continue
                    
                for root, dirs, files in os.walk(scan_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            stat_info = os.stat(file_path)
                            
                            # Check if file was created recently
                            if stat_info.st_ctime > time_threshold:
                                # Check if file is executable
                                if os.access(file_path, os.X_OK) or file.endswith(('.app', '.pkg', '.dmg')):
                                    recent_executables.append({
                                        'path': file_path,
                                        'name': file,
                                        'size': stat_info.st_size,
                                        'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                                        'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                                        'permissions': oct(stat_info.st_mode)[-3:],
                                        'hash': self._calculate_file_hash(file_path)
                                    })
                        except (OSError, PermissionError):
                            continue
                    
                    # Limit recursion depth
                    if len(root.split(os.sep)) > len(scan_dir.split(os.sep)) + 3:
                        dirs.clear()
            
            return {
                "status": "success",
                "recent_executables": recent_executables,
                "count": len(recent_executables),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return "unknown"

    def scan_temporary_directories(self) -> Dict[str, Any]:
        """Scan temporary directories for suspicious files"""
        try:
            suspicious_files = []
            temp_dirs = ['/tmp', '/var/tmp', os.path.expanduser('~/Downloads')]
            
            for temp_dir in temp_dirs:
                if not os.path.exists(temp_dir):
                    continue
                    
                for item in os.listdir(temp_dir):
                    item_path = os.path.join(temp_dir, item)
                    try:
                        if os.path.isfile(item_path):
                            stat_info = os.stat(item_path)
                            
                            # Check for suspicious characteristics
                            reasons = []
                            if os.access(item_path, os.X_OK):
                                reasons.append('executable')
                            if item.startswith('.'):
                                reasons.append('hidden_file')
                            if any(ext in item.lower() for ext in ['.sh', '.py', '.pl', '.rb']):
                                reasons.append('script_file')
                            
                            if reasons:
                                suspicious_files.append({
                                    'path': item_path,
                                    'name': item,
                                    'size': stat_info.st_size,
                                    'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                                    'reasons': reasons
                                })
                    except (OSError, PermissionError):
                        continue
            
            return {
                "status": "success",
                "suspicious_files": suspicious_files,
                "count": len(suspicious_files),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def find_high_resource_processes(self) -> Dict[str, Any]:
        """Find processes using high CPU or memory resources"""
        try:
            high_resource_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    if (proc.info['cpu_percent'] and proc.info['cpu_percent'] > 50) or \
                       (proc.info['memory_percent'] and proc.info['memory_percent'] > 20):
                        high_resource_processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cpu_percent': proc.info['cpu_percent'],
                            'memory_percent': proc.info['memory_percent']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by resource usage
            high_resource_processes.sort(key=lambda x: (x['cpu_percent'] or 0) + (x['memory_percent'] or 0), reverse=True)
            
            return {
                "status": "success",
                "high_resource_processes": high_resource_processes[:10],  # Top 10
                "count": len(high_resource_processes),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def check_startup_items(self) -> Dict[str, Any]:
        """Check startup items and launch agents"""
        try:
            startup_items = []
            
            # LaunchAgents directories
            launch_dirs = [
                '/Library/LaunchAgents',
                '/Library/LaunchDaemons',
                os.path.expanduser('~/Library/LaunchAgents')
            ]
            
            for launch_dir in launch_dirs:
                if os.path.exists(launch_dir):
                    for item in os.listdir(launch_dir):
                        if item.endswith('.plist'):
                            item_path = os.path.join(launch_dir, item)
                            startup_items.append({
                                'name': item,
                                'path': item_path,
                                'directory': launch_dir,
                                'type': 'LaunchAgent' if 'LaunchAgents' in launch_dir else 'LaunchDaemon'
                            })
            
            return {
                "status": "success",
                "startup_items": startup_items,
                "count": len(startup_items),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def check_system_modifications(self) -> Dict[str, Any]:
        """Check for recent system modifications"""
        try:
            modifications = []
            
            # Check system logs for modifications
            try:
                result = subprocess.run(
                    ['log', 'show', '--predicate', 'eventMessage contains "modified"', '--last', '1h', '--style', 'compact'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    log_lines = result.stdout.strip().split('\n')
                    for line in log_lines[:20]:  # Limit to 20 entries
                        if 'modified' in line.lower():
                            modifications.append({
                                'type': 'system_log',
                                'description': line.strip(),
                                'timestamp': datetime.now().isoformat()
                            })
            except Exception:
                pass
            
            return {
                "status": "success",
                "modifications": modifications,
                "count": len(modifications),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def check_authentication_events(self) -> Dict[str, Any]:
        """Check for authentication events and failed logins"""
        try:
            auth_events = []
            
            # Check system logs for authentication events
            try:
                result = subprocess.run(
                    ['log', 'show', '--predicate', 'subsystem contains "com.apple.securityd" OR eventMessage contains "authentication"', '--last', '1h'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    log_lines = result.stdout.strip().split('\n')
                    for line in log_lines[:15]:  # Limit to 15 entries
                        if any(keyword in line.lower() for keyword in ['auth', 'login', 'fail', 'denied']):
                            auth_events.append({
                                'type': 'authentication',
                                'description': line.strip(),
                                'timestamp': datetime.now().isoformat()
                            })
            except Exception:
                pass
            
            return {
                "status": "success",
                "auth_events": auth_events,
                "count": len(auth_events),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def check_privilege_escalation(self) -> Dict[str, Any]:
        """Check for privilege escalation attempts"""
        try:
            escalation_events = []
            
            # Check for recent sudo usage
            try:
                result = subprocess.run(
                    ['log', 'show', '--predicate', 'eventMessage contains "sudo"', '--last', '1h'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    log_lines = result.stdout.strip().split('\n')
                    for line in log_lines[:10]:  # Limit to 10 entries
                        if 'sudo' in line.lower():
                            escalation_events.append({
                                'type': 'sudo_usage',
                                'description': line.strip(),
                                'timestamp': datetime.now().isoformat()
                            })
            except Exception:
                pass
            
            return {
                "status": "success",
                "escalation_events": escalation_events,
                "count": len(escalation_events),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def get_query_suggestions(self) -> List[str]:
        """Get list of supported query types"""
        return [
            "Are there any running processes that are not signed by Apple or a known developer?",
            "Is there any network traffic going to a country known for cyber attacks?",
            "Are there any recently created executable files in temporary directories?",
            "Show me processes with high CPU or memory usage",
            "Check for suspicious network connections",
            "Find startup items and launch agents",
            "Look for recent system modifications",
            "Check for failed authentication attempts",
            "Search for privilege escalation attempts"
        ]
