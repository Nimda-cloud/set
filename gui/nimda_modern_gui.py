#!/usr/bin/env python3
"""
NIMDA Security System - Modern GUI Implementation
Advanced security monitoring with multithreading and responsive design
"""

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import threading
import queue
import time
import os
import sys
from datetime import datetime
import psutil
import logging
import json

# Add root directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import NIMDA components
from core.optimized_rule_manager import OptimizedRuleManager
from core.enhanced_threat_analyzer import EnhancedThreatAnalyzer
from core.security_monitoring_thread import SecurityMonitoringThread
from llm_security_agent import LLMSecurityAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nimda_gui.log"),
        logging.StreamHandler()
    ]
)

class NimdaModernGUI:
    """Modern NIMDA Security System GUI with non-blocking architecture"""
    
    def __init__(self, root, db_path="data/security_events.db"):
        """Initialize the GUI
        
        Args:
            root: The Tkinter root window
            db_path: Path to the security events database
        """
        self.root = root
        self.root.title("NIMDA - Advanced Security")
        self.root.geometry("1280x800")
        
        # Initialize style
        self.style = ttk.Style(theme='darkly')
        
        # Event queue for thread communication
        self.event_queue = queue.Queue()
        
        # Initialize database directory if needed
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Security components with optimized implementations
        self.rule_manager = OptimizedRuleManager()
        self.threat_analyzer = EnhancedThreatAnalyzer(db_path=db_path)
        self.llm_agent = LLMSecurityAgent()
        
        # Monitoring thread with optimized implementation
        self.monitor_thread = SecurityMonitoringThread(
            event_queue=self.event_queue,
            interval=2,
            db_path=db_path
        )
        
        # Initialize UI components
        self.create_widgets()
        
        # Start monitoring thread
        self.monitor_thread.start()
        
        # Set up queue processing
        self.root.after(100, self.process_queue)
        
        # Register cleanup
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container with PanedWindow
        self.main_pane = ttk.PanedWindow(self.root, orient=HORIZONTAL)
        self.main_pane.pack(fill=BOTH, expand=True)
        
        # Left panel for alerts and navigation
        self.left_frame = ttk.Frame(self.main_pane, padding=10)
        self.main_pane.add(self.left_frame, weight=1)
        
        # Right panel for detailed information
        self.right_frame = ttk.Frame(self.main_pane, padding=10)
        self.main_pane.add(self.right_frame, weight=3)
        
        # Create left panel content
        self.create_alerts_panel()
        
        # Create right panel content with notebook
        self.create_notebook()
        
        # Status bar at bottom
        self.create_status_bar()
    
    def create_alerts_panel(self):
        """Create alerts panel in left frame"""
        # Alerts header
        alerts_label = ttk.Label(self.left_frame, text="Active Alerts", font=("-size 14 -weight bold"))
        alerts_label.pack(pady=10)
        
        # Alerts treeview
        self.alerts_tree = ttk.Treeview(
            self.left_frame, 
            columns=("time", "severity", "description"), 
            show="headings", 
            bootstyle="info"
        )
        self.alerts_tree.heading("time", text="Time")
        self.alerts_tree.heading("severity", text="Severity")
        self.alerts_tree.heading("description", text="Description")
        
        self.alerts_tree.column("time", width=80)
        self.alerts_tree.column("severity", width=80)
        self.alerts_tree.column("description", width=200)
        
        self.alerts_tree.pack(fill=BOTH, expand=True)
        
        # Configure tags for severity levels
        self.alerts_tree.tag_configure('critical', background=self.style.colors.danger)
        self.alerts_tree.tag_configure('high', background=self.style.colors.warning)
        self.alerts_tree.tag_configure('medium', background=self.style.colors.info)
        
        # Quick actions button frame
        actions_frame = ttk.Frame(self.left_frame)
        actions_frame.pack(fill=X, pady=10)
        
        # Quick action buttons
        ttk.Button(
            actions_frame, 
            text="Run Full Scan",
            command=self.run_full_scan,
            bootstyle=SUCCESS
        ).pack(fill=X, pady=2)
        
        ttk.Button(
            actions_frame,
            text="Update Rules",
            command=self.update_rules,
            bootstyle=INFO
        ).pack(fill=X, pady=2)
    
    def create_notebook(self):
        """Create the main notebook in right frame"""
        self.notebook = ttk.Notebook(self.right_frame)
        self.notebook.pack(fill=BOTH, expand=True)
        
        # Create the tabs
        self.create_dashboard_tab()
        self.create_network_tab()
        self.create_processes_tab()
        self.create_ai_tab()
        self.create_logs_tab()
    
    def create_dashboard_tab(self):
        """Create the main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")
        
        # Use grid layout for dashboard
        dashboard_frame.columnconfigure(0, weight=2)
        dashboard_frame.columnconfigure(1, weight=1)
        dashboard_frame.rowconfigure(0, weight=1)
        dashboard_frame.rowconfigure(1, weight=1)
        dashboard_frame.rowconfigure(2, weight=1)
        
        # System metrics frame (top left)
        metrics_frame = ttk.LabelFrame(dashboard_frame, text="System Metrics", padding=10)
        metrics_frame.grid(row=0, column=0, padx=5, pady=5, sticky='nsew')
        
        # CPU usage
        ttk.Label(metrics_frame, text="CPU Usage:").grid(row=0, column=0, sticky=W, pady=2)
        self.cpu_bar = ttk.Progressbar(metrics_frame, bootstyle="success-striped")
        self.cpu_bar.grid(row=0, column=1, sticky=EW, padx=5, pady=2)
        self.cpu_label = ttk.Label(metrics_frame, text="0%")
        self.cpu_label.grid(row=0, column=2, sticky=E)
        
        # Memory usage
        ttk.Label(metrics_frame, text="Memory Usage:").grid(row=1, column=0, sticky=W, pady=2)
        self.memory_bar = ttk.Progressbar(metrics_frame, bootstyle="info-striped")
        self.memory_bar.grid(row=1, column=1, sticky=EW, padx=5, pady=2)
        self.memory_label = ttk.Label(metrics_frame, text="0%")
        self.memory_label.grid(row=1, column=2, sticky=E)
        
        # Disk usage
        ttk.Label(metrics_frame, text="Disk Usage:").grid(row=2, column=0, sticky=W, pady=2)
        self.disk_bar = ttk.Progressbar(metrics_frame, bootstyle="warning-striped")
        self.disk_bar.grid(row=2, column=1, sticky=EW, padx=5, pady=2)
        self.disk_label = ttk.Label(metrics_frame, text="0%")
        self.disk_label.grid(row=2, column=2, sticky=E)
        
        # Make the progress bars expandable
        metrics_frame.columnconfigure(1, weight=1)
        
        # Network activity frame (bottom left)
        network_frame = ttk.LabelFrame(dashboard_frame, text="Network Activity", padding=10)
        network_frame.grid(row=1, column=0, padx=5, pady=5, sticky='nsew')
        
        # Network labels
        self.network_in_label = ttk.Label(network_frame, text="Received: 0 B/s")
        self.network_in_label.pack(anchor=W, pady=2)
        
        self.network_out_label = ttk.Label(network_frame, text="Sent: 0 B/s")
        self.network_out_label.pack(anchor=W, pady=2)
        
        self.active_connections_label = ttk.Label(network_frame, text="Active Connections: 0")
        self.active_connections_label.pack(anchor=W, pady=2)
        
        # Security status frame (top right)
        status_frame = ttk.LabelFrame(dashboard_frame, text="Security Status", padding=10)
        status_frame.grid(row=0, column=1, rowspan=1, padx=5, pady=5, sticky='nsew')
        
        self.threat_level_label = ttk.Label(
            status_frame, 
            text="NORMAL", 
            font=("-size 16 -weight bold"),
            foreground=self.style.colors.success
        )
        self.threat_level_label.pack(anchor=CENTER, pady=10)
        
        self.last_scan_label = ttk.Label(status_frame, text="Last Scan: Never")
        self.last_scan_label.pack(anchor=W, pady=2)
        
        self.rule_count_label = ttk.Label(status_frame, text="Active Rules: 0")
        self.rule_count_label.pack(anchor=W, pady=2)
        
        self.alert_count_label = ttk.Label(status_frame, text="Active Alerts: 0")
        self.alert_count_label.pack(anchor=W, pady=2)
        
        # Recent events frame (bottom right)
        events_frame = ttk.LabelFrame(dashboard_frame, text="Recent Events", padding=10)
        events_frame.grid(row=1, column=1, rowspan=1, padx=5, pady=5, sticky='nsew')
        
        self.events_text = ttk.Text(events_frame, height=5, width=30, wrap=WORD)
        self.events_text.pack(fill=BOTH, expand=True)
        
        # Action log (bottom)
        log_frame = ttk.LabelFrame(dashboard_frame, text="Action Log", padding=10)
        log_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')
        
        self.action_text = ttk.Text(log_frame, height=10, wrap=WORD)
        self.action_text.pack(fill=BOTH, expand=True)
        
        # Add a sample log entry
        self.add_action_log("NIMDA Security System initialized")
    
    def create_network_tab(self):
        """Create the network monitoring tab"""
        network_frame = ttk.Frame(self.notebook)
        self.notebook.add(network_frame, text="🌐 Network")
        
        # Create a frame for the connections list
        connections_frame = ttk.LabelFrame(network_frame, text="Active Connections", padding=10)
        connections_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # Create a treeview for connections
        columns = ("local", "remote", "process", "status")
        self.connections_tree = ttk.Treeview(
            connections_frame, 
            columns=columns, 
            show="headings", 
            bootstyle="success"
        )
        
        # Configure columns
        self.connections_tree.heading("local", text="Local Address")
        self.connections_tree.heading("remote", text="Remote Address")
        self.connections_tree.heading("process", text="Process")
        self.connections_tree.heading("status", text="Status")
        
        self.connections_tree.column("local", width=150)
        self.connections_tree.column("remote", width=150)
        self.connections_tree.column("process", width=100)
        self.connections_tree.column("status", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(connections_frame, orient=VERTICAL, command=self.connections_tree.yview)
        self.connections_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.connections_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        # Buttons frame
        buttons_frame = ttk.Frame(network_frame)
        buttons_frame.pack(fill=X, padx=10, pady=5)
        
        ttk.Button(
            buttons_frame, 
            text="Refresh",
            command=self.refresh_connections,
            bootstyle="info"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            buttons_frame, 
            text="Block Selected",
            command=self.block_selected_connection,
            bootstyle="danger"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            buttons_frame, 
            text="Analyze Selected",
            command=self.analyze_selected_connection,
            bootstyle="warning"
        ).pack(side=LEFT, padx=5)
    
    def create_processes_tab(self):
        """Create the processes tab"""
        processes_frame = ttk.Frame(self.notebook)
        self.notebook.add(processes_frame, text="⚙️ Processes")
        
        # Create a frame for the processes list
        list_frame = ttk.LabelFrame(processes_frame, text="Running Processes", padding=10)
        list_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # Create a treeview for processes
        columns = ("pid", "name", "user", "cpu", "memory", "status")
        self.processes_tree = ttk.Treeview(
            list_frame, 
            columns=columns, 
            show="headings", 
            bootstyle="info"
        )
        
        # Configure columns
        self.processes_tree.heading("pid", text="PID")
        self.processes_tree.heading("name", text="Name")
        self.processes_tree.heading("user", text="User")
        self.processes_tree.heading("cpu", text="CPU%")
        self.processes_tree.heading("memory", text="Memory%")
        self.processes_tree.heading("status", text="Status")
        
        self.processes_tree.column("pid", width=70)
        self.processes_tree.column("name", width=150)
        self.processes_tree.column("user", width=100)
        self.processes_tree.column("cpu", width=70)
        self.processes_tree.column("memory", width=70)
        self.processes_tree.column("status", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=VERTICAL, command=self.processes_tree.yview)
        self.processes_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.processes_tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        # Buttons frame
        buttons_frame = ttk.Frame(processes_frame)
        buttons_frame.pack(fill=X, padx=10, pady=5)
        
        ttk.Button(
            buttons_frame, 
            text="Refresh",
            command=self.refresh_processes,
            bootstyle="info"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            buttons_frame, 
            text="Terminate Selected",
            command=self.terminate_selected_process,
            bootstyle="danger"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            buttons_frame, 
            text="Analyze Selected",
            command=self.analyze_selected_process,
            bootstyle="warning"
        ).pack(side=LEFT, padx=5)
    
    def create_ai_tab(self):
        """Create the AI analysis tab"""
        ai_frame = ttk.Frame(self.notebook)
        self.notebook.add(ai_frame, text="🤖 AI Analysis")
        
        # Status section
        status_frame = ttk.LabelFrame(ai_frame, text="AI Status", padding=10)
        status_frame.pack(fill=X, padx=10, pady=5)
        
        self.ai_status_label = ttk.Label(status_frame, text="Checking AI connection...")
        self.ai_status_label.pack(anchor=W, pady=5)
        
        ttk.Button(
            status_frame, 
            text="Check Connection",
            command=self.check_ai_connection,
            bootstyle="info"
        ).pack(anchor=W, pady=5)
        
        # Query section
        query_frame = ttk.LabelFrame(ai_frame, text="Security Analysis", padding=10)
        query_frame.pack(fill=X, padx=10, pady=5)
        
        self.query_entry = ttk.Entry(query_frame, width=60)
        self.query_entry.pack(fill=X, pady=5)
        self.query_entry.insert(0, "Ask about security threats, analyze connections, or get recommendations...")
        
        # Query buttons
        actions_frame = ttk.Frame(query_frame)
        actions_frame.pack(fill=X, pady=5)
        
        ttk.Button(
            actions_frame, 
            text="Analyze Threats",
            command=self.analyze_threats,
            bootstyle="warning"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            actions_frame, 
            text="Get Recommendations",
            command=self.get_recommendations,
            bootstyle="info"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            actions_frame, 
            text="Security Report",
            command=self.security_report,
            bootstyle="success"
        ).pack(side=LEFT, padx=5)
        
        # Response area
        response_frame = ttk.LabelFrame(ai_frame, text="AI Response", padding=10)
        response_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        self.response_text = ttk.Text(response_frame, wrap=WORD)
        self.response_text.pack(fill=BOTH, expand=True)
        
    def create_logs_tab(self):
        """Create the logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="📜 Logs")
        
        # Create a frame for the log viewer
        log_viewer_frame = ttk.LabelFrame(logs_frame, text="Security Logs", padding=10)
        log_viewer_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # Create a text widget for logs
        self.logs_text = ttk.Text(log_viewer_frame, wrap=WORD)
        self.logs_text.pack(fill=BOTH, expand=True)
        
        # Buttons frame
        buttons_frame = ttk.Frame(logs_frame)
        buttons_frame.pack(fill=X, padx=10, pady=5)
        
        ttk.Button(
            buttons_frame, 
            text="Clear Logs",
            command=self.clear_logs,
            bootstyle="warning"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            buttons_frame, 
            text="Export Logs",
            command=self.export_logs,
            bootstyle="info"
        ).pack(side=LEFT, padx=5)
    
    def create_status_bar(self):
        """Create the status bar at the bottom of the window"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=BOTTOM, fill=X)
        
        self.status_label = ttk.Label(status_frame, text="Ready")
        self.status_label.pack(side=LEFT, padx=5)
        
        self.monitoring_status = ttk.Label(status_frame, text="Monitoring: Active")
        self.monitoring_status.pack(side=RIGHT, padx=5)
    
    def process_queue(self):
        """Process events from the monitoring thread queue"""
        try:
            # Process all available events
            while True:
                event = self.event_queue.get_nowait()
                
                event_type = event.get("type", "")
                event_data = event.get("data", {})
                event_timestamp = event.get("timestamp", datetime.now().isoformat())
                
                if event_type == "network_update":
                    self.handle_network_update(event_data)
                elif event_type == "process_update":
                    self.handle_process_update(event_data)
                elif event_type == "system_info_update":
                    self.handle_system_info_update(event_data)
                elif event_type == "security_events":
                    self.handle_security_events(event_data)
                elif event_type == "monitoring_error":
                    self.handle_monitoring_error(event_data)
                elif event_type == "monitoring_status":
                    self.handle_monitoring_status(event_data)
                elif event_type == "security_alert":
                    # New event type from our enhanced monitoring thread
                    self.handle_security_alert(event_data, event_timestamp)
                elif event_type == "file_change":
                    # File system monitoring events
                    self.handle_file_change(event_data, event_timestamp)
                elif event_type == "usb_device":
                    # USB device events
                    self.handle_usb_device(event_data, event_timestamp)
                elif event_type == "threat_analysis":
                    # AI-generated threat analysis results
                    self.handle_threat_analysis(event_data, event_timestamp)
                else:
                    # Unknown event type - log it for debugging
                    self.add_action_log(f"Unknown event type: {event_type}", "WARNING")
        
        except queue.Empty:
            # Queue is empty, nothing to process
            pass
        finally:
            # Schedule the next queue check
            self.root.after(100, self.process_queue)
    
    def handle_network_update(self, connections):
        """Handle network connections update event"""
        # Update connections tree
        self.update_connections_tree(connections)
        
        # Update active connections count on dashboard
        self.active_connections_label.config(text=f"Active Connections: {len(connections)}")
    
    def handle_process_update(self, processes):
        """Handle process list update event"""
        # Update processes tree
        self.update_processes_tree(processes)
    
    def handle_system_info_update(self, system_info):
        """Handle system information update event"""
        # Update CPU
        cpu_percent = system_info.get('cpu_percent', 0)
        self.cpu_bar['value'] = cpu_percent
        self.cpu_label.config(text=f"{cpu_percent:.1f}%")
        
        # Update Memory
        memory_percent = system_info.get('memory_percent', 0)
        self.memory_bar['value'] = memory_percent
        self.memory_label.config(text=f"{memory_percent:.1f}%")
        
        # Update Disk
        disk_percent = system_info.get('disk_percent', 0)
        self.disk_bar['value'] = disk_percent
        self.disk_label.config(text=f"{disk_percent:.1f}%")
        
        # Update network I/O
        if hasattr(self, 'prev_system_info'):
            time_diff = time.time() - self.prev_system_info.get('timestamp', 0)
            if time_diff > 0:
                # Calculate bytes/sec
                bytes_sent = system_info.get('network_bytes_sent', 0)
                bytes_recv = system_info.get('network_bytes_recv', 0)
                prev_bytes_sent = self.prev_system_info.get('network_bytes_sent', 0)
                prev_bytes_recv = self.prev_system_info.get('network_bytes_recv', 0)
                
                bytes_sent_per_sec = (bytes_sent - prev_bytes_sent) / time_diff
                bytes_recv_per_sec = (bytes_recv - prev_bytes_recv) / time_diff
                
                # Update labels with human readable format
                self.network_in_label.config(text=f"Received: {self.format_bytes(bytes_recv_per_sec)}/s")
                self.network_out_label.config(text=f"Sent: {self.format_bytes(bytes_sent_per_sec)}/s")
        
        # Save current info for next comparison
        system_info['timestamp'] = time.time()
        self.prev_system_info = system_info
    
    def handle_security_events(self, events):
        """Handle security events update"""
        for event in events:
            # Add to alerts if it's a high or critical risk
            risk_level = event.get('risk_level', '').lower()
            if risk_level in ['high', 'critical']:
                self.add_alert(
                    time=event.get('timestamp', ''),
                    severity=risk_level,
                    description=event.get('event_type', '') + ': ' + event.get('action', ''),
                )
            
            # Add to events text on dashboard
            timestamp = datetime.strptime(
                event.get('timestamp', '')[:19],  # Remove microseconds
                "%Y-%m-%dT%H:%M:%S"
            ).strftime("%H:%M:%S")
            
            self.events_text.insert(
                "1.0",
                f"[{timestamp}] {event.get('event_type', '')}: {event.get('action', '')}\n"
            )
            
            # Add to logs
            self.add_log_entry(
                f"{event.get('timestamp', '')}: {event.get('event_type', '')} - "
                f"{event.get('device_name', '')}: {event.get('action', '')}"
            )
    
    def handle_monitoring_error(self, error_msg):
        """Handle monitoring error event"""
        self.add_action_log(f"Monitoring error: {error_msg}", level="ERROR")
        self.status_label.config(text=f"Error: {error_msg[:30]}...")
    
    def handle_monitoring_status(self, status_data):
        """Handle monitoring status update"""
        status = status_data.get('status', 'unknown')
        message = status_data.get('message', '')
        
        if status == 'active':
            self.monitoring_status.config(text="Monitoring: Active")
            self.add_action_log(f"Monitoring active: {message}")
        elif status == 'error':
            self.monitoring_status.config(text="Monitoring: Error")
            self.add_action_log(f"Monitoring error: {message}", "ERROR")
        elif status == 'paused':
            self.monitoring_status.config(text="Monitoring: Paused")
            self.add_action_log(f"Monitoring paused: {message}", "WARNING")
        else:
            self.monitoring_status.config(text=f"Monitoring: {status}")
            self.add_action_log(f"Monitoring status changed: {message}")
    
    def handle_security_alert(self, alert_data, timestamp):
        """Handle security alerts from the enhanced monitoring thread"""
        # Extract alert details
        severity = alert_data.get('threat_level', 'medium').lower()
        source = alert_data.get('source', 'unknown')
        target = alert_data.get('target', 'unknown')
        description = alert_data.get('description', '')
        details = alert_data.get('details', '')
        
        # Format timestamp for display
        display_time = timestamp
        if isinstance(timestamp, str) and 'T' in timestamp:
            display_time = timestamp.split('T')[1][:8]  # Extract HH:MM:SS
        
        # Add to alerts panel
        self.add_alert(
            time=display_time,
            severity=severity,
            description=f"{source} → {target}: {description}"
        )
        
        # Add to events text on dashboard
        self.events_text.insert(
            "1.0",
            f"[{display_time}] ALERT ({severity.upper()}): {description}\n"
        )
        
        # Add to logs with full details
        self.add_log_entry(
            f"{timestamp}: ALERT ({severity.upper()}) - {source} → {target}: {description}\n"
            f"Details: {details}"
        )
        
        # Update action log
        self.add_action_log(f"Security alert detected: {description}", "ALERT")
    
    def handle_file_change(self, file_data, timestamp):
        """Handle file system change events"""
        # Extract file change details
        file_path = file_data.get('path', 'unknown')
        change_type = file_data.get('change_type', 'modified')
        threat_level = file_data.get('threat_level', 'info').lower()
        details = file_data.get('details', '')
        
        # Format timestamp for display
        display_time = timestamp
        if isinstance(timestamp, str) and 'T' in timestamp:
            display_time = timestamp.split('T')[1][:8]  # Extract HH:MM:SS
        
        # Add to events text on dashboard
        self.events_text.insert(
            "1.0",
            f"[{display_time}] FILE {change_type}: {file_path}\n"
        )
        
        # Add to logs
        self.add_log_entry(
            f"{timestamp}: File {change_type} - {file_path} - Threat: {threat_level.upper()}\n"
            f"Details: {details}"
        )
        
        # If high-risk file change, add as alert
        if threat_level in ['high', 'critical']:
            self.add_alert(
                time=display_time,
                severity=threat_level,
                description=f"File {change_type}: {file_path}"
            )
    
    def handle_usb_device(self, usb_data, timestamp):
        """Handle USB device events"""
        # Extract USB event details
        device_name = usb_data.get('device_name', 'unknown')
        event_type = usb_data.get('event_type', 'connected')
        vendor_id = usb_data.get('vendor_id', 'unknown')
        product_id = usb_data.get('product_id', 'unknown')
        
        # Format timestamp for display
        display_time = timestamp
        if isinstance(timestamp, str) and 'T' in timestamp:
            display_time = timestamp.split('T')[1][:8]  # Extract HH:MM:SS
        
        # Add to events text on dashboard
        self.events_text.insert(
            "1.0",
            f"[{display_time}] USB {event_type.upper()}: {device_name}\n"
        )
        
        # Add to logs
        self.add_log_entry(
            f"{timestamp}: USB {event_type} - {device_name} - "
            f"VendorID: {vendor_id} ProductID: {product_id}"
        )
        
        # Add to action log
        self.add_action_log(f"USB device {event_type}: {device_name}")
        
        # Always add USB events as alerts (medium severity)
        self.add_alert(
            time=display_time,
            severity="medium",
            description=f"USB {event_type}: {device_name}"
        )
    
    def handle_threat_analysis(self, analysis_data, timestamp):
        """Handle AI threat analysis results"""
        # Extract analysis details
        threat_level = analysis_data.get('threat_level', 'info').lower()
        analysis = analysis_data.get('analysis', '')
        confidence = analysis_data.get('confidence', 0)
        # Source event details if we need to reference them later
        source_type = analysis_data.get('source_event', {}).get('type', 'unknown')
        recommendations = analysis_data.get('recommendations', [])
        
        # Format timestamp for display
        display_time = timestamp
        if isinstance(timestamp, str) and 'T' in timestamp:
            display_time = timestamp.split('T')[1][:8]  # Extract HH:MM:SS
        
        # Add to events text on dashboard
        self.events_text.insert(
            "1.0",
            f"[{display_time}] ANALYSIS: {threat_level.upper()} confidence {confidence}%\n"
        )
        
        # Add to logs
        log_entry = (
            f"{timestamp}: Threat Analysis - Level: {threat_level.upper()} - "
            f"Confidence: {confidence}% - Source: {source_type}\n"
            f"Analysis: {analysis}\n"
        )
        
        if recommendations:
            log_entry += "Recommendations:\n"
            for i, rec in enumerate(recommendations, 1):
                log_entry += f"{i}. {rec}\n"
                
        self.add_log_entry(log_entry)
        
        # If AI found a significant threat, add as alert
        if threat_level in ['medium', 'high', 'critical']:
            self.add_alert(
                time=display_time,
                severity=threat_level,
                description=f"AI Analysis: {analysis[:50]}..."
            )
            
            # Update action log
            self.add_action_log(f"AI detected {threat_level} threat: {analysis[:50]}...", 
                               "WARNING" if threat_level == "medium" else "ALERT")
    
    def check_ai_connection(self):
        """Check the AI connection status"""
        self.add_action_log("Checking AI connection...")
        self.status_label.config(text="Checking AI connection...")
        
        # Run in separate thread
        def check_thread():
            try:
                connected = self.llm_agent.check_ollama_connection()
                models = []
                
                if connected:
                    models = self.llm_agent.get_available_models()
                    model_str = ", ".join(models) if models else "None"
                    
                    self.root.after(0, lambda: self.ai_status_label.config(
                        text=f"✅ Connected | Models: {model_str}",
                        foreground="green"
                    ))
                    self.root.after(0, lambda: self.add_action_log("AI connection successful"))
                else:
                    self.root.after(0, lambda: self.ai_status_label.config(
                        text="❌ Not connected - Please start Ollama",
                        foreground="red"
                    ))
                    self.root.after(0, lambda: self.add_action_log("AI connection failed", "WARNING"))
                
                self.root.after(0, lambda: self.status_label.config(text="AI connection check completed"))
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda: self.ai_status_label.config(
                    text=f"❌ Error: {error_msg[:30]}...",
                    foreground="red"
                ))
                self.root.after(0, lambda: self.add_action_log(f"Error checking AI connection: {error_msg}", "ERROR"))
                self.root.after(0, lambda: self.status_label.config(text="Error checking AI connection"))
        
        # Start the thread
        threading.Thread(target=check_thread, daemon=True).start()
    
    def analyze_threats(self):
        """Analyze security threats using AI"""
        query = self.query_entry.get()
        if not query:
            return
        
        self.add_action_log(f"Analyzing: {query}")
        self.status_label.config(text="Analyzing threats...")
        
        # Clear current response
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, "Analyzing threats, please wait...\n")
        
        # Run in separate thread
        def analyze_thread():
            try:
                response = self.llm_agent.query_ollama(
                    f"Analyze this security question as a macOS security expert and provide a detailed response: {query}", 
                    "You are a macOS security expert analyzing system security."
                )
                
                self.root.after(0, lambda: self.response_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.response_text.insert(tk.END, response))
                self.root.after(0, lambda: self.add_action_log("Threat analysis completed"))
                self.root.after(0, lambda: self.status_label.config(text="Analysis completed"))
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda: self.response_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.response_text.insert(tk.END, f"Error: {error_msg}"))
                self.root.after(0, lambda: self.add_action_log(f"Error in threat analysis: {error_msg}", "ERROR"))
                self.root.after(0, lambda: self.status_label.config(text="Error in analysis"))
        
        # Start the thread
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    def get_recommendations(self):
        """Get security recommendations using AI"""
        self.add_action_log("Getting security recommendations...")
        self.status_label.config(text="Getting security recommendations...")
        
        # Clear current response
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, "Generating recommendations, please wait...\n")
        
        # Run in separate thread
        def recommend_thread():
            try:
                response = self.llm_agent.query_ollama(
                    "Provide a list of the top 5 security recommendations for a macOS system. Include specific commands where applicable.",
                    "You are a macOS security expert providing actionable recommendations."
                )
                
                self.root.after(0, lambda: self.response_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.response_text.insert(tk.END, response))
                self.root.after(0, lambda: self.add_action_log("Security recommendations generated"))
                self.root.after(0, lambda: self.status_label.config(text="Recommendations generated"))
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda: self.response_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.response_text.insert(tk.END, f"Error: {error_msg}"))
                self.root.after(0, lambda: self.add_action_log(f"Error getting recommendations: {error_msg}", "ERROR"))
                self.root.after(0, lambda: self.status_label.config(text="Error in recommendations"))
        
        # Start the thread
        threading.Thread(target=recommend_thread, daemon=True).start()
    
    def security_report(self):
        """Generate a security report using AI"""
        self.add_action_log("Generating security report...")
        self.status_label.config(text="Generating security report...")
        
        # Clear current response
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, "Generating security report, please wait...\n")
        
        # Collect system information for the report
        process_count = len(self.processes_tree.get_children())
        connection_count = len(self.connections_tree.get_children())
        alert_count = len(self.alerts_tree.get_children())
        
        try:
            rule_count = len(self.rule_manager.get_parsed_rules())
        except Exception as e:
            logging.warning(f"Could not get rule count: {e}")
            rule_count = 0
        
        report_data = {
            "processes": process_count,
            "connections": connection_count,
            "alerts": alert_count,
            "rules": rule_count,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Run in separate thread
        def report_thread():
            try:
                # Format the system information as a prompt
                system_info = f"""
System Information:
- Active Processes: {report_data['processes']}
- Network Connections: {report_data['connections']}
- Security Alerts: {report_data['alerts']}
- Security Rules: {report_data['rules']}
- Report Time: {report_data['timestamp']}
"""
                
                response = self.llm_agent.query_ollama(
                    f"Based on the following system information, generate a comprehensive security report for a macOS system. Include any potential concerns and recommendations:\n\n{system_info}",
                    "You are a macOS security expert generating a detailed security report."
                )
                
                self.root.after(0, lambda: self.response_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.response_text.insert(tk.END, response))
                self.root.after(0, lambda: self.add_action_log("Security report generated"))
                self.root.after(0, lambda: self.status_label.config(text="Security report generated"))
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda: self.response_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.response_text.insert(tk.END, f"Error: {error_msg}"))
                self.root.after(0, lambda: self.add_action_log(f"Error generating report: {error_msg}", "ERROR"))
                self.root.after(0, lambda: self.status_label.config(text="Error generating report"))
        
        # Start the thread
        threading.Thread(target=report_thread, daemon=True).start()
    
    def clear_logs(self):
        """Clear the logs text"""
        self.logs_text.delete(1.0, tk.END)
        self.add_action_log("Logs cleared")
    
    def export_logs(self):
        """Export logs to a file"""
        logs = self.logs_text.get(1.0, tk.END)
        
        # Get timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nimda_security_logs_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as file:
                file.write(logs)
            
            self.add_action_log(f"Logs exported to {filename}")
            self.status_label.config(text=f"Logs exported to {filename}")
        except Exception as e:
            self.add_action_log(f"Error exporting logs: {str(e)}", "ERROR")
            self.status_label.config(text="Error exporting logs")
    
    def on_closing(self):
        """Clean up and close the application"""
        # Stop the monitoring thread
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.stop()
            self.monitor_thread.join(timeout=1.0)
        
        self.root.destroy()
    
    def format_bytes(self, bytes_value, decimals=1):
        """Format bytes to a human-readable format"""
        if bytes_value < 0:
            return "0 B"
        
        suffixes = ['B', 'KB', 'MB', 'GB', 'TB']
        i = 0
        while bytes_value >= 1024 and i < len(suffixes) - 1:
            bytes_value /= 1024
            i += 1
        
        return f"{bytes_value:.{decimals}f} {suffixes[i]}"
    
    def update_connections_tree(self, connections):
        """Update the connections treeview with new data"""
        # Clear current items
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        # Add new connections
        for conn in connections:
            self.connections_tree.insert(
                "", 
                "end", 
                values=(
                    conn.get('local_address', ''),
                    conn.get('remote_address', ''),
                    conn.get('process_name', 'N/A'),
                    conn.get('status', '')
                )
            )
    
    def update_processes_tree(self, processes):
        """Update the processes treeview with new data"""
        # Clear current items
        for item in self.processes_tree.get_children():
            self.processes_tree.delete(item)
        
        # Sort processes by CPU usage (descending)
        sorted_processes = sorted(
            processes, 
            key=lambda p: p.get('cpu_percent', 0) or 0,
            reverse=True
        )
        
        # Add new processes
        for proc in sorted_processes[:100]:  # Limit to 100 processes
            self.processes_tree.insert(
                "", 
                "end", 
                values=(
                    proc.get('pid', ''),
                    proc.get('name', '')[:20],
                    proc.get('username', '')[:15],
                    f"{proc.get('cpu_percent', 0):.1f}" if proc.get('cpu_percent') else "0.0",
                    f"{proc.get('memory_percent', 0):.1f}" if proc.get('memory_percent') else "0.0",
                    proc.get('status', '')
                )
            )
    
    def add_alert(self, time, severity, description):
        """Add an alert to the alerts treeview"""
        # Format time to just the time portion (not date)
        if 'T' in time:
            time = time.split('T')[1][:8]  # Extract HH:MM:SS
        
        # Insert at the top
        self.alerts_tree.insert(
            "", 
            0, 
            values=(time, severity.upper(), description),
            tags=(severity,)
        )
        
        # Update alert count on dashboard
        alert_count = len(self.alerts_tree.get_children())
        self.alert_count_label.config(text=f"Active Alerts: {alert_count}")
        
        # Update threat level if critical alert
        if severity.lower() == 'critical':
            self.threat_level_label.config(
                text="CRITICAL", 
                foreground=self.style.colors.danger
            )
        elif severity.lower() == 'high' and self.threat_level_label['text'] != "CRITICAL":
            self.threat_level_label.config(
                text="HIGH", 
                foreground=self.style.colors.warning
            )
    
    def add_log_entry(self, message):
        """Add an entry to the logs tab"""
        self.logs_text.insert("1.0", f"{message}\n")
    
    def add_action_log(self, message, level="INFO"):
        """Add an entry to the action log on the dashboard"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.action_text.insert("1.0", f"[{timestamp}] {level}: {message}\n")
    
    def refresh_connections(self):
        """Manually refresh network connections"""
        self.add_action_log("Refreshing network connections...")
        self.status_label.config(text="Refreshing network connections...")
    
    def refresh_processes(self):
        """Manually refresh processes"""
        self.add_action_log("Refreshing processes...")
        self.status_label.config(text="Refreshing processes...")
    
    def run_full_scan(self):
        """Run a full security scan"""
        self.add_action_log("Starting full security scan...")
        self.status_label.config(text="Running full security scan...")
        
        # Update last scan time
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_scan_label.config(text=f"Last Scan: {scan_time}")
    
    def update_rules(self):
        """Update security rules"""
        self.add_action_log("Updating security rules...")
        self.status_label.config(text="Updating security rules...")
        
        # Run in separate thread
        def update_thread():
            try:
                success_count = self.rule_manager.update_all_rules()
                
                # Update UI in main thread
                self.root.after(0, lambda: self.add_action_log(f"Updated {success_count} rule sets"))
                self.root.after(0, lambda: self.status_label.config(text="Rules updated successfully"))
                
                # Update rule count
                rules = self.rule_manager.get_parsed_rules()
                self.root.after(0, lambda: self.rule_count_label.config(text=f"Active Rules: {len(rules)}"))
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda: self.add_action_log(f"Error updating rules: {error_msg}", "ERROR"))
                self.root.after(0, lambda: self.status_label.config(text="Error updating rules"))
        
        # Start the thread
        threading.Thread(target=update_thread, daemon=True).start()
    
    def block_selected_connection(self):
        """Block the selected network connection"""
        selected = self.connections_tree.selection()
        if not selected:
            return
        
        item = self.connections_tree.item(selected[0])
        values = item['values']
        
        remote_address = values[1]
        process = values[2]
        
        self.add_action_log(f"Blocking connection to {remote_address} ({process})")
        self.status_label.config(text=f"Blocked connection to {remote_address}")
    
    def analyze_selected_connection(self):
        """Analyze the selected network connection"""
        selected = self.connections_tree.selection()
        if not selected:
            return
        
        item = self.connections_tree.item(selected[0])
        values = item['values']
        
        remote_address = values[1]
        process = values[2]
        
        self.add_action_log(f"Analyzing connection to {remote_address} ({process})")
        
        # Switch to AI tab
        self.notebook.select(self.notebook.index(self.notebook.tabs()[-2]))  # AI tab
        
        # Set query
        self.query_entry.delete(0, tk.END)
        self.query_entry.insert(0, f"Analyze network connection to {remote_address} from {process}")
        
        # Trigger analysis
        self.analyze_threats()
    
    def terminate_selected_process(self):
        """Terminate the selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            return
        
        item = self.processes_tree.item(selected[0])
        values = item['values']
        
        pid = values[0]
        name = values[1]
        
        self.add_action_log(f"Terminating process {name} (PID: {pid})")
        self.status_label.config(text=f"Terminated process {name}")
    
    def analyze_selected_process(self):
        """Analyze the selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            return
        
        item = self.processes_tree.item(selected[0])
        values = item['values']
        
        pid = values[0]
        name = values[1]
        
        self.add_action_log(f"Analyzing process {name} (PID: {pid})")
        
        # Trigger AI analysis
        process_info = {
            'pid': int(pid),
            'name': name,
            'user': values[2],
            'cpu_percent': float(values[3]),
            'memory_percent': float(values[4])
        }
        
        # Run in separate thread
        def analyze_thread():
            try:
                result = self.threat_analyzer.analyze_process_activity(process_info)
                
                # Update UI in main thread
                self.root.after(0, lambda: self.display_process_analysis(result))
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda: self.add_action_log(f"Error analyzing process: {error_msg}", "ERROR"))
                self.root.after(0, lambda: self.status_label.config(text="Error analyzing process"))
        
        # Start the thread
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    def display_process_analysis(self, result):
        """Display process analysis results in the AI tab"""
        # Switch to AI tab
        self.notebook.select(self.notebook.index(self.notebook.tabs()[-2]))  # AI tab
        
        # Clear current response
        self.response_text.delete(1.0, tk.END)
        
        # Add analysis results
        process_info = result.get('process_info', {})
        
        self.response_text.insert(tk.END, "# Process Analysis\n\n")
        self.response_text.insert(tk.END, "## Process Information\n")
        self.response_text.insert(tk.END, f"- Name: {process_info.get('name', 'Unknown')}\n")
        self.response_text.insert(tk.END, f"- PID: {process_info.get('pid', 'Unknown')}\n")
        self.response_text.insert(tk.END, f"- User: {process_info.get('user', 'Unknown')}\n")
        
        self.response_text.insert(tk.END, "\n## Threat Analysis\n")
        self.response_text.insert(tk.END, f"- Threat Level: {result.get('threat_level', 'info').upper()}\n")
        
        # Add suspicious indicators
        indicators = result.get('suspicious_indicators', [])
        if indicators:
            self.response_text.insert(tk.END, "\n## Suspicious Indicators\n")
            for indicator in indicators:
                self.response_text.insert(tk.END, f"- {indicator}\n")
        
        # Add AI analysis
        ai_analysis = result.get('ai_analysis', {})
        if ai_analysis:
            self.response_text.insert(tk.END, "\n## AI Analysis\n")
            self.response_text.insert(tk.END, f"- Analysis: {ai_analysis.get('analysis', 'N/A')}\n")
            self.response_text.insert(tk.END, f"- Confidence: {ai_analysis.get('confidence', 0)}%\n")
        
        # Add suggested commands
        commands = result.get('suggested_commands', [])
        if commands:
            self.response_text.insert(tk.END, "\n## Recommended Commands\n")
            for i, cmd in enumerate(commands, 1):
                self.response_text.insert(tk.END, f"{i}. `{cmd}`\n")

    # ...existing methods continue...
