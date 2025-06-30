#!/usr/bin/env python3
"""
NIMDA Security System - Modern GUI Implementation
Advanced security monitoring with multithreading and responsive design
"""

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import (
    HORIZONTAL, VERTICAL, LEFT, RIGHT, TOP, BOTTOM,
    X, Y, BOTH, W, E, EW, CENTER, WORD, SUCCESS,
    INFO, WARNING, DANGER
)
import threading
import queue
import os
import sys
from datetime import datetime
from typing import Dict, Any
import logging
import json

# Add root directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import NIMDA components
from core.optimized_rule_manager import OptimizedRuleManager
from core.enhanced_threat_analyzer import EnhancedThreatAnalyzer
from core.security_monitoring_thread import SecurityMonitoringThread
from core.kernel_monitor import KernelMonitor
from core.system_query_engine import SystemQueryEngine
from core.deception_manager import DeceptionManager
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
        
        # Phase 1: Kernel-level monitoring
        self.kernel_monitor = KernelMonitor(self.event_queue)
        
        # Phase 2: AI hunting capabilities
        self.system_query_engine = SystemQueryEngine()
        
        # Phase 3: Deception management
        self.deception_manager = DeceptionManager(self.handle_deception_alert)
        
        # Enhanced monitoring with kernel-level capabilities
        self.kernel_monitor = KernelMonitor(self.event_queue)
        self.system_query_engine = SystemQueryEngine()
        self.deception_manager = DeceptionManager(self.handle_deception_alert)
        
        # Monitoring thread with optimized implementation
        self.monitor_thread = SecurityMonitoringThread(
            event_queue=self.event_queue,
            interval=2,
            db_path=db_path
        )
        
        # Start kernel-level monitoring
        self.kernel_monitor.start()
        
        # Initialize UI components
        self.create_widgets()
        
        # Start monitoring thread (legacy system monitoring for compatibility)
        self.monitor_thread = SecurityMonitoringThread(
            event_queue=self.event_queue,
            interval=5,
            db_path=db_path
        )
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
        self.create_ai_hunter_tab()  # NEW: AI Hunting tab
        self.create_deception_tab()  # NEW: Deception management tab
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
                elif event_type == "honeypot_alert":
                    # Deception alert events
                    self.handle_deception_alert(event_data)
                elif event_type == "kernel_event":
                    # Kernel event monitoring
                    self.handle_kernel_event(event_data)
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
        """Handle running processes update event"""
        # Update processes tree
        self.update_processes_tree(processes)
    
    def handle_system_info_update(self, system_info):
        """Handle system information update event"""
        # Update system metrics on dashboard
        self.update_system_metrics(system_info)
    
    def handle_security_events(self, events):
        """Handle security events update"""
        # Update alerts tree and dashboard
        self.update_alerts_tree(events)
        self.update_dashboard_alerts_count(len(events))
        
        # Log the received security events
        for event in events:
            self.add_action_log(f"Security event received: {event.get('description')}")
    
    def handle_monitoring_error(self, error_info):
        """Handle monitoring error event"""
        error_message = error_info.get("message", "Unknown error")
        self.add_action_log(f"Monitoring error: {error_message}", "ERROR")
    
    def handle_monitoring_status(self, status_info):
        """Handle monitoring status update"""
        status = status_info.get("status", "unknown")
        if status == "active":
            self.monitoring_status.config(text="Monitoring: Active", foreground=self.style.colors.success)
        elif status == "paused":
            self.monitoring_status.config(text="Monitoring: Paused", foreground=self.style.colors.warning)
        else:
            self.monitoring_status.config(text="Monitoring: Unknown", foreground=self.style.colors.danger)
    
    def handle_security_alert(self, alert_data, timestamp):
        """Handle a new security alert"""
        # Extract alert details
        severity = alert_data.get("severity", "medium")
        description = alert_data.get("description", "No description")
        
        # Insert alert into treeview
        self.alerts_tree.insert("", "end", values=(timestamp, severity, description), tags=[severity])
        
        # Update active alerts count on dashboard
        current_count = int(self.alert_count_label.cget("text").split(": ")[1])
        self.alert_count_label.config(text=f"Active Alerts: {current_count + 1}")
        
        # Log the new alert
        self.add_action_log(f"New alert: {description} (Severity: {severity})")
    
    def handle_file_change(self, file_data, timestamp):
        """Handle file system change event"""
        file_path = file_data.get("path", "Unknown")
        change_type = file_data.get("change_type", "Modified")
        
        # Log the file change
        self.add_action_log(f"File {change_type}: {file_path}")
    
    def handle_usb_device(self, device_data, timestamp):
        """Handle USB device event"""
        device_name = device_data.get("name", "Unknown Device")
        action = device_data.get("action", "Connected")
        
        # Log the USB device event
        self.add_action_log(f"USB Device {action}: {device_name}")
    
    def handle_threat_analysis(self, analysis_data, timestamp):
        """Handle AI-generated threat analysis results"""
        # Extract analysis details
        threats = analysis_data.get("threats", [])
        recommendations = analysis_data.get("recommendations", [])
        
        # Update AI response area with analysis results
        response = "Threat Analysis Results:\n\n"
        response += "Identified Threats:\n"
        for threat in threats:
            response += f"- {threat}\n"
        
        response += "\nRecommendations:\n"
        for rec in recommendations:
            response += f"- {rec}\n"
        
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, response)
        
        # Log the threat analysis
        self.add_action_log("Threat analysis completed")
    
    def handle_deception_alert(self, event_type: str, data: Dict[str, Any]):
        """Handle deception/honeypot alerts"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if event_type == "honeypot_file_access":
            description = f"File honeypot triggered: {data.get('action', 'unknown')} on {data.get('file_path', 'unknown')}"
        elif event_type == "honeypot_port_access":
            description = f"Port honeypot triggered: Connection from {data.get('source_ip', 'unknown')} to port {data.get('port', 'unknown')}"
        else:
            description = f"Honeypot triggered: {event_type}"
        
        # Add to main alerts
        self.add_alert(
            time=timestamp,
            severity="CRITICAL",
            description=description
        )
        
        # Add to deception alerts
        alert_text = f"[{timestamp}] {description}\nDetails: {json.dumps(data, indent=2)}\n\n"
        self.deception_alerts_text.insert("1.0", alert_text)
        
        # Update action log
        self.add_action_log(f"HONEYPOT ALERT: {description}", "CRITICAL")
        
        # Update honeypots tree
        self.update_honeypots_tree()

    def add_alert(self, timestamp: str, severity: str, description: str):
        """Add a new alert to the alerts tree with the specified severity level"""
        self.alerts_tree.insert("", "end", values=(timestamp, severity, description), tags=[severity.lower()])
        
        # Update alerts count
        current_count = int(self.alert_count_label.cget("text").split(": ")[1])
        self.alert_count_label.config(text=f"Active Alerts: {current_count + 1}")
        
        # Log the alert
        self.add_action_log(f"New {severity} alert: {description}")

    def add_action_log(self, message: str, level: str = "INFO"):
        """Add a message to the action log with optional level"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        # Add to action log
        self.action_text.insert("1.0", log_entry)
        
        # Keep only the last 1000 lines
        content = self.action_text.get("1.0", tk.END)
        if content.count("\n") > 1000:
            lines = content.splitlines()[-1000:]
            self.action_text.delete("1.0", tk.END)
            self.action_text.insert("1.0", "\n".join(lines))
    
    def create_ai_hunter_tab(self):
        """Create the AI hunting tab"""
        hunter_frame = ttk.Frame(self.notebook)
        self.notebook.add(hunter_frame, text="🎯 AI Hunter")

        # Status section
        status_frame = ttk.LabelFrame(hunter_frame, text="AI Hunter Status", padding=10)
        status_frame.pack(fill=X, padx=10, pady=5)

        self.hunter_status_label = ttk.Label(status_frame, text="AI Hunter is STOPPED", foreground="red")
        self.hunter_status_label.pack(side=LEFT, pady=5)

        control_frame = ttk.Frame(status_frame)
        control_frame.pack(side=RIGHT, pady=5)

        ttk.Button(
            control_frame,
            text="Start Hunter",
            command=self.start_ai_hunter,
            bootstyle="success"
        ).pack(side=LEFT, padx=5)

        ttk.Button(
            control_frame,
            text="Stop Hunter",
            command=self.stop_ai_hunter,
            bootstyle="danger"
        ).pack(side=LEFT, padx=5)

        # Current hypothesis section
        hypothesis_frame = ttk.LabelFrame(hunter_frame, text="Current Hypothesis", padding=10)
        hypothesis_frame.pack(fill=X, padx=10, pady=5)

        self.hunter_hypothesis_label = ttk.Label(
            hypothesis_frame,
            text="No active hypothesis",
            wraplength=600
        )
        self.hunter_hypothesis_label.pack(anchor=W, pady=5)

        ttk.Button(
            hypothesis_frame,
            text="Generate New Hypothesis",
            command=self.generate_single_hypothesis,
            bootstyle="info"
        ).pack(anchor=W, pady=5)

        # Results section
        results_frame = ttk.LabelFrame(hunter_frame, text="Investigation Results", padding=10)
        results_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)

        # Results text area
        self.hunter_results_text = ttk.Text(results_frame, wrap=WORD, height=15)
        results_scrollbar = ttk.Scrollbar(results_frame, orient=VERTICAL, command=self.hunter_results_text.yview)
        self.hunter_results_text.configure(yscrollcommand=results_scrollbar.set)

        self.hunter_results_text.pack(side=LEFT, fill=BOTH, expand=True)
        results_scrollbar.pack(side=RIGHT, fill=Y)

        # Initialize attributes
        self.ai_hunter_running = False

    def create_deception_tab(self):
        """Create the deception management tab"""
        deception_frame = ttk.Frame(self.notebook)
        self.notebook.add(deception_frame, text="🎭 Deception")

        # Honeypots configuration frame
        config_frame = ttk.LabelFrame(deception_frame, text="Honeypot Configuration", padding=10)
        config_frame.pack(fill=X, padx=10, pady=5)

        # File honeypots
        file_frame = ttk.Frame(config_frame)
        file_frame.pack(fill=X, pady=5)
        
        ttk.Label(file_frame, text="Deploy File Honeypot:").pack(side=LEFT, padx=5)
        
        ttk.Button(
            file_frame,
            text="Credentials File",
            command=lambda: self.deploy_file_honeypot("credentials"),
            bootstyle="info"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            file_frame,
            text="Configuration File",
            command=lambda: self.deploy_file_honeypot("config"),
            bootstyle="info"
        ).pack(side=LEFT, padx=5)

        # Port honeypots
        port_frame = ttk.Frame(config_frame)
        port_frame.pack(fill=X, pady=5)
        
        ttk.Label(port_frame, text="Deploy Port Honeypot:").pack(side=LEFT, padx=5)
        
        ttk.Button(
            port_frame,
            text="SSH (22)",
            command=lambda: self.deploy_port_honeypot("ssh"),
            bootstyle="info"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            port_frame,
            text="HTTP (80)",
            command=lambda: self.deploy_port_honeypot("http"),
            bootstyle="info"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            port_frame,
            text="Custom Port",
            command=self.deploy_custom_port_honeypot,
            bootstyle="warning"
        ).pack(side=LEFT, padx=5)

        # Honeypots status frame
        status_frame = ttk.LabelFrame(deception_frame, text="Active Honeypots", padding=10)
        status_frame.pack(fill=X, padx=10, pady=5)

        # Create a treeview for honeypots
        columns = ("type", "location", "created", "alerts")
        self.honeypots_tree = ttk.Treeview(
            status_frame,
            columns=columns,
            show="headings",
            bootstyle="info",
            height=5
        )

        self.honeypots_tree.heading("type", text="Type")
        self.honeypots_tree.heading("location", text="Location")
        self.honeypots_tree.heading("created", text="Created")
        self.honeypots_tree.heading("alerts", text="Alerts")

        self.honeypots_tree.column("type", width=100)
        self.honeypots_tree.column("location", width=250)
        self.honeypots_tree.column("created", width=100)
        self.honeypots_tree.column("alerts", width=70)

        # Add scrollbar for honeypots tree
        honeypots_scrollbar = ttk.Scrollbar(status_frame, orient=VERTICAL, command=self.honeypots_tree.yview)
        self.honeypots_tree.configure(yscrollcommand=honeypots_scrollbar.set)

        self.honeypots_tree.pack(side=LEFT, fill=X, expand=True)
        honeypots_scrollbar.pack(side=RIGHT, fill=Y)

        # Deception alerts frame
        alerts_frame = ttk.LabelFrame(deception_frame, text="Honeypot Alerts", padding=10)
        alerts_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)

        # Create text widget for alerts with scrollbar
        self.deception_alerts_text = ttk.Text(alerts_frame, wrap=WORD, height=15)
        alerts_scrollbar = ttk.Scrollbar(alerts_frame, orient=VERTICAL, command=self.deception_alerts_text.yview)
        self.deception_alerts_text.configure(yscrollcommand=alerts_scrollbar.set)

        self.deception_alerts_text.pack(side=LEFT, fill=BOTH, expand=True)
        alerts_scrollbar.pack(side=RIGHT, fill=Y)

        # Initialize default honeypots in a separate thread
        threading.Thread(target=self.initialize_default_honeypots, daemon=True).start()

    def start_ai_hunter(self):
        """Start the AI hunting cycle"""
        if not self.ai_hunter_running:
            self.ai_hunter_running = True
            self.hunter_status_label.config(text="AI Hunter is ACTIVE - Searching for threats...", foreground="green")
            self.add_action_log("AI Hunter started", "INFO")
            
            # Start kernel monitoring
            self.kernel_monitor.start()

    def stop_ai_hunter(self):
        """Stop the AI hunting cycle"""
        if self.ai_hunter_running:
            self.ai_hunter_running = False
            self.hunter_status_label.config(text="AI Hunter is STOPPED", foreground="red")
            self.add_action_log("AI Hunter stopped", "INFO")
            
            # Stop kernel monitoring
            self.kernel_monitor.stop()

    def generate_single_hypothesis(self):
        """Generate a single threat hunting hypothesis"""
        self.add_action_log("Generating AI threat hunting hypothesis...", "INFO")
        
        def hypothesis_thread():
            try:
                # Get system summary
                system_summary = self.kernel_monitor.get_status_summary()
                
                # Generate hypothesis
                hypothesis = self.llm_agent.generate_hunting_hypothesis(system_summary)
                
                if hypothesis:
                    self.root.after(0, lambda: self.hunter_hypothesis_label.config(text=f"Hypothesis: {hypothesis}"))
                    
                    # Execute the hypothesis
                    results = self.system_query_engine.execute_query(hypothesis)
                    
                    # Display results
                    results_text = "Investigation Results:\n"
                    results_text += f"Query: {hypothesis}\n"
                    results_text += f"Results: {json.dumps(results, indent=2)}\n\n"
                    
                    self.root.after(0, lambda: self.hunter_results_text.insert("1.0", results_text))
                    self.root.after(0, lambda: self.add_action_log("AI hypothesis investigation completed", "INFO"))
                else:
                    self.root.after(0, lambda: self.add_action_log("Failed to generate AI hypothesis", "WARNING"))
                    
            except Exception as error:
                self.root.after(0, lambda error=error: self.add_action_log(f"Error in hypothesis generation: {error}", "ERROR"))
        
        threading.Thread(target=hypothesis_thread, daemon=True).start()

    def schedule_ai_hunter_cycle(self):
        """Schedule the next AI hunter cycle"""
        if self.ai_hunter_running:
            self.generate_single_hypothesis()
        
        # Schedule next cycle in 30 seconds
        self.root.after(30000, self.schedule_ai_hunter_cycle)

    def deploy_file_honeypot(self, file_type: str):
        """Deploy a file honeypot of the specified type"""
        try:
            file_path = self.deception_manager.deploy_honeypot_file(file_type=file_type)
            self.add_action_log(f"Deployed {file_type} honeypot: {file_path}", "INFO")
            self.update_honeypots_tree()
        except Exception as e:
            self.add_action_log(f"Error deploying {file_type} honeypot: {e}", "ERROR")

    def deploy_port_honeypot(self, service_type: str):
        """Deploy a network port honeypot"""
        try:
            port = self.deception_manager.deploy_honeypot_port(service_type=service_type)
            self.add_action_log(f"Deployed {service_type} honeypot on port {port}", "INFO")
            self.update_honeypots_tree()
        except Exception as e:
            self.add_action_log(f"Error deploying {service_type} honeypot: {e}", "ERROR")

    def deploy_custom_port_honeypot(self):
        """Deploy a honeypot on a custom port"""
        # Create a simple dialog to get port number
        port_dialog = tk.Toplevel(self.root)
        port_dialog.title("Deploy Custom Port Honeypot")
        port_dialog.geometry("300x150")
        
        ttk.Label(port_dialog, text="Enter port number:").pack(pady=10)
        port_entry = ttk.Entry(port_dialog)
        port_entry.pack(pady=5)
        port_entry.insert(0, "31337")
        
        def deploy_custom():
            try:
                port_num = int(port_entry.get())
                port = self.deception_manager.deploy_honeypot_port(port=port_num, service_type="custom")
                self.add_action_log(f"Deployed custom honeypot on port {port}", "INFO")
                self.update_honeypots_tree()
                port_dialog.destroy()
            except ValueError:
                self.add_action_log("Invalid port number", "ERROR")
            except Exception as e:
                self.add_action_log(f"Error deploying custom honeypot: {e}", "ERROR")
        
        ttk.Button(port_dialog, text="Deploy", command=deploy_custom).pack(pady=10)

    def update_honeypots_tree(self):
        """Update the honeypots status tree"""
        # Clear current items
        for item in self.honeypots_tree.get_children():
            self.honeypots_tree.delete(item)
        
        # Get honeypot status
        status = self.deception_manager.get_honeypot_status()
        
        for honeypot in status.get('honeypots', []):
            honeypot_type = honeypot.get('type', 'unknown')
            location = honeypot.get('id', 'unknown')
            created = honeypot.get('created_time', 'unknown')
            if created != 'unknown' and 'T' in created:
                created = created.split('T')[1][:8]  # Extract time only
            alerts = honeypot.get('access_count', 0)
            
            self.honeypots_tree.insert("", "end", values=(honeypot_type, location, created, alerts))

    def initialize_default_honeypots(self):
        """Initialize some default honeypots for demonstration"""
        try:
            # Deploy some default honeypots
            self.deception_manager.deploy_honeypot_file(file_type="credentials")
            self.deception_manager.deploy_honeypot_port(service_type="ssh")
            self.update_honeypots_tree()
            self.add_action_log("Default honeypots deployed", "INFO")
        except Exception as e:
            self.add_action_log(f"Error deploying default honeypots: {e}", "WARNING")
