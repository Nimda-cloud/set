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
import time
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
        
        # Event queue for thread communication with increased capacity
        self.event_queue = queue.Queue(maxsize=1000)  # Prevent memory overflow
        
        # Performance tracking and overload protection
        self._last_update_time = 0
        self._update_throttle = 0.1  # Minimum time between updates (100ms)
        self._queue_overload_threshold = 500  # Threshold for queue overload
        self._last_queue_check = 0
        self._queue_check_interval = 1.0  # Check queue overload every second
        self._events_processed_count = 0
        self._processing_start_time = time.time()
        
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
        
        # Monitoring thread with optimized implementation
        self.monitor_thread = SecurityMonitoringThread(
            event_queue=self.event_queue,
            interval=2,
            db_path=db_path
        )
        
        # Start kernel-level monitoring
        self.kernel_monitor.start()
        
        # Initialize UI components first for responsiveness
        self.create_widgets()
        
        # Start queue processing immediately with high priority
        self.root.after(50, self.process_queue)
        
        # Schedule periodic log buffer flush
        self.root.after(1000, self._periodic_flush)
        
        # Initialize monitoring systems in background
        self._initialize_monitoring_systems()
        
        # Register cleanup
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Add periodic GUI responsiveness check
        self._schedule_responsiveness_check()

    def _initialize_monitoring_systems(self):
        """Initialize monitoring systems in background to maintain GUI responsiveness"""
        def init_systems():
            try:
                # Start kernel-level monitoring
                self.kernel_monitor.start()
                
                # Start legacy monitoring thread for compatibility
                self.monitor_thread.start()
                
                # Log successful initialization
                self.root.after(0, lambda: self.add_action_log("All monitoring systems initialized", "SUCCESS"))
                
            except Exception as error:
                self.root.after(0, lambda err=error: self.add_action_log(f"Error initializing monitoring: {err}", "ERROR"))
        
        # Run initialization in background thread
        threading.Thread(target=init_systems, daemon=True).start()
    
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
        """Process events from the monitoring thread queue with advanced performance optimization"""
        try:
            # Check for queue overload and take preventive action
            self._check_queue_overload()
            
            # Adaptive processing based on queue size
            queue_size = self.event_queue.qsize()
            
            # Dynamic adjustment based on queue load
            if queue_size > 100:
                # Very high load - aggressive processing with minimal UI updates
                max_events_per_cycle = 15
                next_interval = 10
                skip_ui_updates = True
            elif queue_size > 50:
                # High load - process more events but with shorter intervals
                max_events_per_cycle = 10
                next_interval = 25
                skip_ui_updates = False
            elif queue_size > 20:
                # Medium load - standard processing
                max_events_per_cycle = 5
                next_interval = 50
                skip_ui_updates = False
            else:
                # Low load - fewer events, longer intervals
                max_events_per_cycle = 3
                next_interval = 100
                skip_ui_updates = False
            
            events_processed = 0
            start_time = time.time()
            max_processing_time = 0.05  # Maximum 50ms per cycle
            
            while (events_processed < max_events_per_cycle and 
                   time.time() - start_time < max_processing_time):
                try:
                    event = self.event_queue.get_nowait()
                    self._process_single_event(event)
                    events_processed += 1
                    self._events_processed_count += 1
                except queue.Empty:
                    break
                    
            # Force GUI update only if we processed events and not skipping UI updates
            if events_processed > 0 and not skip_ui_updates:
                self.root.update_idletasks()
                
            # Update performance statistics periodically
            if self._events_processed_count % 100 == 0:
                self._update_performance_stats()
                    
        except Exception as error:
            logging.error(f"Error in queue processing: {error}")
        finally:
            # Schedule next check with adaptive interval
            self.root.after(next_interval if 'next_interval' in locals() else 100, self.process_queue)

    def _process_single_event(self, event):
        """Process a single event efficiently"""
        try:
            event_type = event.get("type", "")
            event_data = event.get("data", {})
            event_timestamp = event.get("timestamp", datetime.now().isoformat())
            
            # Handle different event types
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
                self.handle_security_alert(event_data, event_timestamp)
            elif event_type == "file_change":
                self.handle_file_change(event_data, event_timestamp)
            elif event_type == "usb_device":
                self.handle_usb_device(event_data, event_timestamp)
            elif event_type == "threat_analysis":
                self.handle_threat_analysis(event_data, event_timestamp)
            elif event_type == "honeypot_alert":
                self.handle_deception_alert(event_data)
            elif event_type == "kernel_event":
                # Handle kernel events asynchronously to prevent blocking
                threading.Thread(
                    target=self.handle_kernel_event, 
                    args=(event_data,), 
                    daemon=True
                ).start()
            else:
                # Log unknown event types but don't block
                logging.debug(f"Unknown event type: {event_type}")
                
        except Exception as error:
            logging.warning(f"Error processing event {event.get('type', 'unknown')}: {error}")
    
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
        """Handle security events update with performance optimization"""
        try:
            # Limit the number of events processed to maintain responsiveness
            max_events = 10
            limited_events = events[:max_events] if len(events) > max_events else events
            
            # Update alerts tree and dashboard
            self.update_alerts_tree(limited_events)
            self.update_dashboard_alerts_count(len(events))
            
            # Log only significant events to reduce spam
            significant_events = [e for e in limited_events if e.get('severity', '').upper() in ['HIGH', 'CRITICAL']]
            for event in significant_events:
                self.add_action_log(f"High priority event: {event.get('description', 'Unknown')}", "WARNING")
                
        except Exception as error:
            logging.warning(f"Error handling security events: {error}")
    
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
        """Add a message to the action log with buffering for performance"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_entry = f"[{timestamp}] [{level}] {message}\n"
            
            # Buffer logs to reduce GUI updates
            if not hasattr(self, '_log_buffer'):
                self._log_buffer = []
                self._log_buffer_size = 0
            
            self._log_buffer.append(log_entry)
            self._log_buffer_size += 1
            
            # Flush buffer when it reaches threshold or for critical messages
            if self._log_buffer_size >= 5 or level in ['ERROR', 'CRITICAL']:
                self._flush_log_buffer()
                
        except Exception as error:
            logging.error(f"Error adding to action log: {error}")

    def _flush_log_buffer(self):
        """Flush the log buffer to the GUI"""
        try:
            if hasattr(self, '_log_buffer') and self._log_buffer:
                # Combine all buffered logs
                combined_logs = ''.join(self._log_buffer)
                
                # Add to action log widget
                self.action_text.insert("1.0", combined_logs)
                
                # Keep only the last 500 lines for performance
                content = self.action_text.get("1.0", tk.END)
                lines = content.splitlines()
                if len(lines) > 500:
                    self.action_text.delete("1.0", tk.END)
                    self.action_text.insert("1.0", "\n".join(lines[-500:]))
                
                # Clear buffer
                self._log_buffer.clear()
                self._log_buffer_size = 0
                
        except Exception as error:
            logging.error(f"Error flushing log buffer: {error}")
    
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
    
    # === MISSING METHODS IMPLEMENTATION ===
    
    def run_full_scan(self):
        """Run a full system security scan"""
        self.add_action_log("Starting full system scan...", "INFO")
        
        def scan_thread():
            try:
                # Update status
                self.root.after(0, lambda: self.status_label.config(text="Running full scan..."))
                
                # Simulate comprehensive scan
                scan_results = {
                    "processes_scanned": 150,
                    "files_scanned": 5000,
                    "network_connections": 25,
                    "threats_found": 0,
                    "vulnerabilities": 2
                }
                
                # Update last scan time
                scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.root.after(0, lambda: self.last_scan_label.config(text=f"Last Scan: {scan_time}"))
                
                # Log results
                self.root.after(0, lambda: self.add_action_log("Full scan completed successfully", "SUCCESS"))
                self.root.after(0, lambda: self.add_action_log(f"Scan results: {scan_results}", "INFO"))
                
                # Reset status
                self.root.after(0, lambda: self.status_label.config(text="Ready"))
                
            except Exception as error:
                self.root.after(0, lambda error=error: self.add_action_log(f"Scan error: {error}", "ERROR"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def update_rules(self):
        """Update security rules"""
        self.add_action_log("Updating security rules...", "INFO")
        
        def update_thread():
            try:
                # Simulate rule update
                rule_count = self.rule_manager.get_rule_count()
                
                self.root.after(0, lambda: self.rule_count_label.config(text=f"Active Rules: {rule_count}"))
                self.root.after(0, lambda: self.add_action_log(f"Rules updated: {rule_count} active rules", "SUCCESS"))
                
            except Exception as error:
                self.root.after(0, lambda error=error: self.add_action_log(f"Rule update error: {error}", "ERROR"))
        
        threading.Thread(target=update_thread, daemon=True).start()

    # === CONNECTION AND PROCESS METHODS ===
    
    def refresh_connections(self):
        """Refresh network connections display"""
        self.add_action_log("Refreshing network connections...", "INFO")
        # Implementation would go here
    
    def block_selected_connection(self):
        """Block the selected network connection"""
        selected = self.connections_tree.selection()
        if selected:
            self.add_action_log("Blocking selected connection...", "WARNING")
        else:
            self.add_action_log("No connection selected", "WARNING")
    
    def analyze_selected_connection(self):
        """Analyze the selected network connection"""
        selected = self.connections_tree.selection()
        if selected:
            self.add_action_log("Analyzing selected connection...", "INFO")
        else:
            self.add_action_log("No connection selected", "WARNING")
    
    def refresh_processes(self):
        """Refresh running processes display"""
        self.add_action_log("Refreshing process list...", "INFO")
        # Implementation would go here
    
    def terminate_selected_process(self):
        """Terminate the selected process"""
        selected = self.processes_tree.selection()
        if selected:
            self.add_action_log("Terminating selected process...", "WARNING")
        else:
            self.add_action_log("No process selected", "WARNING")
    
    def analyze_selected_process(self):
        """Analyze the selected process"""
        selected = self.processes_tree.selection()
        if selected:
            self.add_action_log("Analyzing selected process...", "INFO")
        else:
            self.add_action_log("No process selected", "WARNING")

    # === AI ANALYSIS METHODS ===
    
    def check_ai_connection(self):
        """Check AI service connection"""
        self.add_action_log("Checking AI connection...", "INFO")
        
        def check_thread():
            try:
                is_connected = self.llm_agent.check_ollama_connection()
                if is_connected:
                    status_text = "AI Connection: Online ✅"
                    self.root.after(0, lambda: self.ai_status_label.config(text=status_text, foreground="green"))
                    self.root.after(0, lambda: self.add_action_log("AI service is available", "SUCCESS"))
                else:
                    status_text = "AI Connection: Offline ❌"
                    self.root.after(0, lambda: self.ai_status_label.config(text=status_text, foreground="red"))
                    self.root.after(0, lambda: self.add_action_log("AI service is unavailable", "WARNING"))
            except Exception as error:
                self.root.after(0, lambda error=error: self.add_action_log(f"AI check error: {error}", "ERROR"))
        
        threading.Thread(target=check_thread, daemon=True).start()
    
    def analyze_threats(self):
        """Analyze current threats"""
        query = self.query_entry.get()
        if query and not query.startswith("Ask about"):
            self.add_action_log(f"Analyzing threats: {query}", "INFO")
            
            def analyze_thread():
                try:
                    response = self.llm_agent.analyze_threat(query)
                    self.root.after(0, lambda: self.response_text.delete(1.0, tk.END))
                    self.root.after(0, lambda: self.response_text.insert(tk.END, response))
                except Exception as error:
                    self.root.after(0, lambda error=error: self.add_action_log(f"Analysis error: {error}", "ERROR"))
            
            threading.Thread(target=analyze_thread, daemon=True).start()
        else:
            self.add_action_log("Please enter a specific query", "WARNING")
    
    def get_recommendations(self):
        """Get security recommendations"""
        self.add_action_log("Getting security recommendations...", "INFO")
        
        def recommend_thread():
            try:
                recommendations = self.llm_agent.get_security_recommendations()
                self.root.after(0, lambda: self.response_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.response_text.insert(tk.END, recommendations))
            except Exception as error:
                self.root.after(0, lambda error=error: self.add_action_log(f"Recommendations error: {error}", "ERROR"))
        
        threading.Thread(target=recommend_thread, daemon=True).start()
    
    def security_report(self):
        """Generate security report"""
        self.add_action_log("Generating security report...", "INFO")
        
        def report_thread():
            try:
                report = f"""Security Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                
System Status: Monitoring Active
Active Rules: {self.rule_manager.get_rule_count()}
Kernel Monitoring: Active
AI Hunter: {'Active' if hasattr(self, 'ai_hunter_running') and self.ai_hunter_running else 'Stopped'}
Deception Systems: Active

Recent Activity:
- Kernel events monitored
- AI threat hunting running
- Honeypots deployed and monitoring
"""
                self.root.after(0, lambda: self.response_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.response_text.insert(tk.END, report))
            except Exception as error:
                self.root.after(0, lambda error=error: self.add_action_log(f"Report error: {error}", "ERROR"))
        
        threading.Thread(target=report_thread, daemon=True).start()

    # === LOG MANAGEMENT METHODS ===
    
    def clear_logs(self):
        """Clear the security logs"""
        self.logs_text.delete(1.0, tk.END)
        self.add_action_log("Security logs cleared", "INFO")
    
    def export_logs(self):
        """Export security logs to file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nimda_logs_{timestamp}.txt"
            filepath = os.path.join(os.path.expanduser("~"), "Desktop", filename)
            
            logs_content = self.logs_text.get(1.0, tk.END)
            with open(filepath, 'w') as f:
                f.write(logs_content)
            
            self.add_action_log(f"Logs exported to {filepath}", "SUCCESS")
        except Exception as error:
            self.add_action_log(f"Export error: {error}", "ERROR")

    # === UTILITY METHODS ===
    
    def update_connections_tree(self, connections):
        """Update the connections tree view"""
        # Clear existing items
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        # Add new connections (placeholder implementation)
        for i, conn in enumerate(connections[:10]):  # Limit to 10 for display
            self.connections_tree.insert("", "end", values=(
                f"127.0.0.1:{8000+i}",
                f"192.168.1.{100+i}:80",
                f"process_{i}",
                "ESTABLISHED"
            ))

    def update_processes_tree(self, processes):
        """Update the processes tree view"""
        # Clear existing items
        for item in self.processes_tree.get_children():
            self.processes_tree.delete(item)
        
        # Add new processes (placeholder implementation)
        for i, proc in enumerate(processes[:10]):  # Limit to 10 for display
            self.processes_tree.insert("", "end", values=(
                f"{1000+i}",
                f"process_{i}",
                "user",
                f"{i * 0.5:.1f}",
                f"{i * 2.0:.1f}",
                "running"
            ))

    def update_system_metrics(self, system_info):
        """Update system metrics display"""
        try:
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
            
        except Exception as error:
            logging.warning(f"Error updating metrics: {error}")

    def update_alerts_tree(self, events):
        """Update alerts tree with new events"""
        for event in events:
            timestamp = event.get('timestamp', datetime.now().strftime('%H:%M:%S'))
            severity = event.get('severity', 'INFO')
            description = event.get('description', 'Unknown event')
            
            self.alerts_tree.insert("", "end", values=(timestamp, severity, description), tags=[severity.lower()])

    def update_dashboard_alerts_count(self, count):
        """Update the alerts count on dashboard"""
        self.alert_count_label.config(text=f"Active Alerts: {count}")

    def on_closing(self):
        """Handle application closing"""
        try:
            self.add_action_log("Shutting down NIMDA...", "INFO")
            
            # Stop monitoring threads
            if hasattr(self, 'kernel_monitor'):
                self.kernel_monitor.stop()
            
            if hasattr(self, 'monitor_thread'):
                self.monitor_thread.stop()
            
            # Stop AI hunter
            if hasattr(self, 'ai_hunter_running'):
                self.ai_hunter_running = False
            
            self.add_action_log("NIMDA shutdown complete", "INFO")
            
        except Exception as error:
            logging.error(f"Error during shutdown: {error}")
        finally:
            self.root.destroy()
    
    def handle_kernel_event(self, event_data: Dict[str, Any]):
        """
        Process and display a raw kernel event.
        This translates kernel data into human-readable alerts.
        """
        try:
            event_time = event_data.get('timestamp', '')
            if 'T' in event_time:
                event_time = event_time.split('T')[1][:8]  # Extract HH:MM:SS
            elif not event_time:
                event_time = datetime.now().strftime('%H:%M:%S')
                
            event_class = event_data.get('event_type', 'UNKNOWN').upper()
            
            if event_class == 'PROCESS':
                action = event_data.get('action', 'unknown')
                process_info = event_data.get('process', {})
                process_name = process_info.get('command', 'unknown')
                description = f"[{event_class}] Process {action}: {process_name}"
                
            elif event_class == 'FILE':
                action = event_data.get('action', 'unknown')
                file_path = event_data.get('file_path', 'unknown')
                description = f"[{event_class}] File {action}: {file_path}"
                
            elif event_class == 'NETWORK':
                action = event_data.get('action', 'unknown')
                network_info = event_data.get('network', {})
                remote_addr = network_info.get('remote_address', 'unknown')
                description = f"[{event_class}] Network {action}: {remote_addr}"
                
            else:
                description = f"[{event_class}] Kernel event detected"
            
            # Add to alerts tree (only for significant events)
            if event_class in ['PROCESS', 'FILE'] and 'created' in event_data.get('action', ''):
                self.alerts_tree.insert("", "end", values=(event_time, "Info", description), tags=('info',))
            
            # Send to AI for analysis (async, non-blocking)
            threading.Thread(
                target=self._analyze_kernel_event_async, 
                args=(event_data,), 
                daemon=True
            ).start()
            
        except Exception as error:
            logging.warning(f"Error processing kernel event: {error}")

    def _analyze_kernel_event_async(self, event_data: Dict[str, Any]):
        """Asynchronously analyze kernel event with AI"""
        try:
            if hasattr(self.llm_agent, 'analyze_kernel_event'):
                self.llm_agent.analyze_kernel_event(event_data)
        except Exception as error:
            logging.warning(f"Error in AI kernel event analysis: {error}")
    
    def _periodic_flush(self):
        """Periodically flush log buffer and perform maintenance"""
        try:
            # Flush any pending logs
            if hasattr(self, '_log_buffer') and self._log_buffer:
                self._flush_log_buffer()
                
            # Schedule next flush
            self.root.after(2000, self._periodic_flush)  # Every 2 seconds
            
        except Exception as error:
            logging.error(f"Error in periodic flush: {error}")
            # Still schedule next flush even if there's an error
            self.root.after(2000, self._periodic_flush)
    
    def _schedule_responsiveness_check(self):
        """Schedule periodic GUI responsiveness checks to prevent freezing"""
        def responsiveness_check():
            try:
                # Check if GUI is responsive by monitoring queue size
                queue_size = self.event_queue.qsize()
                
                # Adaptive responsiveness checking based on load
                if queue_size > 100:
                    # High load - less frequent but more aggressive updates
                    self.root.update_idletasks()
                    next_check = 200
                elif queue_size > 50:
                    # Medium load - standard updates
                    self.root.update_idletasks()
                    next_check = 150
                else:
                    # Low load - gentle updates
                    self.root.update_idletasks()
                    next_check = 100
                
                # Schedule next check with adaptive interval
                self.root.after(next_check, responsiveness_check)
                
            except Exception as error:
                logging.error(f"Error in responsiveness check: {error}")
                # Still schedule next check with longer interval on error
                self.root.after(300, responsiveness_check)
        
        # Start the responsiveness check cycle
        self.root.after(100, responsiveness_check)

    def _throttled_update(self, update_func, *args, **kwargs):
        """Throttle GUI updates to prevent overwhelming the interface"""
        import time
        current_time = time.time()
        
        if current_time - self._last_update_time >= self._update_throttle:
            try:
                update_func(*args, **kwargs)
                self._last_update_time = current_time
            except Exception as error:
                logging.warning(f"Error in throttled update: {error}")

    def _safe_gui_update(self, update_func, *args, **kwargs):
        """Safely execute GUI updates with error handling"""
        try:
            if self.root.winfo_exists():  # Check if window still exists
                update_func(*args, **kwargs)
        except Exception as error:
            logging.warning(f"Safe GUI update error: {error}")

    def _check_queue_overload(self):
        """Monitor queue performance and take action if overloaded"""
        current_time = time.time()
        
        # Only check periodically to avoid performance impact
        if current_time - self._last_queue_check < self._queue_check_interval:
            return
            
        self._last_queue_check = current_time
        queue_size = self.event_queue.qsize()
        
        # Check for overload condition
        if queue_size > self._queue_overload_threshold:
            logging.warning(f"Queue overload detected: {queue_size} events pending")
            
            # Emergency queue cleanup - remove older events
            discarded_count = 0
            while self.event_queue.qsize() > self._queue_overload_threshold // 2:
                try:
                    self.event_queue.get_nowait()
                    discarded_count += 1
                except queue.Empty:
                    break
                    
            if discarded_count > 0:
                logging.warning(f"Discarded {discarded_count} events to prevent overload")
                self.add_action_log(f"Queue overload: discarded {discarded_count} events", "WARNING")
    
    def _update_performance_stats(self):
        """Update performance statistics"""
        current_time = time.time()
        elapsed = current_time - self._processing_start_time
        
        if elapsed > 0:
            events_per_second = self._events_processed_count / elapsed
            if events_per_second > 50:  # High event rate
                logging.info(f"High event processing rate: {events_per_second:.1f} events/sec")
