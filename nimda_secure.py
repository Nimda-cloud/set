#!/usr/bin/env python3
"""
NIMDA Enhanced Security System - Main Entry Point
Non-blocking, multithreaded security monitoring with modern UI
"""

import os
import sys
import tkinter as tk
import queue
import logging
import argparse
import threading
import time

# Configure path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# NIMDA modules
from gui.nimda_modern_gui import NimdaModernGUI
from core.security_monitoring_thread import SecurityMonitoringThread
from core.enhanced_threat_analyzer import EnhancedThreatAnalyzer
from core.optimized_rule_manager import OptimizedRuleManager

# Configure logging
log_file = os.path.join(os.path.dirname(__file__), "nimda_security.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

def main():
    """Main entry point for the NIMDA Enhanced Security System"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="NIMDA Enhanced Security System")
    parser.add_argument('--no-gui', action='store_true', help='Run in headless mode (no GUI)')
    parser.add_argument('--rules-update', action='store_true', help='Update security rules and exit')
    parser.add_argument('--db-path', type=str, default='data/security_events.db', 
                       help='Path to security events database')
    args = parser.parse_args()
    
    # Create data directory if it doesn't exist
    os.makedirs(os.path.dirname(args.db_path), exist_ok=True)
    
    # Initialize the rule manager
    rule_manager = OptimizedRuleManager()
    
    # If requested, update rules and exit
    if args.rules_update:
        print("Updating security rules...")
        success_count = rule_manager.update_all_rules()
        print(f"Successfully updated {success_count} rule sets")
        return
    
    # Initialize threat analyzer
    threat_analyzer = EnhancedThreatAnalyzer(db_path=args.db_path)
    
    # Run in headless mode if requested
    if args.no_gui:
        run_headless(args.db_path, rule_manager, threat_analyzer)
    else:
        run_gui(args.db_path, rule_manager, threat_analyzer)

def run_headless(db_path, rule_manager, threat_analyzer):
    """Run NIMDA in headless mode without GUI"""
    print("Starting NIMDA Enhanced Security System in headless mode")
    print(f"Logs will be written to {log_file}")
    
    # Create event queue (we'll just log events instead of displaying them)
    event_queue = queue.Queue()
    
    # Create and start security monitoring thread
    monitor = SecurityMonitoringThread(event_queue, interval=5, db_path=db_path)
    monitor.start()
    
    # Create a thread to process events from the monitoring thread
    def event_processor():
        while True:
            try:
                event = event_queue.get()
                if event['type'] == 'security_alert':
                    severity = event['data'].get('threat_level', 'unknown').upper()
                    source = event['data'].get('source', 'unknown')
                    target = event['data'].get('target', 'unknown')
                    log_entry = event['data'].get('log_entry', '')
                    
                    logging.warning(f"[{severity}] Alert: {source} → {target}: {log_entry}")
                elif event['type'] == 'monitoring_error':
                    logging.error(f"Monitoring error: {event['data'].get('error', 'Unknown error')}")
            except Exception as e:
                logging.error(f"Error processing event: {e}")
            finally:
                event_queue.task_done()
    
    # Start event processor thread
    processor_thread = threading.Thread(target=event_processor, daemon=True)
    processor_thread.start()
    
    print("NIMDA Enhanced Security System running. Press Ctrl+C to exit.")
    
    try:
        # Keep main thread alive
        while True:
            # Print status update every hour
            logging.info("NIMDA Enhanced Security System is running")
            threat_summary = threat_analyzer.get_threat_summary()
            logging.info(f"Current threat level: {threat_summary.get('threat_level', 'unknown').upper()}")
            logging.info(f"Events in last 24h: {threat_summary.get('event_counts', {}).get('total', 0)}")
            
            # Sleep for an hour
            for _ in range(360):  # Check for KeyboardInterrupt more frequently
                time.sleep(10)
    except KeyboardInterrupt:
        print("\nShutting down NIMDA Enhanced Security System...")
    finally:
        # Stop security monitoring thread
        monitor.stop()
        monitor.join(timeout=2.0)
        print("Shutdown complete.")

def run_gui(db_path, rule_manager, threat_analyzer):
    """Run NIMDA with modern GUI"""
    root = tk.Tk()
    # Create the app instance with the database path
    app = NimdaModernGUI(root, db_path=db_path)
    # Keep a reference to prevent garbage collection
    root.app = app
    
    # Log startup with details
    logging.info(f"NIMDA Enhanced Security System started with GUI - Database: {db_path}")
    
    # Start the Tkinter event loop
    root.mainloop()
    
    # Log shutdown
    logging.info("NIMDA Enhanced Security System shut down")

if __name__ == "__main__":
    main()
