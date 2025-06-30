#!/usr/bin/env python3
"""
NIMDA GUI Stress Test
Tests GUI responsiveness under various load conditions
"""

import os
import sys
import time
import threading
import queue
import random

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def stress_test_gui():
    """Run stress test on NIMDA GUI"""
    print("🧪 Starting NIMDA GUI Stress Test...")
    
    try:
        # Import NIMDA GUI
        import tkinter as tk
        import ttkbootstrap as ttk
        from gui.nimda_modern_gui import NimdaModernGUI
        
        # Create root window
        root = ttk.Window(themename="darkly")
        root.title("NIMDA Stress Test")
        
        # Create GUI instance
        gui = NimdaModernGUI(root)
        
        print("✅ GUI initialized successfully")
        
        # Function to generate test events
        def generate_test_events():
            """Generate various test events to stress the GUI"""
            event_types = [
                "network_update",
                "process_update", 
                "system_info_update",
                "security_events",
                "security_alert",
                "file_change",
                "kernel_event",
                "honeypot_alert"
            ]
            
            test_duration = 30  # 30 seconds of stress testing
            start_time = time.time()
            events_generated = 0
            
            print(f"🔥 Starting {test_duration}s stress test...")
            
            while time.time() - start_time < test_duration:
                try:
                    # Generate random event
                    event_type = random.choice(event_types)
                    event_data = {
                        "type": event_type,
                        "timestamp": time.time(),
                        "data": {
                            "test_id": events_generated,
                            "test_data": f"stress_test_event_{events_generated}",
                            "severity": random.choice(["low", "medium", "high"]),
                            "source": "stress_test"
                        }
                    }
                    
                    # Add to queue (non-blocking)
                    try:
                        gui.event_queue.put_nowait(event_data)
                        events_generated += 1
                    except queue.Full:
                        print(f"⚠️  Queue full at {events_generated} events")
                        break
                    
                    # Variable delay to simulate real conditions
                    time.sleep(random.uniform(0.001, 0.01))
                    
                except Exception as e:
                    print(f"❌ Error generating event: {e}")
                    break
                    
            print(f"✅ Generated {events_generated} test events")
            
            # Monitor queue processing for additional 10 seconds
            print("📊 Monitoring queue processing...")
            monitor_start = time.time()
            while time.time() - monitor_start < 10:
                queue_size = gui.event_queue.qsize()
                if queue_size == 0:
                    print("✅ All events processed successfully!")
                    break
                print(f"📈 Queue size: {queue_size}")
                time.sleep(1)
            
            print("🎯 Stress test completed!")
        
        # Start event generation in background
        event_thread = threading.Thread(target=generate_test_events, daemon=True)
        event_thread.start()
        
        # Run GUI
        print("🖥️  GUI running - monitor for responsiveness...")
        print("   Close window to end test")
        
        root.mainloop()
        
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    stress_test_gui()
