#!/usr/bin/env python3
"""
NIMDA Performance Demo
Demonstrates stable performance with load monitoring
"""

import os
import sys
import time
import threading

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def run_performance_demo():
    """Run NIMDA with performance monitoring"""
    print("🚀 NIMDA Performance Demo")
    print("=" * 50)
    
    try:
        # Import GUI components
        import ttkbootstrap as ttk
        from gui.nimda_modern_gui import NimdaModernGUI
        
        # Create root window with performance theme
        root = ttk.Window(themename="darkly")
        root.title("NIMDA - Performance Demo")
        root.geometry("1400x900")
        
        # Create GUI instance
        print("🔧 Initializing NIMDA GUI...")
        gui = NimdaModernGUI(root)
        
        # Performance monitoring function
        def monitor_performance():
            """Monitor GUI performance in background"""
            last_queue_size = 0
            performance_warnings = 0
            
            while True:
                try:
                    queue_size = gui.event_queue.qsize()
                    
                    # Check for queue growth trends
                    if queue_size > last_queue_size + 10:
                        print(f"📈 Queue growing: {queue_size} events")
                        
                    if queue_size > 100:
                        performance_warnings += 1
                        print(f"⚠️  High queue load: {queue_size} events (warning #{performance_warnings})")
                        
                    if queue_size > 500:
                        print(f"🚨 Critical queue load: {queue_size} events!")
                        
                    last_queue_size = queue_size
                    time.sleep(2)
                    
                except Exception as e:
                    print(f"❌ Performance monitor error: {e}")
                    break
        
        # Start performance monitoring
        perf_thread = threading.Thread(target=monitor_performance, daemon=True)
        perf_thread.start()
        
        print("✅ NIMDA GUI initialized successfully")
        print("📊 Performance monitoring active")
        print("🖥️  GUI Features Available:")
        print("   • Real-time Security Monitoring")
        print("   • Kernel-level Event Processing") 
        print("   • AI-powered Threat Hunting")
        print("   • Deception/Honeypot Management")
        print("   • Adaptive Performance Optimization")
        print("")
        print("💡 Tips:")
        print("   • Monitor console for performance metrics")
        print("   • Test various tabs for responsiveness")
        print("   • Check Action Log for system events")
        print("   • Close window to exit")
        print("")
        
        # Run the GUI
        root.mainloop()
        
        print("👋 NIMDA Performance Demo completed")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure all dependencies are installed:")
        print("   pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_performance_demo()
