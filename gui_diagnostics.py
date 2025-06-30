#!/usr/bin/env python3
"""
NIMDA GUI Diagnostics
Quick diagnostic tool for GUI performance issues
"""

import os
import sys
import time
import psutil

# Add project root to path  
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def run_gui_diagnostics():
    """Run comprehensive GUI diagnostics"""
    print("🔍 NIMDA GUI Diagnostics")
    print("=" * 40)
    
    # System resource check
    print("\n📋 System Resources:")
    print(f"   CPU Usage: {psutil.cpu_percent(interval=1):.1f}%")
    print(f"   Memory Usage: {psutil.virtual_memory().percent:.1f}%")
    print(f"   Available Memory: {psutil.virtual_memory().available / (1024**3):.1f} GB")
    
    # Python environment check
    print(f"\n🐍 Python Environment:")
    print(f"   Python Version: {sys.version.split()[0]}")
    print(f"   Platform: {sys.platform}")
    
    # Check required modules
    print(f"\n📦 Module Dependencies:")
    required_modules = [
        'tkinter', 'ttkbootstrap', 'threading', 'queue',
        'psutil', 'logging', 'sqlite3'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
            print(f"   ✅ {module}")
        except ImportError:
            print(f"   ❌ {module} - MISSING")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\n⚠️  Missing modules: {', '.join(missing_modules)}")
        print("   Install with: pip install -r requirements.txt")
        return False
    
    # Test GUI components
    print(f"\n🖥️  GUI Component Test:")
    try:
        import tkinter as tk
        import ttkbootstrap as ttk
        
        # Test basic GUI creation
        root = tk.Tk()
        root.withdraw()  # Hide test window
        
        print("   ✅ tkinter")
        print("   ✅ ttkbootstrap")
        
        root.destroy()
        
        # Test NIMDA components
        try:
            from gui.nimda_modern_gui import NimdaModernGUI
            print("   ✅ NimdaModernGUI")
            
            from core.kernel_monitor import KernelMonitor
            print("   ✅ KernelMonitor")
            
            from core.system_query_engine import SystemQueryEngine  
            print("   ✅ SystemQueryEngine")
            
            from core.deception_manager import DeceptionManager
            print("   ✅ DeceptionManager")
            
            from llm_security_agent import LLMSecurityAgent
            print("   ✅ LLMSecurityAgent")
            
        except ImportError as e:
            print(f"   ❌ NIMDA component: {e}")
            return False
            
    except Exception as e:
        print(f"   ❌ GUI test failed: {e}")
        return False
    
    # Performance recommendations
    print(f"\n🎯 Performance Recommendations:")
    
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    
    if cpu_percent > 80:
        print("   ⚠️  High CPU usage - consider closing other applications")
    else:
        print("   ✅ CPU usage normal")
        
    if memory_percent > 85:
        print("   ⚠️  High memory usage - may affect GUI responsiveness")
    elif memory_percent > 70:
        print("   ⚠️  Moderate memory usage - monitor during operation")
    else:
        print("   ✅ Memory usage normal")
    
    available_memory_gb = psutil.virtual_memory().available / (1024**3)
    if available_memory_gb < 1:
        print("   ⚠️  Low available memory - may cause slowdowns")
    else:
        print("   ✅ Sufficient available memory")
    
    print(f"\n✅ Diagnostics completed successfully!")
    print("🚀 Ready to launch NIMDA GUI")
    
    return True

def quick_launch_test():
    """Test quick launch capability"""
    print(f"\n🧪 Quick Launch Test:")
    try:
        start_time = time.time()
        
        import ttkbootstrap as ttk
        from gui.nimda_modern_gui import NimdaModernGUI
        
        # Create minimal GUI instance
        root = ttk.Window(themename="darkly")
        root.withdraw()  # Hide window for test
        
        gui = NimdaModernGUI(root)
        
        launch_time = time.time() - start_time
        print(f"   ✅ Launch time: {launch_time:.2f} seconds")
        
        if launch_time < 2.0:
            print("   🚀 Fast launch")
        elif launch_time < 5.0:
            print("   ⚠️  Moderate launch time")
        else:
            print("   🐌 Slow launch - check system resources")
        
        # Cleanup
        root.destroy()
        
    except Exception as e:
        print(f"   ❌ Launch test failed: {e}")

if __name__ == "__main__":
    try:
        # Run full diagnostics
        if run_gui_diagnostics():
            # Run launch test if diagnostics pass
            quick_launch_test()
            
            print(f"\n💡 Next steps:")
            print("   • Run: python performance_demo.py")
            print("   • Run: python stress_test.py")
            print("   • Run: python run_nimda.sh")
            
    except KeyboardInterrupt:
        print(f"\n⏹️  Diagnostics interrupted")
    except Exception as e:
        print(f"\n❌ Diagnostics failed: {e}")
        import traceback
        traceback.print_exc()
