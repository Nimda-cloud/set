#!/usr/bin/env python3
"""
Quick NIMDA Launcher - Minimal startup for maximum responsiveness
"""

import sys
import os
import ttkbootstrap as ttk

def quick_launch():
    """Quick launch with minimal initialization"""
    try:
        # Set up minimal environment
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        
        print("🚀 Quick launching NIMDA...")
        
        # Create lightweight root window
        root = ttk.Window(
            title="NIMDA - Enhanced Security Platform",
            themename="darkly",
            size=(1400, 900)
        )
        
        # Import and create GUI
        from gui.nimda_modern_gui import NimdaModernGUI
        _ = NimdaModernGUI(root)  # Reference not needed
        
        print("✅ NIMDA ready!")
        root.mainloop()
        
    except KeyboardInterrupt:
        print("\n🛑 NIMDA stopped by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(quick_launch())
