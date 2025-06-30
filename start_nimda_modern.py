#!/usr/bin/env python3
"""
NIMDA Modern Security System Launcher
Запуск повноцінного інтерфейсу з усіма трьома фазами
"""

import sys
import os
import tkinter as tk
import ttkbootstrap as ttk
from datetime import datetime

# Додаємо шлях до модулів
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Імпортуємо модерний GUI
from gui.nimda_modern_gui import NimdaModernGUI

def main():
    """Головна функція запуску NIMDA"""
    
    print("🛡️  NIMDA Enhanced Security System")
    print("=" * 50)
    print(f"⏰ Starting at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🚀 Launching Modern GUI with all three phases:")
    print("   Phase 1: Kernel-Level Monitoring")
    print("   Phase 2: AI Threat Hunter")
    print("   Phase 3: Deception Management")
    print("=" * 50)
    
    try:
        # Створюємо головне вікно з темною темою
        root = ttk.Window(
            title="NIMDA - Advanced Security Platform",
            themename="darkly",
            size=(1400, 900),
            resizable=(True, True)
        )
        
        # Встановлюємо іконку (якщо є)
        try:
            root.iconphoto(True, tk.PhotoImage(file="assets/nimda_icon.png"))
        except (tk.TclError, FileNotFoundError):
            pass  # Іконка не обов'язкова
        
        # Створюємо додаток
        _ = NimdaModernGUI(root)  # Посилання зберігати не потрібно
        
        print("✅ GUI successfully initialized")
        print("🔍 All monitoring systems starting...")
        print("🎯 AI Hunter ready for threat hunting")
        print("🎭 Deception systems deploying...")
        print("\n" + "=" * 50)
        print("NIMDA is now running! Check the GUI for real-time security monitoring.")
        print("Press Ctrl+C in terminal to stop the application.")
        print("=" * 50)
        
        # Запускаємо головний цикл
        root.mainloop()
        
    except KeyboardInterrupt:
        print("\n🛑 Shutting down NIMDA...")
        
    except Exception as e:
        print(f"❌ Error starting NIMDA: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        print("👋 NIMDA shutdown complete.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
