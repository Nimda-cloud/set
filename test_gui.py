#!/usr/bin/env python3
"""
NIMDA GUI Test Script
Test both PyQt6 and Tkinter GUI interfaces
"""

import sys
import subprocess
import importlib.util

def test_pyqt6_import():
    """Test if PyQt6 can be imported"""
    try:
        import PyQt6
        print("✅ PyQt6 is available")
        return True
    except ImportError:
        print("❌ PyQt6 not available")
        return False

def test_tkinter_import():
    """Test if tkinter can be imported"""
    try:
        import tkinter
        print("✅ Tkinter is available")
        return True
    except ImportError:
        print("❌ Tkinter not available")
        return False

def test_security_modules():
    """Test if security modules are available"""
    modules = ['security_monitor', 'security_display', 'llm_security_agent']
    available = True
    
    for module in modules:
        try:
            importlib.import_module(module)
            print(f"✅ {module} is available")
        except ImportError as e:
            print(f"❌ {module} not available: {e}")
            available = False
    
    return available

def test_gui_creation():
    """Test GUI creation without running"""
    print("\n🧪 Testing GUI creation...")
    
    # Test PyQt6 GUI
    if test_pyqt6_import():
        try:
            from PyQt6.QtWidgets import QApplication
            app = QApplication([])
            print("✅ PyQt6 QApplication created successfully")
            app.quit()
        except Exception as e:
            print(f"❌ PyQt6 GUI test failed: {e}")
    
    # Test Tkinter GUI
    if test_tkinter_import():
        try:
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()  # Hide the window
            print("✅ Tkinter root window created successfully")
            root.destroy()
        except Exception as e:
            print(f"❌ Tkinter GUI test failed: {e}")

def test_ollama_connection():
    """Test Ollama connection"""
    print("\n🤖 Testing Ollama connection...")
    
    try:
        import requests
        response = requests.get('http://localhost:11434/api/tags', timeout=5)
        if response.status_code == 200:
            print("✅ Ollama is running and accessible")
            return True
        else:
            print(f"❌ Ollama responded with status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Ollama connection failed: {e}")
        return False

def main():
    """Main test function"""
    print("🚀 NIMDA GUI Test Suite")
    print("=" * 50)
    
    # Test imports
    print("\n📦 Testing imports...")
    pyqt6_available = test_pyqt6_import()
    tkinter_available = test_tkinter_import()
    security_available = test_security_modules()
    
    # Test GUI creation
    test_gui_creation()
    
    # Test Ollama
    ollama_available = test_ollama_connection()
    
    # Summary
    print("\n📊 Test Summary")
    print("=" * 50)
    print(f"PyQt6 GUI: {'✅ Available' if pyqt6_available else '❌ Not available'}")
    print(f"Tkinter GUI: {'✅ Available' if tkinter_available else '❌ Not available'}")
    print(f"Security Modules: {'✅ Available' if security_available else '❌ Not available'}")
    print(f"Ollama: {'✅ Available' if ollama_available else '❌ Not available'}")
    
    # Recommendations
    print("\n💡 Recommendations:")
    if not pyqt6_available:
        print("- Install PyQt6: pip3 install PyQt6")
    if not tkinter_available:
        print("- Tkinter should be built into Python")
    if not security_available:
        print("- Security modules are required for full functionality")
    if not ollama_available:
        print("- Install and start Ollama: brew install ollama && ollama serve")
    
    if pyqt6_available and security_available:
        print("\n✅ PyQt6 GUI is ready to use: ./start_nimda_gui.sh")
    elif tkinter_available and security_available:
        print("\n✅ Tkinter GUI is ready to use: ./start_nimda_tkinter.sh")
    else:
        print("\n❌ No GUI is fully ready. Please install missing dependencies.")

if __name__ == "__main__":
    main() 