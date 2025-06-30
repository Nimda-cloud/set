#!/bin/bash
# NIMDA Auto-Fix Script
# Автоматичне виправлення проблем GUI

echo "🔧 NIMDA Auto-Fix Script"
echo "========================"

# Перевірка Python
echo "🐍 Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found!"
    exit 1
fi

echo "✅ Python3 found: $(python3 --version)"

# Перевірка залежностей
echo "📦 Checking dependencies..."
python3 -c "
import sys
missing = []
modules = ['tkinter', 'ttkbootstrap', 'psutil', 'sqlite3', 'threading', 'queue']
for module in modules:
    try:
        __import__(module)
        print(f'   ✅ {module}')
    except ImportError:
        missing.append(module)
        print(f'   ❌ {module}')

if missing:
    print(f'❌ Missing modules: {missing}')
    sys.exit(1)
else:
    print('✅ All modules available')
"

if [ $? -ne 0 ]; then
    echo "🔄 Installing missing dependencies..."
    pip3 install ttkbootstrap psutil requests
fi

# Перевірка файлової структури
echo "📁 Checking file structure..."
required_files=(
    "gui/nimda_modern_gui.py"
    "core/kernel_monitor.py" 
    "core/system_query_engine.py"
    "core/deception_manager.py"
    "llm_security_agent.py"
    "start_nimda_modern.py"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "   ✅ $file"
    else
        echo "   ❌ $file"
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -ne 0 ]; then
    echo "❌ Missing critical files: ${missing_files[*]}"
    echo "💡 Please restore from backup or re-run setup"
    exit 1
fi

# Очищення тимчасових файлів
echo "🧹 Cleaning temporary files..."
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
echo "✅ Cleanup completed"

# Перевірка прав доступу
echo "🔐 Checking permissions..."
chmod +x *.py 2>/dev/null || true
chmod +x *.sh 2>/dev/null || true
echo "✅ Permissions updated"

# Швидкий тест GUI
echo "🧪 Testing GUI components..."
python3 -c "
try:
    import ttkbootstrap as ttk
    from gui.nimda_modern_gui import NimdaModernGUI
    
    # Тест створення GUI
    root = ttk.Window(themename='darkly')
    root.withdraw()
    
    gui = NimdaModernGUI(root)
    print('✅ GUI components working')
    
    root.destroy()
    
except Exception as e:
    print(f'❌ GUI test failed: {e}')
    exit(1)
"

if [ $? -ne 0 ]; then
    echo "❌ GUI test failed"
    exit 1
fi

# Запуск діагностики
echo "🔍 Running diagnostics..."
python3 gui_diagnostics.py | tail -n 5

echo ""
echo "🎉 Auto-fix completed successfully!"
echo ""
echo "💡 Ready to launch NIMDA:"
echo "   ./run_nimda.sh            # Normal launch"
echo "   ./run_nimda.sh quick      # Quick launch"
echo "   python3 performance_demo.py  # Performance demo"
echo "   python3 stress_test.py       # Stress test"
