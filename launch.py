#!/usr/bin/env python3
"""
NIMDA-Mac Enhanced Launcher
Головний лаунчер для покращеної системи безпеки NIMDA з інтеграцією ШІ
"""

import os
import sys
import argparse
import subprocess
from datetime import datetime

def check_dependencies():
    """Перевіряє наявність необхідних залежностей"""
    required_packages = [
        'tkinter', 'psutil', 'requests', 'sqlite3'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Відсутні пакети: {', '.join(missing_packages)}")
        print("💡 Встановіть їх командою: pip install -r requirements.txt")
        return False
    
    return True

def launch_gui():
    """Запускає графічний інтерфейс"""
    print("🖥️ Запуск GUI...")
    gui_path = os.path.join(os.path.dirname(__file__), 'gui', 'nimda_gui.py')
    
    if os.path.exists(gui_path):
        subprocess.run([sys.executable, gui_path])
    else:
        print(f"❌ GUI файл не знайдено: {gui_path}")

def launch_demo():
    """Запускає демонстрацію"""
    print("🎯 Запуск демонстрації...")
    demo_path = os.path.join(os.path.dirname(__file__), 'nimda_enhanced_demo.py')
    
    if os.path.exists(demo_path):
        subprocess.run([sys.executable, demo_path])
    else:
        print(f"❌ Демо файл не знайдено: {demo_path}")

def update_rules():
    """Оновлює правила безпеки"""
    print("📥 Оновлення правил безпеки...")
    try:
        sys.path.append(os.path.dirname(__file__))
        from core.rule_manager import RuleManager
        
        manager = RuleManager()
        success_count = manager.update_all_rules()
        print(f"✅ Оновлено {success_count} наборів правил")
        
        # Показуємо статистику
        rules = manager.load_rules()
        parsed_rules = manager.get_parsed_rules()
        print(f"📊 Завантажено {len(rules)} правил, розпаршено {len(parsed_rules)}")
        
    except Exception as e:
        print(f"❌ Помилка оновлення правил: {e}")

def check_ai_status():
    """Перевіряє статус ШІ"""
    print("🤖 Перевірка статусу ШІ...")
    try:
        sys.path.append(os.path.dirname(__file__))
        from llm_security_agent import LLMSecurityAgent
        
        agent = LLMSecurityAgent()
        if agent.check_ollama_connection():
            models = agent.get_available_models()
            print("✅ Ollama доступна")
            if models:
                print(f"📋 Доступні моделі: {', '.join(models)}")
            else:
                print("⚠️ Моделі не знайдено")
        else:
            print("❌ Ollama недоступна")
            print("💡 Запустіть Ollama командою: ollama serve")
            
    except Exception as e:
        print(f"❌ Помилка перевірки ШІ: {e}")

def run_security_scan():
    """Запускає швидке сканування безпеки"""
    print("🔍 Швидке сканування безпеки...")
    try:
        sys.path.append(os.path.dirname(__file__))
        from security_monitor import SecurityMonitor
        
        monitor = SecurityMonitor()
        
        # Моніторинг завантажень
        downloads = monitor.monitor_suspicious_downloads()
        print(f"📂 Нових файлів у Downloads: {len(downloads)}")
        
        if downloads:
            suspicious_count = sum(1 for f in downloads if f['suspicious'])
            print(f"⚠️ Підозрілих файлів: {suspicious_count}")
        
        # Аналіз команд
        suspicious_commands = monitor.analyze_command_history_for_threats()
        print(f"💻 Підозрілих команд: {len(suspicious_commands)}")
        
        if suspicious_commands:
            high_risk = sum(1 for c in suspicious_commands if c['risk_level'] == 'high')
            print(f"🚨 Високого ризику: {high_risk}")
        
        # Перевірка цілісності
        integrity = monitor.monitor_file_integrity()
        print(f"🔒 Перевірено файлів: {len(integrity)}")
        
        print("✅ Сканування завершено")
        
    except Exception as e:
        print(f"❌ Помилка сканування: {e}")

def show_system_info():
    """Показує інформацію про систему"""
    print("ℹ️ Інформація про систему NIMDA-Mac")
    print("=" * 50)
    
    # Версія Python
    print(f"🐍 Python: {sys.version}")
    
    # Шлях до скрипта
    script_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"📁 Директорія: {script_dir}")
    
    # Перевірка файлів
    key_files = [
        'core/rule_manager.py',
        'core/threat_analyzer.py',
        'gui/nimda_gui.py',
        'security_monitor.py',
        'llm_security_agent.py'
    ]
    
    print("\n📋 Компоненти системи:")
    for file_path in key_files:
        full_path = os.path.join(script_dir, file_path)
        status = "✅" if os.path.exists(full_path) else "❌"
        print(f"  {status} {file_path}")
    
    # Перевірка папок
    print("\n📁 Структура:")
    for folder in ['core', 'gui', 'configs', 'data', 'rules']:
        folder_path = os.path.join(script_dir, folder)
        status = "✅" if os.path.exists(folder_path) else "❌"
        print(f"  {status} {folder}/")

def main():
    """Головна функція лаунчера"""
    parser = argparse.ArgumentParser(
        description="NIMDA-Mac Enhanced Security System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Приклади використання:
  python launch.py gui              # Запуск GUI
  python launch.py demo             # Запуск демонстрації
  python launch.py update-rules     # Оновлення правил
  python launch.py check-ai         # Перевірка ШІ
  python launch.py scan             # Швидке сканування
  python launch.py info             # Інформація про систему
        """
    )
    
    parser.add_argument(
        'command',
        choices=['gui', 'demo', 'update-rules', 'check-ai', 'scan', 'info'],
        help='Команда для виконання'
    )
    
    args = parser.parse_args()
    
    print("🛡️ NIMDA-Mac Enhanced Security System")
    print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    # Перевірка залежностей
    if not check_dependencies():
        return 1
    
    # Виконання команди
    try:
        if args.command == 'gui':
            launch_gui()
        elif args.command == 'demo':
            launch_demo()
        elif args.command == 'update-rules':
            update_rules()
        elif args.command == 'check-ai':
            check_ai_status()
        elif args.command == 'scan':
            run_security_scan()
        elif args.command == 'info':
            show_system_info()
            
    except KeyboardInterrupt:
        print("\n🛑 Операцію перервано користувачем")
        return 1
    except Exception as e:
        print(f"\n❌ Помилка: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
