#!/usr/bin/env python3
"""
NIMDA-Mac Enhanced Launch Script
Запуск покращеної системи безпеки з підготовкою середовища
"""

import os
import sys
import subprocess
import argparse
from datetime import datetime

def setup_environment():
    """Підготовка середовища перед запуском"""
    print("🔧 Підготовка середовища NIMDA-Mac...")
    
    # Перевіряємо права доступу до файлу
    if not os.access(__file__, os.X_OK):
        print("⚠️ Надання прав виконання...")
        os.chmod(__file__, 0o755)
    
    # Створюємо необхідні папки
    required_dirs = ['rules', 'logs', 'data', 'configs']
    for dir_name in required_dirs:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
            print(f"📁 Створено папку: {dir_name}")
    
    # Перевіряємо .gitignore
    gitignore_path = '.gitignore'
    if os.path.exists(gitignore_path):
        with open(gitignore_path, 'r') as f:
            content = f.read()
        
        required_ignores = ['rules/', '*.rules', '*.log', '*.db']
        missing_ignores = [ig for ig in required_ignores if ig not in content]
        
        if missing_ignores:
            with open(gitignore_path, 'a') as f:
                f.write("\n# NIMDA-Mac security files\n")
                for ignore in missing_ignores:
                    f.write(f"{ignore}\n")
            print(f"📝 Оновлено .gitignore з: {', '.join(missing_ignores)}")

def download_initial_rules():
    """Завантаження початкових правил безпеки"""
    print("\n📥 Завантаження початкових правил безпеки...")
    
    try:
        from core.rule_manager import RuleManager
        manager = RuleManager()
        success_count = manager.update_all_rules()
        print(f"✅ Завантажено {success_count} наборів правил")
        
        # Отримуємо кількість правил
        rules = manager.load_rules()
        print(f"📊 Загалом правил для аналізу: {len(rules)}")
        
    except Exception as e:
        print(f"⚠️ Не вдалося завантажити правила: {e}")
        print("💡 Правила будуть завантажені при першому запуску аналізатора")

def check_dependencies():
    """Перевірка залежностей"""
    print("\n🔍 Перевірка залежностей...")
    
    required_packages = [
        'tkinter', 'psutil', 'requests', 'sqlite3'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package}")
    
    if missing_packages:
        print(f"\n⚠️ Відсутні пакети: {', '.join(missing_packages)}")
        print("📦 Встановіть їх командою: pip install -r requirements.txt")
        return False
    
    return True

def check_ollama():
    """Перевірка доступності Ollama"""
    print("\n🤖 Перевірка ШІ (Ollama)...")
    
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=3)
        if response.status_code == 200:
            models = response.json().get('models', [])
            print(f"✅ Ollama доступна, моделей: {len(models)}")
            if models:
                print(f"📋 Доступні моделі: {', '.join([m.get('name', 'Unknown') for m in models[:3]])}")
            return True
        else:
            print(f"⚠️ Ollama відповіла з кодом: {response.status_code}")
    except Exception as e:
        print(f"❌ Ollama недоступна: {e}")
        print("💡 Для роботи ШІ встановіть Ollama: https://ollama.ai/download")
    
    return False

def launch_gui():
    """Запуск GUI"""
    print("\n🚀 Запуск GUI...")
    try:
        subprocess.run([sys.executable, "gui/nimda_gui.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Помилка запуску GUI: {e}")
        return False
    except KeyboardInterrupt:
        print("\n🛑 GUI зупинено користувачем")
    return True

def launch_demo():
    """Запуск демонстрації"""
    print("\n🎭 Запуск демонстрації...")
    try:
        subprocess.run([sys.executable, "nimda_enhanced_demo.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Помилка запуску демонстрації: {e}")
        return False
    except KeyboardInterrupt:
        print("\n🛑 Демонстрацію зупинено користувачем")
    return True

def main():
    """Головна функція"""
    parser = argparse.ArgumentParser(description="NIMDA-Mac Enhanced Security System")
    parser.add_argument('--gui', action='store_true', help='Запустити GUI')
    parser.add_argument('--demo', action='store_true', help='Запустити демонстрацію')
    parser.add_argument('--setup-only', action='store_true', help='Тільки підготовка середовища')
    parser.add_argument('--skip-rules', action='store_true', help='Пропустити завантаження правил')
    
    args = parser.parse_args()
    
    print("🛡️ NIMDA-Mac Enhanced Security System")
    print("=" * 50)
    print(f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Підготовка середовища
    setup_environment()
    
    # Перевірка залежностей
    if not check_dependencies():
        print("\n❌ Критичні залежності відсутні!")
        return 1
    
    # Завантаження правил (якщо не пропускаємо)
    if not args.skip_rules:
        download_initial_rules()
    
    # Перевірка Ollama
    check_ollama()
    
    if args.setup_only:
        print("\n✅ Підготовка середовища завершена!")
        return 0
    
    # Запуск відповідного режиму
    if args.gui:
        success = launch_gui()
    elif args.demo:
        success = launch_demo()
    else:
        # Інтерактивний вибір
        print("\n🎯 Оберіть режим запуску:")
        print("1. GUI (Графічний інтерфейс)")
        print("2. Demo (Демонстрація можливостей)")
        print("3. Вихід")
        
        choice = input("\nВаш вибір (1-3): ").strip()
        
        if choice == '1':
            success = launch_gui()
        elif choice == '2':
            success = launch_demo()
        elif choice == '3':
            print("👋 До побачення!")
            return 0
        else:
            print("❌ Невірний вибір!")
            return 1
    
    if success:
        print("\n🎉 Програма завершена успішно!")
        return 0
    else:
        print("\n💥 Виникли помилки під час виконання!")
        return 1

if __name__ == "__main__":
    exit(main())
