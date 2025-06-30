#!/usr/bin/env python3
"""
NIMDA Project Reorganization Script
Скрипт для реорганізації структури проекту NIMDA

Переносить файли в правильні директорії та виправляє імпорти автоматично.
"""

import os
import shutil
import re
from pathlib import Path

class NIMDAReorganizer:
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.backup_dir = self.base_path / "backup_before_reorganize"
        
        # Нова структура директорій
        self.new_structure = {
            'scripts': ['start_nimda.sh', 'start_nimda_tkinter.sh', 'start_nimda_security.sh', 
                       'setup_gemini.sh', 'test_gemini_curl.sh'],
            'docs': ['README_DEVICES_PROCESSES.md', 'README_MALWARE_DETECTION.md', 
                    'README_SECURITY.md', 'README_THREAT_LEVELS.md', 'README_DARK_THEME.md',
                    'COMPREHENSIVE_FIXES_SUMMARY.md', 'FIXES_SUMMARY.md', 
                    'PRIVILEGES_INSTRUCTIONS.md'],
            'tests': [f for f in os.listdir(self.base_path) if f.startswith('test_') and f.endswith('.py')],
            'demos': ['demo_sounds.py', 'nimda_complete_demo.py'],
            'configs': ['ai_providers_config.json', 'security_policy.json'],
            'data': ['scheduled_tasks.db', 'security_events.db']
        }
        
        # Файли що залишаються в корені (важливі)
        self.root_files = [
            'nimda_integrated.py',
            'nimda_tkinter.py', 
            'security_monitor.py',
            'malware_detection.py',
            'ai_providers.py',
            'llm_security_agent.py',
            'sound_alerts.py',
            'sound_alerts_enhanced.py',
            'security_display.py',
            'task_scheduler.py',
            'threat_level_analyzer.py',
            'requirements.txt',
            'README.md'
        ]
        
        # Мапа переміщених файлів для виправлення імпортів
        self.import_mapping = {}

    def create_backup(self):
        """Створити резервну копію проекту"""
        print("📦 Створення резервної копії...")
        
        if self.backup_dir.exists():
            shutil.rmtree(self.backup_dir)
        
        # Копіювати всі файли в backup
        shutil.copytree(self.base_path, self.backup_dir, 
                       ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.git'))
        
        print(f"✅ Резервна копія створена: {self.backup_dir}")

    def create_directories(self):
        """Створити нові директорії"""
        print("📁 Створення нової структури директорій...")
        
        directories = ['scripts', 'docs', 'tests', 'demos', 'configs', 'data', 'src']
        
        for dir_name in directories:
            dir_path = self.base_path / dir_name
            dir_path.mkdir(exist_ok=True)
            print(f"   📂 Створено: {dir_name}/")

    def move_files(self):
        """Перемістити файли в нові директорії"""
        print("🚚 Переміщення файлів...")
        
        for target_dir, files in self.new_structure.items():
            target_path = self.base_path / target_dir
            
            for file_name in files:
                source_file = self.base_path / file_name
                target_file = target_path / file_name
                
                if source_file.exists() and source_file != target_file:
                    shutil.move(str(source_file), str(target_file))
                    print(f"   📄 {file_name} → {target_dir}/")
                    
                    # Зберегти мапу для виправлення імпортів
                    if file_name.endswith('.py'):
                        module_name = file_name[:-3]  # Прибрати .py
                        self.import_mapping[module_name] = f"{target_dir}.{module_name}"

    def fix_imports_in_file(self, file_path: Path):
        """Виправити імпорти в одному файлі"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            original_content = content
            
            # Виправити імпорти для переміщених модулів
            for old_module, new_module in self.import_mapping.items():
                # Виправити direct imports
                content = re.sub(f'import {old_module}', f'import {new_module}', content)
                content = re.sub(f'from {old_module} import', f'from {new_module} import', content)
                
                # Виправити relative imports якщо файл в підпапці
                if str(file_path).find('/tests/') != -1:
                    # Для тестів додати sys.path
                    if 'sys.path' not in content and any(old in content for old in self.import_mapping.keys()):
                        sys_path_addition = '''import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

'''
                        # Додати після shebang та docstring
                        lines = content.split('\n')
                        insert_index = 0
                        
                        # Пропустити shebang
                        if lines[0].startswith('#!'):
                            insert_index = 1
                        
                        # Пропустити docstring
                        if insert_index < len(lines) and lines[insert_index].strip().startswith('"""'):
                            for i in range(insert_index + 1, len(lines)):
                                if lines[i].strip().endswith('"""'):
                                    insert_index = i + 1
                                    break
                        
                        lines.insert(insert_index, sys_path_addition)
                        content = '\n'.join(lines)
            
            # Записати тільки якщо були зміни
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"   🔧 Виправлено імпорти: {file_path.name}")
                
        except Exception as e:
            print(f"   ❌ Помилка при виправленні {file_path}: {e}")

    def fix_all_imports(self):
        """Виправити імпорти в усіх Python файлах"""
        print("🔧 Виправлення імпортів...")
        
        # Знайти всі .py файли
        python_files = []
        
        # Файли в корені
        for file_path in self.base_path.glob('*.py'):
            python_files.append(file_path)
        
        # Файли в підпапках
        for subdir in ['tests', 'demos', 'scripts']:
            subdir_path = self.base_path / subdir
            if subdir_path.exists():
                for file_path in subdir_path.glob('*.py'):
                    python_files.append(file_path)
        
        # Виправити імпорти в кожному файлі
        for file_path in python_files:
            self.fix_imports_in_file(file_path)

    def create_init_files(self):
        """Створити __init__.py файли для правильної структури пакетів"""
        print("📝 Створення __init__.py файлів...")
        
        # Створити __init__.py в основних директоріях
        init_dirs = ['tests', 'demos']
        
        for dir_name in init_dirs:
            init_file = self.base_path / dir_name / '__init__.py'
            init_file.write_text('# NIMDA module\n')
            print(f"   📄 Створено: {dir_name}/__init__.py")

    def create_updated_scripts(self):
        """Оновити скрипти запуску з новими шляхами"""
        print("📜 Оновлення скриптів запуску...")
        
        scripts_dir = self.base_path / 'scripts'
        
        # Оновити start_nimda_tkinter.sh
        start_script = scripts_dir / 'start_nimda_tkinter.sh'
        if start_script.exists():
            content = start_script.read_text()
            # Виправити шлях до головного модуля
            updated_content = content.replace(
                'python3 nimda_tkinter.py',
                'python3 ../nimda_tkinter.py'
            )
            start_script.write_text(updated_content)
            print("   🔧 Оновлено: start_nimda_tkinter.sh")

    def create_project_summary(self):
        """Створити підсумок реорганізації"""
        summary_file = self.base_path / 'REORGANIZATION_SUMMARY.md'
        
        summary_content = f"""# NIMDA Project Reorganization Summary

## 📅 Дата реорганізації: {os.popen('date').read().strip()}

## 🗂️ Нова структура проекту:

### 📁 Корінь (важливі файли):
{chr(10).join(f'- {f}' for f in self.root_files)}

### 📁 scripts/ (скрипти запуску):
{chr(10).join(f'- {f}' for f in self.new_structure.get('scripts', []))}

### 📁 docs/ (документація):
{chr(10).join(f'- {f}' for f in self.new_structure.get('docs', []))}

### 📁 tests/ (тести):
{chr(10).join(f'- {f}' for f in self.new_structure.get('tests', []))}

### 📁 demos/ (демонстрації):
{chr(10).join(f'- {f}' for f in self.new_structure.get('demos', []))}

### 📁 configs/ (конфігурації):
{chr(10).join(f'- {f}' for f in self.new_structure.get('configs', []))}

### 📁 data/ (бази даних):
{chr(10).join(f'- {f}' for f in self.new_structure.get('data', []))}

## 🔧 Виконані дії:

1. ✅ Створено резервну копію в `backup_before_reorganize/`
2. ✅ Створено нову структуру директорій
3. ✅ Перенесено файли в відповідні папки
4. ✅ Виправлено імпорти в Python файлах
5. ✅ Створено __init__.py файли
6. ✅ Оновлено скрипти запуску

## 🚀 Запуск після реорганізації:

```bash
# З кореня проекту:
python3 nimda_tkinter.py

# Або через скрипт:
./scripts/start_nimda_tkinter.sh

# Тестування:
python3 -m pytest tests/

# Демо:
python3 demos/nimda_complete_demo.py
```

## 🔄 Відновлення (якщо потрібно):

```bash
# Видалити поточну структуру та відновити з backup
rm -rf scripts docs tests demos configs data
cp -r backup_before_reorganize/* .
```

## 📞 Підтримка:

Якщо виникли проблеми з імпортами або запуском, перевірте:
1. sys.path в тестових файлах
2. Шляхи в скриптах запуску
3. Правильність імпортів в основних модулях
"""
        
        summary_file.write_text(summary_content)
        print("📋 Створено звіт: REORGANIZATION_SUMMARY.md")

    def run_reorganization(self):
        """Запустити повну реорганізацію"""
        print("🚀 ПОЧАТОК РЕОРГАНІЗАЦІЇ ПРОЕКТУ NIMDA")
        print("=" * 50)
        
        try:
            # Основні етапи
            self.create_backup()
            self.create_directories()
            self.move_files()
            self.fix_all_imports()
            self.create_init_files()
            self.create_updated_scripts()
            self.create_project_summary()
            
            print("\n" + "=" * 50)
            print("🎉 РЕОРГАНІЗАЦІЯ ЗАВЕРШЕНА УСПІШНО!")
            print("=" * 50)
            print("📁 Нова структура створена")
            print("🔧 Імпорти виправлені")
            print("📦 Резервна копія збережена")
            print("📋 Звіт створено: REORGANIZATION_SUMMARY.md")
            print("\n🚀 Для запуску використовуйте:")
            print("   python3 nimda_tkinter.py")
            print("   або ./scripts/start_nimda_tkinter.sh")
            
        except Exception as e:
            print(f"\n❌ ПОМИЛКА ПРИ РЕОРГАНІЗАЦІЇ: {e}")
            print("📦 Відновіть з резервної копії якщо потрібно")
            raise

def main():
    """Головна функція"""
    # Отримати шлях до проекту
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    print("🛡️ NIMDA Project Reorganization Tool")
    print("=" * 40)
    print(f"📍 Робоча директорія: {current_dir}")
    
    # Підтвердження від користувача
    response = input("\n⚠️  Це реорганізує структуру проекту. Продовжити? (y/N): ")
    if response.lower() not in ['y', 'yes', 'так', 'т']:
        print("❌ Реорганізацію скасовано")
        return
    
    # Запустити реорганізацію
    reorganizer = NIMDAReorganizer(current_dir)
    reorganizer.run_reorganization()

if __name__ == "__main__":
    main()
