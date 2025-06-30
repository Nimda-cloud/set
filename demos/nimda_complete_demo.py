#!/usr/bin/env python3
"""
NIMDA System Complete Demo
Повна демонстрація можливостей системи NIMDA
"""

import time
import sys
from datetime import datetime

def show_header():
    """Показати заголовок демонстрації"""
    print("🛡️" + "=" * 60 + "🛡️")
    print("🚀 NIMDA SECURITY SYSTEM - COMPLETE DEMO 🚀")
    print("🛡️" + "=" * 60 + "🛡️")
    print(f"📅 Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("📋 Версія: 2.5 Enhanced")
    print("🖥️ Платформа: macOS M1 Max")
    print()

def demo_threat_analysis():
    """Демонстрація аналізу загроз"""
    print("🔍 ДЕМОНСТРАЦІЯ АНАЛІЗУ ЗАГРОЗ")
    print("-" * 40)
    
    scenarios = [
        {
            "name": "🟢 Нормальна активність",
            "description": "Chrome браузер, стандартна робота",
            "level": "LOW",
            "color": "\033[92m"
        },
        {
            "name": "🟡 Підозріла активність",
            "description": "SSH з'єднання з невідомого IP",
            "level": "MEDIUM", 
            "color": "\033[93m"
        },
        {
            "name": "🟠 Висока загроза",
            "description": "Відкритий порт 4444 (Metasploit)",
            "level": "HIGH",
            "color": "\033[95m"
        },
        {
            "name": "🔴 Критична загроза",
            "description": "Виявлено підпис трояна",
            "level": "CRITICAL",
            "color": "\033[91m"
        },
        {
            "name": "⚫ Надзвичайна ситуація",
            "description": "Майнер криптовалюти + підвищення привілеїв",
            "level": "EMERGENCY",
            "color": "\033[90m"
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"{scenario['color']}{scenario['name']}\033[0m")
        print(f"  📝 {scenario['description']}")
        print(f"  📊 Рівень: {scenario['level']}")
        
        if scenario['level'] in ['CRITICAL', 'EMERGENCY']:
            print("  🚨 Автоматичні дії:")
            actions = ["Ізоляція файлів", "Блокування процесів", "Сповіщення адміністратора"]
            for action in actions:
                print(f"    ▶ {action}")
                time.sleep(0.3)
        
        print()
        time.sleep(1)

def demo_sound_alerts():
    """Демонстрація звукових сповіщень"""
    print("🔊 ДЕМОНСТРАЦІЯ ЗВУКОВИХ СПОВІЩЕНЬ")
    print("-" * 40)
    
    sound_levels = [
        ("🟢 LOW", "Tink", "Легкий сигнал для звичайних подій"),
        ("🟡 MEDIUM", "Pop", "Помірний сигнал для уваги"),
        ("🟠 HIGH", "Sosumi", "Помітний сигнал для дій"),
        ("🔴 CRITICAL", "Basso", "Гучний сигнал для критичних подій"),
        ("⚫ EMERGENCY", "Funk", "Сирена для надзвичайних ситуацій")
    ]
    
    for level, sound, description in sound_levels:
        print(f"{level}: {sound}")
        print(f"  🎵 {description}")
        print(f"  📢 Відтворення: /System/Library/Sounds/{sound}.aiff")
        print()
        time.sleep(0.8)

def demo_ai_integration():
    """Демонстрація AI інтеграції"""
    print("🤖 ДЕМОНСТРАЦІЯ AI ІНТЕГРАЦІЇ")
    print("-" * 40)
    
    ai_features = [
        {
            "provider": "Ollama (qwen2.5-coder)",
            "model": "qwen2.5-coder:latest",
            "purpose": "Аналіз загроз та рекомендації",
            "status": "✅ Активний"
        },
        {
            "provider": "Gemini",
            "model": "gemini-2.0-flash",
            "purpose": "Глибокий аналіз та звіти",
            "status": "✅ Налаштований"
        },
        {
            "provider": "Cohere Reranker",
            "model": "rerank-english-v3.0",
            "purpose": "Покращення релевантності",
            "status": "✅ Інтегрований"
        }
    ]
    
    for ai in ai_features:
        print(f"🔹 {ai['provider']}")
        print(f"  📊 Модель: {ai['model']}")
        print(f"  🎯 Призначення: {ai['purpose']}")
        print(f"  🔄 Статус: {ai['status']}")
        print()

def demo_system_capabilities():
    """Демонстрація можливостей системи"""
    print("⚙️ МОЖЛИВОСТІ СИСТЕМИ")
    print("-" * 40)
    
    capabilities = [
        "🔍 Реальний моніторинг мережі",
        "🖥️ Відстеження пристроїв (USB, Bluetooth, Thunderbolt)",
        "⚙️ Моніторинг процесів та їх аналіз",
        "🛡️ Автоматичне виявлення малваре",
        "🔊 Розумні звукові сповіщення",
        "🤖 AI-аналіз загроз",
        "📊 Система рівнів загроз",
        "🌙 Темна тема інтерфейсу",
        "📝 Комплексне логування",
        "🔐 Безпечне управління credentials"
    ]
    
    for i, capability in enumerate(capabilities, 1):
        print(f"{i:2d}. {capability}")
        time.sleep(0.2)
    
    print()

def demo_file_structure():
    """Демонстрація структури файлів"""
    print("📁 СТРУКТУРА ПРОЕКТУ")
    print("-" * 40)
    
    structure = {
        "Основні модулі": [
            "nimda_integrated.py - Головний модуль",
            "nimda_tkinter.py - GUI інтерфейс",
            "security_monitor.py - Моніторинг безпеки",
            "malware_detection.py - Виявлення малваре"
        ],
        "AI та звук": [
            "ai_providers.py - Управління AI провайдерами",
            "sound_alerts.py - Звукові сповіщення",
            "sound_alerts_enhanced.py - Розширені сповіщення",
            "threat_level_analyzer.py - Аналіз загроз"
        ],
        "Тестування": [
            "test_threat_analyzer.py - Тест аналізатора",
            "test_*.py - Модульні тести",
            "demo_sounds.py - Демо звуків"
        ],
        "Документація": [
            "README*.md - Детальна документація",
            "FIXES_SUMMARY.md - Огляд виправлень"
        ]
    }
    
    for category, files in structure.items():
        print(f"📂 {category}:")
        for file in files:
            print(f"  📄 {file}")
        print()

def demo_installation():
    """Демонстрація інсталяції"""
    print("🛠️ ШВИДКА ІНСТАЛЯЦІЯ")
    print("-" * 40)
    
    steps = [
        "1️⃣ git clone <repository>",
        "2️⃣ cd NIMDA/set",
        "3️⃣ pip3 install -r requirements.txt",
        "4️⃣ ollama pull qwen2.5-coder:latest",
        "5️⃣ ./start_nimda_tkinter.sh",
        "6️⃣ Готово! 🎉"
    ]
    
    for step in steps:
        print(f"  {step}")
        time.sleep(0.3)
    
    print()

def main():
    """Головна функція демонстрації"""
    show_header()
    
    demos = [
        ("🔍 Аналіз загроз", demo_threat_analysis),
        ("🔊 Звукові сповіщення", demo_sound_alerts),
        ("🤖 AI інтеграція", demo_ai_integration),
        ("⚙️ Можливості системи", demo_system_capabilities),
        ("📁 Структура проекту", demo_file_structure),
        ("🛠️ Інсталяція", demo_installation)
    ]
    
    for title, demo_func in demos:
        input(f"\n🎬 Натисніть Enter для демонстрації: {title}")
        demo_func()
        time.sleep(1)
    
    print("🎉 ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА!")
    print("=" * 62)
    print("🚀 NIMDA Security System готова до використання!")
    print("📞 Для запуску: ./start_nimda_tkinter.sh")
    print("📖 Документація: README*.md")
    print("=" * 62)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 Демонстрацію перервано користувачем")
        sys.exit(0)
