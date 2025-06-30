# NIMDA Security System

## 🔒 Comprehensive Security Monitoring for Mac M1 Max

NIMDA Security System - це розширена система моніторингу безпеки з інтеграцією Ollama для інтелектуального аналізу загроз на Mac M1 Max.

## 🌟 Основні можливості

### 🔍 Моніторинг портів та пристроїв
- **USB пристрої** - відстеження підключень/відключень
- **Thunderbolt** - моніторинг високошвидкісних з'єднань
- **Bluetooth** - контроль бездротових пристроїв
- **Мережеві інтерфейси** - моніторинг мережевої активності
- **Аудіо пристрої** - відстеження гарнітур та динаміків
- **Акумулятор** - контроль стану живлення

### 🤖 LLM-інтеграція (Ollama)
- **Розумний аналіз** подій безпеки
- **Рекомендації** на основі контексту
- **Розвідка загроз** в реальному часі
- **Інтерактивні запити** до AI-агента
- **Аналіз конкретних пристроїв**

### 📊 Багатоекранний інтерфейс
- **TMUX-інтеграція** для зручного відображення
- **Панель безпеки** з подіями та пристроями
- **Інтерактивне меню** з гарячими клавішами
- **Кольорове кодування** рівнів ризику

## 🚀 Швидкий старт

### 1. Встановлення залежностей

```bash
# Перевірка системи
./test_security_system.py

# Встановлення Python залежностей
pip3 install -r requirements.txt

# Встановлення Ollama (якщо потрібно)
brew install ollama
# або
curl -fsSL https://ollama.ai/install.sh | sh
```

### 2. Налаштування Ollama

```bash
# Запуск Ollama сервера
ollama serve

# Завантаження моделі (рекомендовано)
ollama pull llama3:latest
# або
ollama pull qwen2.5-coder:latest
```

### 3. Запуск системи

```bash
# Автоматичний запуск з перевірками
./start_nimda_security.sh

# Або ручний запуск
python3 nimda_integrated.py
```

## 📋 Структура проекту

```
set/
├── security_monitor.py      # Основний монітор безпеки
├── security_display.py      # Відображення подій безпеки
├── llm_security_agent.py    # LLM-агент для аналізу
├── nimda_integrated.py      # Інтегрована система
├── test_security_system.py  # Тестування системи
├── start_nimda_security.sh  # Скрипт запуску
└── requirements.txt         # Залежності Python
```

## 🎮 Керування системою

### Гарячі клавіші в меню

| Клавіша | Дія |
|---------|------|
| `L` | Увімкнути блокування |
| `U` | Вимкнути блокування |
| `1-6` | Фокус на панель |
| `S` | Сканування системи |
| `C` | Очистити логи |
| `R` | Перезапустити монітори |
| `I` | Інформація про систему |
| `T` | Тест звуків |
| `M` | Вимкнути/увімкнути звук |
| `E` | Аварійна сирена |
| `A` | Демо сповіщень |
| `B` | Аналіз безпеки (LLM) |
| `D` | Перевірка пристроїв |
| `H` | Розвідка загроз |
| `O` | Запит до Ollama |
| `Q` | Вийти |

### TMUX навігація

```bash
Ctrl+B + ←→↑↓  # Переміщення між панелями
Ctrl+B + C      # Нова панель
Ctrl+B + %      # Розділити вертикально
Ctrl+B + "      # Розділити горизонтально
```

## 🔧 Налаштування

### Конфігурація рівнів ризику

В `security_monitor.py` можна налаштувати рівні ризику для різних типів подій:

```python
self.risk_thresholds = {
    'new_usb_device': 'medium',
    'new_network': 'high',
    'vpn_connection': 'low',
    'ssh_tunnel': 'medium',
    'bluetooth_device': 'low',
    'thunderbolt_device': 'high',
    'unknown_device': 'high',
    'mass_storage': 'medium',
    'network_interface': 'medium'
}
```

### Вибір моделі Ollama

В `llm_security_agent.py` можна змінити модель:

```python
# Рекомендовані моделі для безпеки:
# - llama3:latest (загальна безпека)
# - qwen2.5-coder:latest (аналіз коду/логів)
# - codellama:latest (технічний аналіз)
```

## 📊 Моніторинг та логування

### База даних подій

Система зберігає всі події в SQLite базі даних:

```sql
-- Таблиця подій безпеки
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    event_type TEXT,
    device_name TEXT,
    device_id TEXT,
    port_type TEXT,
    action TEXT,
    details TEXT,
    risk_level TEXT,
    hash TEXT UNIQUE
);

-- Історія пристроїв
CREATE TABLE device_history (
    id INTEGER PRIMARY KEY,
    device_id TEXT,
    first_seen TEXT,
    last_seen TEXT,
    connection_count INTEGER,
    total_activity_time INTEGER
);
```

### Типи подій

- `device_connected` - підключення пристрою
- `device_disconnected` - відключення пристрою
- `device_activity` - активність пристрою
- `anomaly_detected` - виявлена аномалія

### Рівні ризику

- `low` - низький ризик (зелений)
- `medium` - середній ризик (жовтий)
- `high` - високий ризик (червоний)
- `critical` - критичний ризик (пурпурний)

## 🤖 LLM-функції

### Аналіз подій безпеки

```python
# Автоматичний аналіз подій
analysis = llm_agent.analyze_security_events(events)
```

### Розвідка загроз

```python
# Отримання інформації про загрози
intelligence = llm_agent.get_threat_intelligence("USB attacks")
```

### Аналіз конкретного пристрою

```python
# Аналіз підозрілого пристрою
analysis = llm_agent.analyze_specific_device("Unknown USB Device")
```

## 🔍 Тестування

### Запуск тестів

```bash
# Повне тестування системи
python3 test_security_system.py

# Тестування окремих компонентів
python3 security_monitor.py
python3 security_display.py
python3 llm_security_agent.py
```

### Перевірка Ollama

```bash
# Перевірка підключення
curl http://localhost:11434/api/tags

# Список доступних моделей
ollama list
```

## 🛠️ Розширення

### Додавання нових типів пристроїв

1. Додати новий тип в `extract_devices()`
2. Налаштувати рівень ризику
3. Додати відображення в `security_display.py`

### Створення нових LLM-промптів

```python
def custom_analysis(self, data):
    prompt = """
    Your custom security analysis prompt here.
    Focus on specific security aspects.
    """
    return self.query_ollama(prompt, str(data))
```

## 🚨 Усунення неполадок

### Проблеми з Ollama

```bash
# Перезапуск Ollama
pkill ollama
ollama serve

# Перевірка моделей
ollama list
ollama pull llama3:latest
```

### Проблеми з правами доступу

```bash
# Надання прав для системних команд
sudo chmod +x /usr/bin/system_profiler
sudo chmod +x /usr/sbin/networksetup
```

### Проблеми з TMUX

```bash
# Очищення сесій
tmux kill-server
tmux kill-session -t nimda_integrated
```

## 📈 Продуктивність

### Оптимізація для Mac M1 Max

- Використання нативних ARM64 бінарних файлів
- Оптимізовані запити до системних API
- Ефективне кешування даних пристроїв

### Налаштування інтервалів

```python
# Інтервал моніторингу (секунди)
self.refresh_interval = 2

# Інтервал аналізу LLM (секунди)
self.llm_analysis_interval = 30
```

## 🔐 Безпека

### Рекомендації

1. **Регулярні оновлення** - оновлюйте моделі Ollama
2. **Моніторинг логів** - перевіряйте події безпеки
3. **Налаштування сповіщень** - налаштуйте критичні сповіщення
4. **Резервне копіювання** - зберігайте базу даних подій

### Логування

```bash
# Перегляд логів
tail -f security_monitor.log
tail -f nimda.log

# Аналіз подій
sqlite3 security_events.db "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10;"
```

## 📞 Підтримка

### Корисні команди

```bash
2. **Monitoring Logs** - check security events
3. **Setting Notifications** - configure critical notifications
4. **Backup** - store event database

### Logging

```bash
# View logs
tail -f security_monitor.log
tail -f nimda.log

# Analyze events
sqlite3 security_events.db "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10;"
```

## 📞 Support

### Useful Commands

```bash
# System status
python3 -c "from security_monitor import SecurityMonitor; print(SecurityMonitor().get_status_summary())"

# Check devices
system_profiler SPUSBDataType -json | jq '.'

# Network test
networksetup -listallhardwareports
```

### Logs and Diagnosis

- `security_events.db` - event database
- `security_monitor.log` - monitor logs
- `nimda.log` - main system logs

---

**NIMDA Security System** - smart security for Mac M1 Max with Ollama integration 🤖🔒 