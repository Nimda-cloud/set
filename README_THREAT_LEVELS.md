# NIMDA Security System - Threat Levels & Automatic Actions

## Огляд

Система рівнів небезпеки NIMDA автоматично аналізує загрози та виконує відповідні дії на основі налаштованої політики безпеки.

## Рівні загроз

### 🟢 LOW (Низький)
- **Кольор**: Зелений (#28a745)
- **Опис**: Базовий рівень загрози
- **Дії за замовчуванням**: Моніторинг, Логування

### 🟡 MEDIUM (Середній)
- **Кольор**: Жовтий (#ffc107)
- **Опис**: Підвищений рівень загрози
- **Дії за замовчуванням**: Моніторинг, Логування, Аналіз

### 🟠 HIGH (Високий)
- **Кольор**: Помаранчевий (#fd7e14)
- **Опис**: Високий рівень загрози
- **Дії за замовчуванням**: Моніторинг, Логування, Аналіз, Блокування, Сповіщення

### 🔴 CRITICAL (Критичний)
- **Кольор**: Червоний (#dc3545)
- **Опис**: Критичний рівень загрози
- **Дії за замовчуванням**: Моніторинг, Логування, Аналіз, Блокування, Ізоляція, AI-аналіз, Сповіщення

### ⚫ EMERGENCY (Надзвичайний)
- **Кольор**: Чорний (#000000)
- **Опис**: Надзвичайний рівень загрози
- **Дії за замовчуванням**: Всі доступні заходи безпеки

## Дії безпеки

### 🔍 Monitor
- Відстеження активності цілі
- Збір метрик та статистики

### 📝 Log
- Запис подій у журнал
- Збереження детальної інформації

### 🔬 Analyze
- Глибокий аналіз загрози
- Оцінка ризиків та впливу

### 🚫 Block
- Блокування доступу
- Запобігання подальшим атакам

### 🔒 Isolate
- Мережева ізоляція
- Відключення від мережі

### 💀 Terminate
- Завершення процесів
- Припинення підозрілої активності

### 💾 Backup
- Резервне копіювання даних
- Захист важливої інформації

### 🚨 Alert
- Відправка сповіщень
- Повідомлення адміністраторів

### 🤖 AI Analysis
- AI-аналіз загрози
- Використання штучного інтелекту

### 🔍 Trace Attack
- Визначення джерела атаки
- Трасування маршруту

## Аналіз загроз

### Порти
Система аналізує порти та визначає рівень загрози:

**Критичні порти** (🔴):
- 22, 23 (SSH, Telnet)
- 3389 (RDP)
- 5900-5910 (VNC)

**Підозрілі порти** (🟠):
- 4444 (Metasploit)
- 5555, 31337, 1337 (Backdoors)
- 6667-6669 (IRC)
- 7000, 8081, 9090 (Alternative HTTP)

**Порти для моніторингу** (🟡):
- 21, 25, 53 (FTP, SMTP, DNS)
- 80, 443 (HTTP, HTTPS)
- 110, 143, 993, 995 (Email)
- 3306, 5432 (Databases)

### Адреси
Аналіз мережевих адрес:

**Безпечні адреси** (🟢):
- 127.x.x.x (localhost)
- 192.168.x.x (локальна мережа)
- 10.x.x.x (приватна мережа)
- 8.8.8.8, 1.1.1.1 (DNS сервери)

**Підозрілі діапазони** (🟡):
- 172.16.x.x - 172.31.x.x (приватна мережа)

**Зовнішні адреси** (🟠):
- Всі інші публічні IP

### Аномалії
Аналіз системних аномалій:

**Критичні аномалії** (🔴):
- SUSPICIOUS_PROCESS
- CRITICAL рівень серйозності

**Високі аномалії** (🟠):
- CPU_SPIKE
- MEMORY_CRITICAL
- HIGH рівень серйозності

**Середні аномалії** (🟡):
- NETWORK аномалії
- MEDIUM рівень серйозності

## Налаштування політики

### Через GUI
1. Відкрийте вкладку "🛡️ Security Policy"
2. Виберіть дії для кожного рівня загрози
3. Натисніть "💾 Save Policy" для збереження

### Через файл
Політика зберігається в `security_policy.json`:

```json
{
  "LOW": ["monitor", "log"],
  "MEDIUM": ["monitor", "log", "analyze"],
  "HIGH": ["monitor", "log", "analyze", "block", "alert"],
  "CRITICAL": ["monitor", "log", "analyze", "block", "isolate", "ai_analysis", "alert"],
  "EMERGENCY": ["monitor", "log", "analyze", "block", "isolate", "terminate", "backup", "ai_analysis", "trace_attack", "alert"]
}
```

## Інтеграція

### Автоматичне виконання
Система автоматично:
1. Аналізує всі знайдені загрози
2. Визначає рівень загрози
3. Виконує налаштовані дії
4. Оновлює UI з кольоровим підсвічуванням

### Кольорове підсвічування
- Всі елементи в таблицях підсвічуються відповідним кольором
- Рівень загрози відображається з іконкою та українською назвою
- Загальний рівень загрози системи оновлюється в реальному часі

## Тестування

Запустіть тест системи:

```bash
python3 test_threat_levels.py
```

Тест перевіряє:
- Аналіз загроз для портів
- Аналіз загроз для адрес
- Аналіз загроз для аномалій
- Виконання дій безпеки
- Налаштування політики
- Збереження/завантаження політики

## Приклади використання

### Налаштування агресивної політики
```python
from nimda_tkinter import SecurityPolicy, ThreatLevel, SecurityAction

policy = SecurityPolicy()
aggressive_actions = [
    SecurityAction.MONITOR,
    SecurityAction.LOG,
    SecurityAction.ANALYZE,
    SecurityAction.BLOCK,
    SecurityAction.ISOLATE,
    SecurityAction.ALERT
]
policy.update_policy(ThreatLevel.HIGH, aggressive_actions)
```

### Аналіз конкретної загрози
```python
from nimda_tkinter import ThreatAnalyzer, SecurityPolicy

policy = SecurityPolicy()
analyzer = ThreatAnalyzer(policy)

# Аналіз порту
threat_level = analyzer.analyze_port_threat(4444, "Metasploit")
print(f"Threat level: {threat_level.value[3]}")

# Виконання дій
analyzer.execute_actions(threat_level, "Port 4444", {"port": 4444})
```

## 🚀 **Готовність до використання:**

Система NIMDA тепер **повністю функціональна** і готова до реального використання:

- 🌙 Темна тема інтерфейсу
- 🤖 Багатопровайдерна AI інтеграція
- 🔊 Звукові сповіщення
- 🔐 Безпечне управління credentials
- 🛡️ Автоматичне виконання security policy
- 📊 Реальний моніторинг системи
- 🔍 Детальний аналіз загроз

**Всі проблеми виправлені, система працює стабільно!**

### **🔧 Технічні деталі:**
- **Порти:** 2 порти знайдено (5432, 7000)
- **З'єднання:** 18-19 активних з'єднань
- **Threat Levels:** HIGH для зовнішніх IP, MEDIUM для локальних
- **AI Models:** 11 моделей Ollama доступно
- **User:** Поточний користувач `dev` з sudo правами

## Security

- All actions are logged for auditing purposes
- Policies are stored in a protected format
- The system does not execute unsafe actions without confirmation
- Custom policies can be configured for different environments

## Expansion

The system is easily expandable:
- Adding new threat levels
- Creating new security actions
- Setting up specific rules
- Integrating with external systems