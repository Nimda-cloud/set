# NIMDA-Mac Security Rules Configuration

## Overview
Цей файл пояснює, як система NIMDA-Mac завантажує та використовує правила безпеки.

## Автоматичне завантаження правил

Система автоматично завантажує правила безпеки з відкритих джерел:

### Emerging Threats Rules
- **Джерело**: https://rules.emergingthreats.net/open/suricata-6.0/emerging-all.rules
- **Призначення**: Виявлення відомих загроз та атак
- **Формат**: Suricata/Snort правила
- **Частота оновлення**: Рекомендується щоденно

## Структура папки rules/

Після першого запуску система створить:
```
rules/
├── emerging-all.rules          # Правила Emerging Threats
└── custom-rules.rules          # Користувацькі правила (опціонально)
```

## Використання

### Автоматичне завантаження
```python
from core.rule_manager import RuleManager

manager = RuleManager()
manager.update_all_rules()  # Завантажує всі налаштовані правила
rules = manager.get_parsed_rules()  # Парсить для використання
```

### Ручне оновлення через GUI
1. Запустіть GUI: `python gui/nimda_gui.py`
2. Меню Security → Update Rules
3. Система автоматично завантажить останні правила

### Ручне оновлення через CLI
```bash
python core/rule_manager.py
```

## Налаштування користувацьких правил

Створіть файл `rules/custom-rules.rules` для власних правил:

```
# Приклад користувацького правила
alert tcp any any -> any 22 (msg:"SSH брут-форс спроба"; content:"Failed password"; threshold: type both, track by_src, count 5, seconds 60; sid:1000001;)

# Правило для виявлення підозрілих завантажень
alert http any any -> any any (msg:"Підозріле завантаження script"; content:"GET"; content:".sh"; content:".py"; sid:1000002;)
```

## Підтримувані джерела правил

1. **Emerging Threats** (за замовчуванням)
   - Безкоштовні правила
   - Регулярні оновлення
   - Широке покриття загроз

2. **Користувацькі правила**
   - Правила специфічні для вашого середовища
   - Локальні загрози
   - Корпоративні політики

## Примітки з безпеки

⚠️ **Важливо**: Файли правил можуть містити рядки, які GitHub може інтерпретувати як секрети (OAuth токени, API ключі тощо). Це нормально для правил безпеки, оскільки вони містять приклади атак.

📁 **Рекомендація**: Папка `rules/` додана до `.gitignore` для уникнення false positive спрацьовувань GitHub Secret Scanning.

## Моніторинг ефективності правил

Система надає статистику по спрацьовуванню правил:
- Кількість спрацьовувань по SID
- Типи виявлених загроз
- Ефективність правил

## Troubleshooting

### Проблема: Правила не завантажуються
**Рішення**: Перевірте інтернет-з'єднання та доступність джерел

### Проблема: Багато false positive
**Рішення**: Налаштуйте білі списки у `configs/security_policy.json`

### Проблема: Низька продуктивність
**Рішення**: Оптимізуйте правила, видаліть неактуальні
