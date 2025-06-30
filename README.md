# 🛡️ NIMDA Security System

Комплексна система безпеки з AI-підтримкою для моніторингу та захисту macOS систем.

## 🚀 Швидкий старт

```bash
# 1. Встановлення залежностей
pip3 install -r requirements.txt

# 2. Запуск головного інтерфейсу
python3 nimda_tkinter.py

# або через скрипт
./scripts/start_nimda_tkinter.sh
```

## 📁 Структура проекту

```
NIMDA/
├── 📄 Головні модулі (корінь)
│   ├── nimda_integrated.py      # Основний модуль
│   ├── nimda_tkinter.py         # GUI інтерфейс
│   ├── security_monitor.py      # Моніторинг
│   ├── malware_detection.py     # Виявлення малваре
│   └── ...
├── 📁 scripts/                  # Скрипти запуску
├── 📁 docs/                     # Документація
├── 📁 tests/                    # Тести
├── 📁 demos/                    # Демонстрації
├── 📁 configs/                  # Конфігурації
└── 📁 data/                     # Бази даних
```

## 🔧 Основні можливості

- 🔍 **Реальний моніторинг** мережі та процесів
- 🛡️ **Виявлення малваре** та підозрілої активності
- 🤖 **AI-аналіз загроз** (Ollama + Gemini)
- 🔊 **Звукові сповіщення** для різних рівнів загроз
- 🌙 **Темна тема** інтерфейсу
- 📊 **5-рівнева система загроз**

## 📖 Документація

- [Безпека](docs/README_SECURITY.md)
- [Виявлення малваре](docs/README_MALWARE_DETECTION.md)
- [Рівні загроз](docs/README_THREAT_LEVELS.md)
- [Пристрої та процеси](docs/README_DEVICES_PROCESSES.md)

## 🧪 Тестування

```bash
# Запуск всіх тестів
python3 -m pytest tests/

# Демонстрація системи
python3 demos/nimda_complete_demo.py
```

## ⚙️ Конфігурація

Основні конфігураційні файли:
- `ai_providers_config.json` - AI провайдери
- `security_policy.json` - Політики безпеки

## 🤝 Підтримка

Для питань та підтримки дивіться документацію в папці `docs/`.
