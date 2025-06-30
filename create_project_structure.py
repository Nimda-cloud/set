#!/usr/bin/env python3
"""
NIMDA Project Structure Creator
Створює правильну структуру проекту NIMDA з правильними імпортами
"""

import os
from pathlib import Path

class ProjectStructureCreator:
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
    
    def create_gitignore(self):
        """Створити .gitignore файл"""
        gitignore_content = """# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.so
.pytest_cache/
.coverage
htmlcov/

# Virtual Environment
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# NIMDA specific
backup_before_reorganize/
*.db
*.log
.env
credentials.json

# Temporary files
*.tmp
*.temp
"""
        gitignore_file = self.base_path / '.gitignore'
        gitignore_file.write_text(gitignore_content)
        print("📄 Створено .gitignore")

    def create_main_readme(self):
        """Оновити головний README.md"""
        readme_content = """# 🛡️ NIMDA Security System

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
"""
        readme_file = self.base_path / 'README.md'
        readme_file.write_text(readme_content)
        print("📄 Оновлено README.md")

    def create_setup_py(self):
        """Створити setup.py для правильної інсталяції"""
        setup_content = """#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="nimda-security",
    version="2.5.0",
    description="NIMDA Security System - AI-powered security monitoring",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="NIMDA Team",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=[
        line.strip()
        for line in open("requirements.txt", encoding="utf-8")
        if line.strip() and not line.startswith("#")
    ],
    entry_points={
        "console_scripts": [
            "nimda=nimda_tkinter:main",
            "nimda-security=nimda_integrated:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
"""
        setup_file = self.base_path / 'setup.py'
        setup_file.write_text(setup_content)
        print("📄 Створено setup.py")

    def create_manifest(self):
        """Створити MANIFEST.in"""
        manifest_content = """include README.md
include requirements.txt
include LICENSE
recursive-include docs *.md
recursive-include scripts *.sh
recursive-include configs *.json
recursive-exclude * __pycache__
recursive-exclude * *.py[co]
"""
        manifest_file = self.base_path / 'MANIFEST.in'
        manifest_file.write_text(manifest_content)
        print("📄 Створено MANIFEST.in")

    def create_makefile(self):
        """Створити Makefile для зручності"""
        makefile_content = """# NIMDA Security System Makefile

.PHONY: help install test clean run demo lint format

help:  ## Показати допомогу
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\\033[36m%-20s\\033[0m %s\\n", $$1, $$2}'

install:  ## Встановити залежності
	pip3 install -r requirements.txt

test:  ## Запустити тести
	python3 -m pytest tests/ -v

clean:  ## Очистити тимчасові файли
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete

run:  ## Запустити головний інтерфейс
	python3 nimda_tkinter.py

demo:  ## Запустити демонстрацію
	python3 demos/nimda_complete_demo.py

lint:  ## Перевірити код
	python3 -m flake8 . --max-line-length=100 --exclude=__pycache__,venv

format:  ## Форматувати код
	python3 -m black . --line-length=100

setup:  ## Встановити пакет для розробки
	pip3 install -e .

dist:  ## Створити дистрибутив
	python3 setup.py sdist bdist_wheel

upload:  ## Завантажити до PyPI (тестовий)
	python3 -m twine upload --repository testpypi dist/*

reorganize:  ## Реорганізувати структуру проекту
	python3 reorganize_project.py
"""
        makefile_file = self.base_path / 'Makefile'
        makefile_file.write_text(makefile_content)
        print("📄 Створено Makefile")

    def create_docker_files(self):
        """Створити Docker конфігурацію"""
        dockerfile_content = """# NIMDA Security System Docker Image
FROM python:3.11-slim

LABEL maintainer="NIMDA Team"
LABEL description="NIMDA Security System - AI-powered security monitoring"

# Встановити системні залежності
RUN apt-get update && apt-get install -y \\
    curl \\
    git \\
    && rm -rf /var/lib/apt/lists/*

# Створити робочу директорію
WORKDIR /app

# Копіювати requirements та встановити Python залежності
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копіювати код додатка
COPY . .

# Створити користувача для безпеки
RUN useradd --create-home --shell /bin/bash nimda
RUN chown -R nimda:nimda /app
USER nimda

# Експорт портів
EXPOSE 8000

# Змінні середовища
ENV PYTHONPATH=/app
ENV NIMDA_ENV=production

# Команда запуску
CMD ["python3", "nimda_integrated.py"]
"""
        
        dockerfile = self.base_path / 'Dockerfile'
        dockerfile.write_text(dockerfile_content)
        
        dockerignore_content = """__pycache__
*.pyc
*.pyo
*.pyd
.Python
.git
.gitignore
README.md
Dockerfile
.dockerignore
backup_before_reorganize/
"""
        dockerignore = self.base_path / '.dockerignore'
        dockerignore.write_text(dockerignore_content)
        
        print("📄 Створено Dockerfile та .dockerignore")

    def create_all_files(self):
        """Створити всі допоміжні файли"""
        print("🛠️ Створення додаткових файлів проекту...")
        
        self.create_gitignore()
        self.create_main_readme()
        self.create_setup_py()
        self.create_manifest()
        self.create_makefile()
        self.create_docker_files()
        
        print("✅ Всі додаткові файли створено!")

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    creator = ProjectStructureCreator(current_dir)
    creator.create_all_files()

if __name__ == "__main__":
    main()
