# NIMDA Security System Docker Image
FROM python:3.11-slim

LABEL maintainer="NIMDA Team"
LABEL description="NIMDA Security System - AI-powered security monitoring"

# Встановити системні залежності
RUN apt-get update && apt-get install -y \
    curl \
    git \
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
