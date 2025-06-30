#!/bin/bash

# NIMDA Modern Security System Launcher Script
# Запуск повноцінного інтерфейсу з усіма функціями

echo "🛡️  NIMDA Enhanced Security System"
echo "=================================="
echo "Choose launch mode:"
echo "1. Full Launch (recommended)"
echo "2. Quick Launch (faster startup)"
echo ""

# Перехід до директорії NIMDA
cd "$(dirname "$0")"

# Перевірка наявності Python та необхідних бібліотек
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not installed."
    exit 1
fi

# Перевірка наявності ttkbootstrap
if ! python3 -c "import ttkbootstrap" &> /dev/null; then
    echo "⚠️  Warning: ttkbootstrap not found. Installing..."
    pip3 install ttkbootstrap
fi

# Запуск NIMDA з вибором режиму
if [ "$1" = "quick" ] || [ "$1" = "q" ]; then
    echo "🚀 Quick launching NIMDA..."
    python3 quick_launch.py
elif [ "$1" = "full" ] || [ "$1" = "f" ] || [ -z "$1" ]; then
    echo "🚀 Full launching NIMDA..."
    python3 start_nimda_modern.py
else
    echo "Usage: $0 [quick|q|full|f]"
    echo "  quick/q: Fast startup with minimal initialization"
    echo "  full/f:  Complete startup with all features (default)"
    exit 1
fi

echo "👋 NIMDA has been closed."
