#!/bin/bash

# NIMDA Integrated Security System Launcher
# Запуск інтегрованої системи безпеки з підтримкою звуків

echo "🚀 Starting NIMDA Integrated Security System..."

# Перевірити наявність Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3."
    exit 1
fi

# Перевірити наявність tmux
if ! command -v tmux &> /dev/null; then
    echo "❌ tmux not found. Installing..."
    if command -v brew &> /dev/null; then
        brew install tmux
    else
        echo "Please install tmux manually"
        exit 1
    fi
fi

# Встановити залежності
echo "📦 Installing Python dependencies..."
python3 -m pip install -r requirements.txt

# Перевірити підтримку звуку
echo "� Checking sound support..."
if ! command -v say &> /dev/null; then
    echo "⚠️ 'say' command not found. Voice alerts may not work."
fi

if ! command -v afplay &> /dev/null; then
    echo "⚠️ 'afplay' command not found. System sounds may not work."
fi

# Надати права на виконання
chmod +x nimda_integrated.py
chmod +x sound_alerts.py

# Очистити попередні сесії tmux
tmux kill-session -t nimda_integrated 2>/dev/null || true

echo "✅ Setup complete. Launching NIMDA with sound support..."
echo ""
echo "🎮 Controls:"
echo "  • L - Enable Lockdown"
echo "  • U - Disable Lockdown" 
echo "  • 1-6 - Focus on different monitors"
echo "  • T - Test sound alerts"
echo "  • M - Mute/Unmute sounds"
echo "  • E - Emergency siren test"
echo "  • A - Alert demo"
echo "  • Ctrl+L - Emergency lockdown disable"
echo "  • Q - Quit"
echo ""
echo "🔊 Sound Features:"
echo "  • Low/Medium threats: System beeps"
echo "  • High threats: Voice alerts + beeps"
echo "  • Critical threats: Urgent voice alerts"
echo "  • Emergency: Continuous siren + voice"
echo ""

# Запустити NIMDA
python3 nimda_integrated.py
