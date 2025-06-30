#!/bin/bash

# NIMDA Security System Startup Script
# Comprehensive security monitoring with Ollama integration

echo "🚀 Starting NIMDA Security System..."

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ This system is designed for macOS only"
    exit 1
fi

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.8+ required, found: $python_version"
    exit 1
fi

echo "✅ Python version: $python_version"

# Check dependencies
echo "📦 Checking dependencies..."

# Check if tmux is installed
if ! command -v tmux &> /dev/null; then
    echo "❌ tmux not found. Installing..."
    if command -v brew &> /dev/null; then
        brew install tmux
    else
        echo "❌ Homebrew not found. Please install tmux manually"
        exit 1
    fi
fi

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo "⚠️ Ollama not found. Installing..."
    if command -v brew &> /dev/null; then
        brew install ollama
    else
        echo "⚠️ Homebrew not found. Please install Ollama manually:"
        echo "   curl -fsSL https://ollama.ai/install.sh | sh"
    fi
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Check if Ollama is running
echo "🤖 Checking Ollama status..."
if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "⚠️ Ollama not running. Starting Ollama..."
    ollama serve &
    sleep 3
    
    # Check if we have any models
    if ! curl -s http://localhost:11434/api/tags | grep -q "models"; then
        echo "📥 No models found. Pulling llama3:latest..."
        ollama pull llama3:latest
    fi
else
    echo "✅ Ollama is running"
fi

# Test the security system
echo "🔍 Testing security system..."
python3 test_security_system.py

# Check if tmux session already exists
if tmux has-session -t nimda_integrated 2>/dev/null; then
    echo "⚠️ NIMDA session already exists. Killing old session..."
    tmux kill-session -t nimda_integrated
fi

# Start NIMDA
echo "🚀 Starting NIMDA Integrated Security System..."
python3 nimda_integrated.py

echo "👋 NIMDA Security System stopped" 