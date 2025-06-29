#!/bin/bash

# NIMDA Security System - Tkinter GUI Startup Script
# Simple built-in Python GUI for security monitoring

echo "🚀 Starting NIMDA Security System (Tkinter GUI)..."

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

# Install Python dependencies (tkinter is built-in)
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

# Start NIMDA Tkinter GUI
echo "🚀 Starting NIMDA Security System Tkinter GUI..."
python3 nimda_tkinter.py

echo "👋 NIMDA Security System stopped" 