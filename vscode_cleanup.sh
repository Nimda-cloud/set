#!/bin/bash

# VS Code cache cleanup script for NIMDA project
echo "🧹 Cleaning VS Code cache and temporary files..."

# Define the VS Code cache directories based on OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    VSCODE_CACHE_DIR="$HOME/Library/Application Support/Code/Cache"
    VSCODE_STORAGE_DIR="$HOME/Library/Application Support/Code/User/globalStorage"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    VSCODE_CACHE_DIR="$HOME/.config/Code/Cache"
    VSCODE_STORAGE_DIR="$HOME/.config/Code/User/globalStorage"
elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* ]]; then
    # Windows with Git Bash or Cygwin
    VSCODE_CACHE_DIR="$APPDATA/Code/Cache"
    VSCODE_STORAGE_DIR="$APPDATA/Code/User/globalStorage"
else
    echo "❌ Unsupported operating system."
    exit 1
fi

# Check if VS Code is running
if pgrep -x "Code" > /dev/null || pgrep -x "code" > /dev/null; then
    echo "⚠️ VS Code is currently running. Please close it before proceeding."
    read -p "Do you want to force close VS Code? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "📌 Closing VS Code..."
        killall Code 2>/dev/null
        killall code 2>/dev/null
        sleep 2
    else
        echo "❌ Cleanup aborted. Please close VS Code manually and run this script again."
        exit 1
    fi
fi

# Clean the NIMDA project's __pycache__ directories
echo "🧹 Cleaning Python cache files..."
find /Users/dev/Documents/NIMDA/set -name "__pycache__" -type d -exec rm -rf {} +

# Create backup directories
BACKUP_ROOT="/tmp/vscode_backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "${BACKUP_ROOT}/Cache"
mkdir -p "${BACKUP_ROOT}/Storage"

# Backup and clean VS Code cache
if [ -d "$VSCODE_CACHE_DIR" ]; then
    echo "📋 Backing up VS Code cache..."
    cp -R "$VSCODE_CACHE_DIR" "${BACKUP_ROOT}/Cache"
    
    echo "🧹 Cleaning VS Code cache..."
    rm -rf "${VSCODE_CACHE_DIR:?}"/*
fi

# Clean global storage (extensions data)
if [ -d "$VSCODE_STORAGE_DIR" ]; then
    echo "📋 Backing up VS Code global storage..."
    cp -R "$VSCODE_STORAGE_DIR" "${BACKUP_ROOT}/Storage"
    
    echo "🧹 Cleaning VS Code global storage..."
    # Be more selective with storage cleaning - only remove cache-like directories
    find "$VSCODE_STORAGE_DIR" -name "cache" -type d -exec rm -rf {} \; 2>/dev/null
    find "$VSCODE_STORAGE_DIR" -name "*.db" -type f -exec rm -f {} \; 2>/dev/null
    find "$VSCODE_STORAGE_DIR" -name "*.log" -type f -exec rm -f {} \; 2>/dev/null
fi

echo "✅ VS Code cache cleanup completed."
echo "📝 Backups saved to ${BACKUP_ROOT}"
echo "⚠️ Please restart your computer before launching VS Code again for best results."
