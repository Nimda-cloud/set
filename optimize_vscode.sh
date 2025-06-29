#!/bin/bash

# Script to reset and optimize VS Code settings for NIMDA project
echo "🔧 Optimizing VS Code settings for NIMDA project..."

# Define the VS Code settings directory based on OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    VSCODE_SETTINGS_DIR="$HOME/Library/Application Support/Code/User"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    VSCODE_SETTINGS_DIR="$HOME/.config/Code/User"
elif [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* ]]; then
    # Windows with Git Bash or Cygwin
    VSCODE_SETTINGS_DIR="$APPDATA/Code/User"
else
    echo "❌ Unsupported operating system."
    exit 1
fi

# Create backup directory if it doesn't exist
BACKUP_DIR="${VSCODE_SETTINGS_DIR}/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup current settings
if [ -f "${VSCODE_SETTINGS_DIR}/settings.json" ]; then
    echo "📋 Creating backup of current settings..."
    cp "${VSCODE_SETTINGS_DIR}/settings.json" "${BACKUP_DIR}/settings.json.bak"
fi

# Generate optimized settings
echo "⚙️ Creating optimized VS Code settings for NIMDA project..."

cat > /tmp/optimized_vscode_settings.json << EOL
{
    "files.watcherExclude": {
        "**/.git/objects/**": true,
        "**/.git/subtree-cache/**": true,
        "**/node_modules/**": true,
        "**/__pycache__/**": true,
        "**/venv/**": true,
        "**/env/**": true
    },
    "search.exclude": {
        "**/node_modules": true,
        "**/bower_components": true,
        "**/env": true,
        "**/venv": true,
        "**/__pycache__": true
    },
    "files.exclude": {
        "**/.git": true,
        "**/.svn": true,
        "**/.hg": true,
        "**/CVS": true,
        "**/.DS_Store": true,
        "**/*.pyc": true,
        "**/__pycache__": true
    },
    "editor.formatOnSave": false,
    "files.autoSave": "afterDelay",
    "files.autoSaveDelay": 1000,
    "python.linting.enabled": false,
    "editor.renderWhitespace": "selection",
    "telemetry.telemetryLevel": "off",
    "extensions.autoUpdate": false,
    "window.restoreWindows": "none",
    "window.newWindowDimensions": "inherit",
    "workbench.editor.limit.enabled": true,
    "workbench.editor.limit.value": 6,
    "editor.minimap.enabled": false,
    "editor.largeFileOptimizations": true,
    "files.associations": {
        "*.py": "python"
    }
}
EOL

# Apply the optimized settings
if cp /tmp/optimized_vscode_settings.json "${VSCODE_SETTINGS_DIR}/settings.json"; then
    echo "✅ VS Code settings successfully optimized."
else
    echo "❌ Failed to update VS Code settings."
    exit 1
fi

echo "⚠️ Please restart VS Code for these changes to take effect."
echo "📝 Note: A backup of your original settings has been saved to ${BACKUP_DIR}"
