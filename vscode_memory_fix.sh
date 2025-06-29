#!/bin/bash

# Script to launch VS Code with increased memory limits
echo "🚀 Launching VS Code with increased memory limits..."

# Increase memory limit for VS Code
CODE_ARGS="--js-flags='--max-old-space-size=8192'"

# For VS Code
if command -v code &> /dev/null; then
    echo "Starting VS Code with increased memory..."
    code ${CODE_ARGS} "$@"
else
    echo "❌ VS Code command line tool not found."
    echo "Please make sure VS Code is installed and the 'code' command is in your PATH."
    echo "Or run VS Code manually with increased memory settings."
fi

echo "✅ Done!"
