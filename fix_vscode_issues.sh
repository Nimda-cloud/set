#!/bin/bash

# NIMDA VS Code Fix Master Script
# Addresses memory issues, file path resolution problems, and cache issues

echo "🚀 Starting NIMDA VS Code Fix Script..."
echo "This script will help resolve VS Code issues in your NIMDA Security System project."

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Step 1: Checking if VS Code is running...${NC}"
if pgrep -x "Code" > /dev/null || pgrep -x "code" > /dev/null; then
    echo -e "${YELLOW}⚠️  VS Code is currently running. Please save your work and close it before proceeding.${NC}"
    read -p "Do you want to force close VS Code? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}📌 Closing VS Code...${NC}"
        killall Code 2>/dev/null
        killall code 2>/dev/null
        sleep 2
    else
        echo -e "${RED}❌ Fix aborted. Please close VS Code manually and run this script again.${NC}"
        exit 1
    fi
fi

echo -e "${BLUE}Step 2: Running VS Code cleanup script...${NC}"
if [ -f "/Users/dev/Documents/NIMDA/set/vscode_cleanup.sh" ]; then
    bash /Users/dev/Documents/NIMDA/set/vscode_cleanup.sh
else
    echo -e "${RED}❌ Cleanup script not found.${NC}"
    exit 1
fi

echo -e "${BLUE}Step 3: Optimizing VS Code settings...${NC}"
if [ -f "/Users/dev/Documents/NIMDA/set/optimize_vscode.sh" ]; then
    bash /Users/dev/Documents/NIMDA/set/optimize_vscode.sh
else
    echo -e "${RED}❌ Optimization script not found.${NC}"
    exit 1
fi

echo -e "${BLUE}Step 4: Fixing Python cache issues...${NC}"
echo -e "${YELLOW}Removing __pycache__ directories...${NC}"
find /Users/dev/Documents/NIMDA/set -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null

echo -e "${BLUE}Step 5: Checking your requirements.txt file...${NC}"
REQ_FILE="/Users/dev/Documents/NIMDA/set/requirements.txt"

if [ -f "$REQ_FILE" ]; then
    # Fix the requirements.txt file by removing built-in modules
    echo -e "${YELLOW}Fixing requirements.txt file...${NC}"
    
    # Create a temporary file
    TMP_FILE=$(mktemp)
    
    # Filter out built-in modules
    cat "$REQ_FILE" | grep -v -e "^threading$" -e "^sqlite3$" -e "^datetime$" -e "^enum$" -e "^typing$" -e "^collections$" -e "^re$" > "$TMP_FILE"
    
    # Replace tkinter with python-tk if present
    sed -i.bak 's/^tkinter$/python-tk>=8.6.0/' "$TMP_FILE"
    
    # Move the temporary file to replace the original
    mv "$TMP_FILE" "$REQ_FILE"
    
    echo -e "${GREEN}✅ requirements.txt file has been updated.${NC}"
else
    echo -e "${RED}❌ requirements.txt file not found.${NC}"
fi

echo -e "${GREEN}✅ All fixes have been applied.${NC}"
echo -e "${YELLOW}⚠️  Please restart your computer before launching VS Code again.${NC}"
echo -e "${BLUE}After restart, use the vscode_memory_fix.sh script to launch VS Code with increased memory.${NC}"
echo -e "${GREEN}Command: bash /Users/dev/Documents/NIMDA/set/vscode_memory_fix.sh${NC}"
