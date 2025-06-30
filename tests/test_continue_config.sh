#!/bin/bash

# Continue Configuration Test Script
echo "🔧 Testing Continue configuration..."

# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Step 1: Checking Ollama server...${NC}"
if curl -s http://localhost:11434/api/tags > /dev/null; then
    echo -e "${GREEN}✅ Ollama server is running${NC}"
else
    echo -e "${RED}❌ Ollama server is not running. Starting...${NC}"
    ollama serve &
    sleep 3
fi

echo -e "${BLUE}Step 2: Checking available models...${NC}"
MODELS=$(curl -s http://localhost:11434/api/tags | jq -r '.models[] | select(.name | contains("qwen2.5-coder")) | .name')
if [[ -n "$MODELS" ]]; then
    echo -e "${GREEN}✅ Available Qwen2.5 Coder models:${NC}"
    echo "$MODELS"
else
    echo -e "${RED}❌ No Qwen2.5 Coder models found${NC}"
    echo -e "${YELLOW}Installing qwen2.5-coder models...${NC}"
    ollama pull qwen2.5-coder:latest
    ollama pull qwen2.5-coder:1.5b
fi

echo -e "${BLUE}Step 3: Testing chat model...${NC}"
CHAT_RESPONSE=$(curl -s -X POST http://localhost:11434/api/generate -d '{"model": "qwen2.5-coder:latest", "prompt": "Test", "stream": false}' | jq -r '.response')
if [[ -n "$CHAT_RESPONSE" && "$CHAT_RESPONSE" != "null" ]]; then
    echo -e "${GREEN}✅ Chat model (latest) is working${NC}"
else
    echo -e "${RED}❌ Chat model (latest) is not responding${NC}"
fi

echo -e "${BLUE}Step 4: Testing edit model...${NC}"
EDIT_RESPONSE=$(curl -s -X POST http://localhost:11434/api/generate -d '{"model": "qwen2.5-coder:1.5b", "prompt": "Test", "stream": false}' | jq -r '.response')
if [[ -n "$EDIT_RESPONSE" && "$EDIT_RESPONSE" != "null" ]]; then
    echo -e "${GREEN}✅ Edit model (1.5b) is working${NC}"
else
    echo -e "${RED}❌ Edit model (1.5b) is not responding${NC}"
fi

echo -e "${BLUE}Step 5: Checking Continue config...${NC}"
CONFIG_FILE="$HOME/.continue/config.json"
if [[ -f "$CONFIG_FILE" ]]; then
    echo -e "${GREEN}✅ Continue config file exists${NC}"
    
    # Check if editModel is configured
    if jq -e '.editModel' "$CONFIG_FILE" > /dev/null; then
        echo -e "${GREEN}✅ editModel is configured${NC}"
    else
        echo -e "${RED}❌ editModel is not configured${NC}"
    fi
    
    # Check if reranker is configured
    if jq -e '.reranker' "$CONFIG_FILE" > /dev/null; then
        echo -e "${GREEN}✅ reranker is configured${NC}"
    else
        echo -e "${YELLOW}⚠️ reranker is not configured${NC}"
    fi
else
    echo -e "${RED}❌ Continue config file not found${NC}"
fi

echo -e "${BLUE}Step 6: Recommendations...${NC}"
echo -e "${YELLOW}💡 For optimal Continue performance:${NC}"
echo "   • Restart VS Code after config changes"
echo "   • Use Ctrl+Shift+P -> 'Continue: Reload' to reload extension"
echo "   • Test with simple edit request like 'Add a comment to this function'"
echo "   • Check VS Code Developer Tools (Help -> Developer Tools) for errors"

echo -e "${GREEN}✅ Configuration test completed!${NC}"
