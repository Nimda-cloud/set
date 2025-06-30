#!/bin/bash
#
# Setup Gemini API Key
# Додавання API ключа для Gemini
#

echo "🔧 Gemini API Key Setup"
echo "========================"
echo ""

if [ -z "$1" ]; then
    echo "❌ Please provide your Gemini API key"
    echo ""
    echo "Usage: $0 'your_api_key_here'"
    echo ""
    echo "📝 To get your API key:"
    echo "   1. Go to https://makersuite.google.com/app/apikey"
    echo "   2. Create new API key"
    echo "   3. Copy the key"
    echo ""
    echo "🔒 The key will be added to your ~/.zshrc file"
    exit 1
fi

API_KEY="$1"

# Перевірити, чи ключ вже існує в .zshrc
if grep -q "GEMINI_API_KEY" ~/.zshrc; then
    echo "⚠️  GEMINI_API_KEY already exists in ~/.zshrc"
    echo "   Would you like to update it? (y/n)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "❌ Setup cancelled"
        exit 1
    fi
    
    # Видалити старий ключ
    sed -i '' '/export GEMINI_API_KEY/d' ~/.zshrc
fi

# Додати новий ключ
echo "" >> ~/.zshrc
echo "# Gemini API Configuration" >> ~/.zshrc
echo "export GEMINI_API_KEY=\"$API_KEY\"" >> ~/.zshrc

echo "✅ API key added to ~/.zshrc"
echo ""
echo "🔄 To activate the key, run:"
echo "   source ~/.zshrc"
echo ""
echo "🧪 To test the API, run:"
echo "   test-gemini"
echo ""

# Автоматично перезавантажити конфігурацію
source ~/.zshrc

echo "✅ Configuration reloaded!"
echo "🚀 Ready to test Gemini API!"
