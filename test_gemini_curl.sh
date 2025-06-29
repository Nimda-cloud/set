#!/bin/bash
#
# Gemini API cURL Test Script
# Тестування Gemini API через cURL
#

# Перевірити, чи встановлений API ключ
if [ -z "$GEMINI_API_KEY" ]; then
    echo "❌ GEMINI_API_KEY not found in environment variables"
    echo ""
    echo "🔧 To fix this, run:"
    echo "   export GEMINI_API_KEY='your_api_key_here'"
    echo ""
    echo "📝 Or add to ~/.zshrc:"
    echo "   echo 'export GEMINI_API_KEY=\"your_key_here\"' >> ~/.zshrc"
    echo "   source ~/.zshrc"
    exit 1
fi

echo "✅ Found API key: ${GEMINI_API_KEY:0:10}...${GEMINI_API_KEY: -4}"
echo "🚀 Testing Gemini API with cURL..."
echo ""

# Запит до Gemini API
curl "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=$GEMINI_API_KEY" \
  -H 'Content-Type: application/json' \
  -X POST \
  -d '{
    "contents": [
      {
        "parts": [
          {
            "text": "Explain how AI works in a few words"
          }
        ]
      }
    ]
  }' \
  --max-time 30 \
  --show-error \
  --fail

echo ""
echo "✅ cURL test completed"
