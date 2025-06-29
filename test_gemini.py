#!/usr/bin/env python3
"""
Gemini API Test Script
Тестування роботи Gemini API
"""

import os
import requests
import json
import sys

def test_gemini_api():
    """Тестувати Gemini API"""
    
    # Спробуємо отримати ключ з різних джерел
    api_key = None
    
    # 1. З змінної середовища
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key:
        print("❌ GEMINI_API_KEY not found in environment variables")
        print("\n🔧 To fix this, add your API key:")
        print("   export GEMINI_API_KEY='your_api_key_here'")
        print("   Or add it to your ~/.zshrc file")
        return False
    
    print(f"✅ Found API key: {api_key[:10]}...{api_key[-4:]}")
    
    # Тестовий запит
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    data = {
        "contents": [
            {
                "parts": [
                    {
                        "text": "Explain how AI works in a few words"
                    }
                ]
            }
        ]
    }
    
    print("🚀 Testing Gemini API...")
    print(f"📡 URL: {url.replace(api_key, 'API_KEY')}")
    
    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        
        print(f"📊 Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Gemini API working successfully!")
            
            if 'candidates' in result:
                text = result['candidates'][0]['content']['parts'][0]['text']
                print(f"🤖 Response: {text}")
            else:
                print(f"📄 Full response: {json.dumps(result, indent=2)}")
                
        else:
            print(f"❌ API Error: {response.status_code}")
            print(f"📄 Response: {response.text}")
            
            if response.status_code == 400:
                print("💡 This might be an invalid API key or request format")
            elif response.status_code == 403:
                print("💡 This might be an API key permissions issue")
            elif response.status_code == 404:
                print("💡 Check if the model name is correct")
                
    except requests.exceptions.Timeout:
        print("❌ Request timeout - API might be slow")
    except requests.exceptions.ConnectionError:
        print("❌ Connection error - check your internet connection")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def check_available_models(api_key):
    """Перевірити доступні моделі"""
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            models = response.json()
            print("📋 Available models:")
            for model in models.get('models', []):
                print(f"  - {model.get('name', 'Unknown')}")
        else:
            print(f"❌ Cannot fetch models: {response.status_code}")
    except Exception as e:
        print(f"❌ Error fetching models: {e}")

if __name__ == "__main__":
    print("🔍 Gemini API Test")
    print("=" * 40)
    
    if len(sys.argv) > 1 and sys.argv[1] == "models":
        api_key = os.getenv("GEMINI_API_KEY")
        if api_key:
            check_available_models(api_key)
        else:
            print("❌ GEMINI_API_KEY not found")
    else:
        test_gemini_api()
    
    print("\n💡 Usage:")
    print("  python3 test_gemini.py        - Test API")
    print("  python3 test_gemini.py models - List available models")
