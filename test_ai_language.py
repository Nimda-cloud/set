#!/usr/bin/env python3
"""
Test script for AI language functionality
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nimda_tkinter import TranslationManager

def test_ai_language_functionality():
    """Test AI language switching functionality"""
    print("=== Testing AI Language Functionality ===")
    
    translator = TranslationManager()
    
    # Test initial language
    print(f"\n1. Initial language: {translator.get_current_language()}")
    
    # Test language switching
    print("\n2. Testing language switching:")
    for i in range(3):
        current_lang = translator.get_current_language()
        print(f"   Current: {current_lang}")
        
        # Simulate AI query with language instruction
        if current_lang == 'uk':
            query = f"Відповідай українською мовою. Тестовий запит #{i+1}"
            expected_response = "AI відповідатиме українською"
        else:
            query = f"Answer in English. Test query #{i+1}"
            expected_response = "AI will respond in English"
        
        print(f"   Query: {query}")
        print(f"   Expected: {expected_response}")
        
        # Switch language
        new_lang = translator.switch_language()
        print(f"   Switched to: {new_lang}")
        print()
    
    # Test specific AI queries
    print("3. Testing specific AI queries:")
    test_queries = [
        "Analyze network security",
        "Check for vulnerabilities", 
        "Generate security report",
        "Provide recommendations"
    ]
    
    for query in test_queries:
        current_lang = translator.get_current_language()
        if current_lang == 'uk':
            ai_query = f"Відповідай українською мовою. {query}"
            print(f"   Ukrainian: {ai_query}")
        else:
            ai_query = f"Answer in English. {query}"
            print(f"   English: {ai_query}")
    
    print("\n=== AI Language Tests Completed ===")

if __name__ == "__main__":
    test_ai_language_functionality() 