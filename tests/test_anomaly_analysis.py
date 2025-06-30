#!/usr/bin/env python3
"""
Test script for anomaly analysis functionality
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nimda_tkinter import AnomalyAnalyzer, TranslationManager

def test_anomaly_analyzer():
    """Test the anomaly analyzer functionality"""
    print("=== Testing Anomaly Analyzer ===")
    
    analyzer = AnomalyAnalyzer()
    
    # Test anomaly analysis
    test_anomalies = [
        {
            'type': 'CPU_SPIKE',
            'severity': 'HIGH',
            'description': 'CPU usage spike: 85%',
            'timestamp': '2024-01-01T12:00:00'
        },
        {
            'type': 'NETWORK_SPIKE',
            'severity': 'MEDIUM',
            'description': 'Unusual network activity detected',
            'timestamp': '2024-01-01T12:01:00'
        },
        {
            'type': 'SUSPICIOUS_PROCESS',
            'severity': 'HIGH',
            'description': 'Suspicious process detected: unknown.exe',
            'timestamp': '2024-01-01T12:02:00'
        }
    ]
    
    for i, anomaly in enumerate(test_anomalies, 1):
        print(f"\n{i}. Analyzing anomaly: {anomaly['type']}")
        analysis = analyzer.analyze_anomaly(anomaly)
        
        for key, value in analysis.items():
            if key in ['analysis_timestamp', 'timestamp']:
                continue
            if isinstance(value, list):
                print(f"  {key}:")
                for item in value:
                    print(f"    - {item}")
            else:
                print(f"  {key}: {value}")

def test_translation_manager():
    """Test the translation manager functionality"""
    print("\n=== Testing Translation Manager ===")
    
    translator = TranslationManager()
    
    # Test English translations
    print("\n1. English translations:")
    test_keys = ['dashboard', 'network', 'anomalies', 'analyze', 'error']
    for key in test_keys:
        text = translator.get_text(key)
        print(f"  {key}: {text}")
    
    # Test language switching
    print("\n2. Switching to Ukrainian:")
    translator.switch_language()
    for key in test_keys:
        text = translator.get_text(key)
        print(f"  {key}: {text}")
    
    # Test switching back
    print("\n3. Switching back to English:")
    translator.switch_language()
    for key in test_keys:
        text = translator.get_text(key)
        print(f"  {key}: {text}")

if __name__ == "__main__":
    test_anomaly_analyzer()
    test_translation_manager()
    print("\n=== All Tests Completed ===") 