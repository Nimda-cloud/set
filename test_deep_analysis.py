#!/usr/bin/env python3
"""
Test script for deep analysis functionality
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from nimda_tkinter import DeepAnalyzer

def test_deep_analyzer():
    """Test the deep analyzer functionality"""
    print("=== Testing Deep Analyzer ===")
    
    analyzer = DeepAnalyzer()
    
    # Test port analysis
    print("\n1. Testing Port Analysis:")
    test_ports = [22, 80, 443, 4444, 31337, 8080]
    for port in test_ports:
        print(f"\nAnalyzing port {port}:")
        analysis = analyzer.analyze_port(port)
        for key, value in analysis.items():
            if key != 'timestamp':
                print(f"  {key}: {value}")
    
    # Test address analysis
    print("\n2. Testing Address Analysis:")
    test_addresses = ['127.0.0.1:8080', '192.168.1.100:54321', '8.8.8.8:443']
    for addr in test_addresses:
        print(f"\nAnalyzing address {addr}:")
        analysis = analyzer.analyze_address(addr)
        for key, value in analysis.items():
            if key != 'timestamp':
                print(f"  {key}: {value}")
    
    # Test bulk analysis
    print("\n3. Testing Bulk Port Analysis:")
    bulk_port_analysis = analyzer.analyze_all_ports(test_ports)
    for key, value in bulk_port_analysis.items():
        if key != 'timestamp':
            print(f"  {key}: {value}")
    
    print("\n4. Testing Bulk Address Analysis:")
    bulk_addr_analysis = analyzer.analyze_all_addresses(test_addresses)
    for key, value in bulk_addr_analysis.items():
        if key != 'timestamp':
            print(f"  {key}: {value}")
    
    print("\n=== Deep Analyzer Tests Completed ===")

if __name__ == "__main__":
    test_deep_analyzer() 