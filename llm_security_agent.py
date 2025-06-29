#!/usr/bin/env python3
"""
NIMDA LLM Security Agent
Interactive AI agent for security analysis and recommendations using Ollama
"""

import requests
import json
import time
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import os
import sys
from security_monitor import SecurityMonitor, SecurityEvent

class LLMSecurityAgent:
    def __init__(self, ollama_host="http://localhost:11434", ollama_model="llama3:latest"):
        self.ollama_host = ollama_host
        self.ollama_model = ollama_model
        self.security_monitor = SecurityMonitor()
        self.conversation_history = []
        self.max_history = 10
        
    def check_ollama_connection(self) -> bool:
        """Check if Ollama is available"""
        try:
            response = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def get_available_models(self) -> List[str]:
        """Get list of available Ollama models"""
        try:
            response = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return [model.get('name', 'Unknown') for model in models]
            return []
        except:
            return []
    
    def query_ollama(self, prompt: str, context: str = "") -> str:
        """Query Ollama with prompt and context"""
        try:
            full_prompt = f"{context}\n\n{prompt}" if context else prompt
            
            response = requests.post(
                f"{self.ollama_host}/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": full_prompt,
                    "stream": False
                },
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', 'No response from LLM')
            else:
                return f"Error: HTTP {response.status_code}"
                
        except Exception as e:
            return f"Error querying Ollama: {str(e)}"
    
    def get_security_context(self, hours: int = 24) -> str:
        """Get security context from recent events"""
        try:
            events = self.security_monitor.get_recent_events(hours)
            
            if not events:
                return "No recent security events found."
            
            context_lines = [f"Recent security events (last {hours}h):"]
            
            for event in events[-20:]:  # Last 20 events
                time_str = datetime.fromisoformat(event.timestamp).strftime("%H:%M:%S")
                context_lines.append(
                    f"- {time_str}: {event.event_type} - {event.device_name} "
                    f"({event.port_type}) - Risk: {event.risk_level}"
                )
            
            return "\n".join(context_lines)
            
        except Exception as e:
            return f"Error getting security context: {str(e)}"
    
    def get_current_devices_context(self) -> str:
        """Get context about currently connected devices"""
        try:
            system_info = self.security_monitor.get_system_info()
            devices = self.security_monitor.extract_devices(system_info)
            
            if not devices:
                return "No devices currently connected."
            
            context_lines = ["Currently connected devices:"]
            
            # Group by type
            device_groups = {}
            for device_id, device_info in devices.items():
                device_type = device_info['type']
                if device_type not in device_groups:
                    device_groups[device_type] = []
                device_groups[device_type].append(device_info)
            
            for device_type, device_list in device_groups.items():
                context_lines.append(f"\n{device_type.upper()} ({len(device_list)}):")
                for device in device_list:
                    context_lines.append(f"  - {device['name']}")
                    if 'vendor' in device:
                        context_lines.append(f"    Vendor: {device['vendor']}")
                    if 'serial' in device:
                        context_lines.append(f"    Serial: {device['serial']}")
            
            return "\n".join(context_lines)
            
        except Exception as e:
            return f"Error getting device context: {str(e)}"
    
    def analyze_security_events(self, events: List[SecurityEvent]) -> str:
        """Analyze security events using LLM"""
        if not events:
            return "No events to analyze."
        
        context = "Security events to analyze:\n"
        for event in events:
            context += f"- {event.timestamp}: {event.event_type} - {event.device_name} ({event.port_type}) - Risk: {event.risk_level}\n"
        
        prompt = """
You are a cybersecurity expert analyzing device connection events on a Mac M1 Max system.

Please provide a detailed security analysis including:
1. Risk assessment for each event
2. Potential security implications
3. Recommended actions
4. Any suspicious patterns or anomalies
5. Overall security posture assessment

Provide actionable recommendations and focus on practical security measures.
"""
        
        return self.query_ollama(prompt, context)
    
    def get_security_recommendations(self) -> str:
        """Get general security recommendations"""
        context = self.get_security_context(1)  # Last hour
        devices_context = self.get_current_devices_context()
        
        full_context = f"{context}\n\n{devices_context}"
        
        prompt = """
You are a cybersecurity expert providing recommendations for a Mac M1 Max system.

Based on the current security events and connected devices, provide:
1. Immediate security recommendations
2. Best practices for device management
3. Monitoring suggestions
4. Potential vulnerabilities to address
5. Security tools or measures to implement

Focus on practical, actionable advice for maintaining system security.
"""
        
        return self.query_ollama(prompt, full_context)
    
    def analyze_specific_device(self, device_name: str) -> str:
        """Analyze a specific device for security implications"""
        try:
            system_info = self.security_monitor.get_system_info()
            devices = self.security_monitor.extract_devices(system_info)
            
            # Find the device
            target_device = None
            for device_id, device_info in devices.items():
                if device_name.lower() in device_info['name'].lower():
                    target_device = device_info
                    break
            
            if not target_device:
                return f"Device '{device_name}' not found in currently connected devices."
            
            context = f"Device to analyze:\n"
            context += f"Name: {target_device['name']}\n"
            context += f"Type: {target_device['type']}\n"
            context += f"Details: {json.dumps(target_device['details'], indent=2)}\n"
            
            prompt = f"""
You are a cybersecurity expert analyzing a specific device on a Mac M1 Max system.

Please analyze this device and provide:
1. Security risk assessment
2. Potential threats or vulnerabilities
3. Recommended security measures
4. Monitoring suggestions
5. Whether this device should be trusted

Focus on the security implications of this specific device.
"""
            
            return self.query_ollama(prompt, context)
            
        except Exception as e:
            return f"Error analyzing device: {str(e)}"
    
    def get_threat_intelligence(self, query: str) -> str:
        """Get threat intelligence information"""
        context = self.get_security_context(24)  # Last 24 hours
        
        prompt = f"""
You are a cybersecurity expert providing threat intelligence.

Query: {query}

Based on the current security context, provide:
1. Relevant threat intelligence
2. Known attack patterns
3. Indicators of compromise to watch for
4. Recommended defensive measures
5. Industry best practices

Provide practical, actionable threat intelligence.
"""
        
        return self.query_ollama(prompt, context)
    
    def add_to_conversation(self, role: str, content: str):
        """Add message to conversation history"""
        self.conversation_history.append({
            'role': role,
            'content': content,
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only recent history
        if len(self.conversation_history) > self.max_history:
            self.conversation_history = self.conversation_history[-self.max_history:]
    
    def get_conversation_summary(self) -> str:
        """Get summary of conversation history"""
        if not self.conversation_history:
            return "No conversation history."
        
        context = "Conversation history:\n"
        for msg in self.conversation_history[-5:]:  # Last 5 messages
            context += f"{msg['role']}: {msg['content'][:100]}...\n"
        
        prompt = """
Summarize the key points from this security conversation, including:
1. Main security concerns discussed
2. Recommendations provided
3. Actions taken or suggested
4. Follow-up items

Provide a concise summary of the security discussion.
"""
        
        return self.query_ollama(prompt, context)
    
    def interactive_mode(self):
        """Run interactive mode for user queries"""
        print("🔒 NIMDA LLM Security Agent")
        print("=" * 50)
        
        if not self.check_ollama_connection():
            print("❌ Ollama not available. Please start Ollama first.")
            return
        
        models = self.get_available_models()
        print(f"✅ Connected to Ollama")
        print(f"📋 Available models: {', '.join(models[:3])}{'...' if len(models) > 3 else ''}")
        print(f"🤖 Using model: {self.ollama_model}")
        print("=" * 50)
        
        while True:
            try:
                print("\nOptions:")
                print("1. Analyze recent security events")
                print("2. Get security recommendations")
                print("3. Analyze specific device")
                print("4. Threat intelligence query")
                print("5. Get conversation summary")
                print("6. Custom query")
                print("0. Exit")
                
                choice = input("\nSelect option (0-6): ").strip()
                
                if choice == "0":
                    break
                elif choice == "1":
                    print("\n🔍 Analyzing recent security events...")
                    events = self.security_monitor.get_recent_events(10)
                    response = self.analyze_security_events(events)
                    print(f"\n📊 Analysis:\n{response}")
                    self.add_to_conversation("user", "Analyze recent security events")
                    self.add_to_conversation("assistant", response)
                    
                elif choice == "2":
                    print("\n💡 Getting security recommendations...")
                    response = self.get_security_recommendations()
                    print(f"\n💡 Recommendations:\n{response}")
                    self.add_to_conversation("user", "Get security recommendations")
                    self.add_to_conversation("assistant", response)
                    
                elif choice == "3":
                    device_name = input("Enter device name to analyze: ").strip()
                    if device_name:
                        print(f"\n🔍 Analyzing device: {device_name}")
                        response = self.analyze_specific_device(device_name)
                        print(f"\n📊 Device Analysis:\n{response}")
                        self.add_to_conversation("user", f"Analyze device: {device_name}")
                        self.add_to_conversation("assistant", response)
                    
                elif choice == "4":
                    query = input("Enter threat intelligence query: ").strip()
                    if query:
                        print(f"\n🔍 Getting threat intelligence for: {query}")
                        response = self.get_threat_intelligence(query)
                        print(f"\n🛡️ Threat Intelligence:\n{response}")
                        self.add_to_conversation("user", f"Threat intelligence: {query}")
                        self.add_to_conversation("assistant", response)
                    
                elif choice == "5":
                    print("\n📋 Getting conversation summary...")
                    response = self.get_conversation_summary()
                    print(f"\n📋 Summary:\n{response}")
                    
                elif choice == "6":
                    query = input("Enter your custom query: ").strip()
                    if query:
                        print(f"\n🤖 Processing query: {query}")
                        context = self.get_security_context(1)
                        response = self.query_ollama(query, context)
                        print(f"\n🤖 Response:\n{response}")
                        self.add_to_conversation("user", query)
                        self.add_to_conversation("assistant", response)
                
                input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except Exception as e:
                print(f"\n❌ Error: {str(e)}")
                input("Press Enter to continue...")

def main():
    """Main function"""
    agent = LLMSecurityAgent()
    agent.interactive_mode()

if __name__ == "__main__":
    main() 