#!/usr/bin/env python3
"""
NIMDA LLM Security Agent
Interactive AI agent for security analysis and recommendations using Ollama
"""

import requests
import json
import logging
from datetime import datetime
from typing import List, Dict, Any
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
        except Exception:
            return False
    
    def get_available_models(self) -> List[str]:
        """Get list of available Ollama models"""
        try:
            response = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return [model.get('name', 'Unknown') for model in models]
            return []
        except Exception:
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
            
            context = "Device to analyze:\n"
            context += f"Name: {target_device['name']}\n"
            context += f"Type: {target_device['type']}\n"
            context += f"Details: {json.dumps(target_device['details'], indent=2)}\n"
            
            prompt = """
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
        print("✅ Connected to Ollama")
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

    def analyze_security_query(self, query: str) -> str:
        """Analyze general security queries"""
        try:
            # Get current security context
            security_context = self.get_security_context(1)  # Last hour
            devices_context = self.get_current_devices_context()
            
            full_context = f"{security_context}\n\n{devices_context}"
            
            prompt = f"""
You are a cybersecurity expert assistant for a Mac M1 Max system.

User Query: {query}

Please provide a comprehensive response that includes:
1. Direct answer to the user's question
2. Relevant security context from current system state
3. Practical recommendations
4. Any immediate actions needed

Keep the response clear, actionable, and focused on security best practices.
"""
            
            return self.query_ollama(prompt, full_context)
            
        except Exception as e:
            return f"Error analyzing security query: {str(e)}"
    
    def generate_hunting_hypothesis(self, system_summary: Dict[str, Any]) -> str:
        """
        Asks the AI to generate a hypothesis for a potential hidden threat.
        This implements the proactive hunting capability.
        """
        prompt = f"""
        You are an elite cybersecurity threat hunter. Based on the following system summary, 
        formulate ONE SINGLE probing question to uncover a potential hidden threat.
        The question must be answerable by querying system data (e.g., processes, files, connections).
        
        System Summary:
        {json.dumps(system_summary, indent=2)}

        Example questions:
        - "Are there any running processes that are not signed by Apple or a known developer?"
        - "Is there any network traffic going to a country known for cyber attacks?"
        - "Are there any recently created executable files in temporary directories?"
        - "Show me processes with high CPU or memory usage"
        - "Check for suspicious network connections"

        Formulate your question as a JSON object: {{"hypothesis_query": "Your question here"}}
        """
        try:
            # Assuming analyze_threat returns a dict from the JSON response
            response = self.query_ollama(prompt)
            
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{.*"hypothesis_query".*\}', response)
            if json_match:
                result = json.loads(json_match.group())
                return result.get("hypothesis_query")
            else:
                # Fallback: extract the question directly
                lines = response.split('\n')
                for line in lines:
                    if '?' in line and any(keyword in line.lower() for keyword in ['process', 'network', 'file', 'connection']):
                        return line.strip()
            
            return "Are there any suspicious processes running on the system?"
            
        except Exception as e:
            logging.error(f"Could not generate AI hypothesis: {e}")
            return None

    def analyze_threat(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze a threat using the LLM and return structured data.
        Enhanced to return JSON-structured responses for better integration.
        """
        try:
            response = self.query_ollama(prompt)
            
            # Try to extract structured data from response
            result = {
                'analysis': response,
                'confidence': 75,  # Default confidence
                'threat_level': 'medium',
                'recommendations': []
            }
            
            # Simple analysis of response content for threat level
            response_lower = response.lower()
            if any(word in response_lower for word in ['critical', 'severe', 'high risk', 'malware', 'attack']):
                result['threat_level'] = 'high'
                result['confidence'] = 85
            elif any(word in response_lower for word in ['suspicious', 'concern', 'monitor', 'investigate']):
                result['threat_level'] = 'medium'
                result['confidence'] = 70
            elif any(word in response_lower for word in ['normal', 'safe', 'no threat', 'benign']):
                result['threat_level'] = 'low'
                result['confidence'] = 80
                
            # Extract recommendations
            lines = response.split('\n')
            recommendations = []
            in_recommendations = False
            
            for line in lines:
                line = line.strip()
                if 'recommend' in line.lower() and ':' in line:
                    in_recommendations = True
                    continue
                if in_recommendations and line and (line.startswith('-') or line.startswith('*') or line.startswith('1.')):
                    recommendations.append(line.lstrip('-*1234567890. '))
                elif in_recommendations and not line:
                    break
            
            result['recommendations'] = recommendations
            return result
            
        except Exception as e:
            logging.error(f"Error in threat analysis: {e}")
            return {
                'analysis': f"Error analyzing threat: {str(e)}",
                'confidence': 0,
                'threat_level': 'unknown',
                'recommendations': []
            }

    def analyze_kernel_event(self, event_data: Dict[str, Any]):
        """
        Analyze a kernel event using AI to determine threat level and provide insights.
        This integrates with the KernelMonitor for real-time analysis.
        """
        try:
            event_context = f"""
            Kernel Event Analysis:
            Event Type: {event_data.get('event_type', 'unknown')}
            Timestamp: {event_data.get('timestamp', 'unknown')}
            Process: {event_data.get('process', {})}
            Details: {json.dumps(event_data, indent=2)}
            """
            
            prompt = f"""
            You are a cybersecurity expert analyzing a kernel-level system event.
            
            {event_context}
            
            Please analyze this event and provide:
            1. Threat assessment (low/medium/high/critical)
            2. Potential security implications
            3. Whether this requires immediate attention
            4. Recommended actions
            
            Respond in a structured format focusing on security relevance.
            """
            
            analysis = self.analyze_threat(prompt)
            
            # Store the analysis for correlation
            self.add_to_conversation("system", f"Kernel event: {event_data.get('event_type', 'unknown')}")
            self.add_to_conversation("assistant", analysis['analysis'])
            
            return analysis
            
        except Exception as e:
            logging.error(f"Error analyzing kernel event: {e}")
            return {
                'analysis': f"Error analyzing kernel event: {str(e)}",
                'threat_level': 'unknown',
                'confidence': 0
            }

    def continuous_threat_hunting(self, interval_minutes: int = 30):
        """
        Continuously generate and execute threat hunting hypotheses.
        This implements the autonomous AI agent hunting loop.
        """
        import time
        from core.system_query_engine import SystemQueryEngine
        
        query_engine = SystemQueryEngine()
        
        while True:
            try:
                # Get current system summary
                system_summary = self._get_comprehensive_system_summary()
                
                # Generate hunting hypothesis
                hypothesis = self.generate_hunting_hypothesis(system_summary)
                
                if hypothesis:
                    logging.info(f"AI Hunting Hypothesis: {hypothesis}")
                    
                    # Execute the query
                    results = query_engine.execute_query(hypothesis)
                    
                    # Analyze results with AI
                    if results.get('status') == 'success':
                        analysis_prompt = f"""
                        As a cybersecurity expert, analyze these query results:
                        
                        Query: {hypothesis}
                        Results: {json.dumps(results, indent=2)}
                        
                        Determine:
                        1. Are there any security concerns in these results?
                        2. Threat level assessment
                        3. Immediate actions needed
                        4. Follow-up investigations
                        """
                        
                        analysis = self.analyze_threat(analysis_prompt)
                        
                        # Log significant findings
                        if analysis['threat_level'] in ['high', 'critical']:
                            logging.warning(f"AI Hunter found {analysis['threat_level']} threat: {analysis['analysis'][:100]}...")
                        
                        # Store results for future correlation
                        self.add_to_conversation("hunter", f"Query: {hypothesis}")
                        self.add_to_conversation("hunter_result", str(results))
                        self.add_to_conversation("hunter_analysis", analysis['analysis'])
                
                # Sleep until next hunting cycle
                time.sleep(interval_minutes * 60)
                
            except Exception as e:
                logging.error(f"Error in continuous threat hunting: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying

    def _get_comprehensive_system_summary(self) -> Dict[str, Any]:
        """Get a comprehensive system summary for AI analysis"""
        try:
            summary = {
                'timestamp': datetime.now().isoformat(),
                'security_events_24h': len(self.security_monitor.get_recent_events(24)),
                'connected_devices': len(self.security_monitor.extract_devices(self.security_monitor.get_system_info())),
                'system_load': 'unknown',
                'network_connections': 0,
                'running_processes': 0
            }
            
            # Enhance with real-time data
            try:
                import psutil
                summary['system_load'] = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 'unknown'
                summary['network_connections'] = len(psutil.net_connections())
                summary['running_processes'] = len(psutil.pids())
                summary['cpu_percent'] = psutil.cpu_percent(interval=1)
                summary['memory_percent'] = psutil.virtual_memory().percent
            except Exception:
                pass
            
            return summary
            
        except Exception as e:
            logging.error(f"Error getting system summary: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e)
            }