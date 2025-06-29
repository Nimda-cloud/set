#!/usr/bin/env python3
"""
AI Providers Manager for NIMDA Security System
Supports multiple AI providers: Ollama, Gemini, Groq, Mistral
"""

import requests
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
import os

class AIProvider:
    """Base class for AI providers"""
    
    def __init__(self, name: str, api_key: str = None, base_url: str = None):
        self.name = name
        self.api_key = api_key
        self.base_url = base_url
        self.is_available = False
        self.last_check = None
        
    def check_availability(self) -> bool:
        """Check if provider is available"""
        raise NotImplementedError
        
    def query(self, prompt: str, context: str = "") -> str:
        """Send query to provider"""
        raise NotImplementedError
        
    def get_models(self) -> List[str]:
        """Get available models"""
        raise NotImplementedError

class OllamaProvider(AIProvider):
    """Ollama local provider"""
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        super().__init__("Ollama", base_url=base_url)
        
    def check_availability(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            self.is_available = response.status_code == 200
            self.last_check = datetime.now()
            return self.is_available
        except:
            self.is_available = False
            return False
            
    def query(self, prompt: str, context: str = "", model: str = "llama2") -> str:
        try:
            payload = {
                "model": model,
                "prompt": f"{context}\n\n{prompt}",
                "stream": False
            }
            response = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=30)
            if response.status_code == 200:
                return response.json().get("response", "No response")
            else:
                return f"Error: {response.status_code}"
        except Exception as e:
            return f"Error: {str(e)}"
            
    def get_models(self) -> List[str]:
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get("models", [])
                return [model["name"] for model in models]
            return []
        except:
            return []

class GeminiProvider(AIProvider):
    """Google Gemini provider"""
    
    def __init__(self, api_key: str):
        super().__init__("Gemini", api_key=api_key, base_url="https://generativelanguage.googleapis.com/v1beta/models")
        
    def check_availability(self) -> bool:
        try:
            headers = {"Content-Type": "application/json"}
            params = {"key": self.api_key}
            response = requests.get(f"{self.base_url}/gemini-pro", headers=headers, params=params, timeout=5)
            self.is_available = response.status_code == 200
            self.last_check = datetime.now()
            return self.is_available
        except:
            self.is_available = False
            return False
            
    def query(self, prompt: str, context: str = "", model: str = "gemini-pro") -> str:
        try:
            headers = {"Content-Type": "application/json"}
            params = {"key": self.api_key}
            
            content = f"{context}\n\n{prompt}" if context else prompt
            
            payload = {
                "contents": [{
                    "parts": [{"text": content}]
                }]
            }
            
            response = requests.post(
                f"{self.base_url}/{model}:generateContent",
                headers=headers,
                params=params,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "No response")
            else:
                return f"Error: {response.status_code}"
        except Exception as e:
            return f"Error: {str(e)}"
            
    def get_models(self) -> List[str]:
        return ["gemini-pro", "gemini-pro-vision"]

class GroqProvider(AIProvider):
    """Groq provider"""
    
    def __init__(self, api_key: str):
        super().__init__("Groq", api_key=api_key, base_url="https://api.groq.com/openai/v1")
        
    def check_availability(self) -> bool:
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.get(f"{self.base_url}/models", headers=headers, timeout=5)
            self.is_available = response.status_code == 200
            self.last_check = datetime.now()
            return self.is_available
        except:
            self.is_available = False
            return False
            
    def query(self, prompt: str, context: str = "", model: str = "llama3-8b-8192") -> str:
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            content = f"{context}\n\n{prompt}" if context else prompt
            
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": content}],
                "temperature": 0.7,
                "max_tokens": 1000
            }
            
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("choices", [{}])[0].get("message", {}).get("content", "No response")
            else:
                return f"Error: {response.status_code}"
        except Exception as e:
            return f"Error: {str(e)}"
            
    def get_models(self) -> List[str]:
        return ["llama3-8b-8192", "llama3-70b-8192", "mixtral-8x7b-32768", "gemma-7b-it"]

class MistralProvider(AIProvider):
    """Mistral AI provider"""
    
    def __init__(self, api_key: str):
        super().__init__("Mistral", api_key=api_key, base_url="https://api.mistral.ai/v1")
        
    def check_availability(self) -> bool:
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.get(f"{self.base_url}/models", headers=headers, timeout=5)
            self.is_available = response.status_code == 200
            self.last_check = datetime.now()
            return self.is_available
        except:
            self.is_available = False
            return False
            
    def query(self, prompt: str, context: str = "", model: str = "mistral-tiny") -> str:
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            content = f"{context}\n\n{prompt}" if context else prompt
            
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": content}],
                "temperature": 0.7,
                "max_tokens": 1000
            }
            
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("choices", [{}])[0].get("message", {}).get("content", "No response")
            else:
                return f"Error: {response.status_code}"
        except Exception as e:
            return f"Error: {str(e)}"
            
    def get_models(self) -> List[str]:
        return ["mistral-tiny", "mistral-small", "mistral-medium", "mistral-large"]

class AIProviderManager:
    """Manager for multiple AI providers"""
    
    def __init__(self):
        self.providers: Dict[str, AIProvider] = {}
        self.active_provider = None
        self.fallback_providers = []
        self.load_config()
        
    def load_config(self):
        """Load provider configuration from environment"""
        # Ollama (local)
        self.add_provider(OllamaProvider())
        
        # Gemini
        gemini_key = os.getenv("GEMINI_API_KEY")
        if gemini_key:
            self.add_provider(GeminiProvider(gemini_key))
            
        # Groq
        groq_key = os.getenv("GROQ_API_KEY")
        if groq_key:
            self.add_provider(GroqProvider(groq_key))
            
        # Mistral
        mistral_key = os.getenv("MISTRAL_API_KEY")
        if mistral_key:
            self.add_provider(MistralProvider(mistral_key))
            
        # Set default active provider
        if self.providers:
            self.active_provider = list(self.providers.keys())[0]
            
    def add_provider(self, provider: AIProvider):
        """Add a provider to the manager"""
        self.providers[provider.name] = provider
        
    def set_active_provider(self, provider_name: str) -> bool:
        """Set active provider"""
        if provider_name in self.providers:
            self.active_provider = provider_name
            return True
        return False
        
    def get_active_provider(self) -> Optional[AIProvider]:
        """Get active provider"""
        if self.active_provider and self.active_provider in self.providers:
            return self.providers[self.active_provider]
        return None
        
    def query(self, prompt: str, context: str = "", provider_name: str = None) -> str:
        """Query AI with fallback support"""
        if provider_name and provider_name in self.providers:
            provider = self.providers[provider_name]
        else:
            provider = self.get_active_provider()
            
        if not provider:
            return "No AI providers available"
            
        # Try active provider
        response = provider.query(prompt, context)
        if not response.startswith("Error"):
            return response
            
        # Try fallback providers
        for fallback_name in self.fallback_providers:
            if fallback_name in self.providers:
                fallback_provider = self.providers[fallback_name]
                response = fallback_provider.query(prompt, context)
                if not response.startswith("Error"):
                    return response
                    
        return "All AI providers failed"
        
    def get_available_providers(self) -> List[str]:
        """Get list of available providers"""
        available = []
        for name, provider in self.providers.items():
            if provider.check_availability():
                available.append(name)
        return available
        
    def get_provider_status(self) -> Dict[str, Dict]:
        """Get status of all providers"""
        status = {}
        for name, provider in self.providers.items():
            status[name] = {
                "available": provider.check_availability(),
                "last_check": provider.last_check,
                "models": provider.get_models() if provider.is_available else []
            }
        return status
    
    def load_configuration(self, config_data: Dict):
        """Load configuration from dictionary"""
        try:
            # Clear existing providers
            self.providers.clear()
            
            # Load Ollama configuration
            if 'ollama' in config_data:
                ollama_config = config_data['ollama']
                base_url = ollama_config.get('url', 'http://localhost:11434')
                provider = OllamaProvider(base_url)
                self.add_provider(provider)
            
            # Load Gemini configuration
            if 'gemini' in config_data:
                gemini_config = config_data['gemini']
                api_key = gemini_config.get('api_key')
                if api_key:
                    provider = GeminiProvider(api_key)
                    self.add_provider(provider)
            
            # Load Groq configuration
            if 'groq' in config_data:
                groq_config = config_data['groq']
                api_key = groq_config.get('api_key')
                if api_key:
                    provider = GroqProvider(api_key)
                    self.add_provider(provider)
            
            # Load Mistral configuration
            if 'mistral' in config_data:
                mistral_config = config_data['mistral']
                api_key = mistral_config.get('api_key')
                if api_key:
                    provider = MistralProvider(api_key)
                    self.add_provider(provider)
            
            # Set default active provider
            if self.providers:
                self.active_provider = list(self.providers.keys())[0]
                
        except Exception as e:
            print(f"Failed to load configuration: {e}")
    
    def save_configuration(self, config_file: str = "ai_providers_config.json"):
        """Save current configuration to file"""
        try:
            config_data = {}
            
            for name, provider in self.providers.items():
                if isinstance(provider, OllamaProvider):
                    config_data[name] = {
                        'url': provider.base_url,
                        'model': 'llama2'  # Default model
                    }
                elif isinstance(provider, (GeminiProvider, GroqProvider, MistralProvider)):
                    config_data[name] = {
                        'api_key': provider.api_key,
                        'model': 'default'  # Default model
                    }
            
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
                
        except Exception as e:
            print(f"Failed to save configuration: {e}") 