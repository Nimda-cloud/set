#!/usr/bin/env python3
"""
Simple Threat Level Analyzer Test
Простий тест аналізатора загроз без залежностей
"""

import time
from datetime import datetime
from enum import Enum

class ThreatLevel(Enum):
    """Рівні загроз"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EMERGENCY = 5

class SimpleThreatAnalyzer:
    """Простий аналізатор загроз для демонстрації"""
    
    def __init__(self):
        self.threat_history = []
        
    def analyze_threat_levels(self, target: str, context: dict = None) -> ThreatLevel:
        """Аналізує рівень загроз"""
        print(f"🔍 Аналіз загроз для: {target}")
        
        # Простий алгоритм на основі контексту
        score = 0
        
        if context:
            if context.get('external_ip'):
                score += 30
                print("  ⚠️ Виявлено зовнішній IP")
            if context.get('known_malware_signature'):
                score += 50
                print("  🦠 Виявлено підпис малваре")
            if context.get('privilege_escalation'):
                score += 40
                print("  🔓 Спроба підвищення привілеїв")
            if context.get('suspicious_port'):
                score += 20
                print("  🔌 Підозрілий порт")
        
        # Визначаємо рівень
        if score >= 80:
            threat_level = ThreatLevel.EMERGENCY
        elif score >= 60:
            threat_level = ThreatLevel.CRITICAL
        elif score >= 40:
            threat_level = ThreatLevel.HIGH
        elif score >= 20:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
            
        # Записуємо в історію
        self.threat_history.append({
            'timestamp': datetime.now(),
            'target': target,
            'threat_level': threat_level,
            'score': score
        })
        
        # Виконуємо відповідь
        self._execute_response(threat_level, target)
        
        return threat_level
    
    def _execute_response(self, threat_level: ThreatLevel, target: str):
        """Виконує відповідь на загрозу"""
        responses = {
            ThreatLevel.LOW: ("🟢", "Стандартний моніторинг"),
            ThreatLevel.MEDIUM: ("🟡", "Посилений моніторинг"),
            ThreatLevel.HIGH: ("🟠", "Активні заходи захисту"),
            ThreatLevel.CRITICAL: ("🔴", "Критичні заходи безпеки"),
            ThreatLevel.EMERGENCY: ("⚫", "НАДЗВИЧАЙНА СИТУАЦІЯ")
        }
        
        emoji, description = responses[threat_level]
        print(f"{emoji} {threat_level.name}: {description}")
        
        # Симуляція дій
        if threat_level.value >= 3:
            print("  🚨 Виконання автоматичних дій...")
            time.sleep(1)
    
    def get_history_summary(self):
        """Повертає підсумок історії"""
        if not self.threat_history:
            return "Аналіз не проводився"
        
        levels = [entry['threat_level'] for entry in self.threat_history]
        return {
            'total_analyses': len(self.threat_history),
            'latest_threat': levels[-1].name,
            'max_threat': max(levels, key=lambda x: x.value).name,
            'threats_by_level': {level.name: levels.count(level) for level in ThreatLevel}
        }

def main():
    """Демонстрація роботи аналізатора"""
    print("🚀 NIMDA Simple Threat Level Analyzer")
    print("=" * 50)
    
    analyzer = SimpleThreatAnalyzer()
    
    # Тестові сценарії
    test_scenarios = [
        {
            "target": "Port 22 (SSH)",
            "context": {"external_ip": True, "suspicious_port": True}
        },
        {
            "target": "bitcoin-miner.exe",
            "context": {"known_malware_signature": True, "privilege_escalation": True}
        },
        {
            "target": "Port 4444 (Metasploit)",
            "context": {"external_ip": True, "suspicious_port": True, "known_malware_signature": True}
        },
        {
            "target": "Chrome Browser",
            "context": {}
        },
        {
            "target": "sudo attempt",
            "context": {"privilege_escalation": True}
        }
    ]
    
    # Запускаємо тести
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n📍 Тестовий сценарій {i}:")
        threat_level = analyzer.analyze_threat_levels(
            scenario["target"],
            scenario["context"]
        )
        print(f"Результат: {threat_level.name} (рівень {threat_level.value})")
        time.sleep(1.5)
    
    # Показуємо підсумок
    print("\n📊 Підсумок аналізу:")
    summary = analyzer.get_history_summary()
    for key, value in summary.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for k, v in value.items():
                print(f"    {k}: {v}")
        else:
            print(f"  {key}: {value}")
    
    print("\n✅ Демонстрація завершена!")

if __name__ == "__main__":
    main()
