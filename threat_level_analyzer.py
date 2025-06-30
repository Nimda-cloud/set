#!/usr/bin/env python3
"""
Threat Level Analyzer for NIMDA Security System
Аналізатор рівнів загроз з інтеграцією звукових сповіщень
"""

import sys
import time
import logging
from datetime import datetime
from typing import Dict, List

# Налаштування логування
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nimda_threat_analyzer.log"),
        logging.StreamHandler()
    ]
)

# Імпорт з основних модулів NIMDA
try:
    from nimda_integrated import ThreatLevel, SecurityMonitor
    from sound_alerts_enhanced import SoundAlertSystem
except ImportError as e:
    logging.error(f"Помилка імпорту: {e}")
    print("Запустіть скрипт з основної директорії NIMDA")
    sys.exit(1)

class ThreatLevelAnalyzer:
    """Клас для аналізу рівнів загроз з автоматичними діями."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.sound_alerts = SoundAlertSystem()
        self.security_monitor = SecurityMonitor()
        self.threat_history = []
        self.last_analysis_time = None
        self.logger.info("ThreatLevelAnalyzer ініціалізовано")
        
    def analyze_threat_levels(self, target: str = None, context: Dict = None) -> ThreatLevel:
        """
        Аналізує рівень загроз на основі поточного стану системи
        
        Args:
            target: Ціль аналізу (порт, процес, пристрій)
            context: Додатковий контекст для аналізу
            
        Returns:
            ThreatLevel: Визначений рівень загрози
        """
        self.logger.info(f"Початок аналізу загроз для: {target or 'системи'}")
        print(f"🔍 Аналіз загроз для: {target or 'системи'}")
        
        # Отримуємо поточні дані системи
        current_threats = self._collect_threat_indicators()
        self.logger.debug(f"Зібрані індикатори загроз: {current_threats}")
        
        # Аналізуємо рівень загроз
        threat_level = self._calculate_threat_level(current_threats, context)
        self.logger.info(f"Визначено рівень загрози: {threat_level.name}")
        
        # Записуємо в історію
        self.threat_history.append({
            'timestamp': datetime.now(),
            'target': target,
            'threat_level': threat_level,
            'indicators': current_threats
        })
        
        self.last_analysis_time = datetime.now()
        
        # Виконуємо відповідні дії
        self._execute_threat_response(threat_level, target, context)
        self.logger.info(f"Завершено аналіз загроз для: {target or 'системи'}")
        
        return threat_level

    def _collect_threat_indicators(self) -> Dict:
        """Збирає показники загроз з системи"""
        indicators = {
            'suspicious_processes': [],
            'open_ports': [],
            'network_connections': 0,
            'cpu_usage': 0,
            'memory_usage': 0,
            'disk_activity': 0
        }
        
        try:
            # Отримуємо дані від security monitor
            system_status = self.security_monitor.get_system_status()
            if system_status:
                indicators['cpu_usage'] = system_status.get('cpu_percent', 0)
                indicators['memory_usage'] = system_status.get('memory_percent', 0)
            
            # Аналізуємо процеси
            suspicious_processes = self.security_monitor.get_suspicious_processes()
            indicators['suspicious_processes'] = suspicious_processes
            
            # Аналізуємо порти
            open_ports = self.security_monitor.scan_ports()
            indicators['open_ports'] = open_ports
            
            # Мережеві з'єднання
            indicators['network_connections'] = len(self.security_monitor.get_network_connections())
            
        except Exception as e:
            print(f"⚠️ Помилка збору даних: {e}")
            
        return indicators

    def _calculate_threat_level(self, indicators: Dict, context: Dict = None) -> ThreatLevel:
        """Розраховує рівень загроз на основі показників"""
        score = 0
        
        # Аналіз підозрілих процесів
        suspicious_count = len(indicators.get('suspicious_processes', []))
        if suspicious_count > 5:
            score += 40
        elif suspicious_count > 2:
            score += 20
        elif suspicious_count > 0:
            score += 10
            
        # Аналіз відкритих портів
        port_count = len(indicators.get('open_ports', []))
        if port_count > 20:
            score += 30
        elif port_count > 10:
            score += 15
        elif port_count > 5:
            score += 5
            
        # Аналіз мережевих з'єднань
        connections = indicators.get('network_connections', 0)
        if connections > 50:
            score += 25
        elif connections > 20:
            score += 10
            
        # Додатковий контекст
        if context:
            if context.get('external_ip'):
                score += 20
            if context.get('known_malware_signature'):
                score += 50
            if context.get('privilege_escalation'):
                score += 30
                
        # Визначаємо рівень на основі балів
        if score >= 80:
            return ThreatLevel.EMERGENCY
        elif score >= 60:
            return ThreatLevel.CRITICAL
        elif score >= 40:
            return ThreatLevel.HIGH
        elif score >= 20:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _execute_threat_response(self, threat_level: ThreatLevel, target: str = None, context: Dict = None):
        """Виконує відповідь на загрозу"""
        print(f"🚨 Рівень загрози: {threat_level.name}")
        
        if threat_level == ThreatLevel.CRITICAL:
            self.handle_critical_threat(target, context)
        elif threat_level == ThreatLevel.EMERGENCY:
            self.handle_emergency_threat(target, context)
        elif threat_level == ThreatLevel.HIGH:
            self.handle_high_threat(target, context)
        elif threat_level == ThreatLevel.MEDIUM:
            self.handle_medium_threat(target, context)
        else:
            self.handle_low_threat(target, context)

    def handle_critical_threat(self, target: str = None, context: Dict = None):
        """Обробка критичної загрози"""
        self.logger.critical(f"КРИТИЧНА ЗАГРОЗА виявлена для: {target or 'системи'}")
        print("🔴 КРИТИЧНА ЗАГРОЗА - Виконання екстрених заходів...")
        
        # Звукове сповіщення
        self.sound_alerts.play_alert_pattern("CRITICAL_THREAT", target or "система")
        
        # Додаткові дії
        actions = [
            "Ізоляція підозрілих процесів",
            "Блокування мережевих з'єднань", 
            "Створення детального звіту",
            "Сповіщення адміністратора"
        ]
        
        for action in actions:
            self.logger.info(f"Виконання дії: {action}")
            print(f"  ▶ {action}")
            time.sleep(0.5)

    def handle_emergency_threat(self, target: str = None, context: Dict = None):
        """Обробка надзвичайної загрози"""
        self.logger.critical(f"⚫ НАДЗВИЧАЙНА СИТУАЦІЯ для: {target or 'системи'}")
        print("⚫ НАДЗВИЧАЙНА СИТУАЦІЯ - Активація всіх захисних систем...")
        
        # Аварійна сирена
        self.sound_alerts.play_alert_pattern("EMERGENCY", target or "система")
        
        # Критичні дії
        actions = [
            "Повна ізоляція системи",
            "Аварійне збереження логів",
            "Негайне сповіщення служби безпеки",
            "Ініціація протоколу відновлення"
        ]
        
        for action in actions:
            self.logger.critical(f"Виконання критичної дії: {action}")
            print(f"  🚨 {action}")
            time.sleep(0.3)

    def handle_high_threat(self, target: str = None, context: Dict = None):
        """Обробка високої загрози"""
        self.logger.warning(f"ВИСОКА ЗАГРОЗА для: {target or 'системи'}")
        print("🟠 ВИСОКА ЗАГРОЗА - Підвищені заходи безпеки...")
        
        self.sound_alerts.play_alert_pattern("HIGH_THREAT", target or "система")
        
        actions = [
            "Моніторинг активності",
            "Блокування підозрілих з'єднань",
            "Аналіз логів системи"
        ]
        
        for action in actions:
            self.logger.warning(f"Виконання дії: {action}")
            print(f"  ▶ {action}")

    def handle_medium_threat(self, target: str = None, context: Dict = None):
        """Обробка середньої загрози"""
        self.logger.info(f"СЕРЕДНЯ ЗАГРОЗА для: {target or 'системи'}")
        print("🟡 СЕРЕДНЯ ЗАГРОЗА - Стандартні заходи...")
        
        self.sound_alerts.play_alert_pattern("MEDIUM_THREAT", target or "система")
        
        actions = [
            "Посилений моніторинг",
            "Логування подій"
        ]
        
        for action in actions:
            self.logger.info(f"Виконання дії: {action}")
            print(f"  ▶ {action}")

    def handle_low_threat(self, target: str = None, context: Dict = None):
        """Обробка низької загрози"""
        self.logger.info(f"НИЗЬКА ЗАГРОЗА для: {target or 'системи'}")
        print("🟢 НИЗЬКА ЗАГРОЗА - Стандартний моніторинг...")
        
        self.sound_alerts.play_alert_pattern("LOW_THREAT", target or "система")
        
        self.logger.info("Виконання регулярного моніторингу")
        print("  ▶ Регулярний моніторинг")

    def get_threat_history(self, last_n: int = 10) -> List[Dict]:
        """Повертає історію загроз"""
        return self.threat_history[-last_n:]

    def get_current_threat_summary(self) -> Dict:
        """Повертає поточний стан загроз"""
        if not self.threat_history:
            return {"status": "Аналіз не проводився"}
            
        latest = self.threat_history[-1]
        return {
            "timestamp": latest['timestamp'],
            "current_level": latest['threat_level'].name,
            "target": latest['target'],
            "indicators_count": len(latest['indicators']),
            "last_analysis": self.last_analysis_time
        }

def main():
    """Тестування аналізатора загроз"""
    print("🚀 NIMDA Threat Level Analyzer")
    print("=" * 50)
    
    analyzer = ThreatLevelAnalyzer()
    
    # Тест різних сценаріїв
    test_scenarios = [
        {"target": "Port 4444", "context": {"external_ip": True}},
        {"target": "ssh process", "context": {"privilege_escalation": True}},
        {"target": "bitcoin miner", "context": {"known_malware_signature": True}},
        {"target": "normal activity", "context": {}}
    ]
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n📍 Тестовий сценарій {i}:")
        threat_level = analyzer.analyze_threat_levels(
            scenario["target"], 
            scenario["context"]
        )
        print(f"Результат: {threat_level.name}")
        time.sleep(2)
    
    # Показуємо історію
    print("\n📊 Історія загроз:")
    history = analyzer.get_threat_history()
    for entry in history:
        print(f"  {entry['timestamp'].strftime('%H:%M:%S')} - "
              f"{entry['target']} -> {entry['threat_level'].name}")
    
    # Поточний статус
    print("\n📈 Поточний статус:")
    summary = analyzer.get_current_threat_summary()
    for key, value in summary.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    main()
