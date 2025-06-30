import requests
import os
import logging
import re
from urllib.parse import urlparse

# Налаштування логування
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RuleManager:
    """
    Керує завантаженням, зберіганням та оновленням правил безпеки.
    """
    def __init__(self, rules_dir='rules'):
        self.rules_dir = rules_dir
        self.rulesets = {
            "emerging_threats": "https://rules.emergingthreats.net/open/suricata-6.0/emerging-all.rules"
        }
        
        # Створюємо .gitignore правило для rules директорії, якщо потрібно
        self._ensure_gitignore_rules()
        
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            logging.info(f"Створено директорію для правил: {self.rules_dir}")
            
            # Створюємо README для папки rules
            self._create_rules_readme()

    def _get_filename_from_url(self, url):
        """Отримує ім'я файлу з URL."""
        parsed_url = urlparse(url)
        return os.path.basename(parsed_url.path)

    def download_ruleset(self, name):
        """Завантажує конкретний набір правил."""
        if name not in self.rulesets:
            logging.error(f"Набір правил '{name}' не знайдено.")
            return False

        url = self.rulesets[name]
        filename = self._get_filename_from_url(url)
        filepath = os.path.join(self.rules_dir, filename)

        try:
            logging.info(f"Завантаження набору правил '{name}' з {url}...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()  # Перевірка на HTTP помилки

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            logging.info(f"Набір правил '{name}' успішно завантажено та збережено як {filepath}")
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"Помилка під час завантаження правил '{name}': {e}")
            return False

    def update_all_rules(self):
        """Оновлює всі набори правил."""
        success_count = 0
        for name in self.rulesets:
            if self.download_ruleset(name):
                success_count += 1
        return success_count

    def load_rules(self):
        """
        Завантажує всі правила з файлів у пам'ять.
        Для простоти, ми будемо завантажувати правила, що містять ключові слова для виявлення,
        ігноруючи коментарі та складний синтаксис.
        """
        loaded_rules = []
        if not os.path.exists(self.rules_dir):
            return loaded_rules

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".rules"):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line in f:
                            # Ігноруємо коментарі та пусті рядки
                            if line.strip() and not line.strip().startswith('#'):
                                # Спрощене завантаження: додаємо все правило як рядок
                                loaded_rules.append(line.strip())
                except Exception as e:
                    logging.error(f"Не вдалося прочитати файл правил {filepath}: {e}")
        
        logging.info(f"Завантажено {len(loaded_rules)} правил.")
        return loaded_rules

    def parse_rule_for_analysis(self, rule):
        """
        Парсить правило Suricata для отримання ключових атрибутів для аналізу.
        Повертає словник з extracted інформацією або None, якщо правило не може бути розпаршене.
        """
        try:
            # Шукаємо основні атрибути в правилі
            content_match = re.search(r'content:"([^"]+)"', rule)
            msg_match = re.search(r'msg:"([^"]+)"', rule)
            sid_match = re.search(r'sid:(\d+)', rule)
            
            if content_match or msg_match:
                return {
                    'content': content_match.group(1) if content_match else None,
                    'message': msg_match.group(1) if msg_match else "No message",
                    'sid': sid_match.group(1) if sid_match else "N/A",
                    'raw_rule': rule
                }
        except re.error as e:
            logging.debug(f"Помилка парсингу правила: {e}")
        
        return None

    def get_parsed_rules(self):
        """
        Повертає список розпаршених правил для використання в аналізі.
        """
        raw_rules = self.load_rules()
        parsed_rules = []
        
        for rule in raw_rules:
            parsed = self.parse_rule_for_analysis(rule)
            if parsed:
                parsed_rules.append(parsed)
        
        logging.info(f"Розпаршено {len(parsed_rules)} правил для аналізу.")
        return parsed_rules

    def _ensure_gitignore_rules(self):
        """Забезпечує, що папка rules є в .gitignore"""
        gitignore_path = '.gitignore'
        rules_ignore_line = 'rules/'
        
        try:
            if os.path.exists(gitignore_path):
                with open(gitignore_path, 'r') as f:
                    content = f.read()
                
                if rules_ignore_line not in content:
                    with open(gitignore_path, 'a') as f:
                        f.write(f"\n# Security rules (auto-added by NIMDA)\n{rules_ignore_line}\n")
                    logging.info("Додано rules/ до .gitignore")
        except Exception as e:
            logging.warning(f"Не вдалося оновити .gitignore: {e}")

    def _create_rules_readme(self):
        """Створює README файл у папці rules"""
        readme_content = """# NIMDA Security Rules

Ця папка містить правила безпеки, завантажені з відкритих джерел.

⚠️ УВАГА: Ці файли не повинні потрапляти до git репозиторію через можливі 
false positive спрацьовування GitHub Secret Scanning.

## Файли в цій папці:
- emerging-all.rules: Правила Emerging Threats
- custom-rules.rules: Користувацькі правила (створюються вручну)

## Оновлення правил:
```bash
python core/rule_manager.py
```

Або через GUI: Security → Update Rules
"""
        
        readme_path = os.path.join(self.rules_dir, 'README.md')
        try:
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(readme_content)
            logging.info(f"Створено README у {readme_path}")
        except Exception as e:
            logging.error(f"Не вдалося створити README: {e}")

if __name__ == '__main__':
    # Приклад використання
    manager = RuleManager()
    
    # Спробуємо завантажити правила
    print("Оновлення правил...")
    success_count = manager.update_all_rules()
    print(f"Успішно завантажено {success_count} наборів правил.")
    
    # Завантажуємо та показуємо перші кілька правил
    rules = manager.load_rules()
    print(f"Загалом завантажено {len(rules)} правил.")
    
    if rules:
        print("\nПерші 5 завантажених правил:")
        for i, rule in enumerate(rules[:5]):
            print(f"{i+1}: {rule}")
        
        # Показуємо розпаршені правила
        parsed_rules = manager.get_parsed_rules()
        print("\nПерші 3 розпаршені правила:")
        for i, rule in enumerate(parsed_rules[:3]):
            print(f"{i+1}: SID={rule['sid']}, MSG='{rule['message']}'")
            if rule['content']:
                print(f"   Content pattern: '{rule['content']}'")
