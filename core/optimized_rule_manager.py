#!/usr/bin/env python3
"""
Optimized Rule Manager for NIMDA Security System
Provides efficient rule matching using regex compilation and performance optimizations
"""

import requests
import os
import logging
import re
import json
from urllib.parse import urlparse
from typing import List, Dict, Any
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class OptimizedRuleManager:
    """
    Manages security rule loading, compilation, and efficient matching
    """
    def __init__(self, rules_dir='rules'):
        self.rules_dir = rules_dir
        self.rulesets = {
            "emerging_threats": "https://rules.emergingthreats.net/open/suricata-6.0/emerging-all.rules"
        }
        
        # Ensure directory exists
        self._ensure_directories()
        
        # Compiled rule cache
        self._compiled_rules = {}
        self._compiled_rules_timestamp = 0
        
        # Rule statistics
        self.rule_stats = {
            "total_count": 0,
            "compiled_count": 0,
            "compile_time": 0,
            "match_time_avg": 0,
            "match_count": 0
        }

    def _ensure_directories(self):
        """Create necessary directories and files"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            logging.info(f"Created rules directory: {self.rules_dir}")
            self._create_rules_readme()
        
        # Create .gitignore rule for rules directory
        self._ensure_gitignore_rules()

    def _get_filename_from_url(self, url):
        """Get filename from URL"""
        parsed_url = urlparse(url)
        return os.path.basename(parsed_url.path)

    def download_ruleset(self, name):
        """Download a specific ruleset"""
        if name not in self.rulesets:
            logging.error(f"Ruleset '{name}' not found.")
            return False

        url = self.rulesets[name]
        filename = self._get_filename_from_url(url)
        filepath = os.path.join(self.rules_dir, filename)

        try:
            logging.info(f"Downloading ruleset '{name}' from {url}...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            logging.info(f"Ruleset '{name}' successfully downloaded and saved as {filepath}")
            
            # Clear compiled rules cache to force recompilation
            self._compiled_rules = {}
            self._compiled_rules_timestamp = 0
            
            return True
        except requests.exceptions.RequestException as e:
            logging.error(f"Error downloading rules '{name}': {e}")
            return False

    def update_all_rules(self):
        """Update all rulesets"""
        success_count = 0
        for name in self.rulesets:
            if self.download_ruleset(name):
                success_count += 1
        
        # Force rule recompilation if any rules were updated
        if success_count > 0:
            self.compile_rules()
            
        return success_count

    def load_rules(self):
        """Load all rules from files into memory"""
        loaded_rules = []
        if not os.path.exists(self.rules_dir):
            return loaded_rules

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".rules"):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line in f:
                            # Skip comments and empty lines
                            if line.strip() and not line.strip().startswith('#'):
                                loaded_rules.append(line.strip())
                except Exception as e:
                    logging.error(f"Failed to read rules file {filepath}: {e}")
        
        logging.info(f"Loaded {len(loaded_rules)} rules.")
        return loaded_rules

    def parse_rule_for_analysis(self, rule):
        """
        Parse Suricata rule for key attributes and compile patterns
        Returns a dictionary with extracted information or None if rule can't be parsed
        """
        try:
            # Extract main attributes
            content_match = re.search(r'content:"([^"]+)"', rule)
            msg_match = re.search(r'msg:"([^"]+)"', rule)
            sid_match = re.search(r'sid:(\d+)', rule)
            severity_match = re.search(r'severity:(\d+)', rule)
            rev_match = re.search(r'rev:(\d+)', rule)
            classtype_match = re.search(r'classtype:([^;]+);', rule)
            
            # Extract all pcre patterns from the rule
            pcre_matches = re.findall(r'pcre:"([^"]+)"', rule)
            
            # Determine rule severity based on classtype or explicit severity
            severity = "medium"
            if classtype_match:
                classtype = classtype_match.group(1).strip()
                if "trojan" in classtype or "exploit" in classtype or "attack" in classtype:
                    severity = "high"
                elif "policy" in classtype or "info" in classtype:
                    severity = "low"
            
            if severity_match:
                severity_num = int(severity_match.group(1))
                if severity_num >= 3:
                    severity = "high"
                elif severity_num == 2:
                    severity = "medium"
                else:
                    severity = "low"
                    
            if content_match or pcre_matches:
                parsed_rule = {
                    'content': content_match.group(1) if content_match else None,
                    'message': msg_match.group(1) if msg_match else "No message",
                    'sid': sid_match.group(1) if sid_match else "N/A",
                    'severity': severity,
                    'raw_rule': rule,
                    'pcre_patterns': pcre_matches,
                    'revision': rev_match.group(1) if rev_match else "1",
                    'classtype': classtype_match.group(1) if classtype_match else None
                }
                
                # Compile regex patterns ahead of time for better performance
                if parsed_rule['content']:
                    try:
                        content_pattern = re.escape(parsed_rule['content'])
                        parsed_rule['content_regex'] = re.compile(content_pattern, re.IGNORECASE)
                    except re.error:
                        logging.debug(f"Failed to compile content regex for rule {parsed_rule['sid']}")
                
                # Compile pcre patterns if present
                if pcre_matches:
                    parsed_rule['pcre_compiled'] = []
                    for pcre in pcre_matches:
                        try:
                            # Handle Suricata PCRE flags
                            pcre_parts = pcre.rsplit('/', 1)
                            pattern = pcre_parts[0].lstrip('/')
                            flags = pcre_parts[1] if len(pcre_parts) > 1 else ""
                            
                            # Convert Suricata flags to Python flags
                            py_flags = 0
                            if 'i' in flags:
                                py_flags |= re.IGNORECASE
                            if 's' in flags:
                                py_flags |= re.DOTALL
                            if 'm' in flags:
                                py_flags |= re.MULTILINE
                                
                            compiled = re.compile(pattern, py_flags)
                            parsed_rule['pcre_compiled'].append(compiled)
                        except re.error as e:
                            logging.debug(f"Failed to compile PCRE pattern {pcre}: {e}")
                
                return parsed_rule
        except re.error as e:
            logging.debug(f"Error parsing rule: {e}")
        
        return None

    def compile_rules(self):
        """
        Compile all rules for efficient matching
        This is a performance-critical operation that should be done once at startup
        or after rules are updated
        """
        start_time = time.time()
        
        raw_rules = self.load_rules()
        compiled_rules = []
        
        for rule in raw_rules:
            parsed = self.parse_rule_for_analysis(rule)
            if parsed:
                compiled_rules.append(parsed)
        
        # Store in instance variable for reuse
        self._compiled_rules = compiled_rules
        self._compiled_rules_timestamp = time.time()
        
        # Update stats
        compile_time = time.time() - start_time
        self.rule_stats.update({
            "total_count": len(raw_rules),
            "compiled_count": len(compiled_rules),
            "compile_time": compile_time
        })
        
        logging.info(f"Compiled {len(compiled_rules)} rules in {compile_time:.2f} seconds")
        return compiled_rules

    def get_parsed_rules(self):
        """
        Return list of parsed and compiled rules for analysis
        Uses cached rules if available, otherwise compiles them
        """
        # Check if we need to recompile (cache expired or empty)
        if not self._compiled_rules or time.time() - self._compiled_rules_timestamp > 3600:
            return self.compile_rules()
        
        return self._compiled_rules
    
    def match_rules(self, text):
        """
        Efficiently match text against all compiled rules
        Returns a list of matching rules
        """
        if not self._compiled_rules:
            self.compile_rules()
        
        start_time = time.time()
        matches = []
        
        for rule in self._compiled_rules:
            matched = False
            
            # Try matching content pattern first (faster)
            if rule.get('content_regex') and rule['content']:
                if rule['content_regex'].search(text):
                    matched = True
            elif rule.get('content') and rule['content'] in text:
                # Fallback to simple string matching if regex compilation failed
                matched = True
            
            # If content didn't match but we have PCRE patterns, try those
            if not matched and rule.get('pcre_compiled'):
                for pcre in rule.get('pcre_compiled', []):
                    if pcre.search(text):
                        matched = True
                        break
            
            if matched:
                matches.append(rule)
        
        # Update match stats
        match_time = time.time() - start_time
        total_match_time = self.rule_stats["match_time_avg"] * self.rule_stats["match_count"]
        self.rule_stats["match_count"] += 1
        self.rule_stats["match_time_avg"] = (total_match_time + match_time) / self.rule_stats["match_count"]
        
        return matches
    
    def get_rule_stats(self):
        """Get statistics about rule compilation and matching performance"""
        return self.rule_stats

    def _ensure_gitignore_rules(self):
        """Ensure rules folder is in .gitignore"""
        gitignore_path = '.gitignore'
        rules_ignore_line = 'rules/'
        
        try:
            if os.path.exists(gitignore_path):
                with open(gitignore_path, 'r') as f:
                    content = f.read()
                
                if rules_ignore_line not in content:
                    with open(gitignore_path, 'a') as f:
                        f.write(f"\n# Security rules (auto-added by NIMDA)\n{rules_ignore_line}\n")
                    logging.info("Added rules/ to .gitignore")
        except Exception as e:
            logging.warning(f"Failed to update .gitignore: {e}")

    def _create_rules_readme(self):
        """Create README file in rules folder"""
        readme_content = """# NIMDA Security Rules

This folder contains security rules downloaded from open sources.

⚠️ WARNING: These files should not be committed to git repositories due to possible 
false positive triggers in GitHub Secret Scanning.

## Files in this folder:
- emerging-all.rules: Emerging Threats rules
- custom-rules.rules: Custom rules (created manually)

## Updating rules:
```bash
python core/rule_manager.py
```

Or via GUI: Security → Update Rules
"""
        
        readme_path = os.path.join(self.rules_dir, 'README.md')
        try:
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(readme_content)
            logging.info(f"Created README at {readme_path}")
        except Exception as e:
            logging.error(f"Failed to create README: {e}")

if __name__ == '__main__':
    # Example usage
    manager = OptimizedRuleManager()
    
    # Try to download rules
    print("Updating rules...")
    success_count = manager.update_all_rules()
    print(f"Successfully downloaded {success_count} rule sets.")
    
    # Compile rules and show performance
    rules = manager.compile_rules()
    print(f"Total rules compiled: {len(rules)}")
    print(f"Compilation time: {manager.rule_stats['compile_time']:.4f} seconds")
    
    # Test rule matching
    test_text = "ALERT: Suspicious connection from 192.168.1.1 to example.com"
    matching_rules = manager.match_rules(test_text)
    print(f"\nMatching rules for test text: {len(matching_rules)}")
    for i, rule in enumerate(matching_rules[:3]):
        print(f"{i+1}: SID={rule['sid']}, MSG='{rule['message']}'")
        
    print(f"\nAverage match time: {manager.rule_stats['match_time_avg']*1000:.2f} ms")
