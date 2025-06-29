#!/usr/bin/env python3
"""
Task Scheduler for NIMDA Security System
Supports scheduled and periodic security tasks
"""

import threading
import time
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from enum import Enum
import schedule

class TaskType(Enum):
    """Task types"""
    SECURITY_SCAN = "security_scan"
    NETWORK_ANALYSIS = "network_analysis"
    ANOMALY_DETECTION = "anomaly_detection"
    AI_ANALYSIS = "ai_analysis"
    SYSTEM_CHECK = "system_check"
    CUSTOM = "custom"

class ScheduleType(Enum):
    """Schedule types"""
    ONCE = "once"
    DAILY = "daily"
    HOURLY = "hourly"
    MINUTES = "minutes"
    WEEKLY = "weekly"
    CUSTOM = "custom"

@dataclass
class ScheduledTask:
    """Scheduled task definition"""
    id: str
    name: str
    task_type: TaskType
    schedule_type: ScheduleType
    schedule_params: Dict[str, Any]
    function_name: str
    function_params: Dict[str, Any]
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime = None
    description: str = ""
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.next_run is None:
            self.next_run = self.calculate_next_run()
    
    def calculate_next_run(self) -> datetime:
        """Calculate next run time based on schedule"""
        now = datetime.now()
        
        if self.schedule_type == ScheduleType.ONCE:
            # Parse specific datetime from schedule_params
            if "datetime" in self.schedule_params:
                return datetime.fromisoformat(self.schedule_params["datetime"])
            return now
            
        elif self.schedule_type == ScheduleType.DAILY:
            # Daily at specific time
            hour = self.schedule_params.get("hour", 0)
            minute = self.schedule_params.get("minute", 0)
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run
            
        elif self.schedule_type == ScheduleType.HOURLY:
            # Every N hours
            hours = self.schedule_params.get("hours", 1)
            return now + timedelta(hours=hours)
            
        elif self.schedule_type == ScheduleType.MINUTES:
            # Every N minutes
            minutes = self.schedule_params.get("minutes", 5)
            return now + timedelta(minutes=minutes)
            
        elif self.schedule_type == ScheduleType.WEEKLY:
            # Weekly on specific day and time
            weekday = self.schedule_params.get("weekday", 0)  # Monday = 0
            hour = self.schedule_params.get("hour", 0)
            minute = self.schedule_params.get("minute", 0)
            
            days_ahead = weekday - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            next_run = now + timedelta(days=days_ahead)
            next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)
            return next_run
            
        return now
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        data = asdict(self)
        data["task_type"] = self.task_type.value
        data["schedule_type"] = self.schedule_type.value
        data["last_run"] = self.last_run.isoformat() if self.last_run else None
        data["next_run"] = self.next_run.isoformat() if self.next_run else None
        data["created_at"] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScheduledTask':
        """Create from dictionary"""
        data["task_type"] = TaskType(data["task_type"])
        data["schedule_type"] = ScheduleType(data["schedule_type"])
        if data["last_run"]:
            data["last_run"] = datetime.fromisoformat(data["last_run"])
        if data["next_run"]:
            data["next_run"] = datetime.fromisoformat(data["next_run"])
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        return cls(**data)

class TaskScheduler:
    """Task scheduler for security operations"""
    
    def __init__(self, db_path: str = "scheduled_tasks.db"):
        self.db_path = db_path
        self.tasks: Dict[str, ScheduledTask] = {}
        self.running = False
        self.scheduler_thread = None
        self.callback_functions: Dict[str, Callable] = {}
        self.init_database()
        self.load_tasks()
        
    def init_database(self):
        """Initialize database for task storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                task_type TEXT NOT NULL,
                schedule_type TEXT NOT NULL,
                schedule_params TEXT NOT NULL,
                function_name TEXT NOT NULL,
                function_params TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                last_run TEXT,
                next_run TEXT,
                created_at TEXT NOT NULL,
                description TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_tasks(self):
        """Load tasks from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM scheduled_tasks")
        rows = cursor.fetchall()
        
        for row in rows:
            task_data = {
                "id": row[0],
                "name": row[1],
                "task_type": row[2],
                "schedule_type": row[3],
                "schedule_params": json.loads(row[4]),
                "function_name": row[5],
                "function_params": json.loads(row[6]),
                "enabled": bool(row[7]),
                "last_run": row[8],
                "next_run": row[9],
                "created_at": row[10],
                "description": row[11] or ""
            }
            
            task = ScheduledTask.from_dict(task_data)
            self.tasks[task.id] = task
        
        conn.close()
    
    def save_task(self, task: ScheduledTask):
        """Save task to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO scheduled_tasks 
            (id, name, task_type, schedule_type, schedule_params, function_name, 
             function_params, enabled, last_run, next_run, created_at, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            task.id,
            task.name,
            task.task_type.value,
            task.schedule_type.value,
            json.dumps(task.schedule_params),
            task.function_name,
            json.dumps(task.function_params),
            1 if task.enabled else 0,
            task.last_run.isoformat() if task.last_run else None,
            task.next_run.isoformat() if task.next_run else None,
            task.created_at.isoformat(),
            task.description
        ))
        
        conn.commit()
        conn.close()
    
    def delete_task(self, task_id: str):
        """Delete task from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM scheduled_tasks WHERE id = ?", (task_id,))
        conn.commit()
        conn.close()
        
        if task_id in self.tasks:
            del self.tasks[task_id]
    
    def register_function(self, name: str, func: Callable):
        """Register a function that can be called by tasks"""
        self.callback_functions[name] = func
    
    def add_task(self, task: ScheduledTask) -> bool:
        """Add a new scheduled task"""
        try:
            self.tasks[task.id] = task
            self.save_task(task)
            return True
        except Exception as e:
            print(f"Error adding task: {e}")
            return False
    
    def create_security_scan_task(self, name: str, schedule_type: ScheduleType, 
                                 schedule_params: Dict, description: str = "") -> ScheduledTask:
        """Create a security scan task"""
        task = ScheduledTask(
            id=f"security_scan_{int(time.time())}",
            name=name,
            task_type=TaskType.SECURITY_SCAN,
            schedule_type=schedule_type,
            schedule_params=schedule_params,
            function_name="full_security_scan",
            function_params={},
            description=description
        )
        return task
    
    def create_network_analysis_task(self, name: str, schedule_type: ScheduleType,
                                   schedule_params: Dict, description: str = "") -> ScheduledTask:
        """Create a network analysis task"""
        task = ScheduledTask(
            id=f"network_analysis_{int(time.time())}",
            name=name,
            task_type=TaskType.NETWORK_ANALYSIS,
            schedule_type=schedule_type,
            schedule_params=schedule_params,
            function_name="analyze_network",
            function_params={},
            description=description
        )
        return task
    
    def create_ai_analysis_task(self, name: str, schedule_type: ScheduleType,
                              schedule_params: Dict, prompt: str, description: str = "") -> ScheduledTask:
        """Create an AI analysis task"""
        task = ScheduledTask(
            id=f"ai_analysis_{int(time.time())}",
            name=name,
            task_type=TaskType.AI_ANALYSIS,
            schedule_type=schedule_type,
            schedule_params=schedule_params,
            function_name="ai_analysis",
            function_params={"prompt": prompt},
            description=description
        )
        return task
    
    def execute_task(self, task: ScheduledTask):
        """Execute a scheduled task"""
        try:
            if task.function_name in self.callback_functions:
                func = self.callback_functions[task.function_name]
                result = func(**task.function_params)
                
                # Update task execution time
                task.last_run = datetime.now()
                task.next_run = task.calculate_next_run()
                self.save_task(task)
                
                print(f"Task '{task.name}' executed successfully at {task.last_run}")
                return result
            else:
                print(f"Function '{task.function_name}' not found for task '{task.name}'")
                return None
        except Exception as e:
            print(f"Error executing task '{task.name}': {e}")
            return None
    
    def check_and_execute_tasks(self):
        """Check for tasks that need to be executed"""
        now = datetime.now()
        
        for task in self.tasks.values():
            if not task.enabled:
                continue
                
            if task.next_run and task.next_run <= now:
                self.execute_task(task)
    
    def start(self):
        """Start the scheduler"""
        if self.running:
            return
            
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        print("Task scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()
        print("Task scheduler stopped")
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                self.check_and_execute_tasks()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                print(f"Scheduler error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def get_tasks(self) -> List[ScheduledTask]:
        """Get all tasks"""
        return list(self.tasks.values())
    
    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        """Get specific task"""
        return self.tasks.get(task_id)
    
    def enable_task(self, task_id: str):
        """Enable a task"""
        if task_id in self.tasks:
            self.tasks[task_id].enabled = True
            self.save_task(self.tasks[task_id])
    
    def disable_task(self, task_id: str):
        """Disable a task"""
        if task_id in self.tasks:
            self.tasks[task_id].enabled = False
            self.save_task(self.tasks[task_id])
    
    def run_task_now(self, task_id: str):
        """Run a task immediately"""
        if task_id in self.tasks:
            return self.execute_task(self.tasks[task_id])
        return None 