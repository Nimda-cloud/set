#!/usr/bin/env python3
"""
Test script for AI providers and task scheduler
"""

import sys
import os
import time
from datetime import datetime, timedelta

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ai_providers import AIProviderManager, OllamaProvider, GeminiProvider, GroqProvider, MistralProvider
from task_scheduler import TaskScheduler, TaskType, ScheduleType, ScheduledTask

def test_ai_providers():
    """Test AI providers functionality"""
    print("=== Testing AI Providers ===")
    
    # Create provider manager
    manager = AIProviderManager()
    
    print(f"\n1. Available providers: {list(manager.providers.keys())}")
    
    # Test provider status
    print("\n2. Provider status:")
    status = manager.get_provider_status()
    for name, info in status.items():
        print(f"   {name}: {'Available' if info['available'] else 'Unavailable'}")
        if info['models']:
            print(f"     Models: {', '.join(info['models'][:3])}")
    
    # Test active provider
    active_provider = manager.get_active_provider()
    if active_provider:
        print(f"\n3. Active provider: {active_provider.name}")
        
        # Test query
        test_prompt = "Hello, this is a test. Please respond with 'OK' if you can see this message."
        print(f"\n4. Testing query with {active_provider.name}:")
        response = manager.query(test_prompt)
        print(f"   Response: {response[:200]}...")
    else:
        print("\n3. No active provider available")
    
    # Test provider switching
    available_providers = manager.get_available_providers()
    if len(available_providers) > 1:
        print(f"\n5. Testing provider switching:")
        for provider_name in available_providers[:2]:  # Test first 2 providers
            if manager.set_active_provider(provider_name):
                print(f"   Switched to {provider_name}")
                response = manager.query("Quick test")
                print(f"   Response: {response[:100]}...")
            else:
                print(f"   Failed to switch to {provider_name}")

def test_task_scheduler():
    """Test task scheduler functionality"""
    print("\n=== Testing Task Scheduler ===")
    
    # Create scheduler
    scheduler = TaskScheduler()
    
    # Register test functions
    def test_function(**kwargs):
        print(f"Test function executed at {datetime.now()}")
        return "Test completed"
    
    scheduler.register_function("test_function", test_function)
    
    # Create test tasks
    print("\n1. Creating test tasks:")
    
    # Task 1: Run once in 1 minute
    task1 = ScheduledTask(
        id="test_once",
        name="Test Once Task",
        task_type=TaskType.CUSTOM,
        schedule_type=ScheduleType.ONCE,
        schedule_params={"datetime": (datetime.now() + timedelta(minutes=1)).isoformat()},
        function_name="test_function",
        function_params={},
        description="Test task that runs once"
    )
    
    # Task 2: Run every 2 minutes
    task2 = ScheduledTask(
        id="test_recurring",
        name="Test Recurring Task",
        task_type=TaskType.CUSTOM,
        schedule_type=ScheduleType.MINUTES,
        schedule_params={"minutes": 2},
        function_name="test_function",
        function_params={},
        description="Test task that runs every 2 minutes"
    )
    
    # Add tasks
    scheduler.add_task(task1)
    scheduler.add_task(task2)
    
    print(f"   Created {len(scheduler.get_tasks())} tasks")
    
    # List tasks
    print("\n2. Current tasks:")
    for task in scheduler.get_tasks():
        print(f"   {task.name}: {task.schedule_type.value} - Next run: {task.next_run}")
    
    # Test task execution
    print("\n3. Testing immediate task execution:")
    result = scheduler.run_task_now(task1.id)
    print(f"   Result: {result}")
    
    # Start scheduler for a short time
    print("\n4. Starting scheduler for 10 seconds...")
    scheduler.start()
    time.sleep(10)
    scheduler.stop()
    
    print("\n5. Task execution history:")
    for task in scheduler.get_tasks():
        print(f"   {task.name}: Last run: {task.last_run}")

def test_quick_tasks():
    """Test quick task creation"""
    print("\n=== Testing Quick Task Creation ===")
    
    scheduler = TaskScheduler()
    
    # Test quick task creation methods
    print("\n1. Creating quick tasks:")
    
    # Security scan task
    scan_task = scheduler.create_security_scan_task(
        "Quick Security Scan",
        ScheduleType.MINUTES,
        {"minutes": 5},
        "Quick security scan every 5 minutes"
    )
    scheduler.add_task(scan_task)
    print(f"   Created: {scan_task.name}")
    
    # Network analysis task
    net_task = scheduler.create_network_analysis_task(
        "Quick Network Analysis",
        ScheduleType.HOURLY,
        {"hours": 1},
        "Network analysis every hour"
    )
    scheduler.add_task(net_task)
    print(f"   Created: {net_task.name}")
    
    # AI analysis task
    ai_task = scheduler.create_ai_analysis_task(
        "Quick AI Analysis",
        ScheduleType.DAILY,
        {"hour": 6, "minute": 0},
        "Daily AI analysis at 6 AM",
        "Analyze system security status"
    )
    scheduler.add_task(ai_task)
    print(f"   Created: {ai_task.name}")
    
    print(f"\n2. Total tasks: {len(scheduler.get_tasks())}")
    
    # List all tasks
    print("\n3. All tasks:")
    for task in scheduler.get_tasks():
        print(f"   {task.name}: {task.task_type.value} - {task.schedule_type.value}")

if __name__ == "__main__":
    test_ai_providers()
    test_task_scheduler()
    test_quick_tasks()
    print("\n=== All Tests Completed ===") 