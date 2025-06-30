#!/usr/bin/env python3
"""
Enhanced NIMDA-Mac GUI with Human-in-the-Loop AI Integration
Покращений GUI з інтеграцією ШІ та людським контролем
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import subprocess
import os
import sys
from datetime import datetime
from typing import Dict, Optional, Any
import psutil

# Додаємо шлях до корневої директорії
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.threat_analyzer import ThreatAnalyzer
from llm_security_agent import LLMSecurityAgent
from security_monitor import SecurityMonitor

class AIAssistantTab:
    """
    Вкладка ШІ-помічника з Human-in-the-Loop функціональністю
    """
    
    def __init__(self, parent_notebook, threat_analyzer: ThreatAnalyzer):
        self.parent = parent_notebook
        self.threat_analyzer = threat_analyzer
        self.llm_agent = LLMSecurityAgent()
        
        # Створюємо вкладку
        self.frame = ttk.Frame(parent_notebook)
        parent_notebook.add(self.frame, text="🤖 AI Assistant")
        
        self.create_ai_assistant_interface()
        
    def create_ai_assistant_interface(self):
        """Створює інтерфейс ШІ-помічника"""
        
        # Основний контейнер
        main_frame = ttk.Frame(self.frame)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Секція статусу ШІ
        status_frame = ttk.LabelFrame(main_frame, text="🔌 AI Status")
        status_frame.pack(fill="x", pady=(0, 10))
        
        self.ai_status_label = ttk.Label(status_frame, text="Перевірка з'єднання...")
        self.ai_status_label.pack(pady=5)
        
        # Кнопка оновлення статусу
        ttk.Button(status_frame, text="Оновити статус", 
                  command=self.update_ai_status).pack(pady=5)
        
        # Секція аналізу процесів
        process_frame = ttk.LabelFrame(main_frame, text="🔍 Process Analysis")
        process_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Список процесів
        self.create_process_list(process_frame)
        
        # Секція ШІ рекомендацій
        ai_frame = ttk.LabelFrame(process_frame, text="🧠 AI Recommendations")
        ai_frame.pack(fill="x", padx=5, pady=5)
        
        self.ai_suggestion_label = ttk.Label(ai_frame, text="Виберіть процес та натисніть 'Отримати рекомендацію'")
        self.ai_suggestion_label.pack(pady=5)
        
        # Поле для команди
        command_frame = ttk.Frame(ai_frame)
        command_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(command_frame, text="Рекомендована команда:").pack(anchor="w")
        self.ai_command_entry = ttk.Entry(command_frame, width=80, font=("Courier", 10))
        self.ai_command_entry.pack(fill="x", pady=2)
        
        # Кнопки управління
        button_frame = ttk.Frame(ai_frame)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(button_frame, text="🎯 Отримати рекомендацію", 
                  command=self.get_ai_suggestion).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="✅ Виконати команду", 
                  command=self.execute_ai_command).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="📋 Копіювати", 
                  command=self.copy_command).pack(side="left", padx=5)
        
        # Секція логів ШІ
        log_frame = ttk.LabelFrame(main_frame, text="📜 AI Analysis Log")
        log_frame.pack(fill="both", expand=True)
        
        self.ai_log = scrolledtext.ScrolledText(log_frame, height=10, font=("Courier", 9))
        self.ai_log.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Ініціалізуємо статус
        self.update_ai_status()
        
    def create_process_list(self, parent):
        """Створює список процесів"""
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Заголовок
        ttk.Label(list_frame, text="Активні процеси:").pack(anchor="w")
        
        # Treeview для процесів
        columns = ("PID", "Name", "User", "CPU%", "Memory%", "Status")
        self.processes_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=8)
        
        # Налаштування колонок
        for col in columns:
            self.processes_tree.heading(col, text=col)
            self.processes_tree.column(col, width=100)
        
        # Скролбар
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.processes_tree.yview)
        self.processes_tree.configure(yscrollcommand=scrollbar.set)
        
        # Пакування
        self.processes_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Кнопка оновлення процесів
        ttk.Button(list_frame, text="🔄 Оновити процеси", 
                  command=self.refresh_processes).pack(pady=5)
        
        # Завантажуємо процеси
        self.refresh_processes()
        
    def refresh_processes(self):
        """Оновлює список процесів"""
        try:
            # Очищуємо поточний список
            for item in self.processes_tree.get_children():
                self.processes_tree.delete(item)
            
            # Отримуємо процеси
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    info = proc.info
                    self.processes_tree.insert("", "end", values=(
                        info['pid'],
                        info['name'][:20],  # Обрізаємо довгі імена
                        info['username'][:15] if info['username'] else 'N/A',
                        f"{info['cpu_percent']:.1f}",
                        f"{info['memory_percent']:.1f}",
                        info['status']
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.log_ai_message(f"Помилка оновлення процесів: {e}", "ERROR")
    
    def get_selected_process_info(self) -> Optional[Dict[str, Any]]:
        """Отримує інформацію про вибраний процес"""
        try:
            selected_items = self.processes_tree.selection()
            if not selected_items:
                messagebox.showwarning("Попередження", "Будь ласка, виберіть процес зі списку.")
                return None
            
            item = self.processes_tree.item(selected_items[0])
            values = item['values']
            
            pid = int(values[0])
            name = values[1]
            user = values[2]
            
            # Отримуємо додаткову інформацію про процес
            try:
                proc = psutil.Process(pid)
                return {
                    'pid': pid,
                    'name': name,
                    'user': user,
                    'path': proc.exe() if hasattr(proc, 'exe') else 'N/A',
                    'cmdline': ' '.join(proc.cmdline()) if hasattr(proc, 'cmdline') else 'N/A',
                    'create_time': proc.create_time() if hasattr(proc, 'create_time') else 0
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return {
                    'pid': pid,
                    'name': name,
                    'user': user,
                    'path': 'N/A',
                    'cmdline': 'N/A',
                    'create_time': 0
                }
                
        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося отримати інформацію про процес: {e}")
            return None
    
    def get_ai_suggestion(self):
        """Отримує рекомендацію від ШІ для вибраного процесу"""
        process_info = self.get_selected_process_info()
        if not process_info:
            return
        
        self.ai_suggestion_label.config(text="🤔 Аналізую процес за допомогою ШІ...")
        self.ai_command_entry.delete(0, tk.END)
        
        # Запускаємо аналіз у відокремленому потоці
        thread = threading.Thread(target=self._perform_ai_analysis, args=(process_info,))
        thread.daemon = True
        thread.start()
    
    def _perform_ai_analysis(self, process_info: Dict[str, Any]):
        """Виконує ШІ аналіз у фоновому режимі"""
        try:
            # Логуємо початок аналізу
            self.log_ai_message(f"Початок аналізу процесу PID {process_info['pid']} ({process_info['name']})")
            
            # Використовуємо ThreatAnalyzer для аналізу
            analysis_result = self.threat_analyzer.analyze_process_activity(process_info)
            
            # Оновлюємо GUI в основному потоці
            self.frame.after(0, self._update_ai_results, process_info, analysis_result)
            
        except Exception as e:
            error_msg = f"Помилка ШІ аналізу: {e}"
            self.frame.after(0, self._handle_ai_error, error_msg)
    
    def _update_ai_results(self, process_info: Dict, analysis_result: Dict):
        """Оновлює результати ШІ аналізу в GUI"""
        try:
            threat_level = analysis_result.get('threat_level', 'info')
            suggested_commands = analysis_result.get('suggested_commands', [])
            
            # Оновлюємо статус
            level_emoji = {"info": "ℹ️", "medium": "⚠️", "high": "🚨", "critical": "🔥"}
            emoji = level_emoji.get(threat_level, "❓")
            
            self.ai_suggestion_label.config(
                text=f"{emoji} Рівень загрози: {threat_level.upper()} для PID {process_info['pid']}"
            )
            
            # Вставляємо першу рекомендовану команду
            if suggested_commands:
                self.ai_command_entry.delete(0, tk.END)
                self.ai_command_entry.insert(0, suggested_commands[0])
            
            # Логуємо результати
            self.log_ai_message(f"Аналіз завершено для PID {process_info['pid']}:")
            self.log_ai_message(f"  Рівень загрози: {threat_level}")
            
            if analysis_result.get('suspicious_indicators'):
                self.log_ai_message("  Підозрілі індикатори:")
                for indicator in analysis_result['suspicious_indicators']:
                    self.log_ai_message(f"    - {indicator}")
            
            if suggested_commands:
                self.log_ai_message("  Рекомендовані команди:")
                for i, cmd in enumerate(suggested_commands[:3], 1):
                    self.log_ai_message(f"    {i}. {cmd}")
            
            # ШІ аналіз
            ai_analysis = analysis_result.get('ai_analysis')
            if ai_analysis:
                self.log_ai_message(f"  ШІ аналіз: {ai_analysis.get('analysis', 'N/A')}")
                confidence = ai_analysis.get('confidence', 0)
                self.log_ai_message(f"  Впевненість: {confidence}%")
            
        except Exception as e:
            self._handle_ai_error(f"Помилка оновлення результатів: {e}")
    
    def _handle_ai_error(self, error_msg: str):
        """Обробляє помилки ШІ аналізу"""
        self.ai_suggestion_label.config(text="❌ Помилка отримання рекомендації")
        self.log_ai_message(error_msg, "ERROR")
        messagebox.showerror("Помилка ШІ", error_msg)
    
    def execute_ai_command(self):
        """Виконує рекомендовану ШІ команду після підтвердження користувача"""
        command = self.ai_command_entry.get().strip()
        if not command:
            messagebox.showwarning("Попередження", "Немає команди для виконання.")
            return
        
        # Підтвердження користувача
        result = messagebox.askyesno(
            "Підтвердження виконання", 
            f"Ви дійсно хочете виконати цю команду?\\n\\n{command}\\n\\n"
            "⚠️ УВАГА: Команда буде виконана з поточними привілеями!",
            icon="warning"
        )
        
        if not result:
            self.log_ai_message("Виконання команди скасовано користувачем")
            return
        
        # Виконуємо команду
        self.log_ai_message(f"Виконання команди: {command}")
        
        try:
            # Виконуємо в окремому потоці
            thread = threading.Thread(target=self._execute_command_thread, args=(command,))
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            error_msg = f"Помилка запуску команди: {e}"
            self.log_ai_message(error_msg, "ERROR")
            messagebox.showerror("Помилка", error_msg)
    
    def _execute_command_thread(self, command: str):
        """Виконує команду у фоновому потоці"""
        try:
            # Виконуємо команду
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            # Оновлюємо лог в основному потоці
            self.frame.after(0, self._update_command_result, command, result)
            
        except subprocess.TimeoutExpired:
            self.frame.after(0, self._handle_command_error, command, "Команда перевищила час очікування (30с)")
        except Exception as e:
            self.frame.after(0, self._handle_command_error, command, str(e))
    
    def _update_command_result(self, command: str, result):
        """Оновлює результат виконання команди"""
        self.log_ai_message(f"Команда завершена з кодом: {result.returncode}")
        
        if result.stdout:
            self.log_ai_message("STDOUT:")
            for line in result.stdout.splitlines()[:10]:  # Обмежуємо вивід
                self.log_ai_message(f"  {line}")
        
        if result.stderr:
            self.log_ai_message("STDERR:")
            for line in result.stderr.splitlines()[:5]:
                self.log_ai_message(f"  {line}")
        
        if result.returncode == 0:
            messagebox.showinfo("Успіх", "Команда виконана успішно!")
        else:
            messagebox.showwarning("Попередження", f"Команда завершилась з кодом {result.returncode}")
    
    def _handle_command_error(self, command: str, error: str):
        """Обробляє помилки виконання команди"""
        error_msg = f"Помилка виконання команди '{command}': {error}"
        self.log_ai_message(error_msg, "ERROR")
        messagebox.showerror("Помилка виконання", error_msg)
    
    def copy_command(self):
        """Копіює команду в буфер обміну"""
        command = self.ai_command_entry.get().strip()
        if command:
            self.frame.clipboard_clear()
            self.frame.clipboard_append(command)
            self.log_ai_message(f"Команду скопійовано: {command}")
            messagebox.showinfo("Скопійовано", "Команду скопійовано в буфер обміну!")
        else:
            messagebox.showwarning("Попередження", "Немає команди для копіювання.")
    
    def update_ai_status(self):
        """Оновлює статус ШІ з'єднання"""
        try:
            if self.llm_agent.check_ollama_connection():
                models = self.llm_agent.get_available_models()
                self.ai_status_label.config(
                    text=f"✅ Ollama підключено | Моделі: {', '.join(models[:2])}" if models else "✅ Ollama підключено",
                    foreground="green"
                )
            else:
                self.ai_status_label.config(
                    text="❌ Ollama недоступна | Перевірте, чи запущений сервіс",
                    foreground="red"
                )
        except Exception as e:
            self.ai_status_label.config(
                text=f"⚠️ Помилка перевірки статусу: {e}",
                foreground="orange"
            )
    
    def log_ai_message(self, message: str, level: str = "INFO"):
        """Додає повідомлення до логу ШІ"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {level}: {message}\\n"
        
        self.ai_log.insert(tk.END, formatted_message)
        self.ai_log.see(tk.END)  # Прокручуємо до кінця


class EnhancedNimdaGUI:
    """
    Покращений головний GUI з інтеграцією ШІ-помічника
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ NIMDA-Mac Security System v2.0")
        self.root.geometry("1200x800")
        
        # Ініціалізуємо компоненти
        self.threat_analyzer = ThreatAnalyzer()
        self.security_monitor = SecurityMonitor()
        self.monitoring_active = False
        
        self.create_main_interface()
        
    def create_main_interface(self):
        """Створює основний інтерфейс"""
        
        # Головне меню
        self.create_menu()
        
        # Панель статусу
        self.create_status_bar()
        
        # Основний notebook з вкладками
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Створюємо вкладки
        self.create_overview_tab()
        self.create_processes_tab()
        self.create_network_tab()
        self.create_logs_tab()
        
        # Вкладка ШІ-помічника
        self.ai_assistant = AIAssistantTab(self.notebook, self.threat_analyzer)
        
        self.create_settings_tab()
        
    def create_menu(self):
        """Створює головне меню"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Меню File
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Меню Security
        security_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Security", menu=security_menu)
        security_menu.add_command(label="Update Rules", command=self.update_security_rules)
        security_menu.add_command(label="Run Full Scan", command=self.run_full_scan)
        
        # Меню AI
        ai_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="AI", menu=ai_menu)
        ai_menu.add_command(label="Check AI Status", command=self.check_ai_status)
        ai_menu.add_command(label="Update AI Models", command=self.update_ai_models)
        
    def create_status_bar(self):
        """Створює панель статусу"""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(fill="x", side="bottom")
        
        self.status_label = ttk.Label(self.status_frame, text="🟢 Система готова")
        self.status_label.pack(side="left", padx=5)
        
        # Індикатор моніторингу
        self.monitoring_label = ttk.Label(self.status_frame, text="⏸️ Моніторинг зупинено")
        self.monitoring_label.pack(side="right", padx=5)
    
    def create_overview_tab(self):
        """Створює вкладку огляду"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📊 Overview")
        
        # Статистика загроз
        stats_frame = ttk.LabelFrame(frame, text="📈 Статистика загроз")
        stats_frame.pack(fill="x", padx=10, pady=10)
        
        self.threat_stats = ttk.Label(stats_frame, text="Завантаження статистики...")
        self.threat_stats.pack(pady=10)
        
        # Контроль моніторингу
        control_frame = ttk.LabelFrame(frame, text="🎛️ Контроль моніторингу")
        control_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(control_frame, text="▶️ Старт моніторингу", 
                  command=self.start_monitoring).pack(side="left", padx=5, pady=5)
        ttk.Button(control_frame, text="⏸️ Стоп моніторингу", 
                  command=self.stop_monitoring).pack(side="left", padx=5, pady=5)
        
    def create_processes_tab(self):
        """Створює вкладку процесів"""
        self.processes_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.processes_frame, text="⚙️ Processes")
        
        # Тут можна додати додатковий функціонал для процесів
        info_label = ttk.Label(self.processes_frame, 
                              text="Використовуйте вкладку 'AI Assistant' для аналізу процесів")
        info_label.pack(pady=20)
    
    def create_network_tab(self):
        """Створює вкладку мережі"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="🌐 Network")
        
        network_label = ttk.Label(frame, text="Мережевий моніторинг буде додано в наступних версіях")
        network_label.pack(pady=20)
    
    def create_logs_tab(self):
        """Створює вкладку логів"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="📜 Logs")
        
        self.logs_text = scrolledtext.ScrolledText(frame, height=20, font=("Courier", 9))
        self.logs_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def create_settings_tab(self):
        """Створює вкладку налаштувань"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="⚙️ Settings")
        
        settings_label = ttk.Label(frame, text="Налаштування системи")
        settings_label.pack(pady=20)
    
    # Методи управління
    def start_monitoring(self):
        """Запускає моніторинг"""
        self.monitoring_active = True
        self.monitoring_label.config(text="▶️ Моніторинг активний")
        self.status_label.config(text="🟢 Моніторинг запущено")
        self.log_message("Моніторинг безпеки запущено")
    
    def stop_monitoring(self):
        """Зупиняє моніторинг"""
        self.monitoring_active = False
        self.monitoring_label.config(text="⏸️ Моніторинг зупинено")
        self.status_label.config(text="🟡 Моніторинг зупинено")
        self.log_message("Моніторинг безпеки зупинено")
    
    def update_security_rules(self):
        """Оновлює правила безпеки"""
        self.status_label.config(text="🔄 Оновлення правил...")
        
        def update_thread():
            try:
                success_count = self.threat_analyzer.rule_manager.update_all_rules()
                self.root.after(0, lambda: self.status_label.config(
                    text=f"✅ Оновлено {success_count} наборів правил"
                ))
                self.root.after(0, lambda: self.log_message(f"Правила безпеки оновлено: {success_count} наборів"))
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda: self.status_label.config(text="❌ Помилка оновлення правил"))
                self.root.after(0, lambda: self.log_message(f"Помилка оновлення правил: {error_msg}"))
        
        thread = threading.Thread(target=update_thread)
        thread.daemon = True
        thread.start()
    
    def run_full_scan(self):
        """Запускає повне сканування"""
        self.status_label.config(text="🔍 Виконується повне сканування...")
        self.log_message("Розпочато повне сканування системи")
        # Тут буде логіка повного сканування
    
    def check_ai_status(self):
        """Перевіряє статус ШІ"""
        self.ai_assistant.update_ai_status()
    
    def update_ai_models(self):
        """Оновлює моделі ШІ"""
        messagebox.showinfo("Info", "Функція оновлення моделей ШІ буде додана в наступних версіях")
    
    def export_logs(self):
        """Експортує логи"""
        messagebox.showinfo("Info", "Функція експорту логів буде додана в наступних версіях")
    
    def log_message(self, message: str):
        """Додає повідомлення до логу"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\\n"
        self.logs_text.insert(tk.END, formatted_message)
        self.logs_text.see(tk.END)


def main():
    """Головна функція запуску GUI"""
    root = tk.Tk()
    _ = EnhancedNimdaGUI(root)  # Створюємо GUI, посилання не потрібно зберігати
    
    # Запускаємо GUI
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\\nЗавершення роботи...")


if __name__ == "__main__":
    main()
