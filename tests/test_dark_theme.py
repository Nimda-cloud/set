#!/usr/bin/env python3
"""
Test script for NIMDA Dark Theme
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_dark_theme():
    """Test dark theme components"""
    print("🌙 Testing NIMDA Dark Theme")
    print("=" * 40)
    
    # Create test window
    root = tk.Tk()
    root.title("Dark Theme Test")
    root.geometry("800x600")
    root.configure(bg='#1a1a1a')
    
    # Configure dark theme
    style = ttk.Style()
    style.theme_use('clam')
    
    # Dark theme colors
    bg_color = '#1a1a1a'
    fg_color = '#ffffff'
    accent_color = '#2d2d2d'
    highlight_color = '#007acc'
    
    # Configure styles
    style.configure('TFrame', background=bg_color)
    style.configure('TLabel', background=bg_color, foreground=fg_color)
    style.configure('TButton', 
                   background=accent_color, 
                   foreground=fg_color,
                   borderwidth=1,
                   focuscolor=highlight_color)
    style.map('TButton',
             background=[('active', highlight_color), ('pressed', accent_color)],
             foreground=[('active', fg_color), ('pressed', fg_color)])
    
    style.configure('TNotebook', background=bg_color, borderwidth=0)
    style.configure('TNotebook.Tab', 
                   background=accent_color, 
                   foreground=fg_color,
                   padding=[10, 5],
                   borderwidth=1)
    style.map('TNotebook.Tab',
             background=[('selected', highlight_color), ('active', accent_color)],
             foreground=[('selected', fg_color), ('active', fg_color)])
    
    style.configure('Treeview', 
                   background=accent_color, 
                   foreground=fg_color,
                   fieldbackground=accent_color,
                   borderwidth=1)
    style.configure('Treeview.Heading', 
                   background=bg_color, 
                   foreground=fg_color,
                   borderwidth=1)
    
    style.configure('TEntry', 
                   fieldbackground=accent_color, 
                   foreground=fg_color,
                   borderwidth=1,
                   insertcolor=fg_color)
    
    style.configure('TLabelframe', 
                   background=bg_color, 
                   foreground=fg_color,
                   borderwidth=1)
    style.configure('TLabelframe.Label', 
                   background=bg_color, 
                   foreground=fg_color)
    
    # Configure tk widgets
    root.option_add('*Text.background', accent_color)
    root.option_add('*Text.foreground', fg_color)
    root.option_add('*Text.insertBackground', fg_color)
    root.option_add('*Text.selectBackground', highlight_color)
    
    root.option_add('*Entry.background', accent_color)
    root.option_add('*Entry.foreground', fg_color)
    root.option_add('*Entry.insertBackground', fg_color)
    root.option_add('*Entry.selectBackground', highlight_color)
    
    # Create notebook
    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True, padx=10, pady=10)
    
    # Test tab 1: Buttons and Labels
    tab1 = ttk.Frame(notebook)
    notebook.add(tab1, text="🎨 UI Elements")
    
    frame1 = ttk.LabelFrame(tab1, text="Dark Theme Test", padding=10)
    frame1.pack(fill='x', padx=10, pady=5)
    
    ttk.Label(frame1, text="This is a test of the dark theme").pack(anchor='w')
    ttk.Button(frame1, text="Test Button").pack(anchor='w', pady=5)
    ttk.Entry(frame1, width=30).pack(anchor='w', pady=5)
    
    # Test tab 2: Treeview
    tab2 = ttk.Frame(notebook)
    notebook.add(tab2, text="📊 Treeview")
    
    frame2 = ttk.LabelFrame(tab2, text="Treeview Test", padding=10)
    frame2.pack(fill='both', expand=True, padx=10, pady=5)
    
    tree = ttk.Treeview(frame2, columns=('col1', 'col2', 'col3'), show='headings')
    tree.heading('col1', text='Column 1')
    tree.heading('col2', text='Column 2')
    tree.heading('col3', text='Column 3')
    
    tree.insert('', 'end', values=('Row 1', 'Data 1', 'Info 1'))
    tree.insert('', 'end', values=('Row 2', 'Data 2', 'Info 2'))
    tree.insert('', 'end', values=('Row 3', 'Data 3', 'Info 3'))
    
    tree.pack(fill='both', expand=True)
    
    # Test tab 3: Text Widgets
    tab3 = ttk.Frame(notebook)
    notebook.add(tab3, text="📝 Text Widgets")
    
    frame3 = ttk.LabelFrame(tab3, text="Text Widget Test", padding=10)
    frame3.pack(fill='both', expand=True, padx=10, pady=5)
    
    text_widget = scrolledtext.ScrolledText(frame3, height=15, wrap='word')
    text_widget.pack(fill='both', expand=True)
    
    # Apply dark theme to text widget
    text_widget.configure(
        background=accent_color,
        foreground=fg_color,
        insertbackground=fg_color,
        selectbackground=highlight_color,
        selectforeground=fg_color
    )
    
    text_widget.insert('1.0', """Dark Theme Test

This is a test of the dark theme for text widgets.

Features tested:
• Background color: Dark gray (#2d2d2d)
• Text color: White (#ffffff)
• Selection color: Blue (#007acc)
• Cursor color: White (#ffffff)

The dark theme provides:
• Better eye comfort in low-light conditions
• Professional appearance
• Consistent color scheme
• High contrast for readability

All UI elements should now have a dark appearance!""")
    
    # Status bar
    status_bar = ttk.Label(root, text="Dark theme test ready", relief='sunken', anchor='w')
    status_bar.pack(side='bottom', fill='x')
    status_bar.configure(background=accent_color, foreground=fg_color)
    
    print("✅ Dark theme test window created")
    print("🎨 Features tested:")
    print("  • Dark background (#1a1a1a)")
    print("  • Light text (#ffffff)")
    print("  • Accent colors (#2d2d2d)")
    print("  • Highlight colors (#007acc)")
    print("  • All UI components styled")
    
    # Start the test
    root.mainloop()

if __name__ == "__main__":
    test_dark_theme() 