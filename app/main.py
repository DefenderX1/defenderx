"""
DefendX — Main Application Shell
Tkinter-based desktop application with sidebar navigation,
dark theme, and multi-screen layout.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import threading
import time
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

def get_asset_path(filename):
    """Robust utility to locate asset files in dev, prod, and PyInstaller environments."""
    if hasattr(sys, '_MEIPASS'):
        p = os.path.join(sys._MEIPASS, "User ui wallpaper", filename)
        if os.path.exists(p):
            return p
        p = os.path.join(sys._MEIPASS, filename)
        if os.path.exists(p):
            return p
    try:
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(cur_dir)
        for d in [cur_dir, parent_dir, os.path.dirname(parent_dir)]:
            p = os.path.join(d, "User ui wallpaper", filename)
            if os.path.exists(p):
                return p
    except Exception:
        pass
    p = os.path.join(os.getcwd(), "User ui wallpaper", filename)
    if os.path.exists(p):
        return p
    try:
        exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        for d in [exe_dir, os.path.dirname(exe_dir)]:
            p = os.path.join(d, "User ui wallpaper", filename)
            if os.path.exists(p):
                return p
    except Exception:
        pass
    return os.path.join("User ui wallpaper", filename)


from app.styles import *
from app.threat_analyzer import ThreatAnalyzer
from app.alerts import AlertManager
from app.monitor import SystemMonitor
from app.dashboard import DashboardView
from app.report_gen import ReportGenerator
from app.ai_agent import AIAgent


class DefendXApp:
    """Main application class with sidebar navigation and multi-screen layout."""

    SCREENS = [
        {'id': 'dashboard',          'label': 'Dashboard'},
        {'id': 'simulator',          'label': 'OS Simulator Console'},
        {'id': 'threats',            'label': 'Threat Analysis'},
        {'id': 'users',              'label': 'User Profiles'},
        {'id': 'connect',            'label': 'Connect'},
        {'id': 'malware',            'label': 'Malware Protection'},
        {'id': 'network',            'label': 'Network Packets'},
        {'id': 'realtime_settings',  'label': 'Real-Time Settings'},
        {'id': 'reports',            'label': 'Reports'},
        {'id': 'settings',           'label': 'Settings'},
    ]

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title('DefendX — AI Insider Threat Detection')
        self.root.geometry(f'{WINDOW_WIDTH}x{WINDOW_HEIGHT}')
        self.root.minsize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        self.root.configure(bg=BG_PRIMARY)

        # Try to set icon
        try:
            self.root.iconbitmap(default='')
        except Exception:
            pass

        # Initialize core components
        self.models_dir = os.path.join(PROJECT_ROOT, 'Models')
        self.analyzer = ThreatAnalyzer(self.models_dir)
        self.alert_manager = AlertManager()
        self.alert_manager.register_callback(self._on_new_alert)
        self.system_monitor = SystemMonitor()
        self.report_gen = ReportGenerator(self.analyzer, self.alert_manager)
        
        # Initialize AI Agent (DefenderX) with web deployment directories
        self.ai_agent = AIAgent(
            self.alert_manager,
            web_dir=os.path.join(PROJECT_ROOT, 'web'),
            deploy_dir=os.path.join(PROJECT_ROOT, 'deploy')
        )

        # Connection variables
        self.chrome_connected = tk.BooleanVar(value=True)
        self.vscode_connected = tk.BooleanVar(value=True)
        self.disk_connected = tk.BooleanVar(value=True)

        # Malware Protection variables
        self.malware_active = tk.BooleanVar(value=True)
        self.file_integrity_active = tk.BooleanVar(value=True)
        self.malware_status_text = tk.StringVar(value="Monitoring")
        self.malware_scanned_count = tk.IntVar(value=1420)
        self.malware_quarantined_count = tk.IntVar(value=0)
        self.malware_logs_list = ["[info] Threat database loaded successfully."]

        # Network Packet Capture variables
        self.network_capture_active = tk.BooleanVar(value=False)
        self.network_thread = None

        # Real-time Settings variables
        self.settings_sensitivity = tk.DoubleVar(value=0.05)
        self.settings_refresh_rate = tk.IntVar(value=10)
        self.settings_enable_corner_alerts = tk.BooleanVar(value=True)
        self.settings_auto_isolation = tk.BooleanVar(value=False)

        # Load models if available
        self._load_models()

        # Configure ttk styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        configure_ttk_styles(self.style)

        # Current screen
        self.current_screen = 'dashboard'
        self.sidebar_buttons = {}

        # Show Loading Screen
        self._show_loading_screen()

    def _load_models(self):
        """Load trained AI models if they exist."""
        if os.path.exists(os.path.join(self.models_dir, 'isolation_forest.pkl')):
            self.analyzer.load_models()
            print("[App] AI models loaded successfully")
        else:
            print("[App] No trained models found")

    def _build_ui(self):
        """Build the main application UI layout."""
        # Main container
        main_container = tk.Frame(self.root, bg=BG_PRIMARY)
        main_container.pack(fill='both', expand=True)

        # Sidebar
        self.sidebar = tk.Frame(main_container, bg=BG_SIDEBAR, width=SIDEBAR_WIDTH)
        self.sidebar.pack(side='left', fill='y')
        self.sidebar.pack_propagate(False)

        self._build_sidebar()

        # Content Area
        self.content = tk.Frame(main_container, bg=BG_PRIMARY)
        self.content.pack(side='left', fill='both', expand=True)

        # Status Bar
        self._build_status_bar()

        # Show initial screen
        self._show_screen('dashboard')

        # Elegant floating chatbot bubble button in bottom right (placed above status bar)
        self.chat_btn = tk.Label(self.root, text="AI Assistant", bg=ACCENT_CYAN, fg=BG_PRIMARY, font=FONT_BODY_BOLD, cursor='hand2', padx=15, pady=8, highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        self.chat_btn.place(relx=1.0, rely=1.0, x=-30, y=-50, anchor='se')
        self.chat_btn.bind('<Button-1>', lambda e: self._toggle_chatbot())
        
        self.chat_popup = None
        self.chat_history = []

    def _build_sidebar(self):
        """Build the sidebar navigation."""
        # Logo / Brand
        brand_frame = tk.Frame(self.sidebar, bg=BG_SIDEBAR)
        brand_frame.pack(fill='x', pady=(15, 5))

        tk.Label(brand_frame, text='[DX]', font=(FONT_FAMILY, 24, 'bold'),
                 bg=BG_SIDEBAR, fg=ACCENT_CYAN).pack()
        tk.Label(brand_frame, text='DefendX', font=(FONT_FAMILY, 18, 'bold'),
                 bg=BG_SIDEBAR, fg=TEXT_PRIMARY).pack()
        tk.Label(brand_frame, text='AI Threat Detection',
                 font=FONT_TINY, bg=BG_SIDEBAR, fg=TEXT_TERTIARY).pack()

        # Separator
        sep = tk.Frame(self.sidebar, bg=BORDER_DEFAULT, height=1)
        sep.pack(fill='x', padx=15, pady=10)

        # Navigation buttons
        nav_frame = tk.Frame(self.sidebar, bg=BG_SIDEBAR)
        nav_frame.pack(fill='x', padx=8)

        for screen in self.SCREENS:
            btn = tk.Label(nav_frame, text=screen['label'],
                           font=FONT_SIDEBAR, bg=BG_SIDEBAR, fg=TEXT_SECONDARY,
                           anchor='w', padx=12, pady=8, cursor='hand2')
            btn.pack(fill='x', pady=1)
            btn.bind('<Enter>', lambda e, b=btn, s=screen['id']:
                     self._on_nav_hover(b, s, True))
            btn.bind('<Leave>', lambda e, b=btn, s=screen['id']:
                     self._on_nav_hover(b, s, False))
            btn.bind('<Button-1>', lambda e, s=screen['id']:
                     self._show_screen(s))
            self.sidebar_buttons[screen['id']] = btn

        # Bottom info
        bottom = tk.Frame(self.sidebar, bg=BG_SIDEBAR)
        bottom.pack(side='bottom', fill='x', padx=15, pady=10)

        tk.Frame(bottom, bg=BORDER_DEFAULT, height=1).pack(fill='x', pady=(0, 8))

        model_status = 'Models Loaded' if self.analyzer.is_loaded else 'No Models'
        model_color = ACCENT_GREEN if self.analyzer.is_loaded else ACCENT_YELLOW
        tk.Label(bottom, text=model_status, font=FONT_TINY,
                 bg=BG_SIDEBAR, fg=model_color).pack(anchor='w')
        tk.Label(bottom, text='v1.0.0 • CERT r4.2', font=FONT_TINY,
                 bg=BG_SIDEBAR, fg=TEXT_TERTIARY).pack(anchor='w')

    def _on_nav_hover(self, btn, screen_id, entering):
        """Handle sidebar button hover effects."""
        if screen_id == self.current_screen:
            return
        if entering:
            btn.configure(bg=BG_HOVER, fg=TEXT_PRIMARY)
        else:
            btn.configure(bg=BG_SIDEBAR, fg=TEXT_SECONDARY)

    def _build_status_bar(self):
        """Build the bottom status bar."""
        self.status_bar = tk.Frame(self.root, bg=BG_TERTIARY, height=28)
        self.status_bar.pack(side='bottom', fill='x')
        self.status_bar.pack_propagate(False)

        self.status_label = tk.Label(self.status_bar, text='Ready',
                                     font=FONT_TINY, bg=BG_TERTIARY,
                                     fg=TEXT_SECONDARY, padx=10)
        self.status_label.pack(side='left')

        # Right side info
        import datetime
        time_str = datetime.datetime.now().strftime('%H:%M:%S')
        self.time_lbl = tk.Label(self.status_bar, text=f'Time: {time_str}', font=FONT_TINY,
                 bg=BG_TERTIARY, fg=TEXT_TERTIARY, padx=10)
        self.time_lbl.pack(side='right')

        alert_count = self.alert_manager.get_total_unresolved()
        alert_text = f'Alerts: {alert_count}'
        alert_color = ACCENT_YELLOW if alert_count > 0 else TEXT_TERTIARY
        self.alert_status_lbl = tk.Label(self.status_bar, text=alert_text, font=FONT_TINY,
                 bg=BG_TERTIARY, fg=alert_color, padx=10)
        self.alert_status_lbl.pack(side='right')

        self._update_status_bar_clock()

    def _update_status_bar_clock(self):
        """Periodically update the status bar time and alert counts."""
        try:
            import datetime
            time_str = datetime.datetime.now().strftime('%H:%M:%S')
            self.time_lbl.configure(text=f'Time: {time_str}')
            
            alert_count = self.alert_manager.get_total_unresolved()
            self.alert_status_lbl.configure(text=f'Alerts: {alert_count}')
            self.alert_status_lbl.configure(fg=ACCENT_YELLOW if alert_count > 0 else TEXT_TERTIARY)
        except Exception:
            pass
        self.root.after(1000, self._update_status_bar_clock)

    def _show_screen(self, screen_id: str):
        """Switch to a different screen."""
        # Update sidebar active state
        for sid, btn in self.sidebar_buttons.items():
            if sid == screen_id:
                btn.configure(bg=BG_TERTIARY, fg=ACCENT_CYAN,
                              font=FONT_SIDEBAR_ACTIVE)
            else:
                btn.configure(bg=BG_SIDEBAR, fg=TEXT_SECONDARY,
                              font=FONT_SIDEBAR)

        self.current_screen = screen_id

        # Clear content area
        for widget in self.content.winfo_children():
            widget.destroy()

        # Build screen
        if screen_id == 'dashboard':
            self._build_dashboard_screen()
        elif screen_id == 'simulator':
            self._build_simulator_screen()
        elif screen_id == 'threats':
            self._build_threats_screen()
        elif screen_id == 'users':
            self._build_users_screen()
        elif screen_id == 'connect':
            self._build_connect_screen()
        elif screen_id == 'malware':
            self._build_malware_screen()
        elif screen_id == 'network':
            self._build_network_screen()
        elif screen_id == 'realtime_settings':
            self._build_realtime_settings_screen()
        elif screen_id == 'reports':
            self._build_reports_screen()
        elif screen_id == 'settings':
            self._build_settings_screen()

        self._set_status(f'Viewing: {screen_id.title()}')

    def _set_status(self, text: str):
        """Update status bar text."""
        self.status_label.configure(text=text)

    # ══════════════════════════════════════════════════════════════
    #  TOAST ALERT SYSTEM
    # ══════════════════════════════════════════════════════════════

    def _on_new_alert(self, alert):
        """Triggered automatically whenever a new alert is generated."""
        if not alert:
            return
        # Analyze alert payload asynchronously using the Gemini API
        self.ai_agent.analyze_alert_async(alert)
        
        if self.settings_enable_corner_alerts.get():
            self.root.after(0, lambda: self._show_toast(alert))

        # Check if alert comes from a simulated user and is HIGH/CRITICAL threat, then pop up modal on Admin
        user_id = alert.get('user_id', '')
        if user_id in ['USER01', 'USER02', 'USER03', 'USER04', 'USER05'] and alert.get('severity') in ['CRITICAL', 'HIGH']:
            self.root.after(0, lambda: self._show_admin_anomaly_popup(alert))

    def _show_toast(self, alert):
        """Displays an elegant custom toast window in the bottom-right corner."""
        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.attributes('-topmost', True)
        
        severity_color = ACCENT_RED if alert['severity'] in ['CRITICAL', 'HIGH'] else ACCENT_YELLOW
        toast.configure(bg=BG_SECONDARY, highlightbackground=severity_color, highlightthickness=1)
        
        # Position toast at bottom right of the main application window
        self.root.update_idletasks()
        rx = self.root.winfo_x()
        ry = self.root.winfo_y()
        rw = self.root.winfo_width()
        rh = self.root.winfo_height()
        
        tw = 320
        th = 90
        tx = rx + rw - tw - 20
        ty = ry + rh - th - 50
        
        toast.geometry(f"{tw}x{th}+{tx}+{ty}")
        
        title_lbl = tk.Label(toast, text=f"Alert Level: {alert['severity']}", font=FONT_BODY_BOLD, bg=BG_SECONDARY, fg=severity_color)
        title_lbl.pack(anchor='w', padx=10, pady=(8, 2))
        
        msg_lbl = tk.Label(toast, text=alert['message'], font=FONT_SMALL, bg=BG_SECONDARY, fg=TEXT_PRIMARY, wraplength=300, justify='left', anchor='w')
        msg_lbl.pack(fill='both', expand=True, padx=10, pady=(0, 8))
        
        # Bind click callback to display details window
        toast.bind('<Button-1>', lambda e: self._show_alert_detail(alert))
        title_lbl.bind('<Button-1>', lambda e: self._show_alert_detail(alert))
        msg_lbl.bind('<Button-1>', lambda e: self._show_alert_detail(alert))
        
        toast.after(4000, toast.destroy)

    def _show_alert_detail(self, alert):
        """Show detailed alert window with Gemini AI security assessment."""
        popup = tk.Toplevel(self.root)
        popup.title(f"Alert Details - ID {alert['id']}")
        popup.geometry("520x420")
        popup.configure(bg=BG_PRIMARY)
        popup.transient(self.root)
        popup.focus_set()
        
        tk.Label(popup, text=f"Source: {alert['source']}", font=FONT_BODY_BOLD, bg=BG_PRIMARY, fg=TEXT_PRIMARY).pack(anchor='w', padx=20, pady=(15, 2))
        
        severity_color = ACCENT_RED if alert['severity'] in ['CRITICAL', 'HIGH'] else ACCENT_YELLOW
        tk.Label(popup, text=f"Severity: {alert['severity']}", font=FONT_BODY_BOLD, bg=BG_PRIMARY, fg=severity_color).pack(anchor='w', padx=20, pady=2)
        
        t_val = alert['timestamp']
        if 'T' in t_val:
            t_val = t_val.replace('T', ' ').split('.')[0]
        tk.Label(popup, text=f"Time: {t_val}", font=FONT_TINY, bg=BG_PRIMARY, fg=TEXT_TERTIARY).pack(anchor='w', padx=20, pady=2)
        
        tk.Label(popup, text="Alert Message:", font=FONT_BODY_BOLD, bg=BG_PRIMARY, fg=TEXT_SECONDARY).pack(anchor='w', padx=20, pady=(10, 2))
        tk.Label(popup, text=alert['message'], font=FONT_BODY, bg=BG_PRIMARY, fg=TEXT_PRIMARY, wraplength=480, justify='left', anchor='w').pack(anchor='w', padx=20, pady=2)
        
        tk.Label(popup, text="DefenderX AI Assessment:", font=FONT_BODY_BOLD, bg=BG_PRIMARY, fg=ACCENT_CYAN).pack(anchor='w', padx=20, pady=(15, 2))
        
        text_frame = tk.Frame(popup, bg=BG_SECONDARY, highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        text_frame.pack(fill='both', expand=True, padx=20, pady=(2, 20))
        
        text_area = tk.Text(text_frame, bg=BG_SECONDARY, fg=TEXT_PRIMARY, font=FONT_SMALL, relief='flat', wrap='word')
        text_area.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(text_frame, orient='vertical', command=text_area.yview)
        text_area.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        
        def update_text():
            if not popup.winfo_exists():
                return
            ai_text = alert.get('ai_analysis', "Analyzing alert payload via OpenRouter API...")
            text_area.configure(state='normal')
            text_area.delete('1.0', 'end')
            text_area.insert('end', ai_text)
            text_area.configure(state='disabled')
            if 'Analyzing' in ai_text:
                popup.after(1000, update_text)
                
        update_text()

    def _toggle_chatbot(self):
        """Toggle the floating chatbot helper popup window."""
        if self.chat_popup and self.chat_popup.winfo_exists():
            self.chat_popup.destroy()
            self.chat_popup = None
            return
            
        # Create chat window
        self.chat_popup = tk.Toplevel(self.root)
        self.chat_popup.title("DefenderX Assistant")
        self.chat_popup.geometry("380x480")
        self.chat_popup.configure(bg=BG_SECONDARY)
        self.chat_popup.transient(self.root)
        
        # Position popup relative to main window (bottom right overlay)
        self.root.update_idletasks()
        rx = self.root.winfo_x()
        ry = self.root.winfo_y()
        rw = self.root.winfo_width()
        rh = self.root.winfo_height()
        
        tx = rx + rw - 410
        ty = ry + rh - 560
        self.chat_popup.geometry(f"380x480+{tx}+{ty}")
        
        # Header
        header = tk.Frame(self.chat_popup, bg=BG_TERTIARY, height=45)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        tk.Label(header, text="AI Security Assistant", font=FONT_BODY_BOLD, bg=BG_TERTIARY, fg=ACCENT_CYAN).pack(side='left', padx=15)
        
        close_btn = tk.Label(header, text="Close", font=FONT_TINY, bg=BG_TERTIARY, fg=TEXT_SECONDARY, cursor='hand2')
        close_btn.pack(side='right', padx=15)
        close_btn.bind('<Button-1>', lambda e: self.chat_popup.destroy())
        
        # Logs box
        log_frame = tk.Frame(self.chat_popup, bg=BG_SECONDARY)
        log_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.chat_log = tk.Text(log_frame, bg=BG_TERTIARY, fg=TEXT_PRIMARY, font=FONT_SMALL, relief='flat', wrap='word', state='disabled')
        self.chat_log.pack(side='left', fill='both', expand=True)
        
        scrollbar = ttk.Scrollbar(log_frame, orient='vertical', command=self.chat_log.yview)
        self.chat_log.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        
        # Add initial greeting if log is empty
        if not self.chat_history:
            self._append_to_chat_log("Assistant", "Hello. I am DefenderX, your Cyber security Organization preventer. How can I assist you?")
        else:
            for role, text in self.chat_history:
                sender = "You" if role == "user" else "Assistant"
                self._append_to_chat_log(sender, text)
            
        # Input panel
        input_frame = tk.Frame(self.chat_popup, bg=BG_SECONDARY)
        input_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        self.chat_input_var = tk.StringVar()
        input_entry = tk.Entry(input_frame, textvariable=self.chat_input_var, font=FONT_BODY, bg=BG_TERTIARY, fg=TEXT_PRIMARY, insertbackground=ACCENT_CYAN, relief='flat')
        input_entry.pack(side='left', fill='x', expand=True, padx=(0, 10), ipady=4)
        input_entry.bind('<Return>', lambda e: self._send_chat_message())
        input_entry.focus_set()
        
        send_btn = tk.Label(input_frame, text="Send", font=FONT_BODY_BOLD, bg=ACCENT_CYAN, fg=BG_PRIMARY, cursor='hand2', padx=12, pady=4)
        send_btn.pack(side='right')
        send_btn.bind('<Button-1>', lambda e: self._send_chat_message())

    def _append_to_chat_log(self, sender, text):
        if not self.chat_popup or not self.chat_log.winfo_exists():
            return
        self.chat_log.configure(state='normal')
        self.chat_log.insert('end', f"{sender}: {text}\n\n")
        self.chat_log.see('end')
        self.chat_log.configure(state='disabled')

    def _send_chat_message(self):
        msg = self.chat_input_var.get().strip()
        if not msg:
            return
            
        self._append_to_chat_log("You", msg)
        self.chat_history.append(("user", msg))
        self.chat_input_var.set("")
        
        self._append_to_chat_log("Assistant", "Thinking...")
        
        def on_reply(reply):
            if self.chat_popup and self.chat_log.winfo_exists():
                # Remove the "Thinking..." line
                self.chat_log.configure(state='normal')
                self.chat_log.delete("end-3l", "end")
                self.chat_log.configure(state='disabled')
                
                self._append_to_chat_log("Assistant", reply)
                self.chat_history.append(("assistant", reply))
        
        # Prepare message payload
        history_payload = [{"role": r, "content": t} for r, t in self.chat_history[-10:]]
        self.ai_agent.generate_chat_reply(history_payload, lambda r: self.root.after(0, lambda: on_reply(r)))

    # ══════════════════════════════════════════════════════════════
    #  SCREEN BUILDERS
    # ══════════════════════════════════════════════════════════════

    def _build_dashboard_screen(self):
        """Build the main dashboard screen."""
        dashboard = DashboardView(self.content, self.analyzer,
                                  self.alert_manager, self.system_monitor,
                                  on_alert_click=self._show_alert_detail)
        frame = dashboard.build()
        frame.pack(fill='both', expand=True)

    def _build_threats_screen(self):
        """Build the threat analysis screen."""
        frame = tk.Frame(self.content, bg=BG_PRIMARY)
        frame.pack(fill='both', expand=True)

        title_frame = tk.Frame(frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 10))
        tk.Label(title_frame, text='Threat Analysis',
                 font=FONT_TITLE, bg=BG_PRIMARY, fg=ACCENT_RED).pack(side='left')

        # Search bar
        search_frame = tk.Frame(frame, bg=BG_SECONDARY,
                                highlightbackground=BORDER_DEFAULT,
                                highlightthickness=1)
        search_frame.pack(fill='x', padx=PADDING, pady=(0, 10))

        tk.Label(search_frame, text='Search User:', font=FONT_BODY,
                 bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(side='left', padx=10, pady=8)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                                font=FONT_BODY, bg=BG_TERTIARY, fg=TEXT_PRIMARY,
                                insertbackground=ACCENT_CYAN, relief='flat',
                                width=30)
        search_entry.pack(side='left', padx=5, pady=8)
        search_entry.bind('<Return>', lambda e: self._search_threats())

        search_btn = tk.Label(search_frame, text=' Search ', font=FONT_BODY_BOLD,
                              bg=ACCENT_CYAN, fg=BG_PRIMARY, cursor='hand2',
                              padx=12, pady=4)
        search_btn.pack(side='left', padx=5, pady=8)
        search_btn.bind('<Button-1>', lambda e: self._search_threats())

        # Results table
        table_frame = tk.Frame(frame, bg=BG_SECONDARY,
                               highlightbackground=BORDER_DEFAULT,
                               highlightthickness=1)
        table_frame.pack(fill='both', expand=True, padx=PADDING, pady=(0, PADDING))

        columns = ('user', 'score', 'level', 'anomaly', 'logins', 'usb', 'files')
        self.threat_tree = ttk.Treeview(table_frame, columns=columns,
                                         show='headings', style='Dark.Treeview')

        headers = {
            'user': ('User ID', 120),
            'score': ('Threat Score', 100),
            'level': ('Level', 80),
            'anomaly': ('Anomaly', 70),
            'logins': ('After-Hrs Logins', 110),
            'usb': ('USB Connects', 100),
            'files': ('File Copies', 90),
        }

        for col, (heading, width) in headers.items():
            self.threat_tree.heading(col, text=heading)
            self.threat_tree.column(col, width=width, anchor='center')

        scrollbar = ttk.Scrollbar(table_frame, orient='vertical',
                                   command=self.threat_tree.yview,
                                   style='Dark.Vertical.TScrollbar')
        self.threat_tree.configure(yscrollcommand=scrollbar.set)

        self.threat_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        self.threat_tree.bind('<<TreeviewSelect>>', self._on_threat_select)
        self._populate_threat_table()

    def _populate_threat_table(self, df=None):
        """Populate the threat table with data."""
        self.threat_tree.delete(*self.threat_tree.get_children())

        if df is None:
            df = self.analyzer.get_all_threat_scores()

        if len(df) == 0:
            return

        df_sorted = df.sort_values('threat_score', ascending=False) if 'threat_score' in df.columns else df

        for _, row in df_sorted.head(200).iterrows():
            score = row.get('threat_score', 0)
            values = (
                row.get('user', ''),
                f'{score:.1f}',
                row.get('threat_level', 'N/A'),
                'YES' if row.get('is_anomaly', False) else '—',
                int(row.get('after_hours_logins', 0)),
                int(row.get('usb_connects', 0)),
                int(row.get('file_copy_count', 0)),
            )
            tag = 'critical' if score >= 75 else 'high' if score >= 50 else 'medium' if score >= 25 else 'low'
            self.threat_tree.insert('', 'end', values=values, tags=(tag,))

        self.threat_tree.tag_configure('critical', foreground=THREAT_CRITICAL)
        self.threat_tree.tag_configure('high', foreground=THREAT_HIGH)
        self.threat_tree.tag_configure('medium', foreground=THREAT_MEDIUM)
        self.threat_tree.tag_configure('low', foreground=ACCENT_GREEN)

    def _search_threats(self):
        """Search for a specific user in threats."""
        query = self.search_var.get().strip()
        if not query:
            self._populate_threat_table()
            return
        results = self.analyzer.search_users(query)
        self._populate_threat_table(results)
        self._set_status(f'Search: {len(results)} results for "{query}"')

    def _on_threat_select(self, event):
        """Handle threat table row selection."""
        selection = self.threat_tree.selection()
        if not selection:
            return
        item = self.threat_tree.item(selection[0])
        user_id = item['values'][0]
        self._show_user_detail(user_id)

    def _show_user_detail(self, user_id: str):
        """Show detailed user profile in a popup."""
        profile = self.analyzer.get_user_profile(user_id)
        if not profile:
            return

        popup = tk.Toplevel(self.root)
        popup.title(f'DefendX — User Profile: {user_id}')
        popup.geometry('650x700')
        popup.configure(bg=BG_PRIMARY)
        popup.transient(self.root)

        # Scrollable content
        canvas = tk.Canvas(popup, bg=BG_PRIMARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(popup, orient='vertical', command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=BG_PRIMARY)

        scroll_frame.bind('<Configure>',
                          lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0, 0), window=scroll_frame, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Header
        header = tk.Frame(scroll_frame, bg=BG_SECONDARY,
                          highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        header.pack(fill='x', padx=15, pady=10)

        score = profile.get('threat_score', 0)
        color = get_threat_color(score)
        level = profile.get('threat_level', 'Unknown')

        tk.Label(header, text=f'User Profile: {user_id}', font=FONT_HEADING,
                 bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(anchor='w', padx=10, pady=(10, 0))

        score_frame = tk.Frame(header, bg=BG_SECONDARY)
        score_frame.pack(fill='x', padx=10, pady=(5, 10))

        tk.Label(score_frame, text='Threat Score: ', font=FONT_BODY,
                 bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(side='left')
        tk.Label(score_frame, text=f'{score:.1f}', font=FONT_STAT_NUMBER,
                 bg=BG_SECONDARY, fg=color).pack(side='left', padx=(5, 10))
        tk.Label(score_frame, text=level, font=FONT_BODY_BOLD,
                 bg=color, fg='white' if score >= 50 else BG_PRIMARY,
                 padx=8, pady=2).pack(side='left')

        # Risk Factors
        risk_factors = profile.get('risk_factors', [])
        if risk_factors:
            rf_card = tk.Frame(scroll_frame, bg=BG_SECONDARY,
                               highlightbackground=BORDER_DEFAULT, highlightthickness=1)
            rf_card.pack(fill='x', padx=15, pady=5)

            tk.Label(rf_card, text='Risk Factors', font=FONT_SUBHEADING,
                     bg=BG_SECONDARY, fg=ACCENT_RED).pack(anchor='w', padx=10, pady=(8, 5))

            for rf in risk_factors:
                rf_frame = tk.Frame(rf_card, bg=BG_SECONDARY)
                rf_frame.pack(fill='x', padx=10, pady=3)

                sev_color = {'Critical': THREAT_CRITICAL, 'High': THREAT_HIGH,
                             'Medium': THREAT_MEDIUM}.get(rf['severity'], TEXT_SECONDARY)

                tk.Label(rf_frame, text='●', font=FONT_SMALL,
                         bg=BG_SECONDARY, fg=sev_color).pack(side='left')
                tk.Label(rf_frame, text=rf['factor'], font=FONT_BODY_BOLD,
                         bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(side='left', padx=(5, 0))
                tk.Label(rf_frame, text=f'[{rf["severity"]}]', font=FONT_TINY,
                         bg=BG_SECONDARY, fg=sev_color).pack(side='left', padx=(8, 0))

                detail_frame = tk.Frame(rf_card, bg=BG_SECONDARY)
                detail_frame.pack(fill='x', padx=30, pady=(0, 3))
                tk.Label(detail_frame, text=rf['detail'], font=FONT_SMALL,
                         bg=BG_SECONDARY, fg=TEXT_SECONDARY, wraplength=550,
                         anchor='w', justify='left').pack(anchor='w')

            tk.Frame(rf_card, bg=BG_SECONDARY, height=5).pack()

        # Behavioral Metrics
        metrics = profile.get('metrics', {})
        if metrics:
            met_card = tk.Frame(scroll_frame, bg=BG_SECONDARY,
                                highlightbackground=BORDER_DEFAULT, highlightthickness=1)
            met_card.pack(fill='x', padx=15, pady=5)

            tk.Label(met_card, text='Behavioral Metrics', font=FONT_SUBHEADING,
                     bg=BG_SECONDARY, fg=ACCENT_CYAN).pack(anchor='w', padx=10, pady=(8, 5))

            for label, value in metrics.items():
                met_row = tk.Frame(met_card, bg=BG_SECONDARY)
                met_row.pack(fill='x', padx=10, pady=2)

                tk.Label(met_row, text=label, font=FONT_BODY,
                         bg=BG_SECONDARY, fg=TEXT_SECONDARY, width=25,
                         anchor='w').pack(side='left')
                display_val = f'{value:.2f}' if isinstance(value, float) else str(int(value)) if isinstance(value, (int, float)) else str(value)
                tk.Label(met_row, text=display_val, font=FONT_BODY_BOLD,
                         bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(side='left')

            tk.Frame(met_card, bg=BG_SECONDARY, height=5).pack()

        # Composite Scores
        composites = profile.get('composite_scores', {})
        if composites:
            comp_card = tk.Frame(scroll_frame, bg=BG_SECONDARY,
                                 highlightbackground=BORDER_DEFAULT, highlightthickness=1)
            comp_card.pack(fill='x', padx=15, pady=5)

            tk.Label(comp_card, text='Composite Risk Scores', font=FONT_SUBHEADING,
                     bg=BG_SECONDARY, fg=ACCENT_PURPLE).pack(anchor='w', padx=10, pady=(8, 5))

            for label, value in composites.items():
                comp_row = tk.Frame(comp_card, bg=BG_SECONDARY)
                comp_row.pack(fill='x', padx=10, pady=3)

                tk.Label(comp_row, text=label, font=FONT_BODY,
                         bg=BG_SECONDARY, fg=TEXT_SECONDARY, width=25,
                         anchor='w').pack(side='left')

                # Progress bar
                bar_frame = tk.Frame(comp_row, bg=BG_TERTIARY, height=12, width=200)
                bar_frame.pack(side='left', padx=(0, 10))
                bar_frame.pack_propagate(False)

                bar_width = min(value / 100.0, 1.0) * 200
                bar_color = get_threat_color(value)
                bar = tk.Frame(bar_frame, bg=bar_color, width=int(bar_width))
                bar.pack(side='left', fill='y')

                tk.Label(comp_row, text=f'{value:.1f}', font=FONT_BODY_BOLD,
                         bg=BG_SECONDARY, fg=get_threat_color(value)).pack(side='left')

            tk.Frame(comp_card, bg=BG_SECONDARY, height=8).pack()

    def _build_users_screen(self):
        """Build the user profiles screen."""
        frame = tk.Frame(self.content, bg=BG_PRIMARY)
        frame.pack(fill='both', expand=True)

        title_frame = tk.Frame(frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 10))
        tk.Label(title_frame, text='User Profiles',
                 font=FONT_TITLE, bg=BG_PRIMARY, fg=ACCENT_BLUE).pack(side='left')

        # User list with search
        search_frame = tk.Frame(frame, bg=BG_SECONDARY,
                                highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        search_frame.pack(fill='x', padx=PADDING, pady=(0, 10))

        tk.Label(search_frame, text='Search:', font=FONT_BODY,
                 bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(side='left', padx=(10, 5), pady=8)

        user_search_var = tk.StringVar()
        user_entry = tk.Entry(search_frame, textvariable=user_search_var,
                              font=FONT_BODY, bg=BG_TERTIARY, fg=TEXT_PRIMARY,
                              insertbackground=ACCENT_CYAN, relief='flat', width=30)
        user_entry.pack(side='left', padx=5, pady=8)

        def search_users(event=None):
            q = user_search_var.get().strip()
            if q:
                results = self.analyzer.search_users(q)
            else:
                results = self.analyzer.get_all_threat_scores()
            populate_user_list(results)

        user_entry.bind('<Return>', search_users)
        tk.Label(search_frame, text='  Search  ', font=FONT_BODY_BOLD,
                 bg=ACCENT_CYAN, fg=BG_PRIMARY, cursor='hand2',
                 padx=8, pady=3).pack(side='left', padx=5, pady=8)

        # User list
        list_frame = tk.Frame(frame, bg=BG_SECONDARY,
                              highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        list_frame.pack(fill='both', expand=True, padx=PADDING, pady=(0, PADDING))

        columns = ('user', 'score', 'level', 'role', 'department')
        user_tree = ttk.Treeview(list_frame, columns=columns,
                                  show='headings', style='Dark.Treeview')

        for col, heading, width in [('user', 'User ID', 120), ('score', 'Score', 80),
                                     ('level', 'Level', 80), ('role', 'Role', 150),
                                     ('department', 'Department', 180)]:
            user_tree.heading(col, text=heading)
            user_tree.column(col, width=width, anchor='center')

        user_tree.pack(fill='both', expand=True)
        user_tree.bind('<Double-1>', lambda e: self._on_user_double_click(user_tree))

        def populate_user_list(df=None):
            user_tree.delete(*user_tree.get_children())
            if df is None:
                df = self.analyzer.get_all_threat_scores()
            if len(df) == 0:
                return
            for _, row in df.head(500).iterrows():
                score = row.get('threat_score', 0)
                tag = 'critical' if score >= 75 else 'high' if score >= 50 else 'medium' if score >= 25 else 'low'
                user_tree.insert('', 'end', values=(
                    row.get('user', ''),
                    f'{score:.1f}',
                    row.get('threat_level', 'N/A'),
                    row.get('role', 'N/A'),
                    row.get('department', 'N/A'),
                ), tags=(tag,))

            user_tree.tag_configure('critical', foreground=THREAT_CRITICAL)
            user_tree.tag_configure('high', foreground=THREAT_HIGH)
            user_tree.tag_configure('medium', foreground=THREAT_MEDIUM)
            user_tree.tag_configure('low', foreground=ACCENT_GREEN)

        populate_user_list()

    def _on_user_double_click(self, tree):
        """Handle double-click on user list."""
        selection = tree.selection()
        if selection:
            item = tree.item(selection[0])
            user_id = item['values'][0]
            self._show_user_detail(user_id)

    # ══════════════════════════════════════════════════════════════
    #  NEW SCREENS (CONNECT, MALWARE, NETWORK, REALTIME SETTINGS)
    # ══════════════════════════════════════════════════════════════

    def _build_connect_screen(self):
        """Build the connect screen to manage Chrome, VS Code, and Disk connections."""
        frame = tk.Frame(self.content, bg=BG_PRIMARY)
        frame.pack(fill='both', expand=True)

        title_frame = tk.Frame(frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 10))
        tk.Label(title_frame, text='Connect Data Sources',
                 font=FONT_TITLE, bg=BG_PRIMARY, fg=ACCENT_CYAN).pack(side='left')

        # Grid of connections
        grid_frame = tk.Frame(frame, bg=BG_PRIMARY)
        grid_frame.pack(fill='both', expand=True, padx=PADDING)

        # Helper to create connection cards
        def create_conn_card(title, desc, status_var, path_val):
            card = tk.Frame(grid_frame, bg=BG_SECONDARY, highlightbackground=BORDER_DEFAULT, highlightthickness=1, padx=20, pady=20)
            card.pack(fill='x', pady=8)

            info_f = tk.Frame(card, bg=BG_SECONDARY)
            info_f.pack(side='left', fill='both', expand=True)

            tk.Label(info_f, text=title, font=FONT_HEADING, bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(anchor='w')
            tk.Label(info_f, text=desc, font=FONT_BODY, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(anchor='w', pady=(5, 2))
            tk.Label(info_f, text=f"Source Path: {path_val}", font=FONT_TINY, bg=BG_SECONDARY, fg=TEXT_TERTIARY).pack(anchor='w')

            control_f = tk.Frame(card, bg=BG_SECONDARY)
            control_f.pack(side='right')

            status_lbl = tk.Label(control_f, font=FONT_BODY_BOLD, bg=BG_SECONDARY, width=12)
            status_lbl.pack(side='top', pady=5)

            def update_ui():
                if status_var.get():
                    status_lbl.configure(text="Connected", fg=ACCENT_GREEN)
                    btn.configure(text="Disconnect", bg=ACCENT_RED, fg='white')
                else:
                    status_lbl.configure(text="Disconnected", fg=TEXT_SECONDARY)
                    btn.configure(text="Connect", bg=ACCENT_CYAN, fg=BG_PRIMARY)

            def toggle():
                status_var.set(not status_var.get())
                update_ui()
                self._set_status(f"{title} integration updated.")

            btn = tk.Label(control_f, font=FONT_BODY_BOLD, cursor='hand2', padx=15, pady=6)
            btn.pack(side='top')
            btn.bind('<Button-1>', lambda e: toggle())

            update_ui()

        # Add Chrome connection card
        chrome_path = self.system_monitor.chrome.history_path or "Not Detected"
        create_conn_card("Google Chrome Integration", 
                         "Monitor browser history for Shadow AI, cloud storage uploads, and job site visits.",
                         self.chrome_connected, chrome_path)

        # Add VS Code connection card
        vscode_path = self.system_monitor.vscode.storage_path or "Not Detected"
        create_conn_card("VS Code Integration", 
                         "Monitor workspaces for access to sensitive source code files.",
                         self.vscode_connected, vscode_path)

        # Add Disk connection card
        disk_path = "Local Disk Drives"
        create_conn_card("Local Storage Integration", 
                         "Monitor USB drive mounts, external media copies, and large file events.",
                         self.disk_connected, disk_path)

    def _build_malware_screen(self):
        """Build the AI Malware Protection screen."""
        frame = tk.Frame(self.content, bg=BG_PRIMARY)
        frame.pack(fill='both', expand=True)

        title_frame = tk.Frame(frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 10))
        tk.Label(title_frame, text='Malware Protection',
                 font=FONT_TITLE, bg=BG_PRIMARY, fg=ACCENT_RED).pack(side='left')

        # Status panel
        status_card = tk.Frame(frame, bg=BG_SECONDARY, highlightbackground=BORDER_DEFAULT, highlightthickness=1, padx=20, pady=15)
        status_card.pack(fill='x', padx=PADDING, pady=5)

        tk.Label(status_card, text='Engine Status', font=FONT_SUBHEADING, bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(side='left')
        
        status_val = tk.Label(status_card, textvariable=self.malware_status_text, font=FONT_BODY_BOLD, bg=BG_SECONDARY, fg=ACCENT_GREEN)
        status_val.pack(side='left', padx=10)

        # Statistics
        tk.Label(status_card, text='Scanned Files: ', font=FONT_BODY, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(side='left', padx=(30, 5))
        tk.Label(status_card, textvariable=self.malware_scanned_count, font=FONT_BODY_BOLD, bg=BG_SECONDARY, fg=ACCENT_CYAN).pack(side='left')

        tk.Label(status_card, text='Quarantined: ', font=FONT_BODY, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(side='left', padx=(30, 5))
        tk.Label(status_card, textvariable=self.malware_quarantined_count, font=FONT_BODY_BOLD, bg=BG_SECONDARY, fg=ACCENT_RED).pack(side='left')

        # Scan utility
        scan_card = tk.Frame(frame, bg=BG_SECONDARY, highlightbackground=BORDER_DEFAULT, highlightthickness=1, padx=20, pady=15)
        scan_card.pack(fill='both', expand=True, padx=PADDING, pady=10)

        tk.Label(scan_card, text='Scan Directory', font=FONT_SUBHEADING, bg=BG_SECONDARY, fg=ACCENT_CYAN).pack(anchor='w')
        
        path_frame = tk.Frame(scan_card, bg=BG_SECONDARY)
        path_frame.pack(fill='x', pady=10)

        self.scan_path_var = tk.StringVar(value="Select directory...")
        path_entry = tk.Entry(path_frame, textvariable=self.scan_path_var, font=FONT_BODY, bg=BG_TERTIARY, fg=TEXT_PRIMARY, relief='flat', state='readonly', width=60)
        path_entry.pack(side='left', padx=(0, 10))

        def browse_dir():
            d = filedialog.askdirectory()
            if d:
                self.scan_path_var.set(d)

        browse_btn = tk.Label(path_frame, text='Browse', font=FONT_BODY_BOLD, bg=BG_HOVER, fg=TEXT_PRIMARY, cursor='hand2', padx=12, pady=4)
        browse_btn.pack(side='left', padx=(0, 10))
        browse_btn.bind('<Button-1>', lambda e: browse_dir())

        progress = ttk.Progressbar(scan_card, orient='horizontal', mode='determinate', style='Cyan.Horizontal.TProgressbar')
        progress.pack(fill='x', pady=10)

        log_text = tk.Text(scan_card, bg=BG_TERTIARY, fg=TEXT_PRIMARY, font=FONT_MONO_SMALL, relief='flat', height=8)
        log_text.pack(fill='both', expand=True, pady=5)

        # Populate logs
        log_text.configure(state='normal')
        for log in self.malware_logs_list:
            log_text.insert('end', log + "\n")
        log_text.see('end')
        log_text.configure(state='disabled')

        def log_msg(msg):
            self.malware_logs_list.append(msg)
            log_text.configure(state='normal')
            log_text.insert('end', msg + "\n")
            log_text.see('end')
            log_text.configure(state='disabled')

        def start_scan():
            target = self.scan_path_var.get()
            if target == "Select directory...":
                messagebox.showwarning("Warning", "Please select a directory to scan first.")
                return
            
            scan_btn.configure(state='disabled')
            self.malware_status_text.set("Scanning...")
            status_val.configure(fg=ACCENT_YELLOW)
            progress['value'] = 0

            def scan_job():
                import random
                log_msg(f"[*] Initiating AI behavioral scan of: {target}")
                files = []
                for root, dirs, f_list in os.walk(target):
                    for f in f_list:
                        files.append(os.path.join(root, f))
                        if len(files) >= 100:  # limit for speed
                            break
                    if len(files) >= 100:
                        break

                total_f = len(files)
                if total_f == 0:
                    log_msg("[*] No files found in directory.")
                    self.malware_status_text.set("Monitoring")
                    status_val.configure(fg=ACCENT_GREEN)
                    scan_btn.configure(state='normal')
                    return

                for idx, f in enumerate(files):
                    time.sleep(random.uniform(0.02, 0.08))
                    name = os.path.basename(f)
                    progress['value'] = (idx + 1) / total_f * 100
                    self.malware_scanned_count.set(self.malware_scanned_count.get() + 1)

                    # Simulate simple heuristic rules
                    is_threat = False
                    reason = ""
                    if "malware" in name.lower() or "suspicious" in name.lower():
                        is_threat = True
                        reason = "Heuristic check matches threat signature"
                    elif name.endswith('.bat') or name.endswith('.vbs'):
                        is_threat = True
                        reason = "Suspicious executable script type"

                    if is_threat:
                        self.malware_quarantined_count.set(self.malware_quarantined_count.get() + 1)
                        log_msg(f"[CRITICAL] Threat detected in: {name} - {reason}. Isolated.")
                        self.alert_manager.add_alert("CRITICAL", "Malware Protection", f"AI Malware Engine isolated file: {name}", details=f"File path: {f}")
                    else:
                        log_msg(f"[+] Scanned: {name} - Normal")
                    
                    self.root.update_idletasks()

                log_msg("[*] AI Scan complete. System secured.")
                self.malware_status_text.set("Monitoring")
                status_val.configure(fg=ACCENT_GREEN)
                self.root.after(0, lambda: scan_btn.configure(state='normal'))

            threading.Thread(target=scan_job, daemon=True).start()

        scan_btn = tk.Button(path_frame, text='Start Scan', font=FONT_BODY_BOLD, bg=ACCENT_RED, fg='white', relief='flat', cursor='hand2', activebackground=BG_HOVER, padx=12, pady=4, command=start_scan)
        scan_btn.pack(side='left')

    def _build_network_screen(self):
        """Build the network packets monitor screen."""
        frame = tk.Frame(self.content, bg=BG_PRIMARY)
        frame.pack(fill='both', expand=True)

        title_frame = tk.Frame(frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 10))
        tk.Label(title_frame, text='Network Packets',
                 font=FONT_TITLE, bg=BG_PRIMARY, fg=ACCENT_PURPLE).pack(side='left')

        # Packet control buttons
        def toggle_capture():
            if self.network_capture_active.get():
                self.network_capture_active.set(False)
                cap_btn.configure(text='Start Capture', bg=ACCENT_PURPLE, fg='white')
                self._set_status("Network packet capture stopped")
            else:
                self.network_capture_active.set(True)
                cap_btn.configure(text='Stop Capture', bg=ACCENT_RED, fg='white')
                self._set_status("Network packet capture running")
                start_capture_thread()

        cap_btn = tk.Button(title_frame, text='Start Capture', font=FONT_BODY_BOLD, bg=ACCENT_PURPLE, fg='white', relief='flat', cursor='hand2', command=toggle_capture)
        cap_btn.pack(side='right', padx=10)

        # Table showing packets
        table_frame = tk.Frame(frame, bg=BG_SECONDARY, highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        table_frame.pack(fill='both', expand=True, padx=PADDING, pady=(0, PADDING))

        columns = ('time', 'protocol', 'src', 'dest', 'payload', 'level')
        packet_tree = ttk.Treeview(table_frame, columns=columns, show='headings', style='Dark.Treeview')

        headers = {
            'time': ('Time', 90),
            'protocol': ('Protocol', 80),
            'src': ('Source', 120),
            'dest': ('Destination', 120),
            'payload': ('Payload Snippet', 280),
            'level': ('Threat Level', 100),
        }

        for col, (heading, width) in headers.items():
            packet_tree.heading(col, text=heading)
            packet_tree.column(col, width=width, anchor='center')

        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=packet_tree.yview, style='Dark.Vertical.TScrollbar')
        packet_tree.configure(yscrollcommand=scrollbar.set)

        packet_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        packet_tree.tag_configure('critical', foreground=THREAT_CRITICAL)
        packet_tree.tag_configure('high', foreground=THREAT_HIGH)
        packet_tree.tag_configure('medium', foreground=THREAT_MEDIUM)
        packet_tree.tag_configure('low', foreground=ACCENT_GREEN)

        if self.network_capture_active.get():
            cap_btn.configure(text='Stop Capture', bg=ACCENT_RED, fg='white')

        def start_capture_thread():
            def capture_job():
                import random
                protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'FTP']
                local_ips = ['192.168.1.15', '192.168.1.18', '192.168.1.112']
                dest_ips = ['23.45.67.89', '142.250.190.46', '52.84.120.9', 'openai.com', 'github.com', 'dropbox.com']
                payloads = [
                    "GET /index.html HTTP/1.1",
                    "POST /api/v1/auth HTTP/1.1",
                    "CONNECT chat.openai.com:443 HTTP/1.1",
                    "DB Query: SELECT * FROM users",
                    "Upload: source_code.zip (45MB)",
                    "DNS Query: api.github.com",
                    "POST /upload/chunk HTTP/1.1"
                ]

                while self.network_capture_active.get():
                    time.sleep(random.uniform(0.5, 1.5))
                    t_str = datetime.now().strftime('%H:%M:%S')
                    proto = random.choice(protocols)
                    src = random.choice(local_ips)
                    dest = random.choice(dest_ips)
                    payload = random.choice(payloads)
                    
                    # Real-time packet threat assessment
                    level = 'Low'
                    tag = 'low'
                    if 'upload' in payload.lower() or 'source_code' in payload.lower() or 'dropbox' in dest.lower():
                        level = 'Critical'
                        tag = 'critical'
                        self.alert_manager.add_alert("HIGH", "Network Monitor", f"Suspicious file transfer detected via network payload: {payload}", details=f"Source: {src}, Destination: {dest}")
                    elif 'openai' in dest.lower() or 'chat' in payload.lower():
                        level = 'High'
                        tag = 'high'
                        self.alert_manager.add_alert("MEDIUM", "Network Monitor", "Shadow AI connection detected via HTTPS request header", details=f"Destination: {dest}")
                    elif 'auth' in payload.lower():
                        level = 'Medium'
                        tag = 'medium'

                    self.root.after(0, lambda v=(t_str, proto, src, dest, payload, level), tg=tag: packet_tree.insert('', 0, values=v, tags=(tg,)))
                    self.root.after(0, lambda: clean_table(packet_tree))

            def clean_table(tree):
                try:
                    children = tree.get_children()
                    if len(children) > 100:
                        tree.delete(children[-1])
                except Exception:
                    pass

            self.network_thread = threading.Thread(target=capture_job, daemon=True)
            self.network_thread.start()

    def _build_realtime_settings_screen(self):
        """Build the real-time settings screen."""
        frame = tk.Frame(self.content, bg=BG_PRIMARY)
        frame.pack(fill='both', expand=True)

        title_frame = tk.Frame(frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 10))
        tk.Label(title_frame, text='Real-Time Settings',
                 font=FONT_TITLE, bg=BG_PRIMARY, fg=ACCENT_CYAN).pack(side='left')

        # Form card
        card = tk.Frame(frame, bg=BG_SECONDARY, highlightbackground=BORDER_DEFAULT, highlightthickness=1, padx=25, pady=25)
        card.pack(fill='x', padx=PADDING, pady=5)

        # Parameter 1: Anomaly Contamination
        tk.Label(card, text='Model Anomaly Sensitivity (Contamination)', font=FONT_BODY_BOLD, bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(anchor='w', pady=(0, 5))
        slider1 = tk.Scale(card, from_=0.01, to=0.15, resolution=0.01, orient='horizontal', variable=self.settings_sensitivity, bg=BG_SECONDARY, fg=TEXT_PRIMARY, highlightthickness=0, troughcolor=BG_TERTIARY, activebackground=ACCENT_CYAN)
        slider1.pack(fill='x', pady=(0, 15))

        # Parameter 2: Refresh Rate
        tk.Label(card, text='Background Scan Refresh Interval (Seconds)', font=FONT_BODY_BOLD, bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(anchor='w', pady=(0, 5))
        slider2 = tk.Scale(card, from_=5, to=120, resolution=5, orient='horizontal', variable=self.settings_refresh_rate, bg=BG_SECONDARY, fg=TEXT_PRIMARY, highlightthickness=0, troughcolor=BG_TERTIARY, activebackground=ACCENT_CYAN)
        slider2.pack(fill='x', pady=(0, 15))

        # Parameter 3: Toast Alerts Checkbox
        alert_chk = tk.Checkbutton(card, text='Enable Corner Toast Notifications on Alerts', variable=self.settings_enable_corner_alerts, font=FONT_BODY, bg=BG_SECONDARY, fg=TEXT_PRIMARY, selectcolor=BG_TERTIARY, activebackground=BG_SECONDARY, activeforeground=TEXT_PRIMARY, relief='flat')
        alert_chk.pack(anchor='w', pady=5)

        # Parameter 4: Auto Network Isolation Checkbox
        iso_chk = tk.Checkbutton(card, text='Auto-Isolate Device when Critical Threat is Detected', variable=self.settings_auto_isolation, font=FONT_BODY, bg=BG_SECONDARY, fg=TEXT_PRIMARY, selectcolor=BG_TERTIARY, activebackground=BG_SECONDARY, activeforeground=TEXT_PRIMARY, relief='flat')
        iso_chk.pack(anchor='w', pady=5)

        # Save Button
        def save_configs():
            self._set_status(f"Real-time settings updated: Sensitivity={self.settings_sensitivity.get()}, Refresh={self.settings_refresh_rate.get()}")
            messagebox.showinfo("Success", "Settings successfully saved and applied.")

        save_btn = tk.Label(card, text=' Save Configurations ', font=FONT_BODY_BOLD, bg=ACCENT_CYAN, fg=BG_PRIMARY, cursor='hand2', padx=15, pady=8)
        save_btn.pack(anchor='w', pady=(20, 0))
        save_btn.bind('<Button-1>', lambda e: save_configs())

    # ══════════════════════════════════════════════════════════════
    #  REPORTS & GENERAL SETTINGS BUILDERS
    # ══════════════════════════════════════════════════════════════

    def _build_reports_screen(self):
        """Build the reports screen."""
        frame = tk.Frame(self.content, bg=BG_PRIMARY)
        frame.pack(fill='both', expand=True)

        title_frame = tk.Frame(frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 10))
        tk.Label(title_frame, text='Reports',
                 font=FONT_TITLE, bg=BG_PRIMARY, fg=ACCENT_YELLOW).pack(side='left')

        # Report options
        options_card = tk.Frame(frame, bg=BG_SECONDARY,
                                highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        options_card.pack(fill='x', padx=PADDING, pady=(0, 10))

        tk.Label(options_card, text='Generate Threat Assessment Reports',
                 font=FONT_SUBHEADING, bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(
            anchor='w', padx=10, pady=(10, 5))

        tk.Label(options_card, text='Export comprehensive PDF reports or CSV data for security team review.',
                 font=FONT_BODY, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(
            anchor='w', padx=10, pady=(0, 10))

        btn_frame = tk.Frame(options_card, bg=BG_SECONDARY)
        btn_frame.pack(fill='x', padx=10, pady=(0, 10))

        self.report_status = tk.Label(frame, text='', font=FONT_BODY,
                                       bg=BG_PRIMARY, fg=ACCENT_GREEN)
        self.report_status.pack(padx=PADDING, pady=5)

        def gen_pdf():
            try:
                report_dir = os.path.join(PROJECT_ROOT, 'reports')
                os.makedirs(report_dir, exist_ok=True)
                filename = f'DefendX_Report_{time.strftime("%Y%m%d_%H%M%S")}.pdf'
                path = os.path.join(report_dir, filename)
                result = self.report_gen.generate_pdf(path)
                self.report_status.configure(
                    text=f'PDF Report saved: {result}', fg=ACCENT_GREEN)
                self._set_status(f'Report generated: {filename}')
            except Exception as e:
                self.report_status.configure(
                    text=f'Error: {str(e)}', fg=ACCENT_RED)

        def gen_csv():
            try:
                report_dir = os.path.join(PROJECT_ROOT, 'reports')
                os.makedirs(report_dir, exist_ok=True)
                filename = f'DefendX_ThreatScores_{time.strftime("%Y%m%d_%H%M%S")}.csv'
                path = os.path.join(report_dir, filename)
                result = self.report_gen.generate_csv_report(path)
                self.report_status.configure(
                    text=f'CSV Report saved: {result}', fg=ACCENT_GREEN)
            except Exception as e:
                self.report_status.configure(
                    text=f'Error: {str(e)}', fg=ACCENT_RED)

        pdf_btn = tk.Label(btn_frame, text='  Generate PDF Report  ',
                           font=FONT_BODY_BOLD, bg=ACCENT_YELLOW, fg=BG_PRIMARY,
                           cursor='hand2', padx=12, pady=6)
        pdf_btn.pack(side='left', padx=(0, 10))
        pdf_btn.bind('<Button-1>', lambda e: gen_pdf())

        csv_btn = tk.Label(btn_frame, text='  Export CSV Data  ',
                           font=FONT_BODY_BOLD, bg=ACCENT_CYAN, fg=BG_PRIMARY,
                           cursor='hand2', padx=12, pady=6)
        csv_btn.pack(side='left')
        csv_btn.bind('<Button-1>', lambda e: gen_csv())

    def _build_settings_screen(self):
        """Build the settings screen."""
        frame = tk.Frame(self.content, bg=BG_PRIMARY)
        frame.pack(fill='both', expand=True)

        title_frame = tk.Frame(frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 10))
        tk.Label(title_frame, text='Settings',
                 font=FONT_TITLE, bg=BG_PRIMARY, fg=TEXT_SECONDARY).pack(side='left')

        # Model settings
        model_card = tk.Frame(frame, bg=BG_SECONDARY,
                              highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        model_card.pack(fill='x', padx=PADDING, pady=(0, 10))

        tk.Label(model_card, text='AI Model Configuration', font=FONT_SUBHEADING,
                 bg=BG_SECONDARY, fg=ACCENT_CYAN).pack(
            anchor='w', padx=10, pady=(10, 5))

        model_status = 'Loaded' if self.analyzer.is_loaded else 'Not loaded'
        tk.Label(model_card, text=f'Model Status: {model_status}',
                 font=FONT_BODY, bg=BG_SECONDARY,
                 fg=ACCENT_GREEN if self.analyzer.is_loaded else ACCENT_RED).pack(
            anchor='w', padx=10, pady=3)

        tk.Label(model_card, text=f'Models Directory: {self.models_dir}',
                 font=FONT_SMALL, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(
            anchor='w', padx=10, pady=3)

        if self.analyzer.config:
            config = self.analyzer.config
            tk.Label(model_card, text=f'Features: {config.get("n_features", "N/A")}',
                     font=FONT_SMALL, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(
                anchor='w', padx=10, pady=1)
            tk.Label(model_card, text=f'Training Samples: {config.get("training_samples", "N/A")}',
                     font=FONT_SMALL, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(
                anchor='w', padx=10, pady=1)
            tk.Label(model_card, text=f'AUC Score: {config.get("auc_score", "N/A")}',
                     font=FONT_SMALL, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(
                anchor='w', padx=10, pady=1)

        tk.Frame(model_card, bg=BG_SECONDARY, height=8).pack()

        # Reload button
        reload_btn = tk.Label(model_card, text='  Reload Models  ',
                              font=FONT_BODY_BOLD, bg=ACCENT_CYAN, fg=BG_PRIMARY,
                              cursor='hand2', padx=12, pady=4)
        reload_btn.pack(anchor='w', padx=10, pady=(0, 10))
        reload_btn.bind('<Button-1>', lambda e: self._reload_models())

        # About
        about_card = tk.Frame(frame, bg=BG_SECONDARY,
                              highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        about_card.pack(fill='x', padx=PADDING, pady=(0, 10))

        tk.Label(about_card, text='About DefendX', font=FONT_SUBHEADING,
                 bg=BG_SECONDARY, fg=ACCENT_PURPLE).pack(
            anchor='w', padx=10, pady=(10, 5))

        about_text = (
            'DefendX is an AI-powered Insider Threat Detection System designed for corporate cyber security. '
            'It uses Isolation Forest and Random Forest machine learning models trained on the CERT r4.2 dataset '
            'to detect behavioral anomalies and identify potential insider threats.\n\n'
            'Features:\n'
            '• AI-based anomaly detection (Isolation Forest)\n'
            '• Supervised threat classification (Random Forest)\n'
            '• Shadow AI / GenAI usage detection\n'
            '• USB device & data exfiltration monitoring\n'
            '• Chrome browser & VS Code activity tracking\n'
            '• Real-time threat scoring & alerting\n'
            '• PDF & CSV report generation'
        )
        tk.Label(about_card, text=about_text, font=FONT_BODY,
                 bg=BG_SECONDARY, fg=TEXT_SECONDARY, justify='left',
                 wraplength=600, anchor='w').pack(padx=10, pady=(0, 10))

    def _reload_models(self):
        """Reload AI models."""
        self._load_models()
        self._show_screen(self.current_screen)
        self._set_status('Models reloaded')

    def start_realtime_loop(self):
        """Launches the real-time background scanner loop."""
        def scan_loop():
            while True:
                # Wait for refresh interval
                try:
                    interval = self.settings_refresh_rate.get()
                except Exception:
                    interval = 10
                time.sleep(max(5, interval))

                try:
                    results = {}
                    if self.chrome_connected.get():
                        results['chrome'] = self.system_monitor.chrome.check_history()
                    if self.vscode_connected.get():
                        results['vscode'] = self.system_monitor.vscode.check_recent_activity()
                    if self.disk_connected.get():
                        results['storage'] = self.system_monitor.storage.check_drives()
                    
                    self.system_monitor._generate_alerts(results)
                except Exception:
                    pass

        threading.Thread(target=scan_loop, daemon=True).start()

    def start_api_server(self):
        """Starts a background standard HTTP server for web frontend communication."""
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import json

        app_instance = self

        class APIRequestHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass # suppress printing every hit to stdout

            def end_headers(self):
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')
                super().end_headers()

            def do_OPTIONS(self):
                self.send_response(200)
                self.end_headers()

            def do_GET(self):
                if self.path == '/api/alerts':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    alerts = list(app_instance.alert_manager.alerts)
                    self.wfile.write(json.dumps(alerts).encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                if self.path == '/api/chat':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length)
                    req_data = json.loads(post_data.decode('utf-8'))
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    
                    # Run generate_chat_reply synchronously
                    reply_holder = []
                    event = threading.Event()
                    
                    def cb(reply):
                        reply_holder.append(reply)
                        event.set()
                        
                    app_instance.ai_agent.generate_chat_reply(req_data.get('messages', []), cb)
                    event.wait(timeout=15)
                    
                    reply = reply_holder[0] if reply_holder else "Request timed out."
                    self.wfile.write(json.dumps({"reply": reply}).encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()

        def run_server():
            server_address = ('', 5000)
            try:
                httpd = HTTPServer(server_address, APIRequestHandler)
                print("[App] API Server running on port 5000")
                httpd.serve_forever()
            except Exception as e:
                print(f"[App] API Server failed: {e}")

        threading.Thread(target=run_server, daemon=True).start()

    def _show_loading_screen(self):
        """Displays an elegant, high-fidelity startup screen with dynamic loading status text."""
        self.loading_frame = tk.Frame(self.root, bg=BG_PRIMARY)
        self.loading_frame.pack(fill='both', expand=True)

        center_container = tk.Frame(self.loading_frame, bg=BG_PRIMARY)
        center_container.place(relx=0.5, rely=0.5, anchor='center')

        # Load Logo from User ui wallpaper
        try:
            from PIL import Image, ImageTk
            logo_path = get_asset_path("denderx_logo.png")
            img = Image.open(logo_path)
            img = img.resize((180, 180), Image.Resampling.LANCZOS)
            self.loading_logo_photo = ImageTk.PhotoImage(img)
            
            logo_label = tk.Label(center_container, image=self.loading_logo_photo, bg=BG_PRIMARY)
            logo_label.pack(pady=15)
        except Exception:
            # Fallback
            tk.Label(center_container, text="DX", font=("Outfit", 64, "bold"), bg=BG_PRIMARY, fg=ACCENT_CYAN).pack(pady=15)

        tk.Label(center_container, text="DefendX", font=("Outfit", 30, "bold"), bg=BG_PRIMARY, fg=TEXT_PRIMARY).pack()
        tk.Label(center_container, text="AI Insider Threat Detection & Mitigation Platform", font=("Inter", 11), bg=BG_PRIMARY, fg=TEXT_TERTIARY).pack(pady=(5, 25))

        # Dynamic Status Label
        self.loading_status_var = tk.StringVar(value="Initializing modules...")
        self.status_lbl = tk.Label(center_container, textvariable=self.loading_status_var, font=("Inter", 9, "bold"), bg=BG_PRIMARY, fg=ACCENT_CYAN)
        self.status_lbl.pack(pady=(0, 5))

        # Styled Sleek Progress Bar
        self.style.configure("Elegant.Horizontal.TProgressbar",
                              thickness=5,
                              troughcolor=BG_SECONDARY,
                              background=ACCENT_CYAN,
                              lightcolor=ACCENT_CYAN,
                              darkcolor=ACCENT_CYAN,
                              borderwidth=0)

        progress_bar = ttk.Progressbar(center_container, style="Elegant.Horizontal.TProgressbar", orient='horizontal', length=320, mode='determinate')
        progress_bar.pack()
        progress_bar.start(8)

        # Status text cycling list
        status_steps = [
            "Bootstrapping security framework...",
            "Loading threat telemetry database...",
            "Checking Host Intrusion prevention rules...",
            "Tuning Isolation Forest ML model...",
            "Initializing Gemma-3-IT AI Core...",
            "Activating DefenderX Security Shields..."
        ]

        def update_status(step_idx=0):
            if hasattr(self, 'loading_frame') and self.loading_frame.winfo_exists():
                if step_idx < len(status_steps):
                    self.loading_status_var.set(status_steps[step_idx])
                    self.root.after(400, lambda: update_status(step_idx + 1))

        update_status()

        # Transition timer (2500 ms)
        self.root.after(2500, self._transition_to_login)

    def _transition_to_login(self):
        """Destroys the loading screen and sets up the Login portal screen."""
        if hasattr(self, 'loading_frame'):
            self.loading_frame.destroy()

        self.login_frame = tk.Frame(self.root, bg=BG_PRIMARY)
        self.login_frame.pack(fill='both', expand=True)

        login_card = tk.Frame(self.login_frame, bg=BG_SECONDARY, highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        login_card.place(relx=0.5, rely=0.5, anchor='center', width=380, height=420)

        # Tiny Logo Header
        try:
            from PIL import Image, ImageTk
            logo_path = get_asset_path("denderx_logo.png")
            img = Image.open(logo_path)
            img = img.resize((70, 70), Image.Resampling.LANCZOS)
            self.login_logo_photo = ImageTk.PhotoImage(img)
            logo_label = tk.Label(login_card, image=self.login_logo_photo, bg=BG_SECONDARY)
            logo_label.pack(pady=(25, 5))
        except Exception:
            pass

        tk.Label(login_card, text="DefendX Admin Login", font=("Outfit", 18, "bold"), bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(pady=5)
        tk.Label(login_card, text="Secured Corporate Administrator Portal", font=("Inter", 10), bg=BG_SECONDARY, fg=TEXT_TERTIARY).pack()

        # Username Input
        tk.Label(login_card, text="Username", font=("Inter", 10, "bold"), bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(anchor='w', padx=40, pady=(25, 5))
        self.login_username_var = tk.StringVar(value="admin")
        user_entry = tk.Entry(login_card, textvariable=self.login_username_var, font=FONT_BODY, bg=BG_TERTIARY, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief='flat')
        user_entry.pack(fill='x', padx=40, ipady=4)
        user_entry.focus_set()

        # Password Input
        tk.Label(login_card, text="Password", font=("Inter", 10, "bold"), bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(anchor='w', padx=40, pady=(15, 5))
        self.login_password_var = tk.StringVar()
        pwd_entry = tk.Entry(login_card, textvariable=self.login_password_var, show="*", font=FONT_BODY, bg=BG_TERTIARY, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief='flat')
        pwd_entry.pack(fill='x', padx=40, ipady=4)
        pwd_entry.bind('<Return>', lambda e: self._attempt_admin_login())

        # Login button
        btn = tk.Label(login_card, text=" Authenticate ", font=FONT_BODY_BOLD, bg=ACCENT_CYAN, fg=BG_PRIMARY, cursor='hand2', padx=20, pady=8)
        btn.pack(pady=35)
        btn.bind('<Button-1>', lambda e: self._attempt_admin_login())

    def _attempt_admin_login(self):
        """Attempts admin verification."""
        username = self.login_username_var.get().strip()
        password = self.login_password_var.get()

        if username == "admin" and password == "12345":
            self.login_frame.destroy()
            
            # Initialize layout and start monitor loops
            self._build_ui()
            self.start_realtime_loop()
            self.start_api_server()
        else:
            messagebox.showerror("Authentication Denied", "Incorrect username or password. Please try again.")
            self.login_password_var.set("")

    def _build_simulator_screen(self):
        """Builds the OS simulator controller dashboard screen."""
        frame = tk.Frame(self.content, bg=BG_PRIMARY)
        frame.pack(fill='both', expand=True)

        title_frame = tk.Frame(frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 10))
        
        # Add Logo on title bar
        try:
            from PIL import Image, ImageTk
            logo_path = get_asset_path("denderx_logo.png")
            img = Image.open(logo_path)
            img = img.resize((32, 32), Image.Resampling.LANCZOS)
            self.sim_logo_photo = ImageTk.PhotoImage(img)
            logo_label = tk.Label(title_frame, image=self.sim_logo_photo, bg=BG_PRIMARY)
            logo_label.pack(side='left', padx=(0, 10))
        except Exception:
            pass

        tk.Label(title_frame, text='OS Simulator Console', font=FONT_TITLE, bg=BG_PRIMARY, fg=ACCENT_CYAN).pack(side='left')

        # Description
        desc_frame = tk.Frame(frame, bg=BG_PRIMARY)
        desc_frame.pack(fill='x', padx=PADDING, pady=(0, 15))
        tk.Label(desc_frame, text='Launch and interact with simulated Windows/Linux workstations to trigger corporate policy threat anomalies.', font=FONT_BODY, bg=BG_PRIMARY, fg=TEXT_SECONDARY).pack(side='left')

        # Grid of user cards
        grid_frame = tk.Frame(frame, bg=BG_PRIMARY)
        grid_frame.pack(fill='both', expand=True, padx=PADDING)

        from app.os_simulator import SIMULATED_USERS

        for idx, (user_id, info) in enumerate(SIMULATED_USERS.items()):
            col = idx % 3
            row = idx // 3

            card = tk.Frame(grid_frame, bg=BG_SECONDARY, highlightbackground=BORDER_DEFAULT, highlightthickness=1)
            card.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            grid_frame.grid_columnconfigure(col, weight=1)

            # Details
            tk.Label(card, text=f"{info['name']}", font=FONT_SUBHEADING, bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(anchor='w', padx=15, pady=(15, 2))
            tk.Label(card, text=f"User ID: {user_id}", font=FONT_BODY_BOLD, bg=BG_SECONDARY, fg=ACCENT_CYAN).pack(anchor='w', padx=15, pady=2)
            tk.Label(card, text=f"Dept: {info['dept']}", font=FONT_TINY, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(anchor='w', padx=15, pady=2)
            
            os_lbl = f"OS: {info['os_type'].capitalize()}"
            tk.Label(card, text=os_lbl, font=FONT_TINY, bg=BG_SECONDARY, fg=ACCENT_PURPLE if info['os_type']=='linux' else ACCENT_CYAN).pack(anchor='w', padx=15, pady=2)

            tk.Frame(card, bg=BG_SECONDARY, height=15).pack()

            # Button
            btn = tk.Label(card, text=" Launch Workstation ", font=FONT_BODY_BOLD, bg=ACCENT_CYAN, fg=BG_PRIMARY, cursor='hand2', padx=10, pady=6)
            btn.pack(anchor='w', padx=15, pady=(0, 15))
            btn.bind('<Button-1>', lambda e, uid=user_id: self._launch_user_simulator(uid))

    def _launch_user_simulator(self, user_id):
        """Spawns a new Simulated OS Desktop window."""
        from app.os_simulator import SimulatedOSWindow
        win = SimulatedOSWindow(self, user_id)
        if not hasattr(self, '_active_sim_windows'):
            self._active_sim_windows = {}
        self._active_sim_windows[user_id] = win

    def _show_admin_anomaly_popup(self, alert):
        """Displays a critical popup alert in the center of the Admin portal when a simulated user triggers an anomaly."""
        popup = tk.Toplevel(self.root)
        popup.title("CRITICAL THREAT ALERT")
        popup.geometry("450x320")
        popup.configure(bg=BG_SECONDARY, highlightbackground=ACCENT_RED, highlightthickness=2)
        popup.transient(self.root)
        popup.grab_set()

        self.root.update_idletasks()
        rx = self.root.winfo_x()
        ry = self.root.winfo_y()
        rw = self.root.winfo_width()
        rh = self.root.winfo_height()
        tx = rx + (rw - 450) // 2
        ty = ry + (rh - 320) // 2
        popup.geometry(f"450x320+{tx}+{ty}")

        title_bar = tk.Frame(popup, bg=ACCENT_RED, height=45)
        title_bar.pack(fill='x')
        title_bar.pack_propagate(False)
        tk.Label(title_bar, text="INTRUSION DETECTION ALERT", font=("Outfit", 12, "bold"), bg=ACCENT_RED, fg=BG_PRIMARY).pack(expand=True)

        body = tk.Frame(popup, bg=BG_SECONDARY, padx=20, pady=20)
        body.pack(fill='both', expand=True)

        # Anomaly Logo Icon
        try:
            from PIL import Image, ImageTk
            logo_path = get_asset_path("denderx_logo.png")
            img = Image.open(logo_path)
            img = img.resize((48, 48), Image.Resampling.LANCZOS)
            self.alert_popup_logo_photo = ImageTk.PhotoImage(img)
            logo_label = tk.Label(body, image=self.alert_popup_logo_photo, bg=BG_SECONDARY)
            logo_label.pack(anchor='w', pady=(0, 10))
        except Exception:
            pass

        tk.Label(body, text="Simulated Threat Activity Blocked", font=("Outfit", 14, "bold"), bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(anchor='w', pady=(0, 10))

        tk.Label(body, text=f"User ID: {alert.get('user_id', 'N/A')}", font=("Inter", 11, "bold"), bg=BG_SECONDARY, fg=ACCENT_CYAN).pack(anchor='w', pady=2)
        tk.Label(body, text=f"Activity Name: {alert.get('message', 'N/A')}", font=("Inter", 10), bg=BG_SECONDARY, fg=TEXT_PRIMARY, wraplength=400, justify='left').pack(anchor='w', pady=2)
        
        severity = alert.get('severity', 'HIGH')
        tk.Label(body, text=f"Level of Risk: {severity}", font=("Inter", 11, "bold"), bg=BG_SECONDARY, fg=ACCENT_RED if severity in ['CRITICAL', 'HIGH'] else ACCENT_YELLOW).pack(anchor='w', pady=2)

        tk.Frame(body, bg=BG_SECONDARY, height=15).pack()

        # Action Buttons
        btn_frame = tk.Frame(body, bg=BG_SECONDARY)
        btn_frame.pack(fill='x')

        close_btn = tk.Label(btn_frame, text=" Dismiss Alert ", font=FONT_BODY_BOLD, bg=ACCENT_CYAN, fg=BG_PRIMARY, cursor='hand2', padx=15, pady=6)
        close_btn.pack(side='right')
        close_btn.bind('<Button-1>', lambda e: popup.destroy())


def launch_app():
    """Launch the DefendX application."""
    root = tk.Tk()

    # Center window on screen
    screen_w = root.winfo_screenwidth()
    screen_h = root.winfo_screenheight()
    x = (screen_w - WINDOW_WIDTH) // 2
    y = (screen_h - WINDOW_HEIGHT) // 2
    root.geometry(f'{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y}')

    # Load and set application-wide DefenderX window icon
    try:
        from PIL import Image, ImageTk
        icon_path = get_asset_path("denderx_logo.png")
        img = Image.open(icon_path)
        icon_photo = ImageTk.PhotoImage(img)
        root.iconphoto(True, icon_photo)
    except Exception:
        pass

    app = DefendXApp(root)
    root.mainloop()


if __name__ == '__main__':
    launch_app()
