import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
import time
from datetime import datetime
from PIL import Image, ImageTk
from app.styles import *

SIMULATED_USERS = {
    'USER01': {'name': 'John Doe', 'dept': 'Finance', 'os_type': 'windows', 'password': 'password'},
    'USER02': {'name': 'Jane Smith', 'dept': 'Engineering', 'os_type': 'linux', 'password': 'password'},
    'USER03': {'name': 'Bob Johnson', 'dept': 'Human Resources', 'os_type': 'windows', 'password': 'password'},
    'USER04': {'name': 'Alice Williams', 'dept': 'System Admin', 'os_type': 'linux', 'password': 'password'},
    'USER05': {'name': 'Charlie Brown', 'dept': 'Sales', 'os_type': 'windows', 'password': 'password'},
}

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

class SimulatedOSWindow(tk.Toplevel):
    """A floating window simulating a user's Windows or Linux OS desktop."""

    def __init__(self, parent_app, user_id):
        super().__init__(parent_app.root)
        self.parent_app = parent_app
        self.user_id = user_id
        
        user_info = SIMULATED_USERS.get(user_id, {'name': 'Unknown', 'dept': 'General', 'os_type': 'windows', 'password': 'password'})
        self.user_name = user_info['name']
        self.dept = user_info['dept']
        self.os_type = user_info['os_type']
        self.password = user_info['password']

        self.title(f"{self.user_name} ({self.user_id}) — Simulated {self.os_type.capitalize()} OS")
        self.geometry("850x620")
        self.minsize(800, 600)
        self.configure(bg="#000000")

        self.usb_connected = False
        self.active_app_window = None

        # Resolve assets
        if self.os_type == 'linux':
            self.wallpaper_path = get_asset_path("ubuntu linux.png")
            self.theme_accent = "#e95420"  # Ubuntu Orange
            self.theme_bar_bg = "#300a24"
        else:
            self.wallpaper_path = get_asset_path("Win 11.jpg")
            self.theme_accent = "#0078d4"  # Windows Blue
            self.theme_bar_bg = "#0f172a"

        # Start with Login Screen
        self._build_login_screen()

    def _build_login_screen(self):
        """Draws the OS Login lock screen."""
        self.clear_window()

        # Scale and display background wallpaper (blurred or darkened for login screen)
        try:
            img = Image.open(self.wallpaper_path)
            # Resize image to fit window dimensions
            img = img.resize((850, 620), Image.Resampling.LANCZOS)
            # Darken it for login
            from PIL import ImageEnhance
            enhancer = ImageEnhance.Brightness(img)
            img = enhancer.enhance(0.4)
            self.bg_image = ImageTk.PhotoImage(img)
            
            bg_label = tk.Label(self, image=self.bg_image)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except Exception:
            # Fallback background
            bg_label = tk.Label(self, bg="#111827")
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Login Card Container
        login_card = tk.Frame(self, bg="#1e293b", highlightbackground=self.theme_accent, highlightthickness=1)
        login_card.place(relx=0.5, rely=0.5, anchor="center", width=340, height=380)

        # Round Profile Icon
        p_frame = tk.Frame(login_card, bg=self.theme_accent, width=80, height=80)
        p_frame.pack(pady=(30, 10))
        p_frame.pack_propagate(False)
        tk.Label(p_frame, text=self.user_id[:2], font=("Outfit", 24, "bold"), bg=self.theme_accent, fg="#ffffff").pack(expand=True)

        tk.Label(login_card, text=self.user_name, font=("Outfit", 18, "bold"), bg="#1e293b", fg="#f3f4f6").pack(pady=5)
        tk.Label(login_card, text=f"Corporate {self.dept} Dept", font=("Inter", 11), bg="#1e293b", fg="#9ca3af").pack()

        # Password input field
        tk.Label(login_card, text="Enter Password", font=("Inter", 10, "bold"), bg="#1e293b", fg="#9ca3af").pack(anchor="w", padx=40, pady=(25, 5))
        
        self.password_var = tk.StringVar()
        pwd_entry = tk.Entry(login_card, textvariable=self.password_var, show="*", font=("Inter", 12), bg="#0f172a", fg="#ffffff", insertbackground="#ffffff", relief="flat")
        pwd_entry.pack(fill="x", padx=40, ipady=4)
        pwd_entry.focus_set()
        pwd_entry.bind("<Return>", lambda e: self._attempt_login())

        # Submit Login button
        btn = tk.Label(login_card, text=" Sign In ", font=("Outfit", 12, "bold"), bg=self.theme_accent, fg="#ffffff", cursor="hand2", padx=20, pady=8)
        btn.pack(pady=30)
        btn.bind("<Button-1>", lambda e: self._attempt_login())

        # Instructions Label
        tk.Label(login_card, text="Use default credentials: password", font=("Inter", 9), bg="#1e293b", fg="#6b7280").pack(pady=(0, 10))

    def _attempt_login(self):
        """Validates entered password."""
        entered = self.password_var.get()
        if entered == self.password:
            self._build_desktop()
        else:
            messagebox.showerror("Authentication Failed", "Invalid password. Access Denied.")
            self.password_var.set("")

    def _build_desktop(self):
        """Draws the OS Desktop interface with floating Canvas and program icons."""
        self.clear_window()

        # Draw original wallpaper background
        try:
            img = Image.open(self.wallpaper_path)
            w = max(850, self.winfo_width())
            h = max(620, self.winfo_height())
            img = img.resize((w, h), Image.Resampling.LANCZOS)
            self.bg_image = ImageTk.PhotoImage(img)
            self.canvas = tk.Canvas(self, bg="#111827", highlightthickness=0)
            self.canvas.pack(fill="both", expand=True)
            self.canvas.create_image(0, 0, image=self.bg_image, anchor="nw")
        except Exception:
            self.canvas = tk.Canvas(self, bg="#111827", highlightthickness=0)
            self.canvas.pack(fill="both", expand=True)

        # Bind resize trigger to scale wallpaper background dynamically
        self.bind("<Configure>", self._on_window_resize)

        # Re-build desktop program shortcut widgets
        self._build_desktop_shortcuts()

        # Build OS taskbar/panel at the bottom
        self._build_taskbar()

    def _on_window_resize(self, event):
        """Re-scales the desktop background image to match the window viewport size."""
        if event.widget != self:
            return
        if hasattr(self, 'wallpaper_path'):
            try:
                img = Image.open(self.wallpaper_path)
                img = img.resize((event.width, event.height), Image.Resampling.LANCZOS)
                self.bg_image = ImageTk.PhotoImage(img)
                self.canvas.delete("all")
                self.canvas.create_image(0, 0, image=self.bg_image, anchor="nw")
                
                # Redraw all shortcuts
                self._draw_shortcuts()
            except Exception:
                pass

    def _build_desktop_shortcuts(self):
        """Initializes shortcut specifications."""
        self.shortcuts = [
            {"id": "usb", "label": "Simulate USB Drive", "color": "#00f0ff"},
            {"id": "browser", "label": "Web Browser", "color": "#e95420"},
            {"id": "explorer", "label": "File Explorer", "color": "#facc15"}
        ]
        self._draw_shortcuts()

    def _draw_shortcuts(self):
        """Renders shortcut icons on the Canvas layout."""
        if not hasattr(self, 'canvas'):
            return

        # Preload icons using get_asset_path
        try:
            self.usb_icon_photo = ImageTk.PhotoImage(Image.open(get_asset_path("sim_usb.png")).resize((48, 48), Image.Resampling.LANCZOS))
            self.browser_icon_photo = ImageTk.PhotoImage(Image.open(get_asset_path("web_expo.png")).resize((48, 48), Image.Resampling.LANCZOS))
            self.explorer_icon_photo = ImageTk.PhotoImage(Image.open(get_asset_path("file_expo.png")).resize((48, 48), Image.Resampling.LANCZOS))
        except Exception as e:
            print(f"Error loading desktop icons: {e}")
            self.usb_icon_photo = None
            self.browser_icon_photo = None
            self.explorer_icon_photo = None

        x = 50
        y = 50
        gap = 110

        shortcuts_data = [
            {"id": "usb", "label": "Simulate USB Drive", "photo": self.usb_icon_photo},
            {"id": "browser", "label": "Web Browser", "photo": self.browser_icon_photo},
            {"id": "explorer", "label": "File Explorer", "photo": self.explorer_icon_photo}
        ]

        for s in shortcuts_data:
            if s["photo"]:
                # Draw the loaded image on the canvas
                self.canvas.create_image(x + 30, y + 24, image=s["photo"], tags=s['id'])
            else:
                # Fallback flat rect if image load failed
                self.canvas.create_rectangle(x, y, x+60, y+48, fill="#1e293b", outline=self.theme_accent, width=1, tags=s['id'])
            
            # Label text
            self.canvas.create_text(x+30, y+65, text=s['label'], fill="#ffffff", font=("Inter", 9, "bold"), width=100, justify="center", tags=s['id'])

            # Bind mouse clicks
            self.canvas.tag_bind(s['id'], "<Button-1>", lambda e, sid=s['id']: self._open_app(sid))
            
            y += gap

    def _build_taskbar(self):
        """Builds a bottom taskbar panel showing date, user metrics, and start menu buttons."""
        bar = tk.Frame(self, bg=self.theme_bar_bg, height=45)
        bar.pack(side="bottom", fill="x")

        # Start button
        start_btn = tk.Label(bar, text=" Start Menu ", bg=self.theme_accent, fg="#ffffff", font=("Outfit", 10, "bold"), padx=10, pady=5)
        start_btn.pack(side="left", padx=10, pady=8)
        start_btn.bind("<Button-1>", lambda e: messagebox.showinfo("Start Menu", f"DefendX Security Policy is active for {self.user_name}."))

        # User identity labels
        tk.Label(bar, text=f"User: {self.user_name} | {self.dept}", bg=self.theme_bar_bg, fg="#9ca3af", font=("Inter", 9, "bold")).pack(side="left", padx=20)

        # Date & Time indicators
        now = datetime.now()
        time_str = now.strftime("%H:%M")
        date_str = now.strftime("%d/%m/%Y")
        
        time_lbl = tk.Label(bar, text=f"{time_str}\n{date_str}", bg=self.theme_bar_bg, fg="#ffffff", font=("Inter", 8), justify="right")
        time_lbl.pack(side="right", padx=15)

    def _open_app(self, app_id):
        """Spawns an interactive application panel inside the desktop canvas workspace."""
        if self.active_app_window:
            self.active_app_window.destroy()

        self.active_app_window = tk.Frame(self, bg="#0f172a", highlightbackground=self.theme_accent, highlightthickness=1)
        
        # Position panel overlay in desktop center
        self.active_app_window.place(relx=0.5, rely=0.45, anchor="center", width=520, height=380)

        # Header Title bar
        title_bar = tk.Frame(self.active_app_window, bg="#1e293b", height=32)
        title_bar.pack(fill="x")
        title_bar.pack_propagate(False)

        title_lbl = "App Window"
        if app_id == "usb": title_lbl = "USB Connection Simulator"
        elif app_id == "browser": title_lbl = "Chrome Web Browser"
        elif app_id == "explorer": title_lbl = "OS File Explorer"

        tk.Label(title_bar, text=title_lbl, font=("Outfit", 10, "bold"), bg="#1e293b", fg=self.theme_accent).pack(side="left", padx=10)
        
        close_btn = tk.Label(title_bar, text="X", font=("Outfit", 11, "bold"), bg="#1e293b", fg="#ef4444", cursor="hand2")
        close_btn.pack(side="right", padx=10)
        close_btn.bind("<Button-1>", lambda e: self._close_active_app())

        # Main viewport body
        body = tk.Frame(self.active_app_window, bg="#0f172a")
        body.pack(fill="both", expand=True, padx=15, pady=15)

        if app_id == "usb":
            self._render_usb_app(body)
        elif app_id == "browser":
            self._render_browser_app(body)
        elif app_id == "explorer":
            self._render_explorer_app(body)

    def _close_active_app(self):
        if self.active_app_window:
            self.active_app_window.destroy()
            self.active_app_window = None

    def _render_usb_app(self, parent):
        """USB drive insertion and exfiltration simulator panel."""
        tk.Label(parent, text="Removable Storage Control Panel", font=("Outfit", 12, "bold"), bg="#0f172a", fg="#ffffff").pack(anchor="w")
        tk.Label(parent, text="Simulate USB drive mounting and copy corporate records.", font=("Inter", 9), bg="#0f172a", fg="#9ca3af").pack(anchor="w", pady=(0, 15))

        status_frame = tk.Frame(parent, bg="#1e293b", padx=15, pady=10)
        status_frame.pack(fill="x", pady=10)

        self.usb_status_lbl = tk.Label(status_frame, text="Status: Disconnected", font=("Inter", 11, "bold"), bg="#1e293b", fg="#ef4444")
        self.usb_status_lbl.pack(side="left")

        toggle_btn = tk.Label(status_frame, text=" Insert USB Drive ", font=("Outfit", 10, "bold"), bg=self.theme_accent, fg="#ffffff", cursor="hand2", padx=12, pady=6)
        toggle_btn.pack(side="right")
        toggle_btn.bind("<Button-1>", lambda e: self._toggle_usb_connection(toggle_btn))

        # Files selection list
        tk.Label(parent, text="Files on Workstation:", font=("Inter", 10, "bold"), bg="#0f172a", fg="#f3f4f6").pack(anchor="w", pady=(10, 5))
        
        file_frame = tk.Frame(parent, bg="#0f172a")
        file_frame.pack(fill="both", expand=True)

        files = [
            {"name": "vacation_itinerary.pdf", "desc": "Personal travel itinerary", "threat": False},
            {"name": "source_code_backup.zip", "desc": "Intellectual property source files", "threat": True, "type": "USB Exfiltration"},
            {"name": "confidential_salaries.xlsx", "desc": "Employee payroll details", "threat": True, "type": "USB Exfiltration"}
        ]

        for f in files:
            row = tk.Frame(file_frame, bg="#1e293b", height=32)
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)

            tk.Label(row, text=f["name"], font=("Inter", 9, "bold"), bg="#1e293b", fg="#f3f4f6").pack(side="left", padx=10)
            tk.Label(row, text=f"({f['desc']})", font=("Inter", 8), bg="#1e293b", fg="#9ca3af").pack(side="left", padx=5)

            copy_btn = tk.Label(row, text="Copy to USB", font=("Outfit", 8, "bold"), bg="#475569", fg="#ffffff", cursor="hand2", padx=8, pady=3)
            copy_btn.pack(side="right", padx=10)
            copy_btn.bind("<Button-1>", lambda e, file_obj=f: self._copy_file_to_usb(file_obj))

        # Update initial connection visual states
        if self.usb_connected:
            self.usb_status_lbl.configure(text="Status: Connected (E:/)", fg="#10b981")
            toggle_btn.configure(text=" Eject USB Drive ")

    def _toggle_usb_connection(self, button_widget):
        self.usb_connected = not self.usb_connected
        if self.usb_connected:
            self.usb_status_lbl.configure(text="Status: Connected (E:/)", fg="#10b981")
            button_widget.configure(text=" Eject USB Drive ")
            # Fire normal alert
            self.parent_app.alert_manager.add_alert(
                source="Storage Monitor",
                message="Removable storage media mounted",
                severity="INFO",
                details=f"USB Flash device mounted successfully under volume E:/",
                user_id=self.user_id
            )
        else:
            self.usb_status_lbl.configure(text="Status: Disconnected", fg="#ef4444")
            button_widget.configure(text=" Insert USB Drive ")
            # Fire normal alert
            self.parent_app.alert_manager.add_alert(
                source="Storage Monitor",
                message="Removable storage media ejected",
                severity="INFO",
                details=f"USB volume E:/ ejected successfully by user request",
                user_id=self.user_id
            )

    def _copy_file_to_usb(self, file_obj):
        if not self.usb_connected:
            messagebox.showwarning("Error", "Please connect a USB drive first.")
            return

        if file_obj["threat"]:
            # Fire critical threat alert
            self.parent_app.alert_manager.add_alert(
                source="Storage Monitor",
                message=f"Suspicious transfer: {file_obj['name']} copied to USB",
                severity="CRITICAL",
                details=f"User exfiltrated intellectual corporate property to USB: {file_obj['name']} ({file_obj['desc']})",
                user_id=self.user_id
            )
            messagebox.showwarning("Access Blocked", f"Security Policy Blocked: Unauthorized copy of {file_obj['name']} to USB volume.")
        else:
            # Normal action
            messagebox.showinfo("Success", f"File {file_obj['name']} copied to USB successfully.")

    def _render_browser_app(self, parent):
        """GenAI/Shadow AI browsing simulator panel."""
        # Bookmarks row
        b_frame = tk.Frame(parent, bg="#0f172a")
        b_frame.pack(fill="x", pady=(0, 10))

        bookmarks = [
            {"label": "Google", "url": "https://google.com", "threat": False},
            {"label": "Wikipedia", "url": "https://wikipedia.org", "threat": False},
            {"label": "ChatGPT", "url": "https://chatgpt.com", "threat": True, "type": "Shadow AI Usage"},
            {"label": "DeepSeek", "url": "https://deepseek.com", "threat": True, "type": "Shadow AI Usage"}
        ]

        for bm in bookmarks:
            lbl = tk.Label(b_frame, text=bm["label"], font=("Inter", 9, "bold"), bg="#1e293b", fg=self.theme_accent, cursor="hand2", padx=8, pady=4, highlightbackground="#475569", highlightthickness=1)
            lbl.pack(side="left", padx=3)
            lbl.bind("<Button-1>", lambda e, b_obj=bm: self._navigate_browser(b_obj["url"], b_obj["threat"], b_obj.get("type", "")))

        # Address Bar
        addr_frame = tk.Frame(parent, bg="#1e293b", padx=8, pady=6)
        addr_frame.pack(fill="x", pady=5)

        tk.Label(addr_frame, text="URL:", font=("Inter", 9, "bold"), bg="#1e293b", fg="#9ca3af").pack(side="left", padx=(0, 5))
        self.url_var = tk.StringVar(value="https://google.com")
        
        self.url_entry = tk.Entry(addr_frame, textvariable=self.url_var, font=("Inter", 9), bg="#0f172a", fg="#ffffff", insertbackground="#ffffff", relief="flat")
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=2)
        self.url_entry.bind("<Return>", lambda e: self._navigate_browser_text())

        # Go Button
        go_btn = tk.Label(addr_frame, text=" Go ", font=("Outfit", 8, "bold"), bg=self.theme_accent, fg="#ffffff", cursor="hand2", padx=10)
        go_btn.pack(side="right", padx=(5, 0))
        go_btn.bind("<Button-1>", lambda e: self._navigate_browser_text())

        # Mock browser viewport page
        self.browser_viewport = tk.Frame(parent, bg="#1e293b", highlightbackground="#334155", highlightthickness=1)
        self.browser_viewport.pack(fill="both", expand=True, pady=10)

        self.browser_text = tk.Label(self.browser_viewport, text="Welcome to Chrome Browser.\nClick a bookmark above or type a URL.", font=("Inter", 11), bg="#1e293b", fg="#9ca3af", justify="center")
        self.browser_text.pack(expand=True)

    def _navigate_browser_text(self):
        url = self.url_var.get().strip().lower()
        threat = False
        threat_type = ""
        
        if "chatgpt" in url or "claude" in url or "deepseek" in url or "gemini" in url or "copilot" in url:
            threat = True
            threat_type = "Shadow AI Usage"
        elif "hacks" in url or "pirate" in url or "crack" in url:
            threat = True
            threat_type = "Unauthorized Web Browsing"

        self._navigate_browser(url, threat, threat_type)

    def _navigate_browser(self, url, threat, threat_type):
        self.url_var.set(url)
        self.browser_text.configure(text=f"Loading page: {url}...\nSecure connection established.")

        if threat:
            self.browser_text.configure(text=f"Access Blocked!\nURL: {url}\nReason: Corporate Web Filter Policy Violation.", fg="#ef4444")
            # Fire critical threat alert
            self.parent_app.alert_manager.add_alert(
                source="Chrome Monitor",
                message=f"Unauthorized visit: {url}",
                severity="HIGH",
                details=f"User bypassed security warning to navigate to unauthorized site: {url} (Category: {threat_type})",
                user_id=self.user_id
            )
        else:
            self.browser_text.configure(text=f"Loaded successfully:\n{url}\n\nThis page complies with corporate security policies.", fg="#10b981")

    def _render_explorer_app(self, parent):
        """Files access and credentials exfiltration simulator panel."""
        tk.Label(parent, text="System File Directory: C:/Users/Documents", font=("Outfit", 11, "bold"), bg="#0f172a", fg="#ffffff").pack(anchor="w", pady=(0, 10))

        file_list_frame = tk.Frame(parent, bg="#0f172a")
        file_list_frame.pack(fill="both", expand=True)

        files = [
            {"name": "corporate_strategy_2026.docx", "desc": "Company vision slides", "threat": False},
            {"name": "passwords_list.txt", "desc": "Plaintext system passwords", "threat": True, "type": "Credential Theft"},
            {"name": "master_keys.pem", "desc": "Corporate SSL decryption keys", "threat": True, "type": "Secret Key Leak"}
        ]

        for f in files:
            row = tk.Frame(file_list_frame, bg="#1e293b", height=35)
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)

            # Folder icon representation
            tk.Label(row, text="📄", bg="#1e293b", fg=self.theme_accent, font=("Inter", 11)).pack(side="left", padx=10)
            tk.Label(row, text=f["name"], font=("Inter", 9, "bold"), bg="#1e293b", fg="#f3f4f6").pack(side="left")
            tk.Label(row, text=f"({f['desc']})", font=("Inter", 8), bg="#1e293b", fg="#9ca3af").pack(side="left", padx=5)

            open_btn = tk.Label(row, text="Open File", font=("Outfit", 8, "bold"), bg="#475569", fg="#ffffff", cursor="hand2", padx=8, pady=3)
            open_btn.pack(side="right", padx=10)
            open_btn.bind("<Button-1>", lambda e, file_obj=f: self._open_explorer_file(file_obj))

    def _open_explorer_file(self, file_obj):
        if file_obj["threat"]:
            # Fire critical threat alert
            self.parent_app.alert_manager.add_alert(
                source="Threat Engine",
                message=f"Sensitive file access: {file_obj['name']}",
                severity="HIGH",
                details=f"User read highly confidential data: {file_obj['name']} ({file_obj['desc']}) (Category: {file_obj['type']})",
                user_id=self.user_id
            )
            messagebox.showwarning("Security Warning", f"Warning: Accessing {file_obj['name']} has been audited by your Cyber Security preventer.")
        else:
            messagebox.showinfo("File Content", f"Opening {file_obj['name']}:\n\n[Normal corporate content document data]")

    def clear_window(self):
        """Cleans up all child elements currently placed in this window frame."""
        for widget in self.winfo_children():
            widget.destroy()
