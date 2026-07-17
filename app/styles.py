"""
DefendX Application — UI Theme & Styling
Centralized dark theme configuration for the Tkinter GUI.
"""

# ═══════════════════════════════════════════════════════════════
#  Color Palette
# ═══════════════════════════════════════════════════════════════

# Background colors
BG_PRIMARY = '#0d1117'      # Main background (GitHub dark)
BG_SECONDARY = '#161b22'    # Cards, panels
BG_TERTIARY = '#21262d'     # Elevated elements
BG_HOVER = '#30363d'        # Hover states
BG_SIDEBAR = '#010409'      # Sidebar background

# Text colors
TEXT_PRIMARY = '#f0f6fc'     # Primary text
TEXT_SECONDARY = '#8b949e'   # Secondary / muted text
TEXT_TERTIARY = '#6e7681'    # Tertiary text
TEXT_LINK = '#58a6ff'        # Links

# Accent colors
ACCENT_CYAN = '#00d4ff'     # Primary accent
ACCENT_BLUE = '#58a6ff'     # Secondary accent
ACCENT_PURPLE = '#a855f7'   # Tertiary accent
ACCENT_GREEN = '#10b981'    # Success / safe
ACCENT_YELLOW = '#f59e0b'   # Warning
ACCENT_ORANGE = '#ff6b35'   # Alert
ACCENT_RED = '#ff4444'      # Danger / critical

# Border colors
BORDER_DEFAULT = '#30363d'
BORDER_MUTED = '#21262d'
BORDER_ACCENT = '#00d4ff'

# Threat level colors
THREAT_CRITICAL = '#ff0000'
THREAT_HIGH = '#ff4444'
THREAT_MEDIUM = '#f59e0b'
THREAT_LOW = '#10b981'
THREAT_SAFE = '#238636'

# Chart colors
CHART_PALETTE = ['#00d4ff', '#a855f7', '#10b981', '#f59e0b', '#ff4444',
                 '#58a6ff', '#ff6b35', '#ec4899', '#06b6d4', '#84cc16']


# ═══════════════════════════════════════════════════════════════
#  Typography
# ═══════════════════════════════════════════════════════════════

FONT_FAMILY = 'Segoe UI'
FONT_FAMILY_MONO = 'Consolas'

FONT_TITLE = (FONT_FAMILY, 20, 'bold')
FONT_HEADING = (FONT_FAMILY, 16, 'bold')
FONT_SUBHEADING = (FONT_FAMILY, 13, 'bold')
FONT_BODY = (FONT_FAMILY, 11)
FONT_BODY_BOLD = (FONT_FAMILY, 11, 'bold')
FONT_SMALL = (FONT_FAMILY, 9)
FONT_TINY = (FONT_FAMILY, 8)
FONT_MONO = (FONT_FAMILY_MONO, 10)
FONT_MONO_SMALL = (FONT_FAMILY_MONO, 9)

FONT_SIDEBAR = (FONT_FAMILY, 11)
FONT_SIDEBAR_ACTIVE = (FONT_FAMILY, 11, 'bold')
FONT_STAT_NUMBER = (FONT_FAMILY, 28, 'bold')
FONT_STAT_LABEL = (FONT_FAMILY, 10)


# ═══════════════════════════════════════════════════════════════
#  Layout Constants
# ═══════════════════════════════════════════════════════════════

SIDEBAR_WIDTH = 220
PADDING = 15
CARD_PADDING = 12
CARD_CORNER_RADIUS = 8
CARD_BORDER_WIDTH = 1

# Window dimensions
WINDOW_WIDTH = 1400
WINDOW_HEIGHT = 850
WINDOW_MIN_WIDTH = 1100
WINDOW_MIN_HEIGHT = 700


# ═══════════════════════════════════════════════════════════════
#  Ttk Style Configuration
# ═══════════════════════════════════════════════════════════════

def configure_ttk_styles(style):
    """Configure ttk widget styles for the dark theme."""
    
    # Treeview (tables)
    style.configure('Dark.Treeview',
                    background=BG_SECONDARY,
                    foreground=TEXT_PRIMARY,
                    fieldbackground=BG_SECONDARY,
                    borderwidth=0,
                    font=FONT_BODY,
                    rowheight=30)
    style.configure('Dark.Treeview.Heading',
                    background=BG_TERTIARY,
                    foreground=ACCENT_CYAN,
                    font=FONT_BODY_BOLD,
                    borderwidth=0)
    style.map('Dark.Treeview',
              background=[('selected', BG_HOVER)],
              foreground=[('selected', TEXT_PRIMARY)])
    
    # Scrollbar
    style.configure('Dark.Vertical.TScrollbar',
                    background=BG_TERTIARY,
                    troughcolor=BG_SECONDARY,
                    borderwidth=0,
                    arrowsize=0)
    
    # Progressbar
    style.configure('Cyan.Horizontal.TProgressbar',
                    background=ACCENT_CYAN,
                    troughcolor=BG_TERTIARY,
                    borderwidth=0,
                    thickness=6)
    style.configure('Red.Horizontal.TProgressbar',
                    background=ACCENT_RED,
                    troughcolor=BG_TERTIARY,
                    borderwidth=0,
                    thickness=6)
    style.configure('Green.Horizontal.TProgressbar',
                    background=ACCENT_GREEN,
                    troughcolor=BG_TERTIARY,
                    borderwidth=0,
                    thickness=6)
    
    # Notebook (tabs)
    style.configure('Dark.TNotebook',
                    background=BG_PRIMARY,
                    borderwidth=0)
    style.configure('Dark.TNotebook.Tab',
                    background=BG_TERTIARY,
                    foreground=TEXT_SECONDARY,
                    padding=[12, 6],
                    font=FONT_BODY)
    style.map('Dark.TNotebook.Tab',
              background=[('selected', BG_SECONDARY)],
              foreground=[('selected', ACCENT_CYAN)])


# ═══════════════════════════════════════════════════════════════
#  Helper Functions
# ═══════════════════════════════════════════════════════════════

def get_threat_color(score: float) -> str:
    """Return color based on threat score (0-100)."""
    if score >= 75:
        return THREAT_CRITICAL
    elif score >= 50:
        return THREAT_HIGH
    elif score >= 25:
        return THREAT_MEDIUM
    else:
        return THREAT_LOW


def get_threat_label(score: float) -> str:
    """Return threat level label based on score."""
    if score >= 75:
        return 'CRITICAL'
    elif score >= 50:
        return 'HIGH'
    elif score >= 25:
        return 'MEDIUM'
    else:
        return 'LOW'


def create_card(parent, **kwargs):
    """Create a styled card frame."""
    import tkinter as tk
    frame = tk.Frame(parent,
                     bg=kwargs.get('bg', BG_SECONDARY),
                     highlightbackground=kwargs.get('border_color', BORDER_DEFAULT),
                     highlightthickness=kwargs.get('border_width', 1),
                     padx=kwargs.get('padx', CARD_PADDING),
                     pady=kwargs.get('pady', CARD_PADDING))
    return frame
