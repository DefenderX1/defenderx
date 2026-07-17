"""
DefendX — Main Dashboard
Threat overview dashboard with real-time charts, risk scores,
top threats list, and activity monitoring panels.
"""

import tkinter as tk
from tkinter import ttk
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
import pandas as pd

from app.styles import *


class DashboardView:
    """Main threat overview dashboard with charts and metrics."""
    
    def __init__(self, parent, threat_analyzer, alert_manager, system_monitor, on_alert_click=None):
        self.parent = parent
        self.analyzer = threat_analyzer
        self.alerts = alert_manager
        self.monitor = system_monitor
        self.on_alert_click = on_alert_click
        self.frame = None
        self._charts = {}
    
    def build(self) -> tk.Frame:
        """Build the dashboard UI."""
        self.frame = tk.Frame(self.parent, bg=BG_PRIMARY)
        
        # Title bar
        title_frame = tk.Frame(self.frame, bg=BG_PRIMARY)
        title_frame.pack(fill='x', padx=PADDING, pady=(PADDING, 5))
        
        tk.Label(title_frame, text='Threat Dashboard',
                font=FONT_TITLE, bg=BG_PRIMARY, fg=ACCENT_CYAN).pack(side='left')
        
        tk.Label(title_frame, text='Real-time Insider Threat Overview',
                font=FONT_SMALL, bg=BG_PRIMARY, fg=TEXT_SECONDARY).pack(side='left', padx=(15, 0))
        
        # ── Top Stats Row ──
        self._build_stats_row()
        
        # ── Main Content: Charts + Right Panel ──
        content_frame = tk.Frame(self.frame, bg=BG_PRIMARY)
        content_frame.pack(fill='both', expand=True, padx=PADDING, pady=5)
        
        # Left: Charts
        charts_frame = tk.Frame(content_frame, bg=BG_PRIMARY)
        charts_frame.pack(side='left', fill='both', expand=True, padx=(0, 5))
        
        self._build_threat_chart(charts_frame)
        self._build_activity_chart(charts_frame)
        
        # Right: Top Threats + Alerts
        right_panel = tk.Frame(content_frame, bg=BG_PRIMARY, width=340)
        right_panel.pack(side='right', fill='y', padx=(5, 0))
        right_panel.pack_propagate(False)
        
        self._build_top_threats(right_panel)
        self._build_alerts_panel(right_panel)
        
        return self.frame
    
    def _build_stats_row(self):
        """Build the top statistics cards row."""
        stats_frame = tk.Frame(self.frame, bg=BG_PRIMARY)
        stats_frame.pack(fill='x', padx=PADDING, pady=5)
        
        # Get data
        stats = self.analyzer.get_anomaly_stats()
        dist = self.analyzer.get_threat_distribution()
        unresolved = self.alerts.get_total_unresolved()
        
        cards = [
            {
                'label': 'Total Users',
                'value': str(stats.get('total_users', 0)),
                'color': ACCENT_CYAN,
                'icon': '',
                'sub': 'Monitored employees'
            },
            {
                'label': 'Anomalies',
                'value': str(stats.get('anomalies', 0)),
                'color': ACCENT_RED,
                'icon': '',
                'sub': f'{stats.get("anomalies", 0) / max(stats.get("total_users", 1), 1) * 100:.1f}% of total'
            },
            {
                'label': 'Critical Threats',
                'value': str(dist.get('Critical', 0)),
                'color': THREAT_CRITICAL,
                'icon': '',
                'sub': 'Immediate attention required'
            },
            {
                'label': 'High Risk',
                'value': str(dist.get('High', 0)),
                'color': THREAT_HIGH,
                'icon': '',
                'sub': 'Elevated risk users'
            },
            {
                'label': 'Active Alerts',
                'value': str(unresolved),
                'color': ACCENT_YELLOW,
                'icon': '',
                'sub': 'Pending review'
            },
            {
                'label': 'Avg Threat Score',
                'value': f'{stats.get("mean_threat_score", 0):.1f}',
                'color': ACCENT_GREEN,
                'icon': '',
                'sub': f'Max: {stats.get("max_threat_score", 0):.1f}'
            },
        ]
        
        for i, card in enumerate(cards):
            card_frame = tk.Frame(stats_frame, bg=BG_SECONDARY,
                                highlightbackground=BORDER_DEFAULT,
                                highlightthickness=1, padx=12, pady=10)
            card_frame.pack(side='left', fill='both', expand=True,
                          padx=(0 if i == 0 else 3, 3 if i < len(cards)-1 else 0))
            
            # Icon + Label
            header = tk.Frame(card_frame, bg=BG_SECONDARY)
            header.pack(fill='x')
            tk.Label(header, text=card['icon'], font=(FONT_FAMILY, 14),
                    bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(side='left')
            tk.Label(header, text=card['label'], font=FONT_SMALL,
                    bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(side='left', padx=(5, 0))
            
            # Value
            tk.Label(card_frame, text=card['value'], font=FONT_STAT_NUMBER,
                    bg=BG_SECONDARY, fg=card['color']).pack(anchor='w', pady=(2, 0))
            
            # Sub-label
            tk.Label(card_frame, text=card['sub'], font=FONT_TINY,
                    bg=BG_SECONDARY, fg=TEXT_TERTIARY).pack(anchor='w')
    
    def _build_threat_chart(self, parent):
        """Build the threat score distribution chart."""
        chart_card = tk.Frame(parent, bg=BG_SECONDARY,
                             highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        chart_card.pack(fill='both', expand=True, pady=(0, 5))
        
        # Header
        header = tk.Frame(chart_card, bg=BG_SECONDARY)
        header.pack(fill='x', padx=10, pady=(8, 0))
        tk.Label(header, text='Threat Score Distribution', font=FONT_SUBHEADING,
                bg=BG_SECONDARY, fg=ACCENT_CYAN).pack(side='left')
        
        # Matplotlib chart
        fig = Figure(figsize=(8, 3), dpi=100, facecolor=BG_SECONDARY)
        ax = fig.add_subplot(111)
        ax.set_facecolor(BG_TERTIARY)
        
        scores_df = self.analyzer.get_all_threat_scores()
        if len(scores_df) > 0 and 'threat_score' in scores_df.columns:
            scores = scores_df['threat_score'].dropna()
            
            # Color-coded bins
            bins = np.linspace(0, 100, 40)
            n, bins_out, patches = ax.hist(scores, bins=bins, edgecolor=BG_SECONDARY, alpha=0.85)
            
            for patch, left_edge in zip(patches, bins_out[:-1]):
                if left_edge >= 75:
                    patch.set_facecolor(THREAT_CRITICAL)
                elif left_edge >= 50:
                    patch.set_facecolor(THREAT_HIGH)
                elif left_edge >= 25:
                    patch.set_facecolor(THREAT_MEDIUM)
                else:
                    patch.set_facecolor(ACCENT_GREEN)
            
            ax.axvline(75, color=THREAT_CRITICAL, linestyle='--', linewidth=1, alpha=0.7)
            ax.axvline(50, color=THREAT_HIGH, linestyle='--', linewidth=1, alpha=0.5)
            ax.axvline(25, color=THREAT_MEDIUM, linestyle='--', linewidth=1, alpha=0.3)
        else:
            ax.text(0.5, 0.5, 'No threat data available\nRun EDA & Training first',
                   transform=ax.transAxes, ha='center', va='center',
                   fontsize=12, color=TEXT_SECONDARY)
        
        ax.set_xlabel('Threat Score', color=TEXT_SECONDARY, fontsize=9)
        ax.set_ylabel('Users', color=TEXT_SECONDARY, fontsize=9)
        ax.tick_params(colors=TEXT_TERTIARY, labelsize=8)
        ax.spines['bottom'].set_color(BORDER_DEFAULT)
        ax.spines['left'].set_color(BORDER_DEFAULT)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        fig.tight_layout(pad=1.5)
        
        canvas = FigureCanvasTkAgg(fig, chart_card)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=5, pady=(0, 5))
        self._charts['threat_dist'] = (fig, canvas)
    
    def _build_activity_chart(self, parent):
        """Build the threat category breakdown chart."""
        chart_card = tk.Frame(parent, bg=BG_SECONDARY,
                             highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        chart_card.pack(fill='both', expand=True, pady=(0, 0))
        
        header = tk.Frame(chart_card, bg=BG_SECONDARY)
        header.pack(fill='x', padx=10, pady=(8, 0))
        tk.Label(header, text='Threat Category Breakdown', font=FONT_SUBHEADING,
                bg=BG_SECONDARY, fg=ACCENT_PURPLE).pack(side='left')
        
        fig = Figure(figsize=(8, 3), dpi=100, facecolor=BG_SECONDARY)
        
        scores_df = self.analyzer.get_all_threat_scores()
        
        if len(scores_df) > 0:
            # Build category data
            categories = {}
            cat_map = {
                'After-Hours Activity': 'after_hours_logins',
                'USB Device Usage': 'usb_connects',
                'File Exfiltration': 'file_copy_count',
                'Shadow AI Usage': 'http_shadow_ai',
                'Cloud Storage': 'http_cloud_storage',
                'Job Site Visits': 'http_job_sites',
            }
            
            for label, col in cat_map.items():
                if col in scores_df.columns:
                    val = scores_df[col].sum()
                    if val > 0:
                        categories[label] = float(val)
            
            if categories:
                ax = fig.add_subplot(121)
                ax.set_facecolor(BG_SECONDARY)
                
                colors = [ACCENT_RED, ACCENT_PURPLE, ACCENT_ORANGE,
                         ACCENT_YELLOW, ACCENT_BLUE, ACCENT_GREEN]
                
                wedges, texts, autotexts = ax.pie(
                    list(categories.values()),
                    labels=None,
                    colors=colors[:len(categories)],
                    autopct='%1.1f%%',
                    startangle=90,
                    textprops={'color': TEXT_PRIMARY, 'fontsize': 8},
                    wedgeprops={'edgecolor': BG_SECONDARY, 'linewidth': 1.5},
                )
                
                # Legend
                ax2 = fig.add_subplot(122)
                ax2.axis('off')
                for i, (label, val) in enumerate(categories.items()):
                    color = colors[i % len(colors)]
                    ax2.text(0, 0.9 - i * 0.15, '●', color=color, fontsize=14,
                            transform=ax2.transAxes, va='center')
                    ax2.text(0.08, 0.9 - i * 0.15, f'{label}: {int(val):,}',
                            color=TEXT_PRIMARY, fontsize=9,
                            transform=ax2.transAxes, va='center')
            else:
                ax = fig.add_subplot(111)
                ax.text(0.5, 0.5, 'No category data available',
                       transform=ax.transAxes, ha='center', va='center',
                       fontsize=12, color=TEXT_SECONDARY)
                ax.set_facecolor(BG_SECONDARY)
                ax.axis('off')
        else:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No data — Run analysis pipeline',
                   transform=ax.transAxes, ha='center', va='center',
                   fontsize=12, color=TEXT_SECONDARY)
            ax.set_facecolor(BG_SECONDARY)
            ax.axis('off')
        
        fig.tight_layout(pad=1.5)
        
        canvas = FigureCanvasTkAgg(fig, chart_card)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=5, pady=(0, 5))
        self._charts['category'] = (fig, canvas)
    
    def _build_top_threats(self, parent):
        """Build the top threats panel."""
        card = tk.Frame(parent, bg=BG_SECONDARY,
                       highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        card.pack(fill='x', pady=(0, 5))
        
        header = tk.Frame(card, bg=BG_SECONDARY)
        header.pack(fill='x', padx=10, pady=(8, 5))
        tk.Label(header, text='Top Threats', font=FONT_SUBHEADING,
                bg=BG_SECONDARY, fg=ACCENT_RED).pack(side='left')
        
        # Top threats list
        top = self.analyzer.get_top_threats(10)
        
        if len(top) > 0:
            for _, row in top.iterrows():
                item_frame = tk.Frame(card, bg=BG_SECONDARY)
                item_frame.pack(fill='x', padx=10, pady=2)
                
                score = row.get('threat_score', 0)
                color = get_threat_color(score)
                level = get_threat_label(score)
                
                # Threat bar
                tk.Label(item_frame, text='●', font=(FONT_FAMILY, 8),
                        bg=BG_SECONDARY, fg=color).pack(side='left')
                tk.Label(item_frame, text=row['user'], font=FONT_BODY,
                        bg=BG_SECONDARY, fg=TEXT_PRIMARY).pack(side='left', padx=(5, 0))
                
                score_label = tk.Label(item_frame, text=f'{score:.0f}',
                                      font=FONT_BODY_BOLD, bg=BG_SECONDARY, fg=color)
                score_label.pack(side='right')
                
                tk.Label(item_frame, text=level, font=FONT_TINY,
                        bg=BG_SECONDARY, fg=color).pack(side='right', padx=(0, 8))
        else:
            tk.Label(card, text='No threat data available',
                    font=FONT_BODY, bg=BG_SECONDARY, fg=TEXT_SECONDARY).pack(pady=20)
        
        # Bottom padding
        tk.Frame(card, bg=BG_SECONDARY, height=8).pack()
    
    def _build_alerts_panel(self, parent):
        """Build the recent alerts panel."""
        card = tk.Frame(parent, bg=BG_SECONDARY,
                       highlightbackground=BORDER_DEFAULT, highlightthickness=1)
        card.pack(fill='both', expand=True)
        
        header = tk.Frame(card, bg=BG_SECONDARY)
        header.pack(fill='x', padx=10, pady=(8, 5))
        tk.Label(header, text='Recent Alerts', font=FONT_SUBHEADING,
                bg=BG_SECONDARY, fg=ACCENT_YELLOW).pack(side='left')
        
        count = self.alerts.get_total_unresolved()
        if count > 0:
            tk.Label(header, text=str(count), font=FONT_BODY_BOLD,
                    bg=ACCENT_RED, fg='white', padx=6, pady=1).pack(side='right')
        
        # Alerts list
        alerts_list = self.alerts.get_alerts(limit=8)
        
        if alerts_list:
            for alert in alerts_list:
                alert_frame = tk.Frame(card, bg=BG_SECONDARY)
                alert_frame.pack(fill='x', padx=10, pady=2)
                
                severity = alert['severity']
                color = AlertManager.SEVERITY_COLORS.get(severity, TEXT_SECONDARY)
                icon = AlertManager.SEVERITY_ICONS.get(severity, '⚪')
                
                icon_lbl = tk.Label(alert_frame, text=icon, font=FONT_SMALL,
                        bg=BG_SECONDARY)
                icon_lbl.pack(side='left')
                
                msg_label = tk.Label(alert_frame, text=alert['message'],
                                   font=FONT_SMALL, bg=BG_SECONDARY, fg=TEXT_PRIMARY,
                                   wraplength=270, anchor='w', justify='left')
                msg_label.pack(side='left', padx=(5, 0), fill='x', expand=True)
                
                resolved_lbl = None
                if alert['resolved']:
                    resolved_lbl = tk.Label(alert_frame, text='✓', font=FONT_SMALL,
                            bg=BG_SECONDARY, fg=ACCENT_GREEN)
                    resolved_lbl.pack(side='right')
                
                if self.on_alert_click:
                    alert_frame.configure(cursor='hand2')
                    icon_lbl.configure(cursor='hand2')
                    msg_label.configure(cursor='hand2')
                    
                    alert_frame.bind('<Button-1>', lambda e, a=alert: self.on_alert_click(a))
                    icon_lbl.bind('<Button-1>', lambda e, a=alert: self.on_alert_click(a))
                    msg_label.bind('<Button-1>', lambda e, a=alert: self.on_alert_click(a))
                    if resolved_lbl:
                        resolved_lbl.configure(cursor='hand2')
                        resolved_lbl.bind('<Button-1>', lambda e, a=alert: self.on_alert_click(a))
        else:
            tk.Label(card, text='No active alerts',
                    font=FONT_BODY, bg=BG_SECONDARY, fg=ACCENT_GREEN).pack(pady=20)
        
        tk.Frame(card, bg=BG_SECONDARY, height=8).pack()
    
    def refresh(self):
        """Refresh the dashboard data."""
        if self.frame:
            for widget in self.frame.winfo_children():
                widget.destroy()
            self.build()


# Import AlertManager for reference in _build_alerts_panel
from app.alerts import AlertManager
