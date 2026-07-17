"""
DefendX — Alert Management System
Manages threat alerts with severity levels, history, and notification support.
"""

from datetime import datetime
from collections import deque


class AlertManager:
    """
    Manages security alerts with severity classification,
    history tracking, and filtering capabilities.
    """
    
    SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    SEVERITY_COLORS = {
        'CRITICAL': '#ff0000',
        'HIGH': '#ff4444',
        'MEDIUM': '#f59e0b',
        'LOW': '#10b981',
        'INFO': '#58a6ff',
    }
    SEVERITY_ICONS = {
        'CRITICAL': '[CRITICAL]',
        'HIGH': '[HIGH]',
        'MEDIUM': '[WARN]',
        'LOW': '[INFO]',
        'INFO': '[INFO]',
    }
    
    def __init__(self, max_history: int = 500):
        self.alerts = deque(maxlen=max_history)
        self._callbacks = []
        self._next_id = 1
    
    def add_alert(self, severity: str, source: str, message: str,
                  details: str = '', user_id: str = '') -> dict:
        """Add a new alert to the system."""
        severity = severity.upper()
        if severity not in self.SEVERITY_LEVELS:
            severity = 'INFO'
        
        alert = {
            'id': self._next_id,
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'source': source,
            'message': message,
            'details': details,
            'user_id': user_id,
            'resolved': False,
            'resolved_at': None,
            'resolved_by': None,
        }
        
        self._next_id += 1
        self.alerts.appendleft(alert)
        
        # Notify callbacks
        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass
        
        return alert
    
    def resolve_alert(self, alert_id: int, resolved_by: str = 'Admin'):
        """Mark an alert as resolved."""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['resolved'] = True
                alert['resolved_at'] = datetime.now().isoformat()
                alert['resolved_by'] = resolved_by
                return True
        return False
    
    def get_alerts(self, severity: str = None, resolved: bool = None,
                   limit: int = 50) -> list:
        """Get filtered alerts."""
        filtered = list(self.alerts)
        
        if severity:
            filtered = [a for a in filtered if a['severity'] == severity.upper()]
        
        if resolved is not None:
            filtered = [a for a in filtered if a['resolved'] == resolved]
        
        return filtered[:limit]
    
    def get_unresolved_count(self) -> dict:
        """Get count of unresolved alerts by severity."""
        counts = {level: 0 for level in self.SEVERITY_LEVELS}
        for alert in self.alerts:
            if not alert['resolved']:
                counts[alert['severity']] += 1
        return counts
    
    def get_total_unresolved(self) -> int:
        """Get total number of unresolved alerts."""
        return sum(1 for a in self.alerts if not a['resolved'])
    
    def register_callback(self, callback):
        """Register callback for new alerts."""
        self._callbacks.append(callback)
    
    def clear_all(self):
        """Clear all alerts."""
        self.alerts.clear()
    
    def generate_summary(self) -> str:
        """Generate a text summary of current alert status."""
        counts = self.get_unresolved_count()
        total = self.get_total_unresolved()
        
        lines = [
            f"Alert Summary — {total} Unresolved",
            "─" * 35,
        ]
        
        for level in self.SEVERITY_LEVELS:
            icon = self.SEVERITY_ICONS[level]
            count = counts[level]
            if count > 0:
                lines.append(f"  {icon} {level}: {count}")
        
        if total == 0:
            lines.append("  All clear — no active alerts")
        
        return '\n'.join(lines)
