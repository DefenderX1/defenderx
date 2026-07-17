"""
DefendX — System Monitor
Monitors local system for insider threat indicators:
- Google Chrome browsing history (shadow AI detection)
- VS Code workspace activity
- Local storage / USB device monitoring
"""

import os
import sys
import json
import sqlite3
import shutil
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path


class ChromeMonitor:
    """
    Monitors Google Chrome browsing history for shadow AI usage,
    suspicious domains, and data exfiltration indicators.
    """
    
    # Shadow AI / GenAI platforms
    SHADOW_AI_PATTERNS = [
        'chat.openai.com', 'chatgpt.com', 'openai.com',
        'claude.ai', 'anthropic.com',
        'gemini.google.com', 'bard.google.com',
        'copilot.microsoft.com', 'github.com/copilot',
        'huggingface.co', 'perplexity.ai',
        'poe.com', 'character.ai',
        'deepseek.com', 'groq.com',
        'together.ai', 'replicate.com',
        'colab.research.google.com',
    ]
    
    # Cloud storage / data sharing
    CLOUD_STORAGE_PATTERNS = [
        'drive.google.com', 'dropbox.com', 'onedrive.live.com',
        'box.com', 'mega.nz', 'wetransfer.com',
        'pastebin.com', 'hastebin.com', 'privatebin',
        'sendspace.com', 'mediafire.com',
    ]
    
    # Job sites (flight risk)
    JOB_SITE_PATTERNS = [
        'linkedin.com/jobs', 'indeed.com', 'glassdoor.com',
        'monster.com', 'ziprecruiter.com', 'dice.com',
    ]
    
    def __init__(self):
        self.history_path = self._find_chrome_history()
        self.last_check = datetime.now() - timedelta(hours=24)
        self.alerts = []
    
    def _find_chrome_history(self) -> str:
        """Find Chrome's History SQLite database."""
        if sys.platform == 'win32':
            base = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default')
        elif sys.platform == 'darwin':
            base = os.path.expanduser('~/Library/Application Support/Google/Chrome/Default')
        else:
            base = os.path.expanduser('~/.config/google-chrome/Default')
        
        history_path = os.path.join(base, 'History')
        return history_path if os.path.exists(history_path) else ''
    
    def check_history(self, hours_back: int = 24) -> dict:
        """
        Read Chrome browsing history and check for shadow AI usage.
        Copies the DB to avoid lock conflicts with Chrome.
        """
        results = {
            'status': 'ok',
            'shadow_ai': [],
            'cloud_storage': [],
            'job_sites': [],
            'total_urls': 0,
            'time_range': f'Last {hours_back} hours',
            'checked_at': datetime.now().isoformat(),
        }
        
        if not self.history_path:
            results['status'] = 'Chrome history not found'
            return results
        
        # Copy DB to temp file to avoid Chrome lock
        temp_db = None
        try:
            temp_dir = tempfile.mkdtemp()
            temp_db = os.path.join(temp_dir, 'History_copy')
            shutil.copy2(self.history_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Chrome timestamps are microseconds since 1601-01-01
            # Convert to Python datetime
            chrome_epoch = datetime(1601, 1, 1)
            cutoff = datetime.now() - timedelta(hours=hours_back)
            chrome_cutoff = int((cutoff - chrome_epoch).total_seconds() * 1_000_000)
            
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                WHERE last_visit_time > ?
                ORDER BY last_visit_time DESC
            """, (chrome_cutoff,))
            
            rows = cursor.fetchall()
            results['total_urls'] = len(rows)
            
            for url, title, visit_count, last_visit_time in rows:
                url_lower = url.lower()
                
                # Check shadow AI
                for pattern in self.SHADOW_AI_PATTERNS:
                    if pattern in url_lower:
                        visit_time = chrome_epoch + timedelta(microseconds=last_visit_time)
                        results['shadow_ai'].append({
                            'url': url,
                            'title': title or 'N/A',
                            'visits': visit_count,
                            'last_visit': visit_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'platform': pattern,
                        })
                        break
                
                # Check cloud storage
                for pattern in self.CLOUD_STORAGE_PATTERNS:
                    if pattern in url_lower:
                        visit_time = chrome_epoch + timedelta(microseconds=last_visit_time)
                        results['cloud_storage'].append({
                            'url': url,
                            'title': title or 'N/A',
                            'visits': visit_count,
                            'last_visit': visit_time.strftime('%Y-%m-%d %H:%M:%S'),
                        })
                        break
                
                # Check job sites
                for pattern in self.JOB_SITE_PATTERNS:
                    if pattern in url_lower:
                        visit_time = chrome_epoch + timedelta(microseconds=last_visit_time)
                        results['job_sites'].append({
                            'url': url,
                            'title': title or 'N/A',
                            'visits': visit_count,
                            'last_visit': visit_time.strftime('%Y-%m-%d %H:%M:%S'),
                        })
                        break
            
            conn.close()
            
        except Exception as e:
            results['status'] = f'Error: {str(e)}'
        finally:
            if temp_db and os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                    os.rmdir(os.path.dirname(temp_db))
                except Exception:
                    pass
        
        return results


class VSCodeMonitor:
    """
    Monitors VS Code workspace activity for suspicious patterns.
    Reads recent files and workspaces from VS Code's storage.
    """
    
    SENSITIVE_EXTENSIONS = [
        '.env', '.pem', '.key', '.cert', '.p12', '.pfx',
        '.sql', '.db', '.sqlite', '.bak',
        '.conf', '.cfg', '.ini', '.yml', '.yaml',
        '.csv', '.xls', '.xlsx', '.json',
    ]
    
    def __init__(self):
        self.storage_path = self._find_vscode_storage()
    
    def _find_vscode_storage(self) -> str:
        """Find VS Code's storage.json file."""
        if sys.platform == 'win32':
            base = os.path.expandvars(r'%APPDATA%\Code\User')
        elif sys.platform == 'darwin':
            base = os.path.expanduser('~/Library/Application Support/Code/User')
        else:
            base = os.path.expanduser('~/.config/Code/User')
        
        # Check for globalStorage
        storage = os.path.join(base, 'globalStorage', 'storage.json')
        if os.path.exists(storage):
            return storage
        
        # Alternative location
        storage = os.path.join(base, 'storage.json')
        return storage if os.path.exists(storage) else ''
    
    def check_recent_activity(self) -> dict:
        """Check VS Code recent workspaces and files."""
        results = {
            'status': 'ok',
            'recent_workspaces': [],
            'sensitive_files': [],
            'vscode_found': bool(self.storage_path),
            'checked_at': datetime.now().isoformat(),
        }
        
        if not self.storage_path:
            results['status'] = 'VS Code storage not found'
            return results
        
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract recent workspaces
            if 'openedPathsList' in data:
                paths_list = data['openedPathsList']
                if 'workspaces3' in paths_list:
                    for ws in paths_list['workspaces3'][:10]:
                        if isinstance(ws, dict):
                            path = ws.get('folderUri', ws.get('configPath', ''))
                        else:
                            path = str(ws)
                        results['recent_workspaces'].append(path)
                
                if 'entries' in paths_list:
                    for entry in paths_list['entries'][:10]:
                        if isinstance(entry, dict):
                            path = entry.get('folderUri', entry.get('fileUri', ''))
                        else:
                            path = str(entry)
                        if path and path not in results['recent_workspaces']:
                            results['recent_workspaces'].append(path)
            
        except Exception as e:
            results['status'] = f'Error: {str(e)}'
        
        return results


class StorageMonitor:
    """
    Monitors local file system for suspicious storage activity:
    - USB drive connections
    - Large file operations
    - Sensitive file access
    """
    
    def __init__(self):
        self.known_drives = set()
        self._update_drives()
    
    def _update_drives(self):
        """Get list of current drives on Windows."""
        if sys.platform == 'win32':
            import string
            self.known_drives = set()
            for letter in string.ascii_uppercase:
                drive = f'{letter}:\\'
                if os.path.exists(drive):
                    self.known_drives.add(drive)
    
    def check_drives(self) -> dict:
        """Check for new/removed drives (potential USB)."""
        results = {
            'status': 'ok',
            'current_drives': [],
            'new_drives': [],
            'removable_detected': False,
            'checked_at': datetime.now().isoformat(),
        }
        
        if sys.platform == 'win32':
            import string
            current = set()
            for letter in string.ascii_uppercase:
                drive = f'{letter}:\\'
                if os.path.exists(drive):
                    current.add(drive)
                    
                    # Get drive info
                    try:
                        total, used, free = shutil.disk_usage(drive)
                        results['current_drives'].append({
                            'drive': drive,
                            'total_gb': round(total / (1024**3), 1),
                            'used_gb': round(used / (1024**3), 1),
                            'free_gb': round(free / (1024**3), 1),
                            'usage_pct': round(used / total * 100, 1) if total > 0 else 0,
                        })
                    except Exception:
                        results['current_drives'].append({'drive': drive})
            
            new_drives = current - self.known_drives
            if new_drives:
                results['new_drives'] = list(new_drives)
                results['removable_detected'] = True
            
            self.known_drives = current
        
        return results
    
    def scan_recent_files(self, directory: str, hours_back: int = 24,
                          max_files: int = 100) -> list:
        """Scan for recently modified files in a directory."""
        cutoff = datetime.now() - timedelta(hours=hours_back)
        recent = []
        
        try:
            for root, dirs, files in os.walk(directory):
                for f in files:
                    if len(recent) >= max_files:
                        return recent
                    
                    fpath = os.path.join(root, f)
                    try:
                        mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
                        if mtime > cutoff:
                            size = os.path.getsize(fpath)
                            recent.append({
                                'path': fpath,
                                'size_bytes': size,
                                'modified': mtime.isoformat(),
                                'extension': os.path.splitext(f)[1].lower(),
                            })
                    except (OSError, PermissionError):
                        continue
        except Exception:
            pass
        
        return sorted(recent, key=lambda x: x['modified'], reverse=True)


class SystemMonitor:
    """Unified system monitoring interface."""
    
    def __init__(self):
        self.chrome = ChromeMonitor()
        self.vscode = VSCodeMonitor()
        self.storage = StorageMonitor()
        self._monitoring = False
        self._thread = None
        self._alerts = []
        self._callbacks = []
    
    def run_full_scan(self) -> dict:
        """Run all monitors and return combined results."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'chrome': self.chrome.check_history(),
            'vscode': self.vscode.check_recent_activity(),
            'storage': self.storage.check_drives(),
        }
        
        # Generate alerts from results
        self._generate_alerts(results)
        
        return results
    
    def _generate_alerts(self, results: dict):
        """Generate alerts from monitoring results."""
        ts = datetime.now().isoformat()
        
        # Chrome alerts
        chrome = results.get('chrome', {})
        if chrome.get('shadow_ai'):
            count = len(chrome['shadow_ai'])
            self._alerts.append({
                'timestamp': ts,
                'source': 'Chrome Monitor',
                'severity': 'HIGH',
                'message': f'Shadow AI usage detected: {count} platform(s) visited',
                'details': chrome['shadow_ai'],
            })
        
        if chrome.get('cloud_storage'):
            count = len(chrome['cloud_storage'])
            self._alerts.append({
                'timestamp': ts,
                'source': 'Chrome Monitor',
                'severity': 'MEDIUM',
                'message': f'Cloud storage access: {count} service(s) visited',
                'details': chrome['cloud_storage'],
            })
        
        # Storage alerts
        storage = results.get('storage', {})
        if storage.get('removable_detected'):
            self._alerts.append({
                'timestamp': ts,
                'source': 'Storage Monitor',
                'severity': 'HIGH',
                'message': f'New removable drive detected: {storage["new_drives"]}',
                'details': storage['new_drives'],
            })
        
        # Notify callbacks
        for cb in self._callbacks:
            try:
                cb(self._alerts[-1] if self._alerts else None)
            except Exception:
                pass
    
    def get_alerts(self) -> list:
        """Get all generated alerts."""
        return self._alerts.copy()
    
    def clear_alerts(self):
        """Clear all alerts."""
        self._alerts.clear()
    
    def register_callback(self, callback):
        """Register a callback for new alerts."""
        self._callbacks.append(callback)
    
    def start_background_monitoring(self, interval_seconds: int = 300):
        """Start background monitoring loop."""
        self._monitoring = True
        
        def monitor_loop():
            while self._monitoring:
                try:
                    self.run_full_scan()
                except Exception:
                    pass
                time.sleep(interval_seconds)
        
        self._thread = threading.Thread(target=monitor_loop, daemon=True)
        self._thread.start()
    
    def stop_background_monitoring(self):
        """Stop background monitoring."""
        self._monitoring = False
