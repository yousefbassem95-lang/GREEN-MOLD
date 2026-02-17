"""
Real-time Protection for Green Mold Cure.
Continuous file system monitoring with automatic threat detection.

Features:
- File system event monitoring (create, modify, delete)
- Automatic scanning of new/modified files
- Background daemon/service mode
- Configurable watch paths
- Real-time alerts and notifications
"""

import os
import sys
import time
import json
import threading
import signal
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent, FileMovedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = object

from utils.logger import logger
from utils.platform import platform_info
from config.settings import settings
from scanner.enhanced_engine import enhanced_scanner, ScanResult, ScanStatus
from quarantine.manager import quarantine_manager


class ProtectionStatus(Enum):
    """Real-time protection status."""
    RUNNING = "running"
    STOPPED = "stopped"
    PAUSED = "paused"
    ERROR = "error"


@dataclass
class ProtectionEvent:
    """Event recorded by real-time protection."""
    timestamp: datetime
    event_type: str  # created, modified, moved, deleted
    file_path: str
    scan_result: Optional[ScanResult]
    action_taken: str  # none, quarantine, alert, blocked
    details: str


class ThreatHandler(FileSystemEventHandler):
    """
    File system event handler for threat detection.
    
    Monitors file system events and scans new/modified files.
    """
    
    def __init__(
        self,
        scan_callback: Optional[Callable[[ScanResult], None]] = None,
        alert_callback: Optional[Callable[[ProtectionEvent], None]] = None,
    ):
        """
        Initialize the threat handler.
        
        Args:
            scan_callback: Callback for scan results
            alert_callback: Callback for protection events
        """
        super().__init__()
        self.scan_callback = scan_callback
        self.alert_callback = alert_callback
        self.events: List[ProtectionEvent] = []
        self._scan_queue: List[Path] = []
        self._lock = threading.Lock()
        self._auto_quarantine = settings.get("quarantine.auto_quarantine", False)
    
    def _should_scan(self, path: str) -> bool:
        """Check if a file should be scanned."""
        path_lower = path.lower()
        
        # Skip system directories
        skip_dirs = [
            '/proc/', '/sys/', '/dev/',
            'c:\\windows\\winsxs',
            '/node_modules/',
        ]
        
        for skip in skip_dirs:
            if skip in path_lower:
                return False
        
        # Only scan certain file types
        scan_extensions = {
            '.exe', '.dll', '.sys', '.drv', '.scr', '.com', '.pif',
            '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.ps1',
            '.msi', '.msp', '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',
            '.pdf', '.zip', '.rar', '.7z', '.gz',
            '.lnk', '.reg', '.hta', '.wsf', '.wsc', '.wsh',
        }
        
        path_obj = Path(path)
        return path_obj.suffix.lower() in scan_extensions
    
    def _queue_scan(self, path: str) -> None:
        """Queue a file for scanning."""
        if self._should_scan(path):
            with self._lock:
                self._scan_queue.append(Path(path))
    
    def _process_queue(self) -> None:
        """Process queued scans."""
        with self._lock:
            paths = self._scan_queue.copy()
            self._scan_queue.clear()
        
        for path in paths:
            if path.exists():
                self._scan_file(path)
    
    def _scan_file(self, file_path: Path) -> None:
        """
        Scan a file and handle results.
        
        Args:
            file_path: Path to scan
        """
        try:
            result = enhanced_scanner.scan_file(file_path)
            
            # Create protection event
            event = ProtectionEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="scan",
                file_path=str(file_path),
                scan_result=result,
                action_taken="none",
                details=f"Scan status: {result.status.value}"
            )
            
            # Handle based on result
            if result.status == ScanStatus.INFECTED:
                if self._auto_quarantine:
                    entry = quarantine_manager.quarantine_file(
                        file_path,
                        result.threat_name or "Unknown",
                        result.file_hash or "",
                    )
                    if entry:
                        event.action_taken = "quarantine"
                        event.details = f"Automatically quarantined: {result.threat_name}"
                        logger.security(f"Auto-quarantined: {file_path} - {result.threat_name}")
                else:
                    event.action_taken = "alert"
                    event.details = f"THREAT DETECTED: {result.threat_name}"
                    logger.security(f"Threat detected (manual action required): {file_path}")
            
            self.events.append(event)
            
            if self.alert_callback:
                self.alert_callback(event)
            
            if self.scan_callback:
                self.scan_callback(result)
                
        except Exception as e:
            logger.debug(f"Real-time scan error for {file_path}: {e}")
    
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            logger.debug(f"File created: {event.src_path}")
            self._queue_scan(event.src_path)
            self._process_queue()
    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            logger.debug(f"File modified: {event.src_path}")
            self._queue_scan(event.src_path)
            self._process_queue()
    
    def on_moved(self, event):
        """Handle file move events."""
        if not event.is_directory:
            logger.debug(f"File moved: {event.src_path} -> {event.dest_path}")
            self._queue_scan(event.dest_path)
            self._process_queue()


class RealTimeProtection:
    """
    Real-time file system protection service.
    
    Features:
    - Monitor multiple directories
    - Automatic threat scanning
    - Configurable auto-quarantine
    - Background operation
    - Event logging
    """
    
    # Default directories to monitor
    DEFAULT_WATCH_PATHS = {
        'linux': [
            str(Path.home() / 'Downloads'),
            str(Path.home() / 'Desktop'),
            '/tmp',
            '/var/tmp',
        ],
        'windows': [
            str(Path.home() / 'Downloads'),
            str(Path.home() / 'Desktop'),
            os.environ.get('TEMP', 'C:\\Windows\\Temp'),
        ],
        'macos': [
            str(Path.home() / 'Downloads'),
            str(Path.home() / 'Desktop'),
            '/tmp',
        ],
    }
    
    def __init__(self):
        """Initialize real-time protection."""
        self.status = ProtectionStatus.STOPPED
        self.observer: Optional[Observer] = None
        self.handler: Optional[ThreatHandler] = None
        self.watch_paths: List[str] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.events: List[ProtectionEvent] = []
        
        # Load watch paths from settings or use defaults
        self._load_watch_paths()
    
    def _load_watch_paths(self) -> None:
        """Load watch paths from settings or use defaults."""
        saved_paths = settings.get("realtime.watch_paths", [])
        
        if saved_paths:
            self.watch_paths = saved_paths
        else:
            # Use platform-specific defaults
            if platform_info.is_windows:
                self.watch_paths = self.DEFAULT_WATCH_PATHS['windows']
            elif platform_info.is_macos:
                self.watch_paths = self.DEFAULT_WATCH_PATHS['macos']
            else:
                self.watch_paths = self.DEFAULT_WATCH_PATHS['linux']
    
    def _on_alert(self, event: ProtectionEvent) -> None:
        """Handle protection alerts."""
        self.events.append(event)
        
        if event.action_taken == "quarantine":
            logger.info(f"🛡️ Real-time Protection: Quarantined {event.file_path}")
        elif event.action_taken == "alert":
            logger.warning(f"⚠️ Real-time Protection: Threat detected in {event.file_path}")
    
    def start(self, background: bool = False) -> bool:
        """
        Start real-time protection.
        
        Args:
            background: Run in background thread
            
        Returns:
            True if started successfully
        """
        if not WATCHDOG_AVAILABLE:
            logger.error("Real-time protection unavailable: watchdog not installed")
            self.status = ProtectionStatus.ERROR
            return False
        
        if self.status == ProtectionStatus.RUNNING:
            logger.warning("Real-time protection already running")
            return True
        
        try:
            # Create handler and observer
            self.handler = ThreatHandler(alert_callback=self._on_alert)
            self.observer = Observer()
            
            # Add watch paths
            for path_str in self.watch_paths:
                path = Path(path_str)
                if path.exists() and path.is_dir():
                    self.observer.schedule(self.handler, path_str, recursive=False)
                    logger.info(f"Watching: {path_str}")
                else:
                    logger.warning(f"Watch path does not exist: {path_str}")
            
            # Start observer
            self.observer.start()
            self.status = ProtectionStatus.RUNNING
            
            logger.info("Real-time protection started")
            
            if background:
                self._start_background_thread()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start real-time protection: {e}")
            self.status = ProtectionStatus.ERROR
            return False
    
    def _start_background_thread(self) -> None:
        """Start background monitoring thread."""
        def monitor():
            while not self._stop_event.is_set():
                time.sleep(1)
        
        self._thread = threading.Thread(target=monitor, daemon=True)
        self._thread.start()
    
    def stop(self) -> None:
        """Stop real-time protection."""
        if self.status != ProtectionStatus.RUNNING:
            return
        
        self._stop_event.set()
        
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        
        self.status = ProtectionStatus.STOPPED
        logger.info("Real-time protection stopped")
    
    def pause(self) -> None:
        """Pause real-time protection."""
        if self.status == ProtectionStatus.RUNNING:
            if self.observer:
                self.observer.unschedule_all()
            self.status = ProtectionStatus.PAUSED
            logger.info("Real-time protection paused")
    
    def resume(self) -> None:
        """Resume real-time protection."""
        if self.status == ProtectionStatus.PAUSED:
            self.start()
    
    def add_watch_path(self, path: str) -> bool:
        """
        Add a path to watch.
        
        Args:
            path: Path to add
            
        Returns:
            True if added successfully
        """
        path_obj = Path(path)
        
        if not path_obj.exists():
            logger.warning(f"Cannot watch non-existent path: {path}")
            return False
        
        if path not in self.watch_paths:
            self.watch_paths.append(path)
            settings.set("realtime.watch_paths", self.watch_paths)
            settings.save()
            
            if self.status == ProtectionStatus.RUNNING and self.observer and self.handler:
                self.observer.schedule(self.handler, path, recursive=False)
                logger.info(f"Added watch path: {path}")
            
            return True
        
        return False
    
    def remove_watch_path(self, path: str) -> bool:
        """
        Remove a path from watch list.
        
        Args:
            path: Path to remove
            
        Returns:
            True if removed successfully
        """
        if path in self.watch_paths:
            self.watch_paths.remove(path)
            settings.set("realtime.watch_paths", self.watch_paths)
            settings.save()
            
            if self.status == ProtectionStatus.RUNNING and self.observer:
                self.observer.unschedule_all()
                # Re-schedule remaining paths
                if self.handler:
                    for p in self.watch_paths:
                        self.observer.schedule(self.handler, p, recursive=False)
            
            logger.info(f"Removed watch path: {path}")
            return True
        
        return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get real-time protection status."""
        return {
            'status': self.status.value,
            'watch_paths': self.watch_paths,
            'events_count': len(self.events),
            'available': WATCHDOG_AVAILABLE,
            'auto_quarantine': settings.get("quarantine.auto_quarantine", False),
            'recent_events': [
                {
                    'timestamp': e.timestamp.isoformat(),
                    'type': e.event_type,
                    'file': e.file_path,
                    'action': e.action_taken,
                }
                for e in self.events[-10:]  # Last 10 events
            ]
        }
    
    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get protection events."""
        return [
            {
                'timestamp': e.timestamp.isoformat(),
                'type': e.event_type,
                'file': e.file_path,
                'action': e.action_taken,
                'details': e.details,
            }
            for e in self.events[-limit:]
        ]
    
    def clear_events(self) -> None:
        """Clear event history."""
        self.events.clear()
        logger.info("Real-time protection events cleared")


class ProtectionDaemon:
    """
    Daemon/service manager for real-time protection.
    
    Handles running Green Mold Cure as a background service.
    """
    
    def __init__(self):
        """Initialize the daemon manager."""
        self.protection = RealTimeProtection()
        self.pid_file = platform_info.get_app_data_dir() / "protection.pid"
        self.log_file = platform_info.get_logs_dir() / "protection.log"
    
    def start_daemon(self) -> bool:
        """
        Start protection as daemon/service.
        
        Returns:
            True if started successfully
        """
        if not WATCHDOG_AVAILABLE:
            logger.error("Cannot start daemon: watchdog not installed")
            return False
        
        # Check if already running
        if self.pid_file.exists():
            try:
                with open(self.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                # Check if process is running
                os.kill(pid, 0)
                logger.warning(f"Protection daemon already running (PID: {pid})")
                return False
            except (OSError, ValueError):
                # Stale PID file
                self.pid_file.unlink()
        
        # Write PID file
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.pid_file, 'w') as f:
            f.write(str(os.getpid()))
        
        # Start protection
        return self.protection.start(background=True)
    
    def stop_daemon(self) -> bool:
        """
        Stop protection daemon/service.
        
        Returns:
            True if stopped successfully
        """
        self.protection.stop()
        
        if self.pid_file.exists():
            self.pid_file.unlink()
        
        logger.info("Protection daemon stopped")
        return True
    
    def is_running(self) -> bool:
        """Check if daemon is running."""
        if not self.pid_file.exists():
            return False
        
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False
    
    def get_pid(self) -> Optional[int]:
        """Get daemon PID."""
        if self.pid_file.exists():
            try:
                with open(self.pid_file, 'r') as f:
                    return int(f.read().strip())
            except ValueError:
                pass
        return None


# Global real-time protection instance
realtime_protection = RealTimeProtection()
protection_daemon = ProtectionDaemon()
