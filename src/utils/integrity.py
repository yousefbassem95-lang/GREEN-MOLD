import os
import hashlib
import json
import time
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from utils.logger import logger
from utils.platform import platform_info

class IntegrityEventHandler(FileSystemEventHandler):
    """Handles real-time file system events for integrity monitoring."""

    def __init__(self, monitor: 'IntegrityMonitor'):
        self.monitor = monitor

    def on_modified(self, event):
        if not event.is_directory:
            self.monitor.handle_tampering(event.src_path, "modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self.monitor.handle_tampering(event.src_path, "deleted")

    def on_created(self, event):
        if not event.is_directory:
            self.monitor.handle_tampering(event.src_path, "created")

class IntegrityMonitor:
    """
    Maintains system integrity by monitoring file changes against a baseline.
    """

    def __init__(self, root_dir: Optional[Path] = None):
        self.root_dir = root_dir or Path(__file__).parent.parent.parent
        self.db_path = platform_info.get_app_data_dir() / "integrity_baseline.json"
        self.backup_dir = platform_info.get_app_data_dir() / "integrity_backups"
        self.ignore_dirs = {".git", "__pycache__", "node_modules", ".idea", ".vscode", "dist", "build", ".pytest_cache"}
        self.observer = None
        self._baseline_cache: Dict[str, str] = {}

        # Ensure backup directory exists
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def calculate_hash(self, filepath: Path) -> Optional[str]:
        """Calculates SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.debug(f"Failed to calculate hash for {filepath}: {e}")
            return None

    def scan_directory(self) -> Dict[str, str]:
        """Scans the directory and returns a map of file paths to hashes."""
        snapshot = {}
        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]

            for file in files:
                filepath = Path(root) / file
                # Don't monitor the database itself or log files
                if "integrity_baseline.json" in file or ".log" in file:
                    continue

                rel_path = str(filepath.relative_to(self.root_dir))
                file_hash = self.calculate_hash(filepath)
                if file_hash:
                    snapshot[rel_path] = file_hash
        return snapshot

    def create_baseline(self):
        """Creates a new baseline and backs up core files."""
        logger.info("Creating new integrity baseline...")
        snapshot = self.scan_directory()
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "root_dir": str(self.root_dir),
            "files": snapshot
        }

        with open(self.db_path, "w") as f:
            json.dump(data, f, indent=4)

        self._baseline_cache = snapshot

        # Backup core files for recovery
        self._backup_core_files(snapshot.keys())

        logger.info(f"Integrity baseline secured. Monitoring {len(snapshot)} files.")

    def _backup_core_files(self, rel_paths: List[str]):
        """Backs up files to a secure location for recovery."""
        for rel_path in rel_paths:
            src = self.root_dir / rel_path
            dst = self.backup_dir / rel_path

            if src.is_file():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)

    def load_baseline(self) -> bool:
        """Loads the baseline from disk."""
        if not self.db_path.exists():
            return False

        try:
            with open(self.db_path, "r") as f:
                data = json.load(f)
                self._baseline_cache = data.get("files", {})
            return True
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return False

    def check_integrity(self) -> bool:
        """Checks current system state against baseline."""
        if not self._baseline_cache and not self.load_baseline():
            logger.warning("No integrity baseline found. System may be vulnerable.")
            return True # Assume OK if no baseline, but log warning

        current_files = self.scan_directory()
        breach_detected = False

        # Check for modified or deleted files
        for rel_path, stored_hash in self._baseline_cache.items():
            if rel_path not in current_files:
                logger.security(f"Integrity Breach: File DELETED -> {rel_path}", event_type="integrity_breach")
                breach_detected = True
            elif current_files[rel_path] != stored_hash:
                logger.security(f"Integrity Breach: File MODIFIED -> {rel_path}", event_type="integrity_breach")
                breach_detected = True

        # Check for new files
        for rel_path in current_files:
            if rel_path not in self._baseline_cache:
                logger.security(f"Integrity Warning: New File Detected -> {rel_path}", event_type="integrity_warning")
                # breach_detected = True # New files are warnings, not necessarily breaches

        return not breach_detected

    def handle_tampering(self, filepath_str: str, change_type: str):
        """Responds to real-time tampering events."""
        filepath = Path(filepath_str)
        try:
            rel_path = str(filepath.relative_to(self.root_dir))
        except ValueError:
            return # Path outside root

        # Ignore changes to ignored directories
        if any(ignored in rel_path for ignored in self.ignore_dirs):
            return

        logger.security(f"Real-time Tampering Detected: {rel_path} was {change_type}",
                       event_type="tampering_detected",
                       change_type=change_type)

        if change_type in ["modified", "deleted"]:
            self.restore_file(rel_path)

    def restore_file(self, rel_path: str) -> bool:
        """Restores a file from the secure backup."""
        backup_path = self.backup_dir / rel_path
        target_path = self.root_dir / rel_path

        if backup_path.exists():
            logger.info(f"Attempting auto-recovery for {rel_path}...")
            try:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup_path, target_path)
                logger.security(f"Auto-recovery SUCCESS: Restored {rel_path}", event_type="auto_recovery")
                return True
            except Exception as e:
                logger.error(f"Auto-recovery FAILED for {rel_path}: {e}")
        else:
            logger.warning(f"Auto-recovery FAILED: No backup found for {rel_path}")

        return False

    def start_monitoring(self):
        """Starts real-time file system monitoring."""
        if self.observer:
            return

        self.observer = Observer()
        event_handler = IntegrityEventHandler(self)
        self.observer.schedule(event_handler, str(self.root_dir), recursive=True)
        self.observer.start()
        logger.info(f"Real-time integrity monitoring started on {self.root_dir}")

    def stop_monitoring(self):
        """Stops real-time file system monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            logger.info("Real-time integrity monitoring stopped.")

# Global integrity monitor instance
integrity_monitor = IntegrityMonitor()
