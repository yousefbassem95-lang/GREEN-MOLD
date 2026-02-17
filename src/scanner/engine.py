"""
Core scanning engine for Green Mold Cure.
Handles file traversal, hashing, and scan orchestration.
"""

import os
import hashlib
from pathlib import Path
from typing import Callable, Optional, Iterator
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone
import fnmatch

from utils.platform import platform_info
from utils.logger import logger
from config.settings import settings


class ScanStatus(Enum):
    """Scan result status."""
    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"
    SKIPPED = "skipped"


class Severity(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanResult:
    """Result of scanning a single file."""
    file_path: Path
    status: ScanStatus
    threat_name: Optional[str] = None
    severity: Severity = Severity.LOW
    error_message: Optional[str] = None
    scan_time: float = 0.0
    file_hash: Optional[str] = None
    action_taken: Optional[str] = None


@dataclass
class ScanSummary:
    """Summary of a complete scan operation."""
    total_files: int = 0
    scanned_files: int = 0
    infected_files: int = 0
    clean_files: int = 0
    error_files: int = 0
    skipped_files: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    results: list[ScanResult] = None
    
    def __post_init__(self):
        if self.results is None:
            self.results = []
    
    @property
    def duration(self) -> float:
        """Get scan duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def infection_rate(self) -> float:
        """Get infection rate as percentage."""
        if self.scanned_files == 0:
            return 0.0
        return (self.infected_files / self.scanned_files) * 100


class ScannerEngine:
    """
    Core scanning engine for Green Mold Cure.
    
    Features:
    - File traversal with exclusion patterns
    - File hashing (SHA-256)
    - Signature matching
    - Progress reporting via callbacks
    """
    
    # File extensions to skip by default
    SKIP_EXTENSIONS = {
        '.sys', '.drv', '.dll',  # System files (can be optionally scanned)
        '.lock', '.tmp', '.temp',  # Temporary files
    }
    
    # Maximum file size to scan (default 100 MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024
    
    def __init__(self):
        """Initialize the scanner engine."""
        self.signature_database = None
        self.excluded_patterns = []
        self.max_file_size = self.MAX_FILE_SIZE
        self.scan_archives = False
        self.follow_symlinks = False
        self._stop_requested = False
    
    def load_settings(self) -> None:
        """Load scanner settings from configuration."""
        self.max_file_size = settings.get("scan.max_file_size_mb", 100) * 1024 * 1024
        self.scan_archives = settings.get("scan.scan_archives", True)
        self.follow_symlinks = settings.get("scan.follow_symlinks", False)
        self.excluded_patterns = settings.get("scan.exclude_patterns", [])
    
    def set_signature_database(self, database) -> None:
        """
        Set the signature database for threat detection.
        
        Args:
            database: Signature database instance
        """
        self.signature_database = database
    
    def request_stop(self) -> None:
        """Request the scanner to stop gracefully."""
        self._stop_requested = True
    
    def reset_stop(self) -> None:
        """Reset the stop flag for a new scan."""
        self._stop_requested = False
    
    def should_skip_file(self, file_path: Path) -> bool:
        """
        Check if a file should be skipped.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file should be skipped
        """
        # Check exclusion patterns
        file_str = str(file_path)
        for pattern in self.excluded_patterns:
            if fnmatch.fnmatch(file_str, pattern) or fnmatch.fnmatch(file_path.name, pattern):
                return True
        
        # Check file extension
        if file_path.suffix.lower() in self.SKIP_EXTENSIONS:
            return True
        
        # Check file size
        try:
            if file_path.stat().st_size > self.max_file_size:
                return True
        except OSError:
            return True
        
        return False
    
    def get_file_hash(self, file_path: Path) -> Optional[str]:
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Hex-encoded hash or None on error
        """
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash file {file_path}: {e}")
            return None
    
    def traverse_path(
        self,
        path: Path,
        progress_callback: Optional[Callable[[Path], None]] = None,
    ) -> Iterator[Path]:
        """
        Traverse a path and yield files.

        Args:
            path: Path to traverse (file or directory)
            progress_callback: Optional callback for progress reporting

        Yields:
            Path to each file
        """
        if self._stop_requested:
            return

        if path.is_file():
            if not self.should_skip_file(path):
                yield path
        elif path.is_dir():
            try:
                for item in path.iterdir():
                    if self._stop_requested:
                        return

                    try:
                        # Note: follow_symlinks parameter not available in Python < 3.13
                        if item.is_file():
                            if not self.should_skip_file(item):
                                if progress_callback:
                                    progress_callback(item)
                                yield item
                        elif item.is_dir():
                            yield from self.traverse_path(item, progress_callback)
                    except PermissionError:
                        continue
                    except Exception as e:
                        logger.debug(f"Error accessing {item}: {e}")
            except PermissionError:
                pass
            except Exception as e:
                logger.debug(f"Error traversing {path}: {e}")
    
    def scan_file(self, file_path: Path) -> ScanResult:
        """
        Scan a single file for threats.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Scan result
        """
        import time
        start_time = time.time()
        
        # Check if file should be skipped
        if self.should_skip_file(file_path):
            return ScanResult(
                file_path=file_path,
                status=ScanStatus.SKIPPED,
                error_message="File skipped (size or exclusion pattern)",
            )
        
        # Calculate file hash
        file_hash = self.get_file_hash(file_path)
        
        if file_hash is None:
            return ScanResult(
                file_path=file_path,
                status=ScanStatus.ERROR,
                error_message="Failed to read file",
            )
        
        # Check against signature database
        threat_info = None
        if self.signature_database:
            threat_info = self.signature_database.check_hash(file_hash)
        
        # Determine result
        if threat_info:
            result = ScanResult(
                file_path=file_path,
                status=ScanStatus.INFECTED,
                threat_name=threat_info.get("name", "Unknown Threat"),
                severity=Severity(threat_info.get("severity", "medium")),
                file_hash=file_hash,
                scan_time=time.time() - start_time,
            )
            logger.scan_result(
                str(file_path),
                "infected",
                threat_name=result.threat_name,
                severity=result.severity.value,
            )
        else:
            result = ScanResult(
                file_path=file_path,
                status=ScanStatus.CLEAN,
                file_hash=file_hash,
                scan_time=time.time() - start_time,
            )
            logger.scan_result(str(file_path), "clean")
        
        return result
    
    def scan(
        self,
        paths: list[Path],
        result_callback: Optional[Callable[[ScanResult], None]] = None,
        progress_callback: Optional[Callable[[Path, int], None]] = None,
    ) -> ScanSummary:
        """
        Scan multiple paths for threats.
        
        Args:
            paths: List of paths to scan
            result_callback: Optional callback for each scan result
            progress_callback: Optional callback for progress (path, count)
            
        Returns:
            Scan summary
        """
        self.reset_stop()
        self.load_settings()
        
        summary = ScanSummary(
            start_time=datetime.now(timezone.utc),
            results=[],
        )
        
        file_count = 0
        
        for scan_path in paths:
            if self._stop_requested:
                break
            
            for file_path in self.traverse_path(scan_path):
                if self._stop_requested:
                    break
                
                file_count += 1
                summary.total_files = file_count
                
                if progress_callback:
                    progress_callback(file_path, file_count)
                
                result = self.scan_file(file_path)
                summary.results.append(result)
                summary.scanned_files += 1
                
                # Update counters
                match result.status:
                    case ScanStatus.CLEAN:
                        summary.clean_files += 1
                    case ScanStatus.INFECTED:
                        summary.infected_files += 1
                    case ScanStatus.ERROR:
                        summary.error_files += 1
                    case ScanStatus.SKIPPED:
                        summary.skipped_files += 1
                
                # Call result callback
                if result_callback:
                    result_callback(result)
        
        summary.end_time = datetime.now(timezone.utc)
        
        logger.info(
            f"Scan complete: {summary.scanned_files} files, "
            f"{summary.infected_files} infected, "
            f"{summary.clean_files} clean",
            total_files=summary.total_files,
            infected_files=summary.infected_files,
            clean_files=summary.clean_files,
            duration=summary.duration,
        )
        
        return summary
    
    def quick_scan(
        self,
        result_callback: Optional[Callable[[ScanResult], None]] = None,
        progress_callback: Optional[Callable[[Path, int], None]] = None,
    ) -> ScanSummary:
        """
        Perform a quick scan of common malware locations.
        
        Args:
            result_callback: Optional callback for each scan result
            progress_callback: Optional callback for progress
            
        Returns:
            Scan summary
        """
        common_paths = platform_info.get_common_malware_paths()
        return self.scan(common_paths, result_callback, progress_callback)
    
    def full_system_scan(
        self,
        result_callback: Optional[Callable[[ScanResult], None]] = None,
        progress_callback: Optional[Callable[[Path, int], None]] = None,
    ) -> ScanSummary:
        """
        Perform a full system scan.
        
        Args:
            result_callback: Optional callback for each scan result
            progress_callback: Optional callback for progress
            
        Returns:
            Scan summary
        """
        system_root = platform_info.get_system_root()
        return self.scan([system_root], result_callback, progress_callback)


# Global scanner instance
scanner = ScannerEngine()
