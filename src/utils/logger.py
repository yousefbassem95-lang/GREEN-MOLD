"""
Structured logging for Green Mold Cure.
Provides observable, actionable logs for debugging and audits.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Any, Optional

from utils.platform import platform_info


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON."""
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "platform": platform_info.platform.value,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ("msg", "args", "levelname", "levelno", "pathname",
                          "filename", "module", "lineno", "funcName", "created",
                          "msecs", "relativeCreated", "thread", "threadName",
                          "processName", "process", "message", "exc_info",
                          "exc_text", "stack_info"):
                log_data[key] = value
        
        return json.dumps(log_data)


class GMCLogger:
    """
    Green Mold Cure logger with structured JSON output.
    
    Features:
    - JSON formatted logs for machine parsing
    - Rotating file handlers to manage disk space
    - Multiple log levels
    - Context-aware logging
    """
    
    def __init__(
        self,
        name: str = "green_mold_cure",
        log_dir: Optional[Path] = None,
        level: int = logging.INFO,
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 4,  # Keep 4 weeks of logs
    ):
        """
        Initialize the logger.
        
        Args:
            name: Logger name
            log_dir: Directory for log files
            level: Logging level
            max_bytes: Max size per log file before rotation
            backup_count: Number of backup files to keep
        """
        self.name = name
        self.log_dir = log_dir or platform_info.get_logs_dir()
        self.level = level
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        
        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self) -> None:
        """Set up file handlers with rotation."""
        # Main log file
        main_log = self.log_dir / "green_mold_cure.log"
        main_handler = RotatingFileHandler(
            main_log,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8",
        )
        main_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(main_handler)
        
        # Error log file (errors and critical only)
        error_log = self.log_dir / "errors.log"
        error_handler = RotatingFileHandler(
            error_log,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8",
        )
        error_handler.setFormatter(JSONFormatter())
        error_handler.setLevel(logging.ERROR)
        self.logger.addHandler(error_handler)
        
        # Security log file (for security-relevant events)
        security_log = self.log_dir / "security.log"
        security_handler = RotatingFileHandler(
            security_log,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8",
        )
        security_handler.setFormatter(JSONFormatter())
        security_handler.setLevel(logging.WARNING)
        self.logger.addHandler(security_handler)
    
    def _log(
        self,
        level: int,
        message: str,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Internal log method with extra context.
        
        Args:
            level: Log level
            message: Log message
            extra: Additional context data
        """
        self.logger.log(level, message, extra=extra or {})
    
    def debug(self, message: str, **kwargs: Any) -> None:
        """Log a debug message."""
        self._log(logging.DEBUG, message, kwargs if kwargs else None)
    
    def info(self, message: str, **kwargs: Any) -> None:
        """Log an info message."""
        self._log(logging.INFO, message, kwargs if kwargs else None)
    
    def warning(self, message: str, **kwargs: Any) -> None:
        """Log a warning message."""
        self._log(logging.WARNING, message, kwargs if kwargs else None)
    
    def error(self, message: str, **kwargs: Any) -> None:
        """Log an error message."""
        self._log(logging.ERROR, message, kwargs if kwargs else None)
    
    def critical(self, message: str, **kwargs: Any) -> None:
        """Log a critical message."""
        self._log(logging.CRITICAL, message, kwargs if kwargs else None)
    
    def security(self, message: str, **kwargs: Any) -> None:
        """
        Log a security-relevant event.
        
        Args:
            message: Security event message
            kwargs: Additional context
        """
        kwargs["security_event"] = True
        self._log(logging.WARNING, message, kwargs)
    
    def scan_result(
        self,
        file_path: str,
        status: str,
        threat_name: Optional[str] = None,
        severity: Optional[str] = None,
        action_taken: Optional[str] = None,
    ) -> None:
        """
        Log a scan result.
        
        Args:
            file_path: Path to scanned file
            status: Scan status (clean, infected, error, skipped)
            threat_name: Name of detected threat (if any)
            severity: Threat severity (if detected)
            action_taken: Action taken on threat
        """
        self.info(
            f"Scan result: {file_path} - {status}",
            file_path=file_path,
            status=status,
            threat_name=threat_name,
            severity=severity,
            action_taken=action_taken,
            event_type="scan_result",
        )
    
    def threat_detected(
        self,
        file_path: str,
        threat_name: str,
        severity: str,
        action: str,
    ) -> None:
        """
        Log a threat detection.
        
        Args:
            file_path: Path to infected file
            threat_name: Name of detected threat
            severity: Threat severity
            action: Action taken
        """
        self.security(
            f"Threat detected: {threat_name} in {file_path}",
            file_path=file_path,
            threat_name=threat_name,
            severity=severity,
            action=action,
            event_type="threat_detected",
        )
    
    def database_update(
        self,
        source: str,
        signatures_added: int,
        signatures_removed: int,
        success: bool,
    ) -> None:
        """
        Log a database update event.
        
        Args:
            source: Update source name
            signatures_added: Number of new signatures
            signatures_removed: Number of removed signatures
            success: Whether update succeeded
        """
        self.info(
            f"Database update from {source}: {'success' if success else 'failed'}",
            source=source,
            signatures_added=signatures_added,
            signatures_removed=signatures_removed,
            success=success,
            event_type="database_update",
        )
    
    def quarantine_action(
        self,
        file_path: str,
        action: str,
        success: bool,
    ) -> None:
        """
        Log a quarantine action.
        
        Args:
            file_path: Path to quarantined file
            action: Action type (quarantine, restore, delete)
            success: Whether action succeeded
        """
        self.security(
            f"Quarantine {action}: {file_path}",
            file_path=file_path,
            action=action,
            success=success,
            event_type="quarantine_action",
        )


# Global logger instance
logger = GMCLogger()
