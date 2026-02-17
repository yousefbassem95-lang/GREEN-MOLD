"""
Settings management for Green Mold Cure.
Handles user preferences and configuration.
"""

import json
from pathlib import Path
from typing import Any, Optional
from datetime import datetime, timezone

from utils.platform import platform_info
from utils.logger import logger


class Settings:
    """
    Manages user settings and preferences.
    
    Settings are stored in JSON format at the platform-specific config location.
    """
    
    DEFAULT_SETTINGS = {
        # Scan settings
        "scan": {
            "max_file_size_mb": 100,
            "scan_archives": True,
            "scan_heuristic": True,
            "follow_symlinks": False,
            "exclude_patterns": [],
        },
        # Quarantine settings
        "quarantine": {
            "auto_quarantine": False,  # Prompt user by default
            "max_quarantine_size_mb": 1024,
            "retention_days": 30,
        },
        # Update settings
        "updates": {
            "auto_update": False,
            "update_interval_hours": 24,
            "sources": {
                "clamav": True,
                "abuse_ch": True,
                "virustotal": False,
                "hybrid_analysis": False,
                "anyrun": False,
                "tor_feeds": False,
            },
        },
        # UI settings
        "ui": {
            "color_theme": "dark_green",
            "show_progress": True,
            "verbose_output": False,
        },
        # Security settings
        "security": {
            "require_confirmation": True,
            "log_security_events": True,
            "encrypt_quarantine": True,
        },
        # API keys (stored securely)
        "api_keys": {
            "virustotal": None,
            "hybrid_analysis": None,
            "anyrun": None,
            "alienvault": None,
        },
        # Metadata
        "meta": {
            "created_at": None,
            "updated_at": None,
            "version": "1.0.0",
        },
    }
    
    def __init__(self, settings_path: Optional[Path] = None):
        """
        Initialize settings manager.
        
        Args:
            settings_path: Optional custom path to settings file
        """
        self.settings_path = settings_path or platform_info.get_settings_path()
        self.settings = self._load_defaults()
        self._ensure_config_dir()
    
    def _load_defaults(self) -> dict:
        """Load default settings with timestamps."""
        defaults = json.loads(json.dumps(self.DEFAULT_SETTINGS))  # Deep copy
        defaults["meta"]["created_at"] = datetime.now(timezone.utc).isoformat()
        defaults["meta"]["updated_at"] = datetime.now(timezone.utc).isoformat()
        return defaults
    
    def _ensure_config_dir(self) -> None:
        """Ensure the configuration directory exists."""
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
    
    def load(self) -> bool:
        """
        Load settings from file.
        
        Returns:
            True if loaded successfully, False if using defaults
        """
        if not self.settings_path.exists():
            logger.info("No settings file found, using defaults")
            return False
        
        try:
            with open(self.settings_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            
            # Merge with defaults to ensure all keys exist
            self.settings = self._deep_merge(self._load_defaults(), loaded)
            logger.info("Settings loaded successfully")
            return True
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse settings file: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to load settings: {e}")
            return False
    
    def save(self) -> bool:
        """
        Save settings to file.
        
        Returns:
            True if saved successfully
        """
        try:
            self.settings["meta"]["updated_at"] = datetime.now(timezone.utc).isoformat()
            
            with open(self.settings_path, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=2)
            
            # Set restrictive permissions on settings file
            try:
                self.settings_path.chmod(0o600)  # Owner read/write only
            except OSError:
                pass  # May fail on some filesystems
            
            logger.info("Settings saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            return False
    
    def _deep_merge(self, base: dict, override: dict) -> dict:
        """
        Deep merge two dictionaries.
        
        Args:
            base: Base dictionary
            override: Dictionary to merge into base
            
        Returns:
            Merged dictionary
        """
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a setting value by dot-notation path.
        
        Args:
            key_path: Dot-separated path (e.g., "scan.max_file_size_mb")
            default: Default value if key not found
            
        Returns:
            Setting value or default
        """
        keys = key_path.split(".")
        value = self.settings
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> bool:
        """
        Set a setting value by dot-notation path.
        
        Args:
            key_path: Dot-separated path (e.g., "scan.max_file_size_mb")
            value: Value to set
            
        Returns:
            True if set successfully
        """
        keys = key_path.split(".")
        config = self.settings
        
        # Navigate to parent
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set value
        config[keys[-1]] = value
        return True
    
    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get API key for a service.
        
        Args:
            service: Service name (virustotal, hybrid_analysis, etc.)
            
        Returns:
            API key or None
        """
        return self.settings["api_keys"].get(service)
    
    def set_api_key(self, service: str, key: str) -> bool:
        """
        Set API key for a service.
        
        Args:
            service: Service name
            key: API key
            
        Returns:
            True if set successfully
        """
        if service in self.settings["api_keys"]:
            self.settings["api_keys"][service] = key
            return True
        return False
    
    def is_source_enabled(self, source: str) -> bool:
        """
        Check if a threat source is enabled.
        
        Args:
            source: Source name
            
        Returns:
            True if enabled
        """
        return self.settings["updates"]["sources"].get(source, False)
    
    def enable_source(self, source: str) -> bool:
        """Enable a threat source."""
        return self.set(f"updates.sources.{source}", True)
    
    def disable_source(self, source: str) -> bool:
        """Disable a threat source."""
        return self.set(f"updates.sources.{source}", False)
    
    def get_excluded_patterns(self) -> list[str]:
        """Get list of excluded file/path patterns."""
        return self.settings["scan"].get("exclude_patterns", [])
    
    def add_exclusion(self, pattern: str) -> bool:
        """Add an exclusion pattern."""
        patterns = self.get_excluded_patterns()
        if pattern not in patterns:
            patterns.append(pattern)
            return self.set("scan.exclude_patterns", patterns)
        return False
    
    def remove_exclusion(self, pattern: str) -> bool:
        """Remove an exclusion pattern."""
        patterns = self.get_excluded_patterns()
        if pattern in patterns:
            patterns.remove(pattern)
            return self.set("scan.exclude_patterns", patterns)
        return False
    
    def reset_to_defaults(self) -> bool:
        """
        Reset all settings to defaults.
        
        Returns:
            True if reset successfully
        """
        self.settings = self._load_defaults()
        return self.save()
    
    def export_settings(self, output_path: Path) -> bool:
        """
        Export settings to a file.
        
        Args:
            output_path: Path for export file
            
        Returns:
            True if exported successfully
        """
        try:
            # Don't export API keys
            export_data = json.loads(json.dumps(self.settings))
            export_data["api_keys"] = {k: "***REDACTED***" for k in export_data["api_keys"]}
            
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)
            
            return True
        except Exception as e:
            logger.error(f"Failed to export settings: {e}")
            return False
    
    def import_settings(self, input_path: Path) -> bool:
        """
        Import settings from a file.
        
        Args:
            input_path: Path to import file
            
        Returns:
            True if imported successfully
        """
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                imported = json.load(f)
            
            self.settings = self._deep_merge(self._load_defaults(), imported)
            return self.save()
        except Exception as e:
            logger.error(f"Failed to import settings: {e}")
            return False
    
    def __repr__(self) -> str:
        return f"Settings(path={self.settings_path})"


# Global settings instance
settings = Settings()
