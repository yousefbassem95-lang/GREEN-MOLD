"""
Platform detection and OS-specific handling for Green Mold Cure.
Supports Linux, Windows, macOS, Android (Termux), and iOS (a-Shell/iSH).
"""

import os
import sys
import platform
from pathlib import Path
from enum import Enum
from typing import Optional


class Platform(Enum):
    """Supported operating system platforms."""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class PlatformInfo:
    """Provides platform-specific information and utilities."""
    
    def __init__(self):
        self._platform = self._detect_platform()
        self._os_name = os.name
        self._system = platform.system()
        self._release = platform.release()
        self._version = platform.version()
        self._machine = platform.machine()
        self._python_version = sys.version_info
    
    def _detect_platform(self) -> Platform:
        """Detect the current platform."""
        system = platform.system().lower()
        release = platform.release().lower()
        
        # Check for Android (Termux)
        if "ANDROID_ROOT" in os.environ or "/data/data/com.termux" in str(Path.home()):
            return Platform.ANDROID
        
        # Check for iOS (a-Shell/iSH)
        if system == "darwin" and ("ISH" in os.environ.get("PS1", "") or "a-shell" in os.environ.get("SHELL", "")):
            return Platform.IOS
        
        # Standard platform detection
        if system == "linux":
            return Platform.LINUX
        elif system == "windows":
            return Platform.WINDOWS
        elif system == "darwin":
            return Platform.MACOS
        
        return Platform.UNKNOWN
    
    @property
    def platform(self) -> Platform:
        """Get the detected platform."""
        return self._platform
    
    @property
    def is_linux(self) -> bool:
        """Check if running on Linux."""
        return self._platform == Platform.LINUX
    
    @property
    def is_windows(self) -> bool:
        """Check if running on Windows."""
        return self._platform == Platform.WINDOWS
    
    @property
    def is_macos(self) -> bool:
        """Check if running on macOS."""
        return self._platform == Platform.MACOS
    
    @property
    def is_android(self) -> bool:
        """Check if running on Android (Termux)."""
        return self._platform == Platform.ANDROID
    
    @property
    def is_ios(self) -> bool:
        """Check if running on iOS (a-Shell/iSH)."""
        return self._platform == Platform.IOS
    
    @property
    def is_mobile(self) -> bool:
        """Check if running on a mobile platform."""
        return self._platform in (Platform.ANDROID, Platform.IOS)
    
    def get_home_dir(self) -> Path:
        """Get the home directory path."""
        return Path.home()
    
    def get_app_data_dir(self) -> Path:
        """
        Get the application data directory.
        
        Returns:
            Path to the Green Mold Cure data directory
        """
        if self.is_windows:
            # Windows: %APPDATA%\GreenMoldCure
            appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
            return Path(appdata) / "GreenMoldCure"
        else:
            # Unix-like: ~/.green_mold_cure
            return self.get_home_dir() / ".green_mold_cure"
    
    def get_config_dir(self) -> Path:
        """
        Get the configuration directory.
        
        Returns:
            Path to the configuration directory
        """
        if self.is_macos:
            # macOS: ~/Library/Preferences/GreenMoldCure
            return self.get_home_dir() / "Library" / "Preferences" / "GreenMoldCure"
        elif self.is_windows:
            return self.get_app_data_dir() / "config"
        else:
            # Linux/Android: ~/.green_mold_cure/config
            return self.get_app_data_dir() / "config"
    
    def get_quarantine_dir(self) -> Path:
        """
        Get the quarantine directory.
        
        Returns:
            Path to the quarantine vault
        """
        return self.get_app_data_dir() / "quarantine"
    
    def get_logs_dir(self) -> Path:
        """
        Get the logs directory.
        
        Returns:
            Path to the logs directory
        """
        return self.get_app_data_dir() / "logs"
    
    def get_database_path(self) -> Path:
        """
        Get the database file path.
        
        Returns:
            Path to the signatures database
        """
        return self.get_app_data_dir() / "signatures.db"
    
    def get_settings_path(self) -> Path:
        """
        Get the settings file path.
        
        Returns:
            Path to the settings file
        """
        return self.get_config_dir() / "settings.json"
    
    def ensure_directories(self) -> None:
        """Create all necessary directories if they don't exist."""
        dirs = [
            self.get_app_data_dir(),
            self.get_config_dir(),
            self.get_quarantine_dir(),
            self.get_logs_dir(),
        ]
        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)
            
            # Set restrictive permissions on quarantine directory
            if "quarantine" in str(dir_path):
                self._set_restrictive_permissions(dir_path)
    
    def _set_restrictive_permissions(self, path: Path) -> None:
        """
        Set restrictive permissions on a directory.
        
        Args:
            path: Path to the directory
        """
        if not self.is_windows:
            try:
                os.chmod(path, 0o700)  # Owner read/write/execute only
            except OSError:
                pass  # May fail on some filesystems
    
    def get_path_separator(self) -> str:
        """Get the OS path separator."""
        return os.sep
    
    def is_admin(self) -> bool:
        """
        Check if running with administrator/root privileges.
        
        Returns:
            True if running as admin/root
        """
        if self.is_windows:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0  # type: ignore
    
    def get_common_malware_paths(self) -> list[Path]:
        """
        Get common paths where malware is typically found.
        
        Returns:
            List of paths to scan for quick scan
        """
        paths = []
        
        if self.is_windows:
            paths.extend([
                Path(os.environ.get("TEMP", "C:\\Windows\\Temp")),
                Path(os.environ.get("USERPROFILE", "C:\\Users")) / "Downloads",
                Path(os.environ.get("USERPROFILE", "C:\\Users")) / "Desktop",
                Path("C:\\Windows\\System32"),
                Path("C:\\Program Files"),
                Path("C:\\Program Files (x86)"),
            ])
        elif self.is_macos:
            paths.extend([
                self.get_home_dir() / "Downloads",
                self.get_home_dir() / "Desktop",
                Path("/tmp"),
                Path("/Applications"),
                Path("/Library"),
            ])
        elif self.is_android:
            paths.extend([
                self.get_home_dir() / "downloads",
                Path("/sdcard/Download"),
                Path("/sdcard"),
            ])
        else:  # Linux
            paths.extend([
                self.get_home_dir() / "Downloads",
                self.get_home_dir() / "Desktop",
                Path("/tmp"),
                Path("/var/tmp"),
            ])
        
        # Filter to existing paths
        return [p for p in paths if p.exists()]
    
    def get_system_root(self) -> Path:
        """
        Get the system root directory.
        
        Returns:
            Path to system root
        """
        if self.is_windows:
            return Path(os.environ.get("SystemRoot", "C:\\Windows"))
        else:
            return Path("/")
    
    def can_scan_system(self) -> bool:
        """
        Check if full system scan is possible.
        
        Returns:
            True if system scan is possible
        """
        if self.is_mobile:
            return False
        return self.is_admin() or self.is_linux
    
    def get_platform_info(self) -> dict:
        """
        Get comprehensive platform information.
        
        Returns:
            Dictionary with platform details
        """
        return {
            "platform": self._platform.value,
            "os_name": self._os_name,
            "system": self._system,
            "release": self._release,
            "version": self._version,
            "machine": self._machine,
            "python_version": f"{self._python_version.major}.{self._python_version.minor}.{self._python_version.micro}",
            "is_admin": self.is_admin(),
            "is_mobile": self.is_mobile,
        }


# Global platform info instance
platform_info = PlatformInfo()
