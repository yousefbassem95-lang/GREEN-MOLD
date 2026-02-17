"""
Permission Handler for Green Mold Cure.
Manages elevated privileges and user consent for file access.

Features:
- Detect access denied errors
- Prompt user for permission elevation
- Retry file access after permission granted
- Respect user decisions (can deny)
- Log all permission requests
"""

import os
import sys
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from utils.logger import logger
from utils.platform import platform_info


class PermissionStatus(Enum):
    """Permission request status."""
    GRANTED = "granted"
    DENIED = "denied"
    PENDING = "pending"
    ERROR = "error"


class AccessLevel(Enum):
    """Access level types."""
    USER = "user"  # Current user files
    SYSTEM = "system"  # System files (requires admin)
    ROOT = "root"  # Root/admin access
    ALL = "all"  # Full system access


@dataclass
class PermissionRequest:
    """A permission request record."""
    request_id: str
    file_path: str
    access_level: AccessLevel
    reason: str
    status: PermissionStatus
    timestamp: datetime
    user_response: Optional[str] = None


class PermissionHandler:
    """
    Handles permission requests and elevation.
    
    Features:
    - Request elevated privileges when needed
    - Prompt user for consent
    - Retry access after permission granted
    - Track permission history
    """
    
    def __init__(self):
        """Initialize permission handler."""
        self.requests: List[PermissionRequest] = []
        self._granted_paths: set = set()
        self._denied_paths: set = set()
        self._current_level = AccessLevel.USER
        
        # Check if already elevated
        if platform_info.is_admin():
            self._current_level = AccessLevel.ROOT
    
    def is_elevated(self) -> bool:
        """Check if running with elevated privileges."""
        return platform_info.is_admin()
    
    def get_current_level(self) -> AccessLevel:
        """Get current access level."""
        return self._current_level
    
    def can_access(self, file_path: Path) -> bool:
        """
        Check if we can access a file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if accessible
        """
        # Check if previously denied
        if str(file_path) in self._denied_paths:
            return False
        
        # Check if previously granted
        if str(file_path) in self._granted_paths:
            return True
        
        # Try to access
        try:
            if file_path.exists():
                file_path.stat()
                return True
        except PermissionError:
            return False
        except OSError:
            return False
        
        return True
    
    def request_access(
        self,
        file_path: Path,
        reason: str = "File scanning",
        auto_retry: bool = True
    ) -> PermissionStatus:
        """
        Request access to a file or directory.
        
        Args:
            file_path: Path to request access to
            reason: Reason for access request
            auto_retry: Whether to retry after permission granted
            
        Returns:
            Permission status
        """
        import uuid
        
        # Check if already elevated
        if self.is_elevated():
            self._granted_paths.add(str(file_path))
            return PermissionStatus.GRANTED
        
        # Check if previously denied by user
        if str(file_path) in self._denied_paths:
            return PermissionStatus.DENIED
        
        # Create permission request
        request = PermissionRequest(
            request_id=str(uuid.uuid4())[:8],
            file_path=str(file_path),
            access_level=AccessLevel.SYSTEM,
            reason=reason,
            status=PermissionStatus.PENDING,
            timestamp=datetime.now(timezone.utc)
        )
        
        self.requests.append(request)
        
        # Prompt user
        logger.info(f"Permission requested for: {file_path}")
        
        # In CLI, we'll prompt the user
        print(f"\n{'='*60}")
        print(f"⚠️  ACCESS PERMISSION REQUIRED")
        print(f"{'='*60}")
        print(f"\nFile: {file_path}")
        print(f"Reason: {reason}")
        print(f"\nThis requires elevated privileges to scan.")
        print(f"\n[y] Grant access (elevate privileges)")
        print(f"[n] Deny access (skip this file)")
        print(f"[a] Grant access to ALL system files")
        print(f"[s] Skip and continue without elevation")
        print()
        
        try:
            choice = input("Your choice [y/n/a/s]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            request.status = PermissionStatus.DENIED
            self._denied_paths.add(str(file_path))
            return PermissionStatus.DENIED
        
        if choice == 'y':
            request.status = PermissionStatus.GRANTED
            request.user_response = 'yes'
            self._granted_paths.add(str(file_path))
            
            if auto_retry:
                self._elevate_privileges()
            
            return PermissionStatus.GRANTED
            
        elif choice == 'a':
            request.status = PermissionStatus.GRANTED
            request.user_response = 'all'
            self._current_level = AccessLevel.ALL
            
            if auto_retry:
                self._elevate_privileges()
            
            return PermissionStatus.GRANTED
            
        elif choice == 's':
            request.status = PermissionStatus.DENIED
            request.user_response = 'skip'
            return PermissionStatus.DENIED
            
        else:  # 'n' or anything else
            request.status = PermissionStatus.DENIED
            request.user_response = 'no'
            self._denied_paths.add(str(file_path))
            return PermissionStatus.DENIED
    
    def _elevate_privileges(self) -> bool:
        """
        Attempt to elevate privileges.
        
        Returns:
            True if successful
        """
        if self.is_elevated():
            return True
        
        try:
            if platform_info.is_windows():
                # Windows: Use UAC elevation
                import ctypes
                try:
                    ctypes.windll.shell32.IsUserAnAdmin()
                    return True
                except:
                    pass
            else:
                # Linux/macOS: Check for sudo
                result = subprocess.run(
                    ['sudo', '-n', 'true'],
                    capture_output=True
                )
                if result.returncode == 0:
                    self._current_level = AccessLevel.ROOT
                    return True
        except Exception as e:
            logger.debug(f"Elevation failed: {e}")
        
        return False
    
    def request_elevation_prompt(self) -> bool:
        """
        Prompt user to run with elevated privileges.
        
        Returns:
            True if user agrees to elevate
        """
        print(f"\n{'='*60}")
        print(f"🔐 ELEVATED PRIVILEGES RECOMMENDED")
        print(f"{'='*60}")
        print(f"\nRunning without administrator/root privileges limits scanning.")
        print(f"\nBenefits of elevated access:")
        print(f"  ✓ Scan system files and directories")
        print(f"  ✓ Access protected user folders")
        print(f"  ✓ Detect rootkits and hidden malware")
        print(f"  ✓ Complete process memory scanning")
        print(f"\nWithout elevation, some files will show 'Access Denied'.")
        print(f"\n[y] Restart with elevated privileges")
        print(f"[n] Continue with limited access")
        print()
        
        try:
            choice = input("Your choice [y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        
        if choice == 'y':
            return self._restart_elevated()
        
        return False
    
    def _restart_elevated(self) -> bool:
        """
        Restart the application with elevated privileges.
        
        Returns:
            True if restart initiated
        """
        try:
            if platform_info.is_windows():
                import ctypes
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
            else:
                # Linux/macOS: Use sudo
                env = os.environ.copy()
                env['PYTHONPATH'] = str(Path(__file__).parent.parent)
                subprocess.Popen(
                    ['sudo', sys.executable] + sys.argv,
                    env=env
                )
            
            sys.exit(0)
            
        except Exception as e:
            logger.error(f"Failed to elevate: {e}")
            print(f"\n[red]Failed to elevate privileges: {e}[/red]")
            print("[yellow]Continuing with limited access...[/yellow]")
            return False
    
    def get_permission_stats(self) -> Dict[str, Any]:
        """Get permission statistics."""
        return {
            'is_elevated': self.is_elevated(),
            'access_level': self._current_level.value,
            'granted_paths': len(self._granted_paths),
            'denied_paths': len(self._denied_paths),
            'total_requests': len(self.requests),
            'requests_granted': len([r for r in self.requests if r.status == PermissionStatus.GRANTED]),
            'requests_denied': len([r for r in self.requests if r.status == PermissionStatus.DENIED]),
        }
    
    def clear_permission_cache(self) -> None:
        """Clear granted/denied path cache."""
        self._granted_paths.clear()
        self._denied_paths.clear()
        logger.info("Permission cache cleared")
    
    def export_permission_log(self, output_path: Path) -> bool:
        """Export permission request log."""
        try:
            with open(output_path, 'w') as f:
                f.write("GREEN MOLD CURE - PERMISSION LOG\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"Current Level: {self._current_level.value}\n")
                f.write(f"Is Elevated: {self.is_elevated()}\n\n")
                
                for req in self.requests:
                    f.write(f"-" * 40 + "\n")
                    f.write(f"ID: {req.request_id}\n")
                    f.write(f"File: {req.file_path}\n")
                    f.write(f"Level: {req.access_level.value}\n")
                    f.write(f"Reason: {req.reason}\n")
                    f.write(f"Status: {req.status.value}\n")
                    f.write(f"Time: {req.timestamp.isoformat()}\n")
                    if req.user_response:
                        f.write(f"Response: {req.user_response}\n")
            
            return True
        except Exception as e:
            logger.error(f"Failed to export permission log: {e}")
            return False


# Global permission handler instance
permission_handler = PermissionHandler()
