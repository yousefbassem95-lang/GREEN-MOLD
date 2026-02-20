"""
Quarantine management for Green Mold Cure.
Handles secure isolation and management of detected threats.
"""

import shutil
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass, asdict
import uuid

from utils.platform import platform_info
from utils.logger import logger
from utils.crypto import CryptoVault, SecureDeleter
from config.settings import settings


@dataclass
class QuarantineEntry:
    """Represents a quarantined file entry."""
    id: str
    original_path: str
    quarantine_path: str
    threat_name: str
    file_hash: str
    quarantine_date: str
    file_size: int
    encrypted: bool
    notes: Optional[str] = None


class QuarantineManager:
    """
    Manages the quarantine vault for detected threats.
    
    Features:
    - Secure encrypted storage
    - Metadata tracking
    - Restore capability
    - Secure deletion
    """
    
    METADATA_FILE = "quarantine_metadata.json"
    
    def __init__(self, vault_path: Optional[Path] = None):
        """
        Initialize the quarantine manager.
        
        Args:
            vault_path: Optional custom path to quarantine vault
        """
        self.vault_path = vault_path or platform_info.get_quarantine_dir()
        self.crypto = CryptoVault()
        self.entries: dict[str, QuarantineEntry] = {}
        self._ensure_vault()
        self._load_metadata()
    
    def _ensure_vault(self) -> None:
        """Ensure the quarantine vault exists with proper permissions."""
        self.vault_path.mkdir(parents=True, exist_ok=True)
        
        # Set restrictive permissions (Unix-like systems)
        if not platform_info.is_windows:
            try:
                self.vault_path.chmod(0o700)  # Owner only
            except OSError:
                pass
        
        # Create metadata file if it doesn't exist
        self.metadata_path = self.vault_path / self.METADATA_FILE
        if not self.metadata_path.exists():
            self._save_metadata()
    
    def _load_metadata(self) -> None:
        """Load quarantine metadata from disk."""
        try:
            if self.metadata_path.exists():
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                self.entries = {
                    entry_id: QuarantineEntry(**entry_data)
                    for entry_id, entry_data in data.get("entries", {}).items()
                }
                logger.debug(f"Loaded {len(self.entries)} quarantine entries")
        except Exception as e:
            logger.error(f"Failed to load quarantine metadata: {e}")
            self.entries = {}
    
    def _save_metadata(self) -> bool:
        """
        Save quarantine metadata to disk.
        
        Returns:
            True if saved successfully
        """
        try:
            data = {
                "version": "1.0",
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "entries": {
                    entry_id: asdict(entry)
                    for entry_id, entry in self.entries.items()
                },
            }
            
            with open(self.metadata_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            
            # Set restrictive permissions
            if not platform_info.is_windows:
                try:
                    self.metadata_path.chmod(0o600)
                except OSError:
                    pass
            
            return True
        except Exception as e:
            logger.error(f"Failed to save quarantine metadata: {e}")
            return False
    
    def quarantine_file(
        self,
        file_path: Path,
        threat_name: str,
        file_hash: str,
        encrypt: bool = True,
        notes: Optional[str] = None,
    ) -> Optional[QuarantineEntry]:
        """
        Move a file to quarantine.
        
        Args:
            file_path: Path to the file to quarantine
            threat_name: Name of detected threat
            file_hash: SHA-256 hash of the file
            encrypt: Whether to encrypt the file
            notes: Optional notes
            
        Returns:
            QuarantineEntry if successful, None otherwise
        """
        try:
            if not file_path.exists():
                logger.error(f"File to quarantine does not exist: {file_path}")
                return None
            
            # Generate unique ID for this entry
            entry_id = str(uuid.uuid4())[:8]
            
            # Create quarantine filename
            safe_name = f"{entry_id}_{file_path.name}"
            quarantine_path = self.vault_path / safe_name
            
            # Get file size
            file_size = file_path.stat().st_size
            
            # Check quarantine size limit
            if not self._check_size_limit(file_size):
                logger.warning("Quarantine size limit exceeded")
                return None
            
            # Copy and optionally encrypt the file
            if encrypt and settings.get("security.encrypt_quarantine", True):
                success = self.crypto.encrypt_file(file_path, quarantine_path)
            else:
                shutil.copy2(file_path, quarantine_path)
                success = True
            
            if not success or not quarantine_path.exists():
                logger.error("Failed to copy file to quarantine")
                return None
            
            # Create entry
            entry = QuarantineEntry(
                id=entry_id,
                original_path=str(file_path.absolute()),
                quarantine_path=str(quarantine_path.absolute()),
                threat_name=threat_name,
                file_hash=file_hash.lower(),
                quarantine_date=datetime.now(timezone.utc).isoformat(),
                file_size=file_size,
                encrypted=encrypt,
                notes=notes,
            )
            
            self.entries[entry_id] = entry
            self._save_metadata()
            
            # Log the action
            from scanner.signatures import signature_db
            signature_db.log_quarantine(
                str(file_path),
                str(quarantine_path),
                threat_name,
                file_hash,
                "quarantine",
                notes,
            )
            
            logger.security(
                f"File quarantined: {file_path}",
                entry_id=entry_id,
                threat_name=threat_name,
            )
            
            return entry
            
        except Exception as e:
            logger.error(f"Failed to quarantine file: {e}")
            return None
    
    def restore_file(
        self,
        entry_id: str,
        restore_path: Optional[Path] = None,
    ) -> bool:
        """
        Restore a file from quarantine.
        
        Args:
            entry_id: ID of the quarantine entry
            restore_path: Optional custom restore path (defaults to original)
            
        Returns:
            True if restored successfully
        """
        if entry_id not in self.entries:
            logger.error(f"Quarantine entry not found: {entry_id}")
            return False
        
        entry = self.entries[entry_id]
        quarantine_path = Path(entry.quarantine_path)
        
        if not quarantine_path.exists():
            logger.error(f"Quarantined file not found: {quarantine_path}")
            return False
        
        # Determine restore path
        if restore_path:
            target_path = restore_path
        else:
            target_path = Path(entry.original_path)
        
        # Ensure parent directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Decrypt if necessary
            if entry.encrypted:
                success = self.crypto.decrypt_file(quarantine_path, target_path)
            else:
                shutil.copy2(quarantine_path, target_path)
                success = True
            
            if not success:
                logger.error("Failed to restore file")
                return False
            
            # Log the action
            from scanner.signatures import signature_db
            signature_db.log_quarantine(
                entry.original_path,
                entry.quarantine_path,
                entry.threat_name,
                entry.file_hash,
                "restore",
                f"Restored to {target_path}",
            )
            
            logger.security(f"File restored from quarantine: {entry_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore file: {e}")
            return False
    
    def delete_from_quarantine(self, entry_id: str, secure: bool = True) -> bool:
        """
        Delete a file from quarantine.
        
        Args:
            entry_id: ID of the quarantine entry
            secure: Whether to use secure deletion
            
        Returns:
            True if deleted successfully
        """
        if entry_id not in self.entries:
            logger.error(f"Quarantine entry not found: {entry_id}")
            return False
        
        entry = self.entries[entry_id]
        quarantine_path = Path(entry.quarantine_path)
        
        try:
            # Perform secure deletion if requested
            if secure:
                success = SecureDeleter.secure_delete(quarantine_path)
            else:
                quarantine_path.unlink()
                success = True
            
            if success:
                # Remove entry from metadata
                del self.entries[entry_id]
                self._save_metadata()
                
                # Log the action
                from scanner.signatures import signature_db
                signature_db.log_quarantine(
                    entry.original_path,
                    entry.quarantine_path,
                    entry.threat_name,
                    entry.file_hash,
                    "delete",
                    "Secure deleted from quarantine",
                )
                
                logger.security(f"File deleted from quarantine: {entry_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to delete from quarantine: {e}")
            return False
    
    def empty_quarantine(self, secure: bool = True) -> int:
        """
        Empty the entire quarantine vault.
        
        Args:
            secure: Whether to use secure deletion
            
        Returns:
            Number of files deleted
        """
        deleted_count = 0
        
        for entry_id in list(self.entries.keys()):
            if self.delete_from_quarantine(entry_id, secure):
                deleted_count += 1
        
        logger.security(f"Emptied quarantine: {deleted_count} files deleted")
        return deleted_count
    
    def get_entry(self, entry_id: str) -> Optional[QuarantineEntry]:
        """
        Get a quarantine entry by ID.
        
        Args:
            entry_id: Entry ID
            
        Returns:
            QuarantineEntry or None
        """
        return self.entries.get(entry_id)
    
    def get_all_entries(self) -> list[QuarantineEntry]:
        """
        Get all quarantine entries.
        
        Returns:
            List of all entries
        """
        return list(self.entries.values())
    
    def get_entries_by_threat(self, threat_name: str) -> list[QuarantineEntry]:
        """
        Get entries matching a threat name.
        
        Args:
            threat_name: Threat name to search for
            
        Returns:
            List of matching entries
        """
        return [
            entry for entry in self.entries.values()
            if threat_name.lower() in entry.threat_name.lower()
        ]
    
    def _check_size_limit(self, new_file_size: int) -> bool:
        """
        Check if adding a file would exceed size limit.
        
        Args:
            new_file_size: Size of the new file
            
        Returns:
            True if within limit
        """
        max_size_mb = settings.get("quarantine.max_quarantine_size_mb", 1024)
        max_size_bytes = max_size_mb * 1024 * 1024
        
        current_size = sum(entry.file_size for entry in self.entries.values())
        
        if current_size + new_file_size > max_size_bytes:
            return False
        
        return True
    
    def cleanup_old_entries(self, retention_days: Optional[int] = None) -> int:
        """
        Remove entries older than retention period.
        
        Args:
            retention_days: Days to retain (uses settings if not specified)
            
        Returns:
            Number of entries removed
        """
        if retention_days is None:
            retention_days = settings.get("quarantine.retention_days", 30)
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        removed_count = 0
        
        for entry_id, entry in list(self.entries.items()):
            entry_date = datetime.fromisoformat(entry.quarantine_date)
            if entry_date < cutoff_date:
                if self.delete_from_quarantine(entry_id, secure=True):
                    removed_count += 1
        
        logger.info(f"Quarantine cleanup: removed {removed_count} old entries")
        return removed_count
    
    def get_vault_stats(self) -> dict:
        """
        Get quarantine vault statistics.
        
        Returns:
            Dict with vault statistics
        """
        total_size = sum(entry.file_size for entry in self.entries.values())
        
        # Count by threat name
        threat_counts: dict[str, int] = {}
        for entry in self.entries.values():
            threat_counts[entry.threat_name] = threat_counts.get(entry.threat_name, 0) + 1
        
        return {
            "total_entries": len(self.entries),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "vault_path": str(self.vault_path),
            "threat_breakdown": threat_counts,
        }


# Global quarantine manager instance
quarantine_manager = QuarantineManager()
