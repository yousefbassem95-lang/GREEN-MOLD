"""
Signature-based detection for Green Mold Cure.
Manages threat signatures and hash matching.
"""

import sqlite3
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from utils.logger import logger
from utils.platform import platform_info


class SignatureDatabase:
    """
    Manages threat signatures for detection.
    
    Stores and queries threat signatures from multiple sources.
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the signature database.
        
        Args:
            db_path: Optional custom path to database file
        """
        self.db_path = db_path or platform_info.get_database_path()
        self._ensure_db_dir()
        self._init_database()
        self._signature_cache: dict[str, dict] = {}
    
    def _ensure_db_dir(self) -> None:
        """Ensure the database directory exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _init_database(self) -> None:
        """Initialize the database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Signatures table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash_sha256 TEXT UNIQUE NOT NULL,
                threat_name TEXT NOT NULL,
                threat_type TEXT,
                severity TEXT DEFAULT 'medium',
                source TEXT NOT NULL,
                date_added TEXT NOT NULL,
                date_updated TEXT,
                is_active INTEGER DEFAULT 1
            )
        """)
        
        # Create index on hash for fast lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_signatures_hash
            ON signatures(hash_sha256)
        """)
        
        # Create index on threat_name
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_signatures_name
            ON signatures(threat_name)
        """)
        
        # Scan history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_date TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                files_scanned INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0,
                duration_seconds REAL,
                results_summary TEXT
            )
        """)
        
        # Quarantine log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quarantine_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                threat_name TEXT,
                hash_sha256 TEXT,
                action TEXT NOT NULL,
                action_date TEXT NOT NULL,
                restored INTEGER DEFAULT 0,
                notes TEXT
            )
        """)
        
        # Sources table for tracking update sources
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                last_update TEXT,
                signature_count INTEGER DEFAULT 0,
                is_enabled INTEGER DEFAULT 1,
                config TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        
        logger.info(f"Signature database initialized at {self.db_path}")
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def add_signature(
        self,
        hash_sha256: str,
        threat_name: str,
        threat_type: str = "malware",
        severity: str = "medium",
        source: str = "manual",
    ) -> bool:
        """
        Add a signature to the database.
        
        Args:
            hash_sha256: SHA-256 hash of the threat
            threat_name: Name of the threat
            threat_type: Type of threat (malware, virus, trojan, etc.)
            severity: Severity level (low, medium, high, critical)
            source: Source of the signature
            
        Returns:
            True if added successfully
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            now = datetime.now(timezone.utc).isoformat()
            
            cursor.execute("""
                INSERT OR REPLACE INTO signatures
                (hash_sha256, threat_name, threat_type, severity, source, date_added, date_updated, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (hash_sha256.lower(), threat_name, threat_type, severity, source, now, now))
            
            conn.commit()
            conn.close()
            
            # Invalidate cache for this hash
            self._signature_cache.pop(hash_sha256.lower(), None)
            
            logger.debug(f"Added signature: {threat_name} ({hash_sha256[:16]}...)")
            return True
        except Exception as e:
            logger.error(f"Failed to add signature: {e}")
            return False
    
    def add_signatures_batch(
        self,
        signatures: list[dict],
        source: str = "import",
    ) -> tuple[int, int]:
        """
        Add multiple signatures in a batch.
        
        Args:
            signatures: List of signature dicts with keys:
                       hash_sha256, threat_name, threat_type, severity
            source: Source of the signatures
            
        Returns:
            Tuple of (added_count, failed_count)
        """
        added = 0
        failed = 0
        now = datetime.now(timezone.utc).isoformat()
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            for sig in signatures:
                try:
                    cursor.execute("""
                        INSERT OR REPLACE INTO signatures
                        (hash_sha256, threat_name, threat_type, severity, source, date_added, date_updated, is_active)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    """, (
                        sig.get("hash_sha256", "").lower(),
                        sig.get("threat_name", "Unknown"),
                        sig.get("threat_type", "malware"),
                        sig.get("severity", "medium"),
                        source,
                        now,
                        now,
                    ))
                    added += 1
                except Exception:
                    failed += 1
            
            conn.commit()
            conn.close()
            
            # Clear cache
            self._signature_cache.clear()
            
            logger.info(f"Batch import: {added} added, {failed} failed from {source}")
            return added, failed
        except Exception as e:
            logger.error(f"Batch import failed: {e}")
            return 0, len(signatures)
    
    def check_hash(self, hash_sha256: str) -> Optional[dict]:
        """
        Check if a hash matches a known threat.
        
        Args:
            hash_sha256: SHA-256 hash to check
            
        Returns:
            Threat info dict if match found, None otherwise
        """
        hash_lower = hash_sha256.lower()
        
        # Check cache first
        if hash_lower in self._signature_cache:
            return self._signature_cache[hash_lower]
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT threat_name, threat_type, severity, source
                FROM signatures
                WHERE hash_sha256 = ? AND is_active = 1
            """, (hash_lower,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                threat_info = {
                    "name": row["threat_name"],
                    "type": row["threat_type"],
                    "severity": row["severity"],
                    "source": row["source"],
                }
                self._signature_cache[hash_lower] = threat_info
                return threat_info
            
            return None
        except Exception as e:
            logger.error(f"Failed to check hash: {e}")
            return None
    
    def check_hashes_batch(self, hashes: list[str]) -> dict[str, dict]:
        """
        Check multiple hashes in a batch.
        
        Args:
            hashes: List of SHA-256 hashes
            
        Returns:
            Dict mapping hashes to threat info (only matches)
        """
        results = {}
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Use parameterized query for multiple hashes
            placeholders = ",".join("?" * len(hashes))
            hash_lower_list = [h.lower() for h in hashes]
            
            cursor.execute(f"""
                SELECT hash_sha256, threat_name, threat_type, severity, source
                FROM signatures
                WHERE hash_sha256 IN ({placeholders}) AND is_active = 1
            """, hash_lower_list)
            
            for row in cursor.fetchall():
                results[row["hash_sha256"]] = {
                    "name": row["threat_name"],
                    "type": row["threat_type"],
                    "severity": row["severity"],
                    "source": row["source"],
                }
            
            conn.close()
        except Exception as e:
            logger.error(f"Batch hash check failed: {e}")
        
        return results
    
    def get_signature_count(self) -> int:
        """Get total number of active signatures."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM signatures WHERE is_active = 1")
            count = cursor.fetchone()[0]
            
            conn.close()
            return count
        except Exception:
            return 0
    
    def get_signatures_by_source(self, source: str) -> int:
        """Get signature count for a specific source."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) FROM signatures
                WHERE source = ? AND is_active = 1
            """, (source,))
            
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0
    
    def remove_signature(self, hash_sha256: str) -> bool:
        """
        Remove a signature from the database.
        
        Args:
            hash_sha256: Hash to remove
            
        Returns:
            True if removed successfully
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE signatures SET is_active = 0
                WHERE hash_sha256 = ?
            """, (hash_sha256.lower(),))
            
            conn.commit()
            conn.close()
            
            self._signature_cache.pop(hash_sha256.lower(), None)
            return True
        except Exception as e:
            logger.error(f"Failed to remove signature: {e}")
            return False
    
    def clear_signatures(self, source: Optional[str] = None) -> int:
        """
        Clear signatures from the database.
        
        Args:
            source: Optional source to clear (None clears all)
            
        Returns:
            Number of signatures cleared
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            if source:
                cursor.execute("""
                    UPDATE signatures SET is_active = 0
                    WHERE source = ?
                """, (source,))
            else:
                cursor.execute("UPDATE signatures SET is_active = 0")
            
            count = cursor.rowcount
            conn.commit()
            conn.close()
            
            self._signature_cache.clear()
            
            logger.info(f"Cleared {count} signatures" + (f" from {source}" if source else ""))
            return count
        except Exception as e:
            logger.error(f"Failed to clear signatures: {e}")
            return 0
    
    def log_scan(
        self,
        scan_type: str,
        files_scanned: int,
        threats_found: int,
        duration_seconds: float,
    ) -> bool:
        """
        Log a scan to history.
        
        Args:
            scan_type: Type of scan (quick, full, custom)
            files_scanned: Number of files scanned
            threats_found: Number of threats found
            duration_seconds: Scan duration
            
        Returns:
            True if logged successfully
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO scan_history
                (scan_date, scan_type, files_scanned, threats_found, duration_seconds)
                VALUES (?, ?, ?, ?, ?)
            """, (
                datetime.now(timezone.utc).isoformat(),
                scan_type,
                files_scanned,
                threats_found,
                duration_seconds,
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
            return False
    
    def log_quarantine(
        self,
        original_path: str,
        quarantine_path: str,
        threat_name: str,
        hash_sha256: str,
        action: str = "quarantine",
        notes: Optional[str] = None,
    ) -> bool:
        """
        Log a quarantine action.
        
        Args:
            original_path: Original file path
            quarantine_path: Quarantine vault path
            threat_name: Name of detected threat
            hash_sha256: File hash
            action: Action type (quarantine, restore, delete)
            notes: Optional notes
            
        Returns:
            True if logged successfully
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO quarantine_log
                (original_path, quarantine_path, threat_name, hash_sha256, action, action_date, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                original_path,
                quarantine_path,
                threat_name,
                hash_sha256.lower(),
                action,
                datetime.now(timezone.utc).isoformat(),
                notes,
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Failed to log quarantine: {e}")
            return False
    
    def get_quarantine_log(self, limit: int = 100) -> list[dict]:
        """
        Get quarantine log entries.
        
        Args:
            limit: Maximum entries to return
            
        Returns:
            List of quarantine log entries
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM quarantine_log
                ORDER BY action_date DESC
                LIMIT ?
            """, (limit,))
            
            entries = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return entries
        except Exception as e:
            logger.error(f"Failed to get quarantine log: {e}")
            return []
    
    def get_scan_history(self, limit: int = 50) -> list[dict]:
        """
        Get scan history entries.
        
        Args:
            limit: Maximum entries to return
            
        Returns:
            List of scan history entries
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM scan_history
                ORDER BY scan_date DESC
                LIMIT ?
            """, (limit,))
            
            entries = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return entries
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    def update_source_info(
        self,
        name: str,
        signature_count: int,
        config: Optional[str] = None,
    ) -> bool:
        """
        Update source information.
        
        Args:
            name: Source name
            signature_count: Number of signatures from this source
            config: Optional configuration JSON string
            
        Returns:
            True if updated successfully
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO sources
                (name, last_update, signature_count, is_enabled, config)
                VALUES (?, ?, ?, 1, ?)
            """, (
                name,
                datetime.now(timezone.utc).isoformat(),
                signature_count,
                config,
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Failed to update source info: {e}")
            return False
    
    def get_database_stats(self) -> dict:
        """
        Get database statistics.
        
        Returns:
            Dict with database statistics
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Total signatures
            cursor.execute("SELECT COUNT(*) FROM signatures WHERE is_active = 1")
            total_sigs = cursor.fetchone()[0]
            
            # Signatures by severity
            cursor.execute("""
                SELECT severity, COUNT(*) FROM signatures
                WHERE is_active = 1
                GROUP BY severity
            """)
            by_severity = {row["severity"]: row[1] for row in cursor.fetchall()}
            
            # Signatures by source
            cursor.execute("""
                SELECT source, COUNT(*) FROM signatures
                WHERE is_active = 1
                GROUP BY source
            """)
            by_source = {row["source"]: row[1] for row in cursor.fetchall()}
            
            conn.close()
            
            return {
                "total_signatures": total_sigs,
                "by_severity": by_severity,
                "by_source": by_source,
                "database_path": str(self.db_path),
            }
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {}


# Global signature database instance
signature_db = SignatureDatabase()
