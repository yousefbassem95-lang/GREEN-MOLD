"""
ClamAV signature integration for Green Mold Cure.
Fetches signatures from ClamAV's official databases.
"""

import gzip
import hashlib
import io
import re
from typing import Optional
import asyncio

import aiohttp

from.utils.logger import logger
from.scanner.signatures import signature_db


class ClamAVUpdater:
    """
    Fetches and imports ClamAV signatures.
    
    ClamAV databases:
    - daily.cvd: Daily updates
    - main.cvd: Main signature database
    - bytecode.cvd: Bytecode signatures
    
    Note: We extract hash-based signatures from the database files.
    """
    
    # ClamAV mirror URLs
    MIRRORS = [
        "https://database.clamav.net",
        "https://clamav.net/database",
    ]
    
    # Signature types we can import
    HASH_SIGNATURE_PATTERN = re.compile(
        r'^([a-fA-F0-9]{64}):([^:]+):(\d+)',  # MD5/SHA256 hash signatures
        re.MULTILINE
    )
    
    def __init__(self):
        """Initialize the ClamAV updater."""
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=300)  # 5 minute timeout
            )
        return self.session
    
    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def fetch_signatures(self) -> int:
        """
        Fetch signatures from ClamAV databases.
        
        Returns:
            Number of signatures imported
        """
        total_imported = 0
        
        try:
            session = await self._get_session()
            
            # Try to fetch daily database
            for mirror in self.MIRRORS:
                try:
                    daily_url = f"{mirror}/daily.cvd"
                    logger.debug(f"Fetching ClamAV daily database from {daily_url}")
                    
                    async with session.get(daily_url) as response:
                        if response.status == 200:
                            content = await response.read()
                            imported = await self._process_database(content)
                            total_imported += imported
                            break
                except Exception as e:
                    logger.debug(f"Failed to fetch from {mirror}: {e}")
                    continue
            
            # Also try main database if daily failed or had few signatures
            if total_imported < 1000:
                for mirror in self.MIRRORS:
                    try:
                        main_url = f"{mirror}/main.cvd"
                        logger.debug(f"Fetching ClamAV main database from {main_url}")
                        
                        async with session.get(main_url) as response:
                            if response.status == 200:
                                content = await response.read()
                                imported = await self._process_database(content)
                                total_imported += imported
                                break
                    except Exception as e:
                        logger.debug(f"Failed to fetch from {mirror}: {e}")
                        continue
            
            logger.info(f"ClamAV import complete: {total_imported} signatures")
            return total_imported
            
        except Exception as e:
            logger.error(f"ClamAV fetch failed: {e}")
            return 0
        finally:
            await self.close()
    
    async def _process_database(self, content: bytes) -> int:
        """
        Process a ClamAV database file.
        
        Args:
            content: Raw database content (possibly gzipped)
            
        Returns:
            Number of signatures imported
        """
        try:
            # Try to decompress if gzipped
            try:
                decompressed = gzip.decompress(content)
            except gzip.BadGzipFile:
                decompressed = content
            
            # Parse signatures
            signatures = []
            text = decompressed.decode('utf-8', errors='ignore')
            
            for match in self.HASH_SIGNATURE_PATTERN.finditer(text):
                hash_value = match.group(1).lower()
                threat_name = match.group(2)
                
                # Determine hash type by length
                if len(hash_value) == 64:
                    hash_type = "sha256"
                elif len(hash_value) == 32:
                    hash_type = "md5"
                    # Skip MD5 hashes (too many false positives)
                    continue
                else:
                    continue
                
                signatures.append({
                    "hash_sha256": hash_value if hash_type == "sha256" else self._md5_to_placeholder(hash_value),
                    "threat_name": f"ClamAV.{threat_name}",
                    "threat_type": "malware",
                    "severity": self._estimate_severity(threat_name),
                })
            
            # Import in batches
            if signatures:
                imported, failed = signature_db.add_signatures_batch(
                    signatures,
                    source="clamav",
                )
                logger.debug(f"ClamAV: {imported} imported, {failed} failed")
                return imported
            
            return 0
            
        except Exception as e:
            logger.error(f"Failed to process ClamAV database: {e}")
            return 0
    
    def _md5_to_placeholder(self, md5_hash: str) -> str:
        """
        Convert MD5 hash to a SHA256 placeholder.
        
        Note: This is a simplification. In production, you'd want
        to properly handle MD5 signatures.
        
        Args:
            md5_hash: MD5 hash string
            
        Returns:
            SHA256-length placeholder
        """
        # Pad MD5 to SHA256 length (not cryptographically sound, but works for lookup)
        return (md5_hash * 8)[:64]
    
    def _estimate_severity(self, threat_name: str) -> str:
        """
        Estimate threat severity based on name patterns.
        
        Args:
            threat_name: ClamAV threat name
            
        Returns:
            Severity string (low, medium, high, critical)
        """
        name_lower = threat_name.lower()
        
        # Critical threats
        critical_patterns = ["ransom", "wannacry", "locky", "cryptolocker"]
        if any(p in name_lower for p in critical_patterns):
            return "critical"
        
        # High severity threats
        high_patterns = ["trojan", "backdoor", "rootkit", "banker", "rat"]
        if any(p in name_lower for p in high_patterns):
            return "high"
        
        # Medium severity
        medium_patterns = ["worm", "downloader", "dropper", "injector"]
        if any(p in name_lower for p in medium_patterns):
            return "medium"
        
        # Default to low
        return "low"


# For testing
async def main():
    """Test the ClamAV updater."""
    updater = ClamAVUpdater()
    count = await updater.fetch_signatures()
    print(f"Imported {count} signatures from ClamAV")


if __name__ == "__main__":
    asyncio.run(main())
