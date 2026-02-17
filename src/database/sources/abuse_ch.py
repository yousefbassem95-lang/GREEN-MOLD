"""
Abuse.ch feed integration for Green Mold Cure.
Fetches threat data from MalwareBazaar, URLhaus, and ThreatFox.
"""

import asyncio
import hashlib
from typing import Optional

import aiohttp

from.utils.logger import logger
from.scanner.signatures import signature_db


class AbuseChUpdater:
    """
    Fetches threat intelligence from Abuse.ch feeds.
    
    Sources:
    - MalwareBazaar: Malware file hashes
    - URLhaus: Malicious URLs
    - ThreatFox: IOCs associated with malware
    """
    
    # Abuse.ch API endpoints
    MALWARE_BAZAAR_HASHES = "https://bazaar.abuse.ch/export/txt/sha256/latest/"
    URLHAUS_URLS = "https://urlhaus.abuse.ch/downloads/text/"
    THREATFOX_IOCS = "https://threatfox.abuse.ch/downloads/ioc/"
    
    def __init__(self):
        """Initialize the Abuse.ch updater."""
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120)
            )
        return self.session
    
    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def fetch_malware_bazaar(self) -> int:
        """
        Fetch malware hashes from MalwareBazaar.
        
        Returns:
            Number of signatures imported
        """
        try:
            session = await self._get_session()
            
            logger.debug("Fetching MalwareBazaar SHA256 hashes...")
            
            async with session.get(self.MALWARE_BAZAAR_HASHES) as response:
                if response.status == 200:
                    content = await response.text()
                    return await self._process_malware_bazaar(content)
                else:
                    logger.warning(f"MalwareBazaar returned status {response.status}")
                    return 0
                    
        except Exception as e:
            logger.error(f"MalwareBazaar fetch failed: {e}")
            return 0
        finally:
            await self.close()
    
    async def _process_malware_bazaar(self, content: str) -> int:
        """
        Process MalwareBazaar export.
        
        Args:
            content: Raw text content
            
        Returns:
            Number of signatures imported
        """
        signatures = []
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Format: sha256_hash,threat_type,first_seen
            parts = line.split(',')
            if len(parts) >= 2:
                sha256_hash = parts[0].strip().lower()
                threat_type = parts[1].strip() if len(parts) > 1 else "malware"
                
                # Validate hash format
                if len(sha256_hash) == 64 and all(c in '0123456789abcdef' for c in sha256_hash):
                    signatures.append({
                        "hash_sha256": sha256_hash,
                        "threat_name": f"MalwareBazaar.{threat_type}",
                        "threat_type": threat_type,
                        "severity": "high",
                    })
        
        if signatures:
            imported, failed = signature_db.add_signatures_batch(signatures, source="abuse_ch_malwarebazaar")
            logger.debug(f"MalwareBazaar: {imported} imported, {failed} failed")
            return imported
        
        return 0
    
    async def fetch_urlhaus(self) -> int:
        """
        Fetch malicious URLs from URLhaus.
        
        Returns:
            Number of URLs imported
        """
        try:
            session = await self._get_session()
            
            logger.debug("Fetching URLhaus malicious URLs...")
            
            async with session.get(self.URLHAUS_URLS) as response:
                if response.status == 200:
                    content = await response.text()
                    return await self._process_urlhaus(content)
                else:
                    logger.warning(f"URLhaus returned status {response.status}")
                    return 0
                    
        except Exception as e:
            logger.error(f"URLhaus fetch failed: {e}")
            return 0
        finally:
            await self.close()
    
    async def _process_urlhaus(self, content: str) -> int:
        """
        Process URLhaus export.
        
        Args:
            content: Raw text content
            
        Returns:
            Number of URLs imported
        """
        signatures = []
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Create a hash of the URL for signature matching
            url_hash = hashlib.sha256(line.encode()).hexdigest()
            
            signatures.append({
                "hash_sha256": url_hash,
                "threat_name": f"URLhaus.Malicious_URL",
                "threat_type": "phishing",
                "severity": "medium",
                "metadata": {"url": line},
            })
        
        if signatures:
            imported, failed = signature_db.add_signatures_batch(signatures, source="abuse_ch_urlhaus")
            logger.debug(f"URLhaus: {imported} imported, {failed} failed")
            return imported
        
        return 0
    
    async def fetch_threatfox(self) -> int:
        """
        Fetch IOCs from ThreatFox.
        
        Returns:
            Number of IOCs imported
        """
        try:
            session = await self._get_session()
            
            logger.debug("Fetching ThreatFox IOCs...")
            
            async with session.get(self.THREATFOX_IOCS) as response:
                if response.status == 200:
                    content = await response.text()
                    return await self._process_threatfox(content)
                else:
                    logger.warning(f"ThreatFox returned status {response.status}")
                    return 0
                    
        except Exception as e:
            logger.error(f"ThreatFox fetch failed: {e}")
            return 0
        finally:
            await self.close()
    
    async def _process_threatfox(self, content: str) -> int:
        """
        Process ThreatFox IOC export.
        
        Args:
            content: Raw text content (TSV format)
            
        Returns:
            Number of IOCs imported
        """
        signatures = []
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Format: id,first_seen,ioc,ioc_type,threat_type,malprint,attribution
            parts = line.split('\t')
            if len(parts) >= 5:
                ioc = parts[2].strip()
                ioc_type = parts[3].strip()
                threat_type = parts[4].strip()
                
                # Handle different IOC types
                if ioc_type == "sha256" and len(ioc) == 64:
                    signatures.append({
                        "hash_sha256": ioc.lower(),
                        "threat_name": f"ThreatFox.{threat_type}",
                        "threat_type": threat_type.replace('_', '.'),
                        "severity": "high",
                    })
                elif ioc_type in ("url", "ip"):
                    # Hash the IOC for storage
                    ioc_hash = hashlib.sha256(ioc.encode()).hexdigest()
                    signatures.append({
                        "hash_sha256": ioc_hash,
                        "threat_name": f"ThreatFox.{threat_type}.{ioc_type}",
                        "threat_type": threat_type.replace('_', '.'),
                        "severity": "medium",
                        "metadata": {"ioc": ioc, "ioc_type": ioc_type},
                    })
        
        if signatures:
            imported, failed = signature_db.add_signatures_batch(signatures, source="abuse_ch_threatfox")
            logger.debug(f"ThreatFox: {imported} imported, {failed} failed")
            return imported
        
        return 0


# For testing
async def main():
    """Test the Abuse.ch updater."""
    updater = AbuseChUpdater()
    
    print("Fetching from MalwareBazaar...")
    mb_count = await updater.fetch_malware_bazaar()
    print(f"  Imported {mb_count} signatures")
    
    print("Fetching from URLhaus...")
    uh_count = await updater.fetch_urlhaus()
    print(f"  Imported {uh_count} URLs")
    
    print("Fetching from ThreatFox...")
    tf_count = await updater.fetch_threatfox()
    print(f"  Imported {tf_count} IOCs")
    
    print(f"\nTotal: {mb_count + uh_count + tf_count} signatures")


if __name__ == "__main__":
    asyncio.run(main())
