"""
PhishTank API integration for Green Mold Cure.
Fetches phishing URL data from PhishTank.
"""

import asyncio
import hashlib
from typing import Optional, List, Dict

import aiohttp

from.utils.logger import logger
from.scanner.signatures import signature_db


class PhishTankFetcher:
    """
    Fetches phishing data from PhishTank.
    
    PhishTank provides a free API for accessing verified phishing URLs.
    """
    
    # PhishTank data export URL (no API key required for basic access)
    PHISHTANK_DATA = "https://data.phishtank.com/data/online-valid.csv"
    
    def __init__(self):
        """Initialize the PhishTank fetcher."""
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
    
    async def fetch_phishing_urls(self, limit: int = 500) -> int:
        """
        Fetch phishing URLs from PhishTank.
        
        Args:
            limit: Maximum number of URLs to fetch
            
        Returns:
            Number of URLs imported
        """
        try:
            logger.debug(f"Fetching up to {limit} phishing URLs from PhishTank...")
            
            session = await self._get_session()
            
            async with session.get(self.PHISHTANK_DATA) as response:
                if response.status == 200:
                    content = await response.text()
                    urls = await self._process_phishtank_data(content, limit)
                    
                    if urls:
                        imported, failed = signature_db.add_signatures_batch(
                            urls,
                            source="phishtank",
                        )
                        logger.debug(f"PhishTank: {imported} imported, {failed} failed")
                        return imported
                
                return 0
                
        except Exception as e:
            logger.error(f"PhishTank fetch failed: {e}")
            return 0
        finally:
            await self.close()
    
    async def _process_phishtank_data(self, content: str, limit: int) -> List[Dict]:
        """
        Process PhishTank CSV data.
        
        Args:
            content: Raw CSV content
            limit: Maximum URLs to process
            
        Returns:
            List of signature dicts
        """
        signatures = []
        lines = content.strip().split('\n')
        
        # Skip header line
        for line in lines[1:]:
            if len(signatures) >= limit:
                break
            
            line = line.strip()
            if not line:
                continue
            
            # Parse CSV (simple parsing, may need improvement for complex cases)
            parts = line.split(',')
            
            if len(parts) >= 2:
                # Extract URL (may be quoted)
                url = parts[1].strip('"')
                
                if url and url.startswith('http'):
                    # Create hash of URL for signature matching
                    url_hash = hashlib.sha256(url.encode()).hexdigest()
                    
                    signatures.append({
                        "hash_sha256": url_hash,
                        "threat_name": "PhishTank.Phishing_URL",
                        "threat_type": "phishing",
                        "severity": "medium",
                        "metadata": {"url": url},
                    })
        
        return signatures
    
    async def check_url(self, url: str) -> Optional[Dict]:
        """
        Check if a URL is a known phishing site.
        
        Args:
            url: URL to check
            
        Returns:
            Threat info dict or None
        """
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        # Check against local database
        from.scanner.signatures import signature_db
        threat_info = signature_db.check_hash(url_hash)
        
        if threat_info and threat_info.get("source") == "phishtank":
            return threat_info
        
        return None


# For testing
async def main():
    """Test the PhishTank fetcher."""
    fetcher = PhishTankFetcher()
    count = await fetcher.fetch_phishing_urls(limit=100)
    print(f"Imported {count} phishing URLs from PhishTank")


if __name__ == "__main__":
    asyncio.run(main())
