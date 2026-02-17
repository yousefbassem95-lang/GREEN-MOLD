"""
VirusTotal API integration for Green Mold Cure.
Fetches threat intelligence from VirusTotal.
"""

import asyncio
import hashlib
from typing import Optional, List, Dict
from datetime import datetime, timezone, timedelta

import aiohttp

from.utils.logger import logger
from.scanner.signatures import signature_db
from.config.settings import settings


class VirusTotalFetcher:
    """
    Fetches threat intelligence from VirusTotal API.
    
    Note: Requires a valid API key from virustotal.com
    Free tier: 500 requests/day, 4 requests/minute
    """
    
    API_BASE = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        """
        Initialize the VirusTotal fetcher.
        
        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
        self._request_count = 0
        self._last_request_time: Optional[datetime] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with API headers."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    "x-apikey": self.api_key,
                    "Accept": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=60)
            )
        return self.session
    
    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def _rate_limit(self) -> None:
        """Apply rate limiting for API requests."""
        # Free tier: 4 requests per minute
        if self._last_request_time:
            elapsed = (datetime.now(timezone.utc) - self._last_request_time).total_seconds()
            if elapsed < 15:  # 60/4 = 15 seconds between requests
                await asyncio.sleep(15 - elapsed)
        
        self._last_request_time = datetime.now(timezone.utc)
        self._request_count += 1
    
    async def _request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """
        Make an API request.
        
        Args:
            endpoint: API endpoint
            params: Optional query parameters
            
        Returns:
            JSON response or None on error
        """
        await self._rate_limit()
        
        try:
            session = await self._get_session()
            url = f"{self.API_BASE}/{endpoint}"
            
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:
                    logger.warning("VirusTotal rate limit exceeded")
                    await asyncio.sleep(60)
                    return await self._request(endpoint, params)
                else:
                    logger.warning(f"VirusTotal API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"VirusTotal request failed: {e}")
            return None
    
    async def fetch_signatures(self, limit: int = 100) -> int:
        """
        Fetch recent malware signatures from VirusTotal.
        
        Args:
            limit: Maximum number of signatures to fetch
            
        Returns:
            Number of signatures imported
        """
        try:
            logger.debug(f"Fetching up to {limit} signatures from VirusTotal...")
            
            # Get files from VirusTotal intelligence
            # Note: This requires premium API access for full functionality
            # For free tier, we can only check specific hashes
            
            # Try to get from intelligence endpoint (premium)
            signatures = await self._fetch_from_intelligence(limit)
            
            if not signatures:
                # Fallback: Check if we have any stored hashes to verify
                logger.info("No signatures fetched from VirusTotal (may require premium)")
                return 0
            
            # Import signatures
            if signatures:
                imported, failed = signature_db.add_signatures_batch(
                    signatures,
                    source="virustotal",
                )
                logger.debug(f"VirusTotal: {imported} imported, {failed} failed")
                return imported
            
            return 0
            
        except Exception as e:
            logger.error(f"VirusTotal fetch failed: {e}")
            return 0
        finally:
            await self.close()
    
    async def _fetch_from_intelligence(self, limit: int) -> List[Dict]:
        """
        Fetch from VirusTotal Intelligence (premium feature).
        
        Args:
            limit: Maximum signatures to fetch
            
        Returns:
            List of signature dicts
        """
        signatures = []
        
        # Intelligence endpoint requires premium subscription
        # Using retrohunt or search API
        try:
            # Search for recent high-confidence malware
            # This is a simplified example - actual queries may vary
            query = "type:peexe positives:50+"
            
            data = await self._request(
                "intelligence/search",
                {"query": query, "limit": min(limit, 100)},
            )
            
            if data and "data" in data:
                for item in data["data"]:
                    attrs = item.get("attributes", {})
                    sha256 = attrs.get("sha256", "")
                    
                    if sha256:
                        signatures.append({
                            "hash_sha256": sha256.lower(),
                            "threat_name": f"VirusTotal.{attrs.get('meaningful_name', 'Unknown')}",
                            "threat_type": "malware",
                            "severity": self._calculate_severity(attrs),
                        })
        except Exception as e:
            logger.debug(f"VirusTotal Intelligence fetch failed: {e}")
        
        return signatures
    
    def _calculate_severity(self, attrs: Dict) -> str:
        """
        Calculate threat severity based on VirusTotal data.
        
        Args:
            attrs: File attributes from VirusTotal
            
        Returns:
            Severity string
        """
        positives = attrs.get("times_submitted", 0)
        vote_count = attrs.get("total_votes", {}).get("malicious", 0)
        
        if vote_count > 10 or positives > 50:
            return "critical"
        elif vote_count > 5 or positives > 20:
            return "high"
        elif vote_count > 2 or positives > 10:
            return "medium"
        else:
            return "low"
    
    async def check_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Check a single hash against VirusTotal.
        
        Args:
            file_hash: SHA256 hash to check
            
        Returns:
            Threat info dict or None
        """
        try:
            data = await self._request(f"files/{file_hash}")
            
            if data and "data" in data:
                attrs = data["data"].get("attributes", {})
                last_analysis = attrs.get("last_analysis_stats", {})
                
                malicious = last_analysis.get("malicious", 0)
                suspicious = last_analysis.get("suspicious", 0)
                
                if malicious > 5:
                    return {
                        "name": attrs.get("meaningful_name", "Unknown"),
                        "type": "malware",
                        "severity": "high" if malicious > 10 else "medium",
                        "source": "virustotal",
                        "positives": malicious,
                    }
                elif suspicious > 3:
                    return {
                        "name": f"Suspicious.{attrs.get('meaningful_name', 'Unknown')}",
                        "type": "suspicious",
                        "severity": "low",
                        "source": "virustotal",
                        "positives": suspicious,
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"VirusTotal hash check failed: {e}")
            return None
    
    async def check_hashes_batch(self, hashes: List[str]) -> Dict[str, Dict]:
        """
        Check multiple hashes against VirusTotal.
        
        Args:
            hashes: List of SHA256 hashes
            
        Returns:
            Dict mapping hashes to threat info
        """
        results = {}
        
        # Process in batches to respect rate limits
        batch_size = 4  # Free tier limit per minute
        
        for i in range(0, len(hashes), batch_size):
            batch = hashes[i:i + batch_size]
            
            for file_hash in batch:
                result = await self.check_hash(file_hash)
                if result:
                    results[file_hash] = result
            
            # Wait between batches
            if i + batch_size < len(hashes):
                await asyncio.sleep(15)
        
        return results


# For testing
async def main():
    """Test the VirusTotal fetcher."""
    # Get API key from environment or settings
    import os
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    
    if not api_key:
        print("VIRUSTOTAL_API_KEY environment variable not set")
        return
    
    fetcher = VirusTotalFetcher(api_key)
    count = await fetcher.fetch_signatures(limit=50)
    print(f"Imported {count} signatures from VirusTotal")


if __name__ == "__main__":
    asyncio.run(main())
