"""
Hybrid Analysis API integration for Green Mold Cure.
Fetches threat intelligence from Hybrid Analysis.
"""

import asyncio
from typing import Optional, List, Dict

import aiohttp

from.utils.logger import logger
from.scanner.signatures import signature_db


class HybridAnalysisFetcher:
    """
    Fetches threat intelligence from Hybrid Analysis API.
    
    Note: Requires a valid API key from hybrid-analysis.com
    Free tier available with registration.
    """
    
    API_BASE = "https://www.hybrid-analysis.com/api/v2"
    
    def __init__(self, api_key: str):
        """
        Initialize the Hybrid Analysis fetcher.
        
        Args:
            api_key: Hybrid Analysis API key
        """
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with API headers."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    "api-key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "GreenMoldCure/1.0",
                },
                timeout=aiohttp.ClientTimeout(total=60)
            )
        return self.session
    
    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def _request(self, endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Optional[Dict]:
        """
        Make an API request.
        
        Args:
            endpoint: API endpoint
            method: HTTP method
            data: Optional request body
            
        Returns:
            JSON response or None on error
        """
        try:
            session = await self._get_session()
            url = f"{self.API_BASE}/{endpoint}"
            
            async with session.request(method, url, json=data) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:
                    logger.warning("Hybrid Analysis rate limit exceeded")
                    await asyncio.sleep(30)
                    return await self._request(endpoint, method, data)
                else:
                    logger.warning(f"Hybrid Analysis API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Hybrid Analysis request failed: {e}")
            return None
    
    async def fetch_signatures(self, limit: int = 100) -> int:
        """
        Fetch recent malware signatures from Hybrid Analysis.
        
        Args:
            limit: Maximum number of signatures to fetch
            
        Returns:
            Number of signatures imported
        """
        try:
            logger.debug(f"Fetching up to {limit} signatures from Hybrid Analysis...")
            
            signatures = await self._fetch_recent_samples(limit)
            
            if not signatures:
                logger.info("No signatures fetched from Hybrid Analysis")
                return 0
            
            # Import signatures
            imported, failed = signature_db.add_signatures_batch(
                signatures,
                source="hybrid_analysis",
            )
            logger.debug(f"Hybrid Analysis: {imported} imported, {failed} failed")
            return imported
            
        except Exception as e:
            logger.error(f"Hybrid Analysis fetch failed: {e}")
            return 0
        finally:
            await self.close()
    
    async def _fetch_recent_samples(self, limit: int) -> List[Dict]:
        """
        Fetch recent malware samples.
        
        Args:
            limit: Maximum samples to fetch
            
        Returns:
            List of signature dicts
        """
        signatures = []
        
        try:
            # Get recent submissions
            # Note: API endpoint may vary based on subscription level
            data = await self._request("overview/list", "POST", {
                "limit": min(limit, 100),
                "order_by": "last_submission",
                "order": "desc",
            })
            
            if data:
                for sample in data:
                    sha256 = sample.get("sha256", "")
                    if sha256:
                        signatures.append({
                            "hash_sha256": sha256.lower(),
                            "threat_name": f"HybridAnalysis.{sample.get('submit_name', 'Unknown')}",
                            "threat_type": sample.get("type", "malware"),
                            "severity": self._calculate_severity(sample),
                        })
        except Exception as e:
            logger.debug(f"Hybrid Analysis fetch failed: {e}")
        
        return signatures
    
    def _calculate_severity(self, sample: Dict) -> str:
        """
        Calculate threat severity based on Hybrid Analysis data.
        
        Args:
            sample: Sample data from Hybrid Analysis
            
        Returns:
            Severity string
        """
        # Check verdict scores
        threat_score = sample.get("threat_score", 0)
        verdict = sample.get("verdict", "")
        
        if verdict == "malicious" or threat_score > 80:
            return "critical"
        elif verdict == "suspicious" or threat_score > 50:
            return "high"
        elif threat_score > 20:
            return "medium"
        else:
            return "low"
    
    async def check_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Check a single hash against Hybrid Analysis.
        
        Args:
            file_hash: SHA256 hash to check
            
        Returns:
            Threat info dict or None
        """
        try:
            data = await self._request(f"overview/search", "POST", {
                "hash": file_hash,
            })
            
            if data and len(data) > 0:
                sample = data[0]
                verdict = sample.get("verdict", "")
                threat_score = sample.get("threat_score", 0)
                
                if verdict == "malicious" or threat_score > 50:
                    return {
                        "name": sample.get("submit_name", "Unknown"),
                        "type": sample.get("type", "malware"),
                        "severity": "high" if threat_score > 80 else "medium",
                        "source": "hybrid_analysis",
                        "threat_score": threat_score,
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Hybrid Analysis hash check failed: {e}")
            return None
    
    async def get_report(self, job_id: str) -> Optional[Dict]:
        """
        Get a full analysis report.
        
        Args:
            job_id: Analysis job ID
            
        Returns:
            Full report data or None
        """
        try:
            data = await self._request(f"report/{job_id}/summary")
            return data
        except Exception as e:
            logger.error(f"Failed to get Hybrid Analysis report: {e}")
            return None


# For testing
async def main():
    """Test the Hybrid Analysis fetcher."""
    import os
    api_key = os.environ.get("HYBRID_ANALYSIS_API_KEY")
    
    if not api_key:
        print("HYBRID_ANALYSIS_API_KEY environment variable not set")
        return
    
    fetcher = HybridAnalysisFetcher(api_key)
    count = await fetcher.fetch_signatures(limit=50)
    print(f"Imported {count} signatures from Hybrid Analysis")


if __name__ == "__main__":
    asyncio.run(main())
