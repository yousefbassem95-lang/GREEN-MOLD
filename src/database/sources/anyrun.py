"""
Any.run API integration for Green Mold Cure.
Fetches threat intelligence from Any.run sandbox.
"""

import asyncio
from typing import Optional, List, Dict

import aiohttp

from.utils.logger import logger
from.scanner.signatures import signature_db


class AnyRunFetcher:
    """
    Fetches threat intelligence from Any.run API.
    
    Note: Requires a valid API key from any.run
    Free tier available with registration.
    """
    
    API_BASE = "https://api.any.run"
    
    def __init__(self, api_key: str):
        """
        Initialize the Any.run fetcher.
        
        Args:
            api_key: Any.run API key
        """
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with API headers."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Accept": "application/json",
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
                    logger.warning("Any.run rate limit exceeded")
                    await asyncio.sleep(30)
                    return await self._request(endpoint, method, data)
                else:
                    logger.warning(f"Any.run API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Any.run request failed: {e}")
            return None
    
    async def fetch_signatures(self, limit: int = 100) -> int:
        """
        Fetch recent malware signatures from Any.run.
        
        Args:
            limit: Maximum number of signatures to fetch
            
        Returns:
            Number of signatures imported
        """
        try:
            logger.debug(f"Fetching up to {limit} signatures from Any.run...")
            
            signatures = await self._fetch_recent_tasks(limit)
            
            if not signatures:
                logger.info("No signatures fetched from Any.run")
                return 0
            
            # Import signatures
            imported, failed = signature_db.add_signatures_batch(
                signatures,
                source="anyrun",
            )
            logger.debug(f"Any.run: {imported} imported, {failed} failed")
            return imported
            
        except Exception as e:
            logger.error(f"Any.run fetch failed: {e}")
            return 0
        finally:
            await self.close()
    
    async def _fetch_recent_tasks(self, limit: int) -> List[Dict]:
        """
        Fetch recent analysis tasks.
        
        Args:
            limit: Maximum tasks to fetch
            
        Returns:
            List of signature dicts
        """
        signatures = []
        
        try:
            # Get recent public tasks
            data = await self._request("subscriptions", "POST", {
                "limit": min(limit, 100),
                "sort": "desc",
                "order_by": "publish_time",
            })
            
            if data and "tasks" in data:
                for task in data["tasks"]:
                    sha256 = task.get("sha256", "")
                    if sha256:
                        signatures.append({
                            "hash_sha256": sha256.lower(),
                            "threat_name": f"AnyRun.{task.get('verdict', 'Unknown')}",
                            "threat_type": task.get("type", "malware"),
                            "severity": self._calculate_severity(task),
                        })
        except Exception as e:
            logger.debug(f"Any.run fetch failed: {e}")
        
        return signatures
    
    def _calculate_severity(self, task: Dict) -> str:
        """
        Calculate threat severity based on Any.run data.
        
        Args:
            task: Task data from Any.run
            
        Returns:
            Severity string
        """
        verdict = task.get("verdict", "").lower()
        score = task.get("score", 0)
        
        if verdict == "malicious" or score > 80:
            return "critical"
        elif verdict == "suspicious" or score > 50:
            return "high"
        elif score > 20:
            return "medium"
        else:
            return "low"
    
    async def check_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Check a single hash against Any.run.
        
        Args:
            file_hash: SHA256 hash to check
            
        Returns:
            Threat info dict or None
        """
        try:
            data = await self._request("search", "POST", {
                "hash": file_hash,
                "limit": 1,
            })
            
            if data and "tasks" in data and len(data["tasks"]) > 0:
                task = data["tasks"][0]
                verdict = task.get("verdict", "").lower()
                
                if verdict == "malicious":
                    return {
                        "name": task.get("verdict", "Unknown"),
                        "type": task.get("type", "malware"),
                        "severity": "high",
                        "source": "anyrun",
                    }
                elif verdict == "suspicious":
                    return {
                        "name": "Suspicious",
                        "type": "suspicious",
                        "severity": "medium",
                        "source": "anyrun",
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Any.run hash check failed: {e}")
            return None


# For testing
async def main():
    """Test the Any.run fetcher."""
    import os
    api_key = os.environ.get("ANYRUN_API_KEY")
    
    if not api_key:
        print("ANYRUN_API_KEY environment variable not set")
        return
    
    fetcher = AnyRunFetcher(api_key)
    count = await fetcher.fetch_signatures(limit=50)
    print(f"Imported {count} signatures from Any.run")


if __name__ == "__main__":
    asyncio.run(main())
