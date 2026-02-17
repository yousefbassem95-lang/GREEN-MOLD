"""
AlienVault OTX API integration for Green Mold Cure.
Fetches threat indicators from AlienVault Open Threat Exchange.
"""

import asyncio
from typing import Optional, List, Dict
from datetime import datetime, timedelta

import aiohttp

from.utils.logger import logger
from.scanner.signatures import signature_db


class AlienVaultFetcher:
    """
    Fetches threat intelligence from AlienVault OTX.
    
    Note: Requires a valid API key from otx.alienvault.com
    Free tier available with registration.
    """
    
    API_BASE = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: str):
        """
        Initialize the AlienVault fetcher.
        
        Args:
            api_key: AlienVault OTX API key
        """
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session with API headers."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    "X-OTX-API-KEY": self.api_key,
                    "Accept": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=60)
            )
        return self.session
    
    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def _request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """
        Make an API request.
        
        Args:
            endpoint: API endpoint
            params: Optional query parameters
            
        Returns:
            JSON response or None on error
        """
        try:
            session = await self._get_session()
            url = f"{self.API_BASE}/{endpoint}"
            
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:
                    logger.warning("AlienVault rate limit exceeded")
                    await asyncio.sleep(30)
                    return await self._request(endpoint, params)
                else:
                    logger.warning(f"AlienVault API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"AlienVault request failed: {e}")
            return None
    
    async def fetch_indicators(self, limit: int = 200) -> int:
        """
        Fetch threat indicators from AlienVault OTX.
        
        Args:
            limit: Maximum number of indicators to fetch
            
        Returns:
            Number of indicators imported
        """
        try:
            logger.debug(f"Fetching up to {limit} indicators from AlienVault OTX...")
            
            indicators = await self._fetch_subscribed_pulses(limit)
            
            if not indicators:
                logger.info("No indicators fetched from AlienVault OTX")
                return 0
            
            # Import indicators
            imported, failed = signature_db.add_signatures_batch(
                indicators,
                source="alienvault",
            )
            logger.debug(f"AlienVault: {imported} imported, {failed} failed")
            return imported
            
        except Exception as e:
            logger.error(f"AlienVault fetch failed: {e}")
            return 0
        finally:
            await self.close()
    
    async def _fetch_subscribed_pulses(self, limit: int) -> List[Dict]:
        """
        Fetch indicators from subscribed pulses.
        
        Args:
            limit: Maximum indicators to fetch
            
        Returns:
            List of indicator dicts
        """
        indicators = []
        
        try:
            # Get subscribed pulses
            pulses_data = await self._request("pulses/subscribed")
            
            if pulses_data and "results" in pulses_data:
                for pulse in pulses_data["results"][:20]:  # Limit pulses
                    pulse_id = pulse.get("id", "")
                    
                    # Get indicators from each pulse
                    pulse_data = await self._request(f"pulses/{pulse_id}/indicators")
                    
                    if pulse_data and "indicators" in pulse_data:
                        for indicator in pulse_data["indicators"][:10]:  # Limit per pulse
                            ind_type = indicator.get("type", "")
                            ind_value = indicator.get("indicator", "")
                            
                            if ind_type == "FileHash-SHA256" and len(ind_value) == 64:
                                indicators.append({
                                    "hash_sha256": ind_value.lower(),
                                    "threat_name": f"AlienVault.{pulse.get('name', 'Unknown')}",
                                    "threat_type": "malware",
                                    "severity": "high",
                                })
                            elif ind_type in ("URL", "IPv4", "domain"):
                                # Hash other indicator types for storage
                                import hashlib
                                ind_hash = hashlib.sha256(ind_value.encode()).hexdigest()
                                indicators.append({
                                    "hash_sha256": ind_hash,
                                    "threat_name": f"AlienVault.{ind_type}",
                                    "threat_type": ind_type.lower(),
                                    "severity": "medium",
                                    "metadata": {"indicator": ind_value, "type": ind_type},
                                })
                            
                            if len(indicators) >= limit:
                                break
                    
                    if len(indicators) >= limit:
                        break
                            
        except Exception as e:
            logger.debug(f"AlienVault pulse fetch failed: {e}")
        
        return indicators
    
    async def get_pulse_info(self, pulse_id: str) -> Optional[Dict]:
        """
        Get information about a specific pulse.
        
        Args:
            pulse_id: Pulse ID
            
        Returns:
            Pulse information or None
        """
        try:
            return await self._request(f"pulses/{pulse_id}")
        except Exception as e:
            logger.error(f"Failed to get pulse info: {e}")
            return None


# For testing
async def main():
    """Test the AlienVault fetcher."""
    import os
    api_key = os.environ.get("ALIENVAULT_API_KEY")
    
    if not api_key:
        print("ALIENVAULT_API_KEY environment variable not set")
        return
    
    fetcher = AlienVaultFetcher(api_key)
    count = await fetcher.fetch_indicators(limit=100)
    print(f"Imported {count} indicators from AlienVault OTX")


if __name__ == "__main__":
    asyncio.run(main())
