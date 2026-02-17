"""
Database updater for Green Mold Cure.
Orchestrates threat signature updates from multiple sources.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, Callable
from pathlib import Path

from utils.logger import logger
from utils.platform import platform_info
from config.settings import settings
from scanner.signatures import signature_db


class DatabaseUpdater:
    """
    Orchestrates threat database updates from multiple sources.
    
    Supports:
    - ClamAV signatures
    - Abuse.ch feeds (MalwareBazaar, URLhaus, ThreatFox)
    - VirusTotal API
    - Hybrid Analysis API
    - Any.run API
    - AlienVault OTX
    - PhishTank
    - Tor .onion feeds (optional)
    """
    
    def __init__(self):
        """Initialize the database updater."""
        self.sources: dict[str, bool] = {}
        self._load_enabled_sources()
        self._api_keys: dict[str, str] = {}
        self._load_api_keys()
        self.progress_callback: Optional[Callable[[str, str], None]] = None
    
    def _load_enabled_sources(self) -> None:
        """Load enabled sources from settings."""
        self.sources = {
            "clamav": settings.get("updates.sources.clamav", True),
            "abuse_ch": settings.get("updates.sources.abuse_ch", True),
            "virustotal": settings.get("updates.sources.virustotal", False),
            "hybrid_analysis": settings.get("updates.sources.hybrid_analysis", False),
            "anyrun": settings.get("updates.sources.anyrun", False),
            "alienvault": settings.get("updates.sources.alienvault", False),
            "phishtank": settings.get("updates.sources.phishtank", True),
            "tor_feeds": settings.get("updates.sources.tor_feeds", False),
        }
    
    def _load_api_keys(self) -> None:
        """Load API keys from settings."""
        self._api_keys = {
            "virustotal": settings.get_api_key("virustotal"),
            "hybrid_analysis": settings.get_api_key("hybrid_analysis"),
            "anyrun": settings.get_api_key("anyrun"),
            "alienvault": settings.get_api_key("alienvault"),
        }
    
    def set_progress_callback(self, callback: Callable[[str, str], None]) -> None:
        """
        Set a callback for progress updates.
        
        Args:
            callback: Function(source: str, status: str)
        """
        self.progress_callback = callback
    
    def _report_progress(self, source: str, status: str) -> None:
        """Report progress to callback."""
        if self.progress_callback:
            self.progress_callback(source, status)
        logger.info(f"Update progress - {source}: {status}")
    
    async def update_all(self) -> dict[str, bool]:
        """
        Update from all enabled sources.
        
        Returns:
            Dict mapping source names to success status
        """
        self._load_enabled_sources()
        self._load_api_keys()
        
        results = {}
        tasks = []
        
        # Create tasks for enabled sources
        if self.sources.get("clamav"):
            tasks.append(self._update_with_handling("clamav", self._update_clamav))
        
        if self.sources.get("abuse_ch"):
            tasks.append(self._update_with_handling("abuse_ch", self._update_abuse_ch))
        
        if self.sources.get("virustotal") and self._api_keys.get("virustotal"):
            tasks.append(self._update_with_handling("virustotal", self._update_virustotal))
        
        if self.sources.get("hybrid_analysis") and self._api_keys.get("hybrid_analysis"):
            tasks.append(self._update_with_handling("hybrid_analysis", self._update_hybrid_analysis))
        
        if self.sources.get("anyrun") and self._api_keys.get("anyrun"):
            tasks.append(self._update_with_handling("anyrun", self._update_anyrun))
        
        if self.sources.get("alienvault") and self._api_keys.get("alienvault"):
            tasks.append(self._update_with_handling("alienvault", self._update_alienvault))
        
        if self.sources.get("phishtank"):
            tasks.append(self._update_with_handling("phishtank", self._update_phishtank))
        
        if self.sources.get("tor_feeds"):
            tasks.append(self._update_with_handling("tor_feeds", self._update_tor_feeds))
        
        if not tasks:
            logger.warning("No update sources enabled")
            return {"error": "No sources enabled"}
        
        # Run updates concurrently
        if tasks:
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(task_results):
                if isinstance(result, Exception):
                    logger.error(f"Update task failed: {result}")
        
        # Get final stats
        stats = signature_db.get_database_stats()
        logger.info(f"Update complete. Total signatures: {stats.get('total_signatures', 0)}")
        
        return results
    
    async def _update_with_handling(self, source: str, update_func) -> bool:
        """
        Run an update with error handling.
        
        Args:
            source: Source name
            update_func: Async update function
            
        Returns:
            True if successful
        """
        try:
            self._report_progress(source, "Starting update...")
            result = await update_func()
            self._report_progress(source, "Complete" if result else "Failed")
            return result
        except Exception as e:
            logger.error(f"Update failed for {source}: {e}")
            self._report_progress(source, f"Error: {str(e)[:50]}")
            return False
    
    async def _update_clamav(self) -> bool:
        """
        Update from ClamAV signatures.
        
        Returns:
            True if successful
        """
        try:
            # Import here to avoid circular imports
            from sources.clamav import ClamAVUpdater
            
            updater = ClamAVUpdater()
            count = await updater.fetch_signatures()
            
            if count > 0:
                signature_db.update_source_info("clamav", count)
                logger.database_update("clamav", count, 0, True)
                return True
            
            return False
        except Exception as e:
            logger.error(f"ClamAV update failed: {e}")
            return False
    
    async def _update_abuse_ch(self) -> bool:
        """
        Update from Abuse.ch feeds.
        
        Returns:
            True if successful
        """
        try:
            from sources.abuse_ch import AbuseChUpdater
            
            updater = AbuseChUpdater()
            total = 0
            
            # Fetch from MalwareBazaar
            self._report_progress("abuse_ch", "Fetching MalwareBazaar...")
            count = await updater.fetch_malware_bazaar()
            total += count
            self._report_progress("abuse_ch", f"MalwareBazaar: {count} signatures")
            
            # Fetch from URLhaus
            self._report_progress("abuse_ch", "Fetching URLhaus...")
            count = await updater.fetch_urlhaus()
            total += count
            self._report_progress("abuse_ch", f"URLhaus: {count} signatures")
            
            # Fetch from ThreatFox
            self._report_progress("abuse_ch", "Fetching ThreatFox...")
            count = await updater.fetch_threatfox()
            total += count
            self._report_progress("abuse_ch", f"ThreatFox: {count} signatures")
            
            if total > 0:
                signature_db.update_source_info("abuse_ch", total)
                logger.database_update("abuse_ch", total, 0, True)
                return True
            
            return False
        except Exception as e:
            logger.error(f"Abuse.ch update failed: {e}")
            return False
    
    async def _update_virustotal(self) -> bool:
        """
        Update from VirusTotal API.
        
        Returns:
            True if successful
        """
        try:
            from sources.virustotal import VirusTotalFetcher
            
            api_key = self._api_keys.get("virustotal")
            if not api_key:
                logger.warning("VirusTotal API key not configured")
                return False
            
            fetcher = VirusTotalFetcher(api_key)
            count = await fetcher.fetch_signatures()
            
            if count > 0:
                signature_db.update_source_info("virustotal", count)
                logger.database_update("virustotal", count, 0, True)
                return True
            
            return False
        except Exception as e:
            logger.error(f"VirusTotal update failed: {e}")
            return False
    
    async def _update_hybrid_analysis(self) -> bool:
        """
        Update from Hybrid Analysis API.
        
        Returns:
            True if successful
        """
        try:
            from sources.hybrid_analysis import HybridAnalysisFetcher
            
            api_key = self._api_keys.get("hybrid_analysis")
            if not api_key:
                logger.warning("Hybrid Analysis API key not configured")
                return False
            
            fetcher = HybridAnalysisFetcher(api_key)
            count = await fetcher.fetch_signatures()
            
            if count > 0:
                signature_db.update_source_info("hybrid_analysis", count)
                logger.database_update("hybrid_analysis", count, 0, True)
                return True
            
            return False
        except Exception as e:
            logger.error(f"Hybrid Analysis update failed: {e}")
            return False
    
    async def _update_anyrun(self) -> bool:
        """
        Update from Any.run API.
        
        Returns:
            True if successful
        """
        try:
            from sources.anyrun import AnyRunFetcher
            
            api_key = self._api_keys.get("anyrun")
            if not api_key:
                logger.warning("Any.run API key not configured")
                return False
            
            fetcher = AnyRunFetcher(api_key)
            count = await fetcher.fetch_signatures()
            
            if count > 0:
                signature_db.update_source_info("anyrun", count)
                logger.database_update("anyrun", count, 0, True)
                return True
            
            return False
        except Exception as e:
            logger.error(f"Any.run update failed: {e}")
            return False
    
    async def _update_alienvault(self) -> bool:
        """
        Update from AlienVault OTX.
        
        Returns:
            True if successful
        """
        try:
            from sources.alienvault import AlienVaultFetcher
            
            api_key = self._api_keys.get("alienvault")
            if not api_key:
                logger.warning("AlienVault API key not configured")
                return False
            
            fetcher = AlienVaultFetcher(api_key)
            count = await fetcher.fetch_indicators()
            
            if count > 0:
                signature_db.update_source_info("alienvault", count)
                logger.database_update("alienvault", count, 0, True)
                return True
            
            return False
        except Exception as e:
            logger.error(f"AlienVault update failed: {e}")
            return False
    
    async def _update_phishtank(self) -> bool:
        """
        Update from PhishTank.
        
        Returns:
            True if successful
        """
        try:
            from sources.phishtank import PhishTankFetcher
            
            fetcher = PhishTankFetcher()
            count = await fetcher.fetch_phishing_urls()
            
            if count > 0:
                signature_db.update_source_info("phishtank", count)
                logger.database_update("phishtank", count, 0, True)
                return True
            
            return False
        except Exception as e:
            logger.error(f"PhishTank update failed: {e}")
            return False
    
    async def _update_tor_feeds(self) -> bool:
        """
        Update from Tor .onion feeds.
        
        Returns:
            True if successful
        """
        try:
            from sources.tor_feeds import TorFeedFetcher
            
            fetcher = TorFeedFetcher()
            count = await fetcher.fetch_feeds()
            
            if count > 0:
                signature_db.update_source_info("tor_feeds", count)
                logger.database_update("tor_feeds", count, 0, True)
                return True
            
            return False
        except Exception as e:
            logger.error(f"Tor feeds update failed: {e}")
            return False
    
    def get_last_update_times(self) -> dict[str, str]:
        """
        Get last update times for all sources.
        
        Returns:
            Dict mapping source names to last update times
        """
        # This would query the database for last update times
        # For now, return a placeholder
        return {
            source: "Never" for source in self.sources
        }
    
    def should_update(self) -> bool:
        """
        Check if an update is due based on settings.
        
        Returns:
            True if update is due
        """
        if not settings.get("updates.auto_update", False):
            return False
        
        interval_hours = settings.get("updates.update_interval_hours", 24)
        last_update = self._get_last_global_update()
        
        if last_update is None:
            return True
        
        return datetime.now(timezone.utc) - last_update > timedelta(hours=interval_hours)
    
    def _get_last_global_update(self) -> Optional[datetime]:
        """Get the most recent update time across all sources."""
        # Would query database for this
        return None


# Global updater instance
db_updater = DatabaseUpdater()
