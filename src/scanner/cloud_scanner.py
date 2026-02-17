"""
Cloud Integration for Green Mold Cure.
Multi-engine cloud scanning services integration.

Supported Services:
- MetaDefender (OPSWAT) - 30+ antivirus engines
- Jotti's Malware Scan - 15+ antivirus engines
- VirusTotal - 70+ antivirus engines
- Hybrid Analysis - Behavioral analysis
- Any.run - Interactive sandbox
"""

import asyncio
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

import aiohttp

from utils.logger import logger
from config.settings import settings


@dataclass
class CloudScanResult:
    """Result from cloud scanning service."""
    service: str
    file_hash: str
    detected: bool
    detection_ratio: str  # e.g., "5/70"
    threat_name: Optional[str]
    scan_date: Optional[str]
    permalink: Optional[str]
    detailed_results: Dict[str, Any]
    confidence: str  # low, medium, high
    explanation: str


class CloudScanner:
    """
    Multi-service cloud malware scanner.
    
    Features:
    - Scan files against multiple cloud services
    - Aggregate results from all services
    - Cache results to avoid redundant API calls
    - Support for hash-only and file upload scanning
    """
    
    # API endpoints
    SERVICES = {
        'virustotal': {
            'base_url': 'https://www.virustotal.com/api/v3',
            'file_url': 'https://www.virustotal.com/api/v3/files',
            'url_url': 'https://www.virustotal.com/api/v3/urls',
            'auth_header': 'x-apikey',
        },
        'metadefender': {
            'base_url': 'https://api.metadefender.com/v2',
            'hash_url': 'https://api.metadefender.com/v2/hash/',
            'file_url': 'https://api.metadefender.com/v2/file',
            'auth_header': 'Authorization',
        },
        'jotti': {
            'base_url': 'https://jotti.org/api/v1',
            'scan_url': 'https://jotti.org/api/v1/scan_file',
            'search_url': 'https://jotti.org/api/v1/search',
            'auth_header': 'API-Key',
        },
        'hybrid_analysis': {
            'base_url': 'https://www.hybrid-analysis.com/api/v2',
            'search_url': 'https://www.hybrid-analysis.com/api/v2/search',
            'report_url': 'https://www.hybrid-analysis.com/api/v2/report/',
            'auth_header': 'api-key',
        },
    }
    
    def __init__(self):
        """Initialize the cloud scanner."""
        self.results: List[CloudScanResult] = []
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache: Dict[str, CloudScanResult] = {}
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120)
            )
        return self._session
    
    async def close(self):
        """Close HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def _get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service."""
        key_map = {
            'virustotal': 'virustotal',
            'metadefender': 'metadefender',
            'jotti': 'jotti',
            'hybrid_analysis': 'hybrid_analysis',
        }
        return settings.get_api_key(key_map.get(service, service))
    
    async def scan_hash(self, file_hash: str, services: Optional[List[str]] = None) -> List[CloudScanResult]:
        """
        Scan a file hash against cloud services.
        
        Args:
            file_hash: SHA256 hash of the file
            services: List of services to use (None = all available)
            
        Returns:
            List of CloudScanResult objects
        """
        if services is None:
            services = ['virustotal', 'metadefender', 'jotti']
        
        results = []
        
        for service in services:
            # Check cache first
            cache_key = f"{service}:{file_hash}"
            if cache_key in self._cache:
                results.append(self._cache[cache_key])
                continue
            
            api_key = self._get_api_key(service)
            
            if service == 'virustotal':
                result = await self._scan_virustotal_hash(file_hash, api_key)
            elif service == 'metadefender':
                result = await self._scan_metadefender_hash(file_hash, api_key)
            elif service == 'jotti':
                result = await self._scan_jotti_hash(file_hash, api_key)
            elif service == 'hybrid_analysis':
                result = await self._scan_hybrid_analysis_hash(file_hash, api_key)
            else:
                continue
            
            if result:
                self._cache[cache_key] = result
                results.append(result)
        
        self.results.extend(results)
        return results
    
    async def scan_file(self, file_path: Path, services: Optional[List[str]] = None) -> List[CloudScanResult]:
        """
        Upload and scan a file against cloud services.
        
        Args:
            file_path: Path to the file to scan
            services: List of services to use
            
        Returns:
            List of CloudScanResult objects
        """
        if services is None:
            services = ['virustotal', 'metadefender']
        
        # Calculate hash first
        file_hash = self._calculate_hash(file_path)
        
        # Check if already in cache
        results = []
        for service in services:
            cache_key = f"{service}:{file_hash}"
            if cache_key in self._cache:
                results.append(self._cache[cache_key])
        
        # If we have results from all cached services, return them
        if len(results) == len(services):
            return results
        
        # Otherwise, scan
        for service in services:
            cache_key = f"{service}:{file_hash}"
            if cache_key in self._cache:
                continue
            
            api_key = self._get_api_key(service)
            
            if service == 'virustotal':
                result = await self._scan_virustotal_file(file_path, api_key)
            elif service == 'metadefender':
                result = await self._scan_metadefender_file(file_path, api_key)
            else:
                continue
            
            if result:
                self._cache[cache_key] = result
                results.append(result)
        
        self.results.extend(results)
        return results
    
    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    async def _scan_virustotal_hash(self, file_hash: str, api_key: Optional[str]) -> Optional[CloudScanResult]:
        """Scan hash against VirusTotal."""
        if not api_key:
            logger.debug("VirusTotal API key not configured")
            return None
        
        try:
            session = await self._get_session()
            url = f"{self.SERVICES['virustotal']['file_url']}/{file_hash}"
            headers = {self.SERVICES['virustotal']['auth_header']: api_key}
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    attrs = data.get('data', {}).get('attributes', {})
                    last_analysis = attrs.get('last_analysis_stats', {})
                    
                    malicious = last_analysis.get('malicious', 0)
                    total = sum(last_analysis.values())
                    
                    return CloudScanResult(
                        service='VirusTotal',
                        file_hash=file_hash,
                        detected=malicious > 0,
                        detection_ratio=f"{malicious}/{total}",
                        threat_name=attrs.get('meaningful_name'),
                        scan_date=attrs.get('last_analysis_date'),
                        permalink=attrs.get('html_info', {}).get('url') if isinstance(attrs.get('html_info'), dict) else None,
                        detailed_results={'last_analysis_stats': last_analysis},
                        confidence='high' if malicious > 10 else 'medium' if malicious > 5 else 'low',
                        explanation=f"VirusTotal: {malicious}/{total} engines detected this file as malicious."
                    )
                elif response.status == 404:
                    return CloudScanResult(
                        service='VirusTotal',
                        file_hash=file_hash,
                        detected=False,
                        detection_ratio='0/0',
                        threat_name=None,
                        scan_date=None,
                        permalink=None,
                        detailed_results={},
                        confidence='low',
                        explanation='File not found in VirusTotal database.'
                    )
        except Exception as e:
            logger.debug(f"VirusTotal scan failed: {e}")
        
        return None
    
    async def _scan_virultotal_file(self, file_path: Path, api_key: Optional[str]) -> Optional[CloudScanResult]:
        """Upload and scan file to VirusTotal."""
        if not api_key:
            return None
        
        try:
            session = await self._get_session()
            url = f"{self.SERVICES['virustotal']['file_url']}"
            headers = {self.SERVICES['virustotal']['auth_header']: api_key}
            
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}
                async with session.post(url, headers=headers, data=files) as response:
                    if response.status == 200:
                        data = await response.json()
                        # Return analysis URL for user to check results
                        return CloudScanResult(
                            service='VirusTotal',
                            file_hash=self._calculate_hash(file_path),
                            detected=False,
                            detection_ratio='pending',
                            threat_name=None,
                            scan_date=None,
                            permalink=data.get('data', {}).get('links', {}).get('self'),
                            detailed_results={'analysis_id': data.get('data', {}).get('id')},
                            confidence='medium',
                            explanation='File uploaded for analysis. Check permalink for results.'
                        )
        except Exception as e:
            logger.debug(f"VirusTotal file upload failed: {e}")
        
        return None
    
    async def _scan_metadefender_hash(self, file_hash: str, api_key: Optional[str]) -> Optional[CloudScanResult]:
        """Scan hash against MetaDefender."""
        if not api_key:
            # MetaDefender has a free tier without API key (limited)
            api_key = ''
        
        try:
            session = await self._get_session()
            url = f"{self.SERVICES['metadefender']['hash_url']}{file_hash}"
            headers = {
                self.SERVICES['metadefender']['auth_header']: f'Bearer {api_key}' if api_key else '',
                'Content-Type': 'application/json',
            }
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    detections = data.get('detections', [])
                    malicious = len([d for d in detections if d.get('malware')])
                    total = len(detections)
                    
                    return CloudScanResult(
                        service='MetaDefender',
                        file_hash=file_hash,
                        detected=malicious > 0,
                        detection_ratio=f"{malicious}/{total}",
                        threat_name=data.get('file_info', {}).get('infection_type'),
                        scan_date=data.get('file_info', {}).get('last_scan'),
                        permalink=f"https://metadefender.opswat.com/results#!/file-hash/{file_hash}",
                        detailed_results={'detections': detections},
                        confidence='high' if malicious > 5 else 'medium' if malicious > 2 else 'low',
                        explanation=f"MetaDefender: {malicious}/{total} engines detected threats."
                    )
        except Exception as e:
            logger.debug(f"MetaDefender scan failed: {e}")
        
        return None
    
    async def _scan_metadefender_file(self, file_path: Path, api_key: Optional[str]) -> Optional[CloudScanResult]:
        """Upload and scan file to MetaDefender."""
        if not api_key:
            return None
        
        try:
            session = await self._get_session()
            url = self.SERVICES['metadefender']['file_url']
            headers = {
                self.SERVICES['metadefender']['auth_header']: f'Bearer {api_key}',
            }
            
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}
                async with session.post(url, headers=headers, data=files) as response:
                    if response.status == 200:
                        data = await response.json()
                        return CloudScanResult(
                            service='MetaDefender',
                            file_hash=self._calculate_hash(file_path),
                            detected=data.get('detections', []),
                            detection_ratio=data.get('scan_all_result_i', '0/0'),
                            threat_name=data.get('file_info', {}).get('infection_type'),
                            scan_date=data.get('file_info', {}).get('last_scan'),
                            permalink=f"https://metadefender.opswat.com/results#!/file-hash/{data.get('file_info', {}).get('sha256')}",
                            detailed_results=data,
                            confidence='high',
                            explanation='File scanned by MetaDefender cloud.'
                        )
        except Exception as e:
            logger.debug(f"MetaDefender file upload failed: {e}")
        
        return None
    
    async def _scan_jotti_hash(self, file_hash: str, api_key: Optional[str]) -> Optional[CloudScanResult]:
        """Scan hash against Jotti's Malware Scan."""
        if not api_key:
            return None
        
        try:
            session = await self._get_session()
            url = f"{self.SERVICES['jotti']['search_url']}/{file_hash}"
            headers = {self.SERVICES['jotti']['auth_header']: api_key}
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    return CloudScanResult(
                        service="Jotti's",
                        file_hash=file_hash,
                        detected=data.get('malicious', False),
                        detection_ratio=f"{data.get('antivirus_detections', 0)}/{data.get('total_antivirus', 0)}",
                        threat_name=data.get('malware_name'),
                        scan_date=data.get('scan_date'),
                        permalink=f"https://virusscan.jotti.org/en-US/scan-file/{file_hash}",
                        detailed_results=data,
                        confidence='medium',
                        explanation=f"Jotti's: {'Malware detected' if data.get('malicious') else 'No threats detected'}."
                    )
        except Exception as e:
            logger.debug(f"Jotti's scan failed: {e}")
        
        return None
    
    async def _scan_hybrid_analysis_hash(self, file_hash: str, api_key: Optional[str]) -> Optional[CloudScanResult]:
        """Scan hash against Hybrid Analysis."""
        if not api_key:
            return None
        
        try:
            session = await self._get_session()
            url = f"{self.SERVICES['hybrid_analysis']['search_url']}"
            headers = {
                self.SERVICES['hybrid_analysis']['auth_header']: api_key,
                'Accept': 'application/json',
            }
            params = {'hash': file_hash}
            
            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data:
                        sample = data[0]
                        verdict = sample.get('verdict', '')
                        
                        return CloudScanResult(
                            service='Hybrid Analysis',
                            file_hash=file_hash,
                            detected=verdict == 'malicious',
                            detection_ratio=f"{sample.get('threat_score', 0)}/100",
                            threat_name=sample.get('submit_name'),
                            scan_date=sample.get('last_submission'),
                            permalink=f"https://www.hybrid-analysis.com/sample/{file_hash}",
                            detailed_results=sample,
                            confidence='high' if verdict == 'malicious' else 'medium',
                            explanation=f"Hybrid Analysis verdict: {verdict} (threat score: {sample.get('threat_score', 0)})."
                        )
        except Exception as e:
            logger.debug(f"Hybrid Analysis scan failed: {e}")
        
        return None
    
    def get_aggregated_result(self, file_hash: str) -> Dict[str, Any]:
        """
        Get aggregated results from all cloud services.
        
        Args:
            file_hash: SHA256 hash of the file
            
        Returns:
            Aggregated result dictionary
        """
        results = [r for r in self.results if r.file_hash == file_hash]
        
        if not results:
            return {'available': False}
        
        total_services = len(results)
        detected_services = len([r for r in results if r.detected])
        
        # Calculate confidence
        if detected_services == 0:
            confidence = 'low'
            verdict = 'clean'
        elif detected_services >= total_services / 2:
            confidence = 'high'
            verdict = 'malicious'
        else:
            confidence = 'medium'
            verdict = 'suspicious'
        
        return {
            'available': True,
            'file_hash': file_hash,
            'services_scanned': total_services,
            'services_detected': detected_services,
            'detection_ratio': f"{detected_services}/{total_services}",
            'verdict': verdict,
            'confidence': confidence,
            'results': [
                {
                    'service': r.service,
                    'detected': r.detected,
                    'ratio': r.detection_ratio,
                    'threat': r.threat_name,
                }
                for r in results
            ],
            'permalinks': [r.permalink for r in results if r.permalink],
        }
    
    async def scan_all_services(self, file_path: Path) -> Dict[str, Any]:
        """
        Scan a file against all available cloud services.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Aggregated scan results
        """
        file_hash = self._calculate_hash(file_path)
        
        # Scan with all services concurrently
        services = ['virustotal', 'metadefender', 'jotti', 'hybrid_analysis']
        
        tasks = []
        for service in services:
            api_key = self._get_api_key(service)
            if api_key or service in ['virustotal', 'metadefender']:  # Some work without key
                tasks.append(self.scan_hash(file_hash, [service]))
        
        if tasks:
            await asyncio.gather(*tasks)
        
        await self.close()
        
        return self.get_aggregated_result(file_hash)


# Global cloud scanner instance
cloud_scanner = CloudScanner()
