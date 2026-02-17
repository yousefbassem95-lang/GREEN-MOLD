"""
Heuristic analysis for Green Mold Cure.
Behavioral and pattern-based threat detection.
"""

import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from utils.logger import logger


@dataclass
class HeuristicResult:
    """Result of heuristic analysis."""
    file_path: Path
    suspicion_level: int  # 0-100
    indicators: list[str]
    recommendation: str


class HeuristicAnalyzer:
    """
    Performs heuristic analysis on files.
    
    Detects suspicious patterns and behaviors that may indicate
    malware, even without a known signature match.
    """
    
    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.msi', '.com', '.pif', '.reg', '.lnk', '.wsf', '.hta', '.cpl',
    }
    
    # Suspicious strings commonly found in malware
    SUSPICIOUS_STRINGS = [
        # Keylogging
        r'GetAsyncKeyState', r'GetKeyState', r'keylog',
        # Process injection
        r'VirtualAllocEx', r'WriteProcessMemory', r'CreateRemoteThread',
        # Persistence
        r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        # Anti-analysis
        r'IsDebuggerPresent', r'CheckRemoteDebuggerPresent',
        # Network
        r'URLDownloadToFile', r'WinHttpOpen', r'InternetOpen',
        # Encryption (could be ransomware)
        r'CryptEncrypt', r'CryptDecrypt', r'CryptGenKey',
        # Screen capture
        r'BitBlt', r'GetDC', r'PrintScreen',
        # Clipboard
        r'OpenClipboard', r'GetClipboardData',
        # Webcam
        r'capGetDriverDescription',
    ]
    
    # Suspicious PE header patterns (for Windows executables)
    PE_SUSPICIOUS_PATTERNS = [
        r'MZ.{0,256}This program cannot be run',  # Standard PE
        r'\.packed', r'\.encrypt', r'\.vmp',  # Packer/protector sections
    ]
    
    def __init__(self):
        """Initialize the heuristic analyzer."""
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.SUSPICIOUS_STRINGS
        ]
    
    def analyze_file(self, file_path: Path, max_size: int = 10 * 1024 * 1024) -> HeuristicResult:
        """
        Perform heuristic analysis on a file.
        
        Args:
            file_path: Path to the file
            max_size: Maximum file size to analyze (10 MB default)
            
        Returns:
            Heuristic analysis result
        """
        indicators = []
        suspicion_level = 0
        
        # Check file extension
        ext = file_path.suffix.lower()
        if ext in self.SUSPICIOUS_EXTENSIONS:
            indicators.append(f"Suspicious extension: {ext}")
            suspicion_level += 10
        
        # Check file size anomalies
        try:
            file_size = file_path.stat().st_size
            
            # Very small executables are suspicious
            if ext in {'.exe', '.dll'} and file_size < 1024:
                indicators.append("Unusually small executable")
                suspicion_level += 20
            
            # Check if file is empty
            if file_size == 0:
                indicators.append("Empty file")
                suspicion_level += 5
                
        except OSError:
            return HeuristicResult(
                file_path=file_path,
                suspicion_level=0,
                indicators=["Cannot read file metadata"],
                recommendation="Skip - inaccessible file",
            )
        
        # Check file content (for text-based or small files)
        if file_size > 0 and file_size <= max_size:
            content_indicators, content_suspicion = self._analyze_content(file_path)
            indicators.extend(content_indicators)
            suspicion_level += content_suspicion
        
        # Determine recommendation
        if suspicion_level >= 70:
            recommendation = "High suspicion - quarantine recommended"
        elif suspicion_level >= 40:
            recommendation = "Moderate suspicion - manual review recommended"
        elif suspicion_level >= 20:
            recommendation = "Low suspicion - monitor"
        else:
            recommendation = "No significant indicators"
        
        return HeuristicResult(
            file_path=file_path,
            suspicion_level=min(suspicion_level, 100),
            indicators=indicators,
            recommendation=recommendation,
        )
    
    def _analyze_content(self, file_path: Path) -> tuple[list[str], int]:
        """
        Analyze file content for suspicious patterns.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (indicators, suspicion_score)
        """
        indicators = []
        suspicion = 0
        
        try:
            # Try to read as text/binary
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # Read first 1 MB
            
            # Check for suspicious strings
            matches_found = 0
            for pattern in self.compiled_patterns:
                if pattern.search(content.decode('utf-8', errors='ignore')):
                    matches_found += 1
            
            if matches_found > 0:
                indicators.append(f"Found {matches_found} suspicious pattern(s)")
                suspicion += min(matches_found * 15, 60)
            
            # Check for packed/encrypted content (high entropy)
            if self._is_high_entropy(content):
                indicators.append("High entropy content (possibly packed/encrypted)")
                suspicion += 15
            
            # Check for PE file markers
            if content.startswith(b'MZ'):
                indicators.append("Windows PE executable")
                # Check for suspicious PE patterns
                for pattern in self.PE_SUSPICIOUS_PATTERNS:
                    if re.search(pattern, content.decode('utf-8', errors='ignore'), re.IGNORECASE):
                        indicators.append("Suspicious PE pattern detected")
                        suspicion += 20
                        break
            
            # Check for script files with suspicious content
            if file_path.suffix.lower() in {'.ps1', '.vbs', '.js', '.bat'}:
                script_score = self._analyze_script(content)
                if script_score > 0:
                    indicators.append(f"Suspicious script patterns (score: {script_score})")
                    suspicion += script_score
            
        except Exception as e:
            logger.debug(f"Could not analyze content of {file_path}: {e}")
        
        return indicators, suspicion
    
    def _is_high_entropy(self, data: bytes) -> bool:
        """
        Check if data has high entropy (possibly encrypted/packed).
        
        Args:
            data: Data to analyze
            
        Returns:
            True if high entropy
        """
        if len(data) < 256:
            return False
        
        # Simple entropy estimation
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / data_len
                entropy -= p * (p and (p * 0.6931471805599453) or 0)  # log2 approximation
        
        # High entropy threshold (close to 8 bits per byte)
        return entropy > 7.5
    
    def _analyze_script(self, content: bytes) -> int:
        """
        Analyze script content for suspicious patterns.
        
        Args:
            content: Script content
            
        Returns:
            Suspicion score
        """
        score = 0
        text = content.decode('utf-8', errors='ignore').lower()
        
        # PowerShell suspicious patterns
        if 'powershell' in text or 'ps1' in text:
            suspicious_ps = [
                'downloadstring', 'invoke-expression', 'iex',
                'bypass', 'hidden', 'encodedcommand',
                'shellcode', 'inject', 'mimikatz',
            ]
            for pattern in suspicious_ps:
                if pattern in text:
                    score += 10
        
        # VBScript suspicious patterns
        if 'vbs' in text or 'vbscript' in text:
            suspicious_vbs = [
                'wscript.shell', 'run', 'exec',
                'filesystemobject', 'createtextfile',
            ]
            for pattern in suspicious_vbs:
                if pattern in text:
                    score += 10
        
        # Batch file suspicious patterns
        if '@echo off' in text or '.bat' in text:
            suspicious_batch = [
                'del /q', 'rmdir /s', 'format',
                'net user', 'net localgroup',
            ]
            for pattern in suspicious_batch:
                if pattern in text:
                    score += 10
        
        return min(score, 50)
    
    def analyze_process_behavior(self, behaviors: list[str]) -> HeuristicResult:
        """
        Analyze a list of observed behaviors.
        
        Args:
            behaviors: List of observed behavior strings
            
        Returns:
            Heuristic analysis result
        """
        indicators = []
        suspicion_level = 0
        
        suspicious_behaviors = {
            'keylog': 30,
            'screenshot': 20,
            'clipboard': 15,
            'persistence': 25,
            'network': 20,
            'injection': 35,
            'encryption': 30,
            'anti_debug': 25,
            'file_delete': 20,
            'registry_modify': 15,
        }
        
        for behavior in behaviors:
            behavior_lower = behavior.lower()
            for key, score in suspicious_behaviors.items():
                if key in behavior_lower:
                    indicators.append(f"Suspicious behavior: {behavior}")
                    suspicion_level += score
        
        recommendation = "Review required" if suspicion_level > 0 else "No suspicious behaviors"
        
        return HeuristicResult(
            file_path=Path("behavior_analysis"),
            suspicion_level=min(suspicion_level, 100),
            indicators=indicators,
            recommendation=recommendation,
        )


# Global heuristic analyzer instance
heuristic_analyzer = HeuristicAnalyzer()
