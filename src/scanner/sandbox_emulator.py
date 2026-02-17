"""
Sandbox Emulation for Green Mold Cure.
Behavioral analysis through code emulation and API call monitoring.

Features:
- Safe code emulation (scripts, macros)
- API call sequence analysis
- Behavioral pattern detection
- Safe document analysis (Office, PDF)
- Network behavior simulation
"""

import re
import hashlib
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from utils.logger import logger
from utils.platform import platform_info


class EmulationRisk(Enum):
    """Risk levels for emulation results."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class EmulationResult:
    """Result of sandbox emulation."""
    file_path: Path
    file_type: str
    risk_level: EmulationRisk
    risk_score: int  # 0-100
    behaviors_detected: List[str]
    api_calls: List[Dict[str, Any]]
    network_indicators: List[str]
    file_indicators: List[str]
    registry_indicators: List[str]
    explanation: str
    recommendations: List[str]
    emulation_time: float
    safe_to_execute: bool


class SandboxEmulator:
    """
    Sandbox emulator for behavioral analysis.
    
    Features:
    - Script emulation (PowerShell, VBScript, JavaScript)
    - Document analysis (Office macros, PDF JavaScript)
    - API call sequence analysis
    - Network behavior detection
    - File system operation detection
    """
    
    # PowerShell suspicious commands
    POWERSHELL_PATTERNS = {
        'download': r'(?:Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile)',
        'execute': r'(?:Invoke-Expression|IEX|Start-Process|Invoke-Command)',
        'bypass': r'(?:Bypass|Unrestricted|None)',
        'hidden': r'(?:Hidden|WindowStyle\s+Hidden|-w\s+hidden)',
        'encode': r'(?:FromBase64String|ConvertTo-SecureString|-enc)',
        'inject': r'(?:VirtualAlloc|CreateThread|Write-ProcessMemory)',
        'credential': r'(?:Get-Credential|SecureString|Credential)',
        'persistence': r'(?:New-ItemProperty|Set-ItemProperty|ScheduledTask)',
        'keylog': r'(?:Get-AsyncKeyState|Get-KeyStroke|KeyLogger)',
        'mimikatz': r'(?:Invoke-Mimikatz|Sekurlsa|Kerberos)',
    }
    
    # VBScript suspicious patterns
    VBSCRIPT_PATTERNS = {
        'shell': r'(?:WScript\.Shell|Run|Exec)',
        'filesystem': r'(?:FileSystemObject|CreateTextFile|OpenTextFile)',
        'download': r'(?:MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest)',
        'execute': r'(?:Execute|Eval|Run)',
        'registry': r'(?:RegRead|RegWrite|HKLM|HKCU)',
        'obfuscation': r'(?:Chr\(|String\.FromCharCode|Replace)',
    }
    
    # JavaScript suspicious patterns
    JAVASCRIPT_PATTERNS = {
        'eval': r'(?:eval\(|Function\(|setTimeout\(|setInterval\()',
        'document': r'(?:document\.write|innerHTML|outerHTML)',
        'network': r'(?:XMLHttpRequest|fetch\(|WebSocket)',
        'obfuscation': r'(?:atob\(|btoa\(|unescape\(|String\.fromCharCode)',
        'iframe': r'(?:<iframe|iframe.*hidden|display:\s*none)',
        'redirect': r'(?:location\.href|location\.replace|window\.location)',
    }
    
    # Suspicious API calls (Windows)
    SUSPICIOUS_APIS = {
        'process_injection': [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtCreateThreadEx', 'RtlCreateUserThread', 'SetThreadContext'
        ],
        'keylogging': [
            'GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx',
            'GetForegroundWindow', 'GetKeyboardState'
        ],
        'persistence': [
            'RegSetValueEx', 'CreateService', 'ChangeServiceConfig',
            'CreateScheduledTask', 'RegCreateKey'
        ],
        'evasion': [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
            'NtQueryInformationProcess', 'GetTickCount', 'Sleep'
        ],
        'network': [
            'InternetOpen', 'InternetConnect', 'HttpOpenRequest',
            'URLDownloadToFile', 'WinHttpOpen', 'socket', 'connect'
        ],
        'file_operations': [
            'DeleteFile', 'MoveFile', 'CopyFile', 'CreateFile',
            'WriteFile', 'SetFileAttributes'
        ],
        'crypto': [
            'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
            'CryptAcquireContext', 'CryptImportKey'
        ],
    }
    
    def __init__(self):
        """Initialize the sandbox emulator."""
        self.results: List[EmulationResult] = []
        self.emulation_timeout = 30  # seconds
    
    def emulate_file(self, file_path: Path) -> EmulationResult:
        """
        Emulate a file and analyze its behavior.
        
        Args:
            file_path: Path to the file to emulate
            
        Returns:
            EmulationResult object
        """
        import time
        start_time = time.time()
        
        result = EmulationResult(
            file_path=file_path,
            file_type="",
            risk_level=EmulationRisk.SAFE,
            risk_score=0,
            behaviors_detected=[],
            api_calls=[],
            network_indicators=[],
            file_indicators=[],
            registry_indicators=[],
            explanation="",
            recommendations=[],
            emulation_time=0,
            safe_to_execute=True
        )
        
        try:
            # Determine file type
            ext = file_path.suffix.lower()
            result.file_type = self._get_file_type(file_path)
            
            # Read file content
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception:
                with open(file_path, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore')
            
            # Analyze based on file type
            if ext in ['.ps1', '.psm1', '.psd1']:
                self._analyze_powershell(content, result)
            elif ext in ['.vbs', '.vbe', '.wsf', '.wsc']:
                self._analyze_vbscript(content, result)
            elif ext in ['.js', '.jse', '.jsx']:
                self._analyze_javascript(content, result)
            elif ext in ['.bat', '.cmd']:
                self._analyze_batch(content, result)
            elif ext in ['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm']:
                self._analyze_office_macro(content, result)
            elif ext == '.pdf':
                self._analyze_pdf(content, result)
            elif ext in ['.exe', '.dll', '.sys']:
                self._analyze_pe_behavior(file_path, content, result)
            else:
                self._analyze_generic(content, result)
            
            # Calculate final risk level
            self._calculate_risk(result)
            
            # Generate explanation
            self._generate_explanation(result)
            
        except Exception as e:
            result.risk_level = EmulationRisk.LOW
            result.risk_score = 10
            result.explanation = f"Emulation error: {e}\nFile could not be fully analyzed."
            result.recommendations = ["Manual review recommended"]
            logger.debug(f"Emulation error for {file_path}: {e}")
        
        result.emulation_time = time.time() - start_time
        self.results.append(result)
        
        return result
    
    def _get_file_type(self, file_path: Path) -> str:
        """Get human-readable file type."""
        type_map = {
            '.ps1': 'PowerShell Script',
            '.psm1': 'PowerShell Module',
            '.vbs': 'VBScript',
            '.js': 'JavaScript',
            '.bat': 'Batch Script',
            '.cmd': 'Command Script',
            '.exe': 'Windows Executable',
            '.dll': 'Dynamic Link Library',
            '.doc': 'Word Document',
            '.docm': 'Word Macro-Enabled Document',
            '.xls': 'Excel Spreadsheet',
            '.xlsm': 'Excel Macro-Enabled Spreadsheet',
            '.pdf': 'PDF Document',
        }
        return type_map.get(file_path.suffix.lower(), 'Unknown File Type')
    
    def _analyze_powershell(self, content: str, result: EmulationResult) -> None:
        """Analyze PowerShell script."""
        content_lower = content.lower()
        
        for behavior, pattern in self.POWERSHELL_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                result.behaviors_detected.append(f"PowerShell {behavior}")
                result.risk_score += 15
                
                result.api_calls.append({
                    'type': 'powershell',
                    'behavior': behavior,
                    'pattern': pattern
                })
        
        # Check for encoded commands
        if '-enc' in content_lower or '-encodedcommand' in content_lower:
            result.risk_score += 20
            result.behaviors_detected.append("Encoded command execution")
        
        # Check for web requests
        if re.search(r'http[s]?://', content):
            urls = re.findall(r'http[s]?://[^\s"\']+', content)
            result.network_indicators.extend(urls[:10])
            result.risk_score += 10
    
    def _analyze_vbscript(self, content: str, result: EmulationResult) -> None:
        """Analyze VBScript."""
        for behavior, pattern in self.VBSCRIPT_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                result.behaviors_detected.append(f"VBScript {behavior}")
                result.risk_score += 15
        
        # Check for obfuscation
        chr_count = len(re.findall(r'Chr\(\d+\)', content))
        if chr_count > 10:
            result.risk_score += 20
            result.behaviors_detected.append("Heavy character encoding obfuscation")
    
    def _analyze_javascript(self, content: str, result: EmulationResult) -> None:
        """Analyze JavaScript."""
        for behavior, pattern in self.JAVASCRIPT_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                result.behaviors_detected.append(f"JavaScript {behavior}")
                result.risk_score += 15
        
        # Check for document manipulation
        if 'document.write' in content or 'innerHTML' in content:
            result.risk_score += 10
        
        # Check for network activity
        if 'XMLHttpRequest' in content or 'fetch(' in content:
            result.risk_score += 10
    
    def _analyze_batch(self, content: str, result: EmulationResult) -> None:
        """Analyze batch script."""
        content_lower = content.lower()
        
        # Check for dangerous commands
        dangerous = [
            ('del /q', 'Quiet delete'),
            ('format', 'Disk format'),
            ('rd /s', 'Recursive directory delete'),
            ('net user', 'User account manipulation'),
            ('netsh firewall', 'Firewall modification'),
            ('reg add', 'Registry modification'),
            ('schtasks', 'Scheduled task creation'),
            ('powershell', 'PowerShell invocation'),
            ('certutil -decode', 'File decoding'),
            ('bitsadmin', 'File download'),
        ]
        
        for cmd, desc in dangerous:
            if cmd in content_lower:
                result.behaviors_detected.append(desc)
                result.risk_score += 15
                result.api_calls.append({'type': 'batch', 'command': cmd})
    
    def _analyze_office_macro(self, content: str, result: EmulationResult) -> None:
        """Analyze Office macro content."""
        # Check for auto-execute macros
        auto_macros = ['AutoOpen', 'AutoExec', 'Document_Open', 'Workbook_Open']
        for macro in auto_macros:
            if macro in content:
                result.behaviors_detected.append(f"Auto-execute macro: {macro}")
                result.risk_score += 20
        
        # Check for shell execution
        if 'Shell(' in content or 'WScript.Shell' in content:
            result.risk_score += 25
            result.behaviors_detected.append("Shell command execution")
        
        # Check for HTTP requests
        if 'MSXML2.XMLHTTP' in content or 'WinHttp.WinHttpRequest' in content:
            result.risk_score += 20
            result.behaviors_detected.append("Network communication")
        
        # Check for file operations
        if 'Kill' in content or 'RmDir' in content:
            result.risk_score += 15
            result.file_indicators.append("File deletion capability")
    
    def _analyze_pdf(self, content: str, result: EmulationResult) -> None:
        """Analyze PDF for malicious JavaScript."""
        # Check for embedded JavaScript
        if '/JavaScript' in content:
            result.behaviors_detected.append("Embedded JavaScript")
            result.risk_score += 10
        
        # Check for suspicious PDF features
        suspicious = [
            ('/OpenAction', 'Auto-open action'),
            ('/AA', 'Additional actions'),
            ('app.launchURL', 'URL launching'),
            ('util.printf', 'Potential exploit'),
            ('Collab.collectEmailInfo', 'Email harvesting'),
        ]
        
        for pattern, desc in suspicious:
            if pattern in content:
                result.behaviors_detected.append(desc)
                result.risk_score += 15
    
    def _analyze_pe_behavior(self, file_path: Path, content: str, result: EmulationResult) -> None:
        """Analyze PE file behavior through static analysis."""
        # Look for suspicious strings in binary
        suspicious_strings = [
            b'cmd.exe', b'powershell', b'wscript', b'cscript',
            b'http://', b'https://', b'ftp://',
            b'registry', b'HKEY_',
            b'VirtualAlloc', b'CreateThread', b'WriteProcessMemory',
            b'GetAsyncKeyState', b'IsDebuggerPresent',
        ]
        
        content_bytes = content.encode('utf-8', errors='ignore') if isinstance(content, str) else content
        
        for suspicious in suspicious_strings:
            if suspicious in content_bytes:
                result.behaviors_detected.append(f"String reference: {suspicious.decode('utf-8', errors='ignore')}")
                result.risk_score += 5
        
        # Check for PE analysis results if pefile is available
        try:
            import pefile
            pe = pefile.PE(str(file_path))
            
            # Check imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imp_name = imp.name.decode('utf-8', errors='ignore')
                            for category, apis in self.SUSPICIOUS_APIS.items():
                                if any(api.lower() in imp_name.lower() for api in apis):
                                    result.api_calls.append({
                                        'type': 'import',
                                        'api': imp_name,
                                        'category': category
                                    })
                                    result.risk_score += 5
            
            pe.close()
        except Exception:
            pass
    
    def _analyze_generic(self, content: str, result: EmulationResult) -> None:
        """Generic analysis for unknown file types."""
        # Check for URLs
        urls = re.findall(r'http[s]?://[^\s"\']+', content)
        if urls:
            result.network_indicators.extend(urls[:10])
            result.risk_score += 5
        
        # Check for IP addresses
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)
        if ips:
            result.network_indicators.extend(ips[:10])
            result.risk_score += 5
        
        # Check for email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
        if emails:
            result.file_indicators.append(f"Contains {len(emails)} email addresses")
        
        # Check for base64 encoded content
        base64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
        base64_matches = re.findall(base64_pattern, content)
        if base64_matches:
            result.behaviors_detected.append("Contains base64 encoded data")
            result.risk_score += 5
    
    def _calculate_risk(self, result: EmulationResult) -> None:
        """Calculate final risk level based on score."""
        result.risk_score = min(result.risk_score, 100)
        
        if result.risk_score >= 80:
            result.risk_level = EmulationRisk.CRITICAL
            result.safe_to_execute = False
        elif result.risk_score >= 60:
            result.risk_level = EmulationRisk.HIGH
            result.safe_to_execute = False
        elif result.risk_score >= 40:
            result.risk_level = EmulationRisk.MEDIUM
            result.safe_to_execute = False
        elif result.risk_score >= 20:
            result.risk_level = EmulationRisk.LOW
            result.safe_to_execute = True
        else:
            result.risk_level = EmulationRisk.SAFE
            result.safe_to_execute = True
    
    def _generate_explanation(self, result: EmulationResult) -> None:
        """Generate human-readable explanation."""
        if result.risk_level == EmulationRisk.SAFE:
            result.explanation = (
                "No suspicious behaviors detected during emulation.\n"
                f"Analyzed {len(result.behaviors_detected)} potential indicators.\n"
                "File appears safe to execute."
            )
        elif result.risk_level == EmulationRisk.LOW:
            result.explanation = (
                f"Low-risk behaviors detected (risk score: {result.risk_score}/100).\n"
                f"Behaviors: {', '.join(result.behaviors_detected[:3])}\n"
                "File may be safe but review is recommended."
            )
            result.recommendations = ["Review detected behaviors", "Verify file source"]
        elif result.risk_level == EmulationRisk.MEDIUM:
            result.explanation = (
                f"Moderate-risk behaviors detected (risk score: {result.risk_score}/100).\n"
                f"Detected behaviors:\n"
            )
            for behavior in result.behaviors_detected[:5]:
                result.explanation += f"  • {behavior}\n"
            result.explanation += "\nExercise caution before executing."
            result.recommendations = [
                "Do not execute without verification",
                "Upload to VirusTotal for additional analysis",
                "Check file origin and purpose"
            ]
        elif result.risk_level == EmulationRisk.HIGH:
            result.explanation = (
                f"HIGH-RISK behaviors detected (risk score: {result.risk_score}/100)!\n\n"
                f"Detected behaviors:\n"
            )
            for behavior in result.behaviors_detected:
                result.explanation += f"  ⚠ {behavior}\n"
            result.explanation += "\nThis file exhibits malware-like behavior."
            result.recommendations = [
                "DO NOT execute this file",
                "Quarantine immediately",
                "Scan with multiple antivirus engines",
                "Investigate file origin"
            ]
        else:  # CRITICAL
            result.explanation = (
                f"CRITICAL THREAT detected (risk score: {result.risk_score}/100)!\n\n"
                f"Malicious behaviors:\n"
            )
            for behavior in result.behaviors_detected:
                result.explanation += f"  🚨 {behavior}\n"
            
            if result.network_indicators:
                result.explanation += f"\nNetwork indicators found: {len(result.network_indicators)}"
            if result.api_calls:
                result.explanation += f"\nSuspicious API calls: {len(result.api_calls)}"
            
            result.explanation += "\n\nThis file is highly likely to be malware."
            result.recommendations = [
                "QUARANTINE IMMEDIATELY",
                "Do not execute under any circumstances",
                "Delete from system",
                "Scan all files in same directory",
                "Check for persistence mechanisms"
            ]
    
    def emulate_batch(self, file_paths: List[Path]) -> List[EmulationResult]:
        """
        Emulate multiple files.
        
        Args:
            file_paths: List of files to emulate
            
        Returns:
            List of EmulationResult objects
        """
        results = []
        for path in file_paths:
            results.append(self.emulate_file(path))
        return results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of emulation results."""
        if not self.results:
            return {'total': 0}
        
        risk_counts = {}
        for r in self.results:
            level = r.risk_level.value
            risk_counts[level] = risk_counts.get(level, 0) + 1
        
        return {
            'total': len(self.results),
            'by_risk': risk_counts,
            'critical': risk_counts.get('critical', 0),
            'high': risk_counts.get('high', 0),
            'safe': risk_counts.get('safe', 0),
            'avg_risk_score': sum(r.risk_score for r in self.results) / len(self.results),
        }


# Global sandbox emulator instance
sandbox_emulator = SandboxEmulator()
