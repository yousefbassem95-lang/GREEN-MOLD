"""
Enhanced Scanner Engine for Green Mold Cure.
Multi-engine scanning with comprehensive error handling and detailed reporting.

Engines:
1. Signature-based (hash matching)
2. YARA rule-based (pattern matching)
3. Heuristic analysis (behavioral patterns)
4. PE analysis (Windows executable inspection)
5. Archive scanning (zip, rar, 7z)
"""

import os
import hashlib
import zipfile
import io
from pathlib import Path
from typing import Callable, Optional, Iterator, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
import fnmatch
import traceback

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

from utils.platform import platform_info
from utils.logger import logger
from config.settings import settings
from scanner.yara_scanner import yara_scanner, YaraMatch


class ScanStatus(Enum):
    """Scan result status with detailed categories."""
    CLEAN = "clean"
    INFECTED = "infected"
    SUSPICIOUS = "suspicious"  # Not confirmed malware but concerning
    ERROR = "error"
    SKIPPED = "skipped"
    ACCESS_DENIED = "access_denied"
    CORRUPTED = "corrupted"
    ENCRYPTED = "encrypted"  # Encrypted archive/file


class ThreatType(Enum):
    """Types of detected threats."""
    VIRUS = "virus"
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    BACKDOOR = "backdoor"
    ROOTKIT = "rootkit"
    KEYLOGGER = "keylogger"
    DROPPER = "dropper"
    DOWNLOADER = "downloader"
    PACKER = "packer"
    EXPLOIT = "exploit"
    PHISHING = "phishing"
    SUSPICIOUS = "suspicious"


class Severity(Enum):
    """Threat severity levels with detailed descriptions."""
    LOW = ("low", "Minor concern, monitor only")
    MEDIUM = ("medium", "Moderate risk, investigation recommended")
    HIGH = ("high", "High risk, immediate action required")
    CRITICAL = ("critical", "Critical threat, isolate immediately")
    
    def __init__(self, value: str, description: str):
        self._value_ = value
        self.description = description


@dataclass
class ScanError:
    """Detailed error information for failed scans."""
    file_path: Path
    error_type: str
    error_message: str
    stack_trace: Optional[str] = None
    recoverable: bool = True
    suggestion: str = ""


@dataclass
class ScanResult:
    """Comprehensive scan result with multiple engine outputs."""
    file_path: Path
    status: ScanStatus
    threat_name: Optional[str] = None
    threat_type: Optional[ThreatType] = None
    severity: Severity = Severity.LOW
    error_message: Optional[str] = None
    scan_time: float = 0.0
    file_hash: Optional[str] = None
    file_size: int = 0
    file_type: str = ""
    action_taken: Optional[str] = None
    
    # Engine-specific results
    signature_match: bool = False
    yara_matches: List[YaraMatch] = field(default_factory=list)
    heuristic_score: int = 0
    pe_analysis: Optional[Dict] = None
    archive_contents: List[str] = field(default_factory=list)
    
    # Detailed explanations
    explanation: str = ""
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ScanSummary:
    """Comprehensive scan summary with detailed statistics."""
    total_files: int = 0
    scanned_files: int = 0
    infected_files: int = 0
    clean_files: int = 0
    suspicious_files: int = 0
    error_files: int = 0
    skipped_files: int = 0
    access_denied_files: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    results: List[ScanResult] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    
    # Detailed statistics
    by_threat_type: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_file_type: Dict[str, int] = field(default_factory=dict)
    largest_file_scanned: int = 0
    deepest_path_depth: int = 0
    
    @property
    def duration(self) -> float:
        """Get scan duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def infection_rate(self) -> float:
        """Get infection rate as percentage."""
        if self.scanned_files == 0:
            return 0.0
        return (self.infected_files / self.scanned_files) * 100
    
    @property
    def success_rate(self) -> float:
        """Get successful scan rate."""
        if self.total_files == 0:
            return 0.0
        return ((self.scanned_files - self.error_files) / self.total_files) * 100
    
    def get_detailed_report(self) -> str:
        """Generate a detailed scan report."""
        report = []
        report.append("=" * 70)
        report.append("GREEN MOLD CURE - DETAILED SCAN REPORT")
        report.append("=" * 70)
        report.append(f"Scan Date: {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'}")
        report.append(f"Duration: {self.duration:.2f} seconds")
        report.append("")
        report.append("SUMMARY")
        report.append("-" * 70)
        report.append(f"Total Files:        {self.total_files}")
        report.append(f"Successfully Scanned: {self.scanned_files} ({self.success_rate:.1f}%)")
        report.append(f"Clean:              {self.clean_files}")
        report.append(f"Infected:           {self.infected_files} ({self.infection_rate:.1f}%)")
        report.append(f"Suspicious:         {self.suspicious_files}")
        report.append(f"Errors:             {self.error_files}")
        report.append(f"Access Denied:      {self.access_denied_files}")
        report.append(f"Skipped:            {self.skipped_files}")
        
        if self.by_threat_type:
            report.append("")
            report.append("THREATS BY TYPE")
            report.append("-" * 70)
            for threat_type, count in sorted(self.by_threat_type.items(), key=lambda x: x[1], reverse=True):
                report.append(f"  {threat_type}: {count}")
        
        if self.by_severity:
            report.append("")
            report.append("THREATS BY SEVERITY")
            report.append("-" * 70)
            for severity, count in self.by_severity.items():
                report.append(f"  {severity.upper()}: {count}")
        
        if self.errors:
            report.append("")
            report.append("ERRORS ENCOUNTERED")
            report.append("-" * 70)
            for error in self.errors[:10]:  # Show first 10 errors
                report.append(f"  {error.error_type}: {error.file_path}")
                report.append(f"    {error.error_message}")
                if error.suggestion:
                    report.append(f"    Suggestion: {error.suggestion}")
            if len(self.errors) > 10:
                report.append(f"  ... and {len(self.errors) - 10} more errors")
        
        report.append("")
        report.append("=" * 70)
        
        return "\n".join(report)


class EnhancedScannerEngine:
    """
    Enhanced multi-engine scanner for Green Mold Cure.
    
    Features:
    - Multiple detection engines working together
    - Comprehensive error handling with suggestions
    - Archive scanning with recursion
    - PE file analysis
    - Detailed reporting and explanations
    """
    
    # Archive extensions to scan recursively
    ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.gz', '.tar', '.bz2', '.xz'}
    
    # Executable extensions for PE analysis
    EXECUTABLE_EXTENSIONS = {'.exe', '.dll', '.sys', '.drv', '.ocx', '.scr'}
    
    # Maximum archive recursion depth
    MAX_ARCHIVE_DEPTH = 5
    
    # Maximum file size to scan (default 500MB for enhanced scanning)
    MAX_FILE_SIZE = 500 * 1024 * 1024
    
    def __init__(self):
        """Initialize the enhanced scanner engine."""
        self.signature_database = None
        self.excluded_patterns = []
        self.max_file_size = self.MAX_FILE_SIZE
        self.scan_archives = True
        self.follow_symlinks = False
        self._stop_requested = False
        self._archive_depth = 0
        self.load_settings()
    
    def load_settings(self) -> None:
        """Load scanner settings from configuration."""
        self.max_file_size = settings.get("scan.max_file_size_mb", 500) * 1024 * 1024
        self.scan_archives = settings.get("scan.scan_archives", True)
        self.follow_symlinks = settings.get("scan.follow_symlinks", False)
        self.excluded_patterns = settings.get("scan.exclude_patterns", [])
    
    def set_signature_database(self, database) -> None:
        """Set the signature database for threat detection."""
        self.signature_database = database
    
    def request_stop(self) -> None:
        """Request the scanner to stop gracefully."""
        self._stop_requested = True
    
    def reset_stop(self) -> None:
        """Reset the stop flag for a new scan."""
        self._stop_requested = False
        self._archive_depth = 0
    
    def _get_file_type(self, file_path: Path) -> str:
        """
        Determine file type using multiple methods.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File type description
        """
        # Check by extension first
        ext = file_path.suffix.lower()
        
        type_map = {
            '.exe': 'Windows Executable',
            '.dll': 'Dynamic Link Library',
            '.sys': 'System Driver',
            '.scr': 'Screen Saver/Executable',
            '.zip': 'ZIP Archive',
            '.rar': 'RAR Archive',
            '.7z': '7-Zip Archive',
            '.pdf': 'PDF Document',
            '.doc': 'Word Document',
            '.docx': 'Word Document (XML)',
            '.xls': 'Excel Spreadsheet',
            '.xlsx': 'Excel Spreadsheet (XML)',
            '.ppt': 'PowerPoint Presentation',
            '.pptx': 'PowerPoint Presentation (XML)',
            '.js': 'JavaScript',
            '.vbs': 'VBScript',
            '.ps1': 'PowerShell Script',
            '.bat': 'Batch Script',
            '.cmd': 'Command Script',
            '.py': 'Python Script',
            '.lnk': 'Windows Shortcut',
            '.msi': 'Windows Installer',
        }
        
        if ext in type_map:
            return type_map[ext]
        
        # Try python-magic if available
        try:
            import magic
            mime = magic.from_file(str(file_path), mime=True)
            return f"MIME: {mime}"
        except Exception:
            pass
        
        return f"Extension: {ext}" if ext else "Unknown"
    
    def _analyze_pe_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Analyze a Windows PE file for suspicious characteristics.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            PE analysis results or None
        """
        if not PEFILE_AVAILABLE:
            return None
        
        try:
            pe = pefile.PE(str(file_path))
            
            analysis = {
                'imports': [],
                'exports': [],
                'sections': [],
                'suspicious_imports': [],
                'packed': False,
                'compiler': None,
            }
            
            # Check imports
            suspicious_apis = [
                'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
                'CreateRemoteThread', 'GetAsyncKeyState', 'GetKeyState',
                'URLDownloadToFile', 'InternetOpen', 'ShellExecute',
                'RegSetValueEx', 'CryptEncrypt', 'SetWindowsHookEx'
            ]
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imp_name = imp.name.decode('utf-8', errors='ignore')
                            if any(api.lower() in imp_name.lower() for api in suspicious_apis):
                                analysis['suspicious_imports'].append(imp_name)
            
            # Check sections for packing
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                analysis['sections'].append({
                    'name': section_name,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': len(section.get_data()),
                })
                
                # Check for packer signatures
                packer_names = ['UPX', 'ASPack', 'PEtite', 'FSG', 'Themida', 'VMProtect']
                if any(p.lower() in section_name.lower() for p in packer_names):
                    analysis['packed'] = True
            
            pe.close()
            return analysis
            
        except Exception as e:
            logger.debug(f"PE analysis failed for {file_path}: {e}")
            return None
    
    def _scan_archive(
        self,
        file_path: Path,
        result_callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """
        Scan contents of an archive recursively.
        
        Args:
            file_path: Path to the archive
            result_callback: Optional callback for each result
            
        Returns:
            List of scan results from archive contents
        """
        if self._archive_depth >= self.MAX_ARCHIVE_DEPTH:
            return []
        
        self._archive_depth += 1
        results = []
        ext = file_path.suffix.lower()
        
        try:
            if ext == '.zip':
                with zipfile.ZipFile(file_path, 'r') as zf:
                    for name in zf.namelist():
                        if self._stop_requested:
                            break
                        
                        try:
                            # Extract to memory and scan
                            data = zf.read(name)
                            
                            # Create temporary result for archive content
                            temp_result = ScanResult(
                                file_path=file_path / name,
                                status=ScanStatus.CLEAN,
                                file_size=len(data),
                                file_type=self._get_file_type(Path(name)),
                                archive_contents=[name],
                            )
                            
                            # Scan the data
                            if self.signature_database:
                                data_hash = hashlib.sha256(data).hexdigest()
                                threat_info = self.signature_database.check_hash(data_hash)
                                if threat_info:
                                    temp_result.status = ScanStatus.INFECTED
                                    temp_result.threat_name = threat_info['name']
                                    temp_result.signature_match = True
                            
                            # YARA scan
                            yara_matches = yara_scanner.scan_data(data)
                            if yara_matches:
                                temp_result.yara_matches = yara_matches
                                if temp_result.status != ScanStatus.INFECTED:
                                    temp_result.status = ScanStatus.SUSPICIOUS
                            
                            results.append(temp_result)
                            
                            if result_callback:
                                result_callback(temp_result)
                                
                        except Exception as e:
                            logger.debug(f"Failed to scan archive member {name}: {e}")
            
            # TODO: Add support for RAR, 7z with appropriate libraries
            
        except zipfile.BadZipFile:
            logger.warning(f"Corrupted archive: {file_path}")
            results.append(ScanResult(
                file_path=file_path,
                status=ScanStatus.CORRUPTED,
                error_message="Archive is corrupted",
                file_type=self._get_file_type(file_path),
            ))
        except Exception as e:
            logger.warning(f"Failed to open archive {file_path}: {e}")
            results.append(ScanResult(
                file_path=file_path,
                status=ScanStatus.ERROR,
                error_message=str(e),
                file_type=self._get_file_type(file_path),
            ))
        finally:
            self._archive_depth -= 1
        
        return results
    
    def should_skip_file(self, file_path: Path) -> tuple[bool, str]:
        """
        Check if a file should be skipped with reason.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Tuple of (should_skip, reason)
        """
        # Check exclusion patterns
        file_str = str(file_path)
        for pattern in self.excluded_patterns:
            if fnmatch.fnmatch(file_str, pattern) or fnmatch.fnmatch(file_path.name, pattern):
                return True, f"Matches exclusion pattern: {pattern}"
        
        # Check file size
        try:
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return True, f"File too large ({file_size / 1024 / 1024:.1f}MB > {self.max_file_size / 1024 / 1024:.0f}MB limit)"
        except OSError as e:
            return True, f"Cannot access file metadata: {e}"
        
        return False, ""
    
    def scan_file(self, file_path: Path) -> ScanResult:
        """
        Scan a single file with all engines.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Comprehensive scan result
        """
        import time
        start_time = time.time()
        
        # Initialize result
        result = ScanResult(
            file_path=file_path,
            status=ScanStatus.CLEAN,
            file_type=self._get_file_type(file_path),
        )
        
        # Check if should skip
        should_skip, skip_reason = self.should_skip_file(file_path)
        if should_skip:
            result.status = ScanStatus.SKIPPED
            result.error_message = skip_reason
            result.explanation = f"File was not scanned: {skip_reason}"
            return result
        
        # Get file info
        try:
            stat = file_path.stat()
            result.file_size = stat.st_size
            result.file_hash = self._get_file_hash(file_path)
        except OSError as e:
            result.status = ScanStatus.ERROR
            result.error_message = f"Cannot access file: {e}"
            result.explanation = "The scanner cannot read this file. This could be due to:\n" \
                               "• File permissions (try running as administrator)\n" \
                               "• File is in use by another program\n" \
                               "• File path is too long\n" \
                               "• File is a special system file"
            result.recommendations = [
                "Run the scanner with elevated privileges",
                "Close any programs using this file",
                "Add the file path to exclusions if it's a system file"
            ]
            return result
        
        # Check for archive
        if self.scan_archives and file_path.suffix.lower() in self.ARCHIVE_EXTENSIONS:
            result.explanation = "This is an archive file. Contents will be scanned recursively."
            return result  # Archive scanning handled separately
        
        # Engine 1: Signature-based detection
        if self.signature_database and result.file_hash:
            threat_info = self.signature_database.check_hash(result.file_hash)
            if threat_info:
                result.status = ScanStatus.INFECTED
                result.threat_name = threat_info['name']
                result.threat_type = ThreatType(threat_info.get('type', 'suspicious'))
                result.severity = Severity(threat_info.get('severity', 'medium'))
                result.signature_match = True
                result.explanation = f"Known threat detected by signature matching.\n" \
                                   f"Threat: {result.threat_name}\n" \
                                   f"This file matches a known malware signature in our database."
                result.recommendations = [
                    "Quarantine this file immediately",
                    "Do not execute or open this file",
                    "Scan other files in the same directory"
                ]
        
        # Engine 2: YARA rule-based detection
        yara_matches = yara_scanner.scan_file(file_path)
        if yara_matches:
            result.yara_matches = yara_matches
            
            # Determine worst severity from YARA matches
            worst_severity = max(
                (Severity(m.severity) for m in yara_matches),
                key=lambda s: ['low', 'medium', 'high', 'critical'].index(s.value)
            )
            
            if result.status != ScanStatus.INFECTED:
                result.status = ScanStatus.SUSPICIOUS if worst_severity in [Severity.LOW, Severity.MEDIUM] else ScanStatus.INFECTED
            
            if worst_severity.value > result.severity.value:
                result.severity = worst_severity
            
            if not result.explanation:
                result.explanation = "Suspicious patterns detected by YARA rules.\n" \
                                   f"Matched {len(yara_matches)} rule(s):\n"
                for match in yara_matches:
                    result.explanation += f"  • {match.rule_name}: {match.description}\n"
            
            result.recommendations.append("Review the matched YARA rules for details")
        
        # Engine 3: PE Analysis (for executables)
        if file_path.suffix.lower() in self.EXECUTABLE_EXTENSIONS and PEFILE_AVAILABLE:
            pe_analysis = self._analyze_pe_file(file_path)
            if pe_analysis:
                result.pe_analysis = pe_analysis
                
                if pe_analysis['packed']:
                    result.heuristic_score += 30
                    result.explanation += "\n⚠ File appears to be packed (compressed/encrypted).\n" \
                                        "This is common for malware but also legitimate software."
                
                if pe_analysis['suspicious_imports']:
                    result.heuristic_score += len(pe_analysis['suspicious_imports']) * 10
                    result.explanation += f"\n⚠ Suspicious API imports detected: {len(pe_analysis['suspicious_imports'])}\n"
                    result.explanation += "   These APIs are commonly used by malware for:\n"
                    result.explanation += "   • Process injection\n"
                    result.explanation += "   • Keylogging\n"
                    result.explanation += "   • Network communication\n"
                    result.explanation += "   • Registry modification"
        
        # Engine 4: Heuristic analysis
        from scanner.heuristics import heuristic_analyzer
        heuristic_result = heuristic_analyzer.analyze_file(file_path)
        result.heuristic_score = heuristic_result.suspicion_level
        
        if heuristic_result.suspicion_level >= 70:
            if result.status == ScanStatus.CLEAN:
                result.status = ScanStatus.SUSPICIOUS
            result.explanation += f"\n⚠ High heuristic suspicion score: {heuristic_result.suspicion_level}/100\n"
            result.explanation += f"Indicators: {', '.join(heuristic_result.indicators[:5])}"
            result.recommendations.append(heuristic_result.recommendation)
        
        # Final status determination
        if result.status == ScanStatus.CLEAN and result.heuristic_score >= 40:
            result.status = ScanStatus.SUSPICIOUS
            result.explanation += f"\nModerate heuristic suspicion score: {result.heuristic_score}/100"
        
        # Set scan time
        result.scan_time = time.time() - start_time
        
        # Add general recommendations if clean
        if result.status == ScanStatus.CLEAN:
            result.explanation = "No threats detected. File appears to be clean based on:\n" \
                               "• Signature database check\n" \
                               "• YARA pattern matching\n" \
                               "• Heuristic analysis"
            if result.file_type:
                result.explanation += f"\nFile type: {result.file_type}"
        
        return result
    
    def _get_file_hash(self, file_path: Path) -> Optional[str]:
        """Calculate SHA-256 hash of a file."""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.debug(f"Failed to hash {file_path}: {e}")
            return None
    
    def traverse_path(
        self,
        path: Path,
        progress_callback: Optional[Callable[[Path, int], None]] = None,
    ) -> Iterator[tuple[Path, Optional[str]]]:
        """
        Traverse a path and yield files with error information.
        
        Args:
            path: Path to traverse
            progress_callback: Optional callback for progress
            
        Yields:
            Tuple of (file_path, error_message)
        """
        if self._stop_requested:
            return
        
        try:
            if path.is_file():
                yield path, None
            elif path.is_dir():
                try:
                    for item in path.iterdir():
                        if self._stop_requested:
                            return
                        
                        try:
                            if item.is_file():
                                yield item, None
                            elif item.is_dir():
                                yield from self.traverse_path(item, progress_callback)
                        except PermissionError:
                            yield item, "Permission denied"
                        except OSError as e:
                            yield item, str(e)
                except PermissionError:
                    yield path, "Permission denied - directory inaccessible"
                except OSError as e:
                    yield path, f"Directory error: {e}"
        except Exception as e:
            logger.error(f"Traversal error for {path}: {e}")
    
    def scan(
        self,
        paths: List[Path],
        result_callback: Optional[Callable[[ScanResult], None]] = None,
        progress_callback: Optional[Callable[[Path, int], None]] = None,
    ) -> ScanSummary:
        """
        Scan multiple paths with all engines.
        
        Args:
            paths: List of paths to scan
            result_callback: Optional callback for each result
            progress_callback: Optional callback for progress
            
        Returns:
            Comprehensive scan summary
        """
        self.reset_stop()
        self.load_settings()
        
        summary = ScanSummary(
            start_time=datetime.now(timezone.utc),
        )
        
        file_count = 0
        
        for scan_path in paths:
            if self._stop_requested:
                break
            
            for file_path, error in self.traverse_path(scan_path):
                if self._stop_requested:
                    break
                
                file_count += 1
                summary.total_files = file_count
                
                if progress_callback:
                    progress_callback(file_path, file_count)
                
                # Handle traversal errors
                if error:
                    scan_error = ScanError(
                        file_path=file_path,
                        error_type="traversal",
                        error_message=error,
                        suggestion="Run with elevated privileges or add to exclusions"
                    )
                    summary.errors.append(scan_error)
                    summary.access_denied_files += 1
                    
                    result = ScanResult(
                        file_path=file_path,
                        status=ScanStatus.ACCESS_DENIED,
                        error_message=error,
                        explanation=f"Cannot access this file: {error}\n\n" \
                                  f"Possible reasons:\n" \
                                  f"• Insufficient permissions\n" \
                                  f"• File is locked by another process\n" \
                                  f"• Path is too long",
                        recommendations=[
                            "Run scanner as administrator/root",
                            "Close programs using this file",
                            "Add to exclusions if it's a system file"
                        ]
                    )
                else:
                    # Scan the file
                    result = self.scan_file(file_path)
                    
                    # Handle archive scanning
                    if (self.scan_archives and 
                        file_path.suffix.lower() in self.ARCHIVE_EXTENSIONS and 
                        result.status not in [ScanStatus.ERROR, ScanStatus.SKIPPED]):
                        archive_results = self._scan_archive(file_path, result_callback)
                        result.archive_contents = [str(p) for p in file_path.glob('**/*')]
                        
                        # Update result if archive contains threats
                        for ar in archive_results:
                            if ar.status in [ScanStatus.INFECTED, ScanStatus.SUSPICIOUS]:
                                result.status = ScanStatus.INFECTED
                                result.threat_name = f"Archive contains: {ar.threat_name}"
                                result.explanation += f"\n⚠ Archive contains suspicious content: {ar.file_path}"
                
                summary.results.append(result)
                summary.scanned_files += 1
                
                # Update counters
                match result.status:
                    case ScanStatus.CLEAN:
                        summary.clean_files += 1
                    case ScanStatus.INFECTED:
                        summary.infected_files += 1
                        # Update threat statistics
                        if result.threat_type:
                            tt = result.threat_type.value
                            summary.by_threat_type[tt] = summary.by_threat_type.get(tt, 0) + 1
                        summary.by_severity[result.severity.value] = \
                            summary.by_severity.get(result.severity.value, 0) + 1
                    case ScanStatus.SUSPICIOUS:
                        summary.suspicious_files += 1
                    case ScanStatus.ERROR:
                        summary.error_files += 1
                        if result.error_message:
                            summary.errors.append(ScanError(
                                file_path=result.file_path,
                                error_type="scan",
                                error_message=result.error_message,
                                suggestion=result.recommendations[0] if result.recommendations else ""
                            ))
                    case ScanStatus.ACCESS_DENIED:
                        summary.access_denied_files += 1
                    case ScanStatus.SKIPPED:
                        summary.skipped_files += 1
                
                # Track file type statistics
                if result.file_type:
                    summary.by_file_type[result.file_type] = \
                        summary.by_file_type.get(result.file_type, 0) + 1
                
                # Track max file size and path depth
                if result.file_size > summary.largest_file_scanned:
                    summary.largest_file_scanned = result.file_size
                depth = len(result.file_path.parts)
                if depth > summary.deepest_path_depth:
                    summary.deepest_path_depth = depth
                
                # Call result callback
                if result_callback:
                    result_callback(result)
        
        summary.end_time = datetime.now(timezone.utc)
        
        # Log summary
        logger.info(
            f"Scan complete: {summary.scanned_files} files, "
            f"{summary.infected_files} infected, "
            f"{summary.suspicious_files} suspicious, "
            f"{summary.error_files} errors"
        )
        
        return summary
    
    def quick_scan(
        self,
        result_callback: Optional[Callable[[ScanResult], None]] = None,
        progress_callback: Optional[Callable[[Path, int], None]] = None,
    ) -> ScanSummary:
        """Perform a quick scan of common malware locations."""
        common_paths = platform_info.get_common_malware_paths()
        return self.scan(common_paths, result_callback, progress_callback)
    
    def full_system_scan(
        self,
        result_callback: Optional[Callable[[ScanResult], None]] = None,
        progress_callback: Optional[Callable[[Path, int], None]] = None,
    ) -> ScanSummary:
        """Perform a full system scan."""
        system_root = platform_info.get_system_root()
        return self.scan([system_root], result_callback, progress_callback)


# Global enhanced scanner instance
enhanced_scanner = EnhancedScannerEngine()
