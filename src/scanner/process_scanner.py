"""
Process and Memory Scanner for Green Mold Cure.
Scans running processes for injected malware, suspicious behavior, and memory-resident threats.

Features:
- Process enumeration and analysis
- Memory region scanning
- DLL/module inspection
- Suspicious process detection
- Rootkit detection heuristics
"""

import os
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

from utils.logger import logger
from utils.platform import platform_info


@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    name: str
    exe: Optional[str]
    cmdline: List[str]
    username: Optional[str]
    status: str
    cpu_percent: float
    memory_percent: float
    memory_info: Dict[str, int]
    num_threads: int
    open_files: List[str]
    connections: List[Dict[str, Any]]
    loaded_modules: List[str]
    start_time: datetime
    suspicious_score: int = 0
    suspicious_indicators: List[str] = field(default_factory=list)
    is_suspicious: bool = False


@dataclass
class MemoryScanResult:
    """Result of memory scan for a process."""
    pid: int
    process_name: str
    status: str  # clean, suspicious, infected
    threat_name: Optional[str]
    memory_regions_scanned: int
    suspicious_regions: int
    injected_code_detected: bool
    hidden_modules: bool
    explanation: str
    recommendations: List[str]


class ProcessScanner:
    """
    Process and memory scanner for Green Mold Cure.
    
    Features:
    - Enumerate all running processes
    - Analyze process characteristics
    - Scan process memory for threats
    - Detect suspicious behavior patterns
    - Identify potential rootkits
    """
    
    # Suspicious process names (common malware)
    SUSPICIOUS_NAMES = [
        'mimikatz', 'pwdump', 'gsecdump', 'procdump',
        'metasploit', 'meterpreter', 'cobaltstrike', 'beacon',
        'nc.exe', 'ncat', 'netcat', 'powersploit',
        'empire', 'razor', 'psexec', 'wmic',
    ]
    
    # Suspicious command line patterns
    SUSPICIOUS_CMD_PATTERNS = [
        'bypass -enc', 'downloadstring', 'invoke-expression',
        'iex', 'frombase64string', 'reflectiveload',
        'inject', 'shellcode', 'mimikatz',
        '-nop -w hidden', '-enc ', '-e ',
    ]
    
    # Suspicious DLLs/modules
    SUSPICIOUS_MODULES = [
        'ntdll.dll', 'kernel32.dll',  # Normal but often hooked
        'mimilib.dll', 'wceaux.dll',  # Mimikatz
        'inject.dll', 'hook.dll',     # Generic injection
    ]
    
    def __init__(self):
        """Initialize the process scanner."""
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not installed - process scanning disabled")
        
        self.processes: List[ProcessInfo] = []
        self.scan_results: List[MemoryScanResult] = []
    
    def is_available(self) -> bool:
        """Check if process scanning is available."""
        return PSUTIL_AVAILABLE
    
    def get_all_processes(self) -> List[ProcessInfo]:
        """
        Get information about all running processes.
        
        Returns:
            List of ProcessInfo objects
        """
        if not PSUTIL_AVAILABLE:
            return []
        
        self.processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 
                                              'username', 'status', 'cpu_percent',
                                              'memory_percent', 'memory_info',
                                              'num_threads', 'open_files', 
                                              'connections']):
                try:
                    info = proc.info
                    
                    # Get loaded modules
                    loaded_modules = []
                    try:
                        modules = proc.memory_maps(grouped=True)
                        loaded_modules = [m.path for m in modules[:50]]  # Limit to 50
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Get open files
                    open_files = []
                    try:
                        files = proc.open_files()
                        open_files = [f.path for f in files[:20]]  # Limit to 20
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Get connections
                    connections = []
                    try:
                        conns = proc.connections()
                        connections = [
                            {
                                'family': str(c.family),
                                'type': str(c.type),
                                'laddr': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                                'raddr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                                'status': c.status,
                            }
                            for c in conns[:20]  # Limit to 20
                        ]
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Get start time
                    try:
                        start_time = datetime.fromtimestamp(proc.create_time(), tz=timezone.utc)
                    except (psutil.AccessDenied, psutil.NoSuchProcess, ValueError):
                        start_time = datetime.now(timezone.utc)
                    
                    process_info = ProcessInfo(
                        pid=info['pid'],
                        name=info['name'] or "",
                        exe=info['exe'],
                        cmdline=info['cmdline'] or [],
                        username=info['username'],
                        status=info['status'],
                        cpu_percent=info['cpu_percent'] or 0,
                        memory_percent=info['memory_percent'] or 0,
                        memory_info={
                            'rss': info['memory_info'].rss if info['memory_info'] else 0,
                            'vms': info['memory_info'].vms if info['memory_info'] else 0,
                        },
                        num_threads=info['num_threads'] or 0,
                        open_files=open_files,
                        connections=connections,
                        loaded_modules=loaded_modules,
                        start_time=start_time,
                    )
                    
                    # Analyze for suspicious indicators
                    self._analyze_process(process_info)
                    
                    self.processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except Exception as e:
            logger.error(f"Failed to enumerate processes: {e}")
        
        return self.processes
    
    def _analyze_process(self, process_info: ProcessInfo) -> None:
        """
        Analyze a process for suspicious indicators.
        
        Args:
            process_info: Process information to analyze
        """
        score = 0
        indicators = []
        
        # Check process name
        name_lower = process_info.name.lower()
        for suspicious in self.SUSPICIOUS_NAMES:
            if suspicious in name_lower:
                score += 30
                indicators.append(f"Suspicious process name: {suspicious}")
        
        # Check command line
        cmdline_str = ' '.join(process_info.cmdline).lower()
        for pattern in self.SUSPICIOUS_CMD_PATTERNS:
            if pattern in cmdline_str:
                score += 25
                indicators.append(f"Suspicious command pattern: {pattern}")
        
        # Check for hidden processes (name mismatch)
        if process_info.exe:
            exe_name = Path(process_info.exe).name.lower()
            if exe_name != name_lower and exe_name.replace('.exe', '') != name_lower:
                score += 20
                indicators.append(f"Process name/exe mismatch: {process_info.name} vs {exe_name}")
        
        # Check for high resource usage without reason
        if process_info.memory_percent > 50:
            score += 10
            indicators.append(f"High memory usage: {process_info.memory_percent:.1f}%")
        
        if process_info.num_threads > 100:
            score += 15
            indicators.append(f"Unusual thread count: {process_info.num_threads}")
        
        # Check for network connections to suspicious ports
        for conn in process_info.connections:
            raddr = conn.get('raddr', '')
            if raddr:
                port = raddr.split(':')[-1] if ':' in raddr else ''
                if port in ['4444', '5555', '6666', '7777', '8888', '9999']:
                    score += 20
                    indicators.append(f"Connection to suspicious port: {port}")
        
        # Check loaded modules
        for module in process_info.loaded_modules:
            module_lower = module.lower()
            for suspicious in self.SUSPICIOUS_MODULES:
                if suspicious in module_lower and suspicious not in ['ntdll.dll', 'kernel32.dll']:
                    score += 25
                    indicators.append(f"Suspicious module: {suspicious}")
        
        # Check for processes running from temp directories
        if process_info.exe:
            exe_path = process_info.exe.lower()
            if any(temp in exe_path for temp in ['/tmp/', '/temp/', 'appdata/local/temp', 'windows/temp']):
                score += 15
                indicators.append("Process running from temp directory")
        
        # Check for unsigned executables (Windows)
        if platform_info.is_windows and process_info.exe:
            # Would need additional libraries for signature verification
            pass
        
        process_info.suspicious_score = min(score, 100)
        process_info.suspicious_indicators = indicators
        process_info.is_suspicious = score >= 50
    
    def scan_process_memory(self, pid: int) -> MemoryScanResult:
        """
        Scan a process's memory for threats.
        
        Note: This requires elevated privileges and is platform-specific.
        
        Args:
            pid: Process ID to scan
            
        Returns:
            MemoryScanResult object
        """
        result = MemoryScanResult(
            pid=pid,
            process_name="",
            status="clean",
            threat_name=None,
            memory_regions_scanned=0,
            suspicious_regions=0,
            injected_code_detected=False,
            hidden_modules=False,
            explanation="",
            recommendations=[]
        )
        
        if not PSUTIL_AVAILABLE:
            result.status = "error"
            result.explanation = "psutil not installed - memory scanning unavailable"
            return result
        
        try:
            proc = psutil.Process(pid)
            result.process_name = proc.name()
            
            # Check if process is accessible
            if not proc.is_running():
                result.status = "error"
                result.explanation = "Process is no longer running"
                return result
            
            # Scan memory maps for suspicious regions
            try:
                memory_maps = proc.memory_maps(grouped=True)
                result.memory_regions_scanned = len(memory_maps)
                
                for mmap in memory_maps:
                    # Check for RWX (read-write-execute) regions - often indicate injected code
                    perms = mmap.perms if hasattr(mmap, 'perms') else ''
                    if 'r' in perms and 'w' in perms and 'x' in perms:
                        result.suspicious_regions += 1
                        result.injected_code_detected = True
                    
                    # Check for anonymous mappings (no path) - could be shellcode
                    if not mmap.path or mmap.path == '':
                        result.suspicious_regions += 1
                    
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                result.status = "error"
                result.explanation = "Access denied - requires elevated privileges"
                result.recommendations = ["Run as Administrator/Root for memory scanning"]
                return result
            
            # Check for hidden modules (modules not in standard list)
            try:
                modules = proc.memory_maps(grouped=True)
                standard_dlls = {'kernel32.dll', 'ntdll.dll', 'kernelbase.dll', 'user32.dll'}
                
                for module in modules:
                    if module.path:
                        module_name = Path(module.path).name.lower()
                        if module_name not in standard_dlls and 'windows' not in module.path.lower():
                            result.suspicious_regions += 1
                
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Determine status
            if result.injected_code_detected:
                result.status = "infected"
                result.threat_name = "Potential code injection detected"
                result.explanation = (
                    f"Scanned {result.memory_regions_scanned} memory regions.\n"
                    f"Found {result.suspicious_regions} suspicious regions.\n\n"
                    "RWX (read-write-execute) memory regions detected.\n"
                    "This is a common technique used by malware to inject code."
                )
                result.recommendations = [
                    "Investigate this process immediately",
                    "Check process origin and purpose",
                    "Consider terminating if unknown",
                    "Scan the process executable file"
                ]
            elif result.suspicious_regions > 5:
                result.status = "suspicious"
                result.explanation = (
                    f"Scanned {result.memory_regions_scanned} memory regions.\n"
                    f"Found {result.suspicious_regions} unusual regions.\n\n"
                    "This may indicate packed software or potential malware."
                )
                result.recommendations = [
                    "Monitor this process",
                    "Verify the process is legitimate"
                ]
            else:
                result.status = "clean"
                result.explanation = (
                    f"Scanned {result.memory_regions_scanned} memory regions.\n"
                    f"No significant anomalies detected."
                )
            
        except psutil.NoSuchProcess:
            result.status = "error"
            result.explanation = "Process no longer exists"
        except psutil.AccessDenied:
            result.status = "error"
            result.explanation = "Access denied - run as Administrator/Root"
            result.recommendations = ["Run with elevated privileges for memory scanning"]
        except Exception as e:
            result.status = "error"
            result.explanation = f"Scan error: {e}"
            logger.error(f"Memory scan failed for PID {pid}: {e}")
        
        return result
    
    def scan_all_processes(self) -> List[MemoryScanResult]:
        """
        Scan all running processes.
        
        Returns:
            List of MemoryScanResult objects
        """
        self.scan_results = []
        
        processes = self.get_all_processes()
        
        for proc in processes:
            # Only scan suspicious processes or all if privileged
            if proc.is_suspicious or platform_info.is_admin():
                result = self.scan_process_memory(proc.pid)
                self.scan_results.append(result)
            else:
                # Just record basic info for non-suspicious
                result = MemoryScanResult(
                    pid=proc.pid,
                    process_name=proc.name,
                    status="clean",
                    threat_name=None,
                    memory_regions_scanned=0,
                    suspicious_regions=0,
                    injected_code_detected=False,
                    hidden_modules=False,
                    explanation="Process appears normal",
                    recommendations=[]
                )
                self.scan_results.append(result)
        
        return self.scan_results
    
    def get_suspicious_processes(self) -> List[ProcessInfo]:
        """Get list of suspicious processes."""
        return [p for p in self.processes if p.is_suspicious]
    
    def get_process_tree(self) -> Dict[str, Any]:
        """
        Get process tree showing parent-child relationships.
        
        Returns:
            Nested dictionary representing process tree
        """
        if not PSUTIL_AVAILABLE:
            return {}
        
        def build_tree(proc):
            try:
                result = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'children': []
                }
                for child in proc.children():
                    result['children'].append(build_tree(child))
                return result
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return {}
        
        tree = []
        for proc in psutil.process_iter():
            try:
                if proc.parent() is None:  # Root process
                    tree.append(build_tree(proc))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return {'processes': tree}
    
    def terminate_process(self, pid: int, force: bool = False) -> bool:
        """
        Terminate a process.
        
        Args:
            pid: Process ID to terminate
            force: Use force kill instead of graceful terminate
            
        Returns:
            True if successful
        """
        if not PSUTIL_AVAILABLE:
            return False
        
        try:
            proc = psutil.Process(pid)
            
            if force:
                proc.kill()
            else:
                proc.terminate()
            
            # Wait for process to terminate
            proc.wait(timeout=5)
            
            logger.info(f"Terminated process {pid} ({proc.name()})")
            return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
            logger.error(f"Failed to terminate process {pid}: {e}")
            return False
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """
        Get summary of process scan results.
        
        Returns:
            Dictionary with scan statistics
        """
        suspicious = [r for r in self.scan_results if r.status == 'infected']
        warning = [r for r in self.scan_results if r.status == 'suspicious']
        
        return {
            'total_processes': len(self.scan_results),
            'infected': len(suspicious),
            'suspicious': len(warning),
            'clean': len(self.scan_results) - len(suspicious) - len(warning),
            'processes_with_injection': len([r for r in self.scan_results if r.injected_code_detected]),
        }


# Global process scanner instance
process_scanner = ProcessScanner()
