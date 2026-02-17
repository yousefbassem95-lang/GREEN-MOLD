"""
YARA Rule Integration for Green Mold Cure.
Advanced pattern-based malware detection using YARA rules.

YARA (Yet Another Ridiculous Acronym) is a tool for identifying and classifying
malware samples based on textual and binary patterns.
"""

import os
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

from utils.logger import logger
from utils.platform import platform_info


@dataclass
class YaraMatch:
    """Represents a YARA rule match."""
    rule_name: str
    namespace: str
    file_path: Path
    strings: List[Dict[str, Any]]
    tags: List[str]
    metadata: Dict[str, Any]
    severity: str
    description: str


class YaraScanner:
    """
    YARA-based malware scanner for Green Mold Cure.
    
    Features:
    - Load and compile YARA rules from multiple sources
    - Scan files against all rules efficiently
    - Detailed match reporting with string offsets
    - Support for external variables and modules
    """
    
    # Default YARA rule directories
    RULE_DIRS = [
        Path("/usr/share/yara/rules"),  # System rules (Linux)
        Path("/usr/local/share/yara/rules"),  # Local rules (Linux)
        Path.home() / ".green_mold_cure" / "yara_rules",  # User rules
        Path(__file__).parent.parent / "yara_rules",  # Project rules
    ]
    
    # Built-in YARA rules (embedded for portability)
    BUILTIN_RULES = """
rule GreenMold_Suspicious_Strings {
    strings:
        $s1 = "GetAsyncKeyState" nocase
        $s2 = "VirtualAllocEx" nocase
        $s3 = "WriteProcessMemory" nocase
        $s4 = "CreateRemoteThread" nocase
        $s5 = "URLDownloadToFile" nocase
        $s6 = "ShellExecute" nocase
        $s7 = "RegSetValueEx" nocase
        $s8 = "CryptEncrypt" nocase
        $s9 = "InternetOpen" nocase
        $s10 = "WinExec" nocase
    
    condition:
        3 of them
}

rule GreenMold_Packer_Detect {
    strings:
        $upx = "UPX!" fullword
        $aspack = "aPLib" fullword
        $petite = "PEtite" fullword
        $fsg = "FSG!" fullword
    
    condition:
        any of them
}

rule GreenMold_Ransomware_Indicators {
    strings:
        $ransom1 = "Your files have been encrypted" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = "decrypt" nocase
        $ransom4 = ".locked" fullword
        $ransom5 = ".encrypted" fullword
        $ransom6 = "HOW_TO_DECRYPT" nocase
    
    condition:
        2 of them
}

rule GreenMold_Keylogger_Patterns {
    strings:
        $key1 = "GetForegroundWindow" nocase
        $key2 = "GetKeyState" nocase
        $key3 = "SetWindowsHookEx" nocase
        $key4 = "GetAsyncKeyState" nocase
        $key5 = "keylog" nocase
    
    condition:
        3 of them
}

rule GreenMold_AntiVM_AntiDebug {
    strings:
        $vm1 = "vmware" nocase
        $vm2 = "virtualbox" nocase
        $vm3 = "vbox" nocase
        $dbg1 = "IsDebuggerPresent" nocase
        $dbg2 = "CheckRemoteDebuggerPresent" nocase
        $dbg3 = "NtQueryInformationProcess" nocase
    
    condition:
        2 of them
}
"""
    
    def __init__(self, rules_path: Optional[Path] = None):
        """
        Initialize the YARA scanner.
        
        Args:
            rules_path: Optional path to custom YARA rules
        """
        if not YARA_AVAILABLE:
            logger.warning("YARA not installed - pattern matching disabled")
            self.compiled_rules = None
            return
        
        self.rules_path = rules_path
        self.compiled_rules = None
        self.rules_count = 0
        self._load_rules()
    
    def _load_rules(self) -> None:
        """Load and compile YARA rules from all sources."""
        if not YARA_AVAILABLE:
            return
        
        try:
            # Start with built-in rules
            rules_source = self.BUILTIN_RULES
            
            # Load additional rules from directories
            for rule_dir in self.RULE_DIRS:
                if rule_dir.exists():
                    additional_rules = self._load_rules_from_dir(rule_dir)
                    if additional_rules:
                        rules_source += "\n" + additional_rules
            
            # Load custom rules if specified
            if self.rules_path and self.rules_path.exists():
                if self.rules_path.is_file():
                    with open(self.rules_path, 'r') as f:
                        rules_source += "\n" + f.read()
                elif self.rules_path.is_dir():
                    additional_rules = self._load_rules_from_dir(self.rules_path)
                    if additional_rules:
                        rules_source += "\n" + additional_rules
            
            # Compile rules
            self.compiled_rules = yara.compile(source=rules_source)
            self.rules_count = len(self.compiled_rules)
            
            logger.info(f"Loaded {self.rules_count} YARA rules")
            
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.compiled_rules = None
    
    def _load_rules_from_dir(self, rule_dir: Path) -> str:
        """
        Load all YARA rules from a directory.
        
        Args:
            rule_dir: Directory containing .yar or .yarc files
            
        Returns:
            Combined rules as string
        """
        rules = []
        
        for ext in ['*.yar', '*.yarc', '*.yara']:
            for rule_file in rule_dir.glob(ext):
                try:
                    with open(rule_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if content.strip():
                            rules.append(content)
                            logger.debug(f"Loaded YARA rule: {rule_file.name}")
                except Exception as e:
                    logger.warning(f"Failed to load {rule_file}: {e}")
        
        return "\n\n".join(rules)
    
    def scan_file(self, file_path: Path, timeout: int = 30) -> List[YaraMatch]:
        """
        Scan a file with YARA rules.
        
        Args:
            file_path: Path to the file to scan
            timeout: Scan timeout in seconds
            
        Returns:
            List of YaraMatch objects for each rule match
        """
        if not YARA_AVAILABLE or self.compiled_rules is None:
            return []
        
        try:
            if not file_path.exists():
                return []
            
            # Skip very large files (>100MB) for performance
            if file_path.stat().st_size > 100 * 1024 * 1024:
                logger.debug(f"Skipping large file for YARA scan: {file_path}")
                return []
            
            matches = self.compiled_rules.match(
                str(file_path),
                timeout=timeout
            )
            
            results = []
            for match in matches:
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    file_path=file_path,
                    strings=[
                        {
                            'name': s.identifier,
                            'offset': s.offset,
                            'data': s.matched_data.decode('utf-8', errors='replace')
                        }
                        for s in match.strings
                    ],
                    tags=match.tags,
                    metadata=dict(match.meta),
                    severity=self._calculate_severity(match),
                    description=self._get_rule_description(match.rule)
                )
                results.append(yara_match)
            
            if results:
                logger.info(
                    f"YARA matched {len(results)} rules in {file_path}",
                    rules=[m.rule_name for m in results]
                )
            
            return results
            
        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout for {file_path}")
            return []
        except Exception as e:
            logger.debug(f"YARA scan error for {file_path}: {e}")
            return []
    
    def scan_data(self, data: bytes, timeout: int = 10) -> List[YaraMatch]:
        """
        Scan raw data with YARA rules.
        
        Args:
            data: Bytes to scan
            timeout: Scan timeout in seconds
            
        Returns:
            List of YaraMatch objects
        """
        if not YARA_AVAILABLE or self.compiled_rules is None:
            return []
        
        try:
            matches = self.compiled_rules.match(data=data, timeout=timeout)
            
            results = []
            for match in matches:
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    file_path=Path("<memory>"),
                    strings=[
                        {
                            'name': s.identifier,
                            'offset': s.offset,
                            'data': s.matched_data.decode('utf-8', errors='replace')
                        }
                        for s in match.strings
                    ],
                    tags=match.tags,
                    metadata=dict(match.meta),
                    severity=self._calculate_severity(match),
                    description=self._get_rule_description(match.rule)
                )
                results.append(yara_match)
            
            return results
            
        except yara.TimeoutError:
            return []
        except Exception:
            return []
    
    def _calculate_severity(self, match) -> str:
        """
        Calculate severity based on YARA rule match.
        
        Args:
            match: YARA match object
            
        Returns:
            Severity string (low, medium, high, critical)
        """
        rule_name = match.rule.lower()
        tags = [t.lower() for t in match.tags]
        
        # Critical threats
        critical_patterns = ['ransom', 'cryptolocker', 'wannacry', 'destructive']
        if any(p in rule_name or p in tags for p in critical_patterns):
            return 'critical'
        
        # High severity
        high_patterns = ['backdoor', 'rat', 'trojan', 'banker', 'stealer', 'keylogger']
        if any(p in rule_name or p in tags for p in high_patterns):
            return 'high'
        
        # Medium severity
        medium_patterns = ['downloader', 'dropper', 'injector', 'packer', 'suspicious']
        if any(p in rule_name or p in tags for p in medium_patterns):
            return 'medium'
        
        # Low severity
        return 'low'
    
    def _get_rule_description(self, rule_name: str) -> str:
        """
        Get human-readable description for a YARA rule.
        
        Args:
            rule_name: Name of the YARA rule
            
        Returns:
            Description string
        """
        descriptions = {
            'GreenMold_Suspicious_Strings': 'Detected suspicious API calls commonly used by malware',
            'GreenMold_Packer_Detect': 'File appears to be packed or compressed (common malware technique)',
            'GreenMold_Ransomware_Indicators': 'Potential ransomware indicators detected',
            'GreenMold_Keylogger_Patterns': 'Keylogging functionality detected',
            'GreenMold_AntiVM_AntiDebug': 'Anti-analysis techniques detected (anti-VM/anti-debug)',
        }
        
        return descriptions.get(rule_name, f'YARA rule match: {rule_name}')
    
    def get_rules_info(self) -> Dict[str, Any]:
        """
        Get information about loaded YARA rules.
        
        Returns:
            Dict with rules information
        """
        if not YARA_AVAILABLE or self.compiled_rules is None:
            return {
                'available': False,
                'reason': 'YARA not installed or rules not loaded'
            }
        
        return {
            'available': True,
            'rules_count': self.rules_count,
            'rule_dirs': [str(d) for d in self.RULE_DIRS],
            'custom_rules': str(self.rules_path) if self.rules_path else None
        }
    
    def add_rule(self, rule_content: str, name: Optional[str] = None) -> bool:
        """
        Add a new YARA rule.
        
        Args:
            rule_content: YARA rule content
            name: Optional name for the rule file
            
        Returns:
            True if rule added successfully
        """
        if not YARA_AVAILABLE:
            return False
        
        try:
            # Validate rule by compiling
            yara.compile(source=rule_content)
            
            # Save to user rules directory
            rules_dir = platform_info.get_app_data_dir() / "yara_rules"
            rules_dir.mkdir(parents=True, exist_ok=True)
            
            if name:
                rule_file = rules_dir / name
            else:
                rule_file = rules_dir / f"custom_rule_{len(list(rules_dir.glob('*.yar')))}.yar"
            
            with open(rule_file, 'w') as f:
                f.write(rule_content)
            
            # Reload rules
            self._load_rules()
            
            logger.info(f"Added YARA rule: {rule_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add YARA rule: {e}")
            return False


# Global YARA scanner instance
yara_scanner = YaraScanner()
