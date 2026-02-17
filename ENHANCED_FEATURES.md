# Green Mold Cure - Enhanced Features Documentation

## Overview

Green Mold Cure is now an **enterprise-grade CLI antivirus scanner** with multi-engine detection, comprehensive error handling, and detailed explanations for every action.

---

## 🚀 New Enhanced Features

### 1. Multi-Engine Scanning

The enhanced scanner uses **4 detection engines** working together:

| Engine | Description | What It Detects |
|--------|-------------|-----------------|
| **Signature-Based** | Hash matching against known malware database | Known malware, viruses, trojans |
| **YARA Rules** | Pattern matching with customizable rules | Malware families, suspicious patterns, packers |
| **Heuristic Analysis** | Behavioral pattern detection | Unknown malware, suspicious behavior |
| **PE Analysis** | Windows executable inspection | Packed files, suspicious imports, anti-analysis |

### 2. Comprehensive Error Handling

**No more silent failures!** Every error is now:
- **Logged** with full stack trace
- **Explained** with possible causes
- **Actionable** with specific recommendations

#### Error Types Handled:
```
✓ Access Denied     → Run as administrator/root
✓ File In Use       → Close program using file
✓ Corrupted File    → File is damaged
✓ Path Too Long     → Windows 260 char limit
✓ Special Files     → System files, sockets, pipes
✓ Permission Error  → Check file permissions
```

### 3. Detailed Explanations

Every scan result now includes:
- **What was found** (or not found)
- **Why it matters** (threat context)
- **What to do** (specific recommendations)

#### Example Output:
```
✗ THREAT | /path/to/file.exe
  Threat: Win32.Ransomware.Generic
  Type: ransomware | Severity: CRITICAL
  
  Explanation:
  Known threat detected by signature matching.
  This file matches a known malware signature in our database.
  
  Recommendations:
  • Quarantine this file immediately
  • Do not execute or open this file
  • Scan other files in the same directory
```

### 4. YARA Rule Integration

**Built-in YARA rules** for detecting:
- Suspicious API calls (keylogging, injection)
- Packed/encrypted executables
- Ransomware indicators
- Anti-VM/anti-debug techniques
- Network communication patterns

**Custom YARA rules** can be added:
```bash
# Save custom rules to:
~/.green_mold_cure/yara_rules/custom.yar

# Or configure in Settings → Add YARA Rule
```

### 5. Archive Scanning

Recursively scans inside:
- ZIP archives
- RAR archives (with rarfile)
- 7z archives (with py7zr)
- Gzip, Tar, BZ2, XZ

**Features:**
- Multi-level recursion (up to 5 levels)
- Memory-efficient streaming
- Corrupted archive detection

### 6. Enhanced Scan Summary

The new scan report includes:
- **Success rate** percentage
- **Threats by type** breakdown
- **Threats by severity** breakdown
- **File types** scanned
- **Error summary** with solutions
- **Actionable recommendations**

### 7. Quarantine Improvements

- **Encrypted storage** for quarantined files
- **Metadata preservation** for analysis
- **Secure deletion** with 3-pass overwrite
- **Restore capability** for false positives

---

## 📊 Scan Result Status Codes

| Status | Meaning | Action |
|--------|---------|--------|
| `CLEAN` | No threats detected | None needed |
| `INFECTED` | Known malware detected | Quarantine/Delete |
| `SUSPICIOUS` | Potentially unwanted | Review/Investigate |
| `ERROR` | Scan failed | Check error details |
| `ACCESS_DENIED` | Cannot access file | Run as admin |
| `SKIPPED` | Intentionally skipped | Check exclusions |
| `CORRUPTED` | File is damaged | Delete or ignore |

---

## 🎯 Severity Levels

| Severity | Description | Recommended Action |
|----------|-------------|-------------------|
| **CRITICAL** | Immediate threat | Isolate and delete immediately |
| **HIGH** | Confirmed malware | Quarantine as soon as possible |
| **MEDIUM** | Suspicious behavior | Investigate and monitor |
| **LOW** | Minor concern | Monitor only |

---

## 🔧 Configuration Options

### Scan Settings
```
• Max file size (default: 500 MB)
• Archive scanning (enabled/disabled)
• Heuristic analysis (enabled/disabled)
• Follow symlinks (enabled/disabled)
• Exclusion patterns (customizable)
```

### API Integrations
```
• VirusTotal - 70+ antivirus engines
• Hybrid Analysis - Automated sandbox
• Any.run - Interactive sandbox
• AlienVault OTX - Community threat intel
• PhishTank - Phishing URLs
```

---

## 📁 File Structure

```
Green_Mold_Cure_project/
├── src/
│   ├── main.py                 # Main entry point (enhanced)
│   ├── scanner/
│   │   ├── enhanced_engine.py  # NEW: Multi-engine scanner
│   │   ├── yara_scanner.py     # NEW: YARA rule engine
│   │   ├── engine.py           # Original scanner
│   │   ├── signatures.py       # Signature database
│   │   └── heuristics.py       # Heuristic analysis
│   ├── quarantine/
│   │   └── manager.py          # Enhanced quarantine
│   ├── database/
│   │   ├── updater.py          # Multi-source updates
│   │   └── sources/            # Threat feed integrations
│   └── utils/
│       ├── platform.py         # Cross-platform support
│       ├── logger.py           # Structured logging
│       └── crypto.py           # Encryption utilities
├── yara_rules/                 # Custom YARA rules
├── run.py                      # Application launcher
└── requirements.txt            # Updated dependencies
```

---

## 🚀 Usage Examples

### Quick Scan
```bash
python3 run.py
# Select option 1: Quick Scan
```

### Full System Scan (with admin)
```bash
# Linux/macOS
sudo python3 run.py

# Windows (Run as Administrator)
python run.py
```

### Custom Scan
```bash
python3 run.py
# Select option 3: Custom Path Scan
# Enter: /home/user/Downloads, /tmp
```

---

## 📈 Performance Improvements

| Feature | Before | After |
|---------|--------|-------|
| Max file size | 100 MB | 500 MB |
| Archive support | None | ZIP, RAR, 7z, etc. |
| Detection engines | 2 | 4 |
| Error explanations | None | Detailed |
| YARA rules | 0 | 5+ built-in |

---

## 🔒 Security Features

1. **Encrypted Quarantine** - AES-256 encryption for quarantined files
2. **Secure Deletion** - DoD 5220.22-M 3-pass overwrite
3. **API Key Protection** - Stored locally, never transmitted
4. **Audit Logging** - All actions logged for review
5. **Permission Management** - Minimal required permissions

---

## 🐛 Troubleshooting

### High Error Count
```
Problem: Many "Access Denied" errors
Solution: Run as Administrator/Root
```

### YARA Not Available
```
Problem: "YARA not installed" warning
Solution: pip install yara-python
```

### Slow Scanning
```
Problem: Scan takes too long
Solution: 
  • Reduce max file size in settings
  • Add exclusions for large directories
  • Use Quick Scan for routine checks
```

### Archive Not Scanned
```
Problem: Archives show as clean but suspicious
Solution: 
  • Enable archive scanning in settings
  • Check archive isn't password-protected
  • Verify archive isn't corrupted
```

---

## 📝 API Key Setup

Get free API keys for enhanced detection:

1. **VirusTotal**: https://www.virustotal.com/gui/my-apikey
2. **Hybrid Analysis**: https://www.hybrid-analysis.com/api/key
3. **Any.run**: https://any.run/api-documentation
4. **AlienVault OTX**: https://otx.alienvault.com/api

Configure in-app: Settings → Configure API Keys

---

## 🎓 Understanding Scan Results

### Clean File
```
✓ CLEAN | /path/to/file.exe
  Windows Executable | 256.0 KB
  
  Explanation:
  No threats detected based on:
  • Signature database check
  • YARA pattern matching
  • Heuristic analysis
```

### Infected File
```
✗ THREAT | /path/to/malware.exe
  Threat: Win32.Trojan.Generic
  Type: trojan | Severity: HIGH
  
  Explanation:
  Known threat detected by signature matching.
  This file matches a known malware signature.
  
  Recommendations:
  • Quarantine this file immediately
  • Do not execute or open this file
  • Scan other files in the same directory
```

### Suspicious File
```
⚠ SUSPICIOUS | /path/to/unknown.exe
  Heuristic Score: 65/100
  YARA Matches: 2
  
  Explanation:
  Suspicious patterns detected by YARA rules.
  • GreenMold_Suspicious_Strings: Detected suspicious API calls
  • GreenMold_Packer_Detect: File appears to be packed
  
  Recommendations:
  • Review the matched YARA rules for details
  • Upload to VirusTotal for additional analysis
```

---

## 📞 Support

For issues or questions:
1. Check logs: `~/.green_mold_cure/logs/`
2. Review TROUBLESHOOTING.md
3. Check API_KEY_SETUP.md for key configuration

---

**Version:** 2.0.0 Enhanced Edition  
**Last Updated:** Current Date
