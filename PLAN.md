# Green Mold Cure - Project Plan

**Version:** 1.0  
**Created:** February 17, 2026  
**Status:** Approved

---

## Project Overview

A cross-platform CLI antivirus tool with Rich UI, numbered menu interface, comprehensive threat intelligence integration, and user-prompted containment/purge actions.

**Color Scheme:** DARK GREEN  
**Icon:** ASCII art from `ICON.txt` displayed at top of interface

---

## Architecture

### Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| CLI Framework | `click` + `rich` |
| UI Theme | Dark Green |
| Database | SQLite |
| Cross-Platform | `platform` module |

### Platform Support

| Platform | Support Level | Notes |
|----------|--------------|-------|
| Linux | Full | Native execution |
| Windows | Full | Native execution (.exe via PyInstaller) |
| macOS | Full | Native execution |
| Android | Partial | Via Termux (documented setup) |
| iOS | Partial | Via a-Shell/iSH (documented setup) |

---

## Core Features

### 1. Numbered Menu Interface

```
╔═══════════════════════════════════════════════════════════╗
║                    GREEN MOLD CURE                        ║
║                    Antivirus Scanner                      ║
╠═══════════════════════════════════════════════════════════╣
║  1. Quick Scan (common malware locations)                 ║
║  2. Full System Scan                                      ║
║  3. Custom Path Scan                                      ║
║  4. Update Threat Database                                ║
║  5. View Quarantine                                       ║
║  6. Scan & Batch Vulnerabilities                          ║
║  7. Settings                                              ║
║  8. Exit                                                  ║
╚═══════════════════════════════════════════════════════════╝
```

### 2. Threat Intelligence Integration

#### Surface Web Sources
- ClamAV official signatures (freshclam)
- Abuse.ch (MalwareBazaar, URLhaus, ThreatFox)
- VirusTotal API (user provides key)
- Hybrid Analysis API (user provides key)
- Any.run API (user provides key)
- AlienVault OTX
- PhishTank

#### Deep Web (.onion) Sources
- Tor integration via `stem` + `requests` with Tor proxy
- Curated .onion threat feeds (documented setup for Tor)

### 3. Threat Actions (User Prompted)

| Action | Description |
|--------|-------------|
| Quarantine | Move to encrypted/isolated folder with restricted permissions |
| Purge | Secure delete (overwrite + remove) |
| Ignore | Add to exclusion list |

### 4. Batch Vulnerability Scanning

- Scan multiple paths/files in single operation
- Export reports (JSON, CSV, TXT)
- Severity classification (Critical, High, Medium, Low)

---

## Project Structure

```
Green_Mold_Cure_project/
├── Global_Rules.md
├── ICON.txt
├── PLAN.md
├── README.md
├── Project-Map.json
├── requirements.txt
├── constitution.yaml
├── system_constraints.md
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point with icon display
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── menu.py          # Numbered menu system
│   │   └── display.py       # Rich UI components (dark green theme)
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py        # Core scanning logic
│   │   ├── signatures.py    # Signature matching
│   │   └── heuristics.py    # Behavioral detection
│   ├── database/
│   │   ├── __init__.py
│   │   ├── updater.py       # Database update from all sources
│   │   ├── manager.py       # Local DB management (SQLite)
│   │   └── sources/
│   │       ├── clamav.py
│   │       ├── abuse_ch.py
│   │       ├── virustotal.py
│   │       ├── tor_feeds.py
│   │       └── ...
│   ├── quarantine/
│   │   ├── __init__.py
│   │   ├── manager.py       # Quarantine operations
│   │   └── vault.py         # Secure storage
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── platform.py      # OS detection & handling
│   │   ├── crypto.py        # Encryption for quarantine
│   │   └── logger.py        # Structured logging
│   └── config/
│       ├── __init__.py
│       └── settings.py      # User preferences
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_database.py
│   ├── test_quarantine.py
│   └── test_cli.py
└── scripts/
    ├── install.sh           # Linux/macOS installer
    ├── install.bat          # Windows installer
    └── termux_setup.sh      # Android Termux setup
```

---

## Implementation Phases

### Phase 1: Foundation
- [ ] Project structure & documentation (README, Project-Map.json, etc.)
- [ ] Rich CLI with dark green theme + icon display
- [ ] Numbered menu system
- [ ] Basic file scanning engine

### Phase 2: Core Security
- [ ] Signature-based detection
- [ ] Quarantine manager with secure storage
- [ ] Threat prompt system (quarantine/purge/ignore)

### Phase 3: Database & Intelligence
- [ ] SQLite database for signatures
- [ ] ClamAV integration
- [ ] Abuse.ch feeds integration
- [ ] API-based sources (VirusTotal, Hybrid Analysis - user provides keys)

### Phase 4: Advanced Features
- [ ] Tor integration for .onion feeds
- [ ] Batch vulnerability scanning
- [ ] Report generation (JSON/CSV/TXT)
- [ ] Heuristic analysis

### Phase 5: Cross-Platform & Polish
- [ ] Platform-specific optimizations
- [ ] Installers for Linux, Windows, macOS
- [ ] Termux/Android setup documentation
- [ ] iOS compatibility notes
- [ ] Full test suite
- [ ] Troubleshooting guide

---

## Security Considerations

- No hardcoded API keys (environment variables only)
- Quarantine folder with restricted permissions (chmod 000 / encrypted)
- Secure deletion using multiple overwrite passes
- User confirmation before any destructive action
- Logging for audit trail

---

## Deliverables

1. Fully functional CLI antivirus with all features
2. Complete documentation (installation, usage, troubleshooting)
3. Test suite covering all major functions
4. Platform-specific installers
5. API key setup guide for optional threat sources

---

## Estimated Scope

- ~2000-3000 lines of Python code
- 15+ test cases
- Full documentation per Global Rules

---

## Change Log

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | February 17, 2026 | Initial plan approved |
