# System Constraints

## Technical Constraints

### Python Version
- **Minimum:** Python 3.10
- **Reason:** Type hint union syntax (`|`), match-case statements, improved error messages

### Platform Limitations

#### Linux
- Full functionality supported
- Requires appropriate permissions for system scans
- Quarantine uses filesystem permissions (chmod 000)

#### Windows
- Full functionality supported
- Windows Defender may flag quarantine operations (add exclusion)
- Requires Administrator privileges for full system scan
- Path length limitations (260 chars) unless long paths enabled

#### macOS
- Full functionality supported
- SIP (System Integrity Protection) limits scanning of system directories
- Quarantine uses sandboxing where available

#### Android (Termux)
- Limited to user-accessible directories
- No root = no system partition scanning
- Storage permissions required for external storage
- Some Python packages may require compilation

#### iOS (a-Shell/iSH)
- Highly restricted environment
- Limited to app sandbox
- No background processes
- Functionality severely limited - documentation only

### Memory Constraints
- Signature database loaded in chunks for low-memory systems
- Large file scanning uses streaming hashes
- Maximum concurrent file handles: 256

### Network Constraints
- Rate limiting on API calls to respect free tier limits
- Timeout: 30 seconds per request
- Retry logic: 3 attempts with exponential backoff
- Offline mode: Basic scanning with local signatures only

### Storage Constraints
- Default quarantine size limit: 1 GB (configurable)
- Database auto-vacuum when > 500 MB
- Log rotation: Keep last 4 weeks

## Security Constraints

### API Keys
- Never stored in code
- Loaded from environment variables or `.env` file
- `.env` file excluded from version control

### Quarantine
- Files encrypted before storage
- Permissions set to 000 (Unix) or hidden + system (Windows)
- Original metadata preserved for restoration

### Secure Deletion
- 3-pass overwrite (DoD 5220.22-M standard)
- Random data → zeros → random data → delete
- SSD considerations: Use TRIM where available

### User Confirmation
Required for:
- File deletion/purge
- Quarantine restoration
- Database source configuration changes
- Settings that affect security

## Performance Constraints

### Scan Speed Targets
| Scan Type | Target Speed |
|-----------|-------------|
| Quick Scan | < 2 minutes |
| Full System | < 30 minutes (typical) |
| Custom (1000 files) | < 5 minutes |

### Database Update
- Full update: < 5 minutes
- Incremental update: < 1 minute
- Parallel fetching where possible

### Resource Usage
- CPU: < 50% during scan (configurable)
- Memory: < 500 MB typical
- Disk I/O: Throttled to avoid system impact

## Legal Constraints

### Threat Intelligence Sources
- Only use publicly available or properly licensed feeds
- Respect API terms of service
- No unauthorized access to systems
- Deep web scanning limited to publicly documented .onion feeds

### Distribution
- Do not bundle with malware
- Include disclaimer
- No warranty provided
- Educational and protective use only

### Privacy
- No telemetry without explicit consent
- Scan results stored locally only
- User data never transmitted without consent
- Logs can be disabled

## Dependency Constraints

### Required Packages
| Package | Minimum Version | Purpose |
|---------|-----------------|---------|
| click | 8.1.0 | CLI framework |
| rich | 13.0.0 | Terminal UI |
| requests | 2.31.0 | HTTP client |
| cryptography | 41.0.0 | Encryption |

### Optional Packages
| Package | Purpose | Fallback |
|---------|---------|----------|
| stem | Tor integration | Manual Tor config |
| python-magic | File type detection | Extension-based |
| pefile | PE analysis | Basic scanning |

### Incompatible Packages
- None currently identified

## Operational Constraints

### User Requirements
- Basic command-line familiarity
- Python 3.10+ installed (or ability to install)
- Internet connection for updates
- Sufficient disk space (~100 MB for database)

### Environment Requirements
- Write access to home directory
- Read access to scan targets
- Network access for updates
- (Optional) Tor daemon for .onion feeds

### Maintenance Requirements
- Database update: Recommended daily
- Log cleanup: Automatic (4-week retention)
- Version check: On startup (weekly reminder)

## Failure Modes

### Graceful Degradation
| Failure | Fallback Behavior |
|---------|-------------------|
| No internet | Use local signatures only |
| API key missing | Skip premium sources |
| Tor unavailable | Skip .onion feeds |
| Low disk space | Warn and limit quarantine |
| Permission denied | Skip file and continue |

### Critical Failures (Stop and Prompt)
- Database corruption
- Quarantine vault inaccessible
- Critical dependency missing
- Insufficient memory

## Version Compatibility

| Green Mold Cure | Min Python | Max Python | Notes |
|-----------------|------------|------------|-------|
| 1.0.0 | 3.10 | 3.13 | Initial release |

## Future Considerations

- Cloud sync for signatures (optional)
- Real-time protection (daemon/service mode)
- YARA rule integration
- Machine learning classifier
- Network scanning capabilities
