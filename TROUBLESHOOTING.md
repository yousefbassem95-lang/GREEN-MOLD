# Green Mold Cure - Troubleshooting Guide

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Runtime Errors](#runtime-errors)
3. [Scan Issues](#scan-issues)
4. [Database Update Problems](#database-update-problems)
5. [Quarantine Issues](#quarantine-issues)
6. [Platform-Specific Issues](#platform-specific-issues)
7. [Getting Help](#getting-help)

---

## Installation Issues

### "Python 3.10 or higher is required"

**Problem:** The installer reports Python version is too old.

**Solution:**
```bash
# Check current Python version
python3 --version

# Install Python 3.10+ on Ubuntu/Debian
sudo apt update
sudo apt install python3.10 python3-pip

# Install on macOS with Homebrew
brew install python@3.10

# Install on Windows
# Download from https://python.org/downloads/
```

### "pip3 is not installed"

**Problem:** pip package manager is missing.

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install python3-pip

# macOS
brew install pip

# Windows
# pip comes with Python 3.5+
```

### "Failed to install requirements"

**Problem:** Some Python packages fail to install.

**Solution:**
```bash
# Upgrade pip first
pip3 install --upgrade pip

# Install packages one by one to identify the problem
pip3 install click rich requests aiohttp cryptography

# For python-magic (requires libmagic)
# Ubuntu/Debian:
sudo apt install libmagic1

# macOS:
brew install libmagic

# For pefile (Windows PE analysis)
pip3 install pefile
```

### "Permission denied" during installation

**Problem:** Installer cannot write to system directories.

**Solution:**
```bash
# Use --user flag for pip
pip3 install --user -r requirements.txt

# Or run installer with sudo (Linux/macOS)
sudo ./scripts/install.sh

# Or use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Runtime Errors

### "Module not found" error

**Problem:** Python cannot find required modules.

**Solution:**
```bash
# Ensure you're in the project directory
cd /path/to/Green_Mold_Cure_project

# Reinstall dependencies
pip3 install -r requirements.txt

# Check Python path
python3 -c "import sys; print(sys.path)"
```

### "Cannot load icon" warning

**Problem:** ICON.txt file not found.

**Solution:**
- Verify ICON.txt exists in project root
- Check file permissions
- The application will use a fallback text header

### "Settings file corrupted"

**Problem:** Settings JSON cannot be parsed.

**Solution:**
```bash
# Delete corrupted settings file
rm ~/.green_mold_cure/settings.json

# Restart application - defaults will be created
python3 src/main.py
```

---

## Scan Issues

### "No files scanned" during quick scan

**Problem:** Quick scan finds no files.

**Solution:**
- This is normal if common malware locations are empty
- Try Custom Path Scan with specific directories
- Check file permissions on target directories

### "Permission denied" errors during scan

**Problem:** Scanner cannot access some files.

**Solution:**
```bash
# Run with elevated privileges (Linux/macOS)
sudo python3 src/main.py

# Run as Administrator (Windows)
# Right-click terminal -> Run as Administrator
python src\main.py

# Or add exclusions for inaccessible paths
# In Settings -> Manage Exclusions
```

### Scan is very slow

**Problem:** Full system scan takes too long.

**Solution:**
- Use Quick Scan for routine checks
- Add exclusions for large directories (node_modules, .git, etc.)
- Reduce max file size in settings
- Close other applications during scan

```bash
# Add exclusion example
# Settings -> Manage Exclusions -> Add
# Pattern: */node_modules/*
```

### False positives detected

**Problem:** Clean files flagged as threats.

**Solution:**
1. Verify the detection with an online scanner (VirusTotal)
2. If false positive, add to exclusions:
   - Settings -> Manage Exclusions -> Add
3. Report the false positive for signature review

---

## Database Update Problems

### "Update failed" for all sources

**Problem:** Cannot fetch threat signatures.

**Solution:**
```bash
# Check internet connection
ping google.com

# Check firewall settings
# Allow outbound HTTPS (port 443)

# Try updating one source at a time
# Check if specific source is down
```

### "VirusTotal API key not configured"

**Problem:** Premium sources require API keys.

**Solution:**
1. Get API key from virustotal.com
2. Edit `.env` file in project root:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```
3. Or configure in-app: Settings -> Configure API Keys

### ClamAV update fails

**Problem:** Cannot fetch ClamAV signatures.

**Solution:**
```bash
# ClamAV mirrors may be temporarily unavailable
# Try again later

# Check if ClamAV is blocking your IP
# Wait 1 hour between updates

# Alternative: Use Abuse.ch feeds which don't require API keys
```

### "Tor feeds update failed"

**Problem:** Cannot fetch .onion threat feeds.

**Solution:**
```bash
# Install Tor
# Ubuntu/Debian:
sudo apt install tor

# macOS:
brew install tor

# Start Tor service
sudo systemctl start tor

# Verify Tor is running
sudo systemctl status tor

# Configure in Settings -> Enable Tor Feeds
```

---

## Quarantine Issues

### "Failed to quarantine file"

**Problem:** Cannot move file to quarantine.

**Solution:**
```bash
# Check quarantine directory permissions
ls -la ~/.green_mold_cure/quarantine/

# Fix permissions
chmod 700 ~/.green_mold_cure/quarantine/

# Check disk space
df -h ~/.green_mold_cure/

# Quarantine may be full - empty old entries
# In-app: View Quarantine -> Empty Quarantine
```

### "Failed to restore file"

**Problem:** Cannot restore file from quarantine.

**Solution:**
- Verify quarantine file exists
- Check destination path is writable
- Try restoring to a different location
- Encrypted files require same encryption key

### Quarantine is missing files

**Problem:** Quarantined files disappeared.

**Solution:**
- Check retention settings (default 30 days)
- Old files may have been auto-cleaned
- Check quarantine log in database

---

## Platform-Specific Issues

### Linux

**AppArmor/SELinux blocking scans:**
```bash
# Check if AppArmor is blocking
sudo aa-status

# Temporarily disable for testing
sudo systemctl stop apparmor
```

**System scan limited by permissions:**
```bash
# Run with sudo for full access
sudo python3 src/main.py
```

### Windows

**Windows Defender flags quarantine operations:**
```cmd
# Add exclusion to Windows Defender
# Settings -> Update & Security -> Windows Security
# -> Virus & threat protection -> Manage settings
# -> Exclusions -> Add exclusion
# Add: %USERPROFILE%\.green_mold_cure\quarantine
```

**Path length errors (>260 characters):**
```cmd
# Enable long paths in Windows
# Run regedit and set:
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem
# LongPathsEnabled = 1
```

### macOS

**SIP (System Integrity Protection) limits:**
- Cannot scan /System, /bin, /sbin directories
- This is normal and expected
- Focus scans on /Users and /Applications

**Gatekeeper warnings:**
```bash
# If macOS blocks the application
# System Preferences -> Security & Privacy
# Click "Allow Anyway"
```

### Android (Termux)

**Storage access issues:**
```bash
# Grant storage permission
termux-setup-storage

# Access internal storage via ~/storage/shared
```

**Limited scanning scope:**
- Without root, can only scan user directories
- System partition is inaccessible
- This is a security feature, not a bug

### iOS (a-Shell/iSH)

**Highly restricted environment:**
- Only scan files within app sandbox
- Most features unavailable
- Consider using on a different platform

---

## Getting Help

### Enable verbose logging

```bash
# Run with verbose output
python3 src/main.py --verbose

# Check log files
# Linux/macOS: ~/.green_mold_cure/logs/
# Windows: %USERPROFILE%\.green_mold_cure\logs\
```

### Export diagnostic information

```bash
# In the application
# Settings -> Export Settings (redacted)

# Collect logs
tar -czf gmc_logs.tar.gz ~/.green_mold_cure/logs/
```

### Report a bug

When reporting issues, include:
1. Platform and version (Linux/Windows/macOS/Android)
2. Python version (`python3 --version`)
3. Error messages (full text)
4. Steps to reproduce
5. Log files (if applicable)

### Check for updates

```bash
# Check current version
# Application displays version on startup

# Update dependencies
pip3 install --upgrade -r requirements.txt
```

---

## Quick Reference Commands

```bash
# Installation
./scripts/install.sh          # Linux/macOS
scripts\install.bat           # Windows
bash scripts/termux_setup.sh  # Android Termux

# Running the application
python3 src/main.py           # From project directory
green-mold-cure               # After installation (if in PATH)

# Logs location
~/.green_mold_cure/logs/      # Linux/macOS
%USERPROFILE%\.green_mold_cure\logs\  # Windows

# Reset application
rm -rf ~/.green_mold_cure     # Linux/macOS (deletes all data)
```

---

**Last Updated:** February 17, 2026  
**Version:** 1.0.0
