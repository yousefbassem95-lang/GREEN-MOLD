# 🦠 Green Mold Cure - Ultimate Edition

<div align="center">

**The World's First Open-Source Antivirus with Local AI Threat Correlation**

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-70%20passing-brightgreen.svg)](tests/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](README.md)
[![AI Powered](https://img.shields.io/badge/AI-local%20LLM-orange.svg)](README.md)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

## 🌌 Elixirs and Cures Initiative

This project, **Green Mold Cure**, is a significant contribution to the 'Elixirs and Cures' initiative.

- **Your GitHub Profile:** [Yousef Bassem](https://github.com/yousefbassem95-lang)
- **Project Repository:** [GREEN-MOLD](https://github.com/yousefbassem95-lang/GREEN-MOLD)

---

## 🌟 What Makes This Unique

| Feature | Other AV | Green Mold Cure |
|----------|----------|-----------------|
| Local AI threat correlation | ❌ | ✅ **World's First** |
| AI campaign detection | ❌ | ✅ **Exclusive** |
| AI threat actor profiling | ❌ | ✅ **Exclusive** |
| AI-generated reports | ❌ | ✅ **Exclusive** |
| 100% offline AI | ❌ | ✅ **Privacy First** |
| No API keys required | ❌ | ✅ **Free Forever** |

---

## 🚀 Features

### Core Detection (4 Engines)
- 🔍 **Signature-Based** - 77,000+ known malware hashes
- 🎯 **YARA Rules** - Pattern-based detection
- 🧠 **Heuristic Analysis** - Behavioral detection
- 🔧 **PE Analysis** - Executable inspection

### Advanced Features
- 🧬 **Process & Memory Scanning** - Detect injected code
- 🧪 **Sandbox Emulation** - Behavioral analysis
- ☁️ **Cloud Integration** - VirusTotal, MetaDefender, Hybrid Analysis
- 🤖 **AI Threat Correlation** - Local LLM-powered analysis
- 🛡️ **Real-time Protection** - File system monitoring
- 📦 **Archive Scanning** - ZIP, RAR, 7z support

---

## ⚡ Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/green-mold-cure.git
cd green-mold-cure

# Install dependencies
pip install -r requirements.txt

# Run the application
python3 run.py
```

### Optional: AI Features Setup

```bash
# Install Ollama (Linux)
curl -fsSL https://ollama.com/install.sh | sh

# Pull a lightweight AI model
ollama pull phi3:mini

# Start Ollama
ollama serve
```

### First Scan

```bash
python3 run.py

# Select option 1: Quick Scan
# Or option 2: Full System Scan (run as admin/root for best results)
```

---

## 📋 Menu Options

```
╔═══════════════════════════════════════════════════════════╗
║              GREEN MOLD CURE - ULTIMATE                   ║
╠═══════════════════════════════════════════════════════════╣
║  1. Quick Scan - Scan common malware locations            ║
║  2. Full System Scan - Comprehensive system-wide scan     ║
║  3. Process & Memory Scan - Scan running processes        ║
║  4. Sandbox Emulation - Analyze file behavior             ║
║  5. Cloud Scan - Scan with multiple cloud engines         ║
║  6. AI Threat Correlation - AI-powered analysis           ║
║  7. Real-time Protection - Background monitoring          ║
║  8. Update Database - Fetch latest signatures             ║
║  9. Quarantine - Manage quarantined files                 ║
║  10. Settings - Configure preferences                     ║
║  11. Exit - Close application                             ║
╚═══════════════════════════════════════════════════════════╝
```

---

## 🤖 AI Threat Correlation

### What It Does

The AI Threat Correlation feature uses local LLMs to:
- **Correlate threats** across multiple detections
- **Identify campaigns** and coordinated attacks
- **Profile threat actors** based on TTPs
- **Generate reports** with remediation steps
- **Map to MITRE ATT&CK** framework

### Supported Models

Lightweight models (1-3B parameters) recommended:
- **Phi-3 Mini** (3.8B) - Microsoft ⭐ Recommended
- **TinyLlama** (1.1B) - Fastest
- **StableLM2** (1.6B) - Balanced
- **Qwen2** (1.5B) - Alibaba
- **Gemma** (2B) - Google

### Usage

```bash
# In the application, select:
Option 6: AI Threat Correlation

# Then choose:
1. Analyze Specific Threat
2. Correlate Recent Detections
3. Generate AI Report
4. Change AI Model
```

---

## 🛡️ Security Features

- **Encrypted Quarantine** - AES-256 encryption
- **Secure Deletion** - DoD 5220.22-M 3-pass overwrite
- **API Key Protection** - Local storage only
- **Audit Logging** - All actions logged
- **Permission Handling** - User consent for elevation
- **No Telemetry** - Nothing leaves your machine

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Full documentation and usage guide |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute to the project |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |
| [LICENSE](LICENSE) | MIT License |
| [ENHANCED_FEATURES.md](ENHANCED_FEATURES.md) | Detailed feature documentation |
| [API_KEY_SETUP.md](API_KEY_SETUP.md) | API key configuration guide |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and solutions |

---

## 🔧 Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Cloud scanning API keys (optional)
VIRUSTOTAL_API_KEY=your_key_here
HYBRID_ANALYSIS_API_KEY=your_key_here

# Tor settings (optional)
TOR_PROXY_HOST=127.0.0.1
TOR_PROXY_PORT=9050
```

### Settings

Configure in-app via **Option 10: Settings**:
- Auto-update interval
- Max file size for scanning
- Archive scanning
- Auto-quarantine
- Exclusion patterns

---

## 🧪 Testing

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run with coverage
python3 -m pytest tests/ --cov=src --cov-report=html

# Run specific test file
python3 -m pytest tests/test_scanner.py -v
```

**Current Status:** 70 tests passing ✅

---

## 🌍 Platform Support

| Platform | Support | Notes |
|----------|---------|-------|
| **Linux** | ✅ Full | Native execution |
| **Windows** | ✅ Full | Native execution |
| **macOS** | ✅ Full | Native execution |
| **Android** | ⚠️ Partial | Via Termux |
| **iOS** | ⚠️ Partial | Via a-Shell/iSH |

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Coding standards
- Pull request process
- Testing guidelines

### Areas for Contribution

- [ ] Additional YARA rules
- [ ] More threat intelligence sources
- [ ] Performance optimizations
- [ ] Platform-specific improvements
- [ ] Documentation
- [ ] Bug fixes

---

## 📊 Project Statistics

| Metric | Count |
|--------|-------|
| **Python Files** | 42 |
| **Lines of Code** | ~11,000+ |
| **Test Cases** | 70 |
| **Detection Engines** | 4 |
| **Cloud Services** | 8+ |
| **AI Models Supported** | 5+ |

---

## 🔒 Security

### Reporting Vulnerabilities

**Please DO NOT report security vulnerabilities through public GitHub issues.**

See [SECURITY.md](SECURITY.md) for:
- How to report vulnerabilities
- Security response process
- Security best practices

### Security Features

- Encrypted quarantine vault
- Secure file deletion
- No hardcoded credentials
- Input validation
- Permission management
- Audit logging

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Additional Terms

This software is provided for educational and protective purposes only. Users are responsible for:
- Complying with all applicable laws
- Obtaining proper authorization before scanning systems
- Using this software ethically

---

## 🙏 Acknowledgments

- **ClamAV** - Signature database
- **Abuse.ch** - Threat intelligence feeds
- **VirusTotal** - Cloud scanning
- **Ollama** - Local AI infrastructure
- **Rich** - Terminal UI framework
- All open-source contributors

---

## 📞 Support

- **Bug Reports**: [GitHub Issues](https://github.com/YOUR_USERNAME/green-mold-cure/issues)
- **Discussions**: [GitHub Discussions](https://github.com/YOUR_USERNAME/green-mold-cure/discussions)
- **Security Issues**: See [SECURITY.md](SECURITY.md)
- **Documentation**: See docs folder

---

<div align="center">

**Made with ❤️ for a safer digital world**

[Report a Bug](https://github.com/YOUR_USERNAME/green-mold-cure/issues) • [Request Feature](https://github.com/YOUR_USERNAME/green-mold-cure/issues) • [Discussions](https://github.com/YOUR_USERNAME/green-mold-cure/discussions)

</div>