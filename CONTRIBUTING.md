# Contributing to Green Mold Cure

Thank you for your interest in contributing to Green Mold Cure! This document provides guidelines and instructions for contributing.

## 🎯 Project Overview

Green Mold Cure is an advanced open-source antivirus scanner with:
- Multi-engine threat detection
- Local AI-powered threat correlation
- Real-time protection
- Cloud integration
- Cross-platform support

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security](#security)

---

## Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone. We welcome contributors regardless of:
- Background or experience level
- Identity or expression
- Personal characteristics
- Technical preferences

### Expected Behavior

- Be respectful and inclusive
- Accept constructive criticism
- Focus on what's best for the community
- Show empathy towards others

---

## Getting Started

### 1. Fork the Repository

```bash
# Click "Fork" on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/green-mold-cure.git
cd green-mold-cure
```

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-123
```

### 3. Make Your Changes

Follow the coding standards below.

### 4. Test Your Changes

```bash
# Run tests
python3 -m pytest tests/ -v

# Check code style
python3 -m py_compile src/*.py src/**/*.py
```

### 5. Commit Your Changes

```bash
git add .
git commit -m "feat: add new feature description"
# or
git commit -m "fix: resolve issue #123"
```

### 6. Push and Create PR

```bash
git push origin feature/your-feature-name
# Then create a Pull Request on GitHub
```

---

## Development Setup

### Prerequisites

- Python 3.10 or higher
- pip package manager
- Git

### Install Dependencies

```bash
# Install all dependencies including dev tools
pip install -r requirements.txt
pip install pytest pytest-cov black flake8 mypy
```

### Optional: AI Features

```bash
# Install Ollama for AI features
curl -fsSL https://ollama.com/install.sh | sh
ollama pull phi3:mini
```

---

## Pull Request Process

### Before Submitting

1. **Ensure all tests pass**
   ```bash
   python3 -m pytest tests/ -v
   ```

2. **Check code style**
   ```bash
   python3 -m py_compile src/*.py
   ```

3. **Update documentation** if adding features

4. **Test on multiple platforms** if possible (Linux, Windows, macOS)

### PR Title Format

Use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test additions/changes
- `chore:` Maintenance tasks

### PR Description

Include:
- What changes were made
- Why the changes were made
- How to test the changes
- Any breaking changes
- Related issues

### Review Process

1. Maintainers will review within 5 business days
2. Address any feedback or requested changes
3. Once approved, PR will be merged

---

## Coding Standards

### Python Style

Follow PEP 8 guidelines:
- 4 spaces for indentation
- Maximum line length: 100 characters
- Use type hints for function signatures
- Add docstrings for public functions

### Example Function

```python
def scan_file(file_path: Path, timeout: int = 30) -> ScanResult:
    """
    Scan a file for threats.
    
    Args:
        file_path: Path to the file to scan
        timeout: Scan timeout in seconds (default: 30)
    
    Returns:
        ScanResult object with scan results
    
    Raises:
        FileNotFoundError: If file does not exist
        PermissionError: If file cannot be accessed
    """
    # Implementation here
    pass
```

### Naming Conventions

- **Variables**: `snake_case`
- **Functions**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_CASE`
- **Private**: `_leading_underscore`

### Error Handling

```python
try:
    result = scan_file(path)
except FileNotFoundError:
    logger.error(f"File not found: {path}")
    return ScanResult(status=ScanStatus.ERROR)
except Exception as e:
    logger.error(f"Scan failed: {e}")
    raise
```

---

## Testing

### Running Tests

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific test file
python3 -m pytest tests/test_scanner.py -v

# Run with coverage
python3 -m pytest tests/ --cov=src --cov-report=html
```

### Writing Tests

```python
def test_scan_clean_file(scanner, temp_file):
    """Test scanning a clean file."""
    result = scanner.scan_file(temp_file)
    
    assert result.status == ScanStatus.CLEAN
    assert result.file_hash is not None
    assert result.threat_name is None
```

### Test Coverage

Aim for:
- **Minimum**: 70% coverage
- **Target**: 85% coverage
- **Critical modules**: 90%+ coverage

---

## Documentation

### Code Comments

- Explain **why**, not **what**
- Document complex logic
- Include examples for public APIs

### README Updates

Update README.md when:
- Adding new features
- Changing installation steps
- Modifying usage instructions

### Docstrings

All public functions and classes should have docstrings:

```python
class ThreatAnalyzer:
    """
    Analyzes threats using multiple detection engines.
    
    Attributes:
        signature_db: Signature database instance
        yara_rules: Compiled YARA rules
    """
    
    def analyze(self, threat_data: Dict) -> ThreatResult:
        """
        Analyze threat data and return results.
        
        Args:
            threat_data: Dictionary containing threat information
        
        Returns:
            ThreatResult with analysis findings
        """
        pass
```

---

## Security

### Important Guidelines

1. **Never commit secrets**
   - API keys
   - Passwords
   - Private keys
   - `.env` files

2. **Validate all input**
   - Sanitize file paths
   - Check permissions
   - Validate user input

3. **Use secure defaults**
   - Encrypted quarantine
   - Secure deletion
   - Minimal permissions

### Reporting Security Issues

See [SECURITY.md](SECURITY.md) for vulnerability reporting process.

---

## Areas for Contribution

### High Priority

- [ ] Additional YARA rules
- [ ] More threat intelligence sources
- [ ] Performance optimizations
- [ ] Platform-specific improvements
- [ ] Documentation improvements

### Nice to Have

- [ ] GUI frontend
- [ ] Web interface
- [ ] Mobile app
- [ ] Additional report formats
- [ ] Plugin system

---

## Questions?

- **General questions**: Open a GitHub Discussion
- **Bug reports**: Open a GitHub Issue
- **Security issues**: See [SECURITY.md](SECURITY.md)
- **Feature requests**: Open a GitHub Issue with "enhancement" label

---

## Recognition

Contributors will be acknowledged in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for contributing to Green Mold Cure! 🎉

---

**Last Updated:** February 17, 2026  
**Version:** 4.0.1
