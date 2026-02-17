# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 4.0.x   | :white_check_mark: |
| 3.0.x   | :x:                |
| < 3.0   | :x:                |

## Reporting a Vulnerability

We take the security of Green Mold Cure seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via:
- **GitHub Security Advisories**: Use the "Report a vulnerability" feature
- **Email**: security@greenmoldcure.local (placeholder - update when publishing)

### What to Include

Please include the following information:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)
- Your contact information for follow-up

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution Target**: Within 30 days for critical issues

### Security Best Practices for Users

1. **API Keys**: Never commit API keys or credentials to version control
2. **Environment Variables**: Use `.env` files for sensitive configuration
3. **Quarantine**: Quarantined files are encrypted and isolated
4. **Permissions**: Run with minimum required privileges
5. **Updates**: Keep the software updated for latest security patches

## Security Features

### Built-in Protections

- **Encrypted Quarantine**: AES-256 encryption for quarantined files
- **Secure Deletion**: DoD 5220.22-M 3-pass overwrite
- **API Key Protection**: Keys stored locally, never transmitted
- **Audit Logging**: All security events logged
- **Permission Handling**: User consent for elevated access

### AI Security

- **100% Local Processing**: No data leaves your machine
- **No Telemetry**: Nothing is phoned home
- **Offline Capable**: Works without internet connection

## Known Limitations

- Real-time protection requires elevated privileges for full system access
- Some file types may be inaccessible without administrator/root permissions
- Cloud scanning requires API keys from respective services

## Security Research

We welcome responsible security research. If you're conducting research on Green Mold Cure:

1. Notify us before beginning testing
2. Avoid testing on production systems
3. Provide detailed reports of findings
4. Allow reasonable time for remediation before public disclosure

## Recognition

We acknowledge and appreciate security researchers who help improve our security. Contributors will be credited (with permission) in our security acknowledgments.

---

**Last Updated:** February 17, 2026  
**Version:** 4.0.1
