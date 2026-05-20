# API Key Setup Guide

This guide explains how to obtain and configure API keys for enhanced threat intelligence in Green Mold Cure.

---

## Table of Contents

1. [VirusTotal](#virustotal)
2. [Hybrid Analysis](#hybrid-analysis)
3. [Any.run](#anyrun)
4. [AlienVault OTX](#alienvault-otx)
5. [Configuring API Keys](#configuring-api-keys)

---

## VirusTotal

### What is VirusTotal?

VirusTotal is a free online service that analyzes files and URLs for malware using multiple antivirus engines.

### Getting an API Key

1. **Create an account:**
   - Visit https://www.virustotal.com/
   - Click "Sign Up" and create an account

2. **Get API key:**
   - Log in to your account
   - Go to https://www.virustotal.com/gui/my-apikey
   - Copy your API key

3. **Rate limits (Free tier):**
   - 500 requests per day
   - 4 requests per minute

4. **Premium features:**
   - Higher rate limits
   - Advanced search (Intelligence API)
   - Retrohunt capabilities

### When to use VirusTotal

- Verify suspicious files
- Get detailed malware analysis
- Check file reputation

---

## Hybrid Analysis

### What is Hybrid Analysis?

Hybrid Analysis is a free malware analysis service that uses sandbox technology to analyze files.

### Getting an API Key

1. **Create an account:**
   - Visit https://www.hybrid-analysis.com/
   - Click "Sign Up" and register

2. **Get API key:**
   - Log in to your account
   - Go to Account Settings
   - Find the API section
   - Generate/copy your API key

3. **Rate limits:**
   - Free tier: Limited requests per hour
   - Paid tiers available for higher limits

### When to use Hybrid Analysis

- Get behavioral analysis reports
- Check file sandbox results
- Access malware configuration details

---

## Any.run

### What is Any.run?

Any.run is an interactive malware sandbox that allows you to run suspicious files in a virtual environment.

### Getting an API Key

1. **Create an account:**
   - Visit https://any.run/
   - Sign up for a free account

2. **Get API key:**
   - Log in to your account
   - Go to Settings -> API
   - Generate an API token

3. **Rate limits:**
   - Free tier: Limited submissions
   - Subscription required for full API access

### When to use Any.run

- Interactive malware analysis
- Get IOCs from malware behavior
- Check network activity of suspicious files

---

## AlienVault OTX

### What is AlienVault OTX?

Open Threat Exchange (OTX) is a community-driven threat intelligence platform with millions of threat indicators.

### Getting an API Key

1. **Create an account:**
   - Visit https://otx.alienvault.com/
   - Click "Sign Up" and register

2. **Get API key:**
   - Log in to your account
   - Go to Account -> Settings
   - Find the API Key section
   - Copy your key

3. **Rate limits:**
   - Free tier: Reasonable limits for personal use
   - No credit card required

### When to use AlienVault OTX

- Get community-sourced threat indicators
- Access pulse-based threat intelligence
- Check IPs, domains, and file hashes

---

## Configuring API Keys

### Method 1: Using .env file

1. **Create/edit `.env` file in project root:**

```bash
# Copy the template if it doesn't exist
cp .env.example .env

# Edit the file
nano .env  # or use your preferred editor
```

2. **Add your API keys:**

```bash
# VirusTotal API Key
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# Hybrid Analysis API Key
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_key_here

# Any.run API Key
ANYRUN_API_KEY=your_anyrun_key_here

# AlienVault OTX API Key
ALIENVAULT_API_KEY=your_alienvault_key_here
```

3. **Save the file**

### Method 2: Using the application

1. **Start Green Mold Cure:**
   ```bash
   python3 src/main.py
   ```

2. **Navigate to Settings:**
   - Select option `7` (Settings)
   - Select option `1` (Configure API Keys)

3. **Enter your API keys:**
   - Follow the prompts for each service
   - Leave blank to clear a key

4. **Save settings**

### Method 3: Environment variables

Set environment variables before running:

```bash
# Linux/macOS
export VIRUSTOTAL_API_KEY="your_key_here"
export HYBRID_ANALYSIS_API_KEY="your_key_here"
python3 src/main.py

# Windows (PowerShell)
$env:VIRUSTOTAL_API_KEY="your_key_here"
$env:HYBRID_ANALYSIS_API_KEY="your_key_here"
python src\main.py
```

---

## Verifying API Keys

### Test if API keys are working

1. **Start the application**
2. **Go to Update Threat Database (Option 4)**
3. **Check for errors:**
   - Success: Signatures are fetched
   - Error: "API key invalid" or "Authentication failed"

### Troubleshooting API Keys

**"API key not configured":**
- Verify key is set in `.env` or environment
- Restart the application after adding keys

**"Authentication failed":**
- Check if API key is copied correctly (no extra spaces)
- Verify account is active
- Check if API access is enabled for your account

**"Rate limit exceeded":**
- Wait before retrying
- Consider upgrading to paid tier
- Reduce update frequency in settings

---

## Security Best Practices

### Protecting your API keys

1. **Never share your API keys:**
   - Don't commit `.env` to version control
   - Don't post keys in public forums
   - Don't share screenshots with keys visible

2. **Use separate keys for different purposes:**
   - Development key for testing
   - Production key for actual use

3. **Rotate keys periodically:**
   - Regenerate keys every few months
   - Immediately if you suspect compromise

4. **Monitor usage:**
   - Check API dashboards for unusual activity
   - Set up alerts for high usage

### .gitignore configuration

Ensure `.env` is in your `.gitignore`:

```bash
# .gitignore
.env
.env.local
.env.*.local
```

---

## Free vs Paid Tiers

| Service | Free Tier | Paid Tier |
|---------|-----------|-----------|
| VirusTotal | 500/day, 4/min | Unlimited, faster |
| Hybrid Analysis | Limited | Higher limits, priority |
| Any.run | Limited submissions | Full API access |
| AlienVault OTX | Full access | Enterprise features |

---

## Additional Resources

- **VirusTotal API Docs:** https://developers.virustotal.com/reference
- **Hybrid Analysis API:** https://www.hybrid-analysis.com/documentation
- **Any.run API:** https://any.run/api-documentation
- **AlienVault OTX API:** https://otx.alienvault.com/api

---

**Last Updated:** February 17, 2026  
**Version:** 4.0.1
