# SOC OSINT Threat Intelligence Tool

A comprehensive command-line threat intelligence aggregator that queries multiple security APIs to provide actionable intelligence for SOC analysts and security researchers.

## 🚀 Features

- **Multi-Source Intelligence**: Aggregates data from VirusTotal, AbuseIPDB, ThreatFox, AlienVault OTX, and VPN detection services
- **Universal Indicator Support**: Analyses IP addresses (IPv4/IPv6), domains, and file hashes (MD5, SHA1, SHA256)
- **Risk Assessment**: Provides clear LOW/MEDIUM/HIGH risk ratings with threat summaries
- **Interactive Mode**: Continuous analysis workflow for multiple indicators
- **Auto-Updates**: Automatically pulls latest updates from Git repository
- **Export Options**: Save results to JSON files for documentation and reporting
- **VPN/Proxy Detection**: Identifies anonymisation services and hosting providers
- **SOC-Friendly Output**: Formatted for easy copy-paste into security tickets

## 📋 Prerequisites

- **Python 3.7+** - [Download from python.org](https://python.org)
  - ⚠️ **Important**: Tick "Add Python to Environment Variables" during installation
- **Git** (optional) - Enhanced auto-updates for cloned repositories - [Download from git-scm.com](https://git-scm.com/)
- **API Keys** - See [API Configuration](#-api-configuration) section
- **⚠️ Path Requirement**: Install in a directory path **without spaces** (e.g., `OSINT-Tool`, not `OSINT Tool`)

## 🔧 Installation

### 1. Clone or Download
```bash
# Option 1: Clone with Git (recommended for auto-updates)
git clone https://github.com/mattywilson/OSINT-Tool.git
cd OSINT-Tool

# Option 2: Download ZIP (also supports auto-updates)
# Download from: https://github.com/mattywilson/OSINT-Tool/archive/refs/heads/main.zip
# Extract to a folder WITHOUT spaces in the path (e.g., OSINT-Tool, not "OSINT Tool")
```

### 2. Install Dependencies
```bash
pip install requests
```

### 3. Initial Setup
Run the tool once to generate the configuration template:
```bash
python OSINT_Toolkit.py 8.8.8.8
```
This will create a `config.json` file and show an error message asking you to configure API keys.

## 🔑 API Configuration

Edit the generated `config.json` file with your API keys:

```json
{
    "virustotal_api_key": "your_vt_api_key_here",
    "abuseipdb_api_key": "your_abuseipdb_api_key_here", 
    "threatfox_api_key": "your_threatfox_api_key_here",
    "alienvault_api_key": "your_alienvault_api_key_here",
    "vpnapi_key": "your_ipqualityscore_key_here"
}
```

### Free API Key Sources

| Service | Required | URL | Notes |
|---------|----------|-----|--------|
| **VirusTotal** | ✅ Yes | [virustotal.com](https://www.virustotal.com/) | Free tier: 1,000 requests/day |
| **AbuseIPDB** | ✅ Yes | [abuseipdb.com/api](https://www.abuseipdb.com/api.html) | Free tier: 1,000 requests/day |
| **ThreatFox** | ✅ Yes | [abuse.ch](https://auth.abuse.ch/) | **Completely Free** |
| **AlienVault OTX** | ✅ Yes | [otx.alienvault.com](https://otx.alienvault.com/api) | Free with registration |
| **IPQualityScore** | ⚪ Optional | [ipqualityscore.com](https://www.ipqualityscore.com/user/api-keys) | Enhanced VPN detection |

## 🎯 Usage

### Quick Analysis (Single Indicator)
```bash
# Analyse an IP address
python OSINT_Toolkit.py 8.8.8.8

# Analyse a domain
python OSINT_Toolkit.py malicious-domain.com

# Analyse a file hash
python OSINT_Toolkit.py 5d41402abc4b2a76b9719d911017c592

# Save results to JSON
python OSINT_Toolkit.py 8.8.8.8 --output results.json
```

### Interactive Mode
```bash
# Start interactive session
python OSINT_Toolkit.py --interactive

# Interactive with auto-save to directory
python OSINT_Toolkit.py --interactive --output results/
```

In interactive mode:
- Enter indicators at the `Indicator>` prompt
- Type `q`, `quit`, or `exit` to stop
- Use Ctrl+C to exit immediately

### Advanced Options
```bash
# Use custom config file
python OSINT_Toolkit.py 8.8.8.8 --config my_config.json

# Disable automatic updates
python OSINT_Toolkit.py 8.8.8.8 --no-update

# Check current version
python OSINT_Toolkit.py --version

# Check for updates without applying them
python OSINT_Toolkit.py --check-update

# Get help
python OSINT_Toolkit.py --help
```

## 📊 Sample Output

```
Indicator: 203.0.113.42 (IPV4)
Analysis Date: 2024-08-14 15:30:45 UTC

Risk Assessment: MEDIUM

Threats Identified:
  - Moderate abuse confidence (45%)
  - VPN service detected (NordVPN)

Source Results:
  VirusTotal: Clean - 84 engines scanned
  AbuseIPDB: SUSPICIOUS - 45% abuse confidence, 12 reports, US
  ThreatFox: Not found
  AlienVault OTX: Clean
  VPN Check: VPN detected (medium confidence) - NordVPN
```

## 🔍 Supported Indicators

| Type | Examples | Sources |
|------|----------|---------|
| **IPv4** | `192.168.1.1`, `8.8.8.8` | All sources + VPN detection |
| **IPv6** | `2001:db8::1`, `::1` | All sources + VPN detection |
| **Domains** | `example.com`, `malware.net` | VirusTotal, ThreatFox, AlienVault |
| **File Hashes** | MD5, SHA1, SHA256 | VirusTotal, ThreatFox, AlienVault |

## 🎯 Risk Assessment

The tool provides automated risk scoring:

- **🟢 LOW**: No significant threats detected
- **🟡 MEDIUM**: Some suspicious indicators (VPN, moderate abuse reports, threat intelligence mentions)
- **🔴 HIGH**: Clear malicious indicators (multiple AV detections, high abuse confidence, known IOCs)

## 🛠️ Troubleshooting

### Common Issues

**"Path-related errors during update"**
```bash
# Problem: Directory path contains spaces (e.g., "OSINT Tool")
# Solution: Rename directory to remove spaces
mv "OSINT Tool" "OSINT-Tool"
cd OSINT-Tool
python OSINT_Toolkit.py
```

**"Config file not found"**
```bash
# Solution: Run once to generate template
python OSINT_Toolkit.py 8.8.8.8
```

**"API key not configured"**
- Edit `config.json` with valid API keys
- Ensure keys are within quotes: `"your_key_here"`

**"Request failed" errors**
- Check internet connection
- Verify API keys are valid and not expired
- Some free tiers have rate limits - wait and retry

**"Unable to determine indicator type"**
- Verify indicator format (IP, domain, or hash)
- Remove any extra characters or spaces

### Rate Limiting
- Free API tiers have request limits
- Tool includes 1-second delays between requests
- Use `--no-update` to skip update checks if needed
- GitHub API has rate limits for version checking (60 requests/hour for unauthenticated users)

## 🔄 Auto-Updates

The tool features a **hybrid auto-update system** that works with both Git clones and ZIP downloads:

### Update Methods
- **Git Method** (preferred): For cloned repositories - uses `git pull`
- **GitHub Download Method**: For ZIP downloads - downloads latest version from GitHub API
- **Automatic Detection**: Tool automatically chooses the best method

### Requirements for Auto-Updates
- Internet connection
- **Path without spaces** (e.g., `C:\OSINT-Tool\`, not `C:\OSINT Tool\`)
- For Git method: Git installed and repository cloned
- For GitHub method: None (works with simple ZIP download)

### Update Commands
```bash
# Check current version and commit
python OSINT_Toolkit.py --version

# Check for updates without applying
python OSINT_Toolkit.py --check-update

# Disable auto-update for single run
python OSINT_Toolkit.py --no-update <indicator>

# Manual update (Git users)
git pull origin main
```

### Interactive Mode Commands
```
Indicator> version    # Show version information
Indicator> help       # Show available commands
Indicator> quit       # Exit the program
```

**🚨 Important**: If you get path-related errors during auto-update, ensure your installation directory contains **no spaces** in the path.

## 📁 File Structure

```
OSINT-Tool/
├── OSINT_Toolkit.py    # Main application
├── config.json         # API configuration (generated)
├── .version           # Version tracking (auto-generated)
├── README.md          # This file
└── results/           # Output directory (optional)
```
