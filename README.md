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
- **Git** (optional) - For automatic updates
- **API Keys** - See [API Configuration](#-api-configuration) section

## 🔧 Installation

### 1. Clone or Download
```bash
git clone https://github.com/mattywilson/OSINT-Tool.git
cd OSINT-Tool
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
# Analyze an IP address
python OSINT_Toolkit.py 8.8.8.8

# Analyze a domain
python OSINT_Toolkit.py malicious-domain.com

# Analyze a file hash
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
- Use `--no-update` to skip Git operations if needed

## 🔄 Auto-Updates

The tool automatically checks for updates from the Git repository and restarts with the latest version. To disable:
```bash
python OSINT_Toolkit.py --no-update <indicator>
```

## 📁 File Structure

```
OSINT-Tool/
├── OSINT_Toolkit.py    # Main application
├── config.json         # API configuration (generated)
├── README.md          # This file
└── results/           # Output directory (optional)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## ⚖️ Legal Notice

This tool is for authorized security research and SOC operations only. Users are responsible for:
- Complying with API terms of service
- Following applicable laws and regulations  
- Obtaining proper authorization before analyzing systems
- Respecting rate limits and usage policies

## 📞 Support

For issues or questions:
- Check the troubleshooting section above
- Review API provider documentation
- Ensure all dependencies are properly installed

---

**Made for SOC analysts, by SOC analysts** 🛡️
