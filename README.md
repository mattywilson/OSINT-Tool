# CMD-OSINT-Tool

Install Python from python.org (Python 3.7+)
Navigate to this directory within CMD
Install the required library: pip install requests

Run the program once via CMD with an IP (python OSINT_Toolkit.py 47.245.61.75:53)

This will spit out an error and then provide a config.json file
Open this via notepad.

This will require API keys from:
VirusTotal: https://www.virustotal.com/
AbuseIPDB: https://www.abuseipdb.com/api.html
ThreatFox: https://auth.abuse.ch/
AlienVault: https://otx.alienvault.com/api

Re-run this again and this will spit out a result into the CMD console.

============================================================
THREAT INTELLIGENCE ANALYSIS
============================================================
Indicator: 8.8.8.8
Type: IP
Analysis Date: 2025-07-23 20:43:01 UTC
------------------------------------------------------------
RISK ASSESSMENT: LOW
RESULT: No significant threats detected across all sources

DETAILED RESULTS:
--------------------
VirusTotal: Clean - 94 engines scanned, no threats detected
AbuseIPDB: Clean - 0% abuse confidence, 121 reports, Country: US
ThreatFox: Not found in database
AlienVault OTX: Not found in any threat pulses

============================================================
