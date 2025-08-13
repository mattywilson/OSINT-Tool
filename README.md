# OSINT-Tool

Install Python from python.org (Make sure you tick "Add Python to Enviroment Variables")

Navigate to where you have saved this within CMD (e.g: CD C:\Users\User\Documents\OSINT-Tool)

Install the required library: (Run: pip install requests)

Run the program once via CMD with an IP (Run: python OSINT_Toolkit.py 8.8.8.8)

This will spit out an error and then provide a config.json file

Open this via notepad.

This will require API keys from:

VirusTotal: https://www.virustotal.com/

AbuseIPDB: https://www.abuseipdb.com/api.html

ThreatFox: https://auth.abuse.ch/

AlienVault: https://otx.alienvault.com/api

IPQualityScore: https://www.ipqualityscore.com/user/api-keys (Optional)

Re-run this again and this will provide results for the provided IP/Hash/Domain.

Interactive mode:

- Run: `python OSINT_Toolkit.py` (or `python OSINT_Toolkit.py --interactive`)
- Then type an IP/Hash/Domain at the `Indicator>` prompt (type `q` to quit)
- Optional: save each result to JSON by specifying an output directory: `python OSINT_Toolkit.py --interactive --output results/`
This will provide more thorough outputs.

