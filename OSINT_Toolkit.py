#!/usr/bin/env python3
"""
SOC OSINT Tool
A tool to query multiple threat intelligence APIs and provide a copy and pasteable result
"""

import requests
import json
import argparse
import sys
import time
from datetime import datetime
from typing import Dict, Any, Optional
import hashlib
import re
import os
import subprocess
import shutil
import tempfile
import zipfile
from urllib.parse import urlparse

# Tool version - update this when releasing new versions
TOOL_VERSION = "1.0.1"
GITHUB_REPO = "mattywilson/OSINT-Tool"
GITHUB_API_BASE = f"https://api.github.com/repos/{GITHUB_REPO}"

class ThreatIntelAggregator:
    def __init__(self, config_file: str = "config.json"):
        """Initialise the aggregator with API keys from config file"""
        self.config = self.load_config(config_file)
        self.results = {}
        
    def load_config(self, config_file: str) -> Dict[str, str]:
        """Load API configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Config file {config_file} not found. Creating template...")
            self.create_config_template(config_file)
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Invalid JSON in {config_file}")
            sys.exit(1)
    
    def create_config_template(self, config_file: str):
        """Create a template configuration file"""
        template = {
            "virustotal_api_key": "YOUR_VT_API_KEY_HERE",
            "abuseipdb_api_key": "YOUR_ABUSEIPDB_API_KEY_HERE",
            "threatfox_api_key": "YOUR_THREATFOX_API_KEY_HERE",
            "alienvault_api_key": "YOUR_ALIENVAULT_API_KEY_HERE",
            "vpnapi_key": "YOUR_VPNAPI_KEY_HERE_OPTIONAL"
        }
        with open(config_file, 'w') as f:
            json.dump(template, f, indent=4)
        print(f"Template configuration created: {config_file}")
        print("Please add your API keys and run again.")
    
    def detect_indicator_type(self, indicator: str) -> str:
        """Detect if indicator is IP, domain, or hash"""
        # Hash patterns
        md5_pattern = r'^[a-fA-F0-9]{32}$'
        sha1_pattern = r'^[a-fA-F0-9]{40}$'
        sha256_pattern = r'^[a-fA-F0-9]{64}$'
        
        if re.match(md5_pattern, indicator):
            return 'md5'
        elif re.match(sha1_pattern, indicator):
            return 'sha1'
        elif re.match(sha256_pattern, indicator):
            return 'sha256'
        
        # IPv4 pattern
        ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        if re.match(ipv4_pattern, indicator):
            return 'ipv4'
        
        # IPv6 patterns
        ipv6_full = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        ipv6_loopback = r'^::1$'
        ipv6_zero = r'^::$'
        ipv6_compressed1 = r'^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$'
        ipv6_compressed2 = r'^([0-9a-fA-F]{1,4}:)*::[0-9a-fA-F]{1,4}$'
        ipv6_compressed3 = r'^([0-9a-fA-F]{1,4}:)+::$'
        
        ipv6_patterns = [ipv6_full, ipv6_loopback, ipv6_zero, ipv6_compressed1, ipv6_compressed2, ipv6_compressed3]
        
        for pattern in ipv6_patterns:
            if re.match(pattern, indicator):
                return 'ipv6'
        
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(domain_pattern, indicator):
            return 'domain'
        
        return 'unknown'
    
    def query_virustotal(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Query VirusTotal API"""
        vt_key = self.config.get('virustotal_api_key')
        if not vt_key or vt_key == 'YOUR_VT_API_KEY_HERE':
            return {"error": "VirusTotal API key not configured"}
        
        headers = {"x-apikey": vt_key}
        
        try:
            if indicator_type == 'ipv4':
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
            elif indicator_type == 'ipv6':
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
            elif indicator_type == 'domain':
                url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
            elif indicator_type in ['md5', 'sha1', 'sha256']:
                url = f"https://www.virustotal.com/api/v3/files/{indicator}"
            else:
                return {"error": "Unsupported indicator type for VirusTotal"}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    "status": "success",
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0),
                    "reputation": data.get('data', {}).get('attributes', {}).get('reputation', 'N/A'),
                    "last_analysis_date": data.get('data', {}).get('attributes', {}).get('last_analysis_date', 'N/A')
                }
            elif response.status_code == 404:
                return {"status": "not_found", "message": "Indicator not found in VirusTotal"}
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}
    
    def query_abuseipdb(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Query AbuseIPDB API"""
        if indicator_type not in ['ipv4', 'ipv6']:
            return {"error": "AbuseIPDB only supports IP addresses"}
        
        abuse_key = self.config.get('abuseipdb_api_key')
        if not abuse_key or abuse_key == 'YOUR_ABUSEIPDB_API_KEY_HERE':
            return {"error": "AbuseIPDB API key not configured"}
        
        headers = {
            'Key': abuse_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': indicator,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        try:
            response = requests.get('https://api.abuseipdb.com/api/v2/check', 
                                  headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    "status": "success",
                    "abuse_confidence": data.get('abuseConfidencePercentage', 0),
                    "is_public": data.get('isPublic', False),
                    "is_whitelisted": data.get('isWhitelisted', False),
                    "country_code": data.get('countryCode', 'N/A'),
                    "usage_type": data.get('usageType', 'N/A'),
                    "isp": data.get('isp', 'N/A'),
                    "total_reports": data.get('totalReports', 0),
                    "last_reported": data.get('lastReportedAt', 'N/A')
                }
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}
    
    def query_threatfox(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Query ThreatFox API"""
        tf_key = self.config.get('threatfox_api_key')
        if not tf_key or tf_key == 'YOUR_THREATFOX_API_KEY_HERE':
            return {"error": "ThreatFox API key not configured. Get free key at https://auth.abuse.ch/"}
        
        try:
            data = {
                "query": "search_ioc",
                "search_term": indicator,
                "exact_match": False
            }
            
            headers = {
                'Auth-Key': tf_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.post('https://threatfox-api.abuse.ch/api/v1/', 
                                   json=data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    iocs = result.get('data', [])
                    if iocs:
                        best_match = None
                        for ioc in iocs:
                            ioc_value = ioc.get('ioc', '')
                            if ioc_value == indicator:
                                best_match = ioc
                                break
                            elif indicator_type in ['ipv4', 'ipv6'] and ioc_value.startswith(f"{indicator}:"):
                                best_match = ioc
                                break
                            elif indicator in ioc_value and not best_match:
                                best_match = ioc
                        
                        if best_match:
                            return {
                                "status": "success",
                                "ioc_found": best_match.get('ioc', indicator),
                                "threat_type": best_match.get('threat_type', 'N/A'),
                                "malware": best_match.get('malware_printable', best_match.get('malware', 'N/A')),
                                "confidence_level": best_match.get('confidence_level', 'N/A'),
                                "first_seen": best_match.get('first_seen', 'N/A'),
                                "last_seen": best_match.get('last_seen', 'N/A'),
                                "tags": best_match.get('tags', []),
                                "total_matches": len(iocs)
                            }
                        else:
                            return {"status": "not_found", "message": "No matching IOCs found in ThreatFox"}
                    else:
                        return {"status": "not_found", "message": "No IOCs found in ThreatFox"}
                elif result.get('query_status') == 'no_result':
                    return {"status": "not_found", "message": "No IOCs found in ThreatFox"}
                else:
                    return {"error": f"Query failed: {result.get('query_status')}"}
            elif response.status_code == 401:
                return {"error": "Invalid ThreatFox API key. Get free key at https://auth.abuse.ch/"}
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}
    
    def query_alienvault_otx(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Query AlienVault OTX API"""
        otx_key = self.config.get('alienvault_api_key')
        if not otx_key or otx_key == 'YOUR_ALIENVAULT_API_KEY_HERE':
            return {"error": "AlienVault OTX API key not configured"}
        
        headers = {'X-OTX-API-KEY': otx_key}
        
        try:
            if indicator_type == 'ipv4':
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
            elif indicator_type == 'ipv6':
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv6/{indicator}/general"
            elif indicator_type == 'domain':
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
            elif indicator_type in ['md5', 'sha1', 'sha256']:
                url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}/general"
            else:
                return {"error": "Unsupported indicator type for AlienVault OTX"}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "success",
                    "pulse_count": len(data.get('pulse_info', {}).get('pulses', [])),
                    "reputation": data.get('reputation', 0),
                    "first_seen": data.get('first_seen', 'N/A'),
                    "last_seen": data.get('last_seen', 'N/A')
                }
            else:
                return {"error": f"HTTP {response.status_code}: {response.text}"}
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}
    
    def check_vpn_status(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Check if IP is associated with VPN/Proxy services using multiple methods"""
        if indicator_type not in ['ipv4', 'ipv6']:
            return {"error": "VPN check only supports IP addresses"}
        
        vpn_results = {
            "is_vpn": False,
            "is_proxy": False,
            "is_tor": False,
            "vpn_provider": None,
            "confidence": "low",
            "sources_checked": []
        }
        
        # Method 1: Free IP2Location check (IPv4 only)
        if indicator_type == 'ipv4':
            try:
                url = f'https://api.ip2location.io/{indicator}?key=demo'
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    is_proxy = data.get('is_proxy', False)
                    if is_proxy:
                        vpn_results["is_proxy"] = True
                        vpn_results["confidence"] = "medium"
                    vpn_results["sources_checked"].append("IP2Location")
            except:
                pass
        
        # Method 2: IPQualityScore (supports both IPv4 and IPv6)
        vpn_key = self.config.get('vpnapi_key')
        if vpn_key and vpn_key != 'YOUR_VPNAPI_KEY_HERE_OPTIONAL':
            try:
                url = f"https://ipqualityscore.com/api/json/ip/{vpn_key}/{indicator}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('vpn'):
                        vpn_results["is_vpn"] = True
                        vpn_results["confidence"] = "high"
                    if data.get('proxy'):
                        vpn_results["is_proxy"] = True
                        vpn_results["confidence"] = "high"
                    if data.get('tor'):
                        vpn_results["is_tor"] = True
                        vpn_results["confidence"] = "high"
                    vpn_results["sources_checked"].append("IPQualityScore")
            except:
                pass
        
        # Method 3: Check AbuseIPDB data for hosting patterns
        abuse_data = self.query_abuseipdb(indicator, indicator_type)
        if abuse_data.get("status") == "success":
            usage_type = abuse_data.get("usage_type", "").lower()
            isp = abuse_data.get("isp", "").lower()
            
            vpn_keywords = ['vpn', 'proxy', 'hosting', 'cloud', 'datacentre', 'server', 'virtual']
            hosting_providers = ['amazon', 'google', 'microsoft', 'digitalocean', 'linode', 'ovh']
            
            if any(keyword in usage_type for keyword in vpn_keywords):
                vpn_results["is_vpn"] = True
                vpn_results["vpn_provider"] = abuse_data.get("isp", "Unknown")
                if vpn_results["confidence"] == "low":
                    vpn_results["confidence"] = "medium"
            
            if any(provider in isp for provider in hosting_providers):
                vpn_results["is_proxy"] = True
                vpn_results["vpn_provider"] = abuse_data.get("isp", "Unknown")
                if vpn_results["confidence"] == "low":
                    vpn_results["confidence"] = "medium"
            
            vpn_results["sources_checked"].append("AbuseIPDB_Analysis")
        
        return {
            "status": "success",
            **vpn_results
        }
    
    def analyse_indicator(self, indicator: str) -> Dict[str, Any]:
        """Analyse indicator across all configured threat intelligence sources"""
        indicator_type = self.detect_indicator_type(indicator)
        
        if indicator_type == 'unknown':
            return {"error": "Unable to determine indicator type"}
        
        print(f"Analysing {indicator_type.upper()}: {indicator}")
        
        results = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "timestamp": datetime.now().isoformat(),
            "sources": {}
        }
        
        # Query each source with rate limiting
        sources = [
            ("VirusTotal", self.query_virustotal),
            ("AbuseIPDB", self.query_abuseipdb),
            ("ThreatFox", self.query_threatfox),
            ("AlienVault OTX", self.query_alienvault_otx)
        ]
        
        # Add VPN check for IP addresses
        if indicator_type in ['ipv4', 'ipv6']:
            sources.append(("VPN_Check", self.check_vpn_status))
        
        for source_name, query_func in sources:
            print(f"Querying {source_name}...")
            try:
                result = query_func(indicator, indicator_type)
                results["sources"][source_name] = result
                time.sleep(1)
            except Exception as e:
                results["sources"][source_name] = {"error": f"Unexpected error: {str(e)}"}
        
        return results
    
    def print_results(self, results: Dict[str, Any]):
        """Print minimalistic ticket-friendly formatted results"""
        print(f"\nIndicator: {results['indicator']} ({results['indicator_type'].upper()})")
        print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        self._print_summary(results)
        
        print("\nSource Results:")
        
        for source, data in results["sources"].items():
            if "error" in data:
                print(f"  {source}: ERROR - {data['error']}")
            elif data.get("status") == "not_found":
                print(f"  {source}: Not found")
            elif data.get("status") == "success":
                self._print_source_details_simple(source, data)
            else:
                print(f"  {source}: Unknown response")
    
    def _print_source_details_simple(self, source: str, data: Dict[str, Any]):
        """Print simple, ticket-friendly results for each source"""
        if source == "VirusTotal":
            malicious = data.get('malicious', 0)
            total_engines = sum([data.get('malicious', 0), data.get('suspicious', 0), 
                               data.get('harmless', 0), data.get('undetected', 0)])
            if malicious > 0:
                print(f"  VirusTotal: MALICIOUS - {malicious}/{total_engines} engines detected threats")
            else:
                print(f"  VirusTotal: Clean - {total_engines} engines scanned")
        
        elif source == "AbuseIPDB":
            confidence = data.get('abuse_confidence', 0)
            reports = data.get('total_reports', 0)
            country = data.get('country_code', 'Unknown')
            if confidence > 25:
                print(f"  AbuseIPDB: SUSPICIOUS - {confidence}% abuse confidence, {reports} reports, {country}")
            else:
                print(f"  AbuseIPDB: Clean - {confidence}% abuse confidence, {reports} reports, {country}")
        
        elif source == "ThreatFox":
            ioc_found = data.get('ioc_found', 'N/A')
            malware = data.get('malware', 'N/A')
            threat_type = data.get('threat_type', 'N/A')
            confidence = data.get('confidence_level', 'N/A')
            if ioc_found != 'N/A':
                print(f"  ThreatFox: Found - IOC: {ioc_found}, Malware: {malware}, Type: {threat_type}")
            else:
                print(f"  ThreatFox: Found - Malware: {malware}, Type: {threat_type}")
        
        elif source == "AlienVault OTX":
            pulse_count = data.get('pulse_count', 0)
            if pulse_count > 0:
                print(f"  AlienVault OTX: Found in {pulse_count} threat pulse(s)")
            else:
                print(f"  AlienVault OTX: Clean")
        
        elif source == "VPN_Check":
            is_vpn = data.get('is_vpn', False)
            is_proxy = data.get('is_proxy', False) 
            is_tor = data.get('is_tor', False)
            confidence = data.get('confidence', 'low')
            provider = data.get('vpn_provider', '')
            
            if is_tor:
                print(f"  VPN Check: TOR EXIT NODE detected ({confidence} confidence)")
            elif is_vpn:
                provider_text = f" - {provider}" if provider else ""
                print(f"  VPN Check: VPN detected ({confidence} confidence){provider_text}")
            elif is_proxy:
                provider_text = f" - {provider}" if provider else ""
                print(f"  VPN Check: PROXY/HOSTING detected ({confidence} confidence){provider_text}")
            else:
                print(f"  VPN Check: No VPN/Proxy detected")
    
    def _print_summary(self, results: Dict[str, Any]):
        """Print concise analysis summary for tickets"""
        risk_level = "LOW"
        threats_found = []
        
        # Check VirusTotal
        vt_data = results["sources"].get("VirusTotal", {})
        if vt_data.get("status") == "success":
            malicious_count = vt_data.get("malicious", 0)
            if malicious_count > 0:
                risk_level = "HIGH" if malicious_count >= 5 else "MEDIUM"
                threats_found.append(f"{malicious_count} AV engines flagged as malicious")
        
        # Check AbuseIPDB
        abuse_data = results["sources"].get("AbuseIPDB", {})
        if abuse_data.get("status") == "success":
            confidence = abuse_data.get("abuse_confidence", 0)
            if confidence > 75:
                risk_level = "HIGH"
                threats_found.append(f"High abuse confidence ({confidence}%)")
            elif confidence > 25:
                if risk_level == "LOW":
                    risk_level = "MEDIUM"
                threats_found.append(f"Moderate abuse confidence ({confidence}%)")
        
        # Check ThreatFox
        tf_data = results["sources"].get("ThreatFox", {})
        if tf_data.get("status") == "success":
            risk_level = "HIGH"
            malware = tf_data.get('malware', 'Unknown')
            threats_found.append(f"Known IOC associated with {malware}")
        
        # Check AlienVault OTX
        otx_data = results["sources"].get("AlienVault OTX", {})
        if otx_data.get("status") == "success" and otx_data.get("pulse_count", 0) > 0:
            if risk_level == "LOW":
                risk_level = "MEDIUM"
            threats_found.append(f"Found in {otx_data['pulse_count']} threat intelligence pulse(s)")
        
        # Check VPN status
        vpn_data = results["sources"].get("VPN_Check", {})
        if vpn_data.get("status") == "success":
            if vpn_data.get("is_tor"):
                threats_found.append("TOR exit node detected")
                if risk_level == "LOW":
                    risk_level = "MEDIUM"
            elif vpn_data.get("is_vpn") or vpn_data.get("is_proxy"):
                vpn_type = "VPN" if vpn_data.get("is_vpn") else "Proxy/Hosting"
                provider = vpn_data.get("vpn_provider", "Unknown provider")
                threats_found.append(f"{vpn_type} service detected ({provider})")
        
        print(f"\nRisk Assessment: {risk_level}")
        
        if threats_found:
            print("Threats Identified:")
            for threat in threats_found:
                print(f"  - {threat}")
        else:
            print("Result: No significant threats detected")

def _run_git_command(args: list, cwd: str) -> str:
    """Run a git command and return stdout, or raise on failure."""
    completed = subprocess.run([
        "git",
        *args
    ], cwd=cwd, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"git {' '.join(args)} failed")
    return completed.stdout.strip()

def get_version_info():
    """Get current version information from various sources"""
    version_info = {
        "current_version": TOOL_VERSION,
        "source": "unknown",
        "commit_sha": None
    }
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Try to get version from git if available
    try:
        if shutil.which("git") and os.path.isdir(os.path.join(script_dir, ".git")):
            commit_sha = _run_git_command(["rev-parse", "HEAD"], cwd=script_dir)[:7]
            version_info["commit_sha"] = commit_sha
            version_info["source"] = "git"
    except Exception:
        pass
    
    # Try to get version from local version file
    version_file = os.path.join(script_dir, ".version")
    if os.path.exists(version_file):
        try:
            with open(version_file, 'r') as f:
                data = json.load(f)
                if version_info["source"] == "unknown":
                    version_info["source"] = "downloaded"
                    version_info["commit_sha"] = data.get("commit_sha", "unknown")[:7]
        except Exception:
            pass
    
    return version_info

def check_github_version():
    """Check latest version from GitHub without updating"""
    try:
        # Check latest commit on main branch
        api_url = f"{GITHUB_API_BASE}/commits/main"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            commit_data = response.json()
            latest_sha = commit_data["sha"]
            commit_date = commit_data["commit"]["committer"]["date"]
            
            return {
                "available": True,
                "latest_sha": latest_sha,
                "commit_date": commit_date,
                "short_sha": latest_sha[:7]
            }
        else:
            return {"available": False, "error": f"API returned {response.status_code}"}
            
    except Exception as e:
        return {"available": False, "error": str(e)}

def download_and_update():
    """Download latest version from GitHub and update current installation"""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Download latest ZIP
        download_url = f"https://github.com/{GITHUB_REPO}/archive/refs/heads/main.zip"
        print("Downloading latest version...")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = os.path.join(temp_dir, "update.zip")
            
            # Download ZIP file
            response = requests.get(download_url, timeout=30)
            response.raise_for_status()
            
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            
            # Extract ZIP
            extract_dir = os.path.join(temp_dir, "extracted")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Find the extracted folder (usually OSINT-Tool-main)
            extracted_folders = [d for d in os.listdir(extract_dir) 
                               if os.path.isdir(os.path.join(extract_dir, d))]
            
            if not extracted_folders:
                raise Exception("No folders found in downloaded ZIP")
            
            source_dir = os.path.join(extract_dir, extracted_folders[0])
            
            # Get latest commit info for version tracking
            github_info = check_github_version()
            
            # Backup current script
            current_script = os.path.abspath(__file__)
            backup_script = current_script + ".backup"
            shutil.copy2(current_script, backup_script)
            
            try:
                # Copy main script file
                new_script = os.path.join(source_dir, "OSINT_Toolkit.py")
                if os.path.exists(new_script):
                    shutil.copy2(new_script, current_script)
                else:
                    # Try alternative names
                    possible_names = ["osint_tool.py", "main.py", "tool.py"]
                    found = False
                    for name in possible_names:
                        alt_script = os.path.join(source_dir, name)
                        if os.path.exists(alt_script):
                            shutil.copy2(alt_script, current_script)
                            found = True
                            break
                    if not found:
                        raise Exception("Could not find main script file in download")
                
                # Copy other important files (preserve config.json)
                important_files = ["README.md", "requirements.txt", "LICENSE"]
                for file_name in important_files:
                    src_file = os.path.join(source_dir, file_name)
                    dst_file = os.path.join(script_dir, file_name)
                    if os.path.exists(src_file):
                        shutil.copy2(src_file, dst_file)
                
                # Save version information
                if github_info.get("available"):
                    version_data = {
                        "version": TOOL_VERSION,
                        "commit_sha": github_info["latest_sha"],
                        "update_date": datetime.now().isoformat(),
                        "source": "github_download"
                    }
                    version_file = os.path.join(script_dir, ".version")
                    with open(version_file, 'w') as f:
                        json.dump(version_data, f, indent=2)
                
                # Remove backup on success
                if os.path.exists(backup_script):
                    os.remove(backup_script)
                
                return True
                
            except Exception as e:
                # Restore backup on failure
                if os.path.exists(backup_script):
                    shutil.copy2(backup_script, current_script)
                    os.remove(backup_script)
                raise e
                
    except Exception as e:
        print(f"Download update failed: {e}")
        return False

def git_auto_update(script_dir: str) -> bool:
    """Original git-based auto-update functionality"""
    try:
        # Ensure git is available
        if not shutil.which("git"):
            return False
            
        git_dir = os.path.join(script_dir, ".git")
        if not os.path.isdir(git_dir):
            return False

        # Identify branch
        branch = _run_git_command(["rev-parse", "--abbrev-ref", "HEAD"], cwd=script_dir)
        if branch == "HEAD":
            # Detached HEAD; try to resolve remote HEAD branch
            try:
                branch = _run_git_command(["symbolic-ref", "refs/remotes/origin/HEAD"], cwd=script_dir)
                if branch.startswith("refs/remotes/origin/"):
                    branch = branch.split("/")[-1]
            except Exception:
                # Fallback to main
                branch = "main"

        # Fetch latest from origin
        _run_git_command(["fetch", "origin", branch], cwd=script_dir)

        # Compare commit positions
        ahead_behind = _run_git_command(["rev-list", "--left-right", "--count", f"HEAD...origin/{branch}"], cwd=script_dir)
        parts = ahead_behind.split()
        if len(parts) == 2:
            ahead_count = int(parts[0])
            behind_count = int(parts[1])
        else:
            ahead_count = behind_count = 0

        if behind_count > 0:
            print(f"Update available: pulling latest changes from origin/{branch}...")
            # Attempt fast-forward only to avoid merge commits
            try:
                _run_git_command(["pull", "--ff-only", "origin", branch], cwd=script_dir)
            except Exception:
                # Fallback to hard reset if necessary
                _run_git_command(["fetch", "origin", branch], cwd=script_dir)
                _run_git_command(["reset", "--hard", f"origin/{branch}"], cwd=script_dir)
            
            print("Update applied via git. Restarting with latest code...\n")
            return True
            
    except Exception as e:
        print(f"Git update failed: {e}")
        return False
    
    return False

def maybe_auto_update(disable_update: bool = False):
    """Hybrid auto-update: try git first, fallback to GitHub download"""
    if disable_update or os.environ.get("OSINT_TOOLKIT_UPDATED") == "1":
        return
    
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        updated = False
        
        # Method 1: Try git update first (for developers/cloned repos)
        if git_auto_update(script_dir):
            updated = True
        else:
            # Method 2: Try GitHub API update (for downloaded versions)
            current_version = get_version_info()
            github_version = check_github_version()
            
            if github_version.get("available"):
                current_sha = current_version.get("commit_sha", "unknown")
                latest_sha = github_version.get("short_sha", "unknown")
                
                # Check if update is needed
                if current_sha != "unknown" and latest_sha != "unknown" and current_sha != latest_sha:
                    print(f"Update available: {current_sha} -> {latest_sha}")
                    print("Downloading latest version from GitHub...")
                    
                    if download_and_update():
                        print("Update applied via GitHub download. Restarting with latest code...\n")
                        updated = True
                    else:
                        print("GitHub download update failed. Continuing with current version.")
                elif current_sha == "unknown":
                    # First run or no version info available
                    print("Version check: saving current version info...")
                    version_data = {
                        "version": TOOL_VERSION,
                        "commit_sha": github_version.get("latest_sha", "unknown"),
                        "install_date": datetime.now().isoformat(),
                        "source": "unknown"
                    }
                    version_file = os.path.join(script_dir, ".version")
                    with open(version_file, 'w') as f:
                        json.dump(version_data, f, indent=2)
            else:
                # Fallback: simple version check and notification
                print("Unable to check for updates automatically.")
                if not disable_update:
                    print(f"Current version: {TOOL_VERSION}")
                    print(f"Check for updates at: https://github.com/{GITHUB_REPO}")
        
        # Restart if updated
        if updated:
            os.environ["OSINT_TOOLKIT_UPDATED"] = "1"
            os.execv(sys.executable, [sys.executable, os.path.abspath(__file__), *sys.argv[1:]])
            
    except Exception as e:
        # Non-fatal; continue running
        print(f"Update check failed: {e}")

def show_version_info():
    """Display current version information"""
    version_info = get_version_info()
    print(f"SOC OSINT Tool v{version_info['current_version']}")
    print(f"Source: {version_info['source']}")
    if version_info['commit_sha']:
        print(f"Commit: {version_info['commit_sha']}")
    print(f"Repository: https://github.com/{GITHUB_REPO}")

def main():
    parser = argparse.ArgumentParser(description='SOC Threat Intelligence Aggregator')
    parser.add_argument('indicator', nargs='?', help='IP address, domain, or file hash to analyse')
    parser.add_argument('-o', '--output', help='Output results to JSON file (single run), or directory in interactive mode')
    parser.add_argument('-c', '--config', default='config.json', help='Configuration file path')
    parser.add_argument('-i', '--interactive', action='store_true', help='Start in interactive mode')
    parser.add_argument('--no-update', action='store_true', help='Disable automatic update check at startup')
    parser.add_argument('--version', action='store_true', help='Show version information and exit')
    parser.add_argument('--check-update', action='store_true', help='Check for updates without applying them')
    
    args = parser.parse_args()

    # Handle version display
    if args.version:
        show_version_info()
        return

    # Handle update check
    if args.check_update:
        current_version = get_version_info()
        github_version = check_github_version()
        
        print(f"Current version: {current_version['current_version']}")
        print(f"Current commit: {current_version.get('commit_sha', 'unknown')}")
        print(f"Source: {current_version['source']}")
        
        if github_version.get("available"):
            latest_sha = github_version.get("short_sha", "unknown")
            current_sha = current_version.get("commit_sha", "unknown")
            
            if current_sha != latest_sha:
                print(f"Latest commit: {latest_sha}")
                print("Update available!")
                print(f"Download from: https://github.com/{GITHUB_REPO}")
            else:
                print("You are running the latest version.")
        else:
            print(f"Unable to check for updates: {github_version.get('error', 'Unknown error')}")
        return

    # Auto-update (non-fatal) before performing any work
    maybe_auto_update(disable_update=args.no_update)
    
    # Initialise aggregator
    aggregator = ThreatIntelAggregator(args.config)
    
    # Interactive mode if requested or no indicator supplied
    if args.interactive or not args.indicator:
        print(f"\nSOC OSINT Tool v{TOOL_VERSION}")
        print("Interactive mode. Enter an IP, domain, or file hash to analyse. Type 'q' to quit.")
        if args.output:
            # Ensure output is treated as a directory in interactive mode
            if not os.path.isdir(args.output):
                os.makedirs(args.output, exist_ok=True)
            print(f"Results will be saved to directory: {args.output}")
        
        while True:
            try:
                user_input = input("\nIndicator> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting.")
                break
            
            if not user_input:
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                break
            
            # Handle special commands
            if user_input.lower() in ('version', '--version'):
                show_version_info()
                continue
                
            if user_input.lower() in ('help', '--help', '?'):
                print("\nCommands:")
                print("  <indicator>  - Analyse IP, domain, or file hash")
                print("  version      - Show version information")
                print("  help         - Show this help")
                print("  q, quit, exit - Quit the program")
                continue
            
            # Analyse indicator
            results = aggregator.analyse_indicator(user_input)
            
            # Handle errors gracefully in interactive mode
            if isinstance(results, dict) and results.get("error"):
                print(f"Error: {results['error']}")
                continue
            
            # Print results
            aggregator.print_results(results)
            
            # Save per-indicator if requested
            if args.output:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                safe_indicator = re.sub(r'[^A-Za-z0-9._-]+', '_', user_input)
                filepath = os.path.join(args.output, f"{safe_indicator}_{timestamp}.json")
                with open(filepath, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\nResults saved to {filepath}")
        return
    
    # One-shot mode
    # Analyse indicator
    results = aggregator.analyse_indicator(args.indicator)
    
    # Exit gracefully on error in one-shot mode
    if isinstance(results, dict) and results.get("error"):
        print(f"Error: {results['error']}")
        sys.exit(2)
    
    # Print results
    aggregator.print_results(results)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()

