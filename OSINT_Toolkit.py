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

def main():
    parser = argparse.ArgumentParser(description='SOC Threat Intelligence Aggregator')
    parser.add_argument('indicator', help='IP address, domain, or file hash to analyse')
    parser.add_argument('-o', '--output', help='Output results to JSON file')
    parser.add_argument('-c', '--config', default='config.json', help='Configuration file path')
    
    args = parser.parse_args()
    
    # Initialise aggregator
    aggregator = ThreatIntelAggregator(args.config)
    
    # Analyse indicator
    results = aggregator.analyse_indicator(args.indicator)
    
    # Print results
    aggregator.print_results(results)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()
