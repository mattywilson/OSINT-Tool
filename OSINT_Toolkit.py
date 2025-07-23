#!/usr/bin/env python3
"""
SOC Threat Intelligence Aggregator
A tool to query multiple threat intelligence APIs and provide structured results
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
        """Initialize the aggregator with API keys from config file"""
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
            "alienvault_api_key": "YOUR_ALIENVAULT_API_KEY_HERE"
        }
        with open(config_file, 'w') as f:
            json.dump(template, f, indent=4)
        print(f"Template configuration created: {config_file}")
        print("Please add your API keys and run again.")
    
    def detect_indicator_type(self, indicator: str) -> str:
        """Detect if indicator is IP, domain, or hash"""
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):
            return 'md5'
        elif re.match(r'^[a-fA-F0-9]{40}$', indicator):
            return 'sha1'
        elif re.match(r'^[a-fA-F0-9]{64}$', indicator):
            return 'sha256'
        
        # IP pattern
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', indicator):
            return 'ip'
        
        # Domain pattern (basic)
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', indicator):
            return 'domain'
        
        return 'unknown'
    
    def query_virustotal(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Query VirusTotal API"""
        if not self.config.get('virustotal_api_key') or self.config['virustotal_api_key'] == 'YOUR_VT_API_KEY_HERE':
            return {"error": "VirusTotal API key not configured"}
        
        headers = {"x-apikey": self.config['virustotal_api_key']}
        
        try:
            if indicator_type == 'ip':
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
        if indicator_type != 'ip':
            return {"error": "AbuseIPDB only supports IP addresses"}
        
        if not self.config.get('abuseipdb_api_key') or self.config['abuseipdb_api_key'] == 'YOUR_ABUSEIPDB_API_KEY_HERE':
            return {"error": "AbuseIPDB API key not configured"}
        
        headers = {
            'Key': self.config['abuseipdb_api_key'],
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
        if not self.config.get('threatfox_api_key') or self.config['threatfox_api_key'] == 'YOUR_THREATFOX_API_KEY_HERE':
            return {"error": "ThreatFox API key not configured. Get free key at https://auth.abuse.ch/"}
        
        try:
            data = {
                "query": "search_ioc",
                "search_term": indicator,
                "exact_match": False  # Use wildcard search to find IPs with ports
            }
            
            headers = {
                'Auth-Key': self.config['threatfox_api_key'],
                'Content-Type': 'application/json'
            }
            
            response = requests.post('https://threatfox-api.abuse.ch/api/v1/', 
                                   json=data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    iocs = result.get('data', [])
                    if iocs:
                        # Find the best match - prioritize exact matches, then partial matches
                        best_match = None
                        for ioc in iocs:
                            ioc_value = ioc.get('ioc', '')
                            # Exact match (for domains/hashes)
                            if ioc_value == indicator:
                                best_match = ioc
                                break
                            # IP with port match (for IPs)
                            elif indicator_type == 'ip' and ioc_value.startswith(f"{indicator}:"):
                                best_match = ioc
                                break
                            # Partial match as fallback
                            elif indicator in ioc_value and not best_match:
                                best_match = ioc
                        
                        if best_match:
                            return {
                                "status": "success",
                                "ioc_found": best_match.get('ioc', indicator),  # Show actual IOC found
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
        if not self.config.get('alienvault_api_key') or self.config['alienvault_api_key'] == 'YOUR_ALIENVAULT_API_KEY_HERE':
            return {"error": "AlienVault OTX API key not configured"}
        
        headers = {'X-OTX-API-KEY': self.config['alienvault_api_key']}
        
        try:
            if indicator_type == 'ip':
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
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
    
    def analyze_indicator(self, indicator: str) -> Dict[str, Any]:
        """Analyze indicator across all configured threat intelligence sources"""
        indicator_type = self.detect_indicator_type(indicator)
        
        if indicator_type == 'unknown':
            return {"error": "Unable to determine indicator type"}
        
        print(f"Analyzing {indicator_type.upper()}: {indicator}")
        print("=" * 60)
        
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
        
        for source_name, query_func in sources:
            print(f"Querying {source_name}...")
            try:
                result = query_func(indicator, indicator_type)
                results["sources"][source_name] = result
                time.sleep(1)  # Rate limiting
            except Exception as e:
                results["sources"][source_name] = {"error": f"Unexpected error: {str(e)}"}
        
        return results
    
    def print_results(self, results: Dict[str, Any]):
        """Print ticket-friendly formatted results"""
        print("\n" + "=" * 60)
        print("THREAT INTELLIGENCE ANALYSIS")
        print("=" * 60)
        print(f"Indicator: {results['indicator']}")
        print(f"Type: {results['indicator_type'].upper()}")
        print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print("-" * 60)
        
        # Summary first for quick reference
        self._print_summary(results)
        
        print("\nDETAILED RESULTS:")
        print("-" * 20)
        
        for source, data in results["sources"].items():
            if "error" in data:
                print(f"{source}: ERROR - {data['error']}")
            elif data.get("status") == "not_found":
                print(f"{source}: Not found in database")
            elif data.get("status") == "success":
                self._print_source_details_simple(source, data)
            else:
                print(f"{source}: Unknown response")
        
        print("\n" + "=" * 60)
    
    def _print_source_details_simple(self, source: str, data: Dict[str, Any]):
        """Print simple, ticket-friendly results for each source"""
        if source == "VirusTotal":
            malicious = data.get('malicious', 0)
            total_engines = sum([data.get('malicious', 0), data.get('suspicious', 0), 
                               data.get('harmless', 0), data.get('undetected', 0)])
            if malicious > 0:
                print(f"VirusTotal: MALICIOUS - {malicious}/{total_engines} engines detected threats")
            else:
                print(f"VirusTotal: Clean - {total_engines} engines scanned, no threats detected")
        
        elif source == "AbuseIPDB":
            confidence = data.get('abuse_confidence', 0)
            reports = data.get('total_reports', 0)
            country = data.get('country_code', 'Unknown')
            if confidence > 25:
                print(f"AbuseIPDB: SUSPICIOUS - {confidence}% abuse confidence, {reports} reports, Country: {country}")
            else:
                print(f"AbuseIPDB: Clean - {confidence}% abuse confidence, {reports} reports, Country: {country}")
        
        elif source == "ThreatFox":
            ioc_found = data.get('ioc_found', 'N/A')
            malware = data.get('malware', 'N/A')
            threat_type = data.get('threat_type', 'N/A')
            confidence = data.get('confidence_level', 'N/A')
            if ioc_found != 'N/A':
                print(f"ThreatFox: Found - IOC: {ioc_found}, Malware: {malware}, Type: {threat_type}, Confidence: {confidence}")
            else:
                print(f"ThreatFox: Found - Malware: {malware}, Type: {threat_type}, Confidence: {confidence}")
        
        elif source == "AlienVault OTX":
            pulse_count = data.get('pulse_count', 0)
            if pulse_count > 0:
                print(f"AlienVault OTX: Found in {pulse_count} threat pulse(s)")
            else:
                print(f"AlienVault OTX: Not found in any threat pulses")
    
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
        
        print(f"RISK ASSESSMENT: {risk_level}")
        
        if threats_found:
            print("THREATS IDENTIFIED:")
            for threat in threats_found:
                print(f"- {threat}")
        else:
            print("RESULT: No significant threats detected across all sources")

def main():
    parser = argparse.ArgumentParser(description='SOC Threat Intelligence Aggregator')
    parser.add_argument('indicator', help='IP address, domain, or file hash to analyze')
    parser.add_argument('-o', '--output', help='Output results to JSON file')
    parser.add_argument('-c', '--config', default='config.json', help='Configuration file path')
    
    args = parser.parse_args()
    
    # Initialize aggregator
    aggregator = ThreatIntelAggregator(args.config)
    
    # Analyze indicator
    results = aggregator.analyze_indicator(args.indicator)
    
    # Print results
    aggregator.print_results(results)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")

if __name__ == "__main__":
    main()