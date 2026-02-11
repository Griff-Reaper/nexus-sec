"""
Threat Intelligence lookup tool - Enhanced Edition

Now integrates with real threat feeds (AbuseIPDB, AlienVault OTX, VirusTotal)
Falls back to demo database if no API keys configured
"""

from typing import Dict, Any
from .threat_feeds import ThreatIntelManager, IOCType

# Initialize global threat intel manager
_threat_manager = None

def get_threat_manager() -> ThreatIntelManager:
    """Get or create the global threat intel manager"""
    global _threat_manager
    if _threat_manager is None:
        _threat_manager = ThreatIntelManager()
    return _threat_manager

# Demo threat intelligence database (for fallback/testing)
THREAT_DATABASE = {
    "ips": {
        "185.220.101.42": {
            "status": "malicious",
            "threat_type": "TOR Exit Node",
            "confidence": "high",
            "first_seen": "2024-01-15",
            "tags": ["tor", "anonymization", "potential_c2"]
        },
        "192.168.1.1": {
            "status": "benign",
            "threat_type": "private_ip",
            "confidence": "high"
        },
        "45.142.120.10": {
            "status": "malicious",
            "threat_type": "APT29 C2 Infrastructure",
            "confidence": "high",
            "first_seen": "2025-11-20",
            "tags": ["apt29", "cozy_bear", "command_control"]
        }
    },
    "domains": {
        "malicious-site.com": {
            "status": "malicious",
            "threat_type": "Phishing",
            "confidence": "high",
            "tags": ["phishing", "credential_theft"]
        },
        "google.com": {
            "status": "benign",
            "threat_type": "legitimate",
            "confidence": "high"
        }
    },
    "hashes": {
        "5f4dcc3b5aa765d61d8327deb882cf99": {
            "status": "malicious",
            "threat_type": "Ransomware - LockBit",
            "confidence": "high",
            "tags": ["ransomware", "lockbit", "encryption"]
        }
    }
}


def lookup_threat_intel(indicator: str, indicator_type: str) -> Dict[str, Any]:
    """
    Look up threat intelligence for an indicator.
    Now uses ThreatIntelManager for multi-source enrichment.
    
    Args:
        indicator: The indicator to check (IP, domain, or hash)
        indicator_type: Type of indicator ('ip', 'domain', 'hash')
        
    Returns:
        Dict containing aggregated threat intelligence data
    """
    # Map string type to IOCType enum
    type_map = {
        "ip": IOCType.IP,
        "domain": IOCType.DOMAIN,
        "hash": IOCType.HASH
    }
    
    ioc_type = type_map.get(indicator_type.lower())
    if not ioc_type:
        return {
            "error": f"Invalid indicator type: {indicator_type}",
            "valid_types": ["ip", "domain", "hash"]
        }
    
    # Get threat intel manager
    manager = get_threat_manager()
    
    # Enrich the IOC
    result = manager.enrich_ioc(indicator, ioc_type)
    
    # Convert to dict and return
    return result.to_dict()


# Claude tool definition
THREAT_INTEL_TOOL = {
    "name": "threat_intel_lookup",
    "description": "Look up threat intelligence for IPs, domains, or file hashes across multiple sources (AbuseIPDB, AlienVault OTX, VirusTotal). Returns aggregated threat assessment, confidence scores, threat types, and risk score.",
    "input_schema": {
        "type": "object",
        "properties": {
            "indicator": {
                "type": "string",
                "description": "The indicator to check (IP address, domain, or file hash)"
            },
            "indicator_type": {
                "type": "string",
                "enum": ["ip", "domain", "hash"],
                "description": "Type of indicator being checked"
            }
        },
        "required": ["indicator", "indicator_type"]
    }
}
