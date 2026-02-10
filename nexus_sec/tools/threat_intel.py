"""
Threat Intelligence lookup tool.

Checks IPs, domains, and file hashes against known threat indicators.
In production, this would query real threat feeds. For now, it uses a demo database.
"""

from typing import Dict, Any

# Demo threat intelligence database
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
    
    Args:
        indicator: The indicator to check (IP, domain, or hash)
        indicator_type: Type of indicator ('ip', 'domain', 'hash')
        
    Returns:
        Dict containing threat intelligence data
    """
    # Normalize indicator type
    indicator_type = indicator_type.lower()
    
    # Map to correct database key
    db_key = {
        "ip": "ips",
        "domain": "domains", 
        "hash": "hashes"
    }.get(indicator_type)
    
    if not db_key:
        return {
            "error": f"Invalid indicator type: {indicator_type}",
            "valid_types": ["ip", "domain", "hash"]
        }
    
    # Lookup in database
    result = THREAT_DATABASE.get(db_key, {}).get(indicator)
    
    if result:
        return {
            "indicator": indicator,
            "type": indicator_type,
            **result
        }
    else:
        return {
            "indicator": indicator,
            "type": indicator_type,
            "status": "unknown",
            "message": "No threat intelligence found for this indicator"
        }


# Claude tool definition
THREAT_INTEL_TOOL = {
    "name": "threat_intel_lookup",
    "description": "Look up threat intelligence for IPs, domains, or file hashes. Returns status (malicious/benign/unknown), threat type, confidence level, and associated tags.",
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