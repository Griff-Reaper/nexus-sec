"""
MITRE ATT&CK framework lookup tool.

Maps suspicious behaviors and techniques to the MITRE ATT&CK framework.
Provides tactic, technique details, and detection/mitigation guidance.
"""

from typing import Dict, Any, Optional

# Demo MITRE ATT&CK database
MITRE_DATABASE = {
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection.",
        "detection": "Monitor network traffic for unusual protocols or patterns",
        "mitigation": "Network intrusion detection, SSL/TLS inspection"
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems.",
        "detection": "Email gateway analysis, user training, suspicious link detection",
        "mitigation": "Security awareness training, email filtering, anti-phishing tools"
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data to disrupt availability and demand ransom.",
        "detection": "Monitor for unusual file encryption activity, high volumes of file modifications",
        "mitigation": "Backups, endpoint protection, privilege management"
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "detection": "Monitor authentication logs for failed login attempts, account lockouts",
        "mitigation": "Multi-factor authentication, account lockout policies, password complexity"
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access, Persistence, Privilege Escalation",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "detection": "Monitor account activity for anomalies, unusual login times/locations",
        "mitigation": "MFA, privileged account management, least privilege"
    }
}


def lookup_mitre_attack(technique_id: Optional[str] = None, search_term: Optional[str] = None) -> Dict[str, Any]:
    """
    Look up MITRE ATT&CK technique information.
    
    Args:
        technique_id: Specific MITRE technique ID (e.g., "T1071")
        search_term: Search term to find relevant techniques
        
    Returns:
        Dict containing technique details
    """
    if technique_id:
        # Direct lookup by ID
        technique = MITRE_DATABASE.get(technique_id.upper())
        if technique:
            return {
                "technique_id": technique_id.upper(),
                **technique,
                "success": True
            }
        else:
            return {
                "error": f"Technique {technique_id} not found",
                "success": False
            }
    
    elif search_term:
        # Search by keyword
        results = []
        search_term = search_term.lower()
        
        for tid, data in MITRE_DATABASE.items():
            if (search_term in data["name"].lower() or 
                search_term in data["description"].lower() or
                search_term in data["tactic"].lower()):
                results.append({
                    "technique_id": tid,
                    **data
                })
        
        if results:
            return {
                "results": results,
                "count": len(results),
                "success": True
            }
        else:
            return {
                "message": f"No techniques found matching '{search_term}'",
                "success": False
            }
    
    else:
        return {
            "error": "Must provide either technique_id or search_term",
            "success": False
        }


# Claude tool definition
MITRE_ATTACK_TOOL = {
    "name": "mitre_attack_lookup",
    "description": "Look up MITRE ATT&CK technique information by ID or search for techniques by keyword. Returns tactic, description, detection methods, and mitigation strategies.",
    "input_schema": {
        "type": "object",
        "properties": {
            "technique_id": {
                "type": "string",
                "description": "MITRE ATT&CK technique ID (e.g., 'T1071')"
            },
            "search_term": {
                "type": "string",
                "description": "Keyword to search for relevant techniques (e.g., 'phishing', 'ransomware')"
            }
        }
    }
}