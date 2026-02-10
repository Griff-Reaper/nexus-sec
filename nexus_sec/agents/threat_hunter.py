"""
Threat Hunter Agent for Nexus-Sec.

Specialized in analyzing threats, checking indicators, and mapping to MITRE ATT&CK.
"""

from typing import Dict, Any
from .base_agent import BaseAgent
from ..prompts.system_prompts import THREAT_HUNTER_PROMPT
from ..tools.threat_intel import lookup_threat_intel, THREAT_INTEL_TOOL
from ..tools.mitre_attack import lookup_mitre_attack, MITRE_ATTACK_TOOL


class ThreatHunter(BaseAgent):
    """
    Threat Hunter agent - specialized in threat analysis and intelligence.
    
    Capabilities:
    - Analyze suspicious indicators (IPs, domains, hashes)
    - Map attacks to MITRE ATT&CK framework
    - Provide threat context and recommendations
    """
    
    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        """Initialize the Threat Hunter agent."""
        super().__init__(
            name="ThreatHunter",
            role="Threat Intelligence & Analysis",
            system_prompt=THREAT_HUNTER_PROMPT,
            tools=[THREAT_INTEL_TOOL, MITRE_ATTACK_TOOL],
            model=model
        )
    
    def _execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> Any:
        """
        Execute threat hunting tools.
        
        Args:
            tool_name: Name of the tool to execute
            tool_input: Tool parameters
            
        Returns:
            Tool execution result
        """
        if tool_name == "threat_intel_lookup":
            return lookup_threat_intel(
                indicator=tool_input["indicator"],
                indicator_type=tool_input["indicator_type"]
            )
        
        elif tool_name == "mitre_attack_lookup":
            return lookup_mitre_attack(
                technique_id=tool_input.get("technique_id"),
                search_term=tool_input.get("search_term")
            )
        
        else:
            return {"error": f"Unknown tool: {tool_name}"}