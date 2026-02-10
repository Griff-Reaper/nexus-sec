"""
Orchestrator for Nexus-Sec multi-agent system.

The orchestrator is the central coordinator that:
1. Receives user requests
2. Determines which agent(s) should handle the task
3. Routes tasks to appropriate agents
4. Synthesizes responses from multiple agents if needed
"""

from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.panel import Panel

from .agents.threat_hunter import ThreatHunter
from .agents.base_agent import BaseAgent

console = Console()


class Orchestrator:
    """
    Central coordinator for the Nexus-Sec multi-agent system.
    
    The orchestrator maintains a registry of available agents and
    intelligently routes tasks based on their requirements.
    """
    
    def __init__(self, verbose: bool = True):
        """
        Initialize the Orchestrator and all agents.
        
        Args:
            verbose: Whether to print detailed agent communication
        """
        self.verbose = verbose
        self.agents: Dict[str, BaseAgent] = {}
        
        # Initialize agents
        self._initialize_agents()
        
        if self.verbose:
            console.print("[bold green]✓ Nexus-Sec Orchestrator initialized[/bold green]")
            console.print(f"[dim]Available agents: {', '.join(self.agents.keys())}[/dim]\n")
    
    def _initialize_agents(self):
        """Initialize all available agents."""
        # For now, just the Threat Hunter
        # We'll add more agents later
        self.agents["threat_hunter"] = ThreatHunter()
    
    def process_request(self, user_request: str) -> Dict[str, Any]:
        """
        Process a user request by routing to appropriate agent(s).
        
        Args:
            user_request: The user's security question or task
            
        Returns:
            Dict containing the orchestrated response
        """
        if self.verbose:
            console.print(Panel(
                f"[bold cyan]User Request:[/bold cyan]\n{user_request}",
                border_style="cyan"
            ))
        
        # For Phase 1, we'll use simple keyword routing
        # In Phase 2, we'll use Claude to intelligently route
        agent = self._route_request(user_request)
        
        if self.verbose:
            console.print(f"[yellow]→ Routing to: {agent.name}[/yellow]\n")
        
        # Execute the task
        result = agent.process(user_request)
        
        if self.verbose:
            console.print(Panel(
                f"[bold green]{agent.name} Response:[/bold green]\n{result['response']}",
                border_style="green"
            ))
        
        return result
    
    def _route_request(self, request: str) -> BaseAgent:
        """
        Determine which agent should handle the request.
        
        This is a simple keyword-based router for Phase 1.
        Later we'll upgrade to AI-powered routing.
        
        Args:
            request: User's request
            
        Returns:
            The appropriate agent
        """
        request_lower = request.lower()
        
        # Threat hunting keywords
        threat_keywords = [
            "ip", "domain", "hash", "threat", "malicious", 
            "indicator", "ioc", "mitre", "attack", "technique"
        ]
        
        if any(keyword in request_lower for keyword in threat_keywords):
            return self.agents["threat_hunter"]
        
        # Default to threat hunter for now
        return self.agents["threat_hunter"]
    
    def list_agents(self) -> List[str]:
        """Get list of available agents."""
        return list(self.agents.keys())