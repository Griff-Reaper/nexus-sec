"""
Base Agent class for Nexus-Sec.

All specialized agents inherit from this base class which provides:
- Claude API integration
- Tool execution framework
- Standardized communication protocol
"""

import os
from typing import List, Dict, Any, Optional
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()


class BaseAgent:
    """
    Base class for all Nexus-Sec agents.
    
    Each agent has:
    - A name and role
    - Access to Claude for reasoning
    - A set of tools it can use
    - A system prompt defining its behavior
    """
    
    def __init__(
        self,
        name: str,
        role: str,
        system_prompt: str,
        tools: Optional[List[Dict[str, Any]]] = None,
        model: str = "claude-sonnet-4-20250514"
    ):
        """
        Initialize a Nexus-Sec agent.
        
        Args:
            name: Agent's display name
            role: Agent's specialized role
            system_prompt: Instructions defining agent behavior
            tools: List of Claude-compatible tool definitions
            model: Claude model to use for reasoning
        """
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.tools = tools or []
        self.model = model
        
        # Initialize Anthropic client
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment")
        
        self.client = Anthropic(api_key=api_key)
        
    def process(self, task: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process a task using Claude's reasoning and available tools.
        
        Args:
            task: The task or question to process
            context: Optional additional context from other agents
            
        Returns:
            Dict containing the agent's response and any tool results
        """
        messages = [{"role": "user", "content": task}]
        
        # Add context if provided
        if context:
            context_str = f"\n\nAdditional context: {context}"
            messages[0]["content"] += context_str
        
        # Initial API call
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=self.system_prompt,
            messages=messages,
            tools=self.tools if self.tools else None
        )
        
        # Handle tool use if needed
        while response.stop_reason == "tool_use":
            # Extract tool calls
            tool_results = []
            
            for block in response.content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input
                    
                    # Execute the tool
                    result = self._execute_tool(tool_name, tool_input)
                    
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": str(result)
                    })
            
            # Add assistant response and tool results to conversation
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
            
            # Continue conversation
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.system_prompt,
                messages=messages,
                tools=self.tools if self.tools else None
            )
        
        # Extract final text response
        final_response = ""
        for block in response.content:
            if hasattr(block, "text"):
                final_response += block.text
        
        return {
            "agent": self.name,
            "role": self.role,
            "response": final_response,
            "success": True
        }
    
    def _execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> Any:
        """
        Execute a tool by name. Subclasses should override this
        to provide actual tool implementations.
        
        Args:
            tool_name: Name of the tool to execute
            tool_input: Input parameters for the tool
            
        Returns:
            Tool execution result
        """
        raise NotImplementedError(f"Tool {tool_name} not implemented")
    
    def __repr__(self) -> str:
        return f"<{self.name} ({self.role})>"