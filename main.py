"""
Nexus-Sec CLI - Command Line Interface for Multi-Agent Security Operations

Usage:
    python main.py interactive    # Start interactive chat
    python main.py query "Is IP 185.220.101.42 malicious?"
    python main.py demo          # Run demo
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint
from typing import Optional

from nexus_sec.orchestrator import Orchestrator

app = typer.Typer(help="Nexus-Sec - Multi-Agent Security Operations Platform")
console = Console()


@app.command()
def interactive(
    verbose: bool = typer.Option(True, help="Show agent communication details")
):
    """
    Start an interactive session with Nexus-Sec.
    
    Chat with the multi-agent system and watch agents collaborate
    to answer your security questions.
    """
    console.print(Panel.fit(
        "[bold cyan]NEXUS-SEC[/bold cyan]\n"
        "[dim]Multi-Agent Security Operations Platform[/dim]",
        border_style="cyan"
    ))
    
    # Initialize orchestrator
    try:
        orchestrator = Orchestrator(verbose=verbose)
    except Exception as e:
        console.print(f"[red]Error initializing Nexus-Sec: {e}[/red]")
        console.print("[yellow]Make sure ANTHROPIC_API_KEY is set in your .env file[/yellow]")
        raise typer.Exit(1)
    
    console.print("\n[green]Type your security questions below. Type 'quit' to exit.[/green]\n")
    
    # Interactive loop
    while True:
        try:
            user_input = console.input("[bold blue]You:[/bold blue] ")
            
            if user_input.lower() in ["quit", "exit", "q"]:
                console.print("[yellow]Goodbye![/yellow]")
                break
            
            if not user_input.strip():
                continue
            
            # Process request
            console.print()
            result = orchestrator.process_request(user_input)
            console.print()
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Goodbye![/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


@app.command()
def query(
    question: str,
    verbose: bool = typer.Option(True, help="Show agent communication details")
):
    """
    Ask Nexus-Sec a single question.
    
    Example: python main.py query "Is IP 185.220.101.42 malicious?"
    """
    orchestrator = Orchestrator(verbose=verbose)
    result = orchestrator.process_request(question)
    
    if not verbose:
        console.print(result['response'])


@app.command()
def demo():
    """
    Run a demonstration of Nexus-Sec capabilities.
    
    Shows example threat hunting scenarios.
    """
    console.print(Panel.fit(
        "[bold cyan]NEXUS-SEC DEMO[/bold cyan]\n"
        "[dim]Demonstrating multi-agent capabilities[/dim]",
        border_style="cyan"
    ))
    
    orchestrator = Orchestrator(verbose=True)
    
    demo_queries = [
        "Is IP 185.220.101.42 malicious?",
        "What is MITRE technique T1566?",
        "Check if domain malicious-site.com is safe"
    ]
    
    for i, query in enumerate(demo_queries, 1):
        console.print(f"\n[bold yellow]Demo Query {i}/{len(demo_queries)}[/bold yellow]")
        orchestrator.process_request(query)
        
        if i < len(demo_queries):
            console.print("\n" + "="*80 + "\n")
    
    console.print("\n[bold green]✓ Demo complete![/bold green]")


@app.command()
def agents():
    """List all available agents in the system."""
    orchestrator = Orchestrator(verbose=False)
    agent_list = orchestrator.list_agents()
    
    console.print("\n[bold cyan]Available Agents:[/bold cyan]")
    for agent_name in agent_list:
        agent = orchestrator.agents[agent_name]
        console.print(f"  • [green]{agent.name}[/green] - {agent.role}")
    console.print()


if __name__ == "__main__":
    app()