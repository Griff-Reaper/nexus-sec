"""
Nexus-Sec Threat Intel & Correlation Demo

Demonstrates:
1. Multi-source threat intelligence enrichment
2. Event correlation and incident detection
3. Attack chain analysis
4. Automated incident reporting
"""

from datetime import datetime, timedelta
from nexus_sec.tools.threat_feeds import ThreatIntelManager, IOCType
from nexus_sec.tools.correlation import ThreatCorrelationEngine, SecurityEvent
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()


def demo_threat_intel():
    """Demo multi-source threat intelligence enrichment"""
    console.print("\n[bold cyan]═══ DEMO 1: Multi-Source Threat Intelligence ═══[/bold cyan]\n")
    
    manager = ThreatIntelManager()
    
    # Test IOCs
    test_iocs = [
        ("45.142.120.10", IOCType.IP, "Known APT29 C2 Infrastructure"),
        ("malicious-site.com", IOCType.DOMAIN, "Phishing domain"),
        ("5f4dcc3b5aa765d61d8327deb882cf99", IOCType.HASH, "LockBit ransomware hash")
    ]
    
    for indicator, ioc_type, description in test_iocs:
        console.print(f"[yellow]→ Enriching {ioc_type.value.upper()}: {indicator}[/yellow]")
        console.print(f"  [dim]{description}[/dim]\n")
        
        result = manager.enrich_ioc(indicator, ioc_type)
        
        # Display results in a nice table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Malicious", "🔴 YES" if result.is_malicious else "🟢 NO")
        table.add_row("Threat Level", result.threat_level.name)
        table.add_row("Risk Score", f"{result.calculate_risk_score():.1f}/100")
        table.add_row("Confidence", f"{result.confidence_score:.2f}")
        table.add_row("Sources", ", ".join(result.sources))
        table.add_row("Threat Types", ", ".join(result.threat_types[:3]))  # Show first 3
        
        if result.tags:
            table.add_row("Tags", ", ".join(result.tags[:5]))  # Show first 5
        
        console.print(table)
        console.print()


def demo_event_correlation():
    """Demo event correlation and incident detection"""
    console.print("\n[bold cyan]═══ DEMO 2: Event Correlation & Incident Detection ═══[/bold cyan]\n")
    
    # Create correlation engine
    engine = ThreatCorrelationEngine(time_window_hours=24)
    
    # Simulate a coordinated attack scenario
    base_time = datetime.now()
    malicious_ip = "45.142.120.10"
    victim_user = "john.doe"
    
    events = [
        # Phase 1: Reconnaissance
        SecurityEvent(
            event_id="evt_001",
            timestamp=base_time,
            event_type="port_scan",
            source_ip=malicious_ip,
            dest_ip="10.0.1.100",
            metadata={"ports_scanned": "22,80,443,3389"}
        ),
        # Phase 2: Initial Access (successful login)
        SecurityEvent(
            event_id="evt_002",
            timestamp=base_time + timedelta(minutes=15),
            event_type="login_attempt",
            source_ip=malicious_ip,
            user=victim_user,
            metadata={"status": "success", "method": "RDP"}
        ),
        # Phase 3: Execution (malware dropped)
        SecurityEvent(
            event_id="evt_003",
            timestamp=base_time + timedelta(minutes=30),
            event_type="file_execution",
            user=victim_user,
            file_hash="5f4dcc3b5aa765d61d8327deb882cf99",
            metadata={"filename": "update.exe", "location": "C:\\Temp"}
        ),
        # Phase 4: C2 Communication
        SecurityEvent(
            event_id="evt_004",
            timestamp=base_time + timedelta(minutes=35),
            event_type="network_connection",
            source_ip="10.0.1.100",
            dest_ip=malicious_ip,
            domain="malicious-site.com",
            user=victim_user,
            metadata={"protocol": "HTTPS", "port": 443}
        ),
        # Phase 5: Data Exfiltration
        SecurityEvent(
            event_id="evt_005",
            timestamp=base_time + timedelta(hours=2),
            event_type="file_transfer",
            source_ip="10.0.1.100",
            dest_ip=malicious_ip,
            user=victim_user,
            metadata={"bytes": 524288000, "direction": "outbound"}
        )
    ]
    
    console.print("[yellow]Simulating coordinated attack with 5 events...[/yellow]\n")
    
    # Add events to correlation engine
    for event in events:
        engine.add_event(event)
        console.print(f"  ✓ Added {event.event_type} at {event.timestamp.strftime('%H:%M:%S')}")
    
    console.print()
    
    # Correlate events
    console.print("[yellow]Running correlation analysis...[/yellow]\n")
    incidents = engine.correlate_events()
    
    if incidents:
        for incident in incidents:
            console.print(Panel(
                f"[bold red]INCIDENT DETECTED[/bold red]\n\n"
                f"Incident ID: {incident.incident_id}\n"
                f"First Seen: {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Last Seen: {incident.last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Duration: {(incident.last_seen - incident.first_seen).total_seconds() / 60:.0f} minutes\n"
                f"Event Count: {len(incident.events)}\n"
                f"Severity Score: {incident.severity_score:.1f}/100\n"
                f"Confidence: {incident.confidence:.2f}\n"
                f"Shared IOCs: {len(incident.shared_iocs)}",
                border_style="red",
                title="⚠️  SECURITY INCIDENT"
            ))
            
            # Show attack chain
            console.print("\n[bold yellow]Attack Chain Analysis:[/bold yellow]")
            attack_chain = engine.get_attack_chain(incident)
            for phase, event_ids in attack_chain.items():
                console.print(f"  • {phase}: {len(event_ids)} event(s)")
            
            # Generate full report
            console.print("\n[bold yellow]Generating incident report...[/bold yellow]")
            report = engine.generate_incident_report(incident)
            
            # Show recommendations
            console.print("\n[bold green]Recommended Actions:[/bold green]")
            for i, rec in enumerate(report["recommendations"], 1):
                console.print(f"  {i}. {rec}")
    
    console.print()


def demo_full_workflow():
    """Demo complete workflow: Threat Intel + Correlation"""
    console.print("\n[bold cyan]═══ DEMO 3: Complete Workflow ═══[/bold cyan]\n")
    
    console.print("[yellow]Scenario: Suspicious network activity detected[/yellow]\n")
    
    # Step 1: Enrich IOCs with threat intel
    console.print("[bold]Step 1: IOC Enrichment[/bold]")
    manager = ThreatIntelManager()
    
    suspicious_ip = "45.142.120.10"
    result = manager.enrich_ioc(suspicious_ip, IOCType.IP)
    
    console.print(f"  IP: {suspicious_ip}")
    console.print(f"  Risk Score: {result.calculate_risk_score():.1f}/100")
    console.print(f"  Verdict: {'🔴 MALICIOUS' if result.is_malicious else '🟢 CLEAN'}\n")
    
    # Step 2: Check for related events
    console.print("[bold]Step 2: Event Correlation[/bold]")
    engine = ThreatCorrelationEngine()
    
    event = SecurityEvent(
        event_id="evt_suspect",
        timestamp=datetime.now(),
        event_type="network_connection",
        source_ip="10.0.1.50",
        dest_ip=suspicious_ip,
        user="admin"
    )
    
    engine.add_event(event)
    related = engine.find_related_events(event)
    
    console.print(f"  Found {len(related)} related event(s)\n")
    
    # Step 3: Automated response recommendation
    console.print("[bold]Step 3: Automated Response[/bold]")
    
    if result.is_malicious and result.calculate_risk_score() > 70:
        console.print("  [bold red]⚠️  HIGH RISK DETECTED[/bold red]")
        console.print("  [yellow]Recommended Actions:[/yellow]")
        console.print("    1. Block IP at firewall: " + suspicious_ip)
        console.print("    2. Isolate affected host: 10.0.1.50")
        console.print("    3. Reset credentials for user: admin")
        console.print("    4. Initiate forensic investigation")
    
    console.print()


if __name__ == "__main__":
    console.print("[bold green]Nexus-Sec Threat Intelligence & Correlation Demo[/bold green]")
    console.print("[dim]Demonstrating multi-agent security operations capabilities[/dim]")
    
    # Run demos
    demo_threat_intel()
    demo_event_correlation()
    demo_full_workflow()
    
    console.print("\n[bold green]✓ Demo complete![/bold green]")
    console.print("\n[dim]Note: Using demo data. Configure API keys in .env for real threat feeds.[/dim]\n")
