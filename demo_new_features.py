"""
Demo: All New Nexus-Sec Features

Demonstrates:
1. Automated Playbook Execution
2. Threat Hunting
3. SIEM Integration
"""

import logging
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexus_sec.playbooks.playbook_engine import PlaybookEngine, PlaybookExecution
from nexus_sec.hunting.threat_hunter import ThreatHuntingEngine, HuntHypothesis
from nexus_sec.integrations.siem_integration import (
    SIEMIntegrationManager,
    SplunkConnector,
    ElasticConnector,
    SyslogConnector,
    SIEMEvent
)
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def demo_playbook_execution():
    """Demo: Automated Playbook Execution"""
    print("\n" + "=" * 60)
    print("DEMO 1: Automated Playbook Execution")
    print("=" * 60 + "\n")
    
    # Initialize playbook engine
    engine = PlaybookEngine()
    
    # Load playbooks from directory
    playbooks_dir = "playbooks"
    if os.path.exists(playbooks_dir):
        engine.load_playbooks_from_directory(playbooks_dir)
        print(f"✅ Loaded playbooks from {playbooks_dir}\n")
    else:
        print(f"⚠️  Playbooks directory not found: {playbooks_dir}")
        print("    Creating sample playbook in memory...\n")
        
        # Create sample playbook programmatically
        sample_playbook = {
            'name': 'demo_malware_response',
            'description': 'Demo response to malware detection',
            'actions': [
                {
                    'type': 'send_alert',
                    'name': 'notify_team',
                    'params': {
                        'severity': 'high',
                        'message': 'Malware detected - demo response initiated',
                        'channels': ['email', 'slack']
                    }
                },
                {
                    'type': 'isolate_host',
                    'name': 'isolate_host',
                    'params': {},
                    'condition': "severity >= 7"
                },
                {
                    'type': 'quarantine_file',
                    'name': 'quarantine_malware',
                    'params': {}
                },
                {
                    'type': 'create_ticket',
                    'name': 'create_incident',
                    'params': {
                        'title': 'Malware Detection',
                        'priority': 'high'
                    }
                }
            ]
        }
        engine.playbooks['demo_malware_response'] = sample_playbook
    
    # Simulate malware detection event
    trigger_event = {
        "event_type": "malware_detected",
        "hostname": "workstation-042",
        "file_path": "/tmp/suspicious.exe",
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "severity": 8,
        "detection_time": datetime.now().isoformat()
    }
    
    print("📋 Simulating malware detection event:")
    print(f"   Host: {trigger_event['hostname']}")
    print(f"   File: {trigger_event['file_path']}")
    print(f"   Severity: {trigger_event['severity']}/10\n")
    
    # Execute playbook
    print("🔄 Executing automated response playbook...\n")
    
    try:
        execution = engine.execute_playbook('malware_detection_response', trigger_event)
        
        # Display results
        print(f"✅ Playbook execution completed: {execution.status.value}")
        print(f"   Actions executed: {len(execution.actions)}\n")
        
        print("📊 Action Results:")
        for i, action in enumerate(execution.actions, 1):
            status_emoji = "✅" if action.status.value == "success" else "❌"
            print(f"   {i}. {status_emoji} {action.action_name}: {action.message}")
        
        print(f"\n⏱️  Execution time: {(execution.end_time - execution.start_time).total_seconds():.2f}s")
        
    except Exception as e:
        print(f"❌ Playbook execution failed: {e}")


def demo_threat_hunting():
    """Demo: Threat Hunting Module"""
    print("\n" + "=" * 60)
    print("DEMO 2: Threat Hunting")
    print("=" * 60 + "\n")
    
    # Initialize threat hunting engine
    hunter = ThreatHuntingEngine()
    
    # Create a threat hunting hypothesis
    print("🎯 Creating threat hunting hypothesis...\n")
    
    hypothesis = hunter.create_hypothesis(
        title="Potential Lateral Movement Campaign",
        description="Hunt for signs of lateral movement using admin tools and SMB",
        tactics=["lateral-movement", "privilege-escalation"],
        techniques=["T1021.002", "T1021.001"],  # SMB, RDP
        data_sources=["authentication_logs", "network_traffic", "process_monitoring"]
    )
    
    print(f"✅ Created hypothesis: {hypothesis.title}")
    print(f"   Tactics: {', '.join(hypothesis.tactics)}")
    print(f"   Techniques: {', '.join(hypothesis.techniques)}\n")
    
    # Execute the hunt
    print("🔍 Executing threat hunt...\n")
    
    findings = hunter.execute_hunt(hypothesis.id)
    
    print(f"📊 Hunt completed: {len(findings)} findings")
    
    if findings:
        print("\n🚨 Findings:")
        for i, finding in enumerate(findings, 1):
            print(f"\n   {i}. {finding.finding_type} - {finding.severity}")
            print(f"      {finding.description}")
            print(f"      Affected assets: {', '.join(finding.affected_assets)}")
            print(f"      Threat level: {finding.threat_level.value}")
    else:
        print("   No threats detected (simulated environment)")
    
    # Demonstrate IOC hunting
    print("\n" + "-" * 60)
    print("🔎 IOC Hunting")
    print("-" * 60 + "\n")
    
    # Sample IOCs to hunt
    ioc_list = {
        "ips": ["45.142.120.10", "185.220.101.32"],
        "domains": ["malicious-c2.example.com", "phishing-site.xyz"],
        "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        "processes": ["mimikatz.exe", "psexec.exe"]
    }
    
    print("🎯 Hunting for IOCs:")
    for ioc_type, iocs in ioc_list.items():
        print(f"   {ioc_type}: {len(iocs)} indicators")
    
    print("\n🔄 Running IOC hunt...\n")
    
    results = hunter.hunt_ioc_list(ioc_list)
    
    print("📊 IOC Hunt Results:")
    for ioc_type, findings in results.items():
        print(f"   {ioc_type}: {len(findings)} matches found")
        if findings:
            print(f"      (In production: would show detailed matches)")
    
    # Run automated sweep
    print("\n" + "-" * 60)
    print("🤖 Automated Threat Hunting Sweep")
    print("-" * 60 + "\n")
    
    print("🔄 Running comprehensive automated sweep...\n")
    
    sweep_results = hunter.run_automated_sweep()
    
    print("📊 Automated Sweep Results:")
    total_findings = sum(len(findings) for findings in sweep_results.values())
    print(f"   Total findings: {total_findings}\n")
    
    for category, findings in sweep_results.items():
        print(f"   {category}: {len(findings)} findings")


def demo_siem_integration():
    """Demo: SIEM Integration"""
    print("\n" + "=" * 60)
    print("DEMO 3: SIEM Integration")
    print("=" * 60 + "\n")
    
    # Initialize SIEM manager
    manager = SIEMIntegrationManager()
    
    print("🔌 Setting up SIEM connectors...\n")
    
    # Note: These are demo configurations - in production, use real credentials
    
    # 1. Splunk HEC connector (demo)
    print("1. Splunk HEC Connector (Demo Mode)")
    print("   - In production: Configure with real HEC URL and token")
    # splunk = SplunkConnector(
    #     hec_url="https://splunk.example.com:8088",
    #     hec_token="your-hec-token-here",
    #     index="security"
    # )
    # manager.add_connector("splunk", splunk)
    print("   ⚠️  Skipped (requires real Splunk instance)\n")
    
    # 2. Elasticsearch connector (demo)
    print("2. Elasticsearch Connector (Demo Mode)")
    print("   - In production: Configure with real Elastic hosts and credentials")
    # elastic = ElasticConnector(
    #     hosts=["https://elastic.example.com:9200"],
    #     index_prefix="nexus-sec",
    #     username="elastic",
    #     password="your-password"
    # )
    # manager.add_connector("elasticsearch", elastic)
    print("   ⚠️  Skipped (requires real Elasticsearch cluster)\n")
    
    # 3. Syslog connector (demo)
    print("3. Syslog Connector (Demo Mode)")
    print("   - In production: Configure with real syslog server")
    # syslog = SyslogConnector(
    #     syslog_server="syslog.example.com",
    #     syslog_port=514,
    #     protocol="udp"
    # )
    # manager.add_connector("syslog", syslog)
    print("   ⚠️  Skipped (requires real syslog server)\n")
    
    # Create sample security event
    print("📝 Creating sample security event...\n")
    
    event = SIEMEvent(
        timestamp=datetime.now().isoformat(),
        event_type="malware_detection",
        severity="high",
        source="nexus-sec",
        message="Malware detected on workstation-042",
        details={
            "hostname": "workstation-042",
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "file_path": "/tmp/suspicious.exe",
            "detection_method": "signature",
            "action_taken": "quarantined"
        },
        tags=["malware", "endpoint", "automated_response"]
    )
    
    print("Event details:")
    print(f"   Type: {event.event_type}")
    print(f"   Severity: {event.severity}")
    print(f"   Message: {event.message}")
    print(f"   Tags: {', '.join(event.tags)}\n")
    
    # Show event in CEF format
    print("📋 Event in Common Event Format (CEF):")
    print(f"   {event.to_cef()}\n")
    
    # Demonstrate batch sending
    print("📦 Creating batch of events...\n")
    
    events = []
    for i in range(5):
        events.append(SIEMEvent(
            timestamp=datetime.now().isoformat(),
            event_type=f"test_event_{i}",
            severity="info",
            source="nexus-sec",
            message=f"Test event {i}",
            details={"test": True, "index": i},
            tags=["test", "demo"]
        ))
    
    print(f"✅ Created {len(events)} events for batch processing")
    
    print("\n💡 SIEM Integration Features:")
    print("   ✅ Splunk HEC support")
    print("   ✅ Elasticsearch support")
    print("   ✅ Generic syslog support")
    print("   ✅ CEF format conversion")
    print("   ✅ Batch event processing")
    print("   ✅ Connection testing")
    print("   ✅ Query capabilities (Elasticsearch)")
    
    print("\n📚 Usage in Production:")
    print("""
    # Initialize with real credentials
    manager = SIEMIntegrationManager()
    
    # Add Splunk
    splunk = SplunkConnector(
        hec_url="https://your-splunk.com:8088",
        hec_token="your-token",
        index="security"
    )
    manager.add_connector("splunk", splunk)
    
    # Send events
    event = SIEMEvent(...)
    manager.send_to_all(event)
    
    # Test connections
    results = manager.test_all_connections()
    """)


def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("NEXUS-SEC: NEW FEATURES DEMO")
    print("=" * 60)
    
    try:
        # Demo 1: Playbook Execution
        demo_playbook_execution()
        
        # Demo 2: Threat Hunting
        demo_threat_hunting()
        
        # Demo 3: SIEM Integration
        demo_siem_integration()
        
        print("\n" + "=" * 60)
        print("✅ ALL DEMOS COMPLETED SUCCESSFULLY")
        print("=" * 60 + "\n")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        print(f"\n❌ Demo failed: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
