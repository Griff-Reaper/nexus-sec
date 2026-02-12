# Nexus-Sec Demo Script

**Duration:** 5-7 minutes  
**Audience:** Technical recruiters, hiring managers, security professionals  
**Goal:** Demonstrate automated security operations capabilities

---

## 🎬 Scene 1: Introduction (30 seconds)

**[Screen: README.md on GitHub]**

**Script:**
> "Hi, I'm Jace. Today I'm going to show you Nexus-Sec - an AI-powered security operations platform I built that automates incident response, threat hunting, and SIEM integration."
> 
> "This is portfolio work I created to demonstrate my skills in security automation, Python development, and enterprise system integration."
> 
> "Let's see it in action."

**Visual:**
- GitHub repository page showing stars/forks
- Scroll to architecture diagram
- Highlight key features list

---

## 🎬 Scene 2: Automated Incident Response (2 minutes)

**[Screen: Terminal + Code Editor]**

**Script:**
> "The core of Nexus-Sec is automated incident response through playbooks. Let me show you how it works."

**Demo Steps:**

1. **Show a playbook** (`malware_detection_response.yml`)
```bash
cat playbooks/malware_detection_response.yml
```

> "Here's a playbook that responds to malware detection. It's written in YAML, making it easy to customize without changing code."
> 
> "It isolates the infected host, quarantines the malware, collects forensic evidence, and creates an incident ticket - all automatically."

2. **Execute the playbook**
```bash
python
```

```python
from nexus_sec.playbooks.playbook_engine import PlaybookEngine
from datetime import datetime

engine = PlaybookEngine()
engine.load_playbooks_from_directory("playbooks/")

# Simulate malware detection
event = {
    "hostname": "workstation-042",
    "file_path": "/tmp/suspicious.exe",
    "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
    "severity": 8
}

execution = engine.execute_playbook('malware_detection_response', event)

print(f"\nPlaybook Status: {execution.status.value}")
print("\nActions Executed:")
for action in execution.actions:
    status_icon = "✅" if action.status.value == "success" else "❌"
    print(f"  {status_icon} {action.action_name}: {action.message}")
```

> "Watch what happens when malware is detected..."
> 
> [Pause for execution]
> 
> "There - in under a second, we've contained the threat, collected evidence, and created an incident ticket. In a real environment, this would connect to CrowdStrike Falcon or SentinelOne for actual host isolation."

---

## 🎬 Scene 3: Proactive Threat Hunting (1.5 minutes)

**[Screen: Terminal]**

**Script:**
> "But Nexus-Sec doesn't just respond to alerts - it proactively hunts for threats."

**Demo Steps:**

1. **Create a hunting hypothesis**
```python
from nexus_sec.hunting.threat_hunter import ThreatHuntingEngine

hunter = ThreatHuntingEngine()

# Create hypothesis based on recent threat intelligence
hypothesis = hunter.create_hypothesis(
    title="APT28 Lateral Movement Detection",
    description="Hunt for signs of lateral movement using SMB and RDP",
    tactics=["lateral-movement", "privilege-escalation"],
    techniques=["T1021.002", "T1021.001"],  # SMB, RDP
    data_sources=["windows_event_logs", "network_traffic"]
)

print(f"Created hypothesis: {hypothesis.title}")
print(f"MITRE ATT&CK Techniques: {', '.join(hypothesis.techniques)}")
```

> "I've created a hypothesis aligned with the MITRE ATT&CK framework. We're hunting for APT28-style lateral movement."

2. **Execute the hunt**
```python
# Hunt for specific IOCs
ioc_results = hunter.hunt_ioc_list({
    "ips": ["45.142.120.10", "185.220.101.32"],
    "domains": ["malicious-c2.example.com"],
    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
})

print(f"\nIOC Hunt Complete:")
print(f"  IPs searched: 2")
print(f"  Domains searched: 1")
print(f"  Hashes searched: 1")

# Run behavioral analytics
findings = hunter.behavioral_analyzer.analyze_lateral_movement(time_window=24)

print(f"\nBehavioral Analysis:")
print(f"  Findings: {len(findings)}")
for finding in findings[:3]:  # Show first 3
    print(f"  - {finding.finding_type}: {finding.threat_level.value}")
```

> "The threat hunting engine searches for specific indicators AND suspicious behaviors, catching both known and unknown threats."

---

## 🎬 Scene 4: Enterprise SIEM Integration (1 minute)

**[Screen: Terminal]**

**Script:**
> "All of this integrates with your existing security stack. Let me show you SIEM integration."

**Demo Steps:**

```python
from nexus_sec.integrations.siem_integration import (
    SIEMIntegrationManager,
    SplunkConnector,
    SIEMEvent
)

# Initialize SIEM manager
manager = SIEMIntegrationManager()

# Add Splunk (in demo mode)
splunk = SplunkConnector(
    hec_url="https://splunk.company.com:8088",
    hec_token="demo-token",
    index="security"
)
manager.add_connector("splunk", splunk)

# Create event
event = SIEMEvent(
    timestamp=datetime.now().isoformat(),
    event_type="malware_detection",
    severity="high",
    source="nexus-sec",
    message="Automated malware response executed",
    details={
        "hostname": "workstation-042",
        "actions_taken": ["isolation", "quarantine", "evidence_collection"]
    }
)

# Convert to CEF for universal compatibility
print("Common Event Format (CEF):")
print(event.to_cef())
```

> "Events are converted to CEF - Common Event Format - for universal SIEM compatibility. This works with Splunk, QRadar, ElasticSearch, or any SIEM that accepts CEF."

---

## 🎬 Scene 5: Technical Deep Dive (1 minute)

**[Screen: VS Code - show code]**

**Script:**
> "Let me show you some of the code architecture."

**Visual Tour:**

1. **Show playbook engine code** (brief scroll)
> "The playbook engine uses a registry pattern to map YAML actions to Python classes. It's extensible - you can add new actions without changing the core engine."

2. **Show threat hunting code** (brief scroll)
> "The threat hunting module separates IOC-based hunting from behavioral analytics. Both feed into a unified finding system."

3. **Show docstrings**
> "Everything is thoroughly documented with docstrings, type hints, and examples. This isn't just a hobby project - it's written to production standards."

---

## 🎬 Scene 6: Wrap-Up & Call to Action (30 seconds)

**[Screen: GitHub repository]**

**Script:**
> "So that's Nexus-Sec - automated incident response, proactive threat hunting, and enterprise SIEM integration, all powered by AI."
> 
> "This project demonstrates my skills in:"
> - Python development and architecture
> - Security operations and incident response
> - Enterprise system integration
> - MITRE ATT&CK framework knowledge
> - Production-quality documentation
> 
> "The full code is available on GitHub with comprehensive documentation. Thanks for watching!"

**Visual:**
- Show GitHub repository
- Highlight documentation
- Show your contact info or LinkedIn

**End Screen:**
```
Nexus-Sec
AI-Powered Security Operations Platform

github.com/yourusername/nexus-sec
linkedin.com/in/yourprofile

Built by: Jace
System Administrator & AI Security Engineer
```

---

## 📋 Demo Preparation Checklist

Before recording your demo:

**Setup:**
- [ ] Clean terminal with good color scheme
- [ ] Increase font size (16pt minimum for screen recording)
- [ ] Close unnecessary applications
- [ ] Prepare demo environment with sample data
- [ ] Test all commands beforehand
- [ ] Have playbook YAML files ready to show

**Recording:**
- [ ] Use high-quality microphone
- [ ] Record in 1080p or higher
- [ ] Keep recording under 7 minutes
- [ ] Practice script 2-3 times beforehand
- [ ] Speak clearly and at moderate pace
- [ ] Show enthusiasm but stay professional

**Editing:**
- [ ] Add title screen with project name
- [ ] Add transitions between scenes (1-2 seconds)
- [ ] Add text overlays for key concepts
- [ ] Background music (subtle, professional)
- [ ] End screen with contact info
- [ ] Export in high quality (H.264, 1080p)

**Publishing:**
- [ ] Upload to YouTube
- [ ] Add descriptive title: "Nexus-Sec: AI-Powered Security Operations Platform Demo"
- [ ] Write detailed description with GitHub link
- [ ] Add tags: security automation, incident response, python, ai, cybersecurity
- [ ] Create custom thumbnail
- [ ] Add to LinkedIn portfolio
- [ ] Include link in resume/applications

---

## 🎯 Alternative: Live Demo Script

**For In-Person Interviews:**

This same script works for live demos, but adjust timing:
- Skip recordings/editing
- Can go deeper on technical questions
- Be ready to show specific code sections
- Prepare to answer: "How would you implement X in production?"

**Practice Answers:**
- "How does this scale?" → "Horizontal scaling with multiple engine instances, Redis for state"
- "What about errors?" → "Show error handling in playbook engine"
- "Security of the platform?" → "API key management, audit logging, least privilege"

---

## 💡 Tips for Success

1. **Energy Level:** Match your energy to the content (excited about cool features!)
2. **Pacing:** Speak slower than you think - viewers need time to process
3. **Explanations:** Explain WHY, not just WHAT ("This matters because...")
4. **Show, Don't Tell:** Execute code live rather than just describing
5. **Polish:** A 5-minute polished demo beats 20 minutes of rambling

**Remember:** You're not just showing code - you're demonstrating your ability to:
- Solve real security problems
- Think architecturally
- Communicate technical concepts
- Build production-ready systems

Good luck with your demo! 🚀
