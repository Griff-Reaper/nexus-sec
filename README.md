# Nexus-Sec 🔐

Multi-agent AI platform for automated security operations and incident response.

## Overview

Nexus-Sec is an advanced multi-agent system that coordinates specialized AI agents to handle complex security operations. Each agent has unique expertise and can autonomously use security tools to analyze threats, respond to incidents, and generate reports.

### Architecture
```
User Request
     ↓
Orchestrator (coordinates agents)
     ↓
┌────────────┬─────────────────┬──────────────┐
│            │                 │              │
Threat Hunter   Incident Responder   Report Generator
│            │                 │              │
Uses tools:  Creates playbooks  Generates docs
- Threat Intel
- MITRE ATT&CK
```

## Features

- **Multi-Agent Collaboration**: Specialized agents work together on complex security tasks
- **Autonomous Tool Use**: Agents intelligently select and use security tools
- **MITRE ATT&CK Integration**: Maps threats to the MITRE ATT&CK framework
- **Threat Intelligence**: Real-time indicator lookups (IPs, domains, hashes)
  - Multi-source IOC enrichment (AbuseIPDB, AlienVault OTX, VirusTotal)
  - Event correlation and incident detection
  - Attack chain analysis (cyber kill chain mapping)
  - Automated risk scoring and reporting
- **Interactive CLI**: Beautiful terminal interface with agent communication visibility

## Current Agents

### 🔍 Threat Hunter
Analyzes potential security threats and hunts for indicators of compromise.

**Tools:**
- Threat Intelligence Lookup
- MITRE ATT&CK Mapping

**Capabilities:**
- Indicator analysis (IPs, domains, file hashes)
- Threat classification and risk assessment
- Attack technique identification
- Detection and mitigation recommendations

### 🚧 Coming Soon
- **Incident Responder**: Creates IR plans and playbooks
- **Report Generator**: Produces professional security documentation

## Quick Start

### Prerequisites
- Python 3.11+
- Anthropic API key ([Get one here](https://console.anthropic.com))

### Installation
```bash
# Clone the repository
git clone https://github.com/Griff-Reaper/nexus-sec.git
cd nexus-sec

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure API key
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### Usage

**Run Demo:**
```bash
python main.py demo
```

**Interactive Mode:**
```bash
python main.py interactive
```

**Single Query:**
```bash
python main.py query "Is IP 185.220.101.42 malicious?"
```

**List Agents:**
```bash
python main.py agents
```

## Example Queries
```
"Is IP 185.220.101.42 malicious?"
"What is MITRE technique T1566?"
"Check if domain malicious-site.com is safe"
"Analyze this suspicious hash: 5f4dcc3b5aa765d61d8327deb882cf99"
```

## Tech Stack

- **AI Framework**: Claude Sonnet 4 via Anthropic API
- **Agent Framework**: Custom multi-agent architecture with tool use
- **CLI**: Typer + Rich for beautiful terminal UI
- **Language**: Python 3.11+

## Project Structure
```
nexus-sec/
├── nexus_sec/              # Main package
│   ├── orchestrator.py     # Agent coordinator
│   ├── agents/             # Specialized agents
│   │   ├── base_agent.py   # Base agent class
│   │   └── threat_hunter.py
│   ├── tools/              # Security tools
│   │   ├── threat_intel.py
│   │   └── mitre_attack.py
│   ├── prompts/            # System prompts
│   └── utils/              # Helper utilities
├── main.py                 # CLI entry point
└── requirements.txt
```

## Roadmap

**Phase 1 (Current):**
- ✅ Multi-agent architecture
- ✅ Threat Hunter agent
- ✅ Threat intelligence tool
- ✅ MITRE ATT&CK integration
- ✅ CLI interface

**Phase 2 (Next 2 weeks):**
- ⬜ Incident Responder agent
- ⬜ Report Generator agent
- ⬜ Agent memory system
- ⬜ Inter-agent communication
- ⬜ Dashboard UI

**Phase 3 (Future):**
- ⬜ Real threat feed integration
- ⬜ SIEM integration
- ⬜ Automated playbook execution
- ⬜ Team collaboration features

## Contributing

This is a portfolio project, but feedback and suggestions are welcome! Feel free to open issues or reach out.

## License

MIT License - see LICENSE file for details

## Author

**Jace Griffith**
- System Administrator & AI Security Engineer
- [GitHub](https://github.com/Griff-Reaper)
- [LinkedIn](https://linkedin.com/in/jace-griffith-jg11)

---

Built with Claude Sonnet 4 🤖