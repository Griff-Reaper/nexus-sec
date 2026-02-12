# Creating Professional Architecture Diagram in draw.io

If you want to create a polished, professional architecture diagram, follow these steps using draw.io (free tool).

## Quick Setup

1. Go to https://app.diagrams.net/ (draw.io)
2. Choose "Create New Diagram"
3. Select "Blank Diagram"

## Layout Structure

### Layer 1: External Sources (Top)
- 3 boxes for threat intel feeds (AbuseIPDB, AlienVault OTX, VirusTotal)
- 3 boxes for SIEM platforms (Splunk, Elasticsearch, Syslog)
- Color: Gray (#607D8B)

### Layer 2: Nexus-Sec Core (Middle) - Group into 4 sections:

**Detection Layer** (Green #4CAF50)
- Detection Agents (Claude AI)
- Threat Hunting Engine

**Intelligence Layer** (Blue #2196F3)  
- Threat Intelligence Manager
- Correlation Engine

**Response Layer** (Orange #FF9800)
- Playbook Engine
- 6 response action boxes

**Integration Layer** (Purple #9C27B0)
- SIEM Manager

### Layer 3: Target Environment (Bottom)
- EDR/Endpoint
- Firewall
- Log Sources
- Network Devices
- Color: Gray (#607D8B)

## Drawing Instructions

1. **Draw boxes** using Rectangle tool
2. **Add rounded corners** (right-click → Edit Style → rounded=1)
3. **Group related components** (Ctrl+G after selecting multiple)
4. **Add arrows** showing data flow:
   - Threat Intel → Intelligence Layer
   - Logs → Detection Layer
   - Detection → Response
   - Everything → SIEM Manager → External SIEMs
5. **Add labels** to arrows (double-click arrow)

## Pro Tips

- Use consistent spacing (40px between boxes)
- Align everything (use alignment toolbar)
- Group by color = group by function
- Use containers/groups for each layer
- Export as PNG at 2x resolution for crisp GitHub rendering

## Quick Template

Or use this faster method:

1. Go to draw.io
2. File → Import From → URL
3. Paste: [I can create an XML template if needed]
4. Customize colors and text

## Export

File → Export As → PNG
- Settings:
  - Border width: 10
  - Transparent background: NO (use white)
  - Resolution: 200%
  
Save as: `docs/images/architecture.png`

---

**Time estimate**: 15-20 minutes for a polished diagram
**Alternative**: Use the Mermaid version (auto-renders on GitHub, zero effort!)
