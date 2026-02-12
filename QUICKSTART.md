# Nexus-Sec Quick Start Guide

Get up and running with Nexus-Sec in 5 minutes. This guide walks you through installation, configuration, and your first automated incident response.

---

## 🚀 5-Minute Quick Start

### Step 1: Installation (1 minute)

```bash
# Clone the repository
git clone https://github.com/yourusername/nexus-sec.git
cd nexus-sec

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configuration (2 minutes)

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your API keys
nano .env  # or use your preferred editor
```

**Required Configuration:**
```bash
# Anthropic API for AI agents
ANTHROPIC_API_KEY=your-anthropic-key-here

# Optional: Threat Intelligence (for hunting)
ABUSEIPDB_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here

# Optional: SIEM Integration
SPLUNK_HEC_URL=https://splunk.company.com:8088
SPLUNK_HEC_TOKEN=your-hec-token
SPLUNK_INDEX=security
```

**Get Anthropic API Key:**
1. Go to https://console.anthropic.com/
2. Navigate to API Keys
3. Create new key
4. Copy to `.env` file

### Step 3: Verify Installation (1 minute)

```bash
# Test imports
python -c "from nexus_sec.playbooks.playbook_engine import PlaybookEngine; print('✓ Playbooks ready')"
python -c "from nexus_sec.hunting.threat_hunter import ThreatHuntingEngine; print('✓ Hunting ready')"
python -c "from nexus_sec.integrations.siem_integration import SIEMIntegrationManager; print('✓ SIEM ready')"
```

**Expected Output:**
```
✓ Playbooks ready
✓ Hunting ready
✓ SIEM ready
```

### Step 4: Run Your First Demo (1 minute)

```bash
# Run the comprehensive demo
python demo_new_features.py
```

**You should see:**
- ✅ Automated playbook execution
- ✅ Threat hunting with IOC searches
- ✅ SIEM integration setup

---

## 📋 Your First Playbook

Let's create a simple playbook for responding to suspicious login attempts.

### Create: `playbooks/failed_login_response.yml`

```yaml
name: failed_login_response
description: Automated response to suspicious failed login attempts
trigger:
  event_type: failed_login
  severity: medium

actions:
  # 1. Alert the SOC team
  - type: send_alert
    name: notify_security_team
    params:
      severity: medium
      message: "Multiple failed login attempts detected"
      channels: [email, slack]
  
  # 2. Block the source IP (only if > 10 attempts)
  - type: block_ip
    name: block_attacker_ip
    params:
      ip: ${source_ip}
      duration: 3600  # 1 hour
    condition: "failed_attempts >= 10"
  
  # 3. Create incident ticket
  - type: create_ticket
    name: create_security_incident
    params:
      title: "Failed Login Investigation - ${target_account}"
      priority: medium
      description: "Investigate failed login attempts from ${source_ip}"
```

### Test Your Playbook

```python
from nexus_sec.playbooks.playbook_engine import PlaybookEngine
from datetime import datetime

# Initialize engine
engine = PlaybookEngine()
engine.load_playbooks_from_directory("playbooks/")

# Simulate failed login event
failed_login_event = {
    "event_type": "failed_login",
    "timestamp": datetime.now().isoformat(),
    "source_ip": "203.0.113.42",
    "target_account": "admin",
    "failed_attempts": 15,
    "severity": 7
}

# Execute automated response
execution = engine.execute_playbook('failed_login_response', failed_login_event)

# Check results
print(f"Status: {execution.status.value}")
for action in execution.actions:
    print(f"  {action.action_name}: {action.status.value}")
```

**Expected Output:**
```
Status: completed
  notify_security_team: success
  block_attacker_ip: success
  create_security_incident: success
```

---

## 🔍 Your First Threat Hunt

Hunt for signs of lateral movement in your environment.

```python
from nexus_sec.hunting.threat_hunter import ThreatHuntingEngine

# Initialize hunter
hunter = ThreatHuntingEngine()

# Create hypothesis
hypothesis = hunter.create_hypothesis(
    title="Lateral Movement via RDP",
    description="Hunt for unusual RDP connections between workstations",
    tactics=["lateral-movement"],
    techniques=["T1021.001"],  # Remote Desktop Protocol
    data_sources=["windows_event_logs", "network_traffic"]
)

# Execute hunt
findings = hunter.execute_hunt(hypothesis.id)

# Review findings
print(f"Found {len(findings)} suspicious patterns")
for finding in findings:
    print(f"  {finding.finding_type}: {finding.description}")
    print(f"  Threat Level: {finding.threat_level.value}")
```

---

## 🔌 SIEM Integration Setup

Forward all Nexus-Sec events to your SIEM.

### Splunk Integration

```python
from nexus_sec.integrations.siem_integration import (
    SIEMIntegrationManager,
    SplunkConnector,
    SIEMEvent
)
from datetime import datetime

# Initialize SIEM manager
manager = SIEMIntegrationManager()

# Add Splunk connector
splunk = SplunkConnector(
    hec_url="https://splunk.company.com:8088",
    hec_token="your-hec-token-here",
    index="security",
    source="nexus-sec",
    verify_ssl=True
)
manager.add_connector("splunk_prod", splunk)

# Test connection
if splunk.test_connection():
    print("✓ Connected to Splunk")

# Send event
event = SIEMEvent(
    timestamp=datetime.now().isoformat(),
    event_type="malware_detection",
    severity="high",
    source="nexus-sec",
    message="Malware detected on workstation-042",
    details={
        "hostname": "workstation-042",
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "action": "quarantined"
    },
    tags=["malware", "endpoint", "automated_response"]
)

# Forward to SIEM
results = manager.send_to_all(event)
print(f"Event sent: {results}")
```

---

## 📦 Common Use Cases

### Use Case 1: Malware Detection & Response

**Scenario:** EDR detects malware on endpoint  
**Playbook:** `malware_detection_response.yml`  
**Actions:** Isolate host → Quarantine file → Collect evidence → Create ticket

```python
malware_event = {
    "event_type": "malware_detected",
    "hostname": "workstation-042",
    "file_path": "/tmp/suspicious.exe",
    "file_hash": "abc123...",
    "severity": 8
}

execution = engine.execute_playbook('malware_detection_response', malware_event)
```

### Use Case 2: Suspicious C2 Communication

**Scenario:** Firewall detects connection to known C2 server  
**Playbook:** `c2_communication_response.yml`  
**Actions:** Block IP → Isolate source host → Alert SOC → Hunt for related IOCs

```python
c2_event = {
    "event_type": "c2_communication",
    "source_host": "workstation-103",
    "destination_ip": "45.142.120.10",
    "c2_domain": "malicious-c2.example.com",
    "severity": 9
}

execution = engine.execute_playbook('c2_communication_response', c2_event)
```

### Use Case 3: Insider Threat Investigation

**Scenario:** Unusual data access patterns detected  
**Hunt Type:** Behavioral analysis  
**Goal:** Identify data exfiltration attempts

```python
# Run behavioral analysis
findings = hunter.behavioral_analyzer.analyze_data_exfiltration(threshold_mb=100)

# Review suspicious patterns
for finding in findings:
    if finding.threat_level == ThreatLevel.MALICIOUS:
        print(f"⚠️  Data exfiltration detected!")
        print(f"   Source: {finding.affected_assets[0]}")
        print(f"   Volume: {finding.indicators[0]['volume_mb']} MB")
```

---

## 🎯 Next Steps

### 1. Customize Playbooks
Edit the YAML playbooks in `playbooks/` to match your environment:
- Update alert channels (Slack webhook, email addresses)
- Configure EDR API endpoints (CrowdStrike, SentinelOne)
- Set appropriate thresholds and conditions

### 2. Integrate with Your Security Stack
- **EDR**: Replace simulated API calls with real integrations
  - CrowdStrike Falcon API
  - SentinelOne API
  - Microsoft Defender API
- **SIEM**: Configure your Splunk/Elastic credentials
- **Ticketing**: Integrate with Jira, ServiceNow, PagerDuty

### 3. Create Custom Playbooks
Common scenarios to automate:
- Ransomware response
- Data breach containment
- Phishing investigation
- Privilege escalation detection
- Persistence mechanism removal

### 4. Set Up Continuous Hunting
Schedule automated threat hunts:
```python
# Run daily hunt for IOCs from threat intel
def daily_ioc_hunt():
    iocs = threat_intel.get_latest_iocs()
    findings = hunter.hunt_ioc_list(iocs)
    # Forward findings to SIEM and create tickets
```

---

## 🐛 Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'nexus_sec'"

**Solution:** Make sure you're in the correct directory and virtual environment:
```bash
cd nexus-sec
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: "Playbook not found"

**Solution:** Check playbook directory exists and contains YAML files:
```bash
ls playbooks/
# Should show: malware_detection_response.yml, c2_communication_response.yml, etc.
```

### Issue: "Anthropic API key not found"

**Solution:** Set up your `.env` file:
```bash
cp .env.example .env
nano .env  # Add your ANTHROPIC_API_KEY
```

### Issue: Splunk HEC connection failed

**Solution:**
1. Verify HEC is enabled in Splunk (Settings → Data Inputs → HTTP Event Collector)
2. Check token has correct index permissions
3. Test with curl:
```bash
curl -k https://splunk.company.com:8088/services/collector \
  -H "Authorization: Splunk your-hec-token" \
  -d '{"event": "test"}'
```

---

## 📚 Additional Resources

- **Full Documentation:** See [README.md](README.md)
- **Architecture:** See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Playbook Reference:** See playbook YAML files for examples
- **API Documentation:** Use Python's built-in help:
  ```python
  from nexus_sec.playbooks.playbook_engine import PlaybookEngine
  help(PlaybookEngine)
  ```

---

## 💬 Getting Help

- **GitHub Issues:** Report bugs or request features
- **Documentation:** Check docstrings in source code
- **Examples:** Review `demo_new_features.py` for usage patterns

---

## ✅ Quick Start Checklist

- [ ] Repository cloned
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] `.env` file configured with API keys
- [ ] Demo runs successfully (`python demo_new_features.py`)
- [ ] First playbook executed
- [ ] SIEM integration tested (optional)
- [ ] Custom playbook created for your environment

**Congratulations! You're now running Nexus-Sec!** 🎉

---

*For production deployment guidance, see the [README.md](README.md) Enterprise Deployment section.*
