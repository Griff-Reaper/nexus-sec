"""
Proactive Threat Hunting Module for Nexus-Sec

This module implements hypothesis-driven threat hunting capabilities aligned with
the MITRE ATT&CK framework. It enables security teams to proactively search for
threats before they cause damage, rather than waiting for alerts.

Key Features:
    - IOC-based hunting (IPs, domains, file hashes, processes)
    - Behavioral analytics (lateral movement, data exfiltration, privilege escalation)
    - Hypothesis-driven investigations aligned with MITRE ATT&CK
    - Automated threat sweeps for continuous monitoring
    - Finding correlation and threat scoring

Threat Hunting Philosophy:
    Threat hunting is the proactive and iterative search through networks to detect
    and isolate advanced threats that evade existing security solutions. Unlike
    traditional detection which is reactive, hunting assumes compromise and searches
    for evidence of malicious activity.

Architecture:
    - IOCHunter: Searches for specific indicators across data sources
    - BehavioralAnalyzer: Detects suspicious patterns without known IOCs  
    - ThreatHuntingEngine: Orchestrates hunts, manages hypotheses, tracks findings

MITRE ATT&CK Integration:
    Hunts are organized by tactics (high-level goals) and techniques (methods).
    This allows hunters to think like adversaries and search for TTPs (Tactics,
    Techniques, and Procedures) rather than just signatures.
    
    Example Tactics:
        - Initial Access (TA0001)
        - Execution (TA0002)
        - Persistence (TA0003)
        - Lateral Movement (TA0008)
        - Exfiltration (TA0010)

Example:
    >>> # Initialize hunting engine
    >>> hunter = ThreatHuntingEngine()
    >>> 
    >>> # Create hypothesis-driven hunt
    >>> hypothesis = hunter.create_hypothesis(
    ...     title="APT28 Lateral Movement",
    ...     description="Hunt for signs of lateral movement using SMB",
    ...     tactics=["lateral-movement", "credential-access"],
    ...     techniques=["T1021.002", "T1003.001"],  # SMB, LSASS dumping
    ...     data_sources=["windows_event_logs", "network_traffic"]
    ... )
    >>> 
    >>> # Execute hunt
    >>> findings = hunter.execute_hunt(hypothesis.id)
    >>> 
    >>> # Hunt for specific IOCs
    >>> ioc_results = hunter.hunt_ioc_list({
    ...     "ips": ["45.142.120.10"],
    ...     "domains": ["malicious-c2.example.com"],
    ...     "hashes": ["d41d8cd98f00b204e9800998ecf8427e"]
    ... })

Best Practices:
    1. Start with intelligence-driven hypotheses
    2. Document findings thoroughly (even negatives)
    3. Iterate based on results
    4. Track metrics (dwell time, TTPs found, false positives)
    5. Share findings with threat intelligence team

Author: Jace - System Administrator & AI Security Engineer
Version: 1.0.0
"""

import logging
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import re


class HuntStatus(Enum):
    """Status of a threat hunt"""
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SUSPENDED = "suspended"


class ThreatLevel(Enum):
    """Threat level assessment"""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


@dataclass
class HuntHypothesis:
    """A structured threat hunting hypothesis aligned with MITRE ATT&CK.
    
    Represents a testable assumption about adversary behavior in the environment.
    Hypotheses guide structured hunting campaigns and ensure hunts are intelligence-
    driven rather than random searches.
    
    Intelligence-Driven Hunting:
        Good hypotheses come from threat intelligence, incident response lessons,
        red team exercises, or security research. They should be specific enough
        to guide data collection but flexible enough to adapt as you learn.
    
    Attributes:
        id (str): Unique identifier for this hypothesis (UUID recommended)
        title (str): Short, descriptive name (e.g., "APT28 Lateral Movement")
        description (str): Detailed description of what you're hunting for and why
        tactics (List[str]): MITRE ATT&CK tactic names (e.g., ["lateral-movement"])
        techniques (List[str]): MITRE ATT&CK technique IDs (e.g., ["T1021.002"])
        data_sources (List[str]): Required data sources for this hunt
            (e.g., ["windows_event_logs", "network_traffic", "edr_telemetry"])
        created_at (datetime): When this hypothesis was created
        status (HuntStatus): Current hunt status (planned, in_progress, completed)
    
    MITRE ATT&CK Technique Format:
        Technique IDs follow the pattern T####.### where:
        - T#### is the main technique (e.g., T1021 = Remote Services)
        - .### is the sub-technique (e.g., .002 = SMB/Windows Admin Shares)
        
        Example: T1021.002 = Remote Services: SMB/Windows Admin Shares
    
    Example:
        >>> hypothesis = HuntHypothesis(
        ...     id="hunt-001",
        ...     title="Kerberoasting Detection",
        ...     description="Hunt for signs of Kerberos ticket extraction",
        ...     tactics=["credential-access"],
        ...     techniques=["T1558.003"],  # Kerberoasting
        ...     data_sources=["windows_event_logs", "kerberos_logs"],
        ...     status=HuntStatus.PLANNED
        ... )
        >>> print(f"Hunting for: {hypothesis.title}")
        >>> print(f"Techniques: {', '.join(hypothesis.techniques)}")
    """
    id: str
    title: str
    description: str
    tactics: List[str]  # MITRE ATT&CK tactics (e.g., "lateral-movement")
    techniques: List[str]  # MITRE ATT&CK technique IDs (e.g., "T1021.002")
    data_sources: List[str]  # Required data sources for this hunt
    created_at: datetime = field(default_factory=datetime.now)
    status: HuntStatus = HuntStatus.PLANNED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert hypothesis to dictionary for serialization.
        
        Returns:
            Dict containing all hypothesis fields with ISO-formatted timestamp
        """
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "data_sources": self.data_sources,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value
        }


@dataclass
class HuntFinding:
    """A security finding discovered during threat hunting.
    
    Represents a suspicious or malicious activity discovered during proactive
    hunting. Findings should be thoroughly documented for investigation,
    incident response, and threat intelligence purposes.
    
    Finding Lifecycle:
        1. Discovery: Hunter identifies suspicious activity
        2. Analysis: Determine if it's malicious or benign
        3. Classification: Assign threat level and severity
        4. Documentation: Record indicators and affected assets
        5. Response: Trigger incident response if needed
        6. False Positive Check: Mark if determined to be benign
    
    Attributes:
        hunt_id (str): ID of the hypothesis/hunt that generated this finding
        finding_type (str): Category of finding (e.g., "lateral_movement",
            "data_exfiltration", "privilege_escalation")
        severity (str): Business impact level (low, medium, high, critical)
        description (str): Human-readable description of what was found
        indicators (List[Dict[str, Any]]): List of IOCs/TTPs observed
            Format: [{"type": "ip_address", "value": "1.2.3.4"}, ...]
        affected_assets (List[str]): Hosts/systems involved in this finding
        threat_level (ThreatLevel): Assessed threat level (benign to critical)
        timestamp (datetime): When this finding was discovered
        false_positive (bool): True if determined to be a false positive
        notes (str): Additional context, investigation notes, remediation steps
    
    Example:
        >>> finding = HuntFinding(
        ...     hunt_id="hunt-001",
        ...     finding_type="lateral_movement",
        ...     severity="high",
        ...     description="Unusual RDP connections from workstation to server",
        ...     indicators=[
        ...         {"type": "source_host", "value": "ws-042"},
        ...         {"type": "destination_host", "value": "srv-db-01"},
        ...         {"type": "account", "value": "admin"}
        ...     ],
        ...     affected_assets=["ws-042", "srv-db-01"],
        ...     threat_level=ThreatLevel.SUSPICIOUS,
        ...     notes="User account normally doesn't RDP to servers"
        ... )
    """
    hunt_id: str
    finding_type: str
    severity: str
    description: str
    indicators: List[Dict[str, Any]]
    affected_assets: List[str]
    threat_level: ThreatLevel
    timestamp: datetime = field(default_factory=datetime.now)
    false_positive: bool = False
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization and reporting.
        
        Returns:
            Dict containing all finding details with ISO-formatted timestamp
        """
        return {
            "hunt_id": self.hunt_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "description": self.description,
            "indicators": self.indicators,
            "affected_assets": self.affected_assets,
            "threat_level": self.threat_level.value,
            "timestamp": self.timestamp.isoformat(),
            "false_positive": self.false_positive,
            "notes": self.notes
        }


class IOCHunter:
    """Hunt for specific Indicators of Compromise across the environment.
    
    IOC hunting is signature-based threat detection where you search for known
    malicious indicators (IPs, domains, hashes, processes) across your environment.
    This is reactive hunting based on threat intelligence.
    
    Data Sources:
        In production, this connects to:
        - SIEM platforms (Splunk, Elastic) for logs
        - EDR platforms (CrowdStrike, SentinelOne) for endpoint data
        - Network monitoring (Zeek, Suricata) for traffic
        - Firewall logs for connection data
        - DNS logs for domain lookups
    
    Hunting Workflow:
        1. Receive IOC list from threat intelligence
        2. Search across all data sources
        3. Correlate matches across different systems
        4. Identify affected assets
        5. Generate findings for investigation
    
    Attributes:
        logger (logging.Logger): Hunter-specific logger
    
    Example:
        >>> hunter = IOCHunter()
        >>> 
        >>> # Hunt for malicious IPs from threat intel
        >>> results = hunter.hunt_ip_addresses(
        ...     target_ips=["45.142.120.10", "185.220.101.32"],
        ...     time_range=(start_time, end_time)
        ... )
        >>> 
        >>> # Check results
        >>> for result in results:
        ...     print(f"Found {result['ioc_value']} on {len(result['affected_hosts'])} hosts")
    """
    
    def __init__(self):
        """Initialize IOC hunter with logging."""
        self.logger = logging.getLogger("ioc_hunter")
    
    def hunt_ip_addresses(self, target_ips: List[str], 
                          time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Search for specific IP addresses across network logs and traffic.
        
        Searches firewall logs, proxy logs, DNS logs, and network traffic for
        communications with the target IP addresses. Useful for detecting
        command & control (C2) communications, data exfiltration, and lateral
        movement.
        
        Data Sources Searched (Production):
            - Firewall connection logs
            - Proxy/web gateway logs
            - DNS query logs  
            - Network flow data (NetFlow/IPFIX)
            - EDR network connections
        
        Args:
            target_ips: List of IP addresses to search for (e.g., known C2 servers)
            time_range: Optional (start_datetime, end_datetime) tuple to limit search.
                If None, searches recent data (implementation-specific window)
        
        Returns:
            List of dictionaries, one per matched IP:
                {
                    "ioc_type": "ip_address",
                    "ioc_value": "45.142.120.10",
                    "matches": [list of connection records],
                    "first_seen": "2024-02-11T10:00:00Z",
                    "last_seen": "2024-02-11T14:30:00Z",
                    "affected_hosts": ["ws-042", "ws-103"]
                }
        
        Example:
            >>> # Hunt for known C2 IPs
            >>> c2_ips = ["45.142.120.10", "185.220.101.32"]
            >>> results = hunter.hunt_ip_addresses(c2_ips)
            >>> 
            >>> for result in results:
            ...     if result['affected_hosts']:
            ...         print(f"⚠️  C2 communication detected!")
            ...         print(f"   IP: {result['ioc_value']}")
            ...         print(f"   Hosts: {', '.join(result['affected_hosts'])}")
        """
        self.logger.info(f"Hunting for {len(target_ips)} IP addresses")
        
        findings = []
        
        # In production: Query SIEM, firewall logs, proxy logs, etc.
        # For demo: Simulate findings
        for ip in target_ips:
            # Simulated search across data sources
            matches = self._search_network_logs(ip, time_range)
            
            if matches:
                findings.append({
                    "ioc_type": "ip_address",
                    "ioc_value": ip,
                    "matches": matches,
                    "first_seen": min(m["timestamp"] for m in matches),
                    "last_seen": max(m["timestamp"] for m in matches),
                    "affected_hosts": list(set(m["hostname"] for m in matches))
                })
        
        self.logger.info(f"Found {len(findings)} IP matches")
        return findings
    
    def hunt_file_hashes(self, target_hashes: List[str]) -> List[Dict[str, Any]]:
        """
        Search for file hashes across endpoints
        
        Args:
            target_hashes: List of file hashes (MD5, SHA1, SHA256)
            
        Returns:
            List of matches with file locations
        """
        self.logger.info(f"Hunting for {len(target_hashes)} file hashes")
        
        findings = []
        
        # In production: Query EDR, file integrity monitoring, etc.
        for hash_value in target_hashes:
            matches = self._search_file_hashes(hash_value)
            
            if matches:
                findings.append({
                    "ioc_type": "file_hash",
                    "ioc_value": hash_value,
                    "matches": matches,
                    "file_locations": [m["path"] for m in matches],
                    "affected_hosts": list(set(m["hostname"] for m in matches))
                })
        
        self.logger.info(f"Found {len(findings)} hash matches")
        return findings
    
    def hunt_domains(self, target_domains: List[str],
                     time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """
        Search for domain communications
        
        Args:
            target_domains: List of domains to search for
            time_range: Optional (start_time, end_time) tuple
            
        Returns:
            List of matches with DNS and HTTP logs
        """
        self.logger.info(f"Hunting for {len(target_domains)} domains")
        
        findings = []
        
        # In production: Query DNS logs, proxy logs, firewall logs
        for domain in target_domains:
            dns_matches = self._search_dns_logs(domain, time_range)
            http_matches = self._search_http_logs(domain, time_range)
            
            all_matches = dns_matches + http_matches
            
            if all_matches:
                findings.append({
                    "ioc_type": "domain",
                    "ioc_value": domain,
                    "dns_queries": len(dns_matches),
                    "http_connections": len(http_matches),
                    "matches": all_matches,
                    "affected_hosts": list(set(m["hostname"] for m in all_matches))
                })
        
        self.logger.info(f"Found {len(findings)} domain matches")
        return findings
    
    def hunt_process_names(self, target_processes: List[str]) -> List[Dict[str, Any]]:
        """
        Search for suspicious process names
        
        Args:
            target_processes: List of process names or patterns
            
        Returns:
            List of running or historical processes
        """
        self.logger.info(f"Hunting for {len(target_processes)} process names")
        
        findings = []
        
        # In production: Query EDR, Sysmon logs, process monitoring
        for process in target_processes:
            matches = self._search_processes(process)
            
            if matches:
                findings.append({
                    "ioc_type": "process_name",
                    "ioc_value": process,
                    "matches": matches,
                    "affected_hosts": list(set(m["hostname"] for m in matches)),
                    "command_lines": [m.get("command_line") for m in matches if m.get("command_line")]
                })
        
        self.logger.info(f"Found {len(findings)} process matches")
        return findings
    
    def _search_network_logs(self, ip: str, time_range: Optional[tuple]) -> List[Dict[str, Any]]:
        """Simulate network log search"""
        # In production: Query actual logs
        return []
    
    def _search_file_hashes(self, hash_value: str) -> List[Dict[str, Any]]:
        """Simulate file hash search"""
        return []
    
    def _search_dns_logs(self, domain: str, time_range: Optional[tuple]) -> List[Dict[str, Any]]:
        """Simulate DNS log search"""
        return []
    
    def _search_http_logs(self, domain: str, time_range: Optional[tuple]) -> List[Dict[str, Any]]:
        """Simulate HTTP log search"""
        return []
    
    def _search_processes(self, process_name: str) -> List[Dict[str, Any]]:
        """Simulate process search"""
        return []


class BehavioralAnalyzer:
    """Analyze system behaviors for suspicious patterns without known IOCs.
    
    Behavioral analysis detects threats based on how they act, not what they are.
    This catches novel threats, living-off-the-land attacks, and adversaries
    who evade signature-based detection. More difficult than IOC hunting but
    finds threats that IOC hunting misses.
    
    Detection Philosophy:
        Instead of asking "Is this a known bad thing?", behavioral analysis asks
        "Is this normal for my environment?" This requires understanding baselines
        and detecting anomalies or known adversary patterns.
    
    Behavioral Patterns Detected:
        - Lateral Movement: Unusual authentication patterns, tool usage, pivoting
        - Data Exfiltration: Large transfers, unusual protocols, after-hours activity
        - Privilege Escalation: Exploit attempts, credential dumping, token theft
        - Persistence: Registry modifications, scheduled tasks, service creation
    
    MITRE ATT&CK Alignment:
        Each analysis method maps to specific ATT&CK tactics and techniques,
        making findings intelligence-driven and actionable.
    
    Attributes:
        logger (logging.Logger): Analyzer-specific logger
    
    Data Requirements:
        - Windows Event Logs (authentication, process creation, registry)
        - Network traffic (NetFlow, full packet capture)
        - EDR telemetry (process lineage, file operations, network)
        - Firewall logs
        - DNS logs
    
    Example:
        >>> analyzer = BehavioralAnalyzer()
        >>> 
        >>> # Detect lateral movement
        >>> findings = analyzer.analyze_lateral_movement(time_window=24)
        >>> for finding in findings:
        ...     if finding.threat_level == ThreatLevel.MALICIOUS:
        ...         print(f"⚠️  Lateral movement detected!")
        ...         print(f"   Source: {finding.indicators[0]['value']}")
        ...         print(f"   Targets: {finding.affected_assets}")
    """
    
    def __init__(self):
        """Initialize behavioral analyzer with logging."""
        self.logger = logging.getLogger("behavioral_analyzer")
    
    def analyze_lateral_movement(self, time_window: int = 24) -> List[HuntFinding]:
        """Detect lateral movement patterns across the environment.
        
        Lateral movement (MITRE ATT&CK Tactic TA0008) is when an adversary moves
        through your environment to reach their objective. They exploit remote
        services, use admin tools, or abuse trust relationships.
        
        Detection Signals:
            - Single account accessing many systems rapidly
            - Workstation-to-workstation authentication (unusual)
            - Use of admin tools from non-admin workstations
            - Pass-the-hash indicators (same NTLM hash, no Kerberos)
            - Unusual service accounts being used interactively
            - RDP/SMB connections from unexpected sources
        
        MITRE ATT&CK Techniques:
            - T1021.001: Remote Desktop Protocol
            - T1021.002: SMB/Windows Admin Shares
            - T1021.006: Windows Remote Management
            - T1047: Windows Management Instrumentation
            - T1569.002: Service Execution
        
        Args:
            time_window: Hours of historical data to analyze (default: 24)
        
        Returns:
            List of HuntFindings for suspicious lateral movement patterns.
            Each finding includes source host, target hosts, account used,
            and specific indicators observed.
        
        Example:
            >>> findings = analyzer.analyze_lateral_movement(time_window=48)
            >>> 
            >>> # Filter for high-confidence findings
            >>> high_risk = [f for f in findings if f.threat_level == ThreatLevel.MALICIOUS]
            >>> print(f"Found {len(high_risk)} malicious lateral movement patterns")
        """
        self.logger.info(f"Analyzing lateral movement patterns (last {time_window}h)")
        
        findings = []
        
        # In production: Analyze authentication logs, network connections, SMB/RDP usage
        # Look for:
        # - Multiple hosts accessed from single source
        # - Unusual account usage patterns
        # - Admin tools (psexec, wmic, etc.)
        # - Pass-the-hash indicators
        
        # Simulated analysis
        suspicious_patterns = self._detect_lateral_movement_patterns(time_window)
        
        for pattern in suspicious_patterns:
            finding = HuntFinding(
                hunt_id="lateral_movement_hunt",
                finding_type="lateral_movement",
                severity="high",
                description=f"Suspicious lateral movement detected from {pattern['source_host']}",
                indicators=[
                    {"type": "source_host", "value": pattern["source_host"]},
                    {"type": "target_hosts", "value": pattern["target_hosts"]},
                    {"type": "account", "value": pattern["account"]}
                ],
                affected_assets=pattern["target_hosts"],
                threat_level=ThreatLevel.SUSPICIOUS
            )
            findings.append(finding)
        
        return findings
    
    def analyze_data_exfiltration(self, threshold_mb: int = 100) -> List[HuntFinding]:
        """
        Detect potential data exfiltration attempts
        
        Args:
            threshold_mb: Data transfer threshold in MB
            
        Returns:
            List of suspicious data transfer findings
        """
        self.logger.info(f"Analyzing data exfiltration (threshold: {threshold_mb}MB)")
        
        findings = []
        
        # In production: Analyze network traffic, cloud uploads, email, USB usage
        # Look for:
        # - Large outbound transfers
        # - Unusual cloud storage usage
        # - Compression/archiving of sensitive files
        # - After-hours transfers
        
        suspicious_transfers = self._detect_exfiltration_patterns(threshold_mb)
        
        for transfer in suspicious_transfers:
            finding = HuntFinding(
                hunt_id="data_exfil_hunt",
                finding_type="data_exfiltration",
                severity="critical",
                description=f"Large data transfer detected: {transfer['size_mb']}MB to {transfer['destination']}",
                indicators=[
                    {"type": "source_host", "value": transfer["source_host"]},
                    {"type": "destination", "value": transfer["destination"]},
                    {"type": "bytes_transferred", "value": transfer["size_mb"] * 1024 * 1024}
                ],
                affected_assets=[transfer["source_host"]],
                threat_level=ThreatLevel.MALICIOUS
            )
            findings.append(finding)
        
        return findings
    
    def analyze_privilege_escalation(self) -> List[HuntFinding]:
        """
        Detect potential privilege escalation attempts
        
        Returns:
            List of privilege escalation findings
        """
        self.logger.info("Analyzing privilege escalation patterns")
        
        findings = []
        
        # In production: Analyze:
        # - Unusual privilege changes
        # - Exploitation of SUID/sudo
        # - Token manipulation
        # - UAC bypass attempts
        # - Credential dumping tools
        
        escalation_attempts = self._detect_privilege_escalation()
        
        for attempt in escalation_attempts:
            finding = HuntFinding(
                hunt_id="privesc_hunt",
                finding_type="privilege_escalation",
                severity="high",
                description=f"Privilege escalation attempt on {attempt['hostname']}",
                indicators=[
                    {"type": "hostname", "value": attempt["hostname"]},
                    {"type": "account", "value": attempt["account"]},
                    {"type": "method", "value": attempt["method"]}
                ],
                affected_assets=[attempt["hostname"]],
                threat_level=ThreatLevel.SUSPICIOUS
            )
            findings.append(finding)
        
        return findings
    
    def analyze_persistence_mechanisms(self) -> List[HuntFinding]:
        """
        Detect persistence mechanisms
        
        Returns:
            List of persistence mechanism findings
        """
        self.logger.info("Analyzing persistence mechanisms")
        
        findings = []
        
        # In production: Look for:
        # - Registry run keys
        # - Scheduled tasks
        # - Services
        # - WMI subscriptions
        # - Startup folder items
        # - DLL hijacking
        
        persistence_items = self._detect_persistence_mechanisms()
        
        for item in persistence_items:
            finding = HuntFinding(
                hunt_id="persistence_hunt",
                finding_type="persistence_mechanism",
                severity="medium",
                description=f"Suspicious persistence mechanism: {item['mechanism']}",
                indicators=[
                    {"type": "hostname", "value": item["hostname"]},
                    {"type": "mechanism", "value": item["mechanism"]},
                    {"type": "location", "value": item["location"]}
                ],
                affected_assets=[item["hostname"]],
                threat_level=ThreatLevel.SUSPICIOUS
            )
            findings.append(finding)
        
        return findings
    
    def _detect_lateral_movement_patterns(self, time_window: int) -> List[Dict[str, Any]]:
        """Simulate lateral movement detection"""
        # In production: Query actual logs and apply detection logic
        return []
    
    def _detect_exfiltration_patterns(self, threshold_mb: int) -> List[Dict[str, Any]]:
        """Simulate exfiltration detection"""
        return []
    
    def _detect_privilege_escalation(self) -> List[Dict[str, Any]]:
        """Simulate privilege escalation detection"""
        return []
    
    def _detect_persistence_mechanisms(self) -> List[Dict[str, Any]]:
        """Simulate persistence detection"""
        return []


class ThreatHuntingEngine:
    """Central orchestrator for proactive threat hunting operations.
    
    The ThreatHuntingEngine coordinates all hunting activities, managing hypotheses,
    executing hunts using both IOC and behavioral methods, tracking findings, and
    maintaining an audit trail of hunting operations.
    
    Threat Hunting Methodology:
        1. Intelligence Gathering: Collect threat intel, understand adversaries
        2. Hypothesis Formation: Create testable assumptions about adversary behavior
        3. Investigation: Use tools and techniques to test hypothesis
        4. Pattern/TTP Discovery: Document findings and patterns
        5. Analytics Enhancement: Improve detection based on findings
        6. Repeat: Continuous hunting cycle
    
    Key Capabilities:
        - Hypothesis-driven hunting aligned with MITRE ATT&CK
        - IOC-based hunting for known indicators
        - Behavioral analytics for unknown threats
        - Finding correlation and deduplication
        - Automated threat sweeps
        - Hunt metrics and effectiveness tracking
    
    Architecture:
        The engine combines two hunting approaches:
        - IOCHunter: Signature-based hunting for known IOCs
        - BehavioralAnalyzer: Pattern-based hunting for suspicious behaviors
        
        Both feed findings into a central repository for correlation and analysis.
    
    Attributes:
        logger (logging.Logger): Engine-specific logger
        ioc_hunter (IOCHunter): IOC hunting component
        behavioral_analyzer (BehavioralAnalyzer): Behavioral analysis component
        hypotheses (Dict[str, HuntHypothesis]): Active and completed hypotheses
        findings (List[HuntFinding]): All findings from hunting operations
    
    Example:
        >>> # Initialize engine
        >>> hunter = ThreatHuntingEngine()
        >>> 
        >>> # Create hypothesis
        >>> hypothesis = hunter.create_hypothesis(
        ...     title="APT29 Credential Access",
        ...     description="Hunt for credential dumping techniques",
        ...     tactics=["credential-access"],
        ...     techniques=["T1003.001", "T1003.002"],  # LSASS, SAM
        ...     data_sources=["windows_event_logs", "edr_telemetry"]
        ... )
        >>> 
        >>> # Execute hunt
        >>> findings = hunter.execute_hunt(hypothesis.id)
        >>> 
        >>> # Run automated sweep
        >>> sweep_results = hunter.run_automated_sweep()
        >>> 
        >>> # Hunt specific IOCs
        >>> ioc_results = hunter.hunt_ioc_list({
        ...     "ips": ["45.142.120.10"],
        ...     "hashes": ["abc123..."]
        ... })
    
    Best Practices:
        - Start hunts with specific, testable hypotheses
        - Document all findings (including negatives)
        - Share findings with detection engineering team
        - Track hunt effectiveness metrics
        - Iterate and refine based on results
    """
    
    def __init__(self):
        """Initialize the threat hunting engine.
        
        Sets up IOC hunting, behavioral analysis, and tracking structures.
        """
        self.logger = logging.getLogger("threat_hunting")
        self.ioc_hunter = IOCHunter()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.hypotheses: Dict[str, HuntHypothesis] = {}
        self.findings: List[HuntFinding] = []
    
    def create_hypothesis(self, title: str, description: str,
                         tactics: List[str], techniques: List[str],
                         data_sources: List[str]) -> HuntHypothesis:
        """Create a new threat hunting hypothesis aligned with MITRE ATT&CK.
        
        Hypotheses guide structured hunting by defining what you're looking for
        and why. Good hypotheses are intelligence-driven, testable, and specific.
        
        Hypothesis Quality Checklist:
            ✓ Based on threat intelligence or incident lessons learned
            ✓ Testable with available data sources
            ✓ Specific enough to guide hunting
            ✓ Mapped to MITRE ATT&CK for standardization
            ✓ Documents expected indicators
        
        Args:
            title: Short, descriptive name (e.g., "Kerberoasting Detection")
            description: Detailed explanation of what you're hunting for and why.
                Should include threat actor context, techniques expected, and
                the business risk being addressed.
            tactics: List of MITRE ATT&CK tactic names (e.g., ["lateral-movement"])
            techniques: List of MITRE ATT&CK technique IDs (e.g., ["T1021.002"])
                Format: T####.### where #### is technique and ### is sub-technique
            data_sources: Required data sources for this hunt
                (e.g., ["windows_event_logs", "network_traffic", "edr_telemetry"])
        
        Returns:
            HuntHypothesis: Created hypothesis with unique ID, ready to execute
        
        Example:
            >>> hypothesis = hunter.create_hypothesis(
            ...     title="Cobalt Strike Beacon Detection",
            ...     description="Hunt for Cobalt Strike beacons based on recent APT29 activity",
            ...     tactics=["command-and-control", "execution"],
            ...     techniques=["T1071.001", "T1059.003"],  # Web Protocols, Windows Command Shell
            ...     data_sources=["network_traffic", "dns_logs", "proxy_logs", "edr_telemetry"]
            ... )
            >>> print(f"Created: {hypothesis.title} ({hypothesis.id})")
        """
        import uuid
        
        hypothesis = HuntHypothesis(
            id=str(uuid.uuid4()),
            title=title,
            description=description,
            tactics=tactics,
            techniques=techniques,
            data_sources=data_sources
        )
        
        self.hypotheses[hypothesis.id] = hypothesis
        self.logger.info(f"Created hunting hypothesis: {title}")
        
        return hypothesis
    
    def execute_hunt(self, hypothesis_id: str) -> List[HuntFinding]:
        """
        Execute a threat hunt based on a hypothesis
        
        Args:
            hypothesis_id: ID of hypothesis to hunt
            
        Returns:
            List of findings
        """
        if hypothesis_id not in self.hypotheses:
            raise ValueError(f"Hypothesis not found: {hypothesis_id}")
        
        hypothesis = self.hypotheses[hypothesis_id]
        hypothesis.status = HuntStatus.IN_PROGRESS
        
        self.logger.info(f"Executing hunt: {hypothesis.title}")
        
        hunt_findings = []
        
        # Execute different hunt types based on tactics
        if "lateral-movement" in hypothesis.tactics:
            findings = self.behavioral_analyzer.analyze_lateral_movement()
            hunt_findings.extend(findings)
        
        if "exfiltration" in hypothesis.tactics:
            findings = self.behavioral_analyzer.analyze_data_exfiltration()
            hunt_findings.extend(findings)
        
        if "privilege-escalation" in hypothesis.tactics:
            findings = self.behavioral_analyzer.analyze_privilege_escalation()
            hunt_findings.extend(findings)
        
        if "persistence" in hypothesis.tactics:
            findings = self.behavioral_analyzer.analyze_persistence_mechanisms()
            hunt_findings.extend(findings)
        
        # Store findings
        for finding in hunt_findings:
            finding.hunt_id = hypothesis_id
        
        self.findings.extend(hunt_findings)
        hypothesis.status = HuntStatus.COMPLETED
        
        self.logger.info(f"Hunt completed: {len(hunt_findings)} findings")
        return hunt_findings
    
    def hunt_ioc_list(self, ioc_list: Dict[str, List[str]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Hunt for a list of IOCs
        
        Args:
            ioc_list: Dictionary of IOC types and values
                     e.g., {"ips": [...], "domains": [...], "hashes": [...]}
        
        Returns:
            Dictionary of findings by IOC type
        """
        results = {}
        
        if "ips" in ioc_list:
            results["ips"] = self.ioc_hunter.hunt_ip_addresses(ioc_list["ips"])
        
        if "domains" in ioc_list:
            results["domains"] = self.ioc_hunter.hunt_domains(ioc_list["domains"])
        
        if "hashes" in ioc_list:
            results["hashes"] = self.ioc_hunter.hunt_file_hashes(ioc_list["hashes"])
        
        if "processes" in ioc_list:
            results["processes"] = self.ioc_hunter.hunt_process_names(ioc_list["processes"])
        
        return results
    
    def run_automated_sweep(self) -> Dict[str, List[HuntFinding]]:
        """
        Run automated threat hunting sweep
        
        Returns:
            Dictionary of findings by category
        """
        self.logger.info("Starting automated threat hunting sweep")
        
        results = {
            "lateral_movement": self.behavioral_analyzer.analyze_lateral_movement(),
            "data_exfiltration": self.behavioral_analyzer.analyze_data_exfiltration(),
            "privilege_escalation": self.behavioral_analyzer.analyze_privilege_escalation(),
            "persistence": self.behavioral_analyzer.analyze_persistence_mechanisms()
        }
        
        # Store all findings
        for category_findings in results.values():
            self.findings.extend(category_findings)
        
        total_findings = sum(len(findings) for findings in results.values())
        self.logger.info(f"Automated sweep completed: {total_findings} findings")
        
        return results
    
    def get_findings(self, hunt_id: Optional[str] = None,
                    threat_level: Optional[ThreatLevel] = None) -> List[HuntFinding]:
        """Get findings with optional filtering"""
        findings = self.findings
        
        if hunt_id:
            findings = [f for f in findings if f.hunt_id == hunt_id]
        
        if threat_level:
            findings = [f for f in findings if f.threat_level == threat_level]
        
        return findings
    
    def export_findings(self, format: str = "json") -> str:
        """Export findings in specified format"""
        import json
        
        if format == "json":
            return json.dumps([f.to_dict() for f in self.findings], indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")