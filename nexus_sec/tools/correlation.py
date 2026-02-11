"""
Threat Correlation Engine for Nexus-Sec

Correlates threat intelligence with security events to:
- Detect related IOCs (same campaign, similar TTPs)
- Identify attack patterns across multiple events
- Build threat actor profiles
- Track incident timelines
"""

from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib


@dataclass
class SecurityEvent:
    """Represents a security event to correlate"""
    event_id: str
    timestamp: datetime
    event_type: str  # e.g., "network_connection", "file_execution", "login_attempt"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    domain: Optional[str] = None
    file_hash: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def extract_iocs(self) -> List[tuple]:
        """Extract all IOCs from this event"""
        iocs = []
        if self.source_ip:
            iocs.append((self.source_ip, "ip"))
        if self.dest_ip:
            iocs.append((self.dest_ip, "ip"))
        if self.domain:
            iocs.append((self.domain, "domain"))
        if self.file_hash:
            iocs.append((self.file_hash, "hash"))
        return iocs


@dataclass
class CorrelatedIncident:
    """Group of related security events forming an incident"""
    incident_id: str
    first_seen: datetime
    last_seen: datetime
    events: List[SecurityEvent]
    shared_iocs: Set[str]
    threat_actors: Set[str]
    attack_techniques: Set[str]
    severity_score: float
    confidence: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting"""
        return {
            "incident_id": self.incident_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_minutes": (self.last_seen - self.first_seen).total_seconds() / 60,
            "event_count": len(self.events),
            "shared_iocs": list(self.shared_iocs),
            "threat_actors": list(self.threat_actors),
            "attack_techniques": list(self.attack_techniques),
            "severity_score": self.severity_score,
            "confidence": self.confidence
        }


class ThreatCorrelationEngine:
    """
    Correlates security events and threat intelligence to identify:
    - Related incidents
    - Attack campaigns
    - Threat actor patterns
    """
    
    def __init__(self, time_window_hours: int = 24):
        """
        Initialize correlation engine
        
        Args:
            time_window_hours: Time window for event correlation
        """
        self.time_window = timedelta(hours=time_window_hours)
        self.events: List[SecurityEvent] = []
        self.ioc_index: Dict[str, List[SecurityEvent]] = defaultdict(list)
        self.user_index: Dict[str, List[SecurityEvent]] = defaultdict(list)
        self.incidents: List[CorrelatedIncident] = []
        
    def add_event(self, event: SecurityEvent):
        """
        Add a security event and index it
        
        Args:
            event: SecurityEvent to add
        """
        self.events.append(event)
        
        # Index by IOCs
        for ioc, ioc_type in event.extract_iocs():
            self.ioc_index[ioc].append(event)
        
        # Index by user
        if event.user:
            self.user_index[event.user].append(event)
    
    def find_related_events(self, event: SecurityEvent, max_age_hours: int = 24) -> List[SecurityEvent]:
        """
        Find events related to a given event based on shared IOCs
        
        Args:
            event: The event to find related events for
            max_age_hours: Maximum age of related events
            
        Returns:
            List of related events
        """
        related = set()
        cutoff_time = event.timestamp - timedelta(hours=max_age_hours)
        
        # Find events with shared IOCs
        for ioc, ioc_type in event.extract_iocs():
            if ioc in self.ioc_index:
                for related_event in self.ioc_index[ioc]:
                    # Check time window
                    if related_event.timestamp >= cutoff_time:
                        if related_event.event_id != event.event_id:
                            related.add(related_event)
        
        # Find events from same user (potential compromised account)
        if event.user and event.user in self.user_index:
            for user_event in self.user_index[event.user]:
                if user_event.timestamp >= cutoff_time:
                    if user_event.event_id != event.event_id:
                        related.add(user_event)
        
        return list(related)
    
    def correlate_events(self, threat_intel_results: Dict[str, Any] = None) -> List[CorrelatedIncident]:
        """
        Correlate all events to identify incidents
        
        Args:
            threat_intel_results: Optional threat intel data to enrich correlation
            
        Returns:
            List of correlated incidents
        """
        incidents = []
        processed_events = set()
        
        # Sort events by timestamp
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        for event in sorted_events:
            if event.event_id in processed_events:
                continue
            
            # Find all related events
            related = self.find_related_events(event)
            
            if related:
                # Create incident from related events
                incident_events = [event] + related
                
                # Mark as processed
                for e in incident_events:
                    processed_events.add(e.event_id)
                
                # Extract shared IOCs
                ioc_sets = [set(ioc for ioc, _ in e.extract_iocs()) for e in incident_events]
                shared_iocs = set.intersection(*ioc_sets) if len(ioc_sets) > 1 else ioc_sets[0] if ioc_sets else set()
                
                # Calculate incident metadata
                timestamps = [e.timestamp for e in incident_events]
                first_seen = min(timestamps)
                last_seen = max(timestamps)
                
                # Extract threat actors and techniques from threat intel
                threat_actors = set()
                attack_techniques = set()
                
                if threat_intel_results:
                    for ioc in shared_iocs:
                        if ioc in threat_intel_results:
                            intel = threat_intel_results[ioc]
                            if "tags" in intel:
                                for tag in intel["tags"]:
                                    if "apt" in tag.lower():
                                        threat_actors.add(tag)
                            if "threat_types" in intel:
                                attack_techniques.update(intel["threat_types"])
                
                # Calculate severity and confidence
                severity_score = len(incident_events) * 10  # Simple scoring
                confidence = min(len(shared_iocs) / 3, 1.0)  # More shared IOCs = higher confidence
                
                incident = CorrelatedIncident(
                    incident_id=self._generate_incident_id(incident_events),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    events=incident_events,
                    shared_iocs=shared_iocs,
                    threat_actors=threat_actors,
                    attack_techniques=attack_techniques,
                    severity_score=min(severity_score, 100),
                    confidence=confidence
                )
                
                incidents.append(incident)
        
        self.incidents = incidents
        return incidents
    
    def _generate_incident_id(self, events: List[SecurityEvent]) -> str:
        """Generate a unique incident ID based on events"""
        event_ids = "-".join(sorted(e.event_id for e in events[:5]))  # Use first 5 events
        return hashlib.md5(event_ids.encode()).hexdigest()[:16]
    
    def get_incident_timeline(self, incident: CorrelatedIncident) -> List[Dict[str, Any]]:
        """
        Generate a timeline of events for an incident
        
        Args:
            incident: The incident to generate timeline for
            
        Returns:
            List of timeline entries
        """
        timeline = []
        
        for event in sorted(incident.events, key=lambda e: e.timestamp):
            timeline.append({
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "dest_ip": event.dest_ip,
                "domain": event.domain,
                "user": event.user,
                "description": f"{event.event_type} event"
            })
        
        return timeline
    
    def get_attack_chain(self, incident: CorrelatedIncident) -> Dict[str, Any]:
        """
        Analyze the attack chain (kill chain phases) for an incident
        
        Args:
            incident: The incident to analyze
            
        Returns:
            Dict mapping kill chain phases to events
        """
        # Simple kill chain mapping based on event types
        kill_chain = {
            "Reconnaissance": [],
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Command & Control": [],
            "Exfiltration": []
        }
        
        for event in incident.events:
            if "scan" in event.event_type.lower():
                kill_chain["Reconnaissance"].append(event.event_id)
            elif "login" in event.event_type.lower() or "auth" in event.event_type.lower():
                kill_chain["Initial Access"].append(event.event_id)
            elif "execution" in event.event_type.lower() or "process" in event.event_type.lower():
                kill_chain["Execution"].append(event.event_id)
            elif "network" in event.event_type.lower():
                kill_chain["Command & Control"].append(event.event_id)
            elif "file_transfer" in event.event_type.lower() or "upload" in event.event_type.lower():
                kill_chain["Exfiltration"].append(event.event_id)
        
        # Remove empty phases
        return {phase: events for phase, events in kill_chain.items() if events}
    
    def generate_incident_report(self, incident: CorrelatedIncident) -> Dict[str, Any]:
        """
        Generate a comprehensive incident report
        
        Args:
            incident: The incident to report on
            
        Returns:
            Dict containing full incident report
        """
        return {
            "incident_summary": incident.to_dict(),
            "timeline": self.get_incident_timeline(incident),
            "attack_chain": self.get_attack_chain(incident),
            "recommendations": self._generate_recommendations(incident)
        }
    
    def _generate_recommendations(self, incident: CorrelatedIncident) -> List[str]:
        """Generate security recommendations based on incident"""
        recommendations = []
        
        if incident.severity_score > 70:
            recommendations.append("CRITICAL: Immediate containment required")
            recommendations.append("Isolate affected systems from network")
        
        if "apt" in str(incident.threat_actors).lower():
            recommendations.append("Advanced Persistent Threat detected - engage incident response team")
            recommendations.append("Perform full forensic analysis")
        
        if len(incident.shared_iocs) > 5:
            recommendations.append("Multiple shared IOCs indicate coordinated attack")
            recommendations.append("Update threat intelligence feeds with IOCs")
        
        if not recommendations:
            recommendations.append("Monitor for additional suspicious activity")
            recommendations.append("Review security logs for related events")
        
        return recommendations
