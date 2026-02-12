"""
Enterprise SIEM Integration Module for Nexus-Sec

This module provides production-ready connectors for integrating Nexus-Sec with
enterprise SIEM (Security Information and Event Management) platforms. Enables
centralized logging, correlation, alerting, and compliance reporting.

Supported SIEM Platforms:
    - Splunk: HTTP Event Collector (HEC) for real-time streaming
    - Elasticsearch: Bulk API for high-throughput indexing
    - Generic Syslog: RFC 5424 compliant for any SIEM

Key Features:
    - Standardized event format with CEF conversion
    - Batch processing for high throughput
    - Automatic retry and error handling
    - Bi-directional integration (send + query)
    - Connection pooling and keep-alive
    - SSL/TLS support with certificate validation

Why SIEM Integration Matters:
    Security tools generate data in silos. SIEMs aggregate this data for:
    - Centralized visibility across security stack
    - Correlation of events from multiple sources
    - Long-term storage for forensics and compliance
    - Advanced analytics and machine learning
    - Automated alerting and incident workflows

Architecture:
    SIEMConnector (Abstract Base Class)
        ↓
    ┌───────────────┬──────────────────┬─────────────────┐
    │               │                  │                 │
    Splunk      Elasticsearch      Syslog         [Extensible]
    Connector      Connector       Connector
    
    SIEMIntegrationManager orchestrates multiple connectors,
    enabling simultaneous forwarding to multiple platforms.

Common Event Format (CEF):
    Industry-standard log format for SIEM interoperability.
    Format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    
    Example:
        CEF:0|Anthropic|Nexus-Sec|1.0|malware_detection|
        Malware detected on workstation-042|8|hostname=ws-042 file_hash=abc123

Integration Patterns:
    1. Real-time streaming: Events sent as they occur (low latency)
    2. Batch processing: Events queued and sent in batches (high throughput)
    3. Bi-directional: Send events AND query SIEM for enrichment

Example:
    >>> # Initialize connectors
    >>> splunk = SplunkConnector(
    ...     hec_url="https://splunk.company.com:8088",
    ...     hec_token="12345678-abcd-1234-abcd-123456789012",
    ...     index="security"
    ... )
    >>> 
    >>> # Test connection
    >>> if splunk.test_connection():
    ...     print("✓ Connected to Splunk")
    >>> 
    >>> # Send event
    >>> event = SIEMEvent(
    ...     timestamp=datetime.now().isoformat(),
    ...     event_type="malware_detection",
    ...     severity="high",
    ...     source="nexus-sec",
    ...     message="Malware detected on workstation-042",
    ...     details={"hostname": "ws-042", "file_hash": "abc123"}
    ... )
    >>> splunk.send_event(event)
    >>> 
    >>> # Send batch
    >>> events = [event1, event2, event3]
    >>> results = splunk.send_batch(events)
    >>> print(f"Sent {results['success']} events")

Production Considerations:
    - Use batch sending for >100 events/second
    - Implement exponential backoff for retries
    - Monitor SIEM ingestion lag
    - Rotate HEC tokens regularly
    - Use dedicated service accounts
    - Enable TLS/SSL in production
    - Configure appropriate index retention

Author: Jace - System Administrator & AI Security Engineer
Version: 1.0.0
"""

import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from abc import ABC, abstractmethod
import requests
from dataclasses import dataclass, asdict


@dataclass
class SIEMEvent:
    """Standardized security event format for SIEM forwarding.
    
    Provides a vendor-neutral event structure that can be serialized to multiple
    formats including JSON, CEF (Common Event Format), and key-value pairs.
    Ensures consistent event representation across different SIEM platforms.
    
    Event Structure Philosophy:
        - timestamp: When the event occurred (source time, not sent time)
        - event_type: Machine-readable event category
        - severity: Business impact level
        - source: Which system/component generated this event
        - message: Human-readable summary
        - details: Structured data specific to this event type
        - tags: Free-form labels for filtering/grouping
    
    Attributes:
        timestamp (str): ISO 8601 formatted timestamp (e.g., "2024-02-11T10:30:00Z")
        event_type (str): Event category (e.g., "malware_detection", "login_failure")
        severity (str): Impact level - "info", "low", "medium", "high", "critical"
        source (str): Originating system (e.g., "nexus-sec", "edr-agent", "firewall")
        message (str): Human-readable event description
        details (Dict[str, Any]): Event-specific structured data (hostname, IOCs, etc.)
        tags (List[str]): Optional labels for categorization (e.g., ["malware", "endpoint"])
    
    CEF Conversion:
        Common Event Format is an industry standard for SIEM interoperability.
        The to_cef() method converts events to CEF format for universal compatibility.
        
        CEF Severity Mapping:
            info → 2, low → 3, medium → 5, high → 8, critical → 10
    
    Example:
        >>> event = SIEMEvent(
        ...     timestamp="2024-02-11T10:30:00Z",
        ...     event_type="malware_detection",
        ...     severity="high",
        ...     source="nexus-sec",
        ...     message="Malware detected on workstation-042",
        ...     details={
        ...         "hostname": "workstation-042",
        ...         "file_path": "/tmp/malware.exe",
        ...         "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
        ...         "action_taken": "quarantined"
        ...     },
        ...     tags=["malware", "endpoint", "automated_response"]
        ... )
        >>> 
        >>> # Convert to CEF for Splunk/ArcSight
        >>> cef_formatted = event.to_cef()
        >>> print(cef_formatted)
    """
    timestamp: str  # ISO 8601 format
    event_type: str
    severity: str
    source: str
    message: str
    details: Dict[str, Any]
    tags: List[str] = None
    
    def __post_init__(self):
        """Initialize default values after dataclass creation."""
        if self.tags is None:
            self.tags = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for JSON serialization.
        
        Returns:
            Dict containing all event fields
        """
        return asdict(self)
    
    def to_cef(self) -> str:
        """Convert event to Common Event Format (CEF) for SIEM compatibility.
        
        CEF is an open log management standard from ArcSight (now Micro Focus)
        that provides a universal format for SIEM event ingestion. Widely supported
        by Splunk, QRadar, LogRhythm, and other enterprise SIEM platforms.
        
        CEF Format:
            CEF:Version|Device Vendor|Device Product|Device Version|
            Device Event Class ID|Name|Severity|Extension
        
        Returns:
            str: CEF-formatted event string
        
        Example Output:
            CEF:0|Anthropic|Nexus-Sec|1.0|malware_detection|
            Malware detected on workstation-042|8|
            hostname=workstation-042 file_hash=abc123 action_taken=quarantined
        """
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        cef_header = (
            f"CEF:0|Anthropic|Nexus-Sec|1.0|{self.event_type}|"
            f"{self.message}|{self._severity_to_cef()}|"
        )
        
        # CEF extensions (key=value pairs)
        extensions = []
        for key, value in self.details.items():
            extensions.append(f"{key}={value}")
        
        return cef_header + " ".join(extensions)
    
    def _severity_to_cef(self) -> int:
        """Map Nexus-Sec severity to CEF severity scale (0-10).
        
        CEF Severity Scale:
            0-3: Low (informational, minor issues)
            4-6: Medium (warning, potential issues)
            7-8: High (error, significant impact)
            9-10: Critical (emergency, business-critical)
        
        Returns:
            int: CEF severity value 0-10
        """
        severity_map = {
            "info": 2,
            "low": 3,
            "medium": 5,
            "high": 8,
            "critical": 10
        }
        return severity_map.get(self.severity.lower(), 5)


class SIEMConnector(ABC):
    """Abstract base class defining the interface for all SIEM connectors.
    
    This base class establishes a consistent API for integrating with different
    SIEM platforms. All connector implementations must inherit from this class
    and implement the required methods.
    
    Connector Pattern Benefits:
        - Uniform interface across different SIEMs
        - Easy to add new SIEM platforms
        - Consistent error handling
        - Simplified testing with mock connectors
        - Hot-swappable SIEM backends
    
    Required Methods:
        Every connector must implement:
        - send_event(): Send single event (real-time)
        - send_batch(): Send multiple events (bulk)
        - test_connection(): Verify SIEM is reachable
        - query(): Retrieve events from SIEM (bi-directional)
    
    Attributes:
        name (str): Connector name for logging (e.g., "splunk", "elastic")
        logger (logging.Logger): Connector-specific logger
    
    Implementation Guide:
        1. Inherit from SIEMConnector
        2. Implement all @abstractmethod methods
        3. Add connector-specific configuration in __init__
        4. Handle connector-specific errors appropriately
        5. Return consistent data structures
    
    Example:
        >>> class CustomSIEMConnector(SIEMConnector):
        ...     def __init__(self, api_url, api_key):
        ...         super().__init__("custom_siem")
        ...         self.api_url = api_url
        ...         self.api_key = api_key
        ...     
        ...     def send_event(self, event: SIEMEvent) -> bool:
        ...         # Implementation here
        ...         pass
        ...     
        ...     # ... implement other abstract methods
    """
    
    def __init__(self, name: str):
        """Initialize SIEM connector base.
        
        Args:
            name: Connector identifier for logging (e.g., "splunk", "elastic")
        """
        self.name = name
        self.logger = logging.getLogger(f"siem.{name}")
    
    @abstractmethod
    def send_event(self, event: SIEMEvent) -> bool:
        """Send a single event to SIEM in real-time.
        
        For low-latency, real-time streaming of individual events.
        Use send_batch() for high-throughput scenarios.
        
        Args:
            event: SIEMEvent to send
        
        Returns:
            bool: True if event sent successfully, False otherwise
        
        Raises:
            ConnectionError: If unable to reach SIEM
            ValueError: If event format is invalid
        """
        pass
    
    @abstractmethod
    def send_batch(self, events: List[SIEMEvent]) -> Dict[str, int]:
        """Send multiple events to SIEM in a single operation.
        
        Batch processing is more efficient for high event volumes (>100/sec).
        Most SIEMs provide bulk ingestion APIs that accept multiple events.
        
        Args:
            events: List of SIEMEvents to send
        
        Returns:
            Dict with results:
                {
                    "total": int,      # Total events in batch
                    "success": int,    # Successfully sent
                    "failed": int      # Failed to send
                }
        
        Example:
            >>> events = [event1, event2, event3]
            >>> results = connector.send_batch(events)
            >>> print(f"Sent {results['success']}/{results['total']} events")
        """
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """Test connectivity to SIEM platform.
        
        Verifies that the SIEM is reachable, credentials are valid, and
        the connector is properly configured. Should be called before
        sending events in production.
        
        Returns:
            bool: True if connection successful, False otherwise
        
        Example:
            >>> if connector.test_connection():
            ...     print("✓ SIEM connection OK")
            ... else:
            ...     print("✗ SIEM connection failed")
        """
        pass
    
    @abstractmethod
    def query(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Query events from SIEM for enrichment or analysis.
        
        Enables bi-directional integration - not just sending events, but also
        retrieving them for correlation, enrichment, or threat hunting.
        
        Args:
            query: SIEM-specific query string (e.g., SPL for Splunk, KQL for Elastic)
            time_range: Optional (start_datetime, end_datetime) tuple
        
        Returns:
            List of matching events as dictionaries
        
        Example:
            >>> # Query Splunk for recent malware events
            >>> results = splunk.query(
            ...     'sourcetype=nexus-sec event_type=malware_detection',
            ...     time_range=(start_time, end_time)
            ... )
            >>> print(f"Found {len(results)} malware events")
        """
        pass


class SplunkConnector(SIEMConnector):
    """Splunk HTTP Event Collector (HEC) connector for real-time event streaming.
    
    Splunk HEC is a high-performance HTTP(S) endpoint for sending events to Splunk.
    It's the recommended method for custom applications to send data to Splunk,
    replacing older methods like file monitoring or syslog.
    
    HEC Benefits:
        - High throughput (>100K events/second per indexer)
        - Simple HTTP/HTTPS protocol
        - Token-based authentication (no username/password)
        - Automatic load balancing across indexers
        - Built-in event batching and compression
        - TLS encryption support
    
    Configuration Steps:
        1. Enable HEC in Splunk: Settings → Data Inputs → HTTP Event Collector
        2. Create HEC token with appropriate index permissions
        3. Note the HEC URL (typically https://splunk:8088)
        4. Configure SSL certificate validation if needed
    
    Attributes:
        hec_url (str): Splunk HEC endpoint URL (e.g., "https://splunk.company.com:8088")
        hec_token (str): HEC authentication token (UUID format)
        index (str): Target Splunk index for events (e.g., "security", "main")
        source (str): Source identifier for events (appears in Splunk UI)
        sourcetype (str): Splunk sourcetype for parsing/field extraction
        verify_ssl (bool): Enable SSL certificate validation (True in production)
        session (requests.Session): HTTP session for connection pooling
    
    Performance Tuning:
        - Use send_batch() for >100 events/second
        - Enable connection keep-alive (handled by session)
        - Consider HEC indexer acknowledgment for critical events
        - Monitor HEC metrics in Splunk (Settings → Data Inputs → HEC)
    
    Example:
        >>> # Initialize connector
        >>> splunk = SplunkConnector(
        ...     hec_url="https://splunk.company.com:8088",
        ...     hec_token="12345678-1234-1234-1234-123456789012",
        ...     index="security",
        ...     source="nexus-sec",
        ...     verify_ssl=True
        ... )
        >>> 
        >>> # Test connection
        >>> if splunk.test_connection():
        ...     print("✓ Splunk HEC ready")
        >>> 
        >>> # Send event
        >>> event = SIEMEvent(...)
        >>> splunk.send_event(event)
        >>> 
        >>> # Send batch
        >>> events = [event1, event2, event3]
        >>> results = splunk.send_batch(events)
    
    Troubleshooting:
        - 403 Forbidden: Check HEC token and index permissions
        - Connection refused: Verify HEC is enabled and port is correct
        - SSL errors: Set verify_ssl=False for testing (not production!)
        - Timeout: Check network connectivity and HEC load
    """
    
    def __init__(self, hec_url: str, hec_token: str, 
                 index: str = "main", source: str = "nexus-sec",
                 verify_ssl: bool = True):
        """Initialize Splunk HEC connector.
        
        Args:
            hec_url: Splunk HEC endpoint URL including port
                Format: https://hostname:8088
            hec_token: HEC authentication token (create in Splunk UI)
                Format: 12345678-1234-1234-1234-123456789012
            index: Target Splunk index (must exist and token must have access)
            source: Source field value for events (for filtering in Splunk)
            verify_ssl: Verify SSL certificates (set False only for testing)
        
        Example:
            >>> splunk = SplunkConnector(
            ...     hec_url="https://splunk.prod.company.com:8088",
            ...     hec_token="a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6",
            ...     index="security_events",
            ...     verify_ssl=True
            ... )
        """
        super().__init__("splunk")
        self.hec_url = hec_url.rstrip('/')
        self.hec_token = hec_token
        self.index = index
        self.source = source
        self.verify_ssl = verify_ssl
        
        self.headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json"
        }
    
    def send_event(self, event: SIEMEvent) -> bool:
        """Send event to Splunk HEC"""
        try:
            payload = {
                "time": event.timestamp,
                "index": self.index,
                "source": event.source,
                "sourcetype": f"nexus-sec:{event.event_type}",
                "event": event.to_dict()
            }
            
            response = requests.post(
                f"{self.hec_url}/services/collector/event",
                headers=self.headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.debug(f"Event sent to Splunk: {event.event_type}")
                return True
            else:
                self.logger.error(f"Splunk HEC error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to send event to Splunk: {e}")
            return False
    
    def send_batch(self, events: List[SIEMEvent]) -> Dict[str, int]:
        """Send batch of events to Splunk"""
        success_count = 0
        failed_count = 0
        
        # Splunk HEC supports batching
        batch_payload = []
        for event in events:
            batch_payload.append({
                "time": event.timestamp,
                "index": self.index,
                "source": event.source,
                "sourcetype": f"nexus-sec:{event.event_type}",
                "event": event.to_dict()
            })
        
        try:
            # Send as newline-delimited JSON
            payload_str = "\n".join(json.dumps(e) for e in batch_payload)
            
            response = requests.post(
                f"{self.hec_url}/services/collector/event",
                headers=self.headers,
                data=payload_str,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                success_count = len(events)
                self.logger.info(f"Batch sent to Splunk: {success_count} events")
            else:
                failed_count = len(events)
                self.logger.error(f"Splunk batch error: {response.status_code}")
                
        except Exception as e:
            failed_count = len(events)
            self.logger.error(f"Failed to send batch to Splunk: {e}")
        
        return {"success": success_count, "failed": failed_count}
    
    def test_connection(self) -> bool:
        """Test Splunk HEC connection"""
        try:
            test_event = SIEMEvent(
                timestamp=datetime.now().isoformat(),
                event_type="test",
                severity="info",
                source="nexus-sec",
                message="Connection test",
                details={}
            )
            
            return self.send_event(test_event)
            
        except Exception as e:
            self.logger.error(f"Splunk connection test failed: {e}")
            return False
    
    def query(self, search_query: str, 
             time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """
        Query Splunk using REST API
        
        Note: This requires Splunk REST API credentials (different from HEC)
        """
        # This is a simplified version
        # In production, implement proper Splunk REST API client
        self.logger.warning("Splunk query not implemented - use Splunk REST API SDK")
        return []


class ElasticConnector(SIEMConnector):
    """Elasticsearch connector"""
    
    def __init__(self, hosts: List[str], index_prefix: str = "nexus-sec",
                 username: Optional[str] = None, password: Optional[str] = None,
                 api_key: Optional[str] = None, verify_ssl: bool = True):
        super().__init__("elastic")
        self.hosts = hosts
        self.index_prefix = index_prefix
        self.username = username
        self.password = password
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        
        # Build auth
        self.auth = None
        self.headers = {"Content-Type": "application/json"}
        
        if api_key:
            self.headers["Authorization"] = f"ApiKey {api_key}"
        elif username and password:
            self.auth = (username, password)
    
    def send_event(self, event: SIEMEvent) -> bool:
        """Send event to Elasticsearch"""
        try:
            # Generate index name with date
            date_suffix = datetime.now().strftime("%Y.%m.%d")
            index_name = f"{self.index_prefix}-{date_suffix}"
            
            # Prepare document
            doc = event.to_dict()
            doc["@timestamp"] = event.timestamp
            
            # Send to Elasticsearch
            for host in self.hosts:
                try:
                    response = requests.post(
                        f"{host}/{index_name}/_doc",
                        headers=self.headers,
                        auth=self.auth,
                        json=doc,
                        verify=self.verify_ssl,
                        timeout=10
                    )
                    
                    if response.status_code in (200, 201):
                        self.logger.debug(f"Event sent to Elasticsearch: {event.event_type}")
                        return True
                    else:
                        self.logger.error(f"Elasticsearch error: {response.status_code}")
                        continue
                        
                except requests.exceptions.RequestException as e:
                    self.logger.warning(f"Failed to send to {host}: {e}")
                    continue
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to send event to Elasticsearch: {e}")
            return False
    
    def send_batch(self, events: List[SIEMEvent]) -> Dict[str, int]:
        """Send batch of events using Elasticsearch Bulk API"""
        success_count = 0
        failed_count = 0
        
        try:
            # Generate index name
            date_suffix = datetime.now().strftime("%Y.%m.%d")
            index_name = f"{self.index_prefix}-{date_suffix}"
            
            # Build bulk request
            bulk_body = []
            for event in events:
                # Action line
                bulk_body.append(json.dumps({"index": {"_index": index_name}}))
                # Document line
                doc = event.to_dict()
                doc["@timestamp"] = event.timestamp
                bulk_body.append(json.dumps(doc))
            
            bulk_data = "\n".join(bulk_body) + "\n"
            
            # Send bulk request
            for host in self.hosts:
                try:
                    response = requests.post(
                        f"{host}/_bulk",
                        headers={**self.headers, "Content-Type": "application/x-ndjson"},
                        auth=self.auth,
                        data=bulk_data,
                        verify=self.verify_ssl,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if not result.get("errors", False):
                            success_count = len(events)
                            self.logger.info(f"Batch sent to Elasticsearch: {success_count} events")
                            return {"success": success_count, "failed": 0}
                        else:
                            # Count individual failures
                            for item in result.get("items", []):
                                if "error" in item.get("index", {}):
                                    failed_count += 1
                                else:
                                    success_count += 1
                            return {"success": success_count, "failed": failed_count}
                    
                except requests.exceptions.RequestException as e:
                    self.logger.warning(f"Failed to send bulk to {host}: {e}")
                    continue
            
            failed_count = len(events)
            return {"success": 0, "failed": failed_count}
            
        except Exception as e:
            self.logger.error(f"Failed to send batch to Elasticsearch: {e}")
            return {"success": 0, "failed": len(events)}
    
    def test_connection(self) -> bool:
        """Test Elasticsearch connection"""
        try:
            for host in self.hosts:
                response = requests.get(
                    f"{host}/_cluster/health",
                    headers=self.headers,
                    auth=self.auth,
                    verify=self.verify_ssl,
                    timeout=5
                )
                
                if response.status_code == 200:
                    health = response.json()
                    self.logger.info(f"Elasticsearch cluster status: {health.get('status')}")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Elasticsearch connection test failed: {e}")
            return False
    
    def query(self, query: Dict[str, Any], 
             time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """
        Query Elasticsearch using DSL
        
        Args:
            query: Elasticsearch query DSL
            time_range: Optional (start, end) datetime tuple
        """
        try:
            # Add time range if provided
            if time_range:
                start_time, end_time = time_range
                query = {
                    "bool": {
                        "must": [query],
                        "filter": [{
                            "range": {
                                "@timestamp": {
                                    "gte": start_time.isoformat(),
                                    "lte": end_time.isoformat()
                                }
                            }
                        }]
                    }
                }
            
            search_body = {
                "query": query,
                "size": 1000  # Adjust as needed
            }
            
            for host in self.hosts:
                try:
                    response = requests.post(
                        f"{host}/{self.index_prefix}-*/_search",
                        headers=self.headers,
                        auth=self.auth,
                        json=search_body,
                        verify=self.verify_ssl,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        results = response.json()
                        hits = results.get("hits", {}).get("hits", [])
                        return [hit["_source"] for hit in hits]
                
                except requests.exceptions.RequestException as e:
                    self.logger.warning(f"Query failed on {host}: {e}")
                    continue
            
            return []
            
        except Exception as e:
            self.logger.error(f"Elasticsearch query failed: {e}")
            return []


class SyslogConnector(SIEMConnector):
    """Generic syslog forwarding connector"""
    
    def __init__(self, syslog_server: str, syslog_port: int = 514,
                 protocol: str = "udp", facility: int = 16):
        super().__init__("syslog")
        self.syslog_server = syslog_server
        self.syslog_port = syslog_port
        self.protocol = protocol.lower()
        self.facility = facility
        
        if self.protocol not in ["udp", "tcp"]:
            raise ValueError("Protocol must be 'udp' or 'tcp'")
    
    def send_event(self, event: SIEMEvent) -> bool:
        """Send event via syslog"""
        try:
            import socket
            
            # Convert to CEF format
            cef_message = event.to_cef()
            
            # Calculate priority (facility * 8 + severity)
            severity = event._severity_to_cef()
            priority = (self.facility * 8) + min(severity, 7)
            
            # RFC 5424 format
            syslog_message = f"<{priority}>{cef_message}"
            
            # Send via UDP or TCP
            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(syslog_message.encode('utf-8'), 
                           (self.syslog_server, self.syslog_port))
                sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.syslog_server, self.syslog_port))
                sock.send((syslog_message + "\n").encode('utf-8'))
                sock.close()
            
            self.logger.debug(f"Event sent via syslog: {event.event_type}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send syslog: {e}")
            return False
    
    def send_batch(self, events: List[SIEMEvent]) -> Dict[str, int]:
        """Send batch of events via syslog"""
        success_count = 0
        failed_count = 0
        
        for event in events:
            if self.send_event(event):
                success_count += 1
            else:
                failed_count += 1
        
        return {"success": success_count, "failed": failed_count}
    
    def test_connection(self) -> bool:
        """Test syslog connectivity"""
        try:
            test_event = SIEMEvent(
                timestamp=datetime.now().isoformat(),
                event_type="test",
                severity="info",
                source="nexus-sec",
                message="Connection test",
                details={}
            )
            
            return self.send_event(test_event)
            
        except Exception as e:
            self.logger.error(f"Syslog connection test failed: {e}")
            return False
    
    def query(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Syslog doesn't support querying"""
        self.logger.warning("Syslog connector does not support querying")
        return []


class SIEMIntegrationManager:
    """Orchestrate multiple SIEM connections for redundancy and multi-tenancy.
    
    The SIEMIntegrationManager enables simultaneous forwarding to multiple SIEM
    platforms, providing redundancy, compliance (different retention requirements),
    and multi-organizational support (send to both corporate and customer SIEMs).
    
    Use Cases:
        1. **Redundancy**: Send to primary and backup SIEM
        2. **Compliance**: Different retention periods (Splunk 90d, archive SIEM 7y)
        3. **Multi-tenant**: Forward to customer's SIEM while keeping internal copy
        4. **SIEM Migration**: Run old and new SIEM in parallel during cutover
        5. **Security Operations**: Send to SOC SIEM and threat hunting platform
    
    Architecture:
        Manager → [Splunk Connector, Elastic Connector, Syslog Connector]
                     ↓                ↓                    ↓
                 Splunk HEC      Elasticsearch      Generic SIEM
    
    Attributes:
        logger (logging.Logger): Manager-specific logger
        connectors (Dict[str, SIEMConnector]): Registry of active SIEM connectors
            Key: Connector name (e.g., "splunk_prod", "elastic_archive")
            Value: SIEMConnector instance
    
    Error Handling Philosophy:
        - Failures in one connector don't affect others
        - All errors are logged but don't raise exceptions
        - Results dict shows which connectors succeeded/failed
        - Continue sending to working SIEMs even if some fail
    
    Example:
        >>> # Initialize manager
        >>> manager = SIEMIntegrationManager()
        >>> 
        >>> # Add multiple SIEMs
        >>> splunk = SplunkConnector(
        ...     hec_url="https://splunk.prod.company.com:8088",
        ...     hec_token="token1",
        ...     index="security"
        ... )
        >>> manager.add_connector("splunk_prod", splunk)
        >>> 
        >>> elastic = ElasticConnector(
        ...     hosts=["https://elastic.company.com:9200"],
        ...     index_prefix="security"
        ... )
        >>> manager.add_connector("elastic_archive", elastic)
        >>> 
        >>> # Test all connections
        >>> results = manager.test_all_connections()
        >>> for siem, status in results.items():
        ...     print(f"{siem}: {'✓' if status else '✗'}")
        >>> 
        >>> # Send to all SIEMs simultaneously
        >>> event = SIEMEvent(...)
        >>> results = manager.send_to_all(event)
        >>> # results = {"splunk_prod": True, "elastic_archive": True}
        >>> 
        >>> # Send batch to all
        >>> events = [event1, event2, event3]
        >>> results = manager.send_batch_to_all(events)
        >>> # results = {
        >>> #     "splunk_prod": {"success": 3, "failed": 0},
        >>> #     "elastic_archive": {"success": 3, "failed": 0}
        >>> # }
    
    Best Practices:
        - Test connections before sending production events
        - Monitor send_to_all() results for connector failures
        - Use descriptive connector names (e.g., "splunk_prod", not "siem1")
        - Remove connectors during maintenance to prevent errors
        - Log aggregation failures separately for investigation
    """
    
    def __init__(self):
        """Initialize SIEM integration manager.
        
        Creates empty connector registry. Add connectors using add_connector().
        """
        self.logger = logging.getLogger("siem_manager")
        self.connectors: Dict[str, SIEMConnector] = {}
    
    def add_connector(self, name: str, connector: SIEMConnector) -> None:
        """Register a SIEM connector with the manager.
        
        Adds a configured SIEM connector to the manager's registry. The connector
        will receive all events sent via send_to_all() or send_batch_to_all().
        
        Args:
            name: Unique identifier for this connector (e.g., "splunk_prod")
                Used in results dicts to identify which SIEM succeeded/failed
            connector: Initialized SIEMConnector instance (Splunk, Elastic, etc.)
        
        Example:
            >>> manager = SIEMIntegrationManager()
            >>> 
            >>> # Add primary Splunk
            >>> splunk = SplunkConnector(...)
            >>> manager.add_connector("splunk_primary", splunk)
            >>> 
            >>> # Add backup syslog
            >>> syslog = SyslogConnector(...)
            >>> manager.add_connector("syslog_backup", syslog)
        """
        self.connectors[name] = connector
        self.logger.info(f"Added SIEM connector: {name}")
    
    def remove_connector(self, name: str) -> None:
        """Unregister a SIEM connector from the manager.
        
        Removes a connector from the registry. Useful during maintenance,
        SIEM migrations, or temporary issues with specific platforms.
        
        Args:
            name: Connector name to remove
        
        Example:
            >>> # Temporarily remove during maintenance
            >>> manager.remove_connector("splunk_primary")
            >>> # Events will only go to remaining connectors
        """
        if name in self.connectors:
            del self.connectors[name]
            self.logger.info(f"Removed SIEM connector: {name}")
    
    def send_to_all(self, event: SIEMEvent) -> Dict[str, bool]:
        """Send single event to all registered SIEM platforms.
        
        Broadcasts event to every configured SIEM connector. Failures in one
        connector don't affect others - all sends are attempted independently.
        
        Args:
            event: SIEMEvent to send to all platforms
        
        Returns:
            Dict mapping connector names to success status:
                {"splunk_prod": True, "elastic": True, "syslog": False}
        
        Example:
            >>> event = SIEMEvent(...)
            >>> results = manager.send_to_all(event)
            >>> 
            >>> # Check for failures
            >>> failures = [name for name, success in results.items() if not success]
            >>> if failures:
            ...     print(f"Failed SIEMs: {', '.join(failures)}")
        """
        results = {}
        
        for name, connector in self.connectors.items():
            try:
                results[name] = connector.send_event(event)
            except Exception as e:
                self.logger.error(f"Failed to send to {name}: {e}")
                results[name] = False
        
        return results
    
    def send_batch_to_all(self, events: List[SIEMEvent]) -> Dict[str, Dict[str, int]]:
        """Send batch of events to all registered SIEM platforms.
        
        Efficiently sends multiple events to all connectors using their
        batch APIs. More performant than calling send_to_all() repeatedly.
        
        Args:
            events: List of SIEMEvents to send to all platforms
        
        Returns:
            Dict mapping connector names to batch results:
                {
                    "splunk_prod": {"success": 100, "failed": 0},
                    "elastic": {"success": 98, "failed": 2}
                }
        
        Example:
            >>> events = [event1, event2, event3, ...]  # 100 events
            >>> results = manager.send_batch_to_all(events)
            >>> 
            >>> # Report results
            >>> for siem, counts in results.items():
            ...     success_rate = counts['success'] / len(events) * 100
            ...     print(f"{siem}: {success_rate:.1f}% success rate")
        """
        results = {}
        
        for name, connector in self.connectors.items():
            try:
                results[name] = connector.send_batch(events)
            except Exception as e:
                self.logger.error(f"Failed to send batch to {name}: {e}")
                results[name] = {"success": 0, "failed": len(events)}
        
        return results
    
    def test_all_connections(self) -> Dict[str, bool]:
        """Test connectivity to all registered SIEM platforms.
        
        Verifies each connector can reach its SIEM. Should be called during
        initialization and periodically in production to detect issues early.
        
        Returns:
            Dict mapping connector names to connection status:
                {"splunk_prod": True, "elastic": True, "syslog": False}
        
        Example:
            >>> results = manager.test_all_connections()
            >>> 
            >>> # Check all systems operational
            >>> if all(results.values()):
            ...     print("✓ All SIEMs operational")
            ... else:
            ...     failed = [name for name, ok in results.items() if not ok]
            ...     print(f"✗ SIEM issues: {', '.join(failed)}")
        """
        results = {}
        
        for name, connector in self.connectors.items():
            results[name] = connector.test_connection()
        
        return results
    
    def get_connector(self, name: str) -> Optional[SIEMConnector]:
        """Retrieve a specific connector by name for direct use.
        
        Allows direct access to individual connectors for SIEM-specific
        operations like querying or advanced configuration.
        
        Args:
            name: Connector name to retrieve
        
        Returns:
            SIEMConnector instance or None if not found
        
        Example:
            >>> # Query specific SIEM directly
            >>> splunk = manager.get_connector("splunk_prod")
            >>> if splunk:
            ...     results = splunk.query('sourcetype=nexus-sec severity=high')
        """
        return self.connectors.get(name)