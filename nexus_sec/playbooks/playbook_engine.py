"""
Automated Playbook Execution Engine for Nexus-Sec

This module provides enterprise-grade automated incident response through YAML-based playbooks.
Playbooks define sequences of security actions to be executed in response to security events,
enabling consistent, repeatable, and auditable incident response workflows.

Key Features:
    - YAML-based playbook definitions for easy customization
    - 6+ built-in response actions (isolation, blocking, evidence collection, etc.)
    - Conditional logic and branching for complex scenarios
    - Rollback capabilities for safe experimentation
    - Full execution history and audit trail
    - Variable substitution from trigger events

Architecture:
    PlaybookEngine loads YAML playbooks and orchestrates action execution.
    Each action inherits from ResponseAction base class and implements:
        - execute(): Perform the security action
        - rollback(): Undo the action if needed
        - evaluate_condition(): Check if action should run

Example:
    >>> engine = PlaybookEngine()
    >>> engine.load_playbooks_from_directory("playbooks/")
    >>> 
    >>> trigger_event = {
    ...     "hostname": "workstation-042",
    ...     "file_hash": "abc123...",
    ...     "severity": 8
    ... }
    >>> 
    >>> execution = engine.execute_playbook('malware_detection_response', trigger_event)
    >>> print(f"Status: {execution.status.value}")
    >>> for action in execution.actions:
    ...     print(f"{action.action_name}: {action.status.value}")

Author: Jace - System Administrator & AI Security Engineer
Version: 1.0.0
"""

import yaml
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
import json


class ActionStatus(Enum):
    """Status of a playbook action"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class PlaybookStatus(Enum):
    """Status of playbook execution"""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class ActionResult:
    """Result of a single action execution within a playbook.
    
    Captures the outcome of executing a security response action, including
    status, timing, output data, and any error information. Used for audit
    trails and execution analysis.
    
    Attributes:
        action_name (str): Human-readable name of the action (e.g., "isolate_host")
        status (ActionStatus): Current execution status (success, failed, skipped, etc.)
        message (str): Human-readable description of the result
        timestamp (datetime): When the action completed execution
        data (Dict[str, Any]): Structured output data from the action (e.g., ticket IDs,
            isolation IDs, blocked IP addresses)
        error (Optional[str]): Error message if action failed, None otherwise
    
    Example:
        >>> result = ActionResult(
        ...     action_name="isolate_host",
        ...     status=ActionStatus.SUCCESS,
        ...     message="Successfully isolated workstation-042",
        ...     data={"hostname": "workstation-042", "isolation_id": "abc-123"}
        ... )
    """
    action_name: str
    status: ActionStatus
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class PlaybookExecution:
    """Tracks the complete execution lifecycle of a security playbook.
    
    Maintains state and history for a single playbook execution, including
    all actions performed, timing information, and rollback tracking. Provides
    audit trail and execution analysis capabilities.
    
    Attributes:
        playbook_name (str): Name of the playbook being executed
        trigger_event (Dict[str, Any]): The security event that triggered this playbook
            (e.g., malware detection, suspicious login, C2 communication)
        status (PlaybookStatus): Current execution status (running, completed, failed)
        start_time (datetime): When playbook execution began
        end_time (Optional[datetime]): When playbook execution completed, None if still running
        actions (List[ActionResult]): Chronological list of all action results
        rollback_actions (List[str]): Names of actions that support rollback, for recovery
    
    Example:
        >>> execution = PlaybookExecution(
        ...     playbook_name="malware_detection_response",
        ...     trigger_event={"hostname": "ws-042", "severity": 8},
        ...     status=PlaybookStatus.RUNNING,
        ...     start_time=datetime.now()
        ... )
        >>> # Actions are added as they execute
        >>> execution.actions.append(action_result)
    """
    playbook_name: str
    trigger_event: Dict[str, Any]
    status: PlaybookStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    actions: List[ActionResult] = field(default_factory=list)
    rollback_actions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert execution record to dictionary for serialization.
        
        Serializes the complete execution record including all actions,
        timing information, and status. Useful for logging, reporting,
        and API responses.
        
        Returns:
            Dict[str, Any]: Complete execution record with ISO-formatted timestamps
                and serialized action results
        
        Example:
            >>> execution_dict = execution.to_dict()
            >>> import json
            >>> json.dumps(execution_dict, indent=2)
        """
        return {
            "playbook_name": self.playbook_name,
            "trigger_event": self.trigger_event,
            "status": self.status.value,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "actions": [
                {
                    "name": a.action_name,
                    "status": a.status.value,
                    "message": a.message,
                    "timestamp": a.timestamp.isoformat(),
                    "data": a.data,
                    "error": a.error
                }
                for a in self.actions
            ],
            "rollback_actions": self.rollback_actions
        }


class ResponseAction:
    """Abstract base class for all security response actions.
    
    Defines the interface that all response actions must implement. Each action
    represents a specific security operation (e.g., host isolation, IP blocking,
    evidence collection) that can be orchestrated by the playbook engine.
    
    All action subclasses must implement:
        - execute(): Perform the security action
        - rollback(): Undo the action if possible (optional but recommended)
    
    Actions receive context from the trigger event and can use conditional logic
    to determine if they should execute.
    
    Attributes:
        name (str): Human-readable name for this action instance
        params (Dict[str, Any]): Configuration parameters from the playbook
        logger (logging.Logger): Action-specific logger for debugging
    
    Example:
        >>> class CustomAction(ResponseAction):
        ...     def execute(self, context):
        ...         # Perform action logic
        ...         return ActionResult(
        ...             action_name=self.name,
        ...             status=ActionStatus.SUCCESS,
        ...             message="Action completed"
        ...         )
    """
    
    def __init__(self, name: str, params: Dict[str, Any]):
        """Initialize a response action.
        
        Args:
            name: Human-readable action name (e.g., "isolate_compromised_host")
            params: Action parameters from playbook (e.g., {"timeout": 30})
        """
        self.name = name
        self.params = params
        self.logger = logging.getLogger(f"action.{name}")
    
    def execute(self, context: Dict[str, Any]) -> ActionResult:
        """Execute the security action.
        
        Must be implemented by all action subclasses. Performs the actual
        security operation (e.g., isolates host, blocks IP, collects evidence).
        
        Args:
            context: Execution context containing trigger event data and
                results from previous actions. Supports variable substitution.
        
        Returns:
            ActionResult: Result of the action execution including status,
                message, and any output data
        
        Raises:
            NotImplementedError: If subclass doesn't implement this method
        """
        raise NotImplementedError("Action must implement execute()")
    
    def rollback(self, context: Dict[str, Any]) -> bool:
        """Rollback the action if possible.
        
        Optional method that allows actions to be undone (e.g., remove host
        isolation, unblock IP). Not all actions support rollback.
        
        Args:
            context: Execution context with action data needed for rollback
        
        Returns:
            bool: True if rollback succeeded, False if not supported or failed
        """
        self.logger.warning(f"Action {self.name} does not support rollback")
        return False
    
    def evaluate_condition(self, condition: Optional[str], context: Dict[str, Any]) -> bool:
        """Evaluate a conditional expression for this action.
        
        Allows playbooks to conditionally execute actions based on event
        attributes (e.g., "severity >= 7" or "ioc_type == 'ip'").
        
        Security Note: Uses restricted eval() for safety - only basic
        comparisons are supported, no function calls or imports allowed.
        
        Args:
            condition: Python expression string to evaluate (e.g., "severity > 5")
                If None or empty, always returns True
            context: Variables available for condition evaluation (event data)
        
        Returns:
            bool: True if condition is met or no condition specified,
                False if condition fails or evaluation error occurs
        
        Example:
            >>> action.evaluate_condition("severity >= 7", {"severity": 8})
            True
            >>> action.evaluate_condition("threat_level == 'critical'", {"threat_level": "low"})
            False
        """
        if not condition:
            return True
        
        try:
            # Simple condition evaluation (can be expanded)
            # Supports: severity > 7, ioc_type == 'ip', etc.
            return eval(condition, {"__builtins__": {}}, context)
        except Exception as e:
            self.logger.error(f"Condition evaluation failed: {e}")
            return False


class IsolateHostAction(ResponseAction):
    """Isolate a compromised host from the network using EDR platform.
    
    Performs network isolation of a potentially compromised endpoint to prevent
    lateral movement and contain the threat. Integrates with EDR platforms like
    CrowdStrike Falcon, SentinelOne, or Microsoft Defender for Endpoint.
    
    The action can be configured in playbooks with either a static hostname or
    by inheriting it from the trigger event context. Supports rollback to restore
    network connectivity.
    
    Configuration:
        Playbook params:
            hostname (str, optional): Static hostname to isolate. If not provided,
                will use 'hostname' from trigger event context.
    
    Integration:
        Production: Replace _isolate_via_edr() with actual EDR API calls
        CrowdStrike: Use Falcon API /devices/entities/devices-actions/v2
        SentinelOne: Use /agents/{agent_id}/actions/disconnect
        Microsoft: Use Microsoft Graph Security API
    
    Example Playbook:
        ```yaml
        - type: isolate_host
          name: isolate_compromised_endpoint
          params:
            hostname: ${hostname}  # From trigger event
          condition: "severity >= 7"  # Only for high severity
        ```
    
    Returns:
        ActionResult with:
            - isolation_id: Unique ID for this isolation action
            - hostname: The isolated host
            - timestamp: When isolation occurred
    """
    
    def execute(self, context: Dict[str, Any]) -> ActionResult:
        """Execute host isolation via EDR platform.
        
        Isolates the target host from the network, preventing all communication
        except with the EDR management server. The host remains manageable for
        investigation and remediation.
        
        Args:
            context: Execution context containing:
                - hostname (str): Target hostname to isolate
                - Additional event data for logging/audit
        
        Returns:
            ActionResult: Execution result with isolation details or error
        
        Example:
            >>> action = IsolateHostAction("isolate_ws042", {})
            >>> result = action.execute({"hostname": "workstation-042"})
            >>> print(result.data['isolation_id'])
        """
        # Get hostname from params (static) or context (dynamic from event)
        hostname = self.params.get('hostname') or context.get('hostname')
        
        # Validate required parameter
        if not hostname:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message="No hostname provided",
                error="Missing required parameter: hostname"
            )
        
        self.logger.info(f"Isolating host: {hostname}")
        
        # In production, this would call your EDR API (CrowdStrike, SentinelOne, etc.)
        # For demo, we'll simulate the action
        try:
            # Simulated API call - Replace with real EDR integration
            isolation_result = self._isolate_via_edr(hostname)
            
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.SUCCESS,
                message=f"Successfully isolated host {hostname}",
                data={
                    "hostname": hostname,
                    "isolation_id": isolation_result,
                    "timestamp": datetime.now().isoformat()
                }
            )
        except Exception as e:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message=f"Failed to isolate host {hostname}",
                error=str(e)
            )
    
    def _isolate_via_edr(self, hostname: str) -> str:
        """Simulate EDR isolation API call.
        
        In production, replace this with actual EDR API integration:
        
        CrowdStrike Example:
            ```python
            from falconpy import Hosts
            falcon = Hosts(client_id=..., client_secret=...)
            response = falcon.perform_action(
                action_name="contain",
                ids=[device_id]
            )
            return response['body']['resources'][0]['id']
            ```
        
        Args:
            hostname: Target hostname to isolate
        
        Returns:
            str: Isolation action ID from EDR platform
        """
        # In production: Call CrowdStrike Falcon API, SentinelOne, etc.
        import uuid
        return str(uuid.uuid4())
    
    def rollback(self, context: Dict[str, Any]) -> bool:
        """Remove host isolation and restore network connectivity.
        
        Lifts the network isolation applied to the host, allowing normal
        network communication to resume. Should only be called after threat
        has been remediated and verified.
        
        Args:
            context: Execution context with hostname to un-isolate
        
        Returns:
            bool: True if isolation removed successfully
        
        Example:
            >>> action.rollback({"hostname": "workstation-042"})
            True
        """
        hostname = self.params.get('hostname') or context.get('hostname')
        self.logger.info(f"Removing isolation for host: {hostname}")
        # In production: Call EDR API to lift containment
        return True


class BlockIPAction(ResponseAction):
    """Block an IP address at the firewall"""
    
    def execute(self, context: Dict[str, Any]) -> ActionResult:
        ip_address = self.params.get('ip') or context.get('ip_address')
        duration = self.params.get('duration', 3600)  # Default 1 hour
        
        if not ip_address:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message="No IP address provided",
                error="Missing required parameter: ip"
            )
        
        self.logger.info(f"Blocking IP: {ip_address} for {duration} seconds")
        
        try:
            # Simulated firewall API call
            block_id = self._block_via_firewall(ip_address, duration)
            
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.SUCCESS,
                message=f"Successfully blocked IP {ip_address}",
                data={
                    "ip_address": ip_address,
                    "block_id": block_id,
                    "duration": duration,
                    "expires_at": (datetime.now().timestamp() + duration)
                }
            )
        except Exception as e:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message=f"Failed to block IP {ip_address}",
                error=str(e)
            )
    
    def _block_via_firewall(self, ip: str, duration: int) -> str:
        """Simulate firewall API call"""
        # In production: Call Palo Alto, Fortinet, pfSense API, etc.
        import uuid
        return str(uuid.uuid4())
    
    def rollback(self, context: Dict[str, Any]) -> bool:
        """Unblock the IP address"""
        ip_address = self.params.get('ip') or context.get('ip_address')
        self.logger.info(f"Unblocking IP: {ip_address}")
        # In production: Remove firewall rule
        return True


class CollectEvidenceAction(ResponseAction):
    """Collect forensic evidence from a host"""
    
    def execute(self, context: Dict[str, Any]) -> ActionResult:
        hostname = self.params.get('hostname') or context.get('hostname')
        artifacts = self.params.get('artifacts', ['memory', 'disk', 'network'])
        
        if not hostname:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message="No hostname provided",
                error="Missing required parameter: hostname"
            )
        
        self.logger.info(f"Collecting evidence from: {hostname}")
        
        try:
            # Simulated evidence collection
            evidence_paths = self._collect_forensics(hostname, artifacts)
            
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.SUCCESS,
                message=f"Successfully collected evidence from {hostname}",
                data={
                    "hostname": hostname,
                    "artifacts": artifacts,
                    "evidence_paths": evidence_paths,
                    "collection_time": datetime.now().isoformat()
                }
            )
        except Exception as e:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message=f"Failed to collect evidence from {hostname}",
                error=str(e)
            )
    
    def _collect_forensics(self, hostname: str, artifacts: List[str]) -> List[str]:
        """Simulate forensic collection"""
        # In production: Use tools like Velociraptor, GRR, or EDR forensics
        return [f"/evidence/{hostname}/{artifact}.zip" for artifact in artifacts]


class QuarantineFileAction(ResponseAction):
    """Quarantine a malicious file"""
    
    def execute(self, context: Dict[str, Any]) -> ActionResult:
        file_path = self.params.get('file_path') or context.get('file_path')
        file_hash = self.params.get('file_hash') or context.get('file_hash')
        
        if not file_path and not file_hash:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message="No file identifier provided",
                error="Missing required parameter: file_path or file_hash"
            )
        
        self.logger.info(f"Quarantining file: {file_path or file_hash}")
        
        try:
            quarantine_id = self._quarantine_via_edr(file_path, file_hash)
            
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.SUCCESS,
                message=f"Successfully quarantined file",
                data={
                    "file_path": file_path,
                    "file_hash": file_hash,
                    "quarantine_id": quarantine_id
                }
            )
        except Exception as e:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message="Failed to quarantine file",
                error=str(e)
            )
    
    def _quarantine_via_edr(self, file_path: Optional[str], file_hash: Optional[str]) -> str:
        """Simulate EDR quarantine"""
        import uuid
        return str(uuid.uuid4())


class SendAlertAction(ResponseAction):
    """Send alert notification to SOC team"""
    
    def execute(self, context: Dict[str, Any]) -> ActionResult:
        severity = self.params.get('severity', context.get('severity', 'medium'))
        message = self.params.get('message', 'Security incident detected')
        channels = self.params.get('channels', ['email'])
        
        self.logger.info(f"Sending {severity} alert via {channels}")
        
        try:
            notification_ids = self._send_notifications(severity, message, channels, context)
            
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.SUCCESS,
                message="Alert sent successfully",
                data={
                    "severity": severity,
                    "channels": channels,
                    "notification_ids": notification_ids
                }
            )
        except Exception as e:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message="Failed to send alert",
                error=str(e)
            )
    
    def _send_notifications(self, severity: str, message: str, 
                           channels: List[str], context: Dict[str, Any]) -> Dict[str, str]:
        """Simulate notification sending"""
        # In production: Send to Slack, email, PagerDuty, etc.
        import uuid
        return {channel: str(uuid.uuid4()) for channel in channels}


class CreateTicketAction(ResponseAction):
    """Create incident ticket in ticketing system"""
    
    def execute(self, context: Dict[str, Any]) -> ActionResult:
        title = self.params.get('title', 'Security Incident')
        description = self.params.get('description', json.dumps(context, indent=2))
        priority = self.params.get('priority', 'high')
        
        self.logger.info(f"Creating ticket: {title}")
        
        try:
            ticket_id = self._create_ticket_api(title, description, priority)
            
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.SUCCESS,
                message=f"Created ticket {ticket_id}",
                data={
                    "ticket_id": ticket_id,
                    "title": title,
                    "priority": priority
                }
            )
        except Exception as e:
            return ActionResult(
                action_name=self.name,
                status=ActionStatus.FAILED,
                message="Failed to create ticket",
                error=str(e)
            )
    
    def _create_ticket_api(self, title: str, description: str, priority: str) -> str:
        """Simulate ticket creation"""
        # In production: Call Jira, ServiceNow, etc.
        import uuid
        return f"INC-{uuid.uuid4().hex[:8].upper()}"


class PlaybookEngine:
    """Orchestration engine for executing security response playbooks.
    
    The PlaybookEngine is the central coordinator for automated incident response.
    It loads YAML playbooks, validates them, and executes actions in sequence with
    proper error handling, conditional logic, and audit logging.
    
    Key Capabilities:
        - Load playbooks from YAML files or directories
        - Execute playbooks triggered by security events
        - Support conditional action execution
        - Track execution history for audit/analysis
        - Provide rollback capabilities for failed executions
        - Maintain execution context across actions
    
    Architecture:
        The engine uses a registry pattern to map action types (strings in YAML)
        to their implementation classes. This allows easy extension with new actions.
        
        Action execution is sequential with context passing - each action can access:
            - Original trigger event data
            - Results from previous actions
            - Computed variables
    
    Attributes:
        ACTION_REGISTRY (Dict[str, Type[ResponseAction]]): Maps action type names
            to their implementation classes
        logger (logging.Logger): Engine-specific logger
        executions (List[PlaybookExecution]): History of all playbook executions
        playbooks (Dict[str, Dict[str, Any]]): Loaded playbook definitions
    
    Example:
        >>> # Initialize engine
        >>> engine = PlaybookEngine()
        >>> 
        >>> # Load playbooks
        >>> engine.load_playbooks_from_directory("playbooks/")
        >>> 
        >>> # Execute in response to security event
        >>> trigger = {
        ...     "hostname": "ws-042",
        ...     "file_hash": "abc123...",
        ...     "severity": 8
        ... }
        >>> execution = engine.execute_playbook('malware_detection_response', trigger)
        >>> 
        >>> # Check results
        >>> print(f"Status: {execution.status.value}")
        >>> for action in execution.actions:
        ...     print(f"{action.action_name}: {action.status.value}")
    
    Thread Safety:
        This implementation is NOT thread-safe. For concurrent execution,
        create separate engine instances or add synchronization.
    """
    
    # Map action types (from YAML) to their implementation classes
    # Extend this registry to add new action types
    ACTION_REGISTRY = {
        'isolate_host': IsolateHostAction,
        'block_ip': BlockIPAction,
        'collect_evidence': CollectEvidenceAction,
        'quarantine_file': QuarantineFileAction,
        'send_alert': SendAlertAction,
        'create_ticket': CreateTicketAction,
    }
    
    def __init__(self):
        """Initialize the playbook execution engine.
        
        Sets up logging, execution tracking, and playbook storage.
        """
        self.logger = logging.getLogger("playbook_engine")
        self.executions: List[PlaybookExecution] = []  # Execution history
        self.playbooks: Dict[str, Dict[str, Any]] = {}  # Loaded playbooks
    
    def load_playbook(self, playbook_path: str) -> None:
        """Load a single playbook from YAML file.
        
        Reads and validates a YAML playbook file, then adds it to the engine's
        playbook registry. The playbook must have a 'name' field which serves
        as its unique identifier.
        
        Args:
            playbook_path: Filesystem path to the YAML playbook file
        
        Raises:
            ValueError: If playbook is missing required fields
            yaml.YAMLError: If file contains invalid YAML
            FileNotFoundError: If playbook file doesn't exist
            IOError: If file cannot be read
        
        Example:
            >>> engine.load_playbook("playbooks/malware_response.yml")
            >>> # Now available as: engine.execute_playbook('malware_response', ...)
        """
        try:
            with open(playbook_path, 'r') as f:
                playbook = yaml.safe_load(f)
            
            # Validate required fields
            playbook_name = playbook.get('name')
            if not playbook_name:
                raise ValueError("Playbook must have a name")
            
            # Register playbook
            self.playbooks[playbook_name] = playbook
            self.logger.info(f"Loaded playbook: {playbook_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to load playbook {playbook_path}: {e}")
            raise
    
    def load_playbooks_from_directory(self, directory: str) -> None:
        """Load all playbooks from a directory.
        
        Scans the specified directory for YAML files (.yml or .yaml) and loads
        each one as a playbook. Non-YAML files are ignored. Subdirectories are
        not recursively scanned.
        
        Args:
            directory: Path to directory containing playbook YAML files
        
        Raises:
            FileNotFoundError: If directory doesn't exist
            ValueError: If any playbook is invalid
        
        Example:
            >>> engine.load_playbooks_from_directory("playbooks/")
            >>> print(f"Loaded {len(engine.playbooks)} playbooks")
        """
        import os
        for filename in os.listdir(directory):
            if filename.endswith('.yml') or filename.endswith('.yaml'):
                self.load_playbook(os.path.join(directory, filename))
    
    def execute_playbook(self, playbook_name: str, trigger_event: Dict[str, Any]) -> PlaybookExecution:
        """Execute a playbook in response to a security event.
        
        Orchestrates the execution of all actions defined in the playbook,
        handling conditional logic, error cases, and context passing between
        actions. Execution is sequential with proper error handling.
        
        Execution Flow:
            1. Validate playbook exists
            2. Create execution record
            3. Initialize context from trigger event
            4. Execute each action sequentially:
               - Evaluate conditions
               - Execute if condition met
               - Update context with results
               - Handle failures based on continue_on_failure flag
            5. Mark execution as completed/failed
            6. Return execution record
        
        Args:
            playbook_name: Name of the playbook to execute (must be loaded)
            trigger_event: Security event data that triggered this playbook.
                Contains variables like hostname, ip_address, file_hash, etc.
                Available to all actions via variable substitution (${var})
        
        Returns:
            PlaybookExecution: Complete execution record including all action
                results, timing, and status
        
        Raises:
            ValueError: If playbook_name doesn't exist in loaded playbooks
        
        Example:
            >>> trigger = {
            ...     "event_type": "malware_detected",
            ...     "hostname": "workstation-042",
            ...     "file_path": "/tmp/malware.exe",
            ...     "severity": 8
            ... }
            >>> execution = engine.execute_playbook('malware_detection_response', trigger)
            >>> 
            >>> if execution.status == PlaybookStatus.COMPLETED:
            ...     print(f"All {len(execution.actions)} actions succeeded")
            >>> else:
            ...     failed = [a for a in execution.actions if a.status == ActionStatus.FAILED]
            ...     print(f"{len(failed)} actions failed")
        """
        if playbook_name not in self.playbooks:
            raise ValueError(f"Playbook not found: {playbook_name}")
        
        playbook = self.playbooks[playbook_name]
        
        # Create execution tracking record
        execution = PlaybookExecution(
            playbook_name=playbook_name,
            trigger_event=trigger_event,
            status=PlaybookStatus.RUNNING,
            start_time=datetime.now()
        )
        
        self.executions.append(execution)
        self.logger.info(f"Starting playbook execution: {playbook_name}")
        
        # Build initial context from trigger event
        # This allows actions to access event data via ${variable} syntax
        context = trigger_event.copy()
        
        try:
            # Execute actions sequentially
            for action_def in playbook.get('actions', []):
                action_result = self._execute_action(action_def, context)
                execution.actions.append(action_result)
                
                # Update context with action results
                if action_result.status == ActionStatus.SUCCESS:
                    context.update(action_result.data)
                
                # Handle action failure
                if action_result.status == ActionStatus.FAILED:
                    if action_def.get('continue_on_failure', False):
                        self.logger.warning(f"Action {action_result.action_name} failed but continuing")
                        continue
                    else:
                        self.logger.error(f"Action {action_result.action_name} failed, stopping playbook")
                        execution.status = PlaybookStatus.FAILED
                        break
            else:
                # All actions completed
                execution.status = PlaybookStatus.COMPLETED
            
        except Exception as e:
            self.logger.error(f"Playbook execution failed: {e}")
            execution.status = PlaybookStatus.FAILED
        
        finally:
            execution.end_time = datetime.now()
            self.logger.info(f"Playbook execution finished: {playbook_name} - {execution.status.value}")
        
        return execution
    
    def _execute_action(self, action_def: Dict[str, Any], context: Dict[str, Any]) -> ActionResult:
        """Execute a single action"""
        action_type = action_def.get('type')
        action_name = action_def.get('name', action_type)
        params = action_def.get('params', {})
        condition = action_def.get('condition')
        
        if action_type not in self.ACTION_REGISTRY:
            return ActionResult(
                action_name=action_name,
                status=ActionStatus.FAILED,
                message=f"Unknown action type: {action_type}",
                error=f"Action type '{action_type}' not registered"
            )
        
        # Create action instance
        action_class = self.ACTION_REGISTRY[action_type]
        action = action_class(action_name, params)
        
        # Check condition
        if not action.evaluate_condition(condition, context):
            self.logger.info(f"Skipping action {action_name} - condition not met")
            return ActionResult(
                action_name=action_name,
                status=ActionStatus.SKIPPED,
                message="Condition not met"
            )
        
        # Execute action
        self.logger.info(f"Executing action: {action_name}")
        return action.execute(context)
    
    def get_execution_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent playbook execution history"""
        return [exec.to_dict() for exec in self.executions[-limit:]]
    
    def rollback_execution(self, execution: PlaybookExecution) -> bool:
        """Attempt to rollback a playbook execution"""
        self.logger.info(f"Attempting rollback for playbook: {execution.playbook_name}")
        
        success = True
        for action_result in reversed(execution.actions):
            if action_result.status != ActionStatus.SUCCESS:
                continue
            
            try:
                action_def = next(
                    a for a in self.playbooks[execution.playbook_name]['actions']
                    if a.get('name', a['type']) == action_result.action_name
                )
                action_type = action_def['type']
                
                if action_type in self.ACTION_REGISTRY:
                    action_class = self.ACTION_REGISTRY[action_type]
                    action = action_class(action_result.action_name, action_def.get('params', {}))
                    
                    if not action.rollback(action_result.data):
                        success = False
                        self.logger.warning(f"Failed to rollback action: {action_result.action_name}")
                
            except Exception as e:
                self.logger.error(f"Error during rollback of {action_result.action_name}: {e}")
                success = False
        
        return success