"""
SentinelX AI – Real-Time Event Type Constants (Phase 6.4)
Defines all event types broadcast over WebSocket to connected SOC clients.
"""


class RealtimeEventType:
    """Enumeration of all real-time event type strings."""

    # Alert lifecycle events
    ALERT_CREATED = "alert.created"
    ALERT_UPDATED = "alert.updated"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_INVESTIGATED = "alert.investigated"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_DISMISSED = "alert.dismissed"

    # Endpoint / agent status events
    ENDPOINT_ONLINE = "endpoint.online"
    ENDPOINT_OFFLINE = "endpoint.offline"
    ENDPOINT_STATUS_CHANGED = "endpoint.status_changed"

    # Telemetry events (throttled – only significant events)
    TELEMETRY_RECEIVED = "telemetry.received"

    # Threat detection events
    THREAT_DETECTED = "threat.detected"

    # Incident events
    INCIDENT_CREATED = "incident.created"

    # Correlation events
    CORRELATION_CREATED = "correlation.created"

    # SOAR events
    SOAR_EXECUTION_STARTED = "soar.execution_started"
    SOAR_EXECUTION_COMPLETED = "soar.execution_completed"
    SOAR_EXECUTION_FAILED = "soar.execution_failed"

    # Connection management
    PING = "ping"
    PONG = "pong"
    CONNECTION_ESTABLISHED = "connection.established"
    ERROR = "error"
