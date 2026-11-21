import datetime
from enum import Enum
from typing import Optional, Dict, Any

class TemporalRelationType(str, Enum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"
    SIMULTANEOUS = "SIMULTANEOUS"
    WITHIN_TIME_WINDOW = "WITHIN_TIME_WINDOW"
    OVERLAPS = "OVERLAPS"
    MEETS = "MEETS"
    DURING = "DURING"
    CAUSALLY_RELATED_CANDIDATE = "CAUSALLY_RELATED_CANDIDATE"

class TimeInterval:
    def __init__(self, start: datetime.datetime, end: Optional[datetime.datetime] = None):
        self.start = start
        self.end = end if end is not None else start

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    def before(self, other: "TimeInterval") -> bool:
        return self.end < other.start

    def after(self, other: "TimeInterval") -> bool:
        return self.start > other.end

    def meets(self, other: "TimeInterval", tolerance_seconds: float = 1.0) -> bool:
        return abs((self.end - other.start).total_seconds()) <= tolerance_seconds

    def overlaps(self, other: "TimeInterval") -> bool:
        return self.start < other.end and other.start < self.end

    def during(self, other: "TimeInterval") -> bool:
        return other.start <= self.start and self.end <= other.end

    def equals(self, other: "TimeInterval", tolerance_seconds: float = 1.0) -> bool:
        return (
            abs((self.start - other.start).total_seconds()) <= tolerance_seconds
            and abs((self.end - other.end).total_seconds()) <= tolerance_seconds
        )

class TemporalFact:
    """
    Encapsulates a security event as a temporal fact with entity bindings
    and interval / point temporal characteristics.
    """
    def __init__(
        self,
        event_id: str,
        timestamp: datetime.datetime,
        end_timestamp: Optional[datetime.datetime] = None,
        event_type: str = "",
        computer_id: str = "",
        hostname: str = "",
        user_id: str = "",
        source_ip: str = "",
        destination_ip: str = "",
        action: str = "",
        status: str = "SUCCESS",
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.event_id = event_id
        self.interval = TimeInterval(timestamp, end_timestamp)
        self.timestamp = timestamp
        self.event_type = event_type
        self.computer_id = computer_id
        self.hostname = hostname
        self.user_id = user_id
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.action = action
        self.status = status
        self.session_id = session_id
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "computer_id": self.computer_id,
            "hostname": self.hostname,
            "user_id": self.user_id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "action": self.action,
            "status": self.status,
            "session_id": self.session_id,
        }
