import csv
import io
import json
import uuid
import datetime
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from app.models.models import SecurityEvent, Computer, UserIdentity
from app.schemas.schemas import SecurityEventCreate

VALID_EVENT_TYPES = {
    "FAILED_LOGIN",
    "SUCCESSFUL_LOGIN",
    "REMOTE_LOGIN",
    "PRIVILEGE_ESCALATION",
    "SUSPICIOUS_PROCESS",
    "FILE_ACCESS",
    "SENSITIVE_FILE_ACCESS",
    "LARGE_DATA_TRANSFER",
    "UNUSUAL_NETWORK_CONNECTION",
    "MALWARE_INDICATOR"
}

class EventService:
    @staticmethod
    def normalize_timestamp(val: Any) -> datetime.datetime:
        """Parses various timestamp formats and returns UTC datetime."""
        if isinstance(val, datetime.datetime):
            return val if val.tzinfo is None else val.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        if isinstance(val, (int, float)):
            return datetime.datetime.utcfromtimestamp(val)
        if isinstance(val, str):
            val_clean = val.strip().replace("Z", "+00:00")
            try:
                dt = datetime.datetime.fromisoformat(val_clean)
                return dt if dt.tzinfo is None else dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            except Exception:
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
                    try:
                        return datetime.datetime.strptime(val.strip(), fmt)
                    except Exception:
                        pass
        return datetime.datetime.utcnow()

    @classmethod
    def ingest_single_event(cls, db: Session, data: SecurityEventCreate) -> SecurityEvent:
        """Validates and persists a single security event."""
        # Validate event type
        evt_type = data.event_type.upper().strip()
        if evt_type not in VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event_type '{data.event_type}'. Must be one of {sorted(VALID_EVENT_TYPES)}")

        # Ensure unique event_id
        event_id = data.event_id or f"EVT-{uuid.uuid4().hex[:10].upper()}"
        existing = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
        if existing:
            raise ValueError(f"Duplicate event_id '{event_id}' already exists.")

        # Ensure Computer exists
        comp = db.query(Computer).filter(Computer.id == data.computer_id).first()
        if not comp:
            comp = Computer(
                id=data.computer_id,
                hostname=data.hostname or data.computer_id,
                ip_address=data.source_ip or "192.168.1.10",
                os_type="Linux" if "srv" in data.computer_id.lower() else "Windows",
                role="Server" if "srv" in data.computer_id.lower() else "Workstation",
                status="HEALTHY"
            )
            db.add(comp)
            db.flush()

        # Ensure User exists
        if data.user_id:
            user = db.query(UserIdentity).filter(UserIdentity.id == data.user_id).first()
            if not user:
                user = UserIdentity(
                    id=data.user_id,
                    username=data.user_id,
                    role="admin" if "admin" in data.user_id.lower() or "root" in data.user_id.lower() else "user",
                    is_privileged=bool("admin" in data.user_id.lower() or "root" in data.user_id.lower())
                )
                db.add(user)
                db.flush()

        meta_json = json.dumps(data.metadata) if isinstance(data.metadata, dict) else (data.metadata or "{}")

        evt = SecurityEvent(
            event_id=event_id,
            timestamp=cls.normalize_timestamp(data.timestamp),
            computer_id=data.computer_id,
            hostname=data.hostname,
            user_id=data.user_id,
            source_ip=data.source_ip,
            destination_ip=data.destination_ip,
            event_type=evt_type,
            action=data.action,
            status=data.status.upper(),
            severity=data.severity.upper(),
            session_id=data.session_id,
            metadata_json=meta_json,
            raw_data=data.raw_data,
            is_simulated=data.is_simulated,
            simulation_run_id=data.simulation_run_id,
            ingestion_timestamp=datetime.datetime.utcnow()
        )
        db.add(evt)
        db.commit()
        db.refresh(evt)
        return evt

    @classmethod
    def ingest_bulk(cls, db: Session, events_data: List[SecurityEventCreate]) -> Tuple[int, List[str]]:
        """Ingests a list of events, skipping duplicates and reporting errors."""
        inserted = 0
        errors = []
        for idx, item in enumerate(events_data):
            try:
                cls.ingest_single_event(db, item)
                inserted += 1
            except Exception as e:
                errors.append(f"Row {idx+1}: {str(e)}")
        return inserted, errors

    @classmethod
    def parse_and_ingest_csv(cls, db: Session, file_content: str) -> Tuple[int, List[str]]:
        """Parses CSV text and ingests rows into the database."""
        reader = csv.DictReader(io.StringIO(file_content))
        events_to_create = []
        errors = []

        for row_idx, row in enumerate(reader):
            try:
                # Column mapping / normalization
                ts_raw = row.get("timestamp") or row.get("Time") or row.get("date")
                ts = cls.normalize_timestamp(ts_raw)
                
                evt_type = (row.get("event_type") or row.get("Type") or "").strip().upper()
                if evt_type not in VALID_EVENT_TYPES:
                    errors.append(f"Row {row_idx+1}: Invalid event_type '{evt_type}'")
                    continue

                comp_id = (row.get("computer_id") or row.get("host_id") or row.get("computer") or "PC-UNKNOWN").strip()
                hostname = (row.get("hostname") or comp_id).strip()
                user_id = (row.get("user_id") or row.get("user") or "anonymous").strip()
                src_ip = (row.get("source_ip") or row.get("src_ip") or "127.0.0.1").strip()
                dst_ip = (row.get("destination_ip") or row.get("dst_ip") or "127.0.0.1").strip()
                action = (row.get("action") or f"{evt_type} performed").strip()
                status = (row.get("status") or "SUCCESS").strip().upper()
                severity = (row.get("severity") or "LOW").strip().upper()
                session_id = row.get("session_id") or None
                evt_id = row.get("event_id") or None

                meta = {}
                for k, v in row.items():
                    if k not in (
                        "timestamp", "event_type", "computer_id", "hostname",
                        "user_id", "source_ip", "destination_ip", "action",
                        "status", "severity", "session_id", "event_id"
                    ) and v:
                        meta[k] = v

                evt_create = SecurityEventCreate(
                    event_id=evt_id,
                    timestamp=ts,
                    computer_id=comp_id,
                    hostname=hostname,
                    user_id=user_id,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    event_type=evt_type,
                    action=action,
                    status=status,
                    severity=severity,
                    session_id=session_id,
                    metadata=meta,
                    is_simulated=False
                )
                events_to_create.append(evt_create)
            except Exception as ex:
                errors.append(f"Row {row_idx+1}: {str(ex)}")

        inserted, bulk_errors = cls.ingest_bulk(db, events_to_create)
        errors.extend(bulk_errors)
        return inserted, errors
