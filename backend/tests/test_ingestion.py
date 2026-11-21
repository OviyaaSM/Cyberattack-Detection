import datetime
import pytest
from app.services.event_service import EventService
from app.schemas.schemas import SecurityEventCreate
from app.models.models import SecurityEvent, Computer

def test_single_event_ingestion(db_session):
    event_data = SecurityEventCreate(
        event_id="EVT-TEST-001",
        timestamp=datetime.datetime.utcnow(),
        computer_id="PC-FIN-01",
        hostname="finance-ws01.corp",
        user_id="alice.fin",
        source_ip="10.0.1.15",
        destination_ip="10.0.0.5",
        event_type="SUCCESSFUL_LOGIN",
        action="Standard authentication",
        status="SUCCESS",
        severity="LOW"
    )
    evt = EventService.ingest_single_event(db_session, event_data)
    assert evt.id is not None
    assert evt.event_id == "EVT-TEST-001"
    assert evt.computer_id == "PC-FIN-01"

def test_invalid_event_type_rejection(db_session):
    event_data = SecurityEventCreate(
        event_id="EVT-TEST-BAD",
        timestamp=datetime.datetime.utcnow(),
        computer_id="PC-FIN-01",
        hostname="finance-ws01.corp",
        user_id="alice.fin",
        source_ip="10.0.1.15",
        destination_ip="10.0.0.5",
        event_type="UNSUPPORTED_MALICIOUS_TYPE",
        action="Bad type",
        status="SUCCESS",
        severity="LOW"
    )
    with pytest.raises(ValueError, match="Invalid event_type"):
        EventService.ingest_single_event(db_session, event_data)

def test_duplicate_event_rejection(db_session):
    event_data = SecurityEventCreate(
        event_id="EVT-DUP-001",
        timestamp=datetime.datetime.utcnow(),
        computer_id="PC-FIN-01",
        hostname="finance-ws01.corp",
        user_id="alice.fin",
        source_ip="10.0.1.15",
        destination_ip="10.0.0.5",
        event_type="FILE_ACCESS",
        action="Read document",
        status="SUCCESS",
        severity="LOW"
    )
    EventService.ingest_single_event(db_session, event_data)
    with pytest.raises(ValueError, match="Duplicate event_id"):
        EventService.ingest_single_event(db_session, event_data)

def test_auto_creation_of_unknown_computer(db_session):
    event_data = SecurityEventCreate(
        event_id="EVT-NEWCOMP-001",
        timestamp=datetime.datetime.utcnow(),
        computer_id="PC-SALES-99",
        hostname="sales-ws99.corp",
        user_id="sales.rep",
        source_ip="10.0.5.99",
        destination_ip="10.0.0.1",
        event_type="SUCCESSFUL_LOGIN",
        action="Interactive login",
        status="SUCCESS",
        severity="LOW"
    )
    EventService.ingest_single_event(db_session, event_data)
    comp = db_session.query(Computer).filter(Computer.id == "PC-SALES-99").first()
    assert comp is not None
    assert comp.hostname == "sales-ws99.corp"
