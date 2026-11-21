import datetime
from app.temporal.predicates import (
    before, after, simultaneous, within_time_window,
    same_user, same_session, related_computers, is_causal_candidate
)
from app.temporal.relations import TimeInterval
from app.temporal.engine import TemporalReasoningEngine
from app.services.event_service import EventService
from app.schemas.schemas import SecurityEventCreate
from app.models.models import TemporalRelationship

def test_temporal_predicates():
    class DummyEvent:
        def __init__(self, ts, user="", session=None, comp="", src="", dst="", evt_type=""):
            self.timestamp = ts
            self.user_id = user
            self.session_id = session
            self.computer_id = comp
            self.hostname = comp
            self.source_ip = src
            self.destination_ip = dst
            self.event_type = evt_type

    base = datetime.datetime(2026, 11, 20, 10, 0, 0)
    e1 = DummyEvent(base, user="alice", session="s1", comp="PC-1", src="10.0.0.1", dst="10.0.0.2", evt_type="FAILED_LOGIN")
    e2 = DummyEvent(base + datetime.timedelta(seconds=1), user="alice", session="s1", comp="PC-1", src="10.0.0.1", dst="10.0.0.2", evt_type="FAILED_LOGIN")
    e3 = DummyEvent(base + datetime.timedelta(minutes=5), user="alice", session="s1", comp="PC-1", src="10.0.0.1", dst="10.0.0.2", evt_type="SUCCESSFUL_LOGIN")
    e4 = DummyEvent(base + datetime.timedelta(minutes=45), user="bob", comp="PC-2", src="10.0.0.99", dst="10.0.0.1", evt_type="FILE_ACCESS")

    # Before & After
    assert before(e1, e3) is True
    assert before(e3, e1) is False
    assert after(e3, e1) is True

    # Simultaneous (< 2s)
    assert simultaneous(e1, e2, tolerance_seconds=2.0) is True
    assert simultaneous(e1, e3) is False

    # Within time window
    assert within_time_window(e1, e3, minutes=10) is True
    assert within_time_window(e1, e4, minutes=10) is False

    # Entity bindings
    assert same_user(e1, e2) is True
    assert same_user(e1, e4) is False
    assert same_session(e1, e2) is True
    assert same_session(e1, e4) is False
    assert related_computers(e1, e2) is True
    assert related_computers(e1, e4) is False

    # Causal candidate reasoning
    is_cand, conf, reason = is_causal_candidate(e1, e3, max_window_minutes=15)
    assert is_cand is True
    assert conf >= 0.7
    assert "authentication breach transition" in reason

def test_interval_algebra():
    t0 = datetime.datetime(2026, 11, 20, 10, 0, 0)
    i1 = TimeInterval(t0, t0 + datetime.timedelta(minutes=10))
    i2 = TimeInterval(t0 + datetime.timedelta(minutes=15), t0 + datetime.timedelta(minutes=25))
    i3 = TimeInterval(t0 + datetime.timedelta(minutes=5), t0 + datetime.timedelta(minutes=15))

    assert i1.before(i2) is True
    assert i2.after(i1) is True
    assert i1.overlaps(i3) is True

def test_out_of_order_event_inference(db_session):
    """Verifies that events arriving out of chronological order are properly sorted and connected."""
    t0 = datetime.datetime(2026, 11, 20, 12, 0, 0)
    
    # Ingest late event first
    e2 = EventService.ingest_single_event(db_session, SecurityEventCreate(
        event_id="EVT-ORD-2",
        timestamp=t0 + datetime.timedelta(minutes=5),
        computer_id="PC-FIN-01",
        hostname="finance-ws01.corp",
        user_id="alice.fin",
        source_ip="10.0.1.15",
        destination_ip="10.0.0.5",
        event_type="SUCCESSFUL_LOGIN",
        action="Login success",
        status="SUCCESS",
        severity="LOW"
    ))

    # Ingest earlier event second
    e1 = EventService.ingest_single_event(db_session, SecurityEventCreate(
        event_id="EVT-ORD-1",
        timestamp=t0,
        computer_id="PC-FIN-01",
        hostname="finance-ws01.corp",
        user_id="alice.fin",
        source_ip="10.0.1.15",
        destination_ip="10.0.0.5",
        event_type="FAILED_LOGIN",
        action="Login failure",
        status="FAILURE",
        severity="MEDIUM"
    ))

    # Engine should correctly identify e1 BEFORE e2
    rels = TemporalReasoningEngine.infer_and_store_relations(db_session, [e2, e1], max_window_minutes=30)
    assert len(rels) > 0
    before_rel = next(r for r in rels if r.relation_type == "BEFORE")
    assert before_rel.source_event_id == "EVT-ORD-1"
    assert before_rel.target_event_id == "EVT-ORD-2"
