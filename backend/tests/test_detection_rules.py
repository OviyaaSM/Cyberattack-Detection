import datetime
from app.services.event_service import EventService
from app.schemas.schemas import SecurityEventCreate
from app.detection.rules import RuleEngine
from app.models.models import AttackAlert, AlertEvidence

def test_brute_force_detection(db_session):
    t0 = datetime.datetime(2026, 11, 20, 10, 0, 0)
    events = []
    # 3 failures + 1 success within 5 minutes
    for i in range(3):
        e = EventService.ingest_single_event(db_session, SecurityEventCreate(
            event_id=f"EVT-BF-T{i+1}",
            timestamp=t0 + datetime.timedelta(seconds=i * 30),
            computer_id="PC-FIN-01",
            hostname="finance-ws01.corp",
            user_id="target_user",
            source_ip="198.51.100.1",
            destination_ip="10.0.1.15",
            event_type="FAILED_LOGIN",
            action="Failed password",
            status="FAILURE",
            severity="MEDIUM"
        ))
        events.append(e)

    e_succ = EventService.ingest_single_event(db_session, SecurityEventCreate(
        event_id="EVT-BF-TSUCC",
        timestamp=t0 + datetime.timedelta(minutes=3),
        computer_id="PC-FIN-01",
        hostname="finance-ws01.corp",
        user_id="target_user",
        source_ip="198.51.100.1",
        destination_ip="10.0.1.15",
        event_type="SUCCESSFUL_LOGIN",
        action="Successful authentication",
        status="SUCCESS",
        severity="HIGH"
    ))
    events.append(e_succ)

    alerts = RuleEngine.evaluate_all(db_session, events)
    assert len(alerts) >= 1
    bf_alert = next((a for a in alerts if a.rule_id == "RULE-BRUTE-FORCE"), None)
    assert bf_alert is not None
    assert "target_user" in bf_alert.title
    assert bf_alert.risk_score >= 70.0
    assert len(bf_alert.evidence) == 4

def test_false_positive_prevention_different_users(db_session):
    """Failed logins on User A followed by Successful login on User B should NOT trigger brute force."""
    t0 = datetime.datetime(2026, 11, 20, 10, 0, 0)
    events = []
    for i in range(3):
        e = EventService.ingest_single_event(db_session, SecurityEventCreate(
            event_id=f"EVT-FP-U1-{i}",
            timestamp=t0 + datetime.timedelta(seconds=i * 30),
            computer_id="PC-FIN-01",
            hostname="finance-ws01.corp",
            user_id="user_victim",
            source_ip="198.51.100.1",
            destination_ip="10.0.1.15",
            event_type="FAILED_LOGIN",
            action="Failed password",
            status="FAILURE",
            severity="MEDIUM"
        ))
        events.append(e)

    # Completely different user logging in
    e_other = EventService.ingest_single_event(db_session, SecurityEventCreate(
        event_id="EVT-FP-U2",
        timestamp=t0 + datetime.timedelta(minutes=2),
        computer_id="PC-FIN-01",
        hostname="finance-ws01.corp",
        user_id="user_innocent",
        source_ip="10.0.1.20",
        destination_ip="10.0.1.15",
        event_type="SUCCESSFUL_LOGIN",
        action="Routine login",
        status="SUCCESS",
        severity="LOW"
    ))
    events.append(e_other)

    alerts = RuleEngine.evaluate_all(db_session, events)
    bf_alert = next((a for a in alerts if a.rule_id == "RULE-BRUTE-FORCE"), None)
    assert bf_alert is None

def test_false_positive_prevention_time_window_exceeded(db_session):
    """Failed logins separated by 4 hours from a login should NOT trigger alert."""
    t0 = datetime.datetime(2026, 11, 20, 8, 0, 0)
    events = []
    for i in range(3):
        e = EventService.ingest_single_event(db_session, SecurityEventCreate(
            event_id=f"EVT-WIN-FAIL-{i}",
            timestamp=t0 + datetime.timedelta(seconds=i * 30),
            computer_id="PC-FIN-01",
            hostname="finance-ws01.corp",
            user_id="alice.fin",
            source_ip="10.0.1.15",
            destination_ip="10.0.0.5",
            event_type="FAILED_LOGIN",
            action="Typos",
            status="FAILURE",
            severity="MEDIUM"
        ))
        events.append(e)

    # 4 hours later
    e_late = EventService.ingest_single_event(db_session, SecurityEventCreate(
        event_id="EVT-WIN-LATE",
        timestamp=t0 + datetime.timedelta(hours=4),
        computer_id="PC-FIN-01",
        hostname="finance-ws01.corp",
        user_id="alice.fin",
        source_ip="10.0.1.15",
        destination_ip="10.0.0.5",
        event_type="SUCCESSFUL_LOGIN",
        action="Routine login next day",
        status="SUCCESS",
        severity="LOW"
    ))
    events.append(e_late)

    alerts = RuleEngine.evaluate_all(db_session, events)
    bf_alert = next((a for a in alerts if a.rule_id == "RULE-BRUTE-FORCE"), None)
    assert bf_alert is None

def test_lateral_movement_detection(db_session):
    t0 = datetime.datetime(2026, 11, 20, 11, 0, 0)
    e1 = EventService.ingest_single_event(db_session, SecurityEventCreate(
        event_id="EVT-LM-TEST-1",
        timestamp=t0,
        computer_id="PC-DEV-03",
        hostname="dev-ws03.corp",
        user_id="charlie.dev",
        source_ip="10.0.2.45",
        destination_ip="10.0.2.45",
        event_type="SUCCESSFUL_LOGIN",
        action="Workstation login",
        status="SUCCESS",
        severity="LOW"
    ))
    e2 = EventService.ingest_single_event(db_session, SecurityEventCreate(
        event_id="EVT-LM-TEST-2",
        timestamp=t0 + datetime.timedelta(minutes=10),
        computer_id="SRV-DC-01",
        hostname="ad-dc01.corp",
        user_id="charlie.dev",
        source_ip="10.0.2.45",
        destination_ip="10.0.0.5",
        event_type="REMOTE_LOGIN",
        action="Remote WMI session",
        status="SUCCESS",
        severity="HIGH"
    ))

    alerts = RuleEngine.evaluate_all(db_session, [e1, e2])
    lm_alert = next((a for a in alerts if a.rule_id == "RULE-LATERAL-MOV"), None)
    assert lm_alert is not None
    assert "PC-DEV-03" in lm_alert.affected_computers
    assert "SRV-DC-01" in lm_alert.affected_computers

def test_data_exfiltration_detection(db_session):
    t0 = datetime.datetime(2026, 11, 20, 12, 0, 0)
    e1 = EventService.ingest_single_event(db_session, SecurityEventCreate(
        event_id="EVT-EXF-TEST-1",
        timestamp=t0,
        computer_id="SRV-FILE-01",
        hostname="fileshare01.corp",
        user_id="alice.fin",
        source_ip="10.0.0.35",
        destination_ip="10.0.0.1",
        event_type="SENSITIVE_FILE_ACCESS",
        action="Read customer_data.csv",
        status="SUCCESS",
        severity="HIGH"
    ))
    e2 = EventService.ingest_single_event(db_session, SecurityEventCreate(
        event_id="EVT-EXF-TEST-2",
        timestamp=t0 + datetime.timedelta(minutes=3),
        computer_id="SRV-FILE-01",
        hostname="fileshare01.corp",
        user_id="alice.fin",
        source_ip="10.0.0.35",
        destination_ip="203.0.113.89",
        event_type="LARGE_DATA_TRANSFER",
        action="Bulk outbound data transmission",
        status="SUCCESS",
        severity="CRITICAL"
    ))

    alerts = RuleEngine.evaluate_all(db_session, [e1, e2])
    exf_alert = next((a for a in alerts if a.rule_id == "RULE-DATA-EXFIL"), None)
    assert exf_alert is not None
    assert exf_alert.severity in ("CRITICAL", "HIGH")
