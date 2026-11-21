import datetime
from app.detection.correlation import CrossComputerCorrelationEngine
from app.models.models import SecurityEvent

def test_cross_computer_correlation_paths():
    t0 = datetime.datetime(2026, 11, 20, 10, 0, 0)
    
    # 3 computers path: PC-A -> PC-B -> PC-C
    e1 = SecurityEvent(
        event_id="E-P1",
        timestamp=t0,
        computer_id="PC-A",
        hostname="host-a",
        user_id="attacker",
        source_ip="192.168.1.10",
        destination_ip="10.0.1.5",
        event_type="SUCCESSFUL_LOGIN",
        action="Login"
    )
    e2 = SecurityEvent(
        event_id="E-P2",
        timestamp=t0 + datetime.timedelta(minutes=5),
        computer_id="PC-B",
        hostname="host-b",
        user_id="attacker",
        source_ip="10.0.1.5",
        destination_ip="10.0.2.20",
        event_type="REMOTE_LOGIN",
        action="Remote pivot"
    )
    e3 = SecurityEvent(
        event_id="E-P3",
        timestamp=t0 + datetime.timedelta(minutes=12),
        computer_id="PC-C",
        hostname="host-c",
        user_id="attacker",
        source_ip="10.0.2.20",
        destination_ip="10.0.3.30",
        event_type="REMOTE_LOGIN",
        action="Remote lateral jump"
    )

    paths = CrossComputerCorrelationEngine.extract_attack_paths([e1, e2, e3])
    assert len(paths) >= 2
    assert any(p["from_computer"] == "PC-A" and p["to_computer"] == "PC-B" for p in paths)
    assert any(p["from_computer"] == "PC-B" and p["to_computer"] == "PC-C" for p in paths)

    strength = CrossComputerCorrelationEngine.calculate_correlation_strength([e1, e2, e3], {"PC-A", "PC-B", "PC-C"})
    assert strength >= 0.7
