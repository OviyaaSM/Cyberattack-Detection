import datetime
import json

def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "UP"
    assert data["database"] == "HEALTHY"

def test_api_computers(client):
    res = client.get("/api/computers")
    assert res.status_code == 200
    computers = res.json()
    assert len(computers) > 0
    assert any(c["id"] == "PC-FIN-01" for c in computers)

def test_api_create_and_get_events(client):
    payload = {
        "event_id": "EVT-API-001",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "computer_id": "PC-FIN-01",
        "hostname": "finance-ws01.corp",
        "user_id": "alice.fin",
        "source_ip": "10.0.1.15",
        "destination_ip": "10.0.0.5",
        "event_type": "SUCCESSFUL_LOGIN",
        "action": "API test authentication",
        "status": "SUCCESS",
        "severity": "LOW"
    }
    res = client.post("/api/events", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["event_id"] == "EVT-API-001"

    # Fetch events
    get_res = client.get("/api/events")
    assert get_res.status_code == 200
    items = get_res.json()
    assert any(e["event_id"] == "EVT-API-001" for e in items)

def test_api_simulation_and_detection(client):
    # Inject brute force scenario
    sim_res = client.post("/api/simulation/start", json={
        "scenario_type": "brute_force",
        "seed": 42
    })
    assert sim_res.status_code == 200
    sim_data = sim_res.json()
    assert sim_data["scenario"] == "brute_force"
    assert sim_data["events_generated"] == 5

    # Check alerts generated
    alert_res = client.get("/api/alerts")
    assert alert_res.status_code == 200
    alerts = alert_res.json()
    assert len(alerts) >= 1
    alert_id = alerts[0]["id"]

    # Patch alert status
    patch_res = client.patch(f"/api/alerts/{alert_id}", json={"status": "INVESTIGATING"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "INVESTIGATING"

    # Get investigation report
    inv_res = client.get(f"/api/investigation/{alert_id}")
    assert inv_res.status_code == 200
    inv_data = inv_res.json()
    assert inv_data["alert_id"] == alert_id
    assert "Investigation" in inv_data["summary"]

    # Check Dashboard
    dash_res = client.get("/api/dashboard/summary")
    assert dash_res.status_code == 200
    dash_data = dash_res.json()
    assert dash_data["total_events"] >= 5
    assert dash_data["active_alerts"] >= 1

    # Check Network Graph
    net_res = client.get("/api/network/graph")
    assert net_res.status_code == 200
    net_data = net_res.json()
    assert len(net_data["nodes"]) > 0

    # Check Timeline
    time_res = client.get("/api/timeline")
    assert time_res.status_code == 200
    time_data = time_res.json()
    assert len(time_data["events"]) >= 5
    assert len(time_data["relationships"]) > 0
