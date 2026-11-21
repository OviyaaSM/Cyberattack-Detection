import datetime
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database.session import get_db
from app.models.models import Computer, SecurityEvent, AttackAlert
from app.schemas.schemas import DashboardSummary

router = APIRouter()

@router.get("/dashboard/summary", response_model=DashboardSummary, tags=["Dashboard"])
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Provides high-level metrics for the main SOC Security Overview."""
    total_computers = db.query(Computer).count()
    total_events = db.query(SecurityEvent).count()
    
    active_alerts = db.query(AttackAlert).filter(AttackAlert.status.in_(["NEW", "INVESTIGATING"])).count()
    critical_alerts = db.query(AttackAlert).filter(AttackAlert.severity == "CRITICAL").count()
    high_alerts = db.query(AttackAlert).filter(AttackAlert.severity == "HIGH").count()
    medium_alerts = db.query(AttackAlert).filter(AttackAlert.severity == "MEDIUM").count()
    low_alerts = db.query(AttackAlert).filter(AttackAlert.severity == "LOW").count()

    risk_dist = {
        "CRITICAL": critical_alerts,
        "HIGH": high_alerts,
        "MEDIUM": medium_alerts,
        "LOW": low_alerts
    }

    if critical_alerts > 0:
        system_health = "CRITICAL_COMPROMISE"
    elif high_alerts > 0:
        system_health = "HIGH_THREAT"
    elif active_alerts > 0:
        system_health = "ELEVATED_RISK"
    else:
        system_health = "NORMAL"

    return DashboardSummary(
        total_computers=total_computers,
        total_events=total_events,
        active_alerts=active_alerts,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,
        risk_distribution=risk_dist,
        system_health=system_health
    )

@router.get("/dashboard/trends", tags=["Dashboard"])
def get_dashboard_trends(db: Session = Depends(get_db)):
    """Provides time-series trend data for charts."""
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.asc()).all()
    alerts = db.query(AttackAlert).order_by(AttackAlert.detection_timestamp.asc()).all()

    # Bucket by 5-minute intervals or chronological bins
    trend_map: Dict[str, Dict[str, int]] = {}

    for e in events:
        key = e.timestamp.strftime("%H:%M")
        if key not in trend_map:
            trend_map[key] = {"time": key, "events": 0, "alerts": 0, "suspicious": 0}
        trend_map[key]["events"] += 1
        if e.severity in ("HIGH", "CRITICAL") or e.status == "FAILURE":
            trend_map[key]["suspicious"] += 1

    for a in alerts:
        key = a.detection_timestamp.strftime("%H:%M")
        if key not in trend_map:
            trend_map[key] = {"time": key, "events": 0, "alerts": 0, "suspicious": 0}
        trend_map[key]["alerts"] += 1

    # Sort by time
    trends = sorted(trend_map.values(), key=lambda x: x["time"])

    # If empty, provide placeholder baseline
    if not trends:
        now_str = datetime.datetime.utcnow().strftime("%H:%M")
        trends = [{"time": now_str, "events": 0, "alerts": 0, "suspicious": 0}]

    return {"trends": trends}
