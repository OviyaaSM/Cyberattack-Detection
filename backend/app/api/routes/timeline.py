import json
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.session import get_db
from app.models.models import SecurityEvent, TemporalRelationship, AlertEvidence, AttackAlert

router = APIRouter()

@router.get("/timeline", tags=["Timeline"])
def get_attack_timeline(
    db: Session = Depends(get_db),
    alert_id: Optional[str] = Query(None, description="Optional alert ID to scope the timeline"),
    limit: int = Query(100, ge=1, le=500)
):
    """
    Returns the chronological progression of security events, with:
    - Point in time & duration
    - Associated alert stages (if part of an attack)
    - Temporal relationships & causal edges
    """
    if alert_id:
        alert = db.query(AttackAlert).filter(AttackAlert.id == alert_id).first()
        if not alert:
            return {"events": [], "relationships": [], "alert": None}

        evidence = sorted(alert.evidence, key=lambda ev: ev.sequence_order)
        event_ids = [ev.event_id for ev in evidence]
        events = db.query(SecurityEvent).filter(SecurityEvent.event_id.in_(event_ids)).order_by(SecurityEvent.timestamp.asc()).all()
        
        relationships = db.query(TemporalRelationship).filter(
            TemporalRelationship.source_event_id.in_(event_ids),
            TemporalRelationship.target_event_id.in_(event_ids)
        ).all()
    else:
        events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.asc()).limit(limit).all()
        event_ids = [e.event_id for e in events]
        relationships = db.query(TemporalRelationship).filter(
            TemporalRelationship.source_event_id.in_(event_ids),
            TemporalRelationship.target_event_id.in_(event_ids)
        ).all()

    # Preload evidence mapping
    evidences = db.query(AlertEvidence).filter(AlertEvidence.event_id.in_(event_ids)).all()
    evidence_by_event: Dict[str, List[Dict[str, Any]]] = {}
    for ev in evidences:
        evidence_by_event.setdefault(ev.event_id, []).append({
            "alert_id": ev.alert_id,
            "stage_name": ev.stage_name,
            "role_in_attack": ev.role_in_attack,
            "sequence_order": ev.sequence_order
        })

    event_timeline = []
    for e in events:
        event_timeline.append({
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "computer_id": e.computer_id,
            "hostname": e.hostname,
            "user_id": e.user_id,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "event_type": e.event_type,
            "action": e.action,
            "status": e.status,
            "severity": e.severity,
            "session_id": e.session_id,
            "stages": evidence_by_event.get(e.event_id, [])
        })

    rel_list = [
        {
            "id": r.id,
            "source_event_id": r.source_event_id,
            "target_event_id": r.target_event_id,
            "relation_type": r.relation_type,
            "delta_seconds": r.delta_seconds,
            "confidence": r.confidence,
            "evidence_text": r.evidence_text
        }
        for r in relationships
    ]

    return {
        "events": event_timeline,
        "relationships": rel_list,
        "total_events": len(event_timeline)
    }
