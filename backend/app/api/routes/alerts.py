from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.session import get_db
from app.models.models import AttackAlert
from app.schemas.schemas import AttackAlertResponse, AlertStatusUpdate

router = APIRouter()

@router.get("/alerts", response_model=List[AttackAlertResponse], tags=["Alerts"])
def get_alerts(
    db: Session = Depends(get_db),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    status: Optional[str] = Query(None, description="Filter by status: NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE"),
    rule_id: Optional[str] = Query(None, description="Filter by detection rule ID"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    query = db.query(AttackAlert)
    if severity:
        query = query.filter(AttackAlert.severity == severity.upper())
    if status:
        query = query.filter(AttackAlert.status == status.upper())
    if rule_id:
        query = query.filter(AttackAlert.rule_id == rule_id)

    return query.order_by(desc(AttackAlert.detection_timestamp)).offset(offset).limit(limit).all()

@router.get("/alerts/{alert_id}", response_model=AttackAlertResponse, tags=["Alerts"])
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.query(AttackAlert).filter(AttackAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert

@router.patch("/alerts/{alert_id}", response_model=AttackAlertResponse, tags=["Alerts"])
def update_alert_status(
    alert_id: str,
    status_update: AlertStatusUpdate,
    db: Session = Depends(get_db)
):
    alert = db.query(AttackAlert).filter(AttackAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    valid_statuses = {"NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
    new_status = status_update.status.upper()
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status '{new_status}'. Allowed: {sorted(valid_statuses)}")

    alert.status = new_status
    db.commit()
    db.refresh(alert)
    return alert
