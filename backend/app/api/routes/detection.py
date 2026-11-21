import json
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.models import DetectionRule, AttackAlert
from app.schemas.schemas import DetectionRuleResponse, DetectionRuleUpdate
from app.detection.engine import CyberattackDetectionEngine
from app.detection.rules import ensure_default_rules

router = APIRouter()

@router.post("/detection/run", tags=["Detection"])
def run_detection(db: Session = Depends(get_db)):
    """Triggers temporal reasoning and detection across all ingested security events."""
    results = CyberattackDetectionEngine.run_detection_pipeline(db)
    return {
        "status": "success",
        "events_processed": results["events_processed"],
        "temporal_relations_generated": results["temporal_relations_generated"],
        "alerts_generated": results["alerts_generated"]
    }

@router.get("/detection/rules", response_model=List[DetectionRuleResponse], tags=["Detection"])
def get_detection_rules(db: Session = Depends(get_db)):
    """Lists all configurable detection rules."""
    ensure_default_rules(db)
    return db.query(DetectionRule).all()

@router.patch("/detection/rules/{rule_id}", response_model=DetectionRuleResponse, tags=["Detection"])
def update_detection_rule(
    rule_id: str,
    rule_update: DetectionRuleUpdate,
    db: Session = Depends(get_db)
):
    """Updates thresholds, time windows, or status of a detection rule."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")

    if rule_update.name is not None:
        rule.name = rule_update.name
    if rule_update.description is not None:
        rule.description = rule_update.description
    if rule_update.severity is not None:
        rule.severity = rule_update.severity.upper()
    if rule_update.default_risk_score is not None:
        rule.default_risk_score = rule_update.default_risk_score
    if rule_update.time_window_minutes is not None:
        rule.time_window_minutes = rule_update.time_window_minutes
    if rule_update.is_enabled is not None:
        rule.is_enabled = rule_update.is_enabled
    if rule_update.parameters is not None:
        rule.parameters_json = json.dumps(rule_update.parameters)

    db.commit()
    db.refresh(rule)
    return rule

@router.get("/detection/results", tags=["Detection"])
def get_detection_results(db: Session = Depends(get_db)):
    """Summary of detection state, rule counts, and alert breakdown."""
    total_rules = db.query(DetectionRule).count()
    enabled_rules = db.query(DetectionRule).filter(DetectionRule.is_enabled == True).count()
    total_alerts = db.query(AttackAlert).count()
    critical_alerts = db.query(AttackAlert).filter(AttackAlert.severity == "CRITICAL").count()
    high_alerts = db.query(AttackAlert).filter(AttackAlert.severity == "HIGH").count()

    return {
        "total_rules": total_rules,
        "enabled_rules": enabled_rules,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts
    }
