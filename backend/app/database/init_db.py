from app.database.session import engine, Base, SessionLocal
from app.models.models import (
    Computer, UserIdentity, SecurityEvent, TemporalRelationship,
    DetectionRule, AttackAlert, AlertEvidence, SimulationRun, InvestigationReport
)
from app.detection.rules import ensure_default_rules
from app.services.simulation_service import SimulationService

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        ensure_default_rules(db)
        SimulationService.initialize_environment(db)
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
    print("Database schema successfully initialized.")
