import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.database.session import Base, get_db
from app.models.models import (
    Computer, UserIdentity, SecurityEvent, TemporalRelationship,
    DetectionRule, AttackAlert, AlertEvidence, SimulationRun, InvestigationReport
)
from app.detection.rules import ensure_default_rules
from app.services.simulation_service import SimulationService
from main import app

# StaticPool ensures the single in-memory SQLite database persists across all sessions and requests in a test
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    ensure_default_rules(session)
    SimulationService.initialize_environment(session)
    yield session
    session.close()
    Base.metadata.drop_all(bind=test_engine)

@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
