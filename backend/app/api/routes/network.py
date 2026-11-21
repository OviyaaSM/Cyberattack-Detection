from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.detection.engine import CyberattackDetectionEngine
from app.schemas.schemas import NetworkGraphResponse

router = APIRouter()

@router.get("/network/graph", response_model=NetworkGraphResponse, tags=["Network"])
def get_network_graph(db: Session = Depends(get_db)):
    """Returns network graph topology, computers as nodes, and communication/attack paths as edges."""
    return CyberattackDetectionEngine.get_network_topology(db)
