import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.database.session import get_db

router = APIRouter()

@router.get("/health", tags=["Health"])
def health_check(db: Session = Depends(get_db)):
    """Health check endpoint to verify API and database connectivity."""
    db_status = "HEALTHY"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"ERROR: {str(e)}"

    return {
        "status": "UP",
        "service": "Intelligent Cyberattack Detection Using Temporal Knowledge Representation",
        "database": db_status,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
