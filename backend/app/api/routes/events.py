import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database.session import get_db
from app.models.models import SecurityEvent
from app.schemas.schemas import SecurityEventCreate, SecurityEventResponse
from app.services.event_service import EventService

router = APIRouter()

@router.get("/events", response_model=List[SecurityEventResponse], tags=["Events"])
def get_events(
    db: Session = Depends(get_db),
    computer_id: Optional[str] = Query(None, description="Filter by computer ID"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    user_id: Optional[str] = Query(None, description="Filter by user"),
    search: Optional[str] = Query(None, description="Search action or hostname"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    query = db.query(SecurityEvent)
    if computer_id:
        query = query.filter(SecurityEvent.computer_id == computer_id)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type.upper())
    if severity:
        query = query.filter(SecurityEvent.severity == severity.upper())
    if user_id:
        query = query.filter(SecurityEvent.user_id == user_id)
    if search:
        s = f"%{search}%"
        query = query.filter((SecurityEvent.action.ilike(s)) | (SecurityEvent.hostname.ilike(s)))

    return query.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit).all()

@router.post("/events", response_model=SecurityEventResponse, tags=["Events"])
def create_event(
    event_in: SecurityEventCreate,
    db: Session = Depends(get_db)
):
    try:
        evt = EventService.ingest_single_event(db, event_in)
        return evt
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest event: {str(e)}")

@router.post("/events/bulk", tags=["Events"])
def create_events_bulk(
    events_in: List[SecurityEventCreate],
    db: Session = Depends(get_db)
):
    inserted, errors = EventService.ingest_bulk(db, events_in)
    return {
        "status": "success" if not errors else "partial_success",
        "inserted_count": inserted,
        "failed_count": len(errors),
        "errors": errors[:50]
    }

@router.post("/events/upload", tags=["Events"])
async def upload_events_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Accepts CSV or JSON file upload containing security logs."""
    filename = file.filename.lower()
    content_bytes = await file.read()
    content_str = content_bytes.decode("utf-8", errors="replace")

    if filename.endswith(".csv"):
        inserted, errors = EventService.parse_and_ingest_csv(db, content_str)
        return {
            "format": "csv",
            "inserted_count": inserted,
            "failed_count": len(errors),
            "errors": errors[:50]
        }
    elif filename.endswith(".json"):
        try:
            data = json.loads(content_str)
            if isinstance(data, dict):
                data = [data]
            validated = [SecurityEventCreate(**item) for item in data]
            inserted, errors = EventService.ingest_bulk(db, validated)
            return {
                "format": "json",
                "inserted_count": inserted,
                "failed_count": len(errors),
                "errors": errors[:50]
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON format: {str(e)}")
    else:
        raise HTTPException(status_code=400, detail="Unsupported file format. Please upload .csv or .json files.")
