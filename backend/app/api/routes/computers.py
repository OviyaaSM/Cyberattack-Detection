from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.models import Computer
from app.schemas.schemas import ComputerResponse

router = APIRouter()

@router.get("/computers", response_model=List[ComputerResponse], tags=["Computers"])
def get_computers(db: Session = Depends(get_db)):
    """Returns list of monitored computers and their status."""
    return db.query(Computer).all()

@router.get("/computers/{computer_id}", response_model=ComputerResponse, tags=["Computers"])
def get_computer(computer_id: str, db: Session = Depends(get_db)):
    comp = db.query(Computer).filter(Computer.id == computer_id).first()
    if not comp:
        raise HTTPException(status_code=404, detail=f"Computer '{computer_id}' not found.")
    return comp
