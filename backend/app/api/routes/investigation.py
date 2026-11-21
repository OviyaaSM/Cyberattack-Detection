from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.services.investigation_service import InvestigationService
from app.schemas.schemas import InvestigationRequest, InvestigationReportResponse
from app.models.models import InvestigationReport

router = APIRouter()

@router.post("/investigation/explain", response_model=InvestigationReportResponse, tags=["Investigation"])
def explain_alert(
    request: InvestigationRequest,
    db: Session = Depends(get_db)
):
    """Generates an evidence-grounded incident investigation report for an alert."""
    try:
        report = InvestigationService.generate_investigation_report(
            db=db,
            alert_id=request.alert_id,
            use_ai=request.use_ai
        )
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

@router.get("/investigation/{alert_id}", response_model=InvestigationReportResponse, tags=["Investigation"])
def get_investigation_report(
    alert_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves an existing investigation report for an alert, or generates one if missing."""
    report = db.query(InvestigationReport).filter(InvestigationReport.alert_id == alert_id).first()
    if not report:
        try:
            report = InvestigationService.generate_investigation_report(db, alert_id=alert_id, use_ai=False)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
    return report
