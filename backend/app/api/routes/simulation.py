from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.services.simulation_service import SimulationService
from app.schemas.schemas import SimulationScenarioRequest

router = APIRouter()

@router.post("/simulation/start", tags=["Simulation"])
def start_simulation(
    request: SimulationScenarioRequest,
    db: Session = Depends(get_db)
):
    """Generates events according to scenario (normal or attack scenario) and executes detection."""
    valid_scenarios = {
        "normal", "brute_force", "lateral_movement",
        "data_exfiltration", "privilege_escalation", "multi_stage"
    }
    scen = request.scenario_type.lower()
    if scen not in valid_scenarios:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{request.scenario_type}'. Allowed: {sorted(valid_scenarios)}"
        )

    if scen == "normal":
        events = SimulationService.generate_normal_traffic(
            db,
            count=request.event_count or 15,
            seed=request.seed
        )
        return {
            "status": "success",
            "scenario": "normal",
            "events_generated": len(events)
        }
    else:
        result = SimulationService.inject_attack_scenario(
            db,
            scenario_type=scen,
            seed=request.seed
        )
        return {
            "status": "success",
            "simulation_id": result["simulation_id"],
            "scenario": result["scenario"],
            "events_generated": result["events_generated"],
            "detection": {
                "events_processed": result["detection_results"]["events_processed"],
                "temporal_relations_generated": result["detection_results"]["temporal_relations_generated"],
                "alerts_generated": result["detection_results"]["alerts_generated"]
            }
        }

@router.post("/simulation/stop", tags=["Simulation"])
def stop_simulation(db: Session = Depends(get_db)):
    """Stops any active running simulation."""
    return {"status": "success", "message": "Simulation stopped."}

@router.post("/simulation/reset", tags=["Simulation"])
def reset_simulation(db: Session = Depends(get_db)):
    """Resets the demo database: clears events, alerts, relations and restores healthy computers."""
    SimulationService.reset_database(db)
    return {"status": "success", "message": "Database and simulation state cleanly reset."}

@router.post("/simulation/scenario", tags=["Simulation"])
def inject_scenario(
    request: SimulationScenarioRequest,
    db: Session = Depends(get_db)
):
    """Convenience alias for /simulation/start."""
    return start_simulation(request, db)
