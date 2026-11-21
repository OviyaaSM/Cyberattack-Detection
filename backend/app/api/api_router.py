from fastapi import APIRouter
from app.api.routes import (
    health, events, computers, detection, alerts,
    timeline, network, simulation, investigation, dashboard
)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(events.router)
api_router.include_router(computers.router)
api_router.include_router(detection.router)
api_router.include_router(alerts.router)
api_router.include_router(timeline.router)
api_router.include_router(network.router)
api_router.include_router(simulation.router)
api_router.include_router(investigation.router)
api_router.include_router(dashboard.router)
