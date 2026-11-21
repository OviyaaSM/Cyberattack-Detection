#!/usr/bin/env python3
"""
Seed Script for Intelligent Cyberattack Detection System
Seeds simulated enterprise computers, users, default rules, and sample attacks.
"""
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.database.session import SessionLocal
from app.database.init_db import init_db
from app.services.simulation_service import SimulationService
from app.detection.engine import CyberattackDetectionEngine

def seed():
    print("Initializing database...")
    init_db()
    db = SessionLocal()
    try:
        print("Resetting database to clean baseline...")
        SimulationService.reset_database(db)

        print("Generating baseline normal operational traffic...")
        SimulationService.generate_normal_traffic(db, count=20, seed=42)

        print("Injecting sample Multi-Stage Cyberattack scenario...")
        SimulationService.inject_attack_scenario(db, scenario_type="multi_stage", seed=101)

        print("Executing detection pipeline...")
        result = CyberattackDetectionEngine.run_detection_pipeline(db)

        print(f"Database successfully seeded:")
        print(f"  - Events processed: {result['events_processed']}")
        print(f"  - Temporal relations generated: {result['temporal_relations_generated']}")
        print(f"  - Alerts generated: {result['alerts_generated']}")
    finally:
        db.close()

if __name__ == "__main__":
    seed()
