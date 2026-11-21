#!/usr/bin/env python3
"""
Evaluation Script for Intelligent Cyberattack Detection System
Evaluates detection accuracy, false positive rates, and latency on labeled benchmark scenarios.
"""
import sys
import os
import time
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.database.session import Base
from app.models.models import SecurityEvent, AttackAlert
from app.detection.rules import ensure_default_rules, RuleEngine
from app.detection.engine import CyberattackDetectionEngine
from app.services.simulation_service import SimulationService

def run_evaluation():
    print("=" * 70)
    print("BENCHMARK EVALUATION: TEMPORAL CYBERATTACK DETECTION SYSTEM")
    print("=" * 70)

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    ensure_default_rules(db)
    SimulationService.initialize_environment(db)

    # Scenarios to test: (scenario_name, is_malicious, expected_rule_id)
    benchmark_suite = [
        ("normal_1", "normal", False, None),
        ("normal_2", "normal", False, None),
        ("brute_force_1", "brute_force", True, "RULE-BRUTE-FORCE"),
        ("lateral_movement_1", "lateral_movement", True, "RULE-LATERAL-MOV"),
        ("data_exfil_1", "data_exfiltration", True, "RULE-DATA-EXFIL"),
        ("priv_esc_1", "privilege_escalation", True, "RULE-PRIV-ESC"),
        ("multi_stage_1", "multi_stage", True, "RULE-MULTI-STAGE"),
        ("normal_3", "normal", False, None),
        ("brute_force_2", "brute_force", True, "RULE-BRUTE-FORCE"),
        ("data_exfil_2", "data_exfiltration", True, "RULE-DATA-EXFIL"),
    ]

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    latencies = []

    print(f"\nRunning {len(benchmark_suite)} evaluation trial scenarios...\n")

    for idx, (label, scen_type, is_malicious, expected_rule) in enumerate(benchmark_suite):
        SimulationService.reset_database(db)

        # Generate scenario
        if scen_type == "normal":
            SimulationService.generate_normal_traffic(db, count=25, seed=idx + 100)
        else:
            SimulationService.inject_attack_scenario(db, scenario_type=scen_type, seed=idx + 200)

        # Measure detection latency
        t_start = time.perf_counter()
        det_result = CyberattackDetectionEngine.run_detection_pipeline(db)
        t_end = time.perf_counter()
        latency_ms = (t_end - t_start) * 1000.0
        latencies.append(latency_ms)

        alerts = db.query(AttackAlert).all()
        has_alert = len(alerts) > 0

        if is_malicious:
            matched_expected = any(a.rule_id == expected_rule for a in alerts) if expected_rule else has_alert
            if matched_expected:
                tp += 1
                outcome = "TRUE POSITIVE (TP)"
            else:
                fn += 1
                outcome = "FALSE NEGATIVE (FN)"
        else:
            if not has_alert:
                tn += 1
                outcome = "TRUE NEGATIVE (TN)"
            else:
                fp += 1
                outcome = "FALSE POSITIVE (FP)"

        print(f"[{idx+1:02d}/{len(benchmark_suite):02d}] {label.ljust(22)} | Type: {scen_type.ljust(20)} | Latency: {latency_ms:6.2f} ms | Result: {outcome}")

    # Metrics computation
    total = len(benchmark_suite)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    print("\n" + "=" * 70)
    print("EVALUATION RESULTS SUMMARY")
    print("=" * 70)
    print(f"Total Scenarios Evaluated: {total}")
    print(f"True Positives  (TP)     : {tp}")
    print(f"True Negatives  (TN)     : {tn}")
    print(f"False Positives (FP)     : {fp}")
    print(f"False Negatives (FN)     : {fn}")
    print("-" * 70)
    print(f"Accuracy                 : {accuracy * 100:.2f}%")
    print(f"Precision                : {precision * 100:.2f}%")
    print(f"Recall                   : {recall * 100:.2f}%")
    print(f"F1-Score                 : {f1:.4f}")
    print(f"Average Detection Latency: {avg_latency:.2f} ms")
    print("=" * 70)
    print("NOTE: Evaluation performed on synthetic benchmark scenarios.")
    print("Real-world network environments contain diverse background noise.")
    print("=" * 70)

if __name__ == "__main__":
    run_evaluation()
