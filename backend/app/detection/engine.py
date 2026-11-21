import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.models import (
    SecurityEvent, AttackAlert, Computer, TemporalRelationship
)
from app.temporal.engine import TemporalReasoningEngine
from app.detection.rules import RuleEngine
from app.detection.correlation import CrossComputerCorrelationEngine
from app.schemas.schemas import NetworkGraphResponse, NetworkNode, NetworkEdge

class CyberattackDetectionEngine:
    """
    Unified detection orchestrator. Coordinates temporal reasoning,
    correlation analysis, rule execution, and network topology generation.
    """

    @classmethod
    def run_detection_pipeline(
        cls,
        db: Session,
        events: Optional[List[SecurityEvent]] = None,
        max_window_minutes: float = 60.0
    ) -> Dict[str, Any]:
        """
        Executes the full pipeline:
        1. Fetch events if not provided
        2. Infer & persist temporal relationships
        3. Evaluate temporal detection rules
        4. Update system health / computer compromise statuses
        5. Return detection execution summary
        """
        if events is None:
            events = db.query(SecurityEvent).all()

        if not events:
            return {
                "events_processed": 0,
                "temporal_relations_generated": 0,
                "alerts_generated": 0,
                "alerts": []
            }

        # 1. Temporal Knowledge Representation & Relationships
        temporal_relations = TemporalReasoningEngine.infer_and_store_relations(
            db=db,
            events=events,
            max_window_minutes=max_window_minutes
        )

        # 2. Attack Pattern Detection
        alerts = RuleEngine.evaluate_all(db=db, events=events)

        # 3. Update Computer Statuses
        all_alerts = db.query(AttackAlert).all()
        compromised_comps = set()
        suspicious_comps = set()

        for alt in all_alerts:
            comp_ids = json.loads(alt.affected_computers or "[]")
            if alt.severity in ("CRITICAL", "HIGH"):
                compromised_comps.update(comp_ids)
            else:
                suspicious_comps.update(comp_ids)

        computers = db.query(Computer).all()
        for comp in computers:
            if comp.id in compromised_comps:
                comp.status = "COMPROMISED"
            elif comp.id in suspicious_comps:
                comp.status = "SUSPICIOUS"
            else:
                comp.status = "HEALTHY"
        db.commit()

        return {
            "events_processed": len(events),
            "temporal_relations_generated": len(temporal_relations),
            "alerts_generated": len(alerts),
            "alerts": alerts
        }

    @classmethod
    def get_network_topology(cls, db: Session) -> NetworkGraphResponse:
        """
        Constructs a network graph for visualization:
        - Nodes: Computers (with IP, role, health status, alert count)
        - Edges: Observed connections and inferred attack propagation paths
        """
        computers = db.query(Computer).all()
        events = db.query(SecurityEvent).all()
        alerts = db.query(AttackAlert).all()

        # Map alert counts to computers
        alert_counts: Dict[str, int] = {}
        compromised_set = set()
        for alt in alerts:
            comp_ids = json.loads(alt.affected_computers or "[]")
            for cid in comp_ids:
                alert_counts[cid] = alert_counts.get(cid, 0) + 1
                if alt.severity in ("HIGH", "CRITICAL"):
                    compromised_set.add(cid)

        nodes: List[NetworkNode] = []
        for c in computers:
            status = "COMPROMISED" if c.id in compromised_set else ("SUSPICIOUS" if alert_counts.get(c.id, 0) > 0 else c.status)
            nodes.append(NetworkNode(
                id=c.id,
                label=f"{c.hostname} ({c.id})",
                ip=c.ip_address,
                role=c.role,
                status=status,
                alert_count=alert_counts.get(c.id, 0)
            ))

        # Build edges based on event traffic and correlated attack paths
        edge_map: Dict[str, Dict[str, Any]] = {}
        
        # Observed communication
        for e in events:
            if e.source_ip and e.destination_ip and e.source_ip != e.destination_ip:
                # Find matching computers
                src_comp = next((c.id for c in computers if c.ip_address == e.source_ip or c.id == e.computer_id), None)
                dst_comp = next((c.id for c in computers if c.ip_address == e.destination_ip), None)

                if src_comp and dst_comp and src_comp != dst_comp:
                    key = f"{src_comp}->{dst_comp}"
                    if key not in edge_map:
                        edge_map[key] = {
                            "id": f"edge-{src_comp}-{dst_comp}",
                            "source": src_comp,
                            "target": dst_comp,
                            "type": "observed",
                            "label": "Network Traffic",
                            "is_suspicious": False,
                            "event_count": 0,
                            "events": []
                        }
                    edge_map[key]["event_count"] += 1
                    if len(edge_map[key]["events"]) < 5:
                        edge_map[key]["events"].append(e.event_id)
                    if e.severity in ("HIGH", "CRITICAL") or e.event_type in ("REMOTE_LOGIN", "LARGE_DATA_TRANSFER"):
                        edge_map[key]["is_suspicious"] = True

        # Correlated attack paths from alerts
        for alt in alerts:
            comp_ids = json.loads(alt.affected_computers or "[]")
            if len(comp_ids) >= 2:
                for i in range(len(comp_ids) - 1):
                    src_id = comp_ids[i]
                    tgt_id = comp_ids[i+1]
                    key = f"{src_id}->{tgt_id}"
                    if key in edge_map:
                        edge_map[key]["type"] = "attack_path"
                        edge_map[key]["is_suspicious"] = True
                        edge_map[key]["label"] = f"Attack Path: {alt.rule_name}"
                    else:
                        edge_map[key] = {
                            "id": f"attack-{src_id}-{tgt_id}",
                            "source": src_id,
                            "target": tgt_id,
                            "type": "attack_path",
                            "label": f"Attack Path: {alt.rule_name}",
                            "is_suspicious": True,
                            "event_count": 1,
                            "events": []
                        }

        edges = [NetworkEdge(**data) for data in edge_map.values()]

        return NetworkGraphResponse(nodes=nodes, edges=edges)
