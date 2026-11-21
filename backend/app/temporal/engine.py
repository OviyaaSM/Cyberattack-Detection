from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.models import SecurityEvent, TemporalRelationship
from app.temporal.predicates import (
    before, after, simultaneous, within_time_window,
    time_delta_seconds, is_causal_candidate
)
from app.temporal.relations import TemporalRelationType

class TemporalReasoningEngine:
    """
    Main engine for computing, persisting, and querying temporal knowledge
    representations between security events.
    """

    @staticmethod
    def infer_and_store_relations(
        db: Session,
        events: List[SecurityEvent],
        max_window_minutes: float = 60.0
    ) -> List[TemporalRelationship]:
        """
        Analyzes a set of events, computes temporal predicates, identifies causal candidates,
        and saves new TemporalRelationship records in the database.
        """
        if len(events) < 2:
            return []

        # Sort events strictly by timestamp ascending
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        new_relations: List[TemporalRelationship] = []

        # Existing pairs cache to avoid duplicate insertion
        existing_pairs = set(
            db.query(TemporalRelationship.source_event_id, TemporalRelationship.target_event_id, TemporalRelationship.relation_type).all()
        )

        for i in range(len(sorted_events)):
            e1 = sorted_events[i]
            for j in range(i + 1, len(sorted_events)):
                e2 = sorted_events[j]
                
                delta_sec = time_delta_seconds(e1, e2)
                # If beyond the temporal analysis window, stop inner loop (since sorted)
                if delta_sec > (max_window_minutes * 60):
                    break

                # 1. Point relation: BEFORE
                if (e1.event_id, e2.event_id, TemporalRelationType.BEFORE.value) not in existing_pairs:
                    rel_before = TemporalRelationship(
                        source_event_id=e1.event_id,
                        target_event_id=e2.event_id,
                        relation_type=TemporalRelationType.BEFORE.value,
                        delta_seconds=delta_sec,
                        confidence=1.0,
                        evidence_text=f"Event {e1.event_id} occurred {delta_sec:.1f}s before {e2.event_id}."
                    )
                    new_relations.append(rel_before)
                    existing_pairs.add((e1.event_id, e2.event_id, TemporalRelationType.BEFORE.value))

                # 2. Simultaneous check (< 2s)
                if simultaneous(e1, e2, tolerance_seconds=2.0):
                    if (e1.event_id, e2.event_id, TemporalRelationType.SIMULTANEOUS.value) not in existing_pairs:
                        rel_sim = TemporalRelationship(
                            source_event_id=e1.event_id,
                            target_event_id=e2.event_id,
                            relation_type=TemporalRelationType.SIMULTANEOUS.value,
                            delta_seconds=delta_sec,
                            confidence=0.95,
                            evidence_text=f"Events {e1.event_id} and {e2.event_id} occurred simultaneously ({delta_sec:.2f}s gap)."
                        )
                        new_relations.append(rel_sim)
                        existing_pairs.add((e1.event_id, e2.event_id, TemporalRelationType.SIMULTANEOUS.value))

                # 3. Within time window check (e.g. 5m, 15m, 30m, 60m)
                if within_time_window(e1, e2, minutes=max_window_minutes):
                    if (e1.event_id, e2.event_id, TemporalRelationType.WITHIN_TIME_WINDOW.value) not in existing_pairs:
                        rel_win = TemporalRelationship(
                            source_event_id=e1.event_id,
                            target_event_id=e2.event_id,
                            relation_type=TemporalRelationType.WITHIN_TIME_WINDOW.value,
                            delta_seconds=delta_sec,
                            confidence=1.0,
                            evidence_text=f"Event {e2.event_id} occurred within {max_window_minutes}m of {e1.event_id} ({delta_sec/60:.1f}m)."
                        )
                        new_relations.append(rel_win)
                        existing_pairs.add((e1.event_id, e2.event_id, TemporalRelationType.WITHIN_TIME_WINDOW.value))

                # 4. Causally related candidate check
                is_candidate, conf, reason = is_causal_candidate(e1, e2, max_window_minutes=max_window_minutes)
                if is_candidate:
                    if (e1.event_id, e2.event_id, TemporalRelationType.CAUSALLY_RELATED_CANDIDATE.value) not in existing_pairs:
                        rel_causal = TemporalRelationship(
                            source_event_id=e1.event_id,
                            target_event_id=e2.event_id,
                            relation_type=TemporalRelationType.CAUSALLY_RELATED_CANDIDATE.value,
                            delta_seconds=delta_sec,
                            confidence=conf,
                            evidence_text=reason
                        )
                        new_relations.append(rel_causal)
                        existing_pairs.add((e1.event_id, e2.event_id, TemporalRelationType.CAUSALLY_RELATED_CANDIDATE.value))

        if new_relations:
            db.add_all(new_relations)
            db.commit()

        return new_relations

    @staticmethod
    def get_temporal_graph_for_events(
        events: List[SecurityEvent],
        relationships: List[TemporalRelationship]
    ) -> Dict[str, Any]:
        """
        Returns a graph representation of the events and their temporal/causal connections.
        """
        nodes = []
        for e in events:
            nodes.append({
                "id": e.event_id,
                "label": f"{e.event_type} ({e.hostname})",
                "timestamp": e.timestamp.isoformat(),
                "computer_id": e.computer_id,
                "hostname": e.hostname,
                "user_id": e.user_id,
                "severity": e.severity,
                "action": e.action,
                "status": e.status
            })

        edges = []
        for r in relationships:
            edges.append({
                "id": f"rel-{r.id}",
                "source": r.source_event_id,
                "target": r.target_event_id,
                "relation_type": r.relation_type,
                "delta_seconds": r.delta_seconds,
                "confidence": r.confidence,
                "evidence": r.evidence_text
            })

        return {"nodes": nodes, "edges": edges}
