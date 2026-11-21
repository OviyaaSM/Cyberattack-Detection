from typing import List, Set, Dict, Any
from app.models.models import SecurityEvent

class RiskScoringEngine:
    """
    Transparent, explainable risk scoring system.

    SCORING FORMULA:
    RiskScore = clamp(
        BaseRuleWeight
        + EventCountWeight * min(len(events), 5)
        + SeverityWeight (max event severity contribution)
        + TemporalConsistencyScore (tightness of timestamps)
        + CrossHostWeight * (number of distinct affected computers)
        + CorrelationStrength * 15
        + AssetCriticalityBonus (if server / domain controller involved)
        + PatternCompleteness * 20,
        min=10.0,
        max=100.0
    )

    Classification Bands:
    - 0  to 39 : LOW
    - 40 to 69 : MEDIUM
    - 70 to 89 : HIGH
    - 90 to 100: CRITICAL

    Note: This is an empirical heuristic risk indicator, not a statistical probability.
    """

    @classmethod
    def calculate_risk(
        cls,
        base_rule_score: float,
        events: List[SecurityEvent],
        affected_computers: Set[str],
        correlation_strength: float,
        pattern_completeness: float = 1.0,
        is_sensitive_asset: bool = False
    ) -> Dict[str, Any]:
        breakdown: Dict[str, float] = {}

        # 1. Base rule weight (30-60)
        breakdown["base_rule"] = round(base_rule_score, 1)

        # 2. Event volume contribution (max 15)
        event_vol = min(len(events) * 3.0, 15.0)
        breakdown["event_volume"] = round(event_vol, 1)

        # 3. Maximum severity of matched events (0-20)
        severity_map = {"CRITICAL": 20.0, "HIGH": 15.0, "MEDIUM": 10.0, "LOW": 5.0}
        severities = [e.severity.upper() for e in events if e.severity]
        max_sev = max([severity_map.get(s, 5.0) for s in severities], default=5.0)
        breakdown["max_event_severity"] = round(max_sev, 1)

        # 4. Temporal consistency (5-15)
        # Closer events in chronological sequence indicate focused coordinated activity
        temporal_bonus = 5.0
        if len(events) >= 2:
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            span_minutes = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds() / 60.0
            if span_minutes <= 10.0:
                temporal_bonus = 15.0
            elif span_minutes <= 30.0:
                temporal_bonus = 10.0
        breakdown["temporal_consistency"] = round(temporal_bonus, 1)

        # 5. Cross-host propagation (0-15)
        host_count = len(affected_computers)
        host_contrib = min((host_count - 1) * 7.5, 15.0) if host_count > 1 else 0.0
        breakdown["cross_host_propagation"] = round(host_contrib, 1)

        # 6. Correlation strength (0-15)
        corr_contrib = correlation_strength * 15.0
        breakdown["correlation_strength"] = round(corr_contrib, 1)

        # 7. Sensitive asset involvement (0 or 10)
        asset_contrib = 10.0 if is_sensitive_asset else 0.0
        breakdown["sensitive_asset_bonus"] = round(asset_contrib, 1)

        # 8. Pattern completeness (0-15)
        completeness_contrib = min(pattern_completeness * 15.0, 15.0)
        breakdown["pattern_completeness"] = round(completeness_contrib, 1)

        # Total Raw Score
        raw_score = sum(breakdown.values())
        final_score = min(max(raw_score, 10.0), 100.0)
        final_score = round(final_score, 1)

        # Classification
        if final_score >= 90.0:
            classification = "CRITICAL"
        elif final_score >= 70.0:
            classification = "HIGH"
        elif final_score >= 40.0:
            classification = "MEDIUM"
        else:
            classification = "LOW"

        return {
            "score": final_score,
            "severity": classification,
            "breakdown": breakdown,
            "explanation": (
                f"Risk score {final_score}/100 ({classification}) determined from base rule ({breakdown['base_rule']}), "
                f"event count bonus (+{breakdown['event_volume']}), severity (+{breakdown['max_event_severity']}), "
                f"temporal consistency (+{breakdown['temporal_consistency']}), "
                f"multi-host propagation (+{breakdown['cross_host_propagation']}), "
                f"correlation strength (+{breakdown['correlation_strength']}), and "
                f"pattern completeness (+{breakdown['pattern_completeness']})."
            )
        }
