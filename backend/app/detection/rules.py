import json
import uuid
import datetime
from typing import List, Dict, Any, Optional, Set, Tuple
from sqlalchemy.orm import Session
from app.models.models import (
    SecurityEvent, AttackAlert, AlertEvidence, DetectionRule, Computer
)
from app.temporal.predicates import (
    before, after, within_time_window, same_user, same_session,
    related_computers, related_network_activity, time_delta_seconds
)
from app.detection.correlation import CrossComputerCorrelationEngine
from app.detection.scoring import RiskScoringEngine

DEFAULT_RULES = [
    {
        "id": "RULE-BRUTE-FORCE",
        "name": "Brute-force Account Compromise",
        "description": "Detects multiple failed authentication attempts followed by a successful login for the same account within a configured time window.",
        "scenario": "brute_force",
        "severity": "HIGH",
        "default_risk_score": 75.0,
        "time_window_minutes": 10,
        "parameters": {"min_failed_attempts": 3}
    },
    {
        "id": "RULE-LATERAL-MOV",
        "name": "Lateral Movement Across Systems",
        "description": "Detects authentication or compromise on one computer followed by remote authentication or access to a secondary host by correlated credentials or network activity.",
        "scenario": "lateral_movement",
        "severity": "HIGH",
        "default_risk_score": 80.0,
        "time_window_minutes": 30,
        "parameters": {}
    },
    {
        "id": "RULE-DATA-EXFIL",
        "name": "Sensitive File Staging & Data Exfiltration",
        "description": "Detects unauthorized or sensitive file access followed by an unusually large outbound network transfer or connection within a short interval.",
        "scenario": "data_exfiltration",
        "severity": "CRITICAL",
        "default_risk_score": 88.0,
        "time_window_minutes": 20,
        "parameters": {}
    },
    {
        "id": "RULE-PRIV-ESC",
        "name": "Privilege Escalation Chain",
        "description": "Detects normal user authentication followed rapidly by unauthorized privilege alteration and subsequent privileged resource access on the host.",
        "scenario": "privilege_escalation",
        "severity": "HIGH",
        "default_risk_score": 78.0,
        "time_window_minutes": 15,
        "parameters": {}
    },
    {
        "id": "RULE-MULTI-STAGE",
        "name": "Coordinated Multi-Stage Cyberattack",
        "description": "Detects an advanced multi-phase persistent attack spanning credential brute-forcing, breach, lateral movement across computers, privilege escalation, and external data exfiltration.",
        "scenario": "multi_stage",
        "severity": "CRITICAL",
        "default_risk_score": 95.0,
        "time_window_minutes": 60,
        "parameters": {}
    }
]

def ensure_default_rules(db: Session):
    """Initializes standard detection rules if not already in the database."""
    for r in DEFAULT_RULES:
        existing = db.query(DetectionRule).filter(DetectionRule.id == r["id"]).first()
        if not existing:
            rule_obj = DetectionRule(
                id=r["id"],
                name=r["name"],
                description=r["description"],
                scenario=r["scenario"],
                severity=r["severity"],
                default_risk_score=r["default_risk_score"],
                time_window_minutes=r["time_window_minutes"],
                is_enabled=True,
                parameters_json=json.dumps(r["parameters"])
            )
            db.add(rule_obj)
    db.commit()


class RuleEngine:
    """
    Executes declarative temporal detection rules over ingested security events.
    Enforces temporal constraints, entity bindings, and false-positive prevention.
    """

    @staticmethod
    def _is_duplicate_alert(db: Session, matched_event_ids: List[str], rule_id: str) -> bool:
        """Checks if an alert for this exact set of events and rule already exists."""
        event_set = set(matched_event_ids)
        existing_alerts = db.query(AttackAlert).filter(AttackAlert.rule_id == rule_id).all()
        for alt in existing_alerts:
            alt_evidence_ids = {ev.event_id for ev in alt.evidence}
            if alt_evidence_ids == event_set:
                return True
        return False

    @classmethod
    def evaluate_all(cls, db: Session, events: List[SecurityEvent]) -> List[AttackAlert]:
        ensure_default_rules(db)
        if not events:
            return []

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        generated_alerts: List[AttackAlert] = []

        rules = {r.id: r for r in db.query(DetectionRule).filter(DetectionRule.is_enabled == True).all()}

        # 1. Brute Force Rule
        if "RULE-BRUTE-FORCE" in rules:
            rule = rules["RULE-BRUTE-FORCE"]
            alerts = cls._detect_brute_force(db, sorted_events, rule)
            generated_alerts.extend(alerts)

        # 2. Lateral Movement Rule
        if "RULE-LATERAL-MOV" in rules:
            rule = rules["RULE-LATERAL-MOV"]
            alerts = cls._detect_lateral_movement(db, sorted_events, rule)
            generated_alerts.extend(alerts)

        # 3. Data Exfiltration Rule
        if "RULE-DATA-EXFIL" in rules:
            rule = rules["RULE-DATA-EXFIL"]
            alerts = cls._detect_data_exfiltration(db, sorted_events, rule)
            generated_alerts.extend(alerts)

        # 4. Privilege Escalation Rule
        if "RULE-PRIV-ESC" in rules:
            rule = rules["RULE-PRIV-ESC"]
            alerts = cls._detect_privilege_escalation(db, sorted_events, rule)
            generated_alerts.extend(alerts)

        # 5. Multi-Stage Coordinated Attack Rule
        if "RULE-MULTI-STAGE" in rules:
            rule = rules["RULE-MULTI-STAGE"]
            alerts = cls._detect_multi_stage(db, sorted_events, rule)
            generated_alerts.extend(alerts)

        return generated_alerts

    @classmethod
    def _detect_brute_force(cls, db: Session, events: List[SecurityEvent], rule: DetectionRule) -> List[AttackAlert]:
        alerts = []
        params = json.loads(rule.parameters_json or "{}")
        min_fails = params.get("min_failed_attempts", 3)
        window = rule.time_window_minutes

        # Group events by user_id
        user_events: Dict[str, List[SecurityEvent]] = {}
        for e in events:
            if e.user_id:
                user_events.setdefault(e.user_id.lower(), []).append(e)

        for user, u_events in user_events.items():
            u_events.sort(key=lambda e: e.timestamp)
            for i, success_evt in enumerate(u_events):
                if success_evt.event_type != "SUCCESSFUL_LOGIN":
                    continue

                # Look back for failed logins within window
                failed_preceding = []
                for prev in u_events[:i]:
                    if prev.event_type == "FAILED_LOGIN" and within_time_window(prev, success_evt, window):
                        failed_preceding.append(prev)

                if len(failed_preceding) >= min_fails:
                    matched_ids = [f.event_id for f in failed_preceding] + [success_evt.event_id]
                    if cls._is_duplicate_alert(db, matched_ids, rule.id):
                        continue

                    all_matched = failed_preceding + [success_evt]
                    affected_comps = list({e.computer_id for e in all_matched})
                    start_t = failed_preceding[0].timestamp
                    end_t = success_evt.timestamp
                    delta_m = (end_t - start_t).total_seconds() / 60.0

                    risk_data = RiskScoringEngine.calculate_risk(
                        base_rule_score=rule.default_risk_score,
                        events=all_matched,
                        affected_computers=set(affected_comps),
                        correlation_strength=0.9,
                        pattern_completeness=1.0
                    )

                    constraints = {
                        "temporal_window_minutes": window,
                        "elapsed_minutes": round(delta_m, 2),
                        "failed_attempts_count": len(failed_preceding),
                        "temporal_predicate": f"before(FAILED_LOGIN x {len(failed_preceding)}, SUCCESSFUL_LOGIN) AND within_time_window({window}m)",
                        "entity_binding": f"user_id == '{user}'"
                    }

                    explanation = (
                        f"Detected brute-force credential attack against account '{user}'. "
                        f"{len(failed_preceding)} failed authentication attempts were observed on "
                        f"computer '{failed_preceding[0].hostname}', followed by a successful login "
                        f"at {end_t.strftime('%H:%M:%S UTC')} ({delta_m:.1f} minutes elapsed). "
                        f"Chronological temporal constraints and user identity correlation verified."
                    )

                    alert = AttackAlert(
                        id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                        rule_id=rule.id,
                        rule_name=rule.name,
                        title=f"Brute-Force Account Compromise: {user}",
                        severity=risk_data["severity"],
                        risk_score=risk_data["score"],
                        affected_computers=json.dumps(affected_comps),
                        related_users=json.dumps([user]),
                        start_time=start_t,
                        end_time=end_t,
                        status="NEW",
                        explanation=explanation,
                        temporal_constraints=json.dumps(constraints),
                        detection_timestamp=datetime.datetime.utcnow()
                    )
                    db.add(alert)
                    db.flush()

                    for idx, fe in enumerate(failed_preceding):
                        db.add(AlertEvidence(
                            alert_id=alert.id,
                            event_id=fe.event_id,
                            sequence_order=idx + 1,
                            stage_name="Credential Access",
                            role_in_attack=f"Failed authentication attempt #{idx+1} from source {fe.source_ip}"
                        ))
                    db.add(AlertEvidence(
                        alert_id=alert.id,
                        event_id=success_evt.event_id,
                        sequence_order=len(failed_preceding) + 1,
                        stage_name="Initial Compromise",
                        role_in_attack="Successful authentication breaching the targeted account"
                    ))
                    db.commit()
                    alerts.append(alert)

        return alerts

    @classmethod
    def _detect_lateral_movement(cls, db: Session, events: List[SecurityEvent], rule: DetectionRule) -> List[AttackAlert]:
        alerts = []
        window = rule.time_window_minutes

        for i in range(len(events)):
            e1 = events[i]
            if e1.event_type not in ("SUCCESSFUL_LOGIN", "REMOTE_LOGIN", "PRIVILEGE_ESCALATION"):
                continue

            for j in range(i + 1, len(events)):
                e2 = events[j]
                if not within_time_window(e1, e2, window):
                    break

                # Must be different computers
                if e1.computer_id == e2.computer_id:
                    continue

                # Target must be remote login or high-severity network session
                if e2.event_type not in ("REMOTE_LOGIN",) and not (e2.event_type == "UNUSUAL_NETWORK_CONNECTION" and e2.severity in ("HIGH", "CRITICAL")):
                    continue

                # Check entity correlation: same user OR direct network hop
                is_user_match = same_user(e1, e2)
                is_net_hop = (e1.destination_ip == e2.source_ip or e1.source_ip == e2.source_ip) and e1.source_ip not in ("127.0.0.1", "")

                if is_user_match or is_net_hop:
                    matched_ids = [e1.event_id, e2.event_id]
                    if cls._is_duplicate_alert(db, matched_ids, rule.id):
                        continue

                    all_matched = [e1, e2]
                    affected_comps = [e1.computer_id, e2.computer_id]
                    users = list({e.user_id for e in all_matched if e.user_id})
                    delta_sec = time_delta_seconds(e1, e2)

                    corr_strength = CrossComputerCorrelationEngine.calculate_correlation_strength(all_matched, set(affected_comps))
                    risk_data = RiskScoringEngine.calculate_risk(
                        base_rule_score=rule.default_risk_score,
                        events=all_matched,
                        affected_computers=set(affected_comps),
                        correlation_strength=corr_strength,
                        pattern_completeness=1.0
                    )

                    constraints = {
                        "temporal_window_minutes": window,
                        "elapsed_seconds": round(delta_sec, 1),
                        "temporal_predicate": f"before({e1.event_type}, {e2.event_type}) AND within_time_window({window}m)",
                        "host_transition": f"{e1.hostname} ({e1.computer_id}) -> {e2.hostname} ({e2.computer_id})",
                        "correlation_type": "Same User & Network Hop" if (is_user_match and is_net_hop) else ("Same User" if is_user_match else "Network Route")
                    }

                    explanation = (
                        f"Detected lateral movement from {e1.hostname} to {e2.hostname}. "
                        f"Initial authentication on {e1.hostname} was followed {delta_sec/60:.1f} minutes later "
                        f"by remote connection/authentication on {e2.hostname} using identity '{e2.user_id}'. "
                        f"Temporal sequence satisfies cross-computer pivot constraints."
                    )

                    alert = AttackAlert(
                        id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                        rule_id=rule.id,
                        rule_name=rule.name,
                        title=f"Lateral Movement: {e1.hostname} -> {e2.hostname}",
                        severity=risk_data["severity"],
                        risk_score=risk_data["score"],
                        affected_computers=json.dumps(affected_comps),
                        related_users=json.dumps(users),
                        start_time=e1.timestamp,
                        end_time=e2.timestamp,
                        status="NEW",
                        explanation=explanation,
                        temporal_constraints=json.dumps(constraints),
                        detection_timestamp=datetime.datetime.utcnow()
                    )
                    db.add(alert)
                    db.flush()

                    db.add(AlertEvidence(
                        alert_id=alert.id,
                        event_id=e1.event_id,
                        sequence_order=1,
                        stage_name="Initial Foothold",
                        role_in_attack=f"Authentication activity on origin computer {e1.hostname}"
                    ))
                    db.add(AlertEvidence(
                        alert_id=alert.id,
                        event_id=e2.event_id,
                        sequence_order=2,
                        stage_name="Lateral Movement",
                        role_in_attack=f"Remote authentication pivot to target computer {e2.hostname}"
                    ))
                    db.commit()
                    alerts.append(alert)

        return alerts

    @classmethod
    def _detect_data_exfiltration(cls, db: Session, events: List[SecurityEvent], rule: DetectionRule) -> List[AttackAlert]:
        alerts = []
        window = rule.time_window_minutes

        for i in range(len(events)):
            e1 = events[i]
            is_sensitive_file = (
                e1.event_type == "SENSITIVE_FILE_ACCESS" or
                any(keyword in e1.action.lower() for keyword in ("confidential", "sensitive", "secret", "patent", "financial", "dump", ".zip", ".tar.gz", "/etc/shadow"))
            )
            if not is_sensitive_file:
                continue

            for j in range(i + 1, len(events)):
                e2 = events[j]
                if not within_time_window(e1, e2, window):
                    break

                is_exfil_channel = (
                    e2.event_type == "LARGE_DATA_TRANSFER" or
                    (e2.event_type == "UNUSUAL_NETWORK_CONNECTION" and e2.severity in ("HIGH", "CRITICAL")) or
                    any(keyword in e2.action.lower() for keyword in ("exfil", "outbound", "transfer"))
                )
                if not is_exfil_channel:
                    continue

                # Correlation: same host OR same user OR same session
                is_host_match = (e1.computer_id == e2.computer_id)
                is_user_match = same_user(e1, e2)
                is_session_match = same_session(e1, e2)

                if is_host_match or is_user_match or is_session_match:
                    matched_ids = [e1.event_id, e2.event_id]
                    if cls._is_duplicate_alert(db, matched_ids, rule.id):
                        continue

                    all_matched = [e1, e2]
                    affected_comps = list({e.computer_id for e in all_matched})
                    users = list({e.user_id for e in all_matched if e.user_id})
                    delta_sec = time_delta_seconds(e1, e2)

                    risk_data = RiskScoringEngine.calculate_risk(
                        base_rule_score=rule.default_risk_score,
                        events=all_matched,
                        affected_computers=set(affected_comps),
                        correlation_strength=0.95,
                        pattern_completeness=1.0,
                        is_sensitive_asset=True
                    )

                    constraints = {
                        "temporal_window_minutes": window,
                        "elapsed_seconds": round(delta_sec, 1),
                        "temporal_predicate": f"before({e1.event_type}, {e2.event_type}) AND within_time_window({window}m)",
                        "data_target_ip": e2.destination_ip,
                        "staging_host": e1.hostname
                    }

                    explanation = (
                        f"Detected data exfiltration sequence on {e1.hostname}. "
                        f"Access to sensitive files by user '{e1.user_id}' was followed within {delta_sec:.0f} seconds "
                        f"by an outbound data transfer to external IP {e2.destination_ip}. "
                        f"Temporal proximity strongly indicates data staging and exfiltration."
                    )

                    alert = AttackAlert(
                        id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                        rule_id=rule.id,
                        rule_name=rule.name,
                        title=f"Data Exfiltration Alert: {e1.hostname}",
                        severity=risk_data["severity"],
                        risk_score=risk_data["score"],
                        affected_computers=json.dumps(affected_comps),
                        related_users=json.dumps(users),
                        start_time=e1.timestamp,
                        end_time=e2.timestamp,
                        status="NEW",
                        explanation=explanation,
                        temporal_constraints=json.dumps(constraints),
                        detection_timestamp=datetime.datetime.utcnow()
                    )
                    db.add(alert)
                    db.flush()

                    db.add(AlertEvidence(
                        alert_id=alert.id,
                        event_id=e1.event_id,
                        sequence_order=1,
                        stage_name="Data Staging",
                        role_in_attack=f"Access to sensitive files: {e1.action}"
                    ))
                    db.add(AlertEvidence(
                        alert_id=alert.id,
                        event_id=e2.event_id,
                        sequence_order=2,
                        stage_name="Exfiltration",
                        role_in_attack=f"High-volume data transfer to destination {e2.destination_ip}"
                    ))
                    db.commit()
                    alerts.append(alert)

        return alerts

    @classmethod
    def _detect_privilege_escalation(cls, db: Session, events: List[SecurityEvent], rule: DetectionRule) -> List[AttackAlert]:
        alerts = []
        window = rule.time_window_minutes

        for i in range(len(events)):
            e1 = events[i]
            if e1.event_type not in ("SUCCESSFUL_LOGIN", "REMOTE_LOGIN"):
                continue

            for j in range(i + 1, len(events)):
                e2 = events[j]
                if not within_time_window(e1, e2, window):
                    break

                if e2.event_type not in ("PRIVILEGE_ESCALATION", "SUSPICIOUS_PROCESS"):
                    continue

                if e1.computer_id != e2.computer_id and not same_user(e1, e2):
                    continue

                for k in range(j + 1, len(events)):
                    e3 = events[k]
                    if not within_time_window(e2, e3, window):
                        break

                    if e3.event_type not in ("SENSITIVE_FILE_ACCESS", "FILE_ACCESS", "SUSPICIOUS_PROCESS"):
                        continue

                    if e2.computer_id == e3.computer_id:
                        matched_ids = [e1.event_id, e2.event_id, e3.event_id]
                        if cls._is_duplicate_alert(db, matched_ids, rule.id):
                            continue

                        all_matched = [e1, e2, e3]
                        affected_comps = list({e.computer_id for e in all_matched})
                        users = list({e.user_id for e in all_matched if e.user_id})

                        risk_data = RiskScoringEngine.calculate_risk(
                            base_rule_score=rule.default_risk_score,
                            events=all_matched,
                            affected_computers=set(affected_comps),
                            correlation_strength=0.9,
                            pattern_completeness=1.0
                        )

                        constraints = {
                            "temporal_window_minutes": window,
                            "temporal_chain": "before(LOGIN, PRIV_ESC) AND before(PRIV_ESC, SENSITIVE_ACCESS)",
                            "host": e1.hostname,
                            "user": e1.user_id
                        }

                        explanation = (
                            f"Detected privilege escalation chain on {e1.hostname}. "
                            f"User '{e1.user_id}' authenticated at {e1.timestamp.strftime('%H:%M:%S UTC')}, "
                            f"escalated privileges via {e2.action} at {e2.timestamp.strftime('%H:%M:%S UTC')}, "
                            f"and subsequently accessed protected resources ({e3.action})."
                        )

                        alert = AttackAlert(
                            id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                            rule_id=rule.id,
                            rule_name=rule.name,
                            title=f"Privilege Escalation Chain: {e1.hostname}",
                            severity=risk_data["severity"],
                            risk_score=risk_data["score"],
                            affected_computers=json.dumps(affected_comps),
                            related_users=json.dumps(users),
                            start_time=e1.timestamp,
                            end_time=e3.timestamp,
                            status="NEW",
                            explanation=explanation,
                            temporal_constraints=json.dumps(constraints),
                            detection_timestamp=datetime.datetime.utcnow()
                        )
                        db.add(alert)
                        db.flush()

                        db.add(AlertEvidence(
                            alert_id=alert.id,
                            event_id=e1.event_id,
                            sequence_order=1,
                            stage_name="Initial Authentication",
                            role_in_attack=f"Initial login as user '{e1.user_id}'"
                        ))
                        db.add(AlertEvidence(
                            alert_id=alert.id,
                            event_id=e2.event_id,
                            sequence_order=2,
                            stage_name="Privilege Escalation",
                            role_in_attack=f"Privilege alteration event: {e2.action}"
                        ))
                        db.add(AlertEvidence(
                            alert_id=alert.id,
                            event_id=e3.event_id,
                            sequence_order=3,
                            stage_name="Privileged Resource Access",
                            role_in_attack=f"Accessing restricted asset: {e3.action}"
                        ))
                        db.commit()
                        alerts.append(alert)

        return alerts

    @classmethod
    def _detect_multi_stage(cls, db: Session, events: List[SecurityEvent], rule: DetectionRule) -> List[AttackAlert]:
        alerts = []
        window = rule.time_window_minutes

        # We look for a composite multi-stage attack:
        # Stage 1: Failed login(s) or initial exploit
        # Stage 2: Successful login on PC-A
        # Stage 3: Lateral movement to PC-B
        # Stage 4: Sensitive file access on PC-B
        # Stage 5: Outbound data transfer
        for i, s2 in enumerate(events):
            if s2.event_type != "SUCCESSFUL_LOGIN":
                continue

            # Stage 1 (Failed login before s2 within 15m)
            s1_candidates = [
                e for e in events[:i]
                if e.event_type == "FAILED_LOGIN"
                and same_user(e, s2)
                and within_time_window(e, s2, 15)
            ]
            if not s1_candidates:
                continue
            s1 = s1_candidates[-1]

            # Stage 3 (Lateral movement from s2 host to another host within window)
            for j in range(i + 1, len(events)):
                s3 = events[j]
                if not within_time_window(s2, s3, window):
                    break
                if s3.event_type not in ("REMOTE_LOGIN", "UNUSUAL_NETWORK_CONNECTION") or s3.computer_id == s2.computer_id:
                    continue
                if not (same_user(s2, s3) or s2.destination_ip == s3.source_ip or s2.computer_id in s3.source_ip):
                    continue

                # Stage 4 (Sensitive file access on target system)
                for k in range(j + 1, len(events)):
                    s4 = events[k]
                    if not within_time_window(s3, s4, window):
                        break
                    if s4.event_type not in ("SENSITIVE_FILE_ACCESS", "FILE_ACCESS") or s4.computer_id != s3.computer_id:
                        continue

                    # Stage 5 (Large data transfer / exfiltration)
                    for m in range(k + 1, len(events)):
                        s5 = events[m]
                        if not within_time_window(s4, s5, window):
                            break
                        if s5.event_type not in ("LARGE_DATA_TRANSFER", "UNUSUAL_NETWORK_CONNECTION"):
                            continue

                        # Full 5-stage attack confirmed
                        matched_ids = [s1.event_id, s2.event_id, s3.event_id, s4.event_id, s5.event_id]
                        if cls._is_duplicate_alert(db, matched_ids, rule.id):
                            continue

                        all_matched = [s1, s2, s3, s4, s5]
                        affected_comps = list({e.computer_id for e in all_matched})
                        users = list({e.user_id for e in all_matched if e.user_id})

                        risk_data = RiskScoringEngine.calculate_risk(
                            base_rule_score=rule.default_risk_score,
                            events=all_matched,
                            affected_computers=set(affected_comps),
                            correlation_strength=1.0,
                            pattern_completeness=1.0,
                            is_sensitive_asset=True
                        )

                        span_min = (s5.timestamp - s1.timestamp).total_seconds() / 60.0
                        constraints = {
                            "stages_count": 5,
                            "temporal_progression": f"{s1.timestamp.strftime('%H:%M')} -> {s2.timestamp.strftime('%H:%M')} -> {s3.timestamp.strftime('%H:%M')} -> {s4.timestamp.strftime('%H:%M')} -> {s5.timestamp.strftime('%H:%M')}",
                            "total_span_minutes": round(span_min, 1),
                            "origin_host": s2.hostname,
                            "pivot_host": s3.hostname,
                            "exfiltration_target": s5.destination_ip
                        }

                        explanation = (
                            f"CRITICAL: Full coordinated multi-stage cyberattack sequence detected spanning {len(affected_comps)} systems. "
                            f"1) Brute force credential access against '{s1.user_id}' on {s1.hostname}; "
                            f"2) Initial authentication breach at {s2.timestamp.strftime('%H:%M:%S UTC')}; "
                            f"3) Lateral movement to internal host {s3.hostname}; "
                            f"4) Sensitive document discovery and staging; "
                            f"5) Data exfiltration to external endpoint {s5.destination_ip}. "
                            f"All chronological, temporal interval, and cross-machine correlation constraints verified."
                        )

                        alert = AttackAlert(
                            id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
                            rule_id=rule.id,
                            rule_name=rule.name,
                            title=f"Coordinated Multi-Stage Cyberattack: {s2.hostname} -> {s3.hostname}",
                            severity="CRITICAL",
                            risk_score=risk_data["score"],
                            affected_computers=json.dumps(affected_comps),
                            related_users=json.dumps(users),
                            start_time=s1.timestamp,
                            end_time=s5.timestamp,
                            status="NEW",
                            explanation=explanation,
                            temporal_constraints=json.dumps(constraints),
                            detection_timestamp=datetime.datetime.utcnow()
                        )
                        db.add(alert)
                        db.flush()

                        stages = [
                            (s1, 1, "Credential Access", "Failed authentication brute force attempt"),
                            (s2, 2, "Initial Access", "Successful account breach"),
                            (s3, 3, "Lateral Movement", f"Remote network pivot from {s2.hostname} to {s3.hostname}"),
                            (s4, 4, "Collection & Staging", f"Access to restricted sensitive file {s4.action}"),
                            (s5, 5, "Exfiltration", f"High-volume data transfer to {s5.destination_ip}")
                        ]
                        for evt, order, stage_name, role_desc in stages:
                            db.add(AlertEvidence(
                                alert_id=alert.id,
                                event_id=evt.event_id,
                                sequence_order=order,
                                stage_name=stage_name,
                                role_in_attack=role_desc
                            ))
                        db.commit()
                        alerts.append(alert)
                        break

        return alerts
