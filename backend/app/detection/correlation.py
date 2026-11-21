from typing import List, Dict, Any, Set, Tuple
from app.models.models import SecurityEvent
from app.temporal.predicates import before, same_user, same_session, related_network_activity

class CrossComputerCorrelationEngine:
    """
    Correlates security events occurring across distinct computer systems.
    Identifies lateral pivot chains (e.g. Host A -> Host B -> Host C),
    tracks credential reuse across hosts, and assesses correlation strength.
    """

    @staticmethod
    def extract_attack_paths(events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """
        Extracts directed multi-host attack paths from an ordered list of security events.
        A path exists when an entity (user, session, or network connection) moves from
        one computer to another in chronological order.
        """
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        paths: List[Dict[str, Any]] = []

        # Find transitions across different hosts
        for i in range(len(sorted_events)):
            e1 = sorted_events[i]
            for j in range(i + 1, len(sorted_events)):
                e2 = sorted_events[j]

                # Only cross-computer transitions
                if e1.computer_id == e2.computer_id:
                    continue

                # Check connection mechanisms
                is_direct_net = (
                    e1.destination_ip == e2.source_ip
                    and e1.destination_ip not in ("127.0.0.1", "0.0.0.0", "")
                )
                is_user_hop = same_user(e1, e2) and e2.event_type in ("REMOTE_LOGIN", "SUCCESSFUL_LOGIN", "UNUSUAL_NETWORK_CONNECTION")
                is_session_hop = same_session(e1, e2)

                if is_direct_net or is_user_hop or is_session_hop:
                    delta_sec = (e2.timestamp - e1.timestamp).total_seconds()
                    
                    # Calculate correlation confidence
                    confidence = 0.5
                    evidence = []
                    if is_user_hop:
                        confidence += 0.3
                        evidence.append(f"Identical user '{e1.user_id}' authenticated to target")
                    if is_direct_net:
                        confidence += 0.35
                        evidence.append(f"Direct network socket link ({e1.source_ip} -> {e2.source_ip})")
                    if is_session_hop:
                        confidence += 0.25
                        evidence.append(f"Correlated session token '{e1.session_id}'")

                    paths.append({
                        "from_computer": e1.computer_id,
                        "from_hostname": e1.hostname,
                        "to_computer": e2.computer_id,
                        "to_hostname": e2.hostname,
                        "from_event_id": e1.event_id,
                        "to_event_id": e2.event_id,
                        "user_id": e1.user_id,
                        "delta_seconds": delta_sec,
                        "confidence": min(round(confidence, 2), 1.0),
                        "evidence": evidence
                    })

        return paths

    @staticmethod
    def calculate_correlation_strength(
        events: List[SecurityEvent],
        affected_computers: Set[str]
    ) -> float:
        """
        Calculates normalized cross-computer correlation strength (0.0 to 1.0).
        Evaluates user consistency, session continuity, and network continuity across hosts.
        """
        if len(affected_computers) <= 1:
            return 0.5  # Localized to single host

        users = {e.user_id for e in events if e.user_id}
        sessions = {e.session_id for e in events if e.session_id}
        
        strength = 0.4
        # Single attacker identity moving across hosts
        if len(users) == 1:
            strength += 0.3
        elif len(users) > 1:
            # Check if any user spans multiple computers
            user_host_map: Dict[str, Set[str]] = {}
            for e in events:
                user_host_map.setdefault(e.user_id, set()).add(e.computer_id)
            if any(len(hosts) > 1 for hosts in user_host_map.values()):
                strength += 0.25

        # Session continuity
        if len(sessions) == 1 and len(events) > 1:
            strength += 0.2

        # Temporal tightness
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        total_span = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds()
        if total_span <= 1800: # Within 30 minutes
            strength += 0.1

        return min(round(strength, 2), 1.0)
