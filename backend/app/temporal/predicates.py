import datetime
from typing import Tuple, Any

def before(e1: Any, e2: Any) -> bool:
    """True if e1 strictly occurred before e2."""
    t1 = getattr(e1, "timestamp", None)
    t2 = getattr(e2, "timestamp", None)
    if not t1 or not t2:
        return False
    return t1 < t2

def after(e1: Any, e2: Any) -> bool:
    """True if e1 strictly occurred after e2."""
    t1 = getattr(e1, "timestamp", None)
    t2 = getattr(e2, "timestamp", None)
    if not t1 or not t2:
        return False
    return t1 > t2

def simultaneous(e1: Any, e2: Any, tolerance_seconds: float = 2.0) -> bool:
    """True if e1 and e2 occurred within a tight tolerance (effectively simultaneous)."""
    t1 = getattr(e1, "timestamp", None)
    t2 = getattr(e2, "timestamp", None)
    if not t1 or not t2:
        return False
    return abs((t1 - t2).total_seconds()) <= tolerance_seconds

def time_delta_seconds(e1: Any, e2: Any) -> float:
    """Returns elapsed seconds from e1 to e2 (e2.timestamp - e1.timestamp)."""
    t1 = getattr(e1, "timestamp", None)
    t2 = getattr(e2, "timestamp", None)
    if not t1 or not t2:
        return 0.0
    return (t2 - t1).total_seconds()

def within_time_window(e1: Any, e2: Any, minutes: float) -> bool:
    """
    True if e1 occurred before e2 and within `minutes` time window (inclusive).
    e1.timestamp <= e2.timestamp <= e1.timestamp + minutes
    """
    t1 = getattr(e1, "timestamp", None)
    t2 = getattr(e2, "timestamp", None)
    if not t1 or not t2:
        return False
    delta = (t2 - t1).total_seconds()
    return 0 <= delta <= (minutes * 60)

def same_user(e1: Any, e2: Any) -> bool:
    """True if both events belong to the same non-empty user identifier."""
    u1 = getattr(e1, "user_id", "") or ""
    u2 = getattr(e2, "user_id", "") or ""
    if not u1 or not u2:
        return False
    return u1.strip().lower() == u2.strip().lower()

def same_session(e1: Any, e2: Any) -> bool:
    """True if both events share a non-empty session ID."""
    s1 = getattr(e1, "session_id", None)
    s2 = getattr(e2, "session_id", None)
    if not s1 or not s2:
        return False
    return str(s1).strip() == str(s2).strip()

def related_computers(e1: Any, e2: Any) -> bool:
    """
    True if events are linked by computer ID, hostname,
    or direct network IP hops between the two machines.
    """
    c1 = getattr(e1, "computer_id", "") or ""
    c2 = getattr(e2, "computer_id", "") or ""
    h1 = getattr(e1, "hostname", "") or ""
    h2 = getattr(e2, "hostname", "") or ""
    
    # Direct same host
    if c1 and c2 and c1.lower() == c2.lower():
        return True
    if h1 and h2 and h1.lower() == h2.lower():
        return True

    # Network hop: destination of e1 matches source of e2 or computer_id
    d_ip1 = getattr(e1, "destination_ip", "") or ""
    s_ip2 = getattr(e2, "source_ip", "") or ""
    s_ip1 = getattr(e1, "source_ip", "") or ""
    d_ip2 = getattr(e2, "destination_ip", "") or ""

    if d_ip1 and s_ip2 and d_ip1 == s_ip2 and d_ip1 not in ("127.0.0.1", "0.0.0.0", ""):
        return True
    if s_ip1 and s_ip2 and s_ip1 == s_ip2 and s_ip1 not in ("127.0.0.1", "0.0.0.0", ""):
        return True

    return False

def related_network_activity(e1: Any, e2: Any) -> bool:
    """
    True if there is an overlapping IP address (source or destination)
    or an interactive connection between the endpoints.
    """
    s1 = getattr(e1, "source_ip", "") or ""
    d1 = getattr(e1, "destination_ip", "") or ""
    s2 = getattr(e2, "source_ip", "") or ""
    d2 = getattr(e2, "destination_ip", "") or ""

    ips1 = {ip for ip in (s1, d1) if ip and ip not in ("127.0.0.1", "0.0.0.0")}
    ips2 = {ip for ip in (s2, d2) if ip and ip not in ("127.0.0.1", "0.0.0.0")}

    return len(ips1.intersection(ips2)) > 0

def is_causal_candidate(e1: Any, e2: Any, max_window_minutes: float = 60.0) -> Tuple[bool, float, str]:
    """
    Evaluates whether event e1 is a plausible causal candidate for event e2.
    Requires:
      1. Chronological order (before(e1, e2))
      2. Temporal proximity within max_window_minutes
      3. At least one entity correlation (same user, same session, related computers, or related network)
      4. Semantically plausible transition in attack lifecycle (e.g. Failed -> Success, Login -> Escalation, Access -> Exfiltration)
    """
    if not before(e1, e2):
        return False, 0.0, "Events are not chronologically ordered."

    delta_sec = time_delta_seconds(e1, e2)
    if delta_sec > (max_window_minutes * 60):
        return False, 0.0, f"Time delta ({delta_sec:.1f}s) exceeds maximum causal window ({max_window_minutes}m)."

    # Correlation checks
    has_user = same_user(e1, e2)
    has_session = same_session(e1, e2)
    has_comp = related_computers(e1, e2)
    has_net = related_network_activity(e1, e2)

    if not (has_user or has_session or has_comp or has_net):
        return False, 0.0, "No entity correlation found between events."

    # Action / Type transitions
    t1 = getattr(e1, "event_type", "")
    t2 = getattr(e2, "event_type", "")

    score = 0.5
    reasons = []

    if has_user:
        score += 0.2
        reasons.append(f"user '{e1.user_id}'")
    if has_session:
        score += 0.25
        reasons.append(f"session '{e1.session_id}'")
    if has_comp:
        score += 0.15
        reasons.append("correlated host/computer")
    if has_net:
        score += 0.1
        reasons.append("correlated network path")

    # Semantic transition bonuses
    if t1 == "FAILED_LOGIN" and t2 == "SUCCESSFUL_LOGIN":
        score += 0.2
        reasons.append("authentication breach transition")
    elif t1 in ("SUCCESSFUL_LOGIN", "REMOTE_LOGIN") and t2 == "PRIVILEGE_ESCALATION":
        score += 0.2
        reasons.append("post-compromise privilege escalation")
    elif t1 in ("SUCCESSFUL_LOGIN", "PRIVILEGE_ESCALATION") and t2 == "REMOTE_LOGIN":
        score += 0.25
        reasons.append("lateral movement propagation")
    elif t1 in ("FILE_ACCESS", "SENSITIVE_FILE_ACCESS") and t2 in ("LARGE_DATA_TRANSFER", "UNUSUAL_NETWORK_CONNECTION"):
        score += 0.25
        reasons.append("staging to data exfiltration sequence")
    elif t1 == "SUSPICIOUS_PROCESS" and t2 in ("SENSITIVE_FILE_ACCESS", "LARGE_DATA_TRANSFER", "UNUSUAL_NETWORK_CONNECTION"):
        score += 0.2
        reasons.append("payload execution driving exfiltration")

    confidence = min(round(score, 2), 1.0)
    explanation = f"Plausible causal link via {', '.join(reasons)} ({delta_sec:.0f}s elapsed)."
    return True, confidence, explanation
