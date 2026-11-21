# System Architecture Document

## Intelligent Cyberattack Detection Using Temporal Knowledge Representation

---

### 1. Architectural Overview

The system is designed as an end-to-end, multi-stage cybersecurity monitoring and investigation platform. Rather than relying purely on isolated threshold alerts or point-in-time statistical anomalies, the system treats cybersecurity logs as **temporal facts** and applies **temporal knowledge representation and reasoning** (incorporating Allen's Interval Algebra and point-based temporal predicates) to correlate suspicious activities across multiple hosts.

```mermaid
flowchart TD
    subgraph Data Sources
        S1[Host Event Logs]
        S2[Simulated Event Generator]
        S3[CSV / JSON Uploads]
    end

    subgraph Ingestion & Storage
        ING[Event Ingestion API\n/api/events]
        NORM[Log Normalizer & Validator\nUTC Timestamping, Schema Enforcement]
        DB[(Relational DB\nPostgreSQL / SQLite)]
    end

    subgraph Temporal & Reasoning Core
        TKG[Temporal Knowledge Engine\nTemporal Predicates, Interval Algebra]
        CORR[Cross-Computer Correlation Engine\nEntity Bindings, Network Hops]
        DET[Attack Pattern Detection Engine\nBrute Force, Lateral, Exfil, PrivEsc, Multi-Stage]
        SCORE[Explainable Risk Scoring Engine\nWeighted 0-100 Heuristic]
    end

    subgraph Investigation & Visualization
        INV[Investigation Engine\nDeterministic & AI Assistant]
        DASH[React Cyber Dashboard\nTimeline, React Flow Graph, Monitor]
    end

    S1 --> ING
    S2 --> ING
    S3 --> ING
    ING --> NORM
    NORM --> DB
    DB --> TKG
    TKG --> CORR
    CORR --> DET
    DET --> SCORE
    SCORE --> DB
    SCORE --> INV
    DB --> DASH
    INV --> DASH
```

---

### 2. Pipeline Stages

1. **Log Ingestion & Normalization**:
   - Ingests events from REST endpoints, bulk uploads, or simulation engines.
   - Normalizes timestamps to UTC datetime objects.
   - Validates event types (`FAILED_LOGIN`, `SUCCESSFUL_LOGIN`, `REMOTE_LOGIN`, `PRIVILEGE_ESCALATION`, `SUSPICIOUS_PROCESS`, `FILE_ACCESS`, `SENSITIVE_FILE_ACCESS`, `LARGE_DATA_TRANSFER`, `UNUSUAL_NETWORK_CONNECTION`, `MALWARE_INDICATOR`).
   - Dynamically registers unknown computers and security identities.
   - Rejects malformed and duplicate events.

2. **Temporal Knowledge Representation**:
   - Represents each event as a time-dependent fact: $E_i = \langle \text{id}, t_i, \text{type}, \text{host}, \text{user}, \text{session}, \text{action} \rangle$.
   - Computes pairwise temporal relations between events occurring within a sliding time window:
     - `BEFORE(e1, e2)`
     - `AFTER(e1, e2)`
     - `SIMULTANEOUS(e1, e2)` (within 2s tolerance)
     - `WITHIN_TIME_WINDOW(e1, e2, W)`
     - `OVERLAPS(i1, i2)`
     - `CAUSALLY_RELATED_CANDIDATE(e1, e2)`
   - Causal candidate evaluation requires chronological succession, temporal proximity, entity correlation (same user, session, host, or network path), and semantically plausible lifecycle transitions.

3. **Cross-Computer Correlation**:
   - Tracks lateral pivots and attacker movement across endpoints (e.g. Host A $\rightarrow$ Host B $\rightarrow$ Host C).
   - Validates entity continuity via matching credentials, session tokens, or direct socket links (`e1.destination_ip == e2.source_ip`).
   - Computes normalized correlation strength (0.0 to 1.0) based on user and session persistence across machines.

4. **Attack Detection & Reasoning**:
   - Executes 5 configurable detection rules:
     - **Brute-Force Account Compromise**: $\ge 3$ failed logins followed by successful login for same user within time window (default 10m).
     - **Lateral Movement**: Initial compromise/login on Host A followed by remote login on Host B within window (default 30m).
     - **Data Exfiltration**: Sensitive file access followed by large outbound network transfer within window (default 20m).
     - **Privilege Escalation**: Authentication followed by privilege change followed by restricted asset access within window (default 15m).
     - **Multi-Stage Coordinated Attack**: 5-stage sequential APT progression spanning brute force, breach, lateral movement, database dump, and exfiltration.
   - Enforces duplicate prevention to eliminate redundant alerts for identical event sets.

5. **Explainable Risk Scoring**:
   - Calculates a deterministic heuristic risk score (0–100) based on rule base score, event volume, maximum event severity, temporal consistency, multi-host propagation, correlation strength, sensitive asset bonus, and pattern completeness.
   - Classifies threats into: Low (0–39), Medium (40–69), High (70–89), and Critical (90–100).

6. **Incident Investigation & Reporting**:
   - Synthesizes structured forensic reports detailing executive summary, technical breakdown, temporal constraint proofs, and defensive containment playbooks.
   - Features deterministic rule-based explanations and optional LLM assistant integration.

7. **SOC Dashboard & Visualization**:
   - React 19 + Tailwind CSS + React Flow + Recharts.
   - Interactive live event monitor, chronological attack timeline, topological React Flow network graph, simulation laboratory, and detection rule configuration.

---

### 3. Database Entity Relationship Diagram

```mermaid
erDiagram
    COMPUTERS ||--o{ SECURITY_EVENTS : "hosts"
    USERS ||--o{ SECURITY_EVENTS : "generates"
    SECURITY_EVENTS ||--o{ TEMPORAL_RELATIONSHIPS : "source / target"
    DETECTION_RULES ||--o{ ATTACK_ALERTS : "defines"
    ATTACK_ALERTS ||--o{ ALERT_EVIDENCE : "contains"
    SECURITY_EVENTS ||--o{ ALERT_EVIDENCE : "evidences"
    ATTACK_ALERTS ||--o{ INVESTIGATION_REPORTS : "analyzes"

    COMPUTERS {
        string id PK
        string hostname
        string ip_address
        string os_type
        string role
        string status
        datetime created_at
    }

    SECURITY_EVENTS {
        int id PK
        string event_id UK
        datetime timestamp
        string computer_id FK
        string hostname
        string user_id
        string source_ip
        string destination_ip
        string event_type
        string action
        string status
        string severity
        string session_id
        text metadata_json
        boolean is_simulated
    }

    TEMPORAL_RELATIONSHIPS {
        int id PK
        string source_event_id FK
        string target_event_id FK
        string relation_type
        float delta_seconds
        float confidence
        text evidence_text
    }

    ATTACK_ALERTS {
        string id PK
        string rule_id FK
        string rule_name
        string title
        string severity
        float risk_score
        text affected_computers
        text related_users
        datetime start_time
        datetime end_time
        string status
        text explanation
        text temporal_constraints
    }

    ALERT_EVIDENCE {
        int id PK
        string alert_id FK
        string event_id FK
        int sequence_order
        string stage_name
        text role_in_attack
    }

    INVESTIGATION_REPORTS {
        string id PK
        string alert_id FK
        text summary
        text technical_analysis
        text temporal_analysis
        text recommended_actions
        string generated_by
    }
```

---

### 4. REST API Endpoint Specifications

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | `GET` | Service & database health verification |
| `/api/events` | `GET` | Filterable, paginated security log stream |
| `/api/events` | `POST` | Ingest single security event |
| `/api/events/bulk` | `POST` | Ingest multiple security events |
| `/api/events/upload` | `POST` | Upload CSV / JSON dataset file |
| `/api/computers` | `GET` | List monitored enterprise endpoints |
| `/api/computers/{id}` | `GET` | Retrieve single endpoint metadata |
| `/api/detection/run` | `POST` | Execute temporal reasoning & detection |
| `/api/detection/rules` | `GET` | List configurable detection rules |
| `/api/detection/rules/{id}` | `PATCH` | Update rule thresholds and time windows |
| `/api/detection/results` | `GET` | Detection statistics summary |
| `/api/alerts` | `GET` | List detected cyberattack alerts |
| `/api/alerts/{id}` | `GET` | Retrieve alert with sequential evidence |
| `/api/alerts/{id}` | `PATCH` | Update alert triage status |
| `/api/timeline` | `GET` | Retrieve chronological timeline and causal links |
| `/api/network/graph` | `GET` | Topological React Flow graph data |
| `/api/simulation/start` | `POST` | Run normal traffic or inject attack scenario |
| `/api/simulation/stop` | `POST` | Stop active simulation |
| `/api/simulation/reset` | `POST` | Reset demo database to clean baseline |
| `/api/investigation/explain`| `POST` | Generate evidence-grounded report |
| `/api/investigation/{id}` | `GET` | Retrieve forensic investigation report |
| `/api/dashboard/summary` | `GET` | SOC high-level summary metrics |
| `/api/dashboard/trends` | `GET` | Time-series event and alert trend buckets |
