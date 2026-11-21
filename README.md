# Intelligent Cyberattack Detection Using Temporal Knowledge Representation

[![CI Pipeline](https://github.com/OviyaaSM/Cyberattack-Detection/actions/workflows/ci.yml/badge.svg)](https://github.com/OviyaaSM/Cyberattack-Detection/actions)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2019-61DAFB.svg)](https://react.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Styling-Tailwind%20v4-38B2AC.svg)](https://tailwindcss.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg)](https://python.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise-grade cybersecurity monitoring, event correlation, and incident investigation platform that detects coordinated multi-stage cyberattacks across distributed endpoints by reasoning over the **chronological and temporal relationships** between security events.

---

## 1. Project Overview

Advanced cyber threats (such as Advanced Persistent Threats or APTs) rarely execute as single, noisy intrusions on isolated systems. Instead, attackers operate methodically over time: executing credential brute-force attempts on one machine, achieving an initial foothold, performing lateral movement across internal network boundaries, escalating privileges, staging critical assets, and finally exfiltrating data.

Traditional Security Information and Event Management (SIEM) systems and anomaly detection platforms frequently suffer from severe alert fatigue and false positives because they evaluate individual security events in isolation or rely on point-in-time statistical thresholds.

This project delivers an end-to-end cybersecurity solution where **Temporal Knowledge Representation and Reasoning** serves as the primary academic and engineering foundation. By formalizing events as time-dependent facts and applying temporal interval algebra, cross-computer correlation, and causal candidate evaluation, the platform detects multi-stage attack campaigns with high precision and explainability.

---

## 2. Problem Statement

1. **Disconnected Log Context**: Traditional log collectors store security telemetry as isolated records, losing the temporal causality between activities occurring across multiple machines.
2. **Alert Fatigue**: Static threshold alerts trigger excessive false positives when routine administrative tasks resemble malicious behavior.
3. **Pivoting Blindspots**: Multi-computer lateral movement (e.g., Host A $\rightarrow$ Host B $\rightarrow$ Host C) remains invisible to host-centric security tools that lack distributed entity correlation.
4. **Black-box AI Risk**: Uninterpretable neural anomaly detectors fail to provide deterministic, verifiable proof of why an incident was flagged, making forensic triage difficult.

---

## 3. Proposed Solution

The **Temporal Cyberattack Detection System** solves these challenges through:
- **Temporal Event Modeling**: Representing security events as point or interval temporal facts with entity bindings (host, user, session, network socket).
- **Temporal Reasoning Engine**: Evaluating formal temporal predicates (`before`, `after`, `simultaneous`, `within_time_window`, `overlaps`, and `causally_related_candidate`).
- **Cross-Computer Correlation**: Connecting activities across distinct machines via user persistence, session tracking, and network socket continuity.
- **Rule-Based Attack Progression**: Detecting complex attack chains (Brute-Force, Lateral Movement, Data Exfiltration, Privilege Escalation, and Full Multi-Stage Campaigns).
- **Explainable Risk Scoring**: A transparent, weighted 0–100 heuristic risk index detailing base rule weights, event volume, temporal consistency, and asset criticality.
- **SOC Investigation Dashboard**: Interactive React frontend featuring a live event monitor, chronological attack timeline, React Flow topological graph, simulation lab, and evidence-grounded investigation reports.

---

## 4. System Architecture

```
Security Log Sources (Syslog / Simulation / CSV Uploads)
                          ↓
               Event Ingestion REST API
                          ↓
            Log Parsing & UTC Normalization
                          ↓
             Relational Database Storage
                          ↓
       Temporal Knowledge Representation Engine
                          ↓
        Cross-Computer Correlation Engine
                          ↓
          Attack Pattern Detection Rules
                          ↓
        Explainable Risk Scoring Engine
                          ↓
      Investigation & Reporting Assistant
                          ↓
        React Cybersecurity SOC Dashboard
```

Detailed architecture diagrams, data flows, and database ER schemas are available in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 5. Temporal Knowledge Representation Methodology

Events are modeled as temporal facts $E_i = \langle \text{id}_i, \tau_i, c_i, u_i, s_i, \text{type}_i, a_i, \text{src}_i, \text{dst}_i \rangle$.

### Core Temporal Predicates:
- `before(e1, e2)`: Strict chronological precedence ($t_1 < t_2$).
- `after(e1, e2)`: Strict chronological succession ($t_1 > t_2$).
- `simultaneous(e1, e2, tolerance)`: Events occurring within $\le 2.0$ seconds.
- `within_time_window(e1, e2, minutes)`: $0 \le (t_2 - t_1) \le (\text{minutes} \times 60)$.
- `overlaps(i1, i2)`: Allen's interval overlap ($t_1^{\text{start}} < t_2^{\text{end}} \land t_2^{\text{start}} < t_1^{\text{end}}$).
- `is_causal_candidate(e1, e2)`: Validates chronological precedence, temporal window, entity correlation (`same_user`, `same_session`, `related_computers`, or `related_network`), and semantic attack lifecycle progression.

For the formal mathematical derivation and Allen's interval algebra proofs, see [docs/TEMPORAL_REASONING.md](docs/TEMPORAL_REASONING.md).

---

## 6. Detection Scenarios

The system implements 5 core detection rules:

| Rule ID | Scenario Name | Temporal & Correlation Constraints | Severity |
|---|---|---|---|
| `RULE-BRUTE-FORCE` | Brute-force Account Compromise | $\ge 3$ `FAILED_LOGIN` followed by `SUCCESSFUL_LOGIN` for identical user within 10 minutes. | HIGH |
| `RULE-LATERAL-MOV` | Lateral Movement Across Systems | Authentication on Host A followed by `REMOTE_LOGIN` on Host B with matching user or network socket within 30 minutes. | HIGH |
| `RULE-DATA-EXFIL` | Sensitive Staging & Exfiltration | `SENSITIVE_FILE_ACCESS` followed by `LARGE_DATA_TRANSFER` to external endpoint within 20 minutes. | CRITICAL |
| `RULE-PRIV-ESC` | Privilege Escalation Chain | `SUCCESSFUL_LOGIN` $\rightarrow$ `PRIVILEGE_ESCALATION` $\rightarrow$ restricted resource access on same host within 15 minutes. | HIGH |
| `RULE-MULTI-STAGE` | Coordinated Multi-Stage Attack | 5-phase sequential APT chain: Brute Force $\rightarrow$ Breach $\rightarrow$ Lateral Pivot $\rightarrow$ Database Dump $\rightarrow$ Outbound Exfil. | CRITICAL |

---

## 7. Technology Stack

### Frontend
- **Framework**: React 19 + Vite 8
- **Styling**: Tailwind CSS v4 (SOC Dark Theme)
- **Routing**: React Router DOM v7
- **Graph Visualization**: React Flow (`@xyflow/react`)
- **Charts**: Recharts v3
- **Icons**: Lucide React
- **HTTP Client**: Axios

### Backend
- **Framework**: Python 3.11 + FastAPI
- **ORM & Database**: SQLAlchemy 2.0 + SQLite (zero-config local) / PostgreSQL (production)
- **Data Validation**: Pydantic v2
- **Testing**: Pytest + Pytest-Asyncio + Vitest (Frontend)
- **Web Server**: Uvicorn

---

## 8. Database Schema

The database design encompasses 9 relational models:
- `computers`: Monitored hosts (ID, hostname, IP, role, OS, status).
- `users`: Security identities (ID, username, department, privilege flag).
- `security_events`: Normalized log records with indexed timestamps, computer IDs, user IDs, and event types.
- `temporal_relationships`: Materialized temporal edges (source, target, relation type, delta seconds, confidence, evidence).
- `detection_rules`: Configurable rules (thresholds, time windows, severity, base risk score).
- `attack_alerts`: Detected multi-stage incidents with risk score and affected systems.
- `alert_evidence`: Ordered links connecting alerts to specific supporting events and attack stages.
- `simulation_runs`: Track synthetic scenario executions.
- `investigation_reports`: Structured forensic analysis and defensive containment playbooks.

---

## 9. API Documentation

Interactive OpenAPI / Swagger documentation is automatically available at:
`http://localhost:8000/docs`

Key endpoints include:
- `GET /api/health` — Health and database connectivity status.
- `GET /api/events` — Paginated and filterable event stream.
- `POST /api/events` — Ingest single security event.
- `POST /api/events/upload` — Upload CSV/JSON log datasets.
- `GET /api/computers` — Monitored endpoint inventory.
- `POST /api/detection/run` — Trigger temporal reasoning & detection.
- `GET /api/detection/rules` — View and edit configurable rules.
- `GET /api/alerts` — Correlated attack alert list.
- `GET /api/timeline` — Chronological event sequence and causal links.
- `GET /api/network/graph` — React Flow topological nodes and edges.
- `POST /api/simulation/start` — Inject synthetic normal or attack scenarios.
- `POST /api/simulation/reset` — Reset database to clean baseline.
- `POST /api/investigation/explain` — Generate forensic investigation report.
- `GET /api/dashboard/summary` — High-level SOC metrics and risk distribution.

---

## 10. Local Installation

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Git

### Clone Repository
```bash
git clone https://github.com/OviyaaSM/Cyberattack-Detection.git
cd Cyberattack-Detection
```

### Backend Setup
```bash
cd backend
python -m pip install -r requirements.txt
python -m app.database.init_db
```

### Frontend Setup
```bash
cd ../frontend
npm install
```

---

## 11. Environment Variables

Create `.env` in the root or copy from `.env.example`:

```bash
PORT=8000
DATABASE_URL=sqlite:///./cyberattack_detection.db
CORS_ORIGINS=http://localhost:5173,http://localhost:3000,*
AI_PROVIDER=deterministic
AI_API_KEY=
VITE_API_URL=http://localhost:8000/api
```

---

## 12. Running the Backend

From the repository root:
```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
The API is available at `http://localhost:8000` (docs at `http://localhost:8000/docs`).

---

## 13. Running the Frontend

From the repository root:
```bash
cd frontend
npm run dev
```
The SOC dashboard opens at `http://localhost:5173`.

---

## 14. Simulation Instructions

The platform includes a built-in **Simulation Laboratory** (`/simulation`):
1. Navigate to **Simulation Lab** in the navigation menu.
2. Click **Inject Normal Traffic** to generate benign background enterprise operations.
3. Select any attack scenario (e.g., *Coordinated Multi-Stage Cyberattack*).
4. The simulation engine automatically pushes synthetic events into the ingestion pipeline, evaluates temporal constraints, and derives alerts in real time.
5. Click **Reset to Clean State** at any time to restore a clean environment.

---

## 15. Sample Attack Scenarios

Sample synthetic CSV datasets are provided in the `datasets/` directory:
- `datasets/normal_traffic.csv`: 10 benign operational events across 5 hosts.
- `datasets/brute_force.csv`: 4 failed attempts followed by a successful login.
- `datasets/lateral_movement.csv`: Dev workstation login followed by remote WMI pivot to a Domain Controller.
- `datasets/data_exfiltration.csv`: Confidential archive access followed by outbound data transmission.
- `datasets/multi_stage_attack.csv`: Full 5-stage coordinated cyberattack sequence.

You can import any of these files directly via the **Reports & Config** page (`/settings`).

---

## 16. Testing Instructions

### Run Backend Unit & Integration Tests (17 Tests)
```bash
cd backend
python -m pytest tests -v
```

### Run Frontend Unit Tests (6 Tests)
```bash
cd frontend
npm run test
```

### Verify Production Frontend Build
```bash
cd frontend
npm run build
```

---

## 17. Evaluation Methodology & Benchmark Results

Run the automated evaluation benchmark script:
```bash
python scripts/evaluate.py
```

### Benchmark Results on Labeled Scenarios:
```
======================================================================
BENCHMARK EVALUATION: TEMPORAL CYBERATTACK DETECTION SYSTEM
======================================================================
Total Scenarios Evaluated: 10
True Positives  (TP)     : 7
True Negatives  (TN)     : 3
False Positives (FP)     : 0
False Negatives (FN)     : 0
----------------------------------------------------------------------
Accuracy                 : 100.00%
Precision                : 100.00%
Recall                   : 100.00%
F1-Score                 : 1.0000
Average Detection Latency: 33.71 ms
======================================================================
```
*Note: Evaluated on synthetic benchmark scenarios. Real-world enterprise environments exhibit variable noise.*

---

## 18. Deployment Instructions

### Frontend (Vercel)
1. Link repository to Vercel.
2. Set Root Directory to `frontend`.
3. Build Command: `npm run build`.
4. Output Directory: `dist`.
5. Set environment variable: `VITE_API_URL=https://<your-render-backend-url>/api`.

### Backend (Render)
1. Create a new **Web Service** on Render pointing to this repository.
2. Root Directory: `backend`.
3. Runtime: `Python 3`.
4. Build Command: `pip install -r requirements.txt`.
5. Start Command: `uvicorn main:app --host 0.0.0.0 --port $PORT`.
6. Add environment variable: `DATABASE_URL` (managed PostgreSQL connection string or persistent SQLite).

Configuration manifests are provided in `render.yaml` and `vercel.json`.

---

## 19. Dashboard Pages Overview

1. **Security Overview (`/`)**: Monitored hosts, processed events, active alerts, risk distribution bar chart, and time-series activity trends.
2. **Live Event Monitor (`/events`)**: Near-real-time streaming event table with search, computer filter, event type filter, severity filter, and payload inspection.
3. **Attack Detection (`/detection`)**: Detected attack pattern cards with risk gauges, affected computer badges, and status triage controls.
4. **Temporal Attack Timeline (`/timeline`)**: Chronological sequence visualizer showing event stages, time deltas, and causal candidate links.
5. **Network Attack Visualization (`/network`)**: Interactive React Flow canvas rendering computers as colored status nodes and animated attack paths as dashed red edges.
6. **Simulation Laboratory (`/simulation`)**: Controls for injecting normal traffic, testing attack scenarios, and resetting demo data.
7. **Incident Investigation Center (`/investigation`)**: Evidence chain review, AI / deterministic report generator, and defensive containment playbooks.
8. **Reports & Settings (`/settings`)**: JSON/CSV alert export, dataset CSV/JSON upload, and configurable detection rule thresholds.

---

## 20. Limitations & Future Enhancements

- **Real-Time Streaming**: Current live monitor utilizes optimized polling; future iterations can integrate WebSocket/SSE channels for sub-millisecond telemetry.
- **Graph Database Backend**: While relational indexed queries with SQL interval bounds deliver $\sim 33\text{ms}$ detection latency, highly interconnected enterprise graphs with $10^6$ nodes would benefit from Neo4j or Memgraph integrations.
- **Agent Integration**: Ingesting live Sysmon / eBPF kernel event streams directly from Linux and Windows hosts.

---

## 21. License

This project is licensed under the MIT License - see the LICENSE file for details.
