import uuid
import random
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.models import (
    Computer, UserIdentity, SecurityEvent, AttackAlert,
    AlertEvidence, TemporalRelationship, SimulationRun, InvestigationReport
)
from app.services.event_service import EventService
from app.schemas.schemas import SecurityEventCreate
from app.detection.engine import CyberattackDetectionEngine

SIMULATED_COMPUTERS = [
    {"id": "PC-FIN-01", "hostname": "finance-ws01.corp", "ip": "10.0.1.15", "os": "Windows 11", "role": "Workstation"},
    {"id": "PC-HR-02", "hostname": "hr-ws02.corp", "ip": "10.0.1.22", "os": "Windows 11", "role": "Workstation"},
    {"id": "PC-DEV-03", "hostname": "dev-ws03.corp", "ip": "10.0.2.45", "os": "Ubuntu 22.04", "role": "Workstation"},
    {"id": "PC-ENG-04", "hostname": "eng-ws04.corp", "ip": "10.0.2.88", "os": "macOS Sonoma", "role": "Workstation"},
    {"id": "SRV-DC-01", "hostname": "ad-dc01.corp", "ip": "10.0.0.5", "os": "Windows Server 2022", "role": "Domain Controller"},
    {"id": "SRV-DB-01", "hostname": "sql-prod01.corp", "ip": "10.0.0.20", "os": "RHEL 9", "role": "Database Server"},
    {"id": "SRV-FILE-01", "hostname": "fileshare01.corp", "ip": "10.0.0.35", "os": "Windows Server 2022", "role": "File Server"},
    {"id": "SRV-WEB-01", "hostname": "web-gateway01.corp", "ip": "10.0.0.80", "os": "Ubuntu 22.04", "role": "Web Gateway"}
]

SIMULATED_USERS = [
    {"id": "alice.fin", "username": "alice", "role": "financial_analyst", "dept": "Finance", "priv": False},
    {"id": "bob.hr", "username": "bob", "role": "recruiter", "dept": "HR", "priv": False},
    {"id": "charlie.dev", "username": "charlie", "role": "developer", "dept": "Engineering", "priv": False},
    {"id": "david.admin", "username": "david", "role": "sysadmin", "dept": "IT Security", "priv": True},
    {"id": "sec_auditor", "username": "auditor", "role": "compliance", "dept": "Audit", "priv": False}
]

class SimulationService:
    @classmethod
    def initialize_environment(cls, db: Session):
        """Seeds standard computers and users if empty."""
        for c in SIMULATED_COMPUTERS:
            if not db.query(Computer).filter(Computer.id == c["id"]).first():
                db.add(Computer(
                    id=c["id"],
                    hostname=c["hostname"],
                    ip_address=c["ip"],
                    os_type=c["os"],
                    role=c["role"],
                    status="HEALTHY"
                ))

        for u in SIMULATED_USERS:
            if not db.query(UserIdentity).filter(UserIdentity.id == u["id"]).first():
                db.add(UserIdentity(
                    id=u["id"],
                    username=u["username"],
                    role=u["role"],
                    department=u["dept"],
                    is_privileged=u["priv"]
                ))
        db.commit()

    @classmethod
    def reset_database(cls, db: Session):
        """Clears all events, alerts, evidence, relations, and simulation runs."""
        db.query(InvestigationReport).delete()
        db.query(AlertEvidence).delete()
        db.query(AttackAlert).delete()
        db.query(TemporalRelationship).delete()
        db.query(SecurityEvent).delete()
        db.query(SimulationRun).delete()
        
        # Reset computers to HEALTHY
        computers = db.query(Computer).all()
        for comp in computers:
            comp.status = "HEALTHY"
        db.commit()

        # Re-initialize clean environment
        cls.initialize_environment(db)

    @classmethod
    def generate_normal_traffic(
        cls,
        db: Session,
        count: int = 15,
        base_time: Optional[datetime.datetime] = None,
        seed: Optional[int] = None
    ) -> List[SecurityEvent]:
        """Generates benign operational activities across simulated computers."""
        cls.initialize_environment(db)
        if seed is not None:
            random.seed(seed)

        start_time = base_time or (datetime.datetime.utcnow() - datetime.timedelta(minutes=45))
        generated = []

        actions = [
            ("SUCCESSFUL_LOGIN", "Interactive console authentication successful", "SUCCESS", "LOW"),
            ("FILE_ACCESS", "Read project_documentation.pdf", "SUCCESS", "LOW"),
            ("FILE_ACCESS", "Updated sprint_tasks.xlsx", "SUCCESS", "LOW"),
            ("FILE_ACCESS", "Reviewed quarterly_report_v2.docx", "SUCCESS", "LOW"),
            ("SUCCESSFUL_LOGIN", "Standard desktop workstation unlock", "SUCCESS", "LOW"),
        ]

        for i in range(count):
            comp = random.choice(SIMULATED_COMPUTERS)
            user = random.choice(SIMULATED_USERS)
            evt_type, act, status, sev = random.choice(actions)
            t = start_time + datetime.timedelta(seconds=i * random.randint(30, 90))

            evt_create = SecurityEventCreate(
                event_id=f"EVT-NORM-{uuid.uuid4().hex[:8].upper()}",
                timestamp=t,
                computer_id=comp["id"],
                hostname=comp["hostname"],
                user_id=user["id"],
                source_ip=comp["ip"],
                destination_ip="10.0.0.1",
                event_type=evt_type,
                action=act,
                status=status,
                severity=sev,
                session_id=f"sess-{user['username']}-{random.randint(100, 999)}",
                metadata={"normal_routine": True, "process": "explorer.exe"},
                is_simulated=True
            )
            evt = EventService.ingest_single_event(db, evt_create)
            generated.append(evt)

        return generated

    @classmethod
    def inject_attack_scenario(
        cls,
        db: Session,
        scenario_type: str,
        base_time: Optional[datetime.datetime] = None,
        seed: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Injects a designated multi-step attack sequence into the pipeline,
        executes temporal reasoning and detection, and returns the result.
        """
        cls.initialize_environment(db)
        if seed is not None:
            random.seed(seed)

        start_time = base_time or (datetime.datetime.utcnow() - datetime.timedelta(minutes=30))
        sim_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
        run_record = SimulationRun(
            id=sim_id,
            scenario_name=scenario_type,
            status="RUNNING",
            started_at=datetime.datetime.utcnow(),
            seed=seed
        )
        db.add(run_record)
        db.commit()

        events_created: List[SecurityEvent] = []

        if scenario_type == "brute_force":
            # 4 failed logins followed by 1 successful login within 8 minutes
            target_comp = SIMULATED_COMPUTERS[0] # PC-FIN-01
            target_user = SIMULATED_USERS[0]["id"] # alice.fin
            attacker_ip = "198.51.100.44"

            for k in range(4):
                evt_t = start_time + datetime.timedelta(seconds=k * 45)
                e = EventService.ingest_single_event(db, SecurityEventCreate(
                    event_id=f"EVT-BF-{k+1}-{uuid.uuid4().hex[:6].upper()}",
                    timestamp=evt_t,
                    computer_id=target_comp["id"],
                    hostname=target_comp["hostname"],
                    user_id=target_user,
                    source_ip=attacker_ip,
                    destination_ip=target_comp["ip"],
                    event_type="FAILED_LOGIN",
                    action=f"Failed SSH authentication attempt #{k+1} - invalid password",
                    status="FAILURE",
                    severity="MEDIUM",
                    session_id=None,
                    metadata={"attempt": k+1, "auth_method": "password"},
                    is_simulated=True,
                    simulation_run_id=sim_id
                ))
                events_created.append(e)

            # Success at +4 minutes
            success_t = start_time + datetime.timedelta(minutes=4)
            e_succ = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-BF-SUCC-{uuid.uuid4().hex[:6].upper()}",
                timestamp=success_t,
                computer_id=target_comp["id"],
                hostname=target_comp["hostname"],
                user_id=target_user,
                source_ip=attacker_ip,
                destination_ip=target_comp["ip"],
                event_type="SUCCESSFUL_LOGIN",
                action="Successful authentication - compromised credentials",
                status="SUCCESS",
                severity="HIGH",
                session_id=f"sess-breached-{uuid.uuid4().hex[:6]}",
                metadata={"auth_method": "password", "compromised": True},
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e_succ)

        elif scenario_type == "lateral_movement":
            comp_a = SIMULATED_COMPUTERS[2] # PC-DEV-03
            comp_b = SIMULATED_COMPUTERS[4] # SRV-DC-01
            pivot_user = SIMULATED_USERS[2]["id"] # charlie.dev

            # Initial login on PC-DEV-03
            t1 = start_time
            e1 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-LAT-1-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t1,
                computer_id=comp_a["id"],
                hostname=comp_a["hostname"],
                user_id=pivot_user,
                source_ip="192.168.1.50",
                destination_ip=comp_a["ip"],
                event_type="SUCCESSFUL_LOGIN",
                action="Interactive user workstation session opened",
                status="SUCCESS",
                severity="LOW",
                session_id="sess-dev-pivot",
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e1)

            # Remote authentication pivot to SRV-DC-01 at +8 minutes
            t2 = start_time + datetime.timedelta(minutes=8)
            e2 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-LAT-2-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t2,
                computer_id=comp_b["id"],
                hostname=comp_b["hostname"],
                user_id=pivot_user,
                source_ip=comp_a["ip"], # Originating from dev machine
                destination_ip=comp_b["ip"],
                event_type="REMOTE_LOGIN",
                action="Remote PowerShell / WMI connection initiated",
                status="SUCCESS",
                severity="HIGH",
                session_id="sess-remote-pivot",
                metadata={"protocol": "WMI", "pivot_origin": comp_a["hostname"]},
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e2)

        elif scenario_type == "data_exfiltration":
            target_comp = SIMULATED_COMPUTERS[6] # SRV-FILE-01
            user = SIMULATED_USERS[0]["id"] # alice.fin
            exfil_ip = "203.0.113.89"

            # Access sensitive file
            t1 = start_time
            e1 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-EXF-1-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t1,
                computer_id=target_comp["id"],
                hostname=target_comp["hostname"],
                user_id=user,
                source_ip=target_comp["ip"],
                destination_ip="10.0.0.1",
                event_type="SENSITIVE_FILE_ACCESS",
                action="Extracted Q4_Confidential_Financial_Ledger.zip",
                status="SUCCESS",
                severity="HIGH",
                session_id="sess-exfil-staging",
                metadata={"file": "Q4_Confidential_Financial_Ledger.zip", "size_kb": 45000},
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e1)

            # High volume outbound network transfer at +4 minutes
            t2 = start_time + datetime.timedelta(minutes=4)
            e2 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-EXF-2-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t2,
                computer_id=target_comp["id"],
                hostname=target_comp["hostname"],
                user_id=user,
                source_ip=target_comp["ip"],
                destination_ip=exfil_ip,
                event_type="LARGE_DATA_TRANSFER",
                action="Outbound encrypted HTTPS transfer of 512 MB to external server",
                status="SUCCESS",
                severity="CRITICAL",
                session_id="sess-exfil-staging",
                metadata={"destination": exfil_ip, "bytes_transferred": 536870912},
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e2)

        elif scenario_type == "privilege_escalation":
            comp = SIMULATED_COMPUTERS[3] # PC-ENG-04
            user = SIMULATED_USERS[2]["id"] # charlie.dev

            t1 = start_time
            e1 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-PE-1-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t1,
                computer_id=comp["id"],
                hostname=comp["hostname"],
                user_id=user,
                source_ip=comp["ip"],
                destination_ip=comp["ip"],
                event_type="SUCCESSFUL_LOGIN",
                action="Standard user terminal session started",
                status="SUCCESS",
                severity="LOW",
                session_id="sess-privesc-chain",
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e1)

            t2 = start_time + datetime.timedelta(minutes=3)
            e2 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-PE-2-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t2,
                computer_id=comp["id"],
                hostname=comp["hostname"],
                user_id=user,
                source_ip=comp["ip"],
                destination_ip=comp["ip"],
                event_type="PRIVILEGE_ESCALATION",
                action="Exploitation of sudo CVE token to spawn root shell",
                status="SUCCESS",
                severity="HIGH",
                session_id="sess-privesc-chain",
                metadata={"vulnerability": "Sudoers Misconfiguration", "target_uid": 0},
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e2)

            t3 = start_time + datetime.timedelta(minutes=6)
            e3 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-PE-3-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t3,
                computer_id=comp["id"],
                hostname=comp["hostname"],
                user_id=user,
                source_ip=comp["ip"],
                destination_ip=comp["ip"],
                event_type="SENSITIVE_FILE_ACCESS",
                action="Read master credentials store /etc/shadow",
                status="SUCCESS",
                severity="CRITICAL",
                session_id="sess-privesc-chain",
                metadata={"file": "/etc/shadow", "privileged_access": True},
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e3)

        elif scenario_type == "multi_stage":
            comp_a = SIMULATED_COMPUTERS[0] # PC-FIN-01
            comp_b = SIMULATED_COMPUTERS[5] # SRV-DB-01
            user = SIMULATED_USERS[0]["id"] # alice.fin
            attacker_ip = "185.220.101.5"
            exfil_ip = "194.26.29.112"

            # Stage 1: Failed login
            t1 = start_time
            e1 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-MS-1-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t1,
                computer_id=comp_a["id"],
                hostname=comp_a["hostname"],
                user_id=user,
                source_ip=attacker_ip,
                destination_ip=comp_a["ip"],
                event_type="FAILED_LOGIN",
                action="Password spraying attempt rejected",
                status="FAILURE",
                severity="MEDIUM",
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e1)

            # Stage 2: Successful breach
            t2 = start_time + datetime.timedelta(minutes=4)
            e2 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-MS-2-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t2,
                computer_id=comp_a["id"],
                hostname=comp_a["hostname"],
                user_id=user,
                source_ip=attacker_ip,
                destination_ip=comp_a["ip"],
                event_type="SUCCESSFUL_LOGIN",
                action="Authentication successful with stolen credential",
                status="SUCCESS",
                severity="HIGH",
                session_id="sess-ms-chain",
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e2)

            # Stage 3: Lateral movement to DB server
            t3 = start_time + datetime.timedelta(minutes=11)
            e3 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-MS-3-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t3,
                computer_id=comp_b["id"],
                hostname=comp_b["hostname"],
                user_id=user,
                source_ip=comp_a["ip"],
                destination_ip=comp_b["ip"],
                event_type="REMOTE_LOGIN",
                action="Remote SSH connection established into production database",
                status="SUCCESS",
                severity="HIGH",
                session_id="sess-ms-db-pivot",
                metadata={"origin": comp_a["hostname"]},
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e3)

            # Stage 4: Sensitive customer database dump
            t4 = start_time + datetime.timedelta(minutes=16)
            e4 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-MS-4-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t4,
                computer_id=comp_b["id"],
                hostname=comp_b["hostname"],
                user_id=user,
                source_ip=comp_b["ip"],
                destination_ip=comp_b["ip"],
                event_type="SENSITIVE_FILE_ACCESS",
                action="Executed pg_dump on customer_credit_cards table",
                status="SUCCESS",
                severity="CRITICAL",
                session_id="sess-ms-db-pivot",
                metadata={"table": "customer_credit_cards", "records": 125000},
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e4)

            # Stage 5: Exfiltration to external server
            t5 = start_time + datetime.timedelta(minutes=22)
            e5 = EventService.ingest_single_event(db, SecurityEventCreate(
                event_id=f"EVT-MS-5-{uuid.uuid4().hex[:6].upper()}",
                timestamp=t5,
                computer_id=comp_b["id"],
                hostname=comp_b["hostname"],
                user_id=user,
                source_ip=comp_b["ip"],
                destination_ip=exfil_ip,
                event_type="LARGE_DATA_TRANSFER",
                action="Encrypted multi-part archive sent to overseas bulletproof server",
                status="SUCCESS",
                severity="CRITICAL",
                session_id="sess-ms-db-pivot",
                metadata={"destination": exfil_ip, "size_mb": 1420},
                is_simulated=True,
                simulation_run_id=sim_id
            ))
            events_created.append(e5)

        # Run detection pipeline
        detection_res = CyberattackDetectionEngine.run_detection_pipeline(db)

        # Update simulation record
        run_record.status = "COMPLETED"
        run_record.events_generated = len(events_created)
        run_record.completed_at = datetime.datetime.utcnow()
        db.commit()

        return {
            "simulation_id": sim_id,
            "scenario": scenario_type,
            "events_generated": len(events_created),
            "detection_results": detection_res
        }
