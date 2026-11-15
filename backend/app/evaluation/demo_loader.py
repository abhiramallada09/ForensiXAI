import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from sqlalchemy.orm import Session

from backend.app.models.case import Case
from backend.app.models.evidence import Evidence
from backend.app.models.memory import MemoryAnalysisRecord
from backend.app.models.event import TimelineEvent
from backend.app.models.finding import ForensicFinding
from backend.app.models.deleted_file import DeletedFileRecord
from backend.app.models.timestamp_reconstruction import TimestampReconstructionRecord
from backend.app.models.anti_forensic import AntiForensicIndicatorRecord
from backend.app.models.cloud import CloudEvidenceRecord, CloudCorrelationRecord
from backend.app.reports.pdf_generator import generate_case_pdf_report


def load_complete_demo_scenario(db: Session) -> Case:
    """
    Creates or resets an exhaustive, end-to-end forensic demonstration case.
    Populates all 8 modules (Evidence, Volatility Memory, Deep Learning, Deleted Files,
    Timestamp Reconstruction, Anti-Forensics, Cloudtrail/Azure, and Reports).
    """
    demo_case_number = "DEMO-NIMBUS-2026"
    existing_case = db.query(Case).filter(Case.case_number == demo_case_number).first()
    if existing_case:
        db.delete(existing_case)
        db.commit()

    base_time = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Create Case
    demo_case = Case(
        case_number=demo_case_number,
        name="[CONTROLLED DEMONSTRATION SCENARIO - SYNTHETIC DATA] Operation Nimbus Breach: Memory Forensics & Cloud Evasion Demonstration",
        investigator="A. Abhiram (Lead Forensic Examiner)",
        description=(
            "[CONTROLLED DEMONSTRATION SCENARIO - SYNTHETIC BENCHMARK DATA] Standardized academic evaluation benchmark scenario: "
            "Simulated APT intrusion involving in-memory code injection, anti-forensic timestomping, sdelete artifact wiping, "
            "and AWS CloudTrail StopLogging evasion. All artifacts are synthetically generated for academic research validation "
            "and do not represent a real enterprise breach."
        ),
        status="Analysis Complete",
    )
    db.add(demo_case)
    db.commit()

    # 2. Stage Physical Evidence
    ev_mem_id = str(uuid.uuid4())
    ev_disk_id = str(uuid.uuid4())
    ev_cloud_id = str(uuid.uuid4())

    ev_mem = Evidence(
        id=ev_mem_id,
        case_id=demo_case.id,
        evidence_number="EVD-001",
        filename="workstation_win10_x64.raw",
        stored_path="/evidence/workstation_win10_x64.raw",
        file_type="Raw Memory Image",
        file_size_bytes=4294967296,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        classification="OBSERVED",
        status="Verified",
        notes="[CONTROLLED DEMONSTRATION SCENARIO - SYNTHETIC DATA] Generated memory image containing simulated injection artifacts.",
        metadata_json={"os_architecture": "Windows 10 x64 (Build 19041)", "page_size": 4096},
    )

    ev_disk = Evidence(
        id=ev_disk_id,
        case_id=demo_case.id,
        evidence_number="EVD-002",
        filename="system_volume_c.vhd",
        stored_path="/evidence/system_volume_c.vhd",
        file_type="Virtual Hard Disk",
        file_size_bytes=10737418240,
        sha256="2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        classification="OBSERVED",
        status="Verified",
        notes="[CONTROLLED DEMONSTRATION SCENARIO - SYNTHETIC DATA] Synthesized VHD image modeling NTFS MFT remnants.",
        metadata_json={"filesystem": "NTFS", "cluster_size": 4096},
    )

    ev_cloud = Evidence(
        id=ev_cloud_id,
        case_id=demo_case.id,
        evidence_number="EVD-003",
        filename="cloudtrail_audit_events.json",
        stored_path="/evidence/cloudtrail_audit_events.json",
        file_type="Cloud Audit Log",
        file_size_bytes=819200,
        sha256="fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
        classification="OBSERVED",
        status="Verified",
        notes="[CONTROLLED DEMONSTRATION SCENARIO - SYNTHETIC DATA] Synthesized CloudTrail log records with StopLogging events.",
    )
    db.add_all([ev_mem, ev_disk, ev_cloud])
    db.commit()

    # 3. Volatility 3 Memory Forensics Record
    mem = MemoryAnalysisRecord(
        case_id=demo_case.id,
        evidence_id=ev_mem_id,
        plugins_run=["windows.pslist", "windows.netscan", "windows.malfind", "windows.handles", "windows.cmdline"],
        processes=[
            {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 154, "CreateTime": "2026-11-14 08:00:00"},
            {"PID": 620, "PPID": 580, "ImageFileName": "lsass.exe", "Threads": 22, "CreateTime": "2026-11-14 08:00:05"},
            {"PID": 2844, "PPID": 620, "ImageFileName": "svchost.exe", "Threads": 8, "CreateTime": "2026-11-14 10:02:10"},
            {"PID": 3912, "PPID": 2844, "ImageFileName": "powershell.exe", "Threads": 14, "CreateTime": "2026-11-14 10:03:15"},
            {"PID": 4120, "PPID": 3912, "ImageFileName": "aws.exe", "Threads": 4, "CreateTime": "2026-11-14 10:04:12"},
        ],
        network_connections=[
            {"PID": 3912, "ForeignAddress": "198.51.100.55:443", "State": "ESTABLISHED", "Proto": "TCP"},
            {"PID": 4120, "ForeignAddress": "52.216.142.12:443", "State": "ESTABLISHED", "Proto": "TCP"},
        ],
        injected_regions=[
            {"PID": 620, "Process": "lsass.exe", "Protection": "PAGE_EXECUTE_READWRITE", "Injected": True, "Disassembly": "push rbp; mov rbp, rsp; sub rsp, 0x40"},
        ],
        cmdlines=[
            {"PID": 3912, "Process": "powershell.exe", "CommandLine": "powershell.exe -NoP -NonI -W Hidden -c \"sdelete -p 3 -z C:\\Windows\\Temp\\stager.exe\""},
            {"PID": 4120, "Process": "aws.exe", "CommandLine": "aws cloudtrail stop-logging --name production-trail"},
        ],
    )
    db.add(mem)

    # 4. Deleted File Remnants
    df1 = DeletedFileRecord(
        case_id=demo_case.id,
        evidence_id=ev_disk_id,
        filename="stager_payload.exe",
        original_path="C:\\Windows\\Temp\\stager_payload.exe",
        carved_header_signature="4D 5A 90 00",
        file_type="PE Executable",
        estimated_size_bytes=65536,
        deletion_timestamp=base_time + timedelta(minutes=4),
        confidence=0.94,
        classification="RECONSTRUCTED",
        status="Probable deleted artifact",
        corroborating_sources=["Closed Memory Handle PID 3912", "MFT $STANDARD_INFO Slack", "Sysmon Event ID 23"],
        reconstruction_reason="Correlated memory residue and secure deletion command in PowerShell history",
        carved_hex_preview="4D5A90000300000004000000FFFF0000B8000000000000004000000000000000",
    )
    df2 = DeletedFileRecord(
        case_id=demo_case.id,
        evidence_id=ev_disk_id,
        filename="exfil_archive.zip",
        original_path="C:\\Users\\Victim\\AppData\\Local\\Temp\\exfil_archive.zip",
        carved_header_signature="50 4B 03 04",
        file_type="ZIP Archive",
        estimated_size_bytes=1048576,
        deletion_timestamp=base_time + timedelta(minutes=5),
        confidence=0.89,
        classification="RECONSTRUCTED",
        status="Probable deleted artifact",
        corroborating_sources=["USN Journal ID 4660", "Unallocated Disk Sector #10249"],
        reconstruction_reason="Carved ZIP signature at unallocated boundary matching USN deletion entry",
        carved_hex_preview="504B030414000000080088A1A24B00000000000000000000000010000000",
    )
    db.add_all([df1, df2])

    # 5. Timestamp Reconstruction Windows
    tw1 = TimestampReconstructionRecord(
        case_id=demo_case.id,
        event_title="Beacon Ingress & Process Execution",
        observed_timestamp=base_time + timedelta(minutes=3, seconds=15),
        probable_window_start=base_time + timedelta(minutes=3, seconds=10),
        probable_window_end=base_time + timedelta(minutes=3, seconds=55),
        probable_event_time=base_time + timedelta(minutes=3, seconds=15),
        window_duration_seconds=45.0,
        consistency_status="CONSISTENT",
        classification="RECONSTRUCTED",
        confidence=0.96,
        sources_compared=[
            {"source": "Volatility pslist (CreateTime)"},
            {"source": "NTFS $MFT $FILE_NAME"},
            {"source": "Windows Security Event ID 4688"},
        ],
        related_event_ids=[],
        reconstruction_reason="Observed execution aligns with MACB modification within 45s window",
    )
    tw2 = TimestampReconstructionRecord(
        case_id=demo_case.id,
        event_title="Timestomped Driver Modification",
        observed_timestamp=base_time + timedelta(minutes=1),
        probable_window_start=base_time - timedelta(days=600),
        probable_window_end=base_time + timedelta(minutes=1),
        probable_event_time=base_time + timedelta(minutes=1),
        window_duration_seconds=51840000.0,
        consistency_status="INCONSISTENT",
        classification="SUSPICIOUS",
        confidence=0.92,
        sources_compared=[
            {"source": "NTFS $STANDARD_INFORMATION"},
            {"source": "NTFS $FILE_NAME"},
            {"source": "USN Journal Record #4912"},
        ],
        related_event_ids=[],
        reconstruction_reason="Observed modification timestamp precedes creation by 600 days with zeroed subseconds",
    )
    db.add_all([tw1, tw2])

    # 6. Anti-Forensic Tampering Indicators
    af1 = AntiForensicIndicatorRecord(
        case_id=demo_case.id,
        indicator_type="Audit Log Cleared",
        title="Anti-Forensic Log Cleansing Detected",
        severity="Critical",
        confidence=0.98,
        classification="SUSPICIOUS",
        supporting_evidence_ids=[ev_disk_id],
        supporting_artifacts=["Windows Security Event ID 1102", "wevtutil cl Security"],
        reason="Possible manipulation detected: Windows Security Audit Log was intentionally cleared.",
        recommendation="Inspect unallocated disk clusters, Volume Shadow Copies, and memory unmapped buffers for carved EVTX log fragments.",
    )
    af2 = AntiForensicIndicatorRecord(
        case_id=demo_case.id,
        indicator_type="Secure Deletion & Anti-Forensics Tool",
        title="Execution of Anti-Forensic Tool: sdelete",
        severity="High",
        confidence=0.95,
        classification="SUSPICIOUS",
        supporting_evidence_ids=[ev_mem_id],
        supporting_artifacts=["PowerShell Command Line History PID 3912"],
        reason="Possible manipulation detected: volatile process memory captured execution of anti-forensic tooling ('sdelete').",
        recommendation="Correlate execution time with filesystem MFT journal and examine VSS metadata.",
    )
    af3 = AntiForensicIndicatorRecord(
        case_id=demo_case.id,
        indicator_type="Volatile Memory Injection",
        title="Kernel Memory Injection: lsass.exe (PID 620)",
        severity="Critical",
        confidence=0.96,
        classification="SUSPICIOUS",
        supporting_evidence_ids=[ev_mem_id],
        supporting_artifacts=["Volatility malfind VAD Injection (PID 620, PAGE_EXECUTE_READWRITE)"],
        reason="Possible manipulation detected in memory dump: process 'lsass.exe' (PID 620) contains unmapped memory region with RWX protection.",
        recommendation="Extract injected VAD region bytes and inspect process PEB for unlinked loaded modules.",
    )
    db.add_all([af1, af2, af3])

    # 7. Cloud Audit Records & Cross-Correlations
    cr1 = CloudEvidenceRecord(
        case_id=demo_case.id,
        provider="AWS",
        event_time=base_time + timedelta(minutes=4, seconds=20),
        event_name="StopLogging",
        service_name="cloudtrail.amazonaws.com",
        identity_arn="arn:aws:iam::123456789012:user/admin_infiltrator",
        source_ip="198.51.100.55",
        aws_region="us-east-1",
        classification="SUSPICIOUS",
        severity="Critical",
        is_anti_forensic=True,
        raw_payload={"eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com"},
        notes="Possible anti-forensic manipulation: CloudTrail logging was halted.",
    )
    cr2 = CloudEvidenceRecord(
        case_id=demo_case.id,
        provider="AWS",
        event_time=base_time + timedelta(minutes=5),
        event_name="DeleteBucket",
        service_name="s3.amazonaws.com",
        identity_arn="arn:aws:iam::123456789012:user/admin_infiltrator",
        source_ip="198.51.100.55",
        aws_region="us-east-1",
        classification="SUSPICIOUS",
        severity="High",
        is_anti_forensic=True,
        raw_payload={"eventName": "DeleteBucket", "bucketName": "corporate-backups-2026"},
        notes="Possible anti-forensic evidence destruction: S3 backup bucket deleted.",
    )
    cr3 = CloudEvidenceRecord(
        case_id=demo_case.id,
        provider="Azure",
        event_time=base_time + timedelta(minutes=6),
        event_name="Microsoft.Insights/diagnosticSettings/delete",
        service_name="Microsoft.Insights",
        identity_arn="infiltrator@enterprise.onmicrosoft.com",
        source_ip="203.0.113.99",
        aws_region="eastus",
        classification="SUSPICIOUS",
        severity="Critical",
        is_anti_forensic=True,
        raw_payload={"operationName": "Microsoft.Insights/diagnosticSettings/delete"},
        notes="Possible anti-forensic manipulation: Azure diagnostic settings deleted.",
    )
    db.add_all([cr1, cr2, cr3])
    db.commit()

    # Cloud Cross-Correlations
    cc1 = CloudCorrelationRecord(
        case_id=demo_case.id,
        cloud_event_id=cr1.id,
        local_artifact_type="Process",
        local_artifact_desc="Local execution of 'aws' (PID 4120)",
        local_timestamp=base_time + timedelta(minutes=4, seconds=12),
        cloud_timestamp=base_time + timedelta(minutes=4, seconds=20),
        time_delta_seconds=8.0,
        correlation_type="Process-API Attribution",
        confidence=0.96,
        classification="CORRELATED",
        rationale="Local memory execution of aws.exe occurred 8.0s prior to remote AWS CloudTrail StopLogging action.",
    )
    cc2 = CloudCorrelationRecord(
        case_id=demo_case.id,
        cloud_event_id=cr1.id,
        local_artifact_type="Network Socket",
        local_artifact_desc="Socket connection to 198.51.100.55:443 (PID 3912)",
        local_timestamp=base_time + timedelta(minutes=4, seconds=20),
        cloud_timestamp=base_time + timedelta(minutes=4, seconds=20),
        time_delta_seconds=0.0,
        correlation_type="IP Match",
        confidence=0.98,
        classification="CORRELATED",
        rationale="Local memory socket matches the caller source IP (198.51.100.55) that halted CloudTrail audit logging.",
    )
    db.add_all([cc1, cc2])

    # 8. Master Timeline Events
    timeline_events = [
        TimelineEvent(
            case_id=demo_case.id,
            timestamp=base_time + timedelta(minutes=2, seconds=10),
            timestamp_source="Volatility 3 windows.pslist",
            event_type="Process Started",
            artifact_category="Memory Image",
            description="Process svchost.exe (PID 2844) spawned by lsass.exe",
            confidence=0.95,
            classification="OBSERVED",
        ),
        TimelineEvent(
            case_id=demo_case.id,
            timestamp=base_time + timedelta(minutes=3, seconds=15),
            timestamp_source="Volatility 3 windows.malfind",
            event_type="Code Injection",
            artifact_category="Memory Image",
            description="Process lsass.exe (PID 620) injected with unbacked PAGE_EXECUTE_READWRITE code",
            confidence=0.96,
            classification="SUSPICIOUS",
        ),
        TimelineEvent(
            case_id=demo_case.id,
            timestamp=base_time + timedelta(minutes=4),
            timestamp_source="PowerShell History",
            event_type="File Deleted",
            artifact_category="Command",
            description="cmd.exe /c sdelete -p 3 -z C:\\Windows\\Temp\\stager_payload.exe",
            confidence=0.94,
            classification="SUSPICIOUS",
        ),
        TimelineEvent(
            case_id=demo_case.id,
            timestamp=base_time + timedelta(minutes=4, seconds=20),
            timestamp_source="AWS CloudTrail Audit Log",
            event_type="Cloud API: StopLogging",
            artifact_category="Cloud Audit",
            description="[AWS] StopLogging invoked by arn:aws:iam::123456789012:user/admin_infiltrator (IP: 198.51.100.55)",
            confidence=0.98,
            classification="SUSPICIOUS",
        ),
    ]
    db.add_all(timeline_events)

    # 9. Synthesized Case Forensic Finding
    f1 = ForensicFinding(
        case_id=demo_case.id,
        title="Multi-Stage Intrusion with In-Memory Execution and Cloud Anti-Forensics",
        finding_type="APT Intrusion & Anti-Forensics",
        severity="Critical",
        confidence=0.97,
        classification="CORRELATED",
        reason="Correlated local in-memory code injection, sdelete secure deletion, and remote AWS CloudTrail StopLogging evasion.",
        explanation=(
            "Cross-correlation of Volatility 3 kernel memory with AWS CloudTrail audit logs confirmed an unauthorized "
            "actor executed in-memory shellcode in lsass.exe (PID 620), wiped local stager artifacts using sdelete, "
            "and disabled CloudTrail logging via CLI within an 8-second attribution window."
        ),
        supporting_artifacts=[
            "Volatility malfind RWX VAD",
            "MFT Carved Signature 4D 5A 90 00",
            "AWS CloudTrail StopLogging Event",
            "Source IP: 198.51.100.55",
        ],
        recommendation="Revoke compromised IAM credentials immediately, isolate workstation endpoint, and audit VSS shadow copies.",
    )
    db.add(f1)
    db.commit()

    # Pre-generate and seal report on disk
    try:
        pdf_bytes = generate_case_pdf_report(demo_case.id, db)
        reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "reports"))
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, f"ForensiX_Report_{demo_case_number}.pdf")
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
    except Exception:
        pass

    db.refresh(demo_case)
    return demo_case

