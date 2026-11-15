from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field, ConfigDict


VALID_CASE_STATUSES = [
    "New",
    "Evidence Collected",
    "Analyzing",
    "Analysis Complete",
    "Review Required",
    "Archived",
]

VALID_EVIDENCE_CATEGORIES = [
    "File",
    "Memory Image",
    "System Log",
    "Application Log",
    "Cloud Log",
    "Network Evidence",
    "Other",
]

VALID_EVENT_TYPES = [
    "File Created",
    "File Modified",
    "File Accessed",
    "File Deleted",
    "Process Started",
    "Network Activity",
    "Login",
    "Cloud Activity",
    "Other",
]

VALID_CLASSIFICATIONS = [
    "OBSERVED",
    "CORRELATED",
    "RECONSTRUCTED",
    "SUSPICIOUS",
    "UNKNOWN",
]


class CaseBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, json_schema_extra={"example": "Incident-2026-Alpha"})
    description: Optional[str] = Field(None, json_schema_extra={"example": "Forensic analysis of suspicious endpoint memory and log dump"})
    investigator: str = Field(default="A. Abhiram", max_length=128)
    status: str = Field(default="New", json_schema_extra={"example": "New"})


class CaseCreate(CaseBase):
    case_number: Optional[str] = Field(None, json_schema_extra={"example": "CAS-2026-001"})


class CaseUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    description: Optional[str] = None
    investigator: Optional[str] = Field(None, max_length=128)
    status: Optional[str] = None


class CaseResponse(CaseBase):
    id: str
    case_number: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CaseDetailResponse(CaseResponse):
    evidence_count: int = 0
    timeline_events_count: int = 0
    findings_count: int = 0


class CaseExportResponse(BaseModel):
    case: CaseResponse
    evidence: List[Dict[str, Any]] = []
    timeline_events: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    exported_at: datetime
    format_version: str = "1.0"


class EvidenceResponse(BaseModel):
    id: str
    case_id: str
    evidence_number: Optional[str] = None
    filename: str
    file_type: str
    mime_type: Optional[str] = None
    file_size_bytes: int
    readable_size: Optional[str] = None
    sha256: str
    md5: Optional[str] = None
    created_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None
    accessed_time: Optional[datetime] = None
    classification: str
    status: str
    notes: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class EvidenceDetailResponse(EvidenceResponse):
    case_number: Optional[str] = None
    case_name: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None


class EvidenceVerificationResponse(BaseModel):
    evidence_id: str
    stored_sha256: str
    computed_sha256: str
    status: str  # "MATCH" or "TAMPERED"
    verified_at: datetime
    notes: str


# ----------------- Timeline Schemas -----------------

class TimelineEventBase(BaseModel):
    timestamp: datetime
    timestamp_end: Optional[datetime] = None
    timestamp_source: str = Field(default="Filesystem MACB", json_schema_extra={"example": "Filesystem MACB ($FILE_MODIFY)"})
    event_type: str = Field(default="File Modified", json_schema_extra={"example": "File Modified"})
    artifact_category: Optional[str] = Field(None, json_schema_extra={"example": "File"})
    description: str = Field(..., min_length=2, json_schema_extra={"example": "Observed modification of payload file"})
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, json_schema_extra={"example": 1.0})
    classification: str = Field(default="OBSERVED", json_schema_extra={"example": "OBSERVED"})
    event_metadata: Optional[Dict[str, Any]] = None


class TimelineEventCreate(TimelineEventBase):
    case_id: str
    evidence_id: Optional[str] = None


class TimelineEventResponse(TimelineEventBase):
    id: str
    case_id: str
    evidence_id: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class TimelineEventDetailResponse(TimelineEventResponse):
    case_number: Optional[str] = None
    source_evidence_filename: Optional[str] = None
    source_evidence_sha256: Optional[str] = None
    source_evidence_number: Optional[str] = None


class SystemStatusResponse(BaseModel):
    app_name: str
    app_version: str
    academic_title: str
    environment: str
    status: str
    database_connected: bool
    active_cases_count: int
    total_evidence_count: int
    system_time: datetime


# ----------------- Finding & Correlation Schemas -----------------

class ForensicFindingBase(BaseModel):
    title: str = Field(..., min_length=2, max_length=255, json_schema_extra={"example": "Correlated Process Launch & Payload Creation"})
    finding_type: str = Field(default="Correlation Cluster", json_schema_extra={"example": "Correlation Cluster"})
    classification: str = Field(default="CORRELATED", json_schema_extra={"example": "CORRELATED"})
    severity: str = Field(default="Medium", json_schema_extra={"example": "Medium"})
    confidence: float = Field(default=0.85, ge=0.0, le=1.0, json_schema_extra={"example": 0.85})
    reason: str = Field(..., min_length=2, json_schema_extra={"example": "Independent filesystem modification and memory process traces occurred within 3.2s."})
    explanation: Optional[str] = None
    supporting_artifacts: Optional[List[Dict[str, Any]]] = None
    recommendation: Optional[str] = None


class ForensicFindingCreate(ForensicFindingBase):
    case_id: str


class ForensicFindingResponse(ForensicFindingBase):
    id: str
    case_id: str
    created_at: datetime

    model_config = {"from_attributes": True}


class CorrelatedEventItem(BaseModel):
    id: str
    timestamp: datetime
    event_type: str
    timestamp_source: str
    description: str
    classification: str
    confidence: float
    evidence_id: Optional[str] = None
    evidence_filename: Optional[str] = None
    time_delta_seconds: float = 0.0


class CorrelationCluster(BaseModel):
    cluster_id: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    event_count: int
    evidence_sources_count: int
    evidence_filenames: List[str]
    confidence: float
    cluster_classification: str
    summary: str
    events: List[CorrelatedEventItem]


class CorrelationRunRequest(BaseModel):
    time_window_seconds: int = Field(default=60, ge=5, le=3600, json_schema_extra={"example": 60})
    min_cluster_size: int = Field(default=2, ge=2, le=50, json_schema_extra={"example": 2})
    generate_findings: bool = Field(default=True)


class CorrelationReportResponse(BaseModel):
    case_id: str
    time_window_seconds: int
    total_events_analyzed: int
    total_clusters: int
    multi_source_correlations_count: int
    findings_generated_count: int
    clusters: List[CorrelationCluster]
    generated_at: datetime


# ----------------- Memory Forensics Schemas (Volatility 3) -----------------

class ProcessItem(BaseModel):
    pid: int
    ppid: int
    image_name: str
    offset: Optional[str] = None
    threads: Optional[int] = 1
    handles: Optional[int] = None
    session_id: Optional[int] = 1
    created_time: Optional[str] = None
    exit_time: Optional[str] = None
    status: str = "Running"


class NetworkItem(BaseModel):
    pid: int
    owner: Optional[str] = None
    proto: str = "TCP"
    local_addr: str
    local_port: int
    foreign_addr: str
    foreign_port: int
    state: str = "ESTABLISHED"
    created_time: Optional[str] = None


class InjectedModuleItem(BaseModel):
    pid: int
    process_name: str
    start_vpn: str
    end_vpn: str
    tag: Optional[str] = "VadS"
    protection: str = "PAGE_EXECUTE_READWRITE"
    commit_charge: Optional[int] = 1
    hexdump_snippet: Optional[str] = None
    disassembly_snippet: Optional[str] = None
    severity: str = "High"


class CommandlineItem(BaseModel):
    pid: int
    process_name: str
    args: str


class HandleItem(BaseModel):
    pid: int
    process_name: str
    handle_value: str
    item_type: str
    granted_access: Optional[str] = None
    name: str


class MemoryAnalysisRequest(BaseModel):
    evidence_id: str
    plugins: List[str] = Field(
        default=["windows.pslist", "windows.netscan", "windows.malfind", "windows.cmdline"],
        json_schema_extra={"example": ["windows.pslist", "windows.netscan", "windows.malfind"]},
    )
    sync_timeline: bool = Field(default=True)


class MemoryAnalysisResponse(BaseModel):
    id: str
    case_id: str
    evidence_id: str
    evidence_filename: str
    plugins_run: List[str]
    processes: List[ProcessItem]
    network_connections: List[NetworkItem]
    injected_regions: List[InjectedModuleItem]
    handles: List[HandleItem]
    cmdlines: List[CommandlineItem]
    raw_output: Optional[str] = None
    timeline_events_created: int = 0
    findings_created: int = 0
    created_at: datetime


# ----------------- Machine Learning Baseline Schemas -----------------

class MLModelResponse(BaseModel):
    id: str
    name: str
    version: str
    algorithm: str
    task_type: str
    training_dataset: str
    metrics: Dict[str, Any]
    feature_names: List[str]
    feature_importances: Optional[Dict[str, Any]] = None
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class EvidencePredictionResponse(BaseModel):
    evidence_id: str
    filename: str
    is_anomaly: bool
    probability: float
    confidence: float
    classification: str
    severity: str
    reason: str
    features: Dict[str, Any]
    key_factors: List[str]


class TimelineAnomalyResponse(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    description: str
    anomaly_score: float
    is_anomaly: bool
    confidence: float
    classification: str
    reason: str


class MLCaseSummaryResponse(BaseModel):
    case_id: str
    deleted_file_probability: int
    manipulation_likelihood: int
    malware_indicator: int
    confidence_score: int
    confidence_level: str
    total_evidence_evaluated: int
    total_events_evaluated: int
    total_findings_evaluated: int
    generated_at: str


# ----------------- Deep Learning (PyTorch) Schemas -----------------

class DeepPredictionResponse(BaseModel):
    evidence_id: str
    filename: str
    deleted_file_probability: float
    manipulation_likelihood: float
    malware_indicator: float
    confidence: float
    classification: str
    severity: str
    reason: str
    features: Dict[str, Any]
    key_factors: List[str]


class DeepTrainResponse(BaseModel):
    status: str
    model_name: str
    metrics: Dict[str, Any]
    model_path: str
    architecture_summary: Dict[str, Any]


# ----------------- Phase 9: Deleted-File Analysis Schemas -----------------

class DeletedFileResponse(BaseModel):
    id: str
    case_id: str
    evidence_id: Optional[str] = None
    filename: str
    original_path: Optional[str] = None
    file_type: str
    estimated_size_bytes: int
    carved_header_signature: Optional[str] = None
    deletion_timestamp: Optional[datetime] = None
    confidence: float
    classification: str
    status: str
    corroborating_sources: List[str]
    reconstruction_reason: str
    carved_hex_preview: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class DeletedAnalysisSummaryResponse(BaseModel):
    case_id: str
    total_deleted_artifacts: int
    memory_corroborated_count: int
    log_corroborated_count: int
    average_confidence: float
    artifacts: List[DeletedFileResponse]


# ----------------- Phase 10: Timestamp Reconstruction Schemas -----------------

class TimestampReconstructionResponse(BaseModel):
    id: str
    case_id: str
    anchor_event_id: Optional[str] = None
    event_title: str
    observed_timestamp: datetime
    probable_window_start: datetime
    probable_window_end: datetime
    probable_event_time: datetime
    window_duration_seconds: float
    consistency_status: str
    classification: str
    confidence: float
    sources_compared: List[Dict[str, Any]]
    related_event_ids: List[str]
    reconstruction_reason: str
    created_at: datetime

    model_config = {"from_attributes": True}


class TimestampAnalysisSummaryResponse(BaseModel):
    case_id: str
    total_windows_evaluated: int
    consistent_count: int
    inconsistent_count: int
    average_confidence: float
    reconstructed_windows: List[TimestampReconstructionResponse]


# ----------------- Phase 11: Anti-Forensic Schemas -----------------

class AntiForensicIndicatorResponse(BaseModel):
    id: str
    case_id: str
    indicator_type: str
    title: str
    severity: str
    confidence: float
    classification: str
    supporting_evidence_ids: List[str]
    supporting_artifacts: List[str]
    reason: str
    recommendation: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AntiForensicsSummaryResponse(BaseModel):
    case_id: str
    total_indicators: int
    critical_severity_count: int
    high_severity_count: int
    average_confidence: float
    indicators: List[AntiForensicIndicatorResponse]


# ----------------- Phase 12: Cloud Evidence (SaaS/IaaS) Schemas -----------------

class CloudEvidenceItemResponse(BaseModel):
    id: str
    case_id: str
    provider: str
    event_time: datetime
    event_name: str
    service_name: Optional[str] = None
    identity_arn: Optional[str] = None
    identity_type: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    aws_region: Optional[str] = None
    error_code: Optional[str] = None
    classification: str
    severity: str
    is_anti_forensic: bool
    raw_payload: Dict[str, Any]
    notes: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class CloudCorrelationItemResponse(BaseModel):
    id: str
    case_id: str
    cloud_event_id: Optional[str] = None
    local_artifact_type: str
    local_artifact_desc: str
    local_timestamp: Optional[datetime] = None
    cloud_timestamp: datetime
    time_delta_seconds: float
    correlation_type: str
    confidence: float
    classification: str
    rationale: str
    created_at: datetime

    model_config = {"from_attributes": True}


class CloudIngestRequest(BaseModel):
    payload: Any
    provider: Optional[str] = None


class CloudIngestResponse(BaseModel):
    case_id: str
    records_ingested: int
    anti_forensic_evasion_detected: int
    provider: str
    records: List[CloudEvidenceItemResponse]


class CloudSummaryResponse(BaseModel):
    case_id: str
    total_records: int
    anti_forensic_count: int
    providers: List[str]
    critical_count: int
    high_count: int
    records: List[CloudEvidenceItemResponse]


class CloudCorrelationsSummaryResponse(BaseModel):
    case_id: str
    total_correlations: int
    average_confidence: float
    correlations: List[CloudCorrelationItemResponse]


# ----------------- Authentication Schemas -----------------

class UserSignUp(BaseModel):
    email: str = Field(..., min_length=3, max_length=255, json_schema_extra={"example": "investigator@forensix.ai"})
    username: str = Field(..., min_length=3, max_length=100, json_schema_extra={"example": "abhiram"})
    password: str = Field(..., min_length=6, max_length=128, json_schema_extra={"example": "Password123!"})
    full_name: Optional[str] = Field("A. Abhiram", max_length=255)
    role: Optional[str] = Field("Lead Forensic Examiner", max_length=100)


class UserLogin(BaseModel):
    username_or_email: str = Field(..., min_length=1, json_schema_extra={"example": "abhiram"})
    password: str = Field(..., min_length=1, json_schema_extra={"example": "Password123!"})


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse









