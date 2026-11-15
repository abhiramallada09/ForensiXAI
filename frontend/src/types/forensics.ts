export type EvidenceClassification =
  | 'OBSERVED'
  | 'CORRELATED'
  | 'RECONSTRUCTED'
  | 'SUSPICIOUS'
  | 'UNKNOWN';

export type CaseStatus =
  | 'New'
  | 'Evidence Collected'
  | 'Analyzing'
  | 'Analysis Complete'
  | 'Review Required'
  | 'Archived';

export interface Case {
  id: string;
  case_number: string;
  name: string;
  description?: string;
  investigator: string;
  status: CaseStatus;
  created_at: string;
  updated_at: string;
  evidence_count?: number;
  timeline_events_count?: number;
  findings_count?: number;
}

export interface CaseCreatePayload {
  name: string;
  case_number?: string;
  description?: string;
  investigator?: string;
  status?: CaseStatus;
}

export interface CaseUpdatePayload {
  name?: string;
  description?: string;
  investigator?: string;
  status?: CaseStatus;
}

export interface CaseExportData {
  case: Case;
  evidence: any[];
  timeline_events: any[];
  findings: any[];
  exported_at: string;
  format_version: string;
}

export interface EvidenceItem {
  id: string;
  case_id: string;
  evidence_number?: string;
  filename: string;
  file_type: string;
  mime_type?: string;
  file_size_bytes: number;
  readable_size?: string;
  sha256: string;
  md5?: string;
  created_time?: string;
  modified_time?: string;
  accessed_time?: string;
  classification: EvidenceClassification;
  status: string;
  notes?: string;
  created_at: string;
  case_number?: string;
  case_name?: string;
  metadata_json?: Record<string, any>;
}

export interface EvidenceVerificationResult {
  evidence_id: string;
  stored_sha256: string;
  computed_sha256: string;
  status: 'MATCH' | 'TAMPERED';
  verified_at: string;
  notes: string;
}

export interface TimelineEvent {
  id: string;
  case_id: string;
  evidence_id?: string;
  timestamp: string;
  timestamp_end?: string;
  timestamp_source: string;
  event_type: string;
  artifact_category?: string;
  description: string;
  confidence: number;
  classification: EvidenceClassification;
  created_at: string;
  case_number?: string;
  source_evidence_filename?: string;
  source_evidence_sha256?: string;
  source_evidence_number?: string;
  event_metadata?: Record<string, any>;
}

export interface TimelineEventCreatePayload {
  case_id: string;
  evidence_id?: string;
  timestamp: string;
  timestamp_end?: string;
  timestamp_source: string;
  event_type: string;
  artifact_category?: string;
  description: string;
  confidence: number;
  classification: EvidenceClassification;
}

export interface SystemStatus {
  app_name: string;
  app_version: string;
  academic_title: string;
  environment: string;
  status: string;
  database_connected: boolean;
  active_cases_count: number;
  total_evidence_count: number;
  system_time: string;
}

export interface KeyFindingItem {
  id: string;
  title: string;
  detail: string;
  type: 'file' | 'clock' | 'alert';
  severity: 'low' | 'medium' | 'high';
}

export interface ForensicFinding {
  id: string;
  case_id: string;
  title: string;
  finding_type: string;
  classification: EvidenceClassification;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: number;
  reason: string;
  explanation?: string;
  supporting_artifacts?: Array<{
    event_id?: string;
    event_type?: string;
    timestamp?: string;
    source?: string;
    evidence_id?: string;
    delta_s?: number;
    [key: string]: any;
  }>;
  recommendation?: string;
  created_at: string;
}

export interface CorrelatedEventItem {
  id: string;
  timestamp: string;
  event_type: string;
  timestamp_source: string;
  description: string;
  classification: EvidenceClassification;
  confidence: number;
  evidence_id?: string;
  evidence_filename?: string;
  time_delta_seconds: number;
}

export interface CorrelationCluster {
  cluster_id: string;
  start_time: string;
  end_time: string;
  duration_seconds: number;
  event_count: number;
  evidence_sources_count: number;
  evidence_filenames: string[];
  confidence: number;
  cluster_classification: EvidenceClassification;
  summary: string;
  events: CorrelatedEventItem[];
}

export interface CorrelationReportResponse {
  case_id: string;
  time_window_seconds: number;
  total_events_analyzed: number;
  total_clusters: number;
  multi_source_correlations_count: number;
  findings_generated_count: number;
  clusters: CorrelationCluster[];
  generated_at: string;
}

// ----------------- Memory Forensics Types (Volatility 3) -----------------

export interface ProcessItem {
  pid: number;
  ppid: number;
  image_name: string;
  offset?: string;
  threads?: number;
  handles?: number;
  session_id?: number;
  created_time?: string;
  exit_time?: string;
  status: 'Running' | 'Terminated' | 'Suspicious';
}

export interface NetworkItem {
  pid: number;
  owner?: string;
  proto: string;
  local_addr: string;
  local_port: number;
  foreign_addr: string;
  foreign_port: number;
  state: string;
  created_time?: string;
}

export interface InjectedModuleItem {
  pid: number;
  process_name: string;
  start_vpn: string;
  end_vpn: string;
  tag?: string;
  protection: string;
  commit_charge?: number;
  hexdump_snippet?: string;
  disassembly_snippet?: string;
  severity: string;
}

export interface CommandlineItem {
  pid: number;
  process_name: string;
  args: string;
}

export interface HandleItem {
  pid: number;
  process_name: string;
  handle_value: string;
  item_type: string;
  granted_access?: string;
  name: string;
}

export interface MemoryAnalysisResponse {
  id: string;
  case_id: string;
  evidence_id: string;
  evidence_filename: string;
  plugins_run: string[];
  processes: ProcessItem[];
  network_connections: NetworkItem[];
  injected_regions: InjectedModuleItem[];
  handles: HandleItem[];
  cmdlines: CommandlineItem[];
  raw_output?: string;
  timeline_events_created: number;
  findings_created: number;
  created_at: string;
}

// ----------------- Machine Learning Baseline Types -----------------

export interface MLModelInfo {
  id: string;
  name: string;
  version: string;
  algorithm: string;
  task_type: string;
  training_dataset: string;
  metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1?: number;
    roc_auc?: number;
    [key: string]: any;
  };
  feature_names: string[];
  feature_importances?: Record<string, number>;
  is_active: boolean;
  created_at: string;
}

export interface EvidencePrediction {
  evidence_id: string;
  filename: string;
  is_anomaly: boolean;
  probability: number;
  confidence: number;
  classification: EvidenceClassification;
  severity: string;
  reason: string;
  features: Record<string, number>;
  key_factors: string[];
}

export interface TimelineAnomaly {
  event_id: string;
  event_type: string;
  timestamp: string;
  description: string;
  anomaly_score: number;
  is_anomaly: boolean;
  confidence: number;
  classification: EvidenceClassification;
  reason: string;
}

export interface MLCaseSummary {
  case_id: string;
  deleted_file_probability: number;
  manipulation_likelihood: number;
  malware_indicator: number;
  confidence_score: number;
  confidence_level: string;
  total_evidence_evaluated: number;
  total_events_evaluated: number;
  total_findings_evaluated: number;
  generated_at: string;
}

// ----------------- Deep Learning (PyTorch) Types -----------------

export interface DeepPredictionItem {
  evidence_id: string;
  filename: string;
  deleted_file_probability: number;
  manipulation_likelihood: number;
  malware_indicator: number;
  confidence: number;
  classification: EvidenceClassification;
  severity: string;
  reason: string;
  features: Record<string, number>;
  key_factors: string[];
}

export interface DeepTrainResponse {
  status: string;
  model_name: string;
  metrics: {
    accuracy?: number;
    deleted_task_accuracy?: number;
    manipulation_task_accuracy?: number;
    malware_task_accuracy?: number;
    final_epoch_loss?: number;
    total_parameters?: number;
    trainable_parameters?: number;
    training_epochs?: number;
    [key: string]: any;
  };
  model_path: string;
  architecture_summary: {
    model_name: string;
    architecture: string;
    framework: string;
    input_dimension: number;
    hidden_dimension: number;
    total_parameters: number;
    trainable_parameters: number;
    layers: Array<{ name: string; type: string; dim: string }>;
  };
}

export interface DeepCaseSummary {
  case_id: string;
  deleted_file_probability: number;
  manipulation_likelihood: number;
  malware_indicator: number;
  confidence_score: number;
  confidence_label: string;
  model_name: string;
  model_version: string;
  evaluated_evidence_count: number;
  deep_learning_active: boolean;
}

// ----------------- Phase 9: Deleted-File Analysis Types -----------------

export interface DeletedFileItem {
  id: string;
  case_id: string;
  evidence_id?: string;
  filename: string;
  original_path?: string;
  file_type: string;
  estimated_size_bytes: number;
  carved_header_signature?: string;
  deletion_timestamp?: string;
  confidence: number;
  classification: EvidenceClassification;
  status: string;
  corroborating_sources: string[];
  reconstruction_reason: string;
  carved_hex_preview?: string;
  created_at: string;
}

export interface DeletedAnalysisSummary {
  case_id: string;
  total_deleted_artifacts: number;
  memory_corroborated_count: number;
  log_corroborated_count: number;
  average_confidence: number;
  artifacts: DeletedFileItem[];
}

// ----------------- Phase 10: Timestamp Reconstruction Types -----------------

export interface TimestampSourceItem {
  source: string;
  timestamp?: string;
  formatted_time?: string;
  event_type: string;
  description: string;
}

export interface TimestampReconstructionItem {
  id: string;
  case_id: string;
  anchor_event_id?: string;
  event_title: string;
  observed_timestamp: string;
  probable_window_start: string;
  probable_window_end: string;
  probable_event_time: string;
  window_duration_seconds: number;
  consistency_status: 'CONSISTENT' | 'INCONSISTENT' | 'MISSING';
  classification: EvidenceClassification;
  confidence: number;
  sources_compared: TimestampSourceItem[];
  related_event_ids: string[];
  reconstruction_reason: string;
  created_at: string;
}

export interface TimestampAnalysisSummary {
  case_id: string;
  total_windows_evaluated: number;
  consistent_count: number;
  inconsistent_count: number;
  average_confidence: number;
  reconstructed_windows: TimestampReconstructionItem[];
}

// ----------------- Phase 11: Anti-Forensic Types -----------------

export interface AntiForensicIndicatorItem {
  id: string;
  case_id: string;
  indicator_type: string;
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence: number;
  classification: EvidenceClassification;
  supporting_evidence_ids: string[];
  supporting_artifacts: string[];
  reason: string;
  recommendation: string;
  created_at: string;
}

export interface AntiForensicsSummary {
  case_id: string;
  total_indicators: number;
  critical_severity_count: number;
  high_severity_count: number;
  average_confidence: number;
  indicators: AntiForensicIndicatorItem[];
}

// ----------------- Phase 12: Cloud Evidence Types -----------------

export interface CloudEvidenceItem {
  id: string;
  case_id: string;
  provider: 'AWS' | 'Azure' | 'GCP' | string;
  event_time: string;
  event_name: string;
  service_name?: string;
  identity_arn?: string;
  identity_type?: string;
  source_ip?: string;
  user_agent?: string;
  aws_region?: string;
  error_code?: string;
  classification: EvidenceClassification;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  is_anti_forensic: boolean;
  raw_payload: Record<string, any>;
  notes?: string;
  created_at: string;
}

export interface CloudCorrelationItem {
  id: string;
  case_id: string;
  cloud_event_id?: string;
  local_artifact_type: string;
  local_artifact_desc: string;
  local_timestamp?: string;
  cloud_timestamp: string;
  time_delta_seconds: number;
  correlation_type: string;
  confidence: number;
  classification: EvidenceClassification;
  rationale: string;
  created_at: string;
}

export interface CloudSummaryResponse {
  case_id: string;
  total_records: number;
  anti_forensic_count: number;
  providers: string[];
  critical_count: number;
  high_count: number;
  records: CloudEvidenceItem[];
}

export interface CloudCorrelationsSummaryResponse {
  case_id: string;
  total_correlations: number;
  average_confidence: number;
  correlations: CloudCorrelationItem[];
}

export interface CloudIngestResponse {
  case_id: string;
  records_ingested: number;
  anti_forensic_evasion_detected: number;
  provider: string;
  records: CloudEvidenceItem[];
}

// ----------------- Phase 13: Report Types -----------------

export interface CaseReportSummary {
  case_id: string;
  case_number: string;
  name: string;
  investigator: string;
  status: string;
  evidence_count: number;
  memory_analyses_count: number;
  deleted_files_count: number;
  timestamp_windows_count: number;
  anti_forensic_indicators_count: number;
  cloud_records_count: number;
  cloud_correlations_count: number;
  findings_count: number;
  evidentiary_standards: string[];
  report_format: string;
}

export interface GeneratedReportFileInfo {
  status: string;
  case_id: string;
  filename: string;
  file_path: string;
  file_size_bytes: number;
  sha256: string;
}

// ----------------- Phase 14: Research Benchmark Types -----------------

export interface ModelComparisonRow {
  model_name: string;
  model_type: string;
  parameters: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  latency_per_100_ms: number;
  multi_task_capable: boolean;
  status: string;
}

export interface TaskBreakdownItem {
  task_id: string;
  task_name: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  description: string;
}

export interface ResearchBenchmarkResponse {
  evaluation_title: string;
  eval_dataset_size: number;
  features_evaluated: number;
  overall_deep_accuracy: number;
  overall_deep_f1: number;
  deep_latency_ms: number;
  comparison_table: ModelComparisonRow[];
  task_breakdown: TaskBreakdownItem[];
  academic_conclusion: string;
}

// ----------------- Authentication & User Types -----------------

export interface User {
  id: string;
  email: string;
  username: string;
  full_name?: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface UserSignUp {
  email: string;
  username: string;
  password: string;
  full_name?: string;
  role?: string;
}

export interface UserLogin {
  username_or_email: string;
  password: string;
}










