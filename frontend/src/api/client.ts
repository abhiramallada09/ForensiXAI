import {
  SystemStatus,
  Case,
  CaseCreatePayload,
  CaseUpdatePayload,
  CaseExportData,
  EvidenceItem,
  EvidenceVerificationResult,
  TimelineEvent,
  TimelineEventCreatePayload,
  ForensicFinding,
  CorrelationReportResponse,
  MemoryAnalysisResponse,
  ProcessItem,
  NetworkItem,
  InjectedModuleItem,
  MLModelInfo,
  EvidencePrediction,
  TimelineAnomaly,
  MLCaseSummary,
  DeepPredictionItem,
  DeepTrainResponse,
  DeepCaseSummary,
  DeletedAnalysisSummary,
  TimestampAnalysisSummary,
  AntiForensicsSummary,
  CloudSummaryResponse,
  CloudCorrelationsSummaryResponse,
  CloudIngestResponse,
  CaseReportSummary,
  GeneratedReportFileInfo,
  ResearchBenchmarkResponse,
  User,
  AuthResponse,
  UserSignUp,
  UserLogin,
} from '../types/forensics';

const API_BASE = '/api/v1';

export async function fetchHealth(): Promise<{ status: string; app: string; version: string }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw new Error(`Failed to fetch health check: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSystemStatus(): Promise<SystemStatus> {
  const res = await fetch(`${API_BASE}/status`);
  if (!res.ok) {
    throw new Error(`Failed to fetch system status: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCases(statusFilter?: string, search?: string): Promise<Case[]> {
  const params = new URLSearchParams();
  if (statusFilter && statusFilter !== 'All') {
    params.append('status', statusFilter);
  }
  if (search && search.trim()) {
    params.append('search', search.trim());
  }

  const url = `${API_BASE}/cases${params.toString() ? `?${params.toString()}` : ''}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch cases: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseById(caseId: string): Promise<Case> {
  const res = await fetch(`${API_BASE}/cases/${caseId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch case: ${res.statusText}`);
  }
  return res.json();
}

export async function createCase(payload: CaseCreatePayload): Promise<Case> {
  const res = await fetch(`${API_BASE}/cases`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to create case');
  }
  return res.json();
}

export async function updateCase(caseId: string, payload: CaseUpdatePayload): Promise<Case> {
  const res = await fetch(`${API_BASE}/cases/${caseId}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to update case');
  }
  return res.json();
}

export async function archiveCase(caseId: string): Promise<Case> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/archive`, {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`Failed to archive case: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteCase(caseId: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/cases/${caseId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`Failed to delete case: ${res.statusText}`);
  }
  return res.json();
}

export async function exportCaseDossier(caseId: string): Promise<CaseExportData> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/export`);
  if (!res.ok) {
    throw new Error(`Failed to export case: ${res.statusText}`);
  }
  return res.json();
}

// ----------------- Evidence API -----------------

export async function uploadEvidenceFile(
  caseId: string,
  file: File,
  fileType: string = 'File',
  notes?: string
): Promise<EvidenceItem> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('file_type', fileType);
  if (notes) {
    formData.append('notes', notes);
  }

  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to upload evidence file');
  }
  return res.json();
}

export async function fetchEvidenceList(
  caseId?: string,
  fileType?: string,
  search?: string
): Promise<EvidenceItem[]> {
  const params = new URLSearchParams();
  if (caseId) params.append('case_id', caseId);
  if (fileType && fileType !== 'All') params.append('file_type', fileType);
  if (search && search.trim()) params.append('search', search.trim());

  const url = `${API_BASE}/evidence${params.toString() ? `?${params.toString()}` : ''}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence list: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvidenceDetail(evidenceId: string): Promise<EvidenceItem> {
  const res = await fetch(`${API_BASE}/evidence/${evidenceId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence detail: ${res.statusText}`);
  }
  return res.json();
}

export async function verifyEvidenceIntegrity(evidenceId: string): Promise<EvidenceVerificationResult> {
  const res = await fetch(`${API_BASE}/evidence/${evidenceId}/verify-hash`, {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`Failed to verify evidence hash: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteEvidenceItem(evidenceId: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/evidence/${evidenceId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`Failed to delete evidence item: ${res.statusText}`);
  }
  return res.json();
}

// ----------------- Timeline API -----------------

export interface TimelineQueryParams {
  case_id?: string;
  event_type?: string;
  classification?: string;
  timestamp_source?: string;
  search?: string;
  order?: 'asc' | 'desc';
}

export async function fetchTimelineEvents(params: TimelineQueryParams = {}): Promise<TimelineEvent[]> {
  const q = new URLSearchParams();
  if (params.case_id && params.case_id !== 'ALL') q.append('case_id', params.case_id);
  if (params.event_type && params.event_type !== 'All') q.append('event_type', params.event_type);
  if (params.classification && params.classification !== 'All') q.append('classification', params.classification);
  if (params.timestamp_source && params.timestamp_source !== 'All') q.append('timestamp_source', params.timestamp_source);
  if (params.search && params.search.trim()) q.append('search', params.search.trim());
  if (params.order) q.append('order', params.order);

  const url = `${API_BASE}/timeline${q.toString() ? `?${q.toString()}` : ''}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch timeline: ${res.statusText}`);
  }
  return res.json();
}

export async function createTimelineEvent(payload: TimelineEventCreatePayload): Promise<TimelineEvent> {
  const res = await fetch(`${API_BASE}/timeline/events`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to create timeline event');
  }
  return res.json();
}

export async function rebuildCaseTimeline(caseId: string): Promise<{ success: boolean; message: string; newly_indexed_events: number }> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/rebuild`, {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`Failed to rebuild timeline: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteTimelineEvent(eventId: string): Promise<{ success: boolean; message: string }> {
  const res = await fetch(`${API_BASE}/timeline/events/${eventId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`Failed to delete timeline event: ${res.statusText}`);
  }
  return res.json();
}

// ----------------- Correlation & Findings APIs -----------------

export interface CorrelationRunOptions {
  time_window_seconds?: number;
  min_cluster_size?: number;
  generate_findings?: boolean;
}

export async function runEvidenceCorrelation(
  caseId: string,
  options: CorrelationRunOptions = {}
): Promise<CorrelationReportResponse> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      time_window_seconds: options.time_window_seconds ?? 60,
      min_cluster_size: options.min_cluster_size ?? 2,
      generate_findings: options.generate_findings ?? true,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to execute correlation engine');
  }
  return res.json();
}

export async function fetchCaseCorrelations(
  caseId: string,
  timeWindowSeconds: number = 60
): Promise<CorrelationReportResponse> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlations?time_window_seconds=${timeWindowSeconds}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch correlations: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseFindings(caseId: string): Promise<ForensicFinding[]> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings`);
  if (!res.ok) {
    throw new Error(`Failed to fetch case findings: ${res.statusText}`);
  }
  return res.json();
}

export async function createCaseFinding(
  caseId: string,
  finding: {
    title: string;
    finding_type?: string;
    classification?: string;
    severity?: string;
    confidence?: number;
    reason: string;
    explanation?: string;
    supporting_artifacts?: any[];
    recommendation?: string;
  }
): Promise<ForensicFinding> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(finding),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to create finding');
  }
  return res.json();
}

export async function deleteFinding(findingId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/findings/${findingId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`Failed to delete finding: ${res.statusText}`);
  }
}

// ----------------- Memory Forensics APIs (Volatility 3) -----------------

export async function runMemoryAnalysis(
  caseId: string,
  payload: {
    evidence_id: string;
    plugins?: string[];
    sync_timeline?: boolean;
  }
): Promise<MemoryAnalysisResponse> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/memory/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      evidence_id: payload.evidence_id,
      plugins: payload.plugins ?? ['windows.pslist', 'windows.netscan', 'windows.malfind', 'windows.cmdline'],
      sync_timeline: payload.sync_timeline ?? true,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to execute Volatility 3 analysis');
  }
  return res.json();
}

export async function fetchLatestMemoryAnalysis(
  caseId: string,
  evidenceId?: string
): Promise<MemoryAnalysisResponse | null> {
  const url = evidenceId
    ? `${API_BASE}/cases/${caseId}/memory/latest?evidence_id=${evidenceId}`
    : `${API_BASE}/cases/${caseId}/memory/latest`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch latest memory analysis: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchMemoryProcesses(caseId: string): Promise<ProcessItem[]> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/memory/processes`);
  if (!res.ok) {
    throw new Error(`Failed to fetch memory processes: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchMemoryNetwork(caseId: string): Promise<NetworkItem[]> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/memory/network`);
  if (!res.ok) {
    throw new Error(`Failed to fetch memory network sockets: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchMemoryInjections(caseId: string): Promise<InjectedModuleItem[]> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/memory/injections`);
  if (!res.ok) {
    throw new Error(`Failed to fetch memory code injections: ${res.statusText}`);
  }
  return res.json();
}

// ----------------- Machine Learning Baseline APIs -----------------

export async function fetchMLModels(): Promise<MLModelInfo[]> {
  const res = await fetch(`${API_BASE}/ml/models`);
  if (!res.ok) {
    throw new Error(`Failed to fetch ML models: ${res.statusText}`);
  }
  return res.json();
}

export async function trainBaselineModels(): Promise<{
  status: string;
  models_trained: number;
  random_forest_metrics: Record<string, number>;
  isolation_forest_metrics: Record<string, number>;
  feature_importances: Record<string, number>;
}> {
  const res = await fetch(`${API_BASE}/ml/train-baseline`, {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`Failed to train baseline models: ${res.statusText}`);
  }
  return res.json();
}

export async function predictCaseEvidence(caseId: string): Promise<EvidencePrediction[]> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/ml/predict-evidence`, {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`Failed to predict case evidence: ${res.statusText}`);
  }
  return res.json();
}

export async function detectCaseAnomalies(caseId: string): Promise<TimelineAnomaly[]> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/ml/detect-anomalies`, {
    method: 'POST',
  });
  if (!res.ok) {
    throw new Error(`Failed to detect timeline anomalies: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseMLSummary(caseId: string): Promise<MLCaseSummary> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/ml/summary`);
  if (!res.ok) {
    throw new Error(`Failed to fetch case ML summary: ${res.statusText}`);
  }
  return res.json();
}

// ----------------- Deep Learning (PyTorch) API Client -----------------

export async function trainDeepNetwork(epochs: number = 25): Promise<DeepTrainResponse> {
  const res = await fetch(`${API_BASE}/ml/train-deep?epochs=${epochs}`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to train deep neural network');
  }
  return res.json();
}

export async function deepEvaluateCaseEvidence(caseId: string): Promise<DeepPredictionItem[]> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/ml/deep-evaluate`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to run deep learning evaluation');
  }
  return res.json();
}

export async function fetchCaseDeepSummary(caseId: string): Promise<DeepCaseSummary> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/ml/deep-summary`);
  if (!res.ok) {
    throw new Error(`Failed to fetch case deep learning summary: ${res.statusText}`);
  }
  return res.json();
}

// ----------------- Phase 9: Deleted-File Analysis Client -----------------

export async function fetchDeletedFiles(caseId: string): Promise<DeletedAnalysisSummary> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/deleted-files`);
  if (!res.ok) {
    throw new Error(`Failed to fetch deleted files for case: ${res.statusText}`);
  }
  return res.json();
}

export async function runDeletedFileAnalysis(caseId: string): Promise<DeletedAnalysisSummary> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/deleted-files/analyze`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to execute deleted file analysis');
  }
  return res.json();
}

export async function deleteDeletedFileRecord(caseId: string, recordId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/deleted-files/${recordId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`Failed to delete record: ${res.statusText}`);
  }
}

// ----------------- Phase 10: Timestamp Reconstruction Client -----------------

export async function fetchTimestampWindows(caseId: string): Promise<TimestampAnalysisSummary> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/timestamps`);
  if (!res.ok) {
    throw new Error(`Failed to fetch timestamp windows: ${res.statusText}`);
  }
  return res.json();
}

export async function runTimestampReconstruction(
  caseId: string,
  windowThreshold: number = 120.0,
): Promise<TimestampAnalysisSummary> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/timestamps/reconstruct?window_threshold_seconds=${windowThreshold}`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to execute timestamp reconstruction');
  }
  return res.json();
}

export async function deleteTimestampWindow(caseId: string, recordId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/timestamps/${recordId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`Failed to delete timestamp window: ${res.statusText}`);
  }
}

// ----------------- Phase 11: Anti-Forensic Anomaly Detection Client -----------------

export async function fetchAntiForensicIndicators(caseId: string): Promise<AntiForensicsSummary> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/anti-forensics`);
  if (!res.ok) {
    throw new Error(`Failed to fetch anti-forensic indicators: ${res.statusText}`);
  }
  return res.json();
}

export async function runAntiForensicScan(caseId: string): Promise<AntiForensicsSummary> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/anti-forensics/analyze`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to execute anti-forensic anomaly scan');
  }
  return res.json();
}

export async function deleteAntiForensicIndicator(caseId: string, indicatorId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/anti-forensics/${indicatorId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`Failed to delete anti-forensic indicator: ${res.statusText}`);
  }
}

// ----------------- Phase 12: Cloud Evidence Client -----------------

export async function fetchCloudEvidence(
  caseId: string,
  provider?: string,
  isAntiForensic?: boolean,
  severity?: string,
): Promise<CloudSummaryResponse> {
  const params = new URLSearchParams();
  if (provider && provider !== 'All') params.append('provider', provider);
  if (isAntiForensic !== undefined) params.append('is_anti_forensic', String(isAntiForensic));
  if (severity && severity !== 'All') params.append('severity', severity);

  const qs = params.toString() ? `?${params.toString()}` : '';
  const res = await fetch(`${API_BASE}/cases/${caseId}/cloud${qs}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch cloud evidence: ${res.statusText}`);
  }
  return res.json();
}

export async function ingestCloudLogs(
  caseId: string,
  payload: any,
  provider?: string,
): Promise<CloudIngestResponse> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/cloud/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payload, provider }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to ingest cloud logs');
  }
  return res.json();
}

export async function runCloudCorrelation(
  caseId: string,
  timeWindowSeconds: number = 300.0,
): Promise<CloudCorrelationsSummaryResponse> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/cloud/correlate?time_window_seconds=${timeWindowSeconds}`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to run cloud correlation');
  }
  return res.json();
}

export async function fetchCloudCorrelations(caseId: string): Promise<CloudCorrelationsSummaryResponse> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/cloud/correlations`);
  if (!res.ok) {
    throw new Error(`Failed to fetch cloud correlations: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteCloudRecord(caseId: string, recordId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/cloud/${recordId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`Failed to delete cloud record: ${res.statusText}`);
  }
}

// ----------------- Phase 13: Forensic Examination Reports Client -----------------

export async function fetchReportSummary(caseId: string): Promise<CaseReportSummary> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/summary`);
  if (!res.ok) {
    throw new Error(`Failed to fetch report summary: ${res.statusText}`);
  }
  return res.json();
}

export async function downloadCasePdfReport(caseId: string, caseNumber: string): Promise<void> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/pdf`);
  if (!res.ok) {
    throw new Error(`Failed to download report PDF: ${res.statusText}`);
  }
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const safeNum = (caseNumber || 'Report').replace(/[\s\/]/g, '_');
  a.download = `ForensiX_Report_${safeNum}.pdf`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}

export async function generateCaseReportFile(caseId: string): Promise<GeneratedReportFileInfo> {
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/generate`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to generate report file on disk');
  }
  return res.json();
}

// ----------------- Phase 14: Research Benchmark & Demo Scenario Client -----------------

export async function fetchResearchBenchmark(): Promise<ResearchBenchmarkResponse> {
  const res = await fetch(`${API_BASE}/evaluation/benchmark`);
  if (!res.ok) {
    throw new Error(`Failed to fetch research benchmark: ${res.statusText}`);
  }
  return res.json();
}

export async function loadDemoScenario(): Promise<Case> {
  const res = await fetch(`${API_BASE}/demo/load-scenario`, {
    method: 'POST',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to load demo scenario');
  }
  return res.json();
}

// ----------------- Authentication & User Management Client -----------------

export function getAuthToken(): string | null {
  return localStorage.getItem('forensix_auth_token');
}

export function setAuthToken(token: string | null): void {
  if (token) {
    localStorage.setItem('forensix_auth_token', token);
  } else {
    localStorage.removeItem('forensix_auth_token');
  }
}

export async function signupUser(payload: UserSignUp): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to register account');
  }
  const data: AuthResponse = await res.json();
  setAuthToken(data.access_token);
  return data;
}

export async function loginUser(payload: UserLogin): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Invalid username or password');
  }
  const data: AuthResponse = await res.json();
  setAuthToken(data.access_token);
  return data;
}

export async function fetchCurrentUser(): Promise<User> {
  const token = getAuthToken();
  if (!token) {
    throw new Error('No authentication token found');
  }
  const res = await fetch(`${API_BASE}/auth/me`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Failed to fetch current user profile');
  }
  return res.json();
}

export async function fetchRegisteredUsers(): Promise<User[]> {
  const res = await fetch(`${API_BASE}/auth/users`);
  if (!res.ok) {
    throw new Error(`Failed to list registered accounts: ${res.statusText}`);
  }
  return res.json();
}









