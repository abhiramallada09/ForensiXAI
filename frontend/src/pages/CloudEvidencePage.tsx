import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Cloud,
  CloudLightning,
  RefreshCw,
  Play,
  CheckCircle2,
  FolderArchive,
  UploadCloud,
  Trash2,
  Search,
  Filter,
  Eye,
  Terminal,
  ShieldAlert,
  ArrowRight,
  Server,
  Globe,
} from 'lucide-react';
import {
  fetchCloudEvidence,
  ingestCloudLogs,
  runCloudCorrelation,
  fetchCloudCorrelations,
  deleteCloudRecord,
} from '../api/client';
import { EvidenceBadge } from '../components/common/EvidenceBadge';
import { useCase } from '../context/CaseContext';
import { CloudEvidenceItem } from '../types/forensics';

// Preset Demonstration Payloads
const AWS_BREACH_SAMPLE = {
  Records: [
    {
      eventTime: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
      eventName: 'ConsoleLogin',
      eventSource: 'signin.amazonaws.com',
      userIdentity: {
        type: 'IAMUser',
        arn: 'arn:aws:iam::123456789012:user/compromised_dev',
      },
      sourceIPAddress: '198.51.100.55',
      userAgent: 'AWS-CLI/2.15.0 Python/3.11.2',
      awsRegion: 'us-east-1',
    },
    {
      eventTime: new Date(Date.now() - 1000 * 60 * 14).toISOString(),
      eventName: 'StopLogging',
      eventSource: 'cloudtrail.amazonaws.com',
      userIdentity: {
        type: 'IAMUser',
        arn: 'arn:aws:iam::123456789012:user/compromised_dev',
      },
      sourceIPAddress: '198.51.100.55',
      awsRegion: 'us-east-1',
    },
    {
      eventTime: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
      eventName: 'DeleteBucket',
      eventSource: 's3.amazonaws.com',
      userIdentity: {
        type: 'IAMUser',
        arn: 'arn:aws:iam::123456789012:user/compromised_dev',
      },
      sourceIPAddress: '198.51.100.55',
      awsRegion: 'us-east-1',
    },
  ],
};

const AZURE_BREACH_SAMPLE = {
  value: [
    {
      eventTimestamp: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
      operationName: { value: 'Microsoft.Insights/diagnosticSettings/delete' },
      resourceProviderName: { value: 'Microsoft.Insights' },
      caller: 'infiltrator@enterprise.onmicrosoft.com',
      callerIpAddress: '203.0.113.99',
      status: { value: 'Succeeded' },
    },
    {
      eventTimestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
      operationName: { value: 'Microsoft.Compute/virtualMachines/delete' },
      resourceProviderName: { value: 'Microsoft.Compute' },
      caller: 'infiltrator@enterprise.onmicrosoft.com',
      callerIpAddress: '203.0.113.99',
      status: { value: 'Succeeded' },
    },
  ],
};

export const CloudEvidencePage: React.FC = () => {
  const queryClient = useQueryClient();
  const { activeCase, allCases } = useCase();

  const [selectedCaseId, setSelectedCaseId] = useState<string>(activeCase ? activeCase.id : '');
  const [activeTab, setActiveTab] = useState<'events' | 'correlations'>('events');
  const [filterProvider, setFilterProvider] = useState<string>('All');
  const [filterAntiForensicOnly, setFilterAntiForensicOnly] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Ingestion Modal State
  const [showIngestModal, setShowIngestModal] = useState<boolean>(false);
  const [ingestPayloadText, setIngestPayloadText] = useState<string>('');
  const [ingestProvider, setIngestProvider] = useState<string>('AWS');
  const [ingestError, setIngestError] = useState<string | null>(null);

  // Detail Modal State
  const [selectedCloudEvent, setSelectedCloudEvent] = useState<CloudEvidenceItem | null>(null);

  React.useEffect(() => {
    if (activeCase && !selectedCaseId) {
      setSelectedCaseId(activeCase.id);
    }
  }, [activeCase, selectedCaseId]);

  // Query Cloud Evidence
  const {
    data: cloudSummary,
    isLoading: isLoadingCloud,
  } = useQuery({
    queryKey: ['cloud-evidence', selectedCaseId, filterProvider, filterAntiForensicOnly],
    queryFn: () =>
      fetchCloudEvidence(
        selectedCaseId,
        filterProvider,
        filterAntiForensicOnly ? true : undefined,
      ),
    enabled: !!selectedCaseId,
  });

  // Query Cloud Correlations
  const {
    data: correlationSummary,
    isLoading: isLoadingCorrelations,
  } = useQuery({
    queryKey: ['cloud-correlations', selectedCaseId],
    queryFn: () => fetchCloudCorrelations(selectedCaseId),
    enabled: !!selectedCaseId,
  });

  // Ingestion Mutation
  const ingestMutation = useMutation({
    mutationFn: (payload: any) => ingestCloudLogs(selectedCaseId, payload, ingestProvider),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['cloud-evidence', selectedCaseId] });
      queryClient.invalidateQueries({ queryKey: ['timeline', selectedCaseId] });
      setShowIngestModal(false);
      setIngestPayloadText('');
      setActionSuccess(`Successfully ingested ${data.records_ingested} ${data.provider} cloud audit records!`);
      setTimeout(() => setActionSuccess(null), 5000);
    },
    onError: (err: any) => {
      setIngestError(err.message || 'Failed to ingest cloud logs');
    },
  });

  // Correlation Mutation
  const correlateMutation = useMutation({
    mutationFn: () => runCloudCorrelation(selectedCaseId, 300.0),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['cloud-correlations', selectedCaseId] });
      setActionSuccess(`Cross-correlation complete! Established ${data.total_correlations} link(s) between local and cloud evidence.`);
      setActiveTab('correlations');
      setTimeout(() => setActionSuccess(null), 5000);
    },
  });

  // Delete Record Mutation
  const deleteMutation = useMutation({
    mutationFn: (recordId: string) => deleteCloudRecord(selectedCaseId, recordId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cloud-evidence', selectedCaseId] });
      if (selectedCloudEvent) setSelectedCloudEvent(null);
    },
  });

  const handleIngestSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIngestError(null);
    try {
      const parsed = JSON.parse(ingestPayloadText);
      ingestMutation.mutate(parsed);
    } catch {
      setIngestError('Invalid JSON format. Please ensure valid CloudTrail or Azure Activity Log JSON.');
    }
  };

  const records = cloudSummary?.records || [];
  const correlations = correlationSummary?.correlations || [];

  const filteredRecords = records.filter((r) => {
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = r.event_name.toLowerCase().includes(q);
      const matchArn = (r.identity_arn || '').toLowerCase().includes(q);
      const matchIp = (r.source_ip || '').toLowerCase().includes(q);
      const matchService = (r.service_name || '').toLowerCase().includes(q);
      if (!matchName && !matchArn && !matchIp && !matchService) return false;
    }
    return true;
  });

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return 'bg-rose-100 text-rose-800 border-rose-300';
      case 'High':
        return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'Medium':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'Low':
        return 'bg-blue-100 text-blue-800 border-blue-300';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded-md bg-blue-100 text-blue-800 text-[11px] font-bold uppercase tracking-wider">
              Cloud Audit Engine
            </span>
            <span className="text-xs text-slate-400 font-medium">
              • SaaS/IaaS Cloud Evidence Recovery & Memory Attribution
            </span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Cloud className="w-5 h-5 text-blue-600" />
            <span>Cloud Service Provider Evidence & Cross-Correlation</span>
          </h2>
          <p className="text-xs text-slate-500 font-medium mt-1">
            Recovers AWS CloudTrail and Azure Activity audit logs, exposes cloud anti-forensics (e.g. StopLogging), and cross-correlates with local volatile memory.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-xl px-3 py-1.5 text-xs">
            <FolderArchive className="w-3.5 h-3.5 text-slate-500" />
            <span className="font-semibold text-slate-600">Case:</span>
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              className="bg-transparent font-bold text-slate-900 focus:outline-none"
            >
              {allCases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.case_number} - {c.name}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => setShowIngestModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-xl text-xs font-bold transition-all shadow-sm"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Ingest Cloud Logs</span>
          </button>

          <button
            onClick={() => correlateMutation.mutate()}
            disabled={!selectedCaseId || correlateMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white rounded-xl text-xs font-bold transition-all shadow-sm shadow-blue-200"
          >
            {correlateMutation.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-white" />
            )}
            <span>{correlateMutation.isPending ? 'Correlating...' : 'Correlate with Endpoint'}</span>
          </button>
        </div>
      </div>

      {actionSuccess && (
        <div className="flex items-center gap-3 p-4 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-2xl text-xs font-semibold animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Telemetry Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Total Cloud Audit Records</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-slate-900">
              {cloudSummary?.total_records ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">API events recorded</span>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Anti-Forensic Evasion Events</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-rose-600">
              {cloudSummary?.anti_forensic_count ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">logging/data tampered</span>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Correlated Endpoint Actions</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-blue-600">
              {correlationSummary?.total_correlations ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">cross-correlations</span>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Active Cloud Providers</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-slate-800">
              {cloudSummary?.providers && cloudSummary.providers.length > 0
                ? cloudSummary.providers.join(', ')
                : 'None'}
            </span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 pb-2">
        <button
          onClick={() => setActiveTab('events')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'events'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <Globe className="w-4 h-4" />
          <span>Cloud Audit Records ({records.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('correlations')}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'correlations'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-600 hover:bg-slate-100'
          }`}
        >
          <CloudLightning className="w-4 h-4" />
          <span>Endpoint-to-Cloud Cross-Correlations ({correlations.length})</span>
        </button>
      </div>

      {/* TAB 1: CLOUD AUDIT RECORDS */}
      {activeTab === 'events' && (
        <div className="space-y-4">
          {/* Filters & Search */}
          <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-2 flex-wrap">
              <Filter className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-bold text-slate-700">Provider:</span>
              {['All', 'AWS', 'Azure'].map((prov) => (
                <button
                  key={prov}
                  onClick={() => setFilterProvider(prov)}
                  className={`px-3 py-1 rounded-xl text-xs font-semibold transition-all ${
                    filterProvider === prov
                      ? 'bg-slate-900 text-white shadow-sm'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {prov}
                </button>
              ))}

              <button
                onClick={() => setFilterAntiForensicOnly(!filterAntiForensicOnly)}
                className={`ml-3 px-3 py-1 rounded-xl text-xs font-semibold border transition-all flex items-center gap-1.5 ${
                  filterAntiForensicOnly
                    ? 'bg-rose-100 border-rose-300 text-rose-800'
                    : 'bg-slate-50 border-slate-200 text-slate-600 hover:bg-slate-100'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Anti-Forensics Only</span>
              </button>
            </div>

            <div className="relative w-full md:w-64">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search action, ARN, IP..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500 font-medium"
              />
            </div>
          </div>

          {/* Records List */}
          {isLoadingCloud ? (
            <div className="bg-white rounded-2xl p-12 text-center border border-slate-200/80 shadow-sm">
              <RefreshCw className="w-6 h-6 animate-spin text-slate-400 mx-auto mb-2" />
              <p className="text-xs text-slate-500 font-medium">Loading cloud audit records...</p>
            </div>
          ) : filteredRecords.length === 0 ? (
            <div className="bg-white rounded-2xl p-12 text-center border border-slate-200/80 shadow-sm space-y-3">
              <UploadCloud className="w-10 h-10 text-slate-400 mx-auto" />
              <h3 className="text-sm font-bold text-slate-800">No Cloud Audit Records Ingested</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                No CloudTrail or Azure Activity Log records match your current criteria. Click "Ingest Cloud Logs" to load an audit JSON file or try a demonstration breach preset.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredRecords.map((item) => (
                <div
                  key={item.id}
                  className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm hover:border-slate-300 transition-all space-y-3"
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <div className="p-2.5 rounded-xl bg-blue-50 border border-blue-100 text-blue-600 shrink-0 mt-0.5">
                        <Server className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700 border border-slate-200">
                            {item.provider}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${getSeverityBadge(item.severity)}`}>
                            {item.severity}
                          </span>
                          {item.is_anti_forensic && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 border border-rose-300 text-rose-800 flex items-center gap-1">
                              <ShieldAlert className="w-3 h-3" />
                              <span>Anti-Forensics</span>
                            </span>
                          )}
                          <span className="text-xs text-slate-400 font-mono">
                            {new Date(item.event_time).toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' })} UTC
                          </span>
                        </div>
                        <h3 className="text-base font-bold text-slate-900 tracking-tight flex items-center gap-2">
                          <span>{item.event_name}</span>
                          {item.service_name && (
                            <span className="text-xs font-semibold text-slate-400 font-mono">
                              ({item.service_name})
                            </span>
                          )}
                        </h3>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 self-end md:self-center">
                      <EvidenceBadge classification={item.classification} confidence={item.is_anti_forensic ? 95 : 90} />
                      <button
                        onClick={() => setSelectedCloudEvent(item)}
                        className="p-1.5 text-slate-400 hover:text-blue-600 rounded-lg hover:bg-blue-50 transition-colors"
                        title="View Raw JSON Payload"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteMutation.mutate(item.id)}
                        className="p-1.5 text-slate-400 hover:text-rose-600 rounded-lg hover:bg-rose-50 transition-colors"
                        title="Delete Record"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs bg-slate-50 p-3.5 rounded-xl border border-slate-200/60 font-medium">
                    <div>
                      <span className="text-slate-400">Caller Identity:</span>
                      <p className="font-mono text-slate-800 truncate mt-0.5">{item.identity_arn || 'N/A'}</p>
                    </div>
                    <div>
                      <span className="text-slate-400">Source IP & Region:</span>
                      <p className="font-mono text-slate-800 truncate mt-0.5">
                        {item.source_ip || 'N/A'} {item.aws_region ? `(${item.aws_region})` : ''}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-400">Forensic Notes:</span>
                      <p className="text-slate-700 truncate mt-0.5">{item.notes || 'Routine operation'}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: ENDPOINT CROSS-CORRELATIONS */}
      {activeTab === 'correlations' && (
        <div className="space-y-4">
          <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm flex items-center justify-between">
            <div className="flex items-center gap-3">
              <CloudLightning className="w-5 h-5 text-blue-600" />
              <div>
                <h3 className="text-sm font-bold text-slate-900">Endpoint Memory to Cloud API Attributions</h3>
                <p className="text-xs text-slate-500 font-medium">
                  Connects local Volatility process execution (e.g. aws.exe, powershell.exe) with remote CloudTrail audit actions.
                </p>
              </div>
            </div>

            <button
              onClick={() => correlateMutation.mutate()}
              disabled={correlateMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-50 text-blue-700 hover:bg-blue-100 rounded-xl text-xs font-bold transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${correlateMutation.isPending ? 'animate-spin' : ''}`} />
              <span>Re-run Correlation</span>
            </button>
          </div>

          {isLoadingCorrelations ? (
            <div className="bg-white rounded-2xl p-12 text-center border border-slate-200/80 shadow-sm">
              <RefreshCw className="w-6 h-6 animate-spin text-slate-400 mx-auto mb-2" />
              <p className="text-xs text-slate-500 font-medium">Computing endpoint-to-cloud correlations...</p>
            </div>
          ) : correlations.length === 0 ? (
            <div className="bg-white rounded-2xl p-12 text-center border border-slate-200/80 shadow-sm space-y-3">
              <CloudLightning className="w-10 h-10 text-slate-400 mx-auto" />
              <h3 className="text-sm font-bold text-slate-800">No Cross-Correlations Generated Yet</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                Click "Correlate with Endpoint" above to cross-reference local memory processes, network sockets, and command histories against ingested cloud events.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {correlations.map((corr) => (
                <div
                  key={corr.id}
                  className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm hover:border-slate-300 transition-all space-y-4"
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-md text-[10px] font-bold bg-indigo-100 text-indigo-800 border border-indigo-200 uppercase tracking-wider">
                        {corr.correlation_type}
                      </span>
                      <span className="text-xs text-slate-400">•</span>
                      <span className="text-xs font-semibold text-slate-500">
                        Delta: {corr.time_delta_seconds}s
                      </span>
                    </div>

                    <EvidenceBadge classification={corr.classification} confidence={Math.round(corr.confidence * 100)} />
                  </div>

                  {/* Flow Diagram */}
                  <div className="grid grid-cols-1 md:grid-cols-5 gap-3 items-center text-xs">
                    <div className="md:col-span-2 bg-slate-50 p-4 rounded-xl border border-slate-200/80 space-y-1">
                      <div className="flex items-center gap-1.5 font-bold text-slate-800">
                        <Terminal className="w-3.5 h-3.5 text-blue-600" />
                        <span>Local Endpoint Artifact</span>
                      </div>
                      <p className="font-mono text-slate-700 text-[11px] truncate">{corr.local_artifact_desc}</p>
                      <p className="text-[10px] text-slate-400">
                        Time: {corr.local_timestamp ? new Date(corr.local_timestamp).toLocaleTimeString() : 'N/A'}
                      </p>
                    </div>

                    <div className="flex flex-col items-center justify-center text-center">
                      <span className="text-[10px] font-bold text-slate-400">Δt = {corr.time_delta_seconds}s</span>
                      <ArrowRight className="w-5 h-5 text-blue-600 my-1 hidden md:block" />
                      <span className="text-[10px] font-semibold text-blue-600 bg-blue-50 px-2 py-0.5 rounded-full">
                        {Math.round(corr.confidence * 100)}% Match
                      </span>
                    </div>

                    <div className="md:col-span-2 bg-blue-50/50 p-4 rounded-xl border border-blue-100 space-y-1">
                      <div className="flex items-center gap-1.5 font-bold text-blue-900">
                        <Cloud className="w-3.5 h-3.5 text-blue-600" />
                        <span>Remote Cloud Event</span>
                      </div>
                      <p className="font-mono text-blue-800 text-[11px] truncate">
                        Cloud Timestamp: {new Date(corr.cloud_timestamp).toLocaleTimeString()}
                      </p>
                      <p className="text-[10px] text-blue-600">Cross-verified against CloudTrail / Azure</p>
                    </div>
                  </div>

                  <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200/60 text-xs">
                    <span className="font-bold text-slate-700">Forensic Correlation Rationale: </span>
                    <span className="text-slate-600">{corr.rationale}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Ingestion Modal */}
      {showIngestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm animate-fadeIn">
          <div className="bg-white rounded-2xl max-w-2xl w-full p-6 shadow-2xl border border-slate-200 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <UploadCloud className="w-5 h-5 text-blue-600" />
                <h3 className="text-base font-bold text-slate-900">Ingest Cloud Service Provider Audit Logs</h3>
              </div>
              <button
                onClick={() => setShowIngestModal(false)}
                className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 text-xs font-bold"
              >
                ✕
              </button>
            </div>

            {/* Presets */}
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200 space-y-2">
              <span className="text-[11px] font-bold text-slate-600 block">Demonstration Presets:</span>
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  type="button"
                  onClick={() => {
                    setIngestProvider('AWS');
                    setIngestPayloadText(JSON.stringify(AWS_BREACH_SAMPLE, null, 2));
                  }}
                  className="px-3 py-1 bg-white hover:bg-blue-50 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700 hover:text-blue-600 transition-colors"
                >
                  ⚡ AWS CloudTrail Breach (StopLogging, DeleteBucket)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setIngestProvider('Azure');
                    setIngestPayloadText(JSON.stringify(AZURE_BREACH_SAMPLE, null, 2));
                  }}
                  className="px-3 py-1 bg-white hover:bg-blue-50 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700 hover:text-blue-600 transition-colors"
                >
                  ⚡ Azure Activity Log (Diagnostic Evasion)
                </button>
              </div>
            </div>

            <form onSubmit={handleIngestSubmit} className="space-y-4">
              <div className="flex items-center gap-4 text-xs font-semibold">
                <span className="text-slate-700">Target Provider:</span>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="provider"
                    value="AWS"
                    checked={ingestProvider === 'AWS'}
                    onChange={() => setIngestProvider('AWS')}
                    className="text-blue-600"
                  />
                  <span>AWS CloudTrail</span>
                </label>
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="radio"
                    name="provider"
                    value="Azure"
                    checked={ingestProvider === 'Azure'}
                    onChange={() => setIngestProvider('Azure')}
                    className="text-blue-600"
                  />
                  <span>Azure Activity Log</span>
                </label>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Raw Audit Log JSON Payload:
                </label>
                <textarea
                  rows={8}
                  value={ingestPayloadText}
                  onChange={(e) => setIngestPayloadText(e.target.value)}
                  placeholder='Paste {"Records": [...]} or raw JSON array here...'
                  className="w-full p-3 font-mono text-xs bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-1 focus:ring-blue-500 transition-all leading-relaxed"
                  required
                />
              </div>

              {ingestError && (
                <div className="p-3 bg-rose-50 border border-rose-200 text-rose-800 rounded-xl text-xs font-medium">
                  {ingestError}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setShowIngestModal(false)}
                  className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={ingestMutation.isPending || !ingestPayloadText.trim()}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white rounded-xl text-xs font-bold shadow-sm"
                >
                  {ingestMutation.isPending ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <UploadCloud className="w-4 h-4" />
                  )}
                  <span>{ingestMutation.isPending ? 'Ingesting...' : 'Ingest Records'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Raw JSON Payload Modal */}
      {selectedCloudEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm animate-fadeIn">
          <div className="bg-white rounded-2xl max-w-2xl w-full p-6 shadow-2xl border border-slate-200 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-slate-700 border">
                    {selectedCloudEvent.provider}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${getSeverityBadge(selectedCloudEvent.severity)}`}>
                    {selectedCloudEvent.severity}
                  </span>
                </div>
                <h3 className="text-base font-bold text-slate-900 mt-1">
                  {selectedCloudEvent.event_name}
                </h3>
              </div>
              <button
                onClick={() => setSelectedCloudEvent(null)}
                className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 text-xs font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-2">
              <span className="text-xs font-bold text-slate-700 block">Raw Cloud Payload JSON:</span>
              <pre className="bg-slate-950 text-slate-200 p-4 rounded-xl text-[11px] font-mono overflow-auto max-h-80 leading-relaxed">
                {JSON.stringify(selectedCloudEvent.raw_payload, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button
                onClick={() => setSelectedCloudEvent(null)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold"
              >
                Close Viewer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
