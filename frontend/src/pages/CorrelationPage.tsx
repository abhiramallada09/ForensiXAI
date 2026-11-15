import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  GitCompare,
  Play,
  Clock,
  Layers,
  ShieldAlert,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  FolderArchive,
  RefreshCw,
  Sparkles,
  Trash2,
  Sliders,
} from 'lucide-react';
import {
  fetchCaseCorrelations,
  runEvidenceCorrelation,
  fetchCaseFindings,
  deleteFinding,
} from '../api/client';
import { EvidenceBadge } from '../components/common/EvidenceBadge';
import { useCase } from '../context/CaseContext';

const TIME_WINDOWS = [
  { label: '15 sec', value: 15 },
  { label: '30 sec', value: 30 },
  { label: '60 sec', value: 60 },
  { label: '2 min', value: 120 },
  { label: '5 min', value: 300 },
];

export const CorrelationPage: React.FC = () => {
  const queryClient = useQueryClient();
  const { activeCase, allCases } = useCase();

  const [selectedCaseId, setSelectedCaseId] = useState<string>(activeCase ? activeCase.id : '');
  const [timeWindow, setTimeWindow] = useState<number>(60);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Sync selectedCaseId if activeCase changes
  React.useEffect(() => {
    if (activeCase && !selectedCaseId) {
      setSelectedCaseId(activeCase.id);
    }
  }, [activeCase, selectedCaseId]);

  // Query Correlation Report
  const {
    data: correlationReport,
    isLoading: isCorrLoading,
    refetch: refetchCorrelations,
  } = useQuery({
    queryKey: ['case-correlations', selectedCaseId, timeWindow],
    queryFn: () => fetchCaseCorrelations(selectedCaseId, timeWindow),
    enabled: !!selectedCaseId,
  });

  // Query Case Findings
  const {
    data: findings,
    isLoading: isFindingsLoading,
    refetch: refetchFindings,
  } = useQuery({
    queryKey: ['case-findings', selectedCaseId],
    queryFn: () => fetchCaseFindings(selectedCaseId),
    enabled: !!selectedCaseId,
  });

  // Mutation to Run Correlation
  const runMutation = useMutation({
    mutationFn: () =>
      runEvidenceCorrelation(selectedCaseId, {
        time_window_seconds: timeWindow,
        min_cluster_size: 2,
        generate_findings: true,
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['case-correlations', selectedCaseId] });
      queryClient.invalidateQueries({ queryKey: ['case-findings', selectedCaseId] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      queryClient.invalidateQueries({ queryKey: ['timeline'] });
      setActionSuccess(
        `Correlation completed! Generated ${data.findings_generated_count} new findings across ${data.total_clusters} clusters.`
      );
      setTimeout(() => setActionSuccess(null), 5000);
    },
  });

  // Mutation to Delete Finding
  const deleteFindingMutation = useMutation({
    mutationFn: (findingId: string) => deleteFinding(findingId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case-findings', selectedCaseId] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });

  const currentCase = allCases?.find((c) => c.id === selectedCaseId);

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded-md bg-blue-100 text-blue-800 text-[11px] font-bold uppercase tracking-wider">
              Correlation Engine
            </span>
            <span className="text-xs text-slate-400 font-medium">
              • {currentCase ? `${currentCase.case_number}: ${currentCase.name}` : 'Multi-Source Corroboration Engine'}
            </span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <GitCompare className="w-5 h-5 text-blue-600" />
            <span>Multiple Evidence Correlation</span>
          </h2>
          <p className="text-xs text-slate-500 font-medium mt-1">
            Correlate filesystem MACB timestamps, memory execution traces, event logs, and network sockets across temporal clusters.
          </p>
        </div>

        {/* Case Selector and Action Button */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <FolderArchive className="w-4 h-4 text-slate-400" />
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              className="px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="" disabled>
                Select Target Case
              </option>
              {allCases?.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.case_number} — {c.name}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => runMutation.mutate()}
            disabled={!selectedCaseId || runMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-[#1E50FF] hover:bg-blue-600 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-blue-600/20"
          >
            {runMutation.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-current" />
            )}
            <span>{runMutation.isPending ? 'Correlating...' : 'Execute Correlation'}</span>
          </button>
        </div>
      </div>

      {actionSuccess && (
        <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3 text-xs font-semibold text-emerald-800 flex items-center gap-2 animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Temporal Window Filter Bar */}
      <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs font-bold text-slate-700">
          <Sliders className="w-4 h-4 text-blue-600" />
          <span>Sliding Temporal Proximity Window (Δt):</span>
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          {TIME_WINDOWS.map((w) => (
            <button
              key={w.value}
              onClick={() => setTimeWindow(w.value)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${timeWindow === w.value
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
            >
              {w.label}
            </button>
          ))}

          <button
            onClick={() => {
              refetchCorrelations();
              refetchFindings();
            }}
            title="Refresh Analysis"
            className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100 ml-2"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Telemetry Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-bold uppercase tracking-wider">Events In Scope</span>
            <Layers className="w-4 h-4 text-blue-500" />
          </div>
          <p className="text-2xl font-extrabold text-slate-900">
            {correlationReport?.total_events_analyzed ?? 0}
          </p>
          <span className="text-[11px] text-slate-400 font-medium">Timeline events scanned</span>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-bold uppercase tracking-wider">Clusters Found</span>
            <Clock className="w-4 h-4 text-indigo-500" />
          </div>
          <p className="text-2xl font-extrabold text-slate-900">
            {correlationReport?.total_clusters ?? 0}
          </p>
          <span className="text-[11px] text-slate-400 font-medium">Within ±{timeWindow}s windows</span>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-bold uppercase tracking-wider">Multi-Source Chains</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <p className="text-2xl font-extrabold text-emerald-600">
            {correlationReport?.multi_source_correlations_count ?? 0}
          </p>
          <span className="text-[11px] text-slate-400 font-medium">Corroborated across files</span>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-bold uppercase tracking-wider">Forensic Findings</span>
            <ShieldAlert className="w-4 h-4 text-amber-500" />
          </div>
          <p className="text-2xl font-extrabold text-amber-600">
            {findings?.length ?? 0}
          </p>
          <span className="text-[11px] text-slate-400 font-medium">Verified by provenance rule</span>
        </div>
      </div>

      {/* Main Grid: Clusters (Left) & Findings (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Temporal Clusters & Chains */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-600" />
              <span>Temporal Proximity Clusters ({correlationReport?.clusters?.length ?? 0})</span>
            </h3>
            <span className="text-xs text-slate-500">Sorted chronologically</span>
          </div>

          {isCorrLoading ? (
            <div className="bg-white rounded-2xl p-8 border border-slate-200/80 text-center text-slate-400">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-blue-600" />
              <p className="text-xs font-semibold">Correlating evidence timestamps...</p>
            </div>
          ) : !selectedCaseId ? (
            <div className="bg-white rounded-2xl p-8 border border-slate-200/80 text-center text-slate-400">
              <FolderArchive className="w-8 h-8 mx-auto mb-2 text-slate-300" />
              <p className="text-xs font-semibold">Select a case above to inspect correlated clusters.</p>
            </div>
          ) : correlationReport?.clusters?.length === 0 ? (
            <div className="bg-white rounded-2xl p-8 border border-slate-200/80 text-center text-slate-500 space-y-3">
              <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto" />
              <p className="text-xs font-bold text-slate-700">
                No temporal clusters found within ±{timeWindow} seconds.
              </p>
              <p className="text-[11px] text-slate-400 max-w-sm mx-auto">
                Try selecting a wider window (e.g. 2 min or 5 min), or add more evidence files and timeline events to the case.
              </p>
              <Link
                to="/evidence"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-50 text-blue-600 font-bold text-xs hover:bg-blue-100"
              >
                <span>Upload More Evidence</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          ) : (
            <div className="space-y-4">
              {correlationReport?.clusters?.map((cluster) => (
                <div
                  key={cluster.cluster_id}
                  className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm hover:border-blue-300 transition-all space-y-4"
                >
                  {/* Cluster Header */}
                  <div className="flex flex-wrap items-start justify-between gap-2 border-b border-slate-100 pb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-blue-600 bg-blue-50 px-2 py-0.5 rounded-md">
                          {cluster.cluster_id}
                        </span>
                        <EvidenceBadge classification={cluster.cluster_classification} />
                        <span className="text-xs font-bold text-slate-700">
                          {cluster.duration_seconds.toFixed(1)}s span
                        </span>
                      </div>
                      <p className="text-xs text-slate-600 font-medium mt-1">
                        {cluster.summary}
                      </p>
                    </div>

                    <div className="text-right">
                      <div className="text-xs font-extrabold text-slate-900">
                        {Math.round(cluster.confidence * 100)}% Confidence
                      </div>
                      <div className="w-20 bg-slate-100 h-1.5 rounded-full overflow-hidden mt-1">
                        <div
                          className="bg-blue-600 h-full rounded-full"
                          style={{ width: `${cluster.confidence * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  {/* Evidence Sources chips */}
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[11px] font-bold text-slate-400 mr-1">Sources:</span>
                    {cluster.evidence_filenames.map((fname, fidx) => (
                      <span
                        key={fidx}
                        className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded-md text-[11px] font-mono font-medium"
                      >
                        {fname}
                      </span>
                    ))}
                  </div>

                  {/* Event Sequence Chain */}
                  <div className="space-y-2 bg-slate-50/80 rounded-xl p-3 border border-slate-100">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                      Sequential Causality Chain
                    </span>
                    <div className="space-y-2">
                      {cluster.events.map((ev, stepIdx) => (
                        <div
                          key={ev.id}
                          className="flex items-start gap-3 text-xs bg-white p-2.5 rounded-lg border border-slate-200/60"
                        >
                          {/* Step number badge */}
                          <div className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center font-bold text-[10px] shrink-0 mt-0.5">
                            {stepIdx + 1}
                          </div>

                          <div className="flex-1 min-w-0">
                            <div className="flex flex-wrap items-center justify-between gap-1">
                              <span className="font-bold text-slate-900">
                                {ev.event_type}
                              </span>
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-[11px] font-bold text-blue-600">
                                  +{ev.time_delta_seconds.toFixed(1)}s
                                </span>
                                <span className="text-[11px] text-slate-400">
                                  {new Date(ev.timestamp).toLocaleTimeString([], {
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    second: '2-digit',
                                  })}
                                </span>
                              </div>
                            </div>
                            <p className="text-[11px] text-slate-600 mt-0.5 truncate">
                              {ev.description}
                            </p>
                            <div className="flex items-center gap-2 mt-1 text-[10px] text-slate-400 font-mono">
                              <span>{ev.timestamp_source}</span>
                              {ev.evidence_filename && (
                                <>
                                  <span>•</span>
                                  <span className="text-slate-500 font-medium">
                                    {ev.evidence_filename}
                                  </span>
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Key Forensic Findings */}
        <div className="lg:col-span-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-500" />
              <span>Key Forensic Findings ({findings?.length ?? 0})</span>
            </h3>
            <span className="text-xs text-slate-500">With AI explanations</span>
          </div>

          {isFindingsLoading ? (
            <div className="bg-white rounded-2xl p-8 border border-slate-200/80 text-center text-slate-400">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-blue-600" />
              <p className="text-xs font-semibold">Loading findings...</p>
            </div>
          ) : !findings || findings.length === 0 ? (
            <div className="bg-white rounded-2xl p-8 border border-slate-200/80 text-center text-slate-500 space-y-3">
              <ShieldAlert className="w-8 h-8 text-slate-300 mx-auto" />
              <p className="text-xs font-bold text-slate-700">No findings registered yet.</p>
              <p className="text-[11px] text-slate-400">
                Click "Execute Correlation" to automatically synthesize corroborated findings from multi-source clusters.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {findings.map((f) => (
                <div
                  key={f.id}
                  className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm space-y-3"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${f.severity === 'High' || f.severity === 'Critical'
                              ? 'bg-rose-100 text-rose-800'
                              : f.severity === 'Medium'
                                ? 'bg-amber-100 text-amber-800'
                                : 'bg-slate-100 text-slate-700'
                            }`}
                        >
                          {f.severity} Severity
                        </span>
                        <EvidenceBadge classification={f.classification} />
                      </div>
                      <h4 className="text-xs font-bold text-slate-900 mt-1.5 leading-snug">
                        {f.title}
                      </h4>
                    </div>

                    <button
                      onClick={() => deleteFindingMutation.mutate(f.id)}
                      title="Discard finding"
                      className="text-slate-300 hover:text-rose-500 p-1 rounded transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  {/* Confidence Bar */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-slate-500 font-medium">Confidence Score</span>
                      <span className="font-mono font-bold text-slate-900">
                        {Math.round(f.confidence * 100)}%
                      </span>
                    </div>
                    <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                      <div
                        className="bg-blue-600 h-full rounded-full"
                        style={{ width: `${f.confidence * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Reason & Explanation */}
                  <div className="text-xs text-slate-600 space-y-1 bg-slate-50 p-2.5 rounded-xl border border-slate-100">
                    <p className="font-medium">{f.reason}</p>
                    {f.explanation && (
                      <p className="text-[11px] text-slate-400 italic mt-1">
                        {f.explanation}
                      </p>
                    )}
                  </div>

                  {/* Supporting Artifacts */}
                  {f.supporting_artifacts && f.supporting_artifacts.length > 0 && (
                    <div>
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                        Supporting Evidence Artifacts ({f.supporting_artifacts.length}):
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {f.supporting_artifacts.map((art: any, aidx: number) => (
                          <span
                            key={aidx}
                            className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded text-[10px] font-mono"
                          >
                            {art.event_type || 'Event'} (Δt={art.delta_s ?? 0}s)
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommendation */}
                  {f.recommendation && (
                    <div className="p-2.5 rounded-xl bg-amber-50/80 border border-amber-200/60 text-[11px] text-amber-900">
                      <span className="font-bold">Recommendation: </span>
                      <span>{f.recommendation}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
