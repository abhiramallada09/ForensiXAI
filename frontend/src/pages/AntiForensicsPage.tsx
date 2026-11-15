import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Play,
  CheckCircle2,
  FolderArchive,
  AlertTriangle,
  FileWarning,
  Trash2,
  Flame,
  Search,
  Filter,
  Eye,
  Info,
  Clock,
  Terminal,
} from 'lucide-react';
import {
  fetchAntiForensicIndicators,
  runAntiForensicScan,
  deleteAntiForensicIndicator,
} from '../api/client';
import { EvidenceBadge } from '../components/common/EvidenceBadge';
import { useCase } from '../context/CaseContext';
import { AntiForensicIndicatorItem } from '../types/forensics';

export const AntiForensicsPage: React.FC = () => {
  const queryClient = useQueryClient();
  const { activeCase, allCases } = useCase();

  const [selectedCaseId, setSelectedCaseId] = useState<string>(activeCase ? activeCase.id : '');
  const [filterSeverity, setFilterSeverity] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedIndicator, setSelectedIndicator] = useState<AntiForensicIndicatorItem | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  React.useEffect(() => {
    if (activeCase && !selectedCaseId) {
      setSelectedCaseId(activeCase.id);
    }
  }, [activeCase, selectedCaseId]);

  // Query anti-forensic indicators for selected case
  const {
    data: summaryData,
    isLoading,
  } = useQuery({
    queryKey: ['anti-forensic-indicators', selectedCaseId],
    queryFn: () => fetchAntiForensicIndicators(selectedCaseId),
    enabled: !!selectedCaseId,
  });

  // Mutation to run anti-forensic detection scan
  const scanMutation = useMutation({
    mutationFn: () => runAntiForensicScan(selectedCaseId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['anti-forensic-indicators', selectedCaseId] });
      setActionSuccess(`Anti-forensic analysis complete! Detected ${data.total_indicators} manipulation indicator(s).`);
      setTimeout(() => setActionSuccess(null), 5000);
    },
  });

  // Mutation to delete an indicator
  const deleteMutation = useMutation({
    mutationFn: (indicatorId: string) => deleteAntiForensicIndicator(selectedCaseId, indicatorId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['anti-forensic-indicators', selectedCaseId] });
      if (selectedIndicator) setSelectedIndicator(null);
    },
  });

  const indicators = summaryData?.indicators || [];

  const filteredIndicators = indicators.filter((item) => {
    if (filterSeverity !== 'All' && item.severity !== filterSeverity) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = item.title.toLowerCase().includes(q);
      const matchType = item.indicator_type.toLowerCase().includes(q);
      const matchReason = item.reason.toLowerCase().includes(q);
      const matchArtifacts = item.supporting_artifacts.some((a) => a.toLowerCase().includes(q));
      if (!matchTitle && !matchType && !matchReason && !matchArtifacts) return false;
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

  const getIndicatorIcon = (type: string) => {
    const t = type.toLowerCase();
    if (t.includes('timestomp')) return <Clock className="w-5 h-5 text-amber-600" />;
    if (t.includes('log') || t.includes('cleans')) return <Flame className="w-5 h-5 text-rose-600" />;
    if (t.includes('wip') || t.includes('sdelete') || t.includes('shadow')) return <Terminal className="w-5 h-5 text-rose-600" />;
    if (t.includes('extension') || t.includes('spoof')) return <FileWarning className="w-5 h-5 text-purple-600" />;
    if (t.includes('inject')) return <AlertTriangle className="w-5 h-5 text-red-600" />;
    return <ShieldAlert className="w-5 h-5 text-slate-600" />;
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded-md bg-rose-100 text-rose-800 text-[11px] font-bold uppercase tracking-wider">
              Anti-Forensics Engine
            </span>
            <span className="text-xs text-slate-400 font-medium">
              • Multi-Heuristic Anti-Forensic Anomaly Detection
            </span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-600" />
            <span>Anti-Forensic Anomaly & Manipulation Detection</span>
          </h2>
          <p className="text-xs text-slate-500 font-medium mt-1">
            Scans filesystem timestamps, audit logs, command histories, and volatile memory for deliberate evasion, timestomping, and log wiping.
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
            onClick={() => scanMutation.mutate()}
            disabled={!selectedCaseId || scanMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-700 disabled:bg-slate-300 text-white rounded-xl text-xs font-bold transition-all shadow-sm shadow-rose-200"
          >
            {scanMutation.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-white" />
            )}
            <span>{scanMutation.isPending ? 'Analyzing Evidence...' : 'Execute Anti-Forensic Scan'}</span>
          </button>
        </div>
      </div>

      {actionSuccess && (
        <div className="flex items-center gap-3 p-4 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-2xl text-xs font-semibold animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Telemetry Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Total Manipulation Anomalies</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-slate-900">
              {summaryData?.total_indicators ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">indicators flagged</span>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Critical Severity Indicators</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-rose-600">
              {summaryData?.critical_severity_count ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">severe tampering</span>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">High Severity Indicators</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-orange-500">
              {summaryData?.high_severity_count ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">elevated concern</span>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Avg Anomaly Confidence</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-indigo-600">
              {summaryData ? `${Math.round(summaryData.average_confidence * 100)}%` : '--'}
            </span>
            <span className="text-xs font-semibold text-slate-500">heuristic fidelity</span>
          </div>
        </div>
      </div>

      {/* Forensic Safety & Evidentiary Standard Notice */}
      <div className="bg-amber-50/80 border border-amber-200/80 rounded-2xl p-4 flex items-start gap-3 text-xs">
        <Info className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
        <div className="text-amber-900 leading-relaxed space-y-1">
          <p className="font-bold">Evidentiary Safety & Admissibility Standard:</p>
          <p className="text-amber-800">
            Anti-forensic heuristics report observable discrepancies as <span className="font-semibold underline">"Possible manipulation detected"</span>. Forensic examiners must corroborate findings with secondary artifacts (e.g., USN Journal, Master File Table, Volume Shadow Copies) before forming legal conclusions.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="text-xs font-bold text-slate-700">Filter Severity:</span>
          {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1 rounded-xl text-xs font-semibold transition-all ${
                filterSeverity === sev
                  ? 'bg-slate-900 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="relative w-full md:w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search anomaly, tool, artifact..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-1 focus:ring-rose-500 transition-all font-medium"
          />
        </div>
      </div>

      {/* Main Content / Indicator List */}
      <div className="space-y-4">
        {isLoading ? (
          <div className="bg-white rounded-2xl p-12 text-center border border-slate-200/80 shadow-sm">
            <RefreshCw className="w-6 h-6 animate-spin text-slate-400 mx-auto mb-2" />
            <p className="text-xs text-slate-500 font-medium">Loading anti-forensic scan records...</p>
          </div>
        ) : filteredIndicators.length === 0 ? (
          <div className="bg-white rounded-2xl p-12 text-center border border-slate-200/80 shadow-sm space-y-3">
            <ShieldCheck className="w-10 h-10 text-emerald-500 mx-auto" />
            <h3 className="text-sm font-bold text-slate-800">No Anti-Forensic Manipulation Flags Found</h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              No anomalies matching the current filter have been recorded for this case. Click "Execute Anti-Forensic Scan" to analyze collected evidence for timestomping, log wiping, or wiping utilities.
            </p>
          </div>
        ) : (
          filteredIndicators.map((item) => (
            <div
              key={item.id}
              className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm hover:border-slate-300 transition-all space-y-4"
            >
              {/* Card Header */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200/60 shrink-0 mt-0.5">
                    {getIndicatorIcon(item.indicator_type)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold border uppercase tracking-wider ${getSeverityBadge(item.severity)}`}>
                        {item.severity}
                      </span>
                      <span className="text-xs font-semibold text-slate-400">•</span>
                      <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                        {item.indicator_type}
                      </span>
                    </div>
                    <h3 className="text-base font-bold text-slate-900 tracking-tight">
                      {item.title}
                    </h3>
                  </div>
                </div>

                <div className="flex items-center gap-3 self-end md:self-center">
                  <EvidenceBadge classification={item.classification} confidence={Math.round(item.confidence * 100)} />
                  <button
                    onClick={() => setSelectedIndicator(item)}
                    className="p-1.5 text-slate-400 hover:text-blue-600 rounded-lg hover:bg-blue-50 transition-colors"
                    title="Inspect Forensic Details"
                  >
                    <Eye className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => deleteMutation.mutate(item.id)}
                    className="p-1.5 text-slate-400 hover:text-rose-600 rounded-lg hover:bg-rose-50 transition-colors"
                    title="Dismiss Indicator"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Anomaly and Action Split */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="bg-slate-50 p-4 rounded-xl border border-slate-200/60 space-y-1.5">
                  <div className="flex items-center gap-1.5 text-slate-700 font-bold">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                    <span>Observed Anomaly / Tampering Traces</span>
                  </div>
                  <p className="text-slate-600 leading-relaxed font-normal">
                    {item.reason}
                  </p>
                </div>

                <div className="bg-blue-50/50 p-4 rounded-xl border border-blue-100/80 space-y-1.5">
                  <div className="flex items-center gap-1.5 text-blue-900 font-bold">
                    <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
                    <span>Examiner Corroboration Recommendation</span>
                  </div>
                  <p className="text-blue-800 leading-relaxed font-normal">
                    {item.recommendation}
                  </p>
                </div>
              </div>

              {/* Supporting Artifacts */}
              {item.supporting_artifacts && item.supporting_artifacts.length > 0 && (
                <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-slate-100 text-xs">
                  <span className="font-semibold text-slate-400 text-[11px]">Supporting Artifacts:</span>
                  {item.supporting_artifacts.map((art, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-0.5 rounded-lg bg-slate-100 text-slate-700 font-mono text-[11px] border border-slate-200"
                    >
                      {art}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Drill-down Modal */}
      {selectedIndicator && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-sm animate-fadeIn">
          <div className="bg-white rounded-2xl max-w-2xl w-full p-6 shadow-2xl border border-slate-200 space-y-6">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-rose-50 border border-rose-200">
                  {getIndicatorIcon(selectedIndicator.indicator_type)}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wider ${getSeverityBadge(selectedIndicator.severity)}`}>
                      {selectedIndicator.severity}
                    </span>
                    <span className="text-xs text-slate-400">•</span>
                    <span className="text-xs font-bold text-slate-600">
                      {selectedIndicator.indicator_type}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-slate-900 mt-0.5">
                    {selectedIndicator.title}
                  </h3>
                </div>
              </div>
              <button
                onClick={() => setSelectedIndicator(null)}
                className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 text-xs font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-200/60">
                <div>
                  <span className="text-slate-400 font-medium">Indicator ID:</span>
                  <p className="font-mono text-slate-800 mt-0.5 truncate">{selectedIndicator.id}</p>
                </div>
                <div>
                  <span className="text-slate-400 font-medium">Evidence Classification:</span>
                  <div className="mt-0.5">
                    <EvidenceBadge classification={selectedIndicator.classification} confidence={Math.round(selectedIndicator.confidence * 100)} />
                  </div>
                </div>
                <div>
                  <span className="text-slate-400 font-medium">Analyzed Timestamp:</span>
                  <p className="font-mono text-slate-800 mt-0.5">
                    {new Date(selectedIndicator.created_at).toLocaleString()}
                  </p>
                </div>
                <div>
                  <span className="text-slate-400 font-medium">Algorithm Confidence:</span>
                  <p className="font-bold text-slate-800 mt-0.5">
                    {Math.round(selectedIndicator.confidence * 100)}%
                  </p>
                </div>
              </div>

              <div>
                <span className="font-bold text-slate-700 block mb-1">Detailed Forensic Reasoning:</span>
                <p className="text-slate-600 leading-relaxed bg-slate-50 p-3.5 rounded-xl border border-slate-200/60">
                  {selectedIndicator.reason}
                </p>
              </div>

              <div>
                <span className="font-bold text-blue-900 block mb-1">Examiner Recovery Recommendation:</span>
                <p className="text-blue-800 leading-relaxed bg-blue-50/50 p-3.5 rounded-xl border border-blue-100">
                  {selectedIndicator.recommendation}
                </p>
              </div>

              <div>
                <span className="font-bold text-slate-700 block mb-1">Supporting Evidentiary Artifacts:</span>
                <div className="flex flex-wrap gap-2">
                  {selectedIndicator.supporting_artifacts.map((art, idx) => (
                    <span
                      key={idx}
                      className="px-3 py-1 bg-slate-100 border border-slate-200 rounded-lg font-mono text-slate-700 text-[11px]"
                    >
                      {art}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-4 border-t border-slate-100">
              <button
                onClick={() => setSelectedIndicator(null)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition-colors"
              >
                Close Drill-down
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
