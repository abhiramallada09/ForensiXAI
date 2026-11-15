import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Clock,
  RefreshCw,
  Play,
  CheckCircle2,
  FolderArchive,
  Calendar,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Timer,
  Trash2,
  Sliders,
} from 'lucide-react';
import {
  fetchTimestampWindows,
  runTimestampReconstruction,
  deleteTimestampWindow,
} from '../api/client';
import { EvidenceBadge } from '../components/common/EvidenceBadge';
import { useCase } from '../context/CaseContext';
import { TimestampReconstructionItem } from '../types/forensics';

export const TimestampReconstructionPage: React.FC = () => {
  const queryClient = useQueryClient();
  const { activeCase, allCases } = useCase();

  const [selectedCaseId, setSelectedCaseId] = useState<string>(activeCase ? activeCase.id : '');
  const [windowThreshold, setWindowThreshold] = useState<number>(120);
  const [filterConsistency, setFilterConsistency] = useState<string>('All');
  const [selectedWindow, setSelectedWindow] = useState<TimestampReconstructionItem | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  React.useEffect(() => {
    if (activeCase && !selectedCaseId) {
      setSelectedCaseId(activeCase.id);
    }
  }, [activeCase, selectedCaseId]);

  // Query timestamp windows for selected case
  const {
    data: summaryData,
    isLoading,
  } = useQuery({
    queryKey: ['timestamp-windows', selectedCaseId],
    queryFn: () => fetchTimestampWindows(selectedCaseId),
    enabled: !!selectedCaseId,
  });

  // Mutation to run timestamp reconstruction
  const reconstructMutation = useMutation({
    mutationFn: () => runTimestampReconstruction(selectedCaseId, windowThreshold),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['timestamp-windows', selectedCaseId] });
      setActionSuccess(`Timestamp reconstruction complete! Evaluated ${data.total_windows_evaluated} event window(s).`);
      setTimeout(() => setActionSuccess(null), 5000);
    },
  });

  // Mutation to delete a window
  const deleteMutation = useMutation({
    mutationFn: (recordId: string) => deleteTimestampWindow(selectedCaseId, recordId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['timestamp-windows', selectedCaseId] });
      if (selectedWindow) setSelectedWindow(null);
    },
  });

  const windows = summaryData?.reconstructed_windows || [];

  const filteredWindows = windows.filter((item) => {
    if (filterConsistency === 'All') return true;
    return item.consistency_status === filterConsistency;
  });

  const formatIsoTime = (isoString?: string) => {
    if (!isoString) return '--:--:--';
    try {
      const dt = new Date(isoString);
      return dt.toLocaleTimeString('en-US', { hour12: false, timeZone: 'UTC' }) + ' UTC';
    } catch {
      return isoString;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded-md bg-blue-100 text-blue-800 text-[11px] font-bold uppercase tracking-wider">
              Temporal Reconstruction
            </span>
            <span className="text-xs text-slate-400 font-medium">
              • Multi-Source Timestamp Reconstruction & Probable Event Windows
            </span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Clock className="w-5 h-5 text-blue-600" />
            <span>Timestamp Reconstruction & Event Windows</span>
          </h2>
          <p className="text-xs text-slate-500 font-medium mt-1">
            Compares File MACB, Volatility Process CreateTime, Network Sockets, and Security Logs to establish probable event windows.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-50 border border-slate-200 rounded-xl px-3 py-1.5 text-xs">
            <Sliders className="w-3.5 h-3.5 text-slate-500" />
            <span className="font-semibold text-slate-600">Threshold:</span>
            <select
              value={windowThreshold}
              onChange={(e) => setWindowThreshold(Number(e.target.value))}
              className="bg-transparent font-bold text-blue-600 focus:outline-none"
            >
              <option value={30}>30s Window</option>
              <option value={60}>60s Window</option>
              <option value={120}>120s Window</option>
              <option value={300}>300s Window</option>
            </select>
          </div>

          <button
            onClick={() => reconstructMutation.mutate()}
            disabled={reconstructMutation.isPending || !selectedCaseId}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-blue-600/20"
          >
            {reconstructMutation.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-current" />
            )}
            <span>{reconstructMutation.isPending ? 'Calculating Windows...' : 'Reconstruct Windows'}</span>
          </button>
        </div>
      </div>

      {actionSuccess && (
        <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3 text-xs font-semibold text-emerald-800 flex items-center gap-2 animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Forensic Safety Notice */}
      <div className="bg-blue-50/70 border border-blue-200/80 rounded-xl p-4 text-xs text-blue-900 flex items-start gap-3">
        <Timer className="w-4 h-4 text-blue-600 mt-0.5 shrink-0" />
        <div className="space-y-1">
          <strong className="font-bold">Forensic Safety Rule Notice (Timestamp Correlation):</strong>
          <p className="text-blue-800 leading-relaxed text-[11px]">
            The system determines a <em>probable event time window</em> through multi-source correlation (e.g. 10:03:18–10:03:27 UTC). The engine never claims an exact original timestamp unless directly recorded by a synchronized clock source.
          </p>
        </div>
      </div>

      {/* 4 Telemetry Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-5 rounded-2xl border border-slate-200/80 shadow-sm flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center shrink-0">
            <Calendar className="w-6 h-6" />
          </div>
          <div>
            <span className="text-[11px] font-bold text-slate-400 uppercase">Windows Evaluated</span>
            <p className="text-2xl font-black text-slate-900">{summaryData?.total_windows_evaluated ?? 0}</p>
          </div>
        </div>

        <div className="bg-white p-5 rounded-2xl border border-slate-200/80 shadow-sm flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-50 text-emerald-600 flex items-center justify-center shrink-0">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <span className="text-[11px] font-bold text-slate-400 uppercase">Consistent Sequences</span>
            <p className="text-2xl font-black text-emerald-600">{summaryData?.consistent_count ?? 0}</p>
          </div>
        </div>

        <div className="bg-white p-5 rounded-2xl border border-slate-200/80 shadow-sm flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <span className="text-[11px] font-bold text-slate-400 uppercase">Inconsistent / Anomalies</span>
            <p className="text-2xl font-black text-amber-600">{summaryData?.inconsistent_count ?? 0}</p>
          </div>
        </div>

        <div className="bg-white p-5 rounded-2xl border border-slate-200/80 shadow-sm flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-indigo-50 text-indigo-600 flex items-center justify-center shrink-0">
            <Timer className="w-6 h-6" />
          </div>
          <div>
            <span className="text-[11px] font-bold text-slate-400 uppercase">Average Confidence</span>
            <p className="text-2xl font-black text-indigo-600">
              {summaryData ? `${(summaryData.average_confidence * 100).toFixed(0)}%` : '85%'}
            </p>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm space-y-6">
        {/* Controls */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <FolderArchive className="w-4 h-4 text-slate-400" />
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700"
            >
              {allCases?.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.case_number} - {c.name}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-medium">Filter Status:</span>
            <select
              value={filterConsistency}
              onChange={(e) => setFilterConsistency(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs font-semibold text-slate-700"
            >
              <option value="All">All Sequences</option>
              <option value="CONSISTENT">CONSISTENT Only</option>
              <option value="INCONSISTENT">INCONSISTENT (Timestomped)</option>
              <option value="MISSING">MISSING Step Traces</option>
            </select>
          </div>
        </div>

        {/* Windows Cards Grid */}
        {isLoading ? (
          <div className="py-12 text-center text-slate-400 text-xs">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-slate-400" />
            Reconstructing multi-source timestamp intervals...
          </div>
        ) : filteredWindows.length > 0 ? (
          <div className="space-y-4">
            {filteredWindows.map((win) => (
              <div
                key={win.id}
                className="p-5 rounded-2xl border border-slate-200/70 hover:border-blue-300/80 bg-slate-50/50 hover:bg-white transition-all space-y-4 shadow-xs"
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200/60 pb-3">
                  <div className="flex items-center gap-2.5">
                    <div
                      className={`w-3 h-3 rounded-full ${
                        win.consistency_status === 'CONSISTENT'
                          ? 'bg-emerald-500'
                          : win.consistency_status === 'INCONSISTENT'
                          ? 'bg-rose-500 animate-pulse'
                          : 'bg-amber-500'
                      }`}
                    />
                    <h4 className="font-bold text-slate-900 text-sm">{win.event_title}</h4>
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider ${
                        win.consistency_status === 'CONSISTENT'
                          ? 'bg-emerald-100 text-emerald-800'
                          : win.consistency_status === 'INCONSISTENT'
                          ? 'bg-rose-100 text-rose-800'
                          : 'bg-amber-100 text-amber-800'
                      }`}
                    >
                      {win.consistency_status}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <EvidenceBadge classification={win.classification} />
                    <span className="font-mono text-xs font-bold text-slate-600 bg-white px-2 py-0.5 rounded-lg border border-slate-200">
                      {(win.confidence * 100).toFixed(0)}% Conf
                    </span>
                  </div>
                </div>

                {/* Timeline Window Visualizer Bar */}
                <div className="space-y-2">
                  <div className="flex justify-between items-center text-[11px] font-mono text-slate-500">
                    <span>Window Start: <strong className="text-slate-800">{formatIsoTime(win.probable_window_start)}</strong></span>
                    <span className="font-bold text-blue-600">Span: {win.window_duration_seconds.toFixed(1)}s</span>
                    <span>Window End: <strong className="text-slate-800">{formatIsoTime(win.probable_window_end)}</strong></span>
                  </div>

                  {/* Visual Bar with Multi-Source Ticks */}
                  <div className="relative w-full h-7 bg-slate-200/70 rounded-xl overflow-hidden flex items-center px-4">
                    <div
                      className={`absolute inset-0 opacity-20 ${
                        win.consistency_status === 'CONSISTENT' ? 'bg-emerald-500' : 'bg-rose-500'
                      }`}
                    />
                    <div className="relative w-full flex items-center justify-between">
                      {win.sources_compared.map((src, i) => (
                        <div
                          key={i}
                          className="flex flex-col items-center group relative cursor-pointer"
                          title={`${src.source}: ${src.formatted_time || ''}`}
                        >
                          <div className="w-3 h-3 rounded-full bg-blue-600 border-2 border-white shadow-sm group-hover:scale-125 transition-transform" />
                          <span className="text-[9px] font-mono font-bold text-slate-600 mt-0.5">
                            {src.formatted_time?.split(' ')[0] || ''}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Scientific Provenance Summary */}
                <p className="text-xs text-slate-600 bg-white p-3 rounded-xl border border-slate-200/60 leading-relaxed">
                  {win.reconstruction_reason}
                </p>

                {/* Footer action */}
                <div className="flex justify-between items-center pt-1 text-xs">
                  <span className="text-slate-400 font-medium text-[11px]">
                    Observed Anchor: {formatIsoTime(win.observed_timestamp)} ({win.sources_compared.length} Sources Compared)
                  </span>

                  <button
                    onClick={() => setSelectedWindow(win)}
                    className="px-3 py-1.5 bg-blue-50 hover:bg-blue-100 text-blue-700 rounded-xl text-xs font-bold transition-colors flex items-center gap-1"
                  >
                    <span>Examine Multi-Source Traces</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-12 text-center text-slate-400 text-xs">
            No reconstructed timestamp windows found. Click "Reconstruct Windows" above to analyze events.
          </div>
        )}
      </div>

      {/* Drill-down Modal */}
      {selectedWindow && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4">
          <div className="bg-white rounded-2xl max-w-2xl w-full p-6 shadow-xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <Clock className="w-5 h-5 text-blue-600" />
                <h3 className="font-bold text-slate-900 text-base">{selectedWindow.event_title}</h3>
              </div>
              <EvidenceBadge classification={selectedWindow.classification} />
            </div>

            <div className="grid grid-cols-2 gap-4 text-xs">
              <div className="p-3 bg-slate-50 rounded-xl space-y-1">
                <span className="text-slate-400 font-medium">Consistency Diagnostics</span>
                <p className="font-bold text-slate-800">{selectedWindow.consistency_status}</p>
              </div>
              <div className="p-3 bg-slate-50 rounded-xl space-y-1">
                <span className="text-slate-400 font-medium">Probable Event Window</span>
                <p className="font-bold text-blue-600">
                  {formatIsoTime(selectedWindow.probable_window_start)} – {formatIsoTime(selectedWindow.probable_window_end)}
                </p>
              </div>
              <div className="p-3 bg-slate-50 rounded-xl space-y-1 col-span-2">
                <span className="text-slate-400 font-medium">Confidence & Duration</span>
                <p className="font-bold text-slate-800">
                  {(selectedWindow.confidence * 100).toFixed(0)}% calibrated confidence across {selectedWindow.window_duration_seconds.toFixed(1)}s span
                </p>
              </div>
            </div>

            {/* Compared Sources List */}
            <div className="space-y-2 text-xs">
              <span className="font-bold text-slate-700">Multi-Source Timestamps Compared:</span>
              <div className="space-y-2">
                {selectedWindow.sources_compared.map((src, i) => (
                  <div
                    key={i}
                    className="p-3 bg-slate-50 rounded-xl border border-slate-200/60 flex items-center justify-between text-xs"
                  >
                    <div>
                      <p className="font-bold text-slate-900">{src.source}</p>
                      <p className="text-[11px] text-slate-500">{src.description}</p>
                    </div>
                    <span className="font-mono font-bold text-blue-700 bg-blue-50 px-2 py-1 rounded-lg">
                      {src.formatted_time || formatIsoTime(src.timestamp)}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex justify-between items-center pt-3 border-t border-slate-100">
              <button
                onClick={() => deleteMutation.mutate(selectedWindow.id)}
                disabled={deleteMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-50 hover:bg-rose-100 text-rose-700 rounded-xl text-xs font-bold transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Dismiss Window</span>
              </button>

              <button
                onClick={() => setSelectedWindow(null)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
