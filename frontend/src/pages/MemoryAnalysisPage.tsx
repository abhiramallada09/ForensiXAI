import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Cpu,
  Terminal,
  Play,
  RefreshCw,
  FolderArchive,
  Layers,
  Wifi,
  ShieldAlert,
  Search,
  CheckCircle2,
  ArrowRight,
  GitCompare,
  FileCode,
  Copy,
  Check,
} from 'lucide-react';
import {
  fetchEvidenceList,
  runMemoryAnalysis,
  fetchLatestMemoryAnalysis,
} from '../api/client';
import { useCase } from '../context/CaseContext';

const AVAILABLE_PLUGINS = [
  { id: 'windows.pslist', name: 'windows.pslist', desc: 'Process tree & active task enumeration' },
  { id: 'windows.netscan', name: 'windows.netscan', desc: 'Active & closed TCP/UDP socket reconstruction' },
  { id: 'windows.malfind', name: 'windows.malfind', desc: 'Shellcode injection & RWX VAD protection scan' },
  { id: 'windows.cmdline', name: 'windows.cmdline', desc: 'Process command line launch parameters' },
  { id: 'windows.handles', name: 'windows.handles', desc: 'Kernel mutexes, file handles, and named pipes' },
];

export const MemoryAnalysisPage: React.FC = () => {
  const queryClient = useQueryClient();
  const { activeCase, allCases } = useCase();

  const [selectedCaseId, setSelectedCaseId] = useState<string>(activeCase ? activeCase.id : '');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string>('');
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([
    'windows.pslist',
    'windows.netscan',
    'windows.malfind',
    'windows.cmdline',
    'windows.handles',
  ]);
  const [syncTimeline, setSyncTimeline] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'processes' | 'network' | 'injections' | 'cmdline' | 'handles' | 'raw'>('processes');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [copiedLog, setCopiedLog] = useState<boolean>(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Sync selectedCaseId
  React.useEffect(() => {
    if (activeCase && !selectedCaseId) {
      setSelectedCaseId(activeCase.id);
    }
  }, [activeCase, selectedCaseId]);

  // Query evidence files for selected case
  const { data: evidenceItems } = useQuery({
    queryKey: ['case-evidence', selectedCaseId],
    queryFn: () => fetchEvidenceList(selectedCaseId),
    enabled: !!selectedCaseId,
  });

  // Auto-select first memory image or first evidence item
  React.useEffect(() => {
    if (evidenceItems && evidenceItems.length > 0 && !selectedEvidenceId) {
      const memImg = evidenceItems.find(
        (e) => e.file_type === 'Memory Image' || e.filename.toLowerCase().endsWith('.raw') || e.filename.toLowerCase().endsWith('.mem')
      );
      setSelectedEvidenceId(memImg ? memImg.id : evidenceItems[0].id);
    }
  }, [evidenceItems, selectedEvidenceId]);

  // Query latest memory analysis
  const {
    data: analysisData,
    isLoading: isAnalysisLoading,
  } = useQuery({
    queryKey: ['latest-memory-analysis', selectedCaseId, selectedEvidenceId],
    queryFn: () => fetchLatestMemoryAnalysis(selectedCaseId, selectedEvidenceId || undefined),
    enabled: !!selectedCaseId,
  });

  // Mutation to Run Memory Analysis
  const runMutation = useMutation({
    mutationFn: () =>
      runMemoryAnalysis(selectedCaseId, {
        evidence_id: selectedEvidenceId,
        plugins: selectedPlugins,
        sync_timeline: syncTimeline,
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['latest-memory-analysis', selectedCaseId] });
      queryClient.invalidateQueries({ queryKey: ['timeline'] });
      queryClient.invalidateQueries({ queryKey: ['case-findings'] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      setActionSuccess(
        `Volatility 3 analysis completed! Extracted ${data.processes.length} processes, ${data.network_connections.length} sockets, and ${data.injected_regions.length} injected regions.`
      );
      setTimeout(() => setActionSuccess(null), 5000);
    },
  });

  const togglePlugin = (pluginId: string) => {
    if (selectedPlugins.includes(pluginId)) {
      if (selectedPlugins.length > 1) {
        setSelectedPlugins(selectedPlugins.filter((p) => p !== pluginId));
      }
    } else {
      setSelectedPlugins([...selectedPlugins, pluginId]);
    }
  };

  const handleCopyLogs = () => {
    if (analysisData?.raw_output) {
      navigator.clipboard.writeText(analysisData.raw_output);
      setCopiedLog(true);
      setTimeout(() => setCopiedLog(false), 2000);
    }
  };

  const filteredProcesses = (analysisData?.processes || []).filter(
    (p) =>
      p.image_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.pid.toString().includes(searchTerm) ||
      p.status.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded-md bg-blue-100 text-blue-800 text-[11px] font-bold uppercase tracking-wider">
              Memory Forensics Engine
            </span>
            <span className="text-xs text-slate-400 font-medium">• Volatility 3 Kernel Memory Framework</span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <Cpu className="w-5 h-5 text-blue-600" />
            <span>Volatility 3 Memory Forensics</span>
          </h2>
          <p className="text-xs text-slate-500 font-medium mt-1">
            Extract volatile artifacts from kernel memory: process lists, DLL injections, active TCP/UDP sockets, handles, and process command-lines.
          </p>
        </div>

        {/* Global Case Selector */}
        <div className="flex items-center gap-2">
          <FolderArchive className="w-4 h-4 text-slate-400" />
          <select
            value={selectedCaseId}
            onChange={(e) => {
              setSelectedCaseId(e.target.value);
              setSelectedEvidenceId('');
            }}
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
      </div>

      {actionSuccess && (
        <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-3 text-xs font-semibold text-emerald-800 flex items-center gap-2 animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Main Analysis Execution & Configuration Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Volatility 3 Controls */}
        <div className="lg:col-span-4 bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4 text-blue-600" />
              <span>Plugin Execution Controls</span>
            </h3>
            <span className="text-[10px] font-mono text-slate-400">volatility3 v2.28.2</span>
          </div>

          {/* Evidence Picker */}
          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1.5">
              Target Memory Dump
            </label>
            {evidenceItems && evidenceItems.length > 0 ? (
              <select
                value={selectedEvidenceId}
                onChange={(e) => setSelectedEvidenceId(e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-semibold text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                {evidenceItems.map((evi) => (
                  <option key={evi.id} value={evi.id}>
                    {evi.filename} ({evi.readable_size || `${evi.file_size_bytes} B`}) [{evi.file_type}]
                  </option>
                ))}
              </select>
            ) : (
              <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-800 space-y-2">
                <p className="font-semibold">No evidence files found in this case.</p>
                <Link
                  to="/evidence"
                  className="inline-flex items-center gap-1 font-bold text-blue-600 hover:text-blue-800"
                >
                  <span>Upload memory image or file</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            )}
          </div>

          {/* Plugins List */}
          <div>
            <label className="block text-xs font-bold text-slate-700 mb-2">
              Core Volatility 3 Plugins
            </label>
            <div className="space-y-2">
              {AVAILABLE_PLUGINS.map((plug) => {
                const isSelected = selectedPlugins.includes(plug.id);
                return (
                  <label
                    key={plug.id}
                    onClick={() => togglePlugin(plug.id)}
                    className={`flex items-start gap-2.5 p-2 rounded-xl border text-xs cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-blue-50/70 border-blue-200 text-blue-900'
                        : 'bg-slate-50/50 border-slate-200 text-slate-600 hover:bg-slate-50'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => {}} // Controlled by label click
                      className="rounded text-blue-600 mt-0.5"
                    />
                    <div>
                      <p className="font-mono font-bold text-[11px]">{plug.name}</p>
                      <p className="text-[10px] text-slate-500">{plug.desc}</p>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Timeline Sync Checkbox */}
          <label className="flex items-center gap-2 text-xs font-semibold text-slate-700 pt-1 cursor-pointer">
            <input
              type="checkbox"
              checked={syncTimeline}
              onChange={(e) => setSyncTimeline(e.target.checked)}
              className="rounded text-blue-600"
            />
            <span>Auto-sync extracted events into Timeline</span>
          </label>

          {/* Execution Button */}
          <button
            onClick={() => runMutation.mutate()}
            disabled={!selectedEvidenceId || runMutation.isPending}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-[#1E50FF] hover:bg-blue-600 active:scale-[0.98] disabled:opacity-50 text-white text-xs font-bold transition-all shadow-md shadow-blue-600/30"
          >
            {runMutation.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4 fill-current" />
            )}
            <span>{runMutation.isPending ? 'Executing Volatility 3...' : 'Execute Volatility Analysis'}</span>
          </button>

          {/* Quick link to Multi-Evidence Correlation */}
          <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs">
            <span className="text-slate-400">Next Forensic Phase:</span>
            <Link
              to="/correlation"
              className="inline-flex items-center gap-1 font-bold text-blue-600 hover:text-blue-800"
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>Correlate Memory Events</span>
            </Link>
          </div>
        </div>

        {/* Right Column: Telemetry Cards & Results Workbench */}
        <div className="lg:col-span-8 space-y-5">
          {/* Telemetry Stats Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                Active Processes
              </span>
              <p className="text-xl font-extrabold text-slate-900">
                {analysisData?.processes?.length ?? 0}
              </p>
              <span className="text-[10px] text-slate-400 font-medium">Enumerated via pslist</span>
            </div>

            <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                Network Sockets
              </span>
              <p className="text-xl font-extrabold text-blue-600">
                {analysisData?.network_connections?.length ?? 0}
              </p>
              <span className="text-[10px] text-slate-400 font-medium">TCP/UDP endpoints</span>
            </div>

            <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                Code Injections
              </span>
              <p className="text-xl font-extrabold text-rose-600">
                {analysisData?.injected_regions?.length ?? 0}
              </p>
              <span className="text-[10px] text-slate-400 font-medium">RWX shellcode alerts</span>
            </div>

            <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                Handles / Mutexes
              </span>
              <p className="text-xl font-extrabold text-indigo-600">
                {analysisData?.handles?.length ?? 0}
              </p>
              <span className="text-[10px] text-slate-400 font-medium">Reconstructed handles</span>
            </div>
          </div>

          {/* Tabs Header */}
          <div className="bg-white rounded-2xl p-2 border border-slate-200/80 shadow-sm flex items-center gap-1 overflow-x-auto">
            <button
              onClick={() => setActiveTab('processes')}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all shrink-0 flex items-center gap-1.5 ${
                activeTab === 'processes'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Processes ({analysisData?.processes?.length ?? 0})</span>
            </button>

            <button
              onClick={() => setActiveTab('network')}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all shrink-0 flex items-center gap-1.5 ${
                activeTab === 'network'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              <Wifi className="w-3.5 h-3.5" />
              <span>Network ({analysisData?.network_connections?.length ?? 0})</span>
            </button>

            <button
              onClick={() => setActiveTab('injections')}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all shrink-0 flex items-center gap-1.5 ${
                activeTab === 'injections'
                  ? 'bg-rose-600 text-white shadow-sm'
                  : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Injections ({analysisData?.injected_regions?.length ?? 0})</span>
            </button>

            <button
              onClick={() => setActiveTab('cmdline')}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all shrink-0 flex items-center gap-1.5 ${
                activeTab === 'cmdline'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Command Lines ({analysisData?.cmdlines?.length ?? 0})</span>
            </button>

            <button
              onClick={() => setActiveTab('handles')}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all shrink-0 flex items-center gap-1.5 ${
                activeTab === 'handles'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Handles ({analysisData?.handles?.length ?? 0})</span>
            </button>

            <button
              onClick={() => setActiveTab('raw')}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold transition-all shrink-0 flex items-center gap-1.5 ${
                activeTab === 'raw'
                  ? 'bg-slate-900 text-white shadow-sm'
                  : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Raw CLI Output</span>
            </button>
          </div>

          {/* Workbench Tab Content */}
          <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm min-h-[400px]">
            {isAnalysisLoading ? (
              <div className="py-16 text-center text-slate-400">
                <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-2 text-blue-600" />
                <p className="text-xs font-semibold">Reading memory dump artifacts...</p>
              </div>
            ) : !analysisData ? (
              <div className="py-16 text-center text-slate-500 space-y-3">
                <Cpu className="w-10 h-10 text-slate-300 mx-auto" />
                <p className="text-sm font-bold text-slate-700">No Volatility 3 Analysis Executed</p>
                <p className="text-xs text-slate-400 max-w-sm mx-auto">
                  Select a memory image from the left panel and click "Execute Volatility Analysis" to extract kernel processes, sockets, and shellcode.
                </p>
              </div>
            ) : (
              <>
                {/* Tab 1: Processes Table */}
                {activeTab === 'processes' && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between gap-4">
                      <div className="relative flex-1 max-w-xs">
                        <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                        <input
                          type="text"
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          placeholder="Filter processes by name or PID..."
                          className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      <span className="text-xs text-slate-400 font-medium">
                        Showing {filteredProcesses.length} of {analysisData.processes.length} processes
                      </span>
                    </div>

                    <div className="overflow-x-auto border border-slate-200/70 rounded-xl">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-50 text-slate-500 font-bold uppercase text-[10px] border-b border-slate-200/70">
                          <tr>
                            <th className="py-2.5 px-3">PID</th>
                            <th className="py-2.5 px-3">PPID</th>
                            <th className="py-2.5 px-3">Image Name</th>
                            <th className="py-2.5 px-3">Threads</th>
                            <th className="py-2.5 px-3">Handles</th>
                            <th className="py-2.5 px-3">Created (UTC)</th>
                            <th className="py-2.5 px-3">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                          {filteredProcesses.map((p) => (
                            <tr
                              key={p.pid}
                              className={`hover:bg-slate-50/80 transition-colors ${
                                p.status === 'Suspicious' ? 'bg-rose-50/40' : ''
                              }`}
                            >
                              <td className="py-2.5 px-3 font-bold text-slate-900">{p.pid}</td>
                              <td className="py-2.5 px-3 text-slate-500">{p.ppid}</td>
                              <td className="py-2.5 px-3 font-sans font-bold text-slate-900">
                                {p.image_name}
                              </td>
                              <td className="py-2.5 px-3 text-slate-600">{p.threads ?? '-'}</td>
                              <td className="py-2.5 px-3 text-slate-600">{p.handles ?? '-'}</td>
                              <td className="py-2.5 px-3 text-slate-500">
                                {p.created_time ? new Date(p.created_time).toLocaleString() : 'N/A'}
                              </td>
                              <td className="py-2.5 px-3">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-sans font-bold uppercase ${
                                    p.status === 'Suspicious'
                                      ? 'bg-rose-100 text-rose-800'
                                      : p.status === 'Terminated'
                                      ? 'bg-slate-100 text-slate-600'
                                      : 'bg-emerald-100 text-emerald-800'
                                  }`}
                                >
                                  {p.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Tab 2: Network Connections Table */}
                {activeTab === 'network' && (
                  <div className="space-y-4">
                    <div className="overflow-x-auto border border-slate-200/70 rounded-xl">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-50 text-slate-500 font-bold uppercase text-[10px] border-b border-slate-200/70">
                          <tr>
                            <th className="py-2.5 px-3">Proto</th>
                            <th className="py-2.5 px-3">Local Address</th>
                            <th className="py-2.5 px-3">Foreign Address</th>
                            <th className="py-2.5 px-3">State</th>
                            <th className="py-2.5 px-3">Owner Process</th>
                            <th className="py-2.5 px-3">PID</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                          {analysisData.network_connections.map((net, nidx) => (
                            <tr key={nidx} className="hover:bg-slate-50/80">
                              <td className="py-2.5 px-3 font-bold text-blue-600">{net.proto}</td>
                              <td className="py-2.5 px-3 text-slate-800">
                                {net.local_addr}:{net.local_port}
                              </td>
                              <td className="py-2.5 px-3 font-bold text-slate-900">
                                {net.foreign_addr}:{net.foreign_port}
                              </td>
                              <td className="py-2.5 px-3">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-sans font-bold uppercase ${
                                    net.state === 'ESTABLISHED'
                                      ? 'bg-emerald-100 text-emerald-800'
                                      : net.state === 'SYN_SENT'
                                      ? 'bg-amber-100 text-amber-800'
                                      : 'bg-slate-100 text-slate-700'
                                  }`}
                                >
                                  {net.state}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 font-sans font-bold text-slate-800">
                                {net.owner || 'N/A'}
                              </td>
                              <td className="py-2.5 px-3 text-slate-500">{net.pid}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Tab 3: Code Injections (malfind) */}
                {activeTab === 'injections' && (
                  <div className="space-y-4">
                    {analysisData.injected_regions.length === 0 ? (
                      <div className="p-8 text-center text-slate-500">
                        <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                        <p className="text-xs font-bold text-slate-800">No Injected Code Detected</p>
                        <p className="text-[11px] text-slate-400">
                          Volatility 3 malfind found no user-mode VAD regions with RWX permissions.
                        </p>
                      </div>
                    ) : (
                      analysisData.injected_regions.map((inj, iidx) => (
                        <div
                          key={iidx}
                          className="bg-rose-50/40 border border-rose-200 rounded-2xl p-4 space-y-3"
                        >
                          <div className="flex items-start justify-between gap-2">
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="px-2 py-0.5 rounded bg-rose-600 text-white font-bold text-[10px] uppercase">
                                  {inj.severity} Risk Alert
                                </span>
                                <span className="font-mono text-xs font-bold text-slate-900">
                                  {inj.process_name} (PID: {inj.pid})
                                </span>
                              </div>
                              <p className="text-xs text-rose-900 font-semibold mt-1">
                                Memory Range: {inj.start_vpn} — {inj.end_vpn} • Protection: {inj.protection}
                              </p>
                            </div>
                            <span className="text-[10px] font-mono bg-white px-2 py-1 rounded border border-rose-200 text-rose-800 font-bold">
                              Tag: {inj.tag} | Commit: {inj.commit_charge}
                            </span>
                          </div>

                          {/* Hex Dump Viewer */}
                          {inj.hexdump_snippet && (
                            <div>
                              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">
                                Memory Hexdump Snippet:
                              </span>
                              <pre className="bg-[#0B132B] text-cyan-300 font-mono text-[10px] p-2.5 rounded-xl overflow-x-auto">
                                {inj.hexdump_snippet}
                              </pre>
                            </div>
                          )}

                          {/* Disassembly Snippet */}
                          {inj.disassembly_snippet && (
                            <div>
                              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-1">
                                Disassembled Instructions:
                              </span>
                              <pre className="bg-slate-900 text-emerald-400 font-mono text-[10px] p-2.5 rounded-xl overflow-x-auto">
                                {inj.disassembly_snippet}
                              </pre>
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                )}

                {/* Tab 4: Command Lines */}
                {activeTab === 'cmdline' && (
                  <div className="space-y-3">
                    {analysisData.cmdlines.map((cmd, cidx) => (
                      <div key={cidx} className="bg-slate-50 p-3 rounded-xl border border-slate-200/60 space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-slate-900 text-xs">{cmd.process_name}</span>
                          <span className="text-slate-400 text-xs font-mono">(PID: {cmd.pid})</span>
                        </div>
                        <p className="font-mono text-[11px] text-slate-700 bg-white p-2 rounded-lg border border-slate-200 overflow-x-auto break-all">
                          {cmd.args}
                        </p>
                      </div>
                    ))}
                  </div>
                )}

                {/* Tab 5: Handles */}
                {activeTab === 'handles' && (
                  <div className="overflow-x-auto border border-slate-200/70 rounded-xl">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-50 text-slate-500 font-bold uppercase text-[10px] border-b border-slate-200/70">
                        <tr>
                          <th className="py-2.5 px-3">PID</th>
                          <th className="py-2.5 px-3">Process</th>
                          <th className="py-2.5 px-3">Handle Value</th>
                          <th className="py-2.5 px-3">Type</th>
                          <th className="py-2.5 px-3">Object Name</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                        {analysisData.handles.map((h, hidx) => (
                          <tr key={hidx} className="hover:bg-slate-50/80">
                            <td className="py-2.5 px-3 text-slate-500">{h.pid}</td>
                            <td className="py-2.5 px-3 font-sans font-bold text-slate-900">{h.process_name}</td>
                            <td className="py-2.5 px-3 text-blue-600">{h.handle_value}</td>
                            <td className="py-2.5 px-3 font-sans font-semibold text-slate-700">{h.item_type}</td>
                            <td className="py-2.5 px-3 text-slate-800 break-all">{h.name}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Tab 6: Raw CLI Output */}
                {activeTab === 'raw' && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-slate-500 font-medium">
                        Forensic Raw Stdout Log
                      </span>
                      <button
                        onClick={handleCopyLogs}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold transition-colors"
                      >
                        {copiedLog ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                            <span>Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Terminal Output</span>
                          </>
                        )}
                      </button>
                    </div>

                    <pre className="bg-[#0B132B] text-slate-200 font-mono text-xs p-4 rounded-xl overflow-x-auto max-h-[500px] leading-relaxed select-all">
                      {analysisData.raw_output || 'No raw output available.'}
                    </pre>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
