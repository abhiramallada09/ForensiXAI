import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  History,
  Plus,
  Search,
  ArrowUpDown,
  RefreshCw,
  FileText,
  Terminal,
  Wifi,
  LogIn,
  Cloud,
  Layers,
  Trash2,
  X,
  Clock,
  GitCompare,
} from 'lucide-react';
import {
  fetchTimelineEvents,
  createTimelineEvent,
  rebuildCaseTimeline,
  deleteTimelineEvent,
  fetchEvidenceList,
} from '../api/client';
import {
  TimelineEvent,
  TimelineEventCreatePayload,
  EvidenceClassification,
} from '../types/forensics';
import { EvidenceBadge } from '../components/common/EvidenceBadge';
import { useCase } from '../context/CaseContext';

const EVENT_TYPE_FILTERS = [
  'All',
  'File Created',
  'File Modified',
  'File Accessed',
  'File Deleted',
  'Process Started',
  'Network Activity',
  'Login',
  'Cloud Activity',
  'Other',
];

const CLASSIFICATION_FILTERS: Array<'All' | EvidenceClassification> = [
  'All',
  'OBSERVED',
  'CORRELATED',
  'RECONSTRUCTED',
  'SUSPICIOUS',
  'UNKNOWN',
];

export const TimelinePage: React.FC = () => {
  const queryClient = useQueryClient();
  const { activeCase, allCases } = useCase();

  const [selectedCaseId, setSelectedCaseId] = useState<string>(activeCase ? activeCase.id : 'ALL');
  const [selectedEventType, setSelectedEventType] = useState('All');
  const [selectedClassification, setSelectedClassification] = useState<'All' | EvidenceClassification>('All');
  const [searchTerm, setSearchTerm] = useState('');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Add Event Modal State
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [targetCaseId, setTargetCaseId] = useState<string>(activeCase ? activeCase.id : '');
  const [eventTimestamp, setEventTimestamp] = useState<string>(
    new Date().toISOString().slice(0, 16)
  );
  const [eventTimestampEnd, setEventTimestampEnd] = useState<string>('');
  const [eventSource, setEventSource] = useState<string>('Volatility 3 (windows.pslist)');
  const [eventType, setEventType] = useState<string>('Process Started');
  const [eventDescription, setEventDescription] = useState<string>('');
  const [eventConfidence, setEventConfidence] = useState<number>(0.9);
  const [eventClassification, setEventClassification] = useState<EvidenceClassification>('CORRELATED');
  const [linkedEvidenceId, setLinkedEvidenceId] = useState<string>('');

  const { data: timelineEvents = [], isLoading } = useQuery({
    queryKey: ['timeline', selectedCaseId, selectedEventType, selectedClassification, searchTerm, sortOrder],
    queryFn: () =>
      fetchTimelineEvents({
        case_id: selectedCaseId,
        event_type: selectedEventType,
        classification: selectedClassification,
        search: searchTerm,
        order: sortOrder,
      }),
  });

  const { data: availableEvidence = [] } = useQuery({
    queryKey: ['evidence', targetCaseId],
    queryFn: () => fetchEvidenceList(targetCaseId || undefined),
    enabled: isAddModalOpen,
  });

  const createEventMutation = useMutation({
    mutationFn: (payload: TimelineEventCreatePayload) => createTimelineEvent(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['timeline'] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      setIsAddModalOpen(false);
      setEventDescription('');
      setEventTimestampEnd('');
    },
    onError: (err: any) => {
      alert(err.message || 'Error creating timeline event');
    },
  });

  const rebuildMutation = useMutation({
    mutationFn: (cid: string) => rebuildCaseTimeline(cid),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['timeline'] });
      alert(data.message);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteTimelineEvent(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['timeline'] });
    },
  });

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!eventDescription.trim()) return;
    const cid = targetCaseId || (activeCase ? activeCase.id : allCases[0]?.id);
    if (!cid) {
      alert('Please select or create an investigation case first');
      return;
    }

    createEventMutation.mutate({
      case_id: cid,
      evidence_id: linkedEvidenceId || undefined,
      timestamp: new Date(eventTimestamp).toISOString(),
      timestamp_end: eventTimestampEnd ? new Date(eventTimestampEnd).toISOString() : undefined,
      timestamp_source: eventSource,
      event_type: eventType,
      artifact_category: 'Correlated Evidence',
      description: eventDescription.trim(),
      confidence: eventConfidence,
      classification: eventClassification,
    });
  };

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'File Created':
      case 'File Modified':
      case 'File Accessed':
      case 'File Deleted':
        return <FileText className="w-4 h-4 text-blue-600" />;
      case 'Process Started':
        return <Terminal className="w-4 h-4 text-emerald-600" />;
      case 'Network Activity':
        return <Wifi className="w-4 h-4 text-rose-600" />;
      case 'Login':
        return <LogIn className="w-4 h-4 text-purple-600" />;
      case 'Cloud Activity':
        return <Cloud className="w-4 h-4 text-cyan-600" />;
      default:
        return <History className="w-4 h-4 text-slate-600" />;
    }
  };

  const getTimelineNodeColor = (classification: EvidenceClassification) => {
    switch (classification) {
      case 'OBSERVED':
        return 'bg-emerald-500 ring-emerald-100 border-emerald-400';
      case 'CORRELATED':
        return 'bg-blue-500 ring-blue-100 border-blue-400';
      case 'RECONSTRUCTED':
        return 'bg-purple-500 ring-purple-100 border-purple-400';
      case 'SUSPICIOUS':
        return 'bg-rose-500 ring-rose-100 border-rose-400';
      default:
        return 'bg-slate-400 ring-slate-100 border-slate-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Header Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">
            Chronological Forensic Timeline Engine
          </h2>
          <p className="text-xs text-slate-500 font-medium mt-1">
            Correlated temporal sequence synthesized from filesystem MACB timestamps, process executions, network logs, and cloud trails.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Link
            to="/correlation"
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-blue-50 hover:bg-blue-100 text-blue-700 text-xs font-semibold border border-blue-200 transition-all"
            title="Inspect multi-source correlation clusters"
          >
            <GitCompare className="w-3.5 h-3.5 text-blue-600" />
            <span>Multi-Evidence Correlation</span>
          </Link>

          {activeCase && (
            <button
              onClick={() => rebuildMutation.mutate(activeCase.id)}
              disabled={rebuildMutation.isPending}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-semibold transition-all disabled:opacity-50"
              title="Extract all evidence MACB timestamps into timeline"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${rebuildMutation.isPending ? 'animate-spin' : ''}`} />
              <span>Sync Evidence MACB</span>
            </button>
          )}

          <button
            onClick={() => {
              if (activeCase) setTargetCaseId(activeCase.id);
              else if (allCases.length > 0) setTargetCaseId(allCases[0].id);
              setIsAddModalOpen(true);
            }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-[#1E50FF] hover:bg-blue-600 active:scale-[0.98] transition-all text-white text-xs font-semibold rounded-xl shadow-md shadow-blue-600/30"
          >
            <Plus className="w-4 h-4" />
            <span>Add Correlated Event</span>
          </button>
        </div>
      </div>

      {/* Filter and Control Bar */}
      <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm space-y-4">
        {/* Classification Quick Filter Pills */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
          <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider shrink-0 mr-1">
            Classification:
          </span>
          {CLASSIFICATION_FILTERS.map((cls) => (
            <button
              key={cls}
              onClick={() => setSelectedClassification(cls)}
              className={`px-3 py-1 rounded-full text-xs font-semibold transition-all shrink-0 ${
                selectedClassification === cls
                  ? 'bg-slate-900 text-white shadow-sm'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {cls}
            </button>
          ))}
        </div>

        {/* Event Type Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs border-t border-slate-100 pt-3">
          <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider shrink-0 mr-1">
            Event Type:
          </span>
          {EVENT_TYPE_FILTERS.map((type) => (
            <button
              key={type}
              onClick={() => setSelectedEventType(type)}
              className={`px-3 py-1 rounded-xl text-xs font-semibold transition-colors shrink-0 ${
                selectedEventType === type
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 hover:bg-slate-100'
              }`}
            >
              {type}
            </button>
          ))}
        </div>

        {/* Search, Case Selector & Chronological Sort Toggle */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-3 border-t border-slate-100">
          <div className="flex items-center gap-3 w-full sm:w-auto">
            {/* Search Input */}
            <div className="relative w-full sm:w-64">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search event descriptions..."
                className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* Case Selector */}
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              className="px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 shrink-0"
            >
              <option value="ALL">All Investigation Cases</option>
              {allCases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.case_number}: {c.name}
                </option>
              ))}
            </select>
          </div>

          {/* Chronological Sorting Switch */}
          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors"
            >
              <ArrowUpDown className="w-3.5 h-3.5" />
              <span>{sortOrder === 'asc' ? 'Oldest First (Chronological)' : 'Newest First'}</span>
            </button>
            <span className="text-xs text-slate-500 font-medium">
              <strong className="text-slate-900">{timelineEvents.length}</strong> events
            </span>
          </div>
        </div>
      </div>

      {/* Main Interactive Timeline Stream */}
      <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm p-6 sm:p-8">
        {isLoading ? (
          <div className="p-12 text-center text-xs text-slate-500 font-medium">
            Loading chronological timeline events...
          </div>
        ) : timelineEvents.length === 0 ? (
          <div className="p-12 text-center space-y-2">
            <History className="w-10 h-10 text-slate-300 mx-auto mb-2" />
            <p className="text-sm font-bold text-slate-700">No Timeline Events Found</p>
            <p className="text-xs text-slate-500">
              Upload evidence files or click &quot;Sync Evidence MACB&quot; to populate filesystem timeline events.
            </p>
            <div className="pt-3">
              <button
                onClick={() => setIsAddModalOpen(true)}
                className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white text-xs font-semibold rounded-lg hover:bg-blue-700"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add First Event</span>
              </button>
            </div>
          </div>
        ) : (
          <div className="relative pl-6 sm:pl-8 space-y-8">
            {/* Continuous Vertical Timeline Line */}
            <div className="absolute top-4 bottom-4 left-[15px] sm:left-[19px] w-0.5 bg-slate-200" />

            {timelineEvents.map((ev: TimelineEvent) => {
              const nodeColor = getTimelineNodeColor(ev.classification);
              const eventDate = new Date(ev.timestamp);

              return (
                <div key={ev.id} className="relative flex items-start gap-4 group">
                  {/* Timeline Node Bullet */}
                  <div
                    className={`w-4 h-4 rounded-full ring-4 shrink-0 mt-1 z-10 ${nodeColor} shadow-sm`}
                  />

                  {/* Event Content Card */}
                  <div className="flex-1 bg-slate-50/70 hover:bg-slate-50 border border-slate-200/80 rounded-2xl p-4 sm:p-5 transition-all space-y-2.5">
                    {/* Header Row */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200/60 pb-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        {/* Event Type with Icon */}
                        <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white border border-slate-200 text-xs font-bold text-slate-900 shadow-2xs">
                          {getEventIcon(ev.event_type)}
                          <span>{ev.event_type}</span>
                        </div>

                        {/* Evidence Classification Badge */}
                        <EvidenceBadge
                          classification={ev.classification}
                          confidence={ev.confidence * 100}
                        />

                        {/* Source Tag */}
                        <span className="font-mono text-[10px] text-slate-500 bg-slate-200/70 px-2 py-0.5 rounded">
                          Source: {ev.timestamp_source}
                        </span>
                      </div>

                      {/* Timestamp (UTC & Local) */}
                      <div className="flex items-center gap-2 text-right">
                        <Clock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        <span className="font-mono text-xs font-bold text-slate-800">
                          {eventDate.toLocaleString()}
                        </span>
                      </div>
                    </div>

                    {/* Reconstructed Event Interval Banner (if window exists) */}
                    {ev.timestamp_end && (
                      <div className="p-2.5 bg-purple-50 border border-purple-200 rounded-xl text-xs text-purple-900 flex items-center justify-between">
                        <span className="font-semibold">
                          Reconstructed Event Interval Window:
                        </span>
                        <span className="font-mono font-bold">
                          {eventDate.toLocaleTimeString()} —{' '}
                          {new Date(ev.timestamp_end).toLocaleTimeString()}
                        </span>
                      </div>
                    )}

                    {/* Description */}
                    <p className="text-xs text-slate-800 font-medium leading-relaxed">
                      {ev.description}
                    </p>

                    {/* Footer: Linked Evidence & Actions */}
                    <div className="flex items-center justify-between text-xs pt-1">
                      <div className="flex items-center gap-2">
                        {ev.source_evidence_filename ? (
                          <Link
                            to={`/evidence/${ev.evidence_id}`}
                            className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-blue-600 hover:text-blue-800 bg-blue-50/80 px-2.5 py-1 rounded-lg border border-blue-200/60"
                          >
                            <Layers className="w-3 h-3" />
                            <span>Linked Evidence: {ev.source_evidence_filename}</span>
                          </Link>
                        ) : ev.case_number ? (
                          <span className="font-mono text-[11px] text-slate-400">
                            Bound to: {ev.case_number}
                          </span>
                        ) : null}
                      </div>

                      <button
                        onClick={() => {
                          if (window.confirm('Delete this timeline event?')) {
                            deleteMutation.mutate(ev.id);
                          }
                        }}
                        className="text-slate-400 hover:text-rose-600 p-1 rounded transition-colors"
                        title="Remove timeline event"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Add Correlated Event Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-200 relative animate-in fade-in zoom-in-95 duration-150 space-y-4 max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setIsAddModalOpen(false)}
              className="absolute top-5 right-5 text-slate-400 hover:text-slate-600"
            >
              <X className="w-5 h-5" />
            </button>

            <div>
              <h3 className="text-lg font-bold text-slate-900">
                Register Correlated Forensic Event
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Add an observed or reconstructed temporal milestone to the case investigation timeline.
              </p>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block font-bold text-slate-700 mb-1">
                  Target Case *
                </label>
                <select
                  required
                  value={targetCaseId}
                  onChange={(e) => setTargetCaseId(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {allCases.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.case_number} — {c.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-bold text-slate-700 mb-1">
                    Event Type *
                  </label>
                  <select
                    value={eventType}
                    onChange={(e) => setEventType(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    {EVENT_TYPE_FILTERS.filter((t) => t !== 'All').map((t) => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block font-bold text-slate-700 mb-1">
                    Classification *
                  </label>
                  <select
                    value={eventClassification}
                    onChange={(e) =>
                      setEventClassification(e.target.value as EvidenceClassification)
                    }
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    {CLASSIFICATION_FILTERS.filter((c) => c !== 'All').map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block font-bold text-slate-700 mb-1">
                    Observed Timestamp *
                  </label>
                  <input
                    type="datetime-local"
                    required
                    value={eventTimestamp}
                    onChange={(e) => setEventTimestamp(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block font-bold text-slate-700 mb-1">
                    Window End Timestamp (Optional)
                  </label>
                  <input
                    type="datetime-local"
                    value={eventTimestampEnd}
                    onChange={(e) => setEventTimestampEnd(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block font-bold text-slate-700 mb-1">
                  Timestamp Source (Provenance) *
                </label>
                <input
                  type="text"
                  required
                  value={eventSource}
                  onChange={(e) => setEventSource(e.target.value)}
                  placeholder="e.g., Volatility 3 (windows.pslist), EventLog ID 4624, CloudTrail"
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block font-bold text-slate-700 mb-1">
                  Event Description *
                </label>
                <textarea
                  rows={3}
                  required
                  value={eventDescription}
                  onChange={(e) => setEventDescription(e.target.value)}
                  placeholder="Detailed description of the temporal action observed or reconstructed..."
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              {availableEvidence.length > 0 && (
                <div>
                  <label className="block font-bold text-slate-700 mb-1">
                    Link Source Evidence File (Optional)
                  </label>
                  <select
                    value={linkedEvidenceId}
                    onChange={(e) => setLinkedEvidenceId(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="">None / External Source</option>
                    {availableEvidence.map((evi) => (
                      <option key={evi.id} value={evi.id}>
                        {evi.evidence_number} — {evi.filename} ({evi.file_type})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="font-bold text-slate-700">
                    Confidence Rating
                  </label>
                  <span className="font-mono font-bold text-blue-600">
                    {Math.round(eventConfidence * 100)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0.1"
                  max="1.0"
                  step="0.05"
                  value={eventConfidence}
                  onChange={(e) => setEventConfidence(parseFloat(e.target.value))}
                  className="w-full"
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-4 py-2 border border-slate-200 text-slate-600 font-semibold rounded-xl hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createEventMutation.isPending}
                  className="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl shadow-md disabled:opacity-50"
                >
                  {createEventMutation.isPending ? 'Registering...' : 'Add Event to Timeline'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
