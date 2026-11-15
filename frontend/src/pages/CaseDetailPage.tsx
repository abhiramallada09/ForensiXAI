import React, { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  Calendar,
  User,
  Layers,
  History,
  ShieldAlert,
  Download,
  Archive,
  Trash2,
  Edit3,
  Upload,
  GitCompare,
  CheckCircle2,
  X,
} from 'lucide-react';
import {
  fetchCaseById,
  updateCase,
  archiveCase,
  deleteCase,
  exportCaseDossier,
} from '../api/client';
import { CaseStatus, CaseUpdatePayload } from '../types/forensics';
import { useCase } from '../context/CaseContext';

const STATUS_OPTIONS: CaseStatus[] = [
  'New',
  'Evidence Collected',
  'Analyzing',
  'Analysis Complete',
  'Review Required',
  'Archived',
];

export const CaseDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { setActiveCaseId } = useCase();

  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [editName, setEditName] = useState('');
  const [editDesc, setEditDesc] = useState('');
  const [editInvestigator, setEditInvestigator] = useState('');

  const { data: caseItem, isLoading, isError } = useQuery({
    queryKey: ['case', id],
    queryFn: () => fetchCaseById(id!),
    enabled: !!id,
  });

  const updateMutation = useMutation({
    mutationFn: (payload: CaseUpdatePayload) => updateCase(id!, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case', id] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      setIsEditModalOpen(false);
    },
  });

  const archiveMutation = useMutation({
    mutationFn: () => archiveCase(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['case', id] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteCase(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      navigate('/cases');
    },
  });

  const handleOpenEdit = () => {
    if (!caseItem) return;
    setEditName(caseItem.name);
    setEditDesc(caseItem.description || '');
    setEditInvestigator(caseItem.investigator);
    setIsEditModalOpen(true);
  };

  const handleSaveEdit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!editName.trim()) return;
    updateMutation.mutate({
      name: editName.trim(),
      description: editDesc.trim() || undefined,
      investigator: editInvestigator.trim() || 'A. Abhiram',
    });
  };

  const handleStatusChange = (newStatus: CaseStatus) => {
    updateMutation.mutate({ status: newStatus });
  };

  const handleExport = async () => {
    if (!caseItem) return;
    try {
      const dossier = await exportCaseDossier(caseItem.id);
      const blob = new Blob([JSON.stringify(dossier, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ForensiX_Case_${caseItem.case_number}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to export case dossier');
    }
  };

  const handleDelete = () => {
    if (!caseItem) return;
    if (
      window.confirm(
        `Are you sure you want to delete investigation "${caseItem.name}" (${caseItem.case_number})? Original forensic raw evidence files will remain preserved.`
      )
    ) {
      deleteMutation.mutate();
    }
  };

  if (isLoading) {
    return (
      <div className="bg-white rounded-2xl p-12 text-center text-xs text-slate-500 font-medium">
        Loading case details...
      </div>
    );
  }

  if (isError || !caseItem) {
    return (
      <div className="bg-white rounded-2xl p-12 text-center space-y-3">
        <p className="text-sm font-bold text-slate-700">Investigation Case Not Found</p>
        <Link
          to="/cases"
          className="inline-flex items-center gap-1.5 text-xs text-blue-600 font-semibold"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Case Repository</span>
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Back and Breadcrumb Header */}
      <div className="flex items-center justify-between">
        <Link
          to="/cases"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to All Investigations</span>
        </Link>
        <button
          onClick={() => {
            setActiveCaseId(caseItem.id);
            alert(`Case ${caseItem.case_number} is now set as the active global investigation.`);
          }}
          className="text-xs font-bold text-blue-600 hover:text-blue-700 bg-blue-50 px-3 py-1.5 rounded-xl border border-blue-200"
        >
          ★ Set as Active Investigation
        </button>
      </div>

      {/* Main Case Dossier Card */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6 border-b border-slate-100 pb-6">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs font-black px-2.5 py-1 rounded-lg bg-blue-500/10 text-blue-700 border border-blue-200">
                {caseItem.case_number}
              </span>
              <span className="text-xs text-slate-400 font-mono">
                ID: {caseItem.id}
              </span>
            </div>
            <h2 className="text-2xl font-black text-slate-900 tracking-tight">
              {caseItem.name}
            </h2>
            <p className="text-xs text-slate-600 leading-relaxed">
              {caseItem.description || 'No description provided for this investigation case.'}
            </p>
          </div>

          {/* Action Bar */}
          <div className="flex flex-wrap items-center gap-2.5">
            <button
              onClick={handleOpenEdit}
              className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors"
            >
              <Edit3 className="w-3.5 h-3.5" />
              <span>Rename / Edit</span>
            </button>

            <button
              onClick={handleExport}
              className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>

            {caseItem.status !== 'Archived' ? (
              <button
                onClick={() => archiveMutation.mutate()}
                disabled={archiveMutation.isPending}
                className="inline-flex items-center gap-1.5 px-3 py-2 bg-amber-50 hover:bg-amber-100 text-amber-800 text-xs font-semibold rounded-xl border border-amber-200 transition-colors"
              >
                <Archive className="w-3.5 h-3.5" />
                <span>Archive</span>
              </button>
            ) : (
              <button
                onClick={() => handleStatusChange('Analyzing')}
                className="inline-flex items-center gap-1.5 px-3 py-2 bg-emerald-50 hover:bg-emerald-100 text-emerald-800 text-xs font-semibold rounded-xl border border-emerald-200 transition-colors"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Re-activate</span>
              </button>
            )}

            <button
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
              className="inline-flex items-center gap-1.5 px-3 py-2 bg-rose-50 hover:bg-rose-100 text-rose-700 text-xs font-semibold rounded-xl border border-rose-200 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Delete</span>
            </button>
          </div>
        </div>

        {/* Metadata Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="bg-slate-50 p-4 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase flex items-center gap-1.5">
              <User className="w-3.5 h-3.5" />
              Lead Investigator
            </span>
            <p className="font-bold text-slate-800 text-sm">{caseItem.investigator}</p>
          </div>

          <div className="bg-slate-50 p-4 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase flex items-center gap-1.5">
              Investigation Status
            </span>
            <select
              value={caseItem.status}
              onChange={(e) => handleStatusChange(e.target.value as CaseStatus)}
              className="mt-0.5 bg-white border border-slate-200 rounded-lg px-2 py-1 text-xs font-bold text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {STATUS_OPTIONS.map((st) => (
                <option key={st} value={st}>
                  {st}
                </option>
              ))}
            </select>
          </div>

          <div className="bg-slate-50 p-4 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase flex items-center gap-1.5">
              <Calendar className="w-3.5 h-3.5" />
              Created Date
            </span>
            <p className="font-mono text-slate-800 font-semibold">
              {new Date(caseItem.created_at).toLocaleString()}
            </p>
          </div>

          <div className="bg-slate-50 p-4 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase flex items-center gap-1.5">
              <History className="w-3.5 h-3.5" />
              Last Modified
            </span>
            <p className="font-mono text-slate-800 font-semibold">
              {new Date(caseItem.updated_at).toLocaleString()}
            </p>
          </div>
        </div>
      </div>

      {/* Case Telemetry Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-xl bg-blue-500/10 text-blue-600 flex items-center justify-center shrink-0">
              <Layers className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium">Evidence Vault</p>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-slate-900">
                  {caseItem.evidence_count || 0}
                </span>
                <span className="text-[11px] text-slate-500 font-medium">Items</span>
              </div>
            </div>
          </div>
          <Link
            to="/evidence"
            className="text-xs font-bold text-blue-600 hover:text-blue-800"
          >
            Manage →
          </Link>
        </div>

        <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-xl bg-emerald-500/10 text-emerald-600 flex items-center justify-center shrink-0">
              <History className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium">Correlated Events</p>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-slate-900">
                  {caseItem.timeline_events_count || 0}
                </span>
                <span className="text-[11px] text-slate-500 font-medium">Events</span>
              </div>
            </div>
          </div>
          <Link
            to="/timeline"
            className="text-xs font-bold text-blue-600 hover:text-blue-800"
          >
            Inspect →
          </Link>
        </div>

        <div className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <div className="w-11 h-11 rounded-xl bg-rose-500/10 text-rose-600 flex items-center justify-center shrink-0">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <p className="text-xs text-slate-500 font-medium">Anomalies & Findings</p>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-slate-900">
                  {caseItem.findings_count || 0}
                </span>
                <span className="text-[11px] text-slate-500 font-medium">Findings</span>
              </div>
            </div>
          </div>
          <Link
            to="/correlation"
            className="text-xs font-bold text-blue-600 hover:text-blue-800"
          >
            Review →
          </Link>
        </div>
      </div>

      {/* Next Step / Evidence Ingestion Quick Card (Leading to Phase 3 & 5) */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-2xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="font-bold text-blue-950 text-sm">
            Ingest & Correlate Forensic Evidence for {caseItem.case_number}
          </h3>
          <p className="text-xs text-blue-800/80 mt-0.5">
            Upload raw Windows files, system logs, memory dumps, and correlate events across temporal clusters.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Link
            to="/correlation"
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-white border border-blue-200 text-blue-700 hover:bg-blue-50 font-semibold text-xs rounded-xl shadow-sm shrink-0 transition-colors"
          >
            <GitCompare className="w-4 h-4 text-blue-600" />
            <span>Correlate Evidence</span>
          </Link>
          <Link
            to="/evidence"
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#1E50FF] hover:bg-blue-600 text-white font-semibold text-xs rounded-xl shadow-md shrink-0 transition-colors"
          >
            <Upload className="w-4 h-4" />
            <span>Upload Evidence</span>
          </Link>
        </div>
      </div>

      {/* Edit / Rename Case Modal */}
      {isEditModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-200 relative animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setIsEditModalOpen(false)}
              className="absolute top-5 right-5 text-slate-400 hover:text-slate-600"
            >
              <X className="w-5 h-5" />
            </button>
            <h3 className="text-lg font-bold text-slate-900 mb-1">
              Edit Investigation Metadata
            </h3>
            <p className="text-xs text-slate-500 mb-5">
              Update case title, incident description, and lead investigator credentials.
            </p>

            <form onSubmit={handleSaveEdit} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Investigation Name *
                </label>
                <input
                  type="text"
                  required
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Description / Incident Notes
                </label>
                <textarea
                  rows={3}
                  value={editDesc}
                  onChange={(e) => setEditDesc(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Lead Investigator
                </label>
                <input
                  type="text"
                  value={editInvestigator}
                  onChange={(e) => setEditInvestigator(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsEditModalOpen(false)}
                  className="px-4 py-2 border border-slate-200 text-slate-600 text-xs font-semibold rounded-xl hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={updateMutation.isPending}
                  className="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-xl shadow-md disabled:opacity-50"
                >
                  {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
