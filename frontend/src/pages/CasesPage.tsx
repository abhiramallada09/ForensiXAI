import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  Plus,
  Search,
  Folder,
  Calendar,
  User,
  ArrowRight,
  X,
  Download,
  Archive,
  Trash2,
  Edit3,
} from 'lucide-react';
import {
  fetchCases,
  createCase,
  updateCase,
  archiveCase,
  deleteCase,
  exportCaseDossier,
} from '../api/client';
import { Case, CaseStatus, CaseCreatePayload } from '../types/forensics';
import { useCase } from '../context/CaseContext';

const STATUS_FILTERS = [
  'All',
  'New',
  'Evidence Collected',
  'Analyzing',
  'Analysis Complete',
  'Review Required',
  'Archived',
];

export const CasesPage: React.FC = () => {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { setActiveCaseId, activeCaseId } = useCase();

  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('All');

  // Create Modal state
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newCaseNumber, setNewCaseNumber] = useState('');
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseDesc, setNewCaseDesc] = useState('');
  const [newCaseInvestigator, setNewCaseInvestigator] = useState('A. Abhiram');

  // Edit / Rename Modal state
  const [editingCase, setEditingCase] = useState<Case | null>(null);
  const [editName, setEditName] = useState('');
  const [editDesc, setEditDesc] = useState('');
  const [editInvestigator, setEditInvestigator] = useState('');

  const { data: cases = [], isLoading } = useQuery({
    queryKey: ['cases', activeTab, searchTerm],
    queryFn: () => fetchCases(activeTab, searchTerm),
  });

  const createMutation = useMutation({
    mutationFn: (payload: CaseCreatePayload) => createCase(payload),
    onSuccess: (newCase) => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      queryClient.invalidateQueries({ queryKey: ['systemStatus'] });
      setActiveCaseId(newCase.id);
      setIsCreateModalOpen(false);
      setNewCaseNumber('');
      setNewCaseName('');
      setNewCaseDesc('');
    },
    onError: (err: any) => {
      alert(err.message || 'Error creating case');
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: any }) =>
      updateCase(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      setEditingCase(null);
    },
  });

  const archiveMutation = useMutation({
    mutationFn: (id: string) => archiveCase(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteCase(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseName.trim()) return;
    createMutation.mutate({
      case_number: newCaseNumber.trim() || undefined,
      name: newCaseName.trim(),
      description: newCaseDesc.trim() || undefined,
      investigator: newCaseInvestigator.trim() || 'A. Abhiram',
      status: 'New',
    });
  };

  const handleOpenEdit = (c: Case) => {
    setEditingCase(c);
    setEditName(c.name);
    setEditDesc(c.description || '');
    setEditInvestigator(c.investigator);
  };

  const handleSaveEdit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingCase || !editName.trim()) return;
    updateMutation.mutate({
      id: editingCase.id,
      payload: {
        name: editName.trim(),
        description: editDesc.trim() || undefined,
        investigator: editInvestigator.trim() || 'A. Abhiram',
      },
    });
  };

  const handleExportJSON = async (c: Case) => {
    try {
      const data = await exportCaseDossier(c.id);
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ForensiX_Case_${c.case_number}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to export case JSON dossier.');
    }
  };

  const handleDeleteCase = (c: Case) => {
    if (
      window.confirm(
        `Are you sure you want to delete investigation "${c.name}" (${c.case_number})? Original forensic raw evidence files will remain preserved.`
      )
    ) {
      deleteMutation.mutate(c.id);
    }
  };

  const handleOpenCase = (c: Case) => {
    setActiveCaseId(c.id);
    navigate(`/cases/${c.id}`);
  };

  const getStatusBadge = (status: CaseStatus) => {
    const map: Record<CaseStatus, string> = {
      New: 'bg-blue-500/10 text-blue-700 border-blue-200',
      'Evidence Collected': 'bg-cyan-500/10 text-cyan-700 border-cyan-200',
      Analyzing: 'bg-amber-500/10 text-amber-700 border-amber-200',
      'Analysis Complete': 'bg-emerald-500/10 text-emerald-700 border-emerald-200',
      'Review Required': 'bg-rose-500/10 text-rose-700 border-rose-200',
      Archived: 'bg-slate-500/10 text-slate-700 border-slate-200',
    };
    return (
      <span
        className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
          map[status] || map.New
        }`}
      >
        {status}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Primary Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">
            Investigation Case Management
          </h2>
          <p className="text-xs text-slate-500 font-medium mt-1">
            Create, track, review, and archive digital forensic investigation cases with full audit provenance.
          </p>
        </div>
        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#1E50FF] hover:bg-blue-600 active:scale-[0.98] transition-all text-white text-xs font-semibold rounded-xl shadow-md shadow-blue-600/30 shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span>New Investigation Case</span>
        </button>
      </div>

      {/* Filter Tabs and Search Bar */}
      <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm space-y-4">
        {/* Status Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
          {STATUS_FILTERS.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3.5 py-1.5 rounded-xl font-semibold transition-colors shrink-0 ${
                activeTab === tab
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Search Input & Counter */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2 border-t border-slate-100">
          <div className="relative w-full max-w-sm">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by case title, case number, or investigator..."
              className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div className="text-xs text-slate-500 font-medium">
            Found <strong className="text-slate-800">{cases.length}</strong> matching investigations
          </div>
        </div>
      </div>

      {/* Cases Table */}
      <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-xs text-slate-500 font-medium">
            Loading investigation cases...
          </div>
        ) : cases.length === 0 ? (
          <div className="p-12 text-center">
            <Folder className="w-10 h-10 text-slate-300 mx-auto mb-2" />
            <p className="text-sm font-bold text-slate-700">No Investigation Cases Found</p>
            <p className="text-xs text-slate-500 mt-1">
              {searchTerm || activeTab !== 'All'
                ? 'Try clearing the search filter.'
                : 'Create a new investigation case to begin collecting evidence and analyzing artifacts.'}
            </p>
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="mt-4 inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white text-xs font-semibold rounded-lg hover:bg-blue-700"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create New Case</span>
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50/80 border-b border-slate-200 text-[11px] font-bold text-slate-600 uppercase tracking-wider">
                  <th className="py-3 px-5">Case Identifier</th>
                  <th className="py-3 px-5">Investigation Title</th>
                  <th className="py-3 px-5">Lead Investigator</th>
                  <th className="py-3 px-5">Status</th>
                  <th className="py-3 px-5">Created Date</th>
                  <th className="py-3 px-5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs text-slate-700">
                {cases.map((c: Case) => {
                  const isActive = c.id === activeCaseId;
                  return (
                    <tr
                      key={c.id}
                      className={`hover:bg-slate-50/80 transition-colors ${
                        isActive ? 'bg-blue-50/30' : ''
                      }`}
                    >
                      <td className="py-3.5 px-5 font-mono font-bold text-blue-600">
                        <div className="flex items-center gap-2">
                          <span>{c.case_number}</span>
                          {isActive && (
                            <span className="text-[10px] bg-blue-600 text-white font-sans px-1.5 py-0.2 rounded font-bold">
                              Active
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-5">
                        <div className="font-bold text-slate-900 hover:text-blue-600 cursor-pointer" onClick={() => handleOpenCase(c)}>
                          {c.name}
                        </div>
                        {c.description && (
                          <div className="text-[11px] text-slate-500 truncate max-w-sm">
                            {c.description}
                          </div>
                        )}
                      </td>
                      <td className="py-3.5 px-5">
                        <div className="flex items-center gap-1.5 text-slate-800 font-medium">
                          <User className="w-3.5 h-3.5 text-slate-400" />
                          <span>{c.investigator}</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-5">{getStatusBadge(c.status)}</td>
                      <td className="py-3.5 px-5 text-slate-500">
                        <div className="flex items-center gap-1.5 font-mono text-[11px]">
                          <Calendar className="w-3.5 h-3.5 text-slate-400" />
                          <span>{new Date(c.created_at).toLocaleDateString()}</span>
                        </div>
                      </td>
                      <td className="py-3.5 px-5 text-right">
                        <div className="inline-flex items-center gap-2">
                          <button
                            onClick={() => handleOpenCase(c)}
                            title="Open Investigation Dossier"
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-blue-50 text-blue-700 hover:bg-blue-100 font-semibold text-xs"
                          >
                            <span>Open</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>

                          <button
                            onClick={() => handleOpenEdit(c)}
                            title="Rename / Edit"
                            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100"
                          >
                            <Edit3 className="w-3.5 h-3.5" />
                          </button>

                          <button
                            onClick={() => handleExportJSON(c)}
                            title="Export JSON Dossier"
                            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>

                          {c.status !== 'Archived' && (
                            <button
                              onClick={() => archiveMutation.mutate(c.id)}
                              title="Archive Case"
                              className="p-1.5 rounded-lg text-slate-400 hover:text-amber-700 hover:bg-amber-50"
                            >
                              <Archive className="w-3.5 h-3.5" />
                            </button>
                          )}

                          <button
                            onClick={() => handleDeleteCase(c)}
                            title="Delete Case Record"
                            className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* New Case Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-200 relative animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setIsCreateModalOpen(false)}
              className="absolute top-5 right-5 text-slate-400 hover:text-slate-600"
            >
              <X className="w-5 h-5" />
            </button>
            <h3 className="text-lg font-bold text-slate-900 mb-1">
              Initialize New Investigation Case
            </h3>
            <p className="text-xs text-slate-500 mb-5">
              Enter the investigation metadata. Evidence and chain of custody will be bound to this case.
            </p>

            <form onSubmit={handleCreateSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Investigation Name *
                </label>
                <input
                  type="text"
                  required
                  value={newCaseName}
                  onChange={(e) => setNewCaseName(e.target.value)}
                  placeholder="e.g., Endpoint Breach Triage - Host 04"
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Custom Case ID (Optional)
                </label>
                <input
                  type="text"
                  value={newCaseNumber}
                  onChange={(e) => setNewCaseNumber(e.target.value)}
                  placeholder="Leave blank to auto-generate (e.g., CAS-179466...)"
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Description / Incident Scope
                </label>
                <textarea
                  rows={3}
                  value={newCaseDesc}
                  onChange={(e) => setNewCaseDesc(e.target.value)}
                  placeholder="Provide scope, suspected intrusion vectors, and affected endpoints..."
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Lead Investigator
                </label>
                <input
                  type="text"
                  value={newCaseInvestigator}
                  onChange={(e) => setNewCaseInvestigator(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 border border-slate-200 text-slate-600 text-xs font-semibold rounded-xl hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-xl shadow-md disabled:opacity-50"
                >
                  {createMutation.isPending ? 'Creating Case...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit / Rename Modal */}
      {editingCase && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-slate-200 relative animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setEditingCase(null)}
              className="absolute top-5 right-5 text-slate-400 hover:text-slate-600"
            >
              <X className="w-5 h-5" />
            </button>
            <h3 className="text-lg font-bold text-slate-900 mb-1">
              Rename / Edit Investigation Case
            </h3>
            <p className="text-xs text-slate-500 mb-5">
              Update name or investigator credentials for case{' '}
              <strong className="text-slate-700 font-mono">
                {editingCase.case_number}
              </strong>
              .
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
                  onClick={() => setEditingCase(null)}
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
