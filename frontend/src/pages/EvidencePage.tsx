import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, Link } from 'react-router-dom';
import {
  Layers,
  Upload,
  ShieldCheck,
  Database,
  HardDrive,
  Search,
  CheckCircle,
  Trash2,
  ArrowRight,
  X,
  FileText,
  RefreshCw,
} from 'lucide-react';
import {
  fetchEvidenceList,
  uploadEvidenceFile,
  verifyEvidenceIntegrity,
  deleteEvidenceItem,
} from '../api/client';
import { EvidenceItem } from '../types/forensics';
import { EvidenceBadge } from '../components/common/EvidenceBadge';
import { useCase } from '../context/CaseContext';

const CATEGORY_TABS = [
  'All',
  'File',
  'Memory Image',
  'System Log',
  'Cloud Log',
  'Network Evidence',
  'Other',
];

export const EvidencePage: React.FC = () => {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { activeCase, allCases } = useCase();

  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [filterCaseId, setFilterCaseId] = useState<string>('ALL');

  // Upload Modal State
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [targetCaseId, setTargetCaseId] = useState<string>(activeCase ? activeCase.id : '');
  const [uploadCategory, setUploadCategory] = useState<string>('File');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [acquisitionNotes, setAcquisitionNotes] = useState<string>('');

  // Inline verification notification
  const [verifyStatus, setVerifyStatus] = useState<{ id: string; status: 'MATCH' | 'TAMPERED' } | null>(null);

  const { data: evidenceItems = [], isLoading } = useQuery({
    queryKey: ['evidence', filterCaseId, selectedCategory, searchTerm],
    queryFn: () =>
      fetchEvidenceList(
        filterCaseId === 'ALL' ? undefined : filterCaseId,
        selectedCategory,
        searchTerm
      ),
  });

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!selectedFile) throw new Error('Please select a file to ingest');
      const cid = targetCaseId || (activeCase ? activeCase.id : allCases[0]?.id);
      if (!cid) throw new Error('Please select or create an investigation case first');
      return uploadEvidenceFile(cid, selectedFile, uploadCategory, acquisitionNotes);
    },
    onSuccess: (newEvidence) => {
      queryClient.invalidateQueries({ queryKey: ['evidence'] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      queryClient.invalidateQueries({ queryKey: ['systemStatus'] });
      setIsUploadModalOpen(false);
      setSelectedFile(null);
      setAcquisitionNotes('');
      navigate(`/evidence/${newEvidence.id}`);
    },
    onError: (err: any) => {
      alert(err.message || 'Error uploading evidence');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteEvidenceItem(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence'] });
      queryClient.invalidateQueries({ queryKey: ['cases'] });
    },
  });

  const verifyMutation = useMutation({
    mutationFn: (id: string) => verifyEvidenceIntegrity(id),
    onSuccess: (data) => {
      setVerifyStatus({ id: data.evidence_id, status: data.status });
      setTimeout(() => setVerifyStatus(null), 4000);
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      // Auto-detect category suggestion
      const name = file.name.toLowerCase();
      if (name.endsWith('.raw') || name.endsWith('.mem') || name.endsWith('.dmp')) {
        setUploadCategory('Memory Image');
      } else if (name.endsWith('.evtx') || name.endsWith('.log')) {
        setUploadCategory('System Log');
      } else if (name.includes('cloudtrail') || name.includes('azure')) {
        setUploadCategory('Cloud Log');
      }
    }
  };

  const handleDeleteItem = (e: EvidenceItem) => {
    if (
      window.confirm(
        `Remove "${e.filename}" (${e.evidence_number}) from active case register? Original file in data/uploads/ is maintained for chain of custody.`
      )
    ) {
      deleteMutation.mutate(e.id);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Upload Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">
            Evidence Vault & Integrity Management
          </h2>
          <p className="text-xs text-slate-500 font-medium mt-1">
            Read-only storage with automatic SHA-256 calculation, MACB filesystem timestamps, and strict OBSERVED classification.
          </p>
        </div>
        <button
          onClick={() => {
            if (activeCase) setTargetCaseId(activeCase.id);
            else if (allCases.length > 0) setTargetCaseId(allCases[0].id);
            setIsUploadModalOpen(true);
          }}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#1E50FF] hover:bg-blue-600 active:scale-[0.98] transition-all text-white text-xs font-semibold rounded-xl shadow-md shadow-blue-600/30 shrink-0"
        >
          <Upload className="w-4 h-4" />
          <span>Ingest Evidence File</span>
        </button>
      </div>

      {/* Storage Architecture Overview Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-xl p-4 border border-slate-200/80 shadow-sm flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-500/10 text-blue-600 flex items-center justify-center shrink-0">
            <HardDrive className="w-5 h-5" />
          </div>
          <div>
            <p className="text-[11px] font-bold text-slate-500 uppercase">Original Evidence Storage</p>
            <p className="text-xs font-mono font-semibold text-slate-800">./data/uploads/ (Read-Only)</p>
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 border border-slate-200/80 shadow-sm flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-600 flex items-center justify-center shrink-0">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <p className="text-[11px] font-bold text-slate-500 uppercase">Analysis Workspaces</p>
            <p className="text-xs font-mono font-semibold text-slate-800">./data/working/ (Isolated)</p>
          </div>
        </div>

        <div className="bg-white rounded-xl p-4 border border-slate-200/80 shadow-sm flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-purple-500/10 text-purple-600 flex items-center justify-center shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <p className="text-[11px] font-bold text-slate-500 uppercase">Integrity Algorithm</p>
            <p className="text-xs font-mono font-semibold text-slate-800">SHA-256 Streamed Ingestion</p>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm space-y-4">
        {/* Category Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
          {CATEGORY_TABS.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3.5 py-1.5 rounded-xl font-semibold transition-colors shrink-0 ${
                selectedCategory === cat
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Search, Case Filter & Item Count */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2 border-t border-slate-100">
          <div className="flex items-center gap-3 w-full sm:w-auto">
            {/* Search Input */}
            <div className="relative w-full sm:w-64">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by filename or hash..."
                className="w-full pl-9 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* Case Filter Selector */}
            <select
              value={filterCaseId}
              onChange={(e) => setFilterCaseId(e.target.value)}
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

          <div className="text-xs text-slate-500 font-medium">
            Showing <strong className="text-slate-800">{evidenceItems.length}</strong> registered artifacts
          </div>
        </div>
      </div>

      {/* Evidence Table */}
      <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-xs text-slate-500 font-medium">
            Loading evidence vault...
          </div>
        ) : evidenceItems.length === 0 ? (
          <div className="p-12 text-center">
            <Layers className="w-10 h-10 text-slate-300 mx-auto mb-2" />
            <p className="text-sm font-bold text-slate-700">No Forensic Evidence Registered</p>
            <p className="text-xs text-slate-500 mt-1">
              Select and upload a normal Windows file to compute its cryptographic hash and extract MACB timestamps.
            </p>
            <button
              onClick={() => setIsUploadModalOpen(true)}
              className="mt-4 inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white text-xs font-semibold rounded-lg hover:bg-blue-700"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Ingest First Evidence File</span>
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50/80 border-b border-slate-200 text-[11px] font-bold text-slate-600 uppercase tracking-wider">
                  <th className="py-3 px-5">Identifier & Filename</th>
                  <th className="py-3 px-5">Bound Case</th>
                  <th className="py-3 px-5">Artifact Type</th>
                  <th className="py-3 px-5">Size</th>
                  <th className="py-3 px-5">Cryptographic SHA-256 Hash</th>
                  <th className="py-3 px-5">Classification</th>
                  <th className="py-3 px-5">Ingestion Timestamp</th>
                  <th className="py-3 px-5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-slate-700">
                {evidenceItems.map((e: EvidenceItem) => {
                  const isVerified = verifyStatus?.id === e.id;
                  return (
                    <tr key={e.id} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3.5 px-5">
                        <div className="flex items-center gap-2">
                          <FileText className="w-4 h-4 text-blue-600 shrink-0" />
                          <div>
                            <div
                              onClick={() => navigate(`/evidence/${e.id}`)}
                              className="font-bold text-slate-900 hover:text-blue-600 cursor-pointer"
                            >
                              {e.filename}
                            </div>
                            <span className="font-mono text-[10px] text-slate-400">
                              {e.evidence_number}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="py-3.5 px-5 font-mono text-xs font-semibold text-slate-700">
                        {e.case_number ? (
                          <Link to={`/cases/${e.case_id}`} className="hover:underline text-blue-600">
                            {e.case_number}
                          </Link>
                        ) : (
                          'Unassigned'
                        )}
                      </td>
                      <td className="py-3.5 px-5 text-slate-600">{e.file_type}</td>
                      <td className="py-3.5 px-5 font-mono text-slate-700 font-semibold">
                        {e.readable_size || `${e.file_size_bytes} B`}
                      </td>
                      <td className="py-3.5 px-5 font-mono text-[11px] text-slate-500 max-w-xs truncate" title={e.sha256}>
                        {e.sha256}
                      </td>
                      <td className="py-3.5 px-5">
                        <EvidenceBadge classification={e.classification} />
                      </td>
                      <td className="py-3.5 px-5 font-mono text-[11px] text-slate-500">
                        {new Date(e.created_at).toLocaleString()}
                      </td>
                      <td className="py-3.5 px-5 text-right">
                        <div className="inline-flex items-center gap-2">
                          {isVerified ? (
                            <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-600 bg-emerald-50 px-2 py-1 rounded">
                              <CheckCircle className="w-3.5 h-3.5" />
                              Match
                            </span>
                          ) : (
                            <button
                              onClick={() => verifyMutation.mutate(e.id)}
                              disabled={verifyMutation.isPending}
                              title="Verify Disk SHA-256 Integrity"
                              className="p-1.5 rounded-lg text-slate-400 hover:text-emerald-700 hover:bg-emerald-50 transition-colors"
                            >
                              <RefreshCw className="w-3.5 h-3.5" />
                            </button>
                          )}

                          <button
                            onClick={() => navigate(`/evidence/${e.id}`)}
                            title="Inspect Evidence Dossier"
                            className="inline-flex items-center gap-1 px-2 py-1 bg-blue-50 text-blue-700 hover:bg-blue-100 rounded-lg text-xs font-semibold"
                          >
                            <span>Inspect</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>

                          <button
                            onClick={() => handleDeleteItem(e)}
                            title="Remove from Case Register"
                            className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors"
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

      {/* Ingest Evidence Modal */}
      {isUploadModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-xl w-full p-6 shadow-2xl border border-slate-200 relative animate-in fade-in zoom-in-95 duration-150 space-y-5">
            <button
              onClick={() => setIsUploadModalOpen(false)}
              className="absolute top-5 right-5 text-slate-400 hover:text-slate-600"
            >
              <X className="w-5 h-5" />
            </button>

            <div>
              <h3 className="text-lg font-bold text-slate-900">
                Ingest Forensic Evidence Artifact
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Target file will be safely streamed to <strong className="font-mono">./data/uploads/</strong> (never executed). Cryptographic SHA-256 and MACB timestamps are automatically computed.
              </p>
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                uploadMutation.mutate();
              }}
              className="space-y-4"
            >
              {/* Target Case Selection */}
              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Bind to Investigation Case *
                </label>
                <select
                  required
                  value={targetCaseId}
                  onChange={(e) => setTargetCaseId(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {allCases.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.case_number} — {c.name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Category Dropdown */}
              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Evidence Category
                </label>
                <select
                  value={uploadCategory}
                  onChange={(e) => setUploadCategory(e.target.value)}
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="File">Normal Windows File (PDF, DOCX, TXT, CSV, EXE Metadata, etc.)</option>
                  <option value="Memory Image">Memory Image (.raw, .mem, .dmp)</option>
                  <option value="System Log">System Log (Windows .evtx, syslog)</option>
                  <option value="Cloud Log">Cloud Log (AWS CloudTrail, Azure Monitor)</option>
                  <option value="Network Evidence">Network Evidence (PCAP, NetFlow)</option>
                  <option value="Other">Other Digital Artifact</option>
                </select>
              </div>

              {/* Windows File Picker Zone */}
              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Select Evidence File from Windows *
                </label>
                <div className="border-2 border-dashed border-slate-300 hover:border-blue-500 rounded-xl p-6 text-center bg-slate-50/60 transition-colors cursor-pointer relative">
                  <input
                    type="file"
                    required
                    onChange={handleFileChange}
                    className="absolute inset-0 opacity-0 cursor-pointer w-full h-full"
                  />
                  <div className="flex flex-col items-center">
                    <Upload className="w-8 h-8 text-blue-600 mb-2" />
                    {selectedFile ? (
                      <div className="space-y-1">
                        <p className="text-xs font-bold text-slate-900">{selectedFile.name}</p>
                        <p className="text-[11px] font-mono text-slate-500">
                          {(selectedFile.size / 1024).toFixed(1)} KB — Click to change
                        </p>
                      </div>
                    ) : (
                      <>
                        <p className="text-xs font-bold text-slate-800">
                          Click to select a file from your Windows filesystem
                        </p>
                        <p className="text-[11px] text-slate-500 mt-1">
                          TXT, CSV, JSON, LOG, PDF, RAW, MEM, EVTX, EXE, PNG, JPG (up to 2048 MB)
                        </p>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {/* Acquisition Notes */}
              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1">
                  Investigator Acquisition Notes
                </label>
                <textarea
                  rows={2}
                  value={acquisitionNotes}
                  onChange={(e) => setAcquisitionNotes(e.target.value)}
                  placeholder="Record source host, acquisition tool, drive letter, or sector provenance..."
                  className="w-full px-3.5 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              {/* Footer Buttons */}
              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsUploadModalOpen(false)}
                  className="px-4 py-2 border border-slate-200 text-slate-600 text-xs font-semibold rounded-xl hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploadMutation.isPending || !selectedFile}
                  className="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-xl shadow-md disabled:opacity-50 flex items-center gap-2"
                >
                  {uploadMutation.isPending && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>{uploadMutation.isPending ? 'Calculating Hash & Ingesting...' : 'Ingest Evidence'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
