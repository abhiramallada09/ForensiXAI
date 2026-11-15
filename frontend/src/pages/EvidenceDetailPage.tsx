import React, { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  ArrowLeft,
  ShieldCheck,
  Copy,
  Check,
  Clock,
  FileText,
  AlertTriangle,
  Trash2,
  Cpu,
  Lock,
  RefreshCw,
} from 'lucide-react';
import { fetchEvidenceDetail, verifyEvidenceIntegrity, deleteEvidenceItem } from '../api/client';
import { EvidenceBadge } from '../components/common/EvidenceBadge';
import { EvidenceVerificationResult } from '../types/forensics';

export const EvidenceDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<EvidenceVerificationResult | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'metadata' | 'custody'>('overview');

  const { data: evidence, isLoading, isError } = useQuery({
    queryKey: ['evidence', id],
    queryFn: () => fetchEvidenceDetail(id!),
    enabled: !!id,
  });

  const verifyMutation = useMutation({
    mutationFn: () => verifyEvidenceIntegrity(id!),
    onSuccess: (data) => {
      setVerificationResult(data);
    },
    onError: (err: any) => {
      alert(err.message || 'Verification check failed');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteEvidenceItem(id!),
    onSuccess: () => {
      navigate('/evidence');
    },
  });

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleDelete = () => {
    if (!evidence) return;
    if (
      window.confirm(
        `Remove "${evidence.filename}" from the active case register? The original file in data/uploads/ is maintained for forensic chain of custody.`
      )
    ) {
      deleteMutation.mutate();
    }
  };

  if (isLoading) {
    return (
      <div className="bg-white rounded-2xl p-12 text-center text-xs text-slate-500 font-medium">
        Loading forensic evidence dossier...
      </div>
    );
  }

  if (isError || !evidence) {
    return (
      <div className="bg-white rounded-2xl p-12 text-center space-y-3">
        <p className="text-sm font-bold text-slate-700">Evidence Record Not Found</p>
        <Link
          to="/evidence"
          className="inline-flex items-center gap-1.5 text-xs text-blue-600 font-semibold"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Evidence Repository</span>
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <Link
          to="/evidence"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Evidence Repository</span>
        </Link>

        <div className="flex items-center gap-3">
          <button
            onClick={() => verifyMutation.mutate()}
            disabled={verifyMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 active:scale-[0.98] text-white text-xs font-semibold rounded-xl shadow-sm transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${verifyMutation.isPending ? 'animate-spin' : ''}`} />
            <span>{verifyMutation.isPending ? 'Verifying Disk Hash...' : 'Verify SHA-256 Integrity'}</span>
          </button>

          <button
            onClick={handleDelete}
            disabled={deleteMutation.isPending}
            className="inline-flex items-center gap-1.5 px-3 py-2 bg-rose-50 hover:bg-rose-100 text-rose-700 text-xs font-semibold rounded-xl border border-rose-200 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Remove</span>
          </button>
        </div>
      </div>

      {/* Verification Live Alert Banner (when checked) */}
      {verificationResult && (
        <div
          className={`p-4 rounded-2xl border flex items-start gap-3 animate-in fade-in duration-200 ${verificationResult.status === 'MATCH'
              ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
              : 'bg-rose-50 border-rose-300 text-rose-900'
            }`}
        >
          {verificationResult.status === 'MATCH' ? (
            <ShieldCheck className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
          )}
          <div className="flex-1 text-xs space-y-1">
            <div className="flex items-center gap-2 font-bold">
              <span>
                {verificationResult.status === 'MATCH'
                  ? 'Cryptographic Hash Match Confirmed (100% Integrity)'
                  : 'INTEGRITY ALERT: Tampering or Disk Modification Detected!'}
              </span>
              <span className="font-mono text-[11px] opacity-75">
                {new Date(verificationResult.verified_at).toLocaleTimeString()}
              </span>
            </div>
            <p className="leading-relaxed opacity-90">{verificationResult.notes}</p>
            <p className="font-mono text-[11px] break-all pt-1">
              On-Disk Hash: <strong>{verificationResult.computed_sha256}</strong>
            </p>
          </div>
        </div>
      )}

      {/* Main Evidence Dossier Card */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6 border-b border-slate-100 pb-6">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="font-mono text-xs font-bold px-2.5 py-1 rounded-lg bg-blue-500/10 text-blue-700 border border-blue-200">
                {evidence.evidence_number}
              </span>
              <EvidenceBadge classification={evidence.classification} />
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-slate-100 text-slate-700 font-semibold">
                {evidence.file_type}
              </span>
            </div>

            <h2 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-2">
              <FileText className="w-6 h-6 text-blue-600 shrink-0" />
              <span>{evidence.filename}</span>
            </h2>

            {evidence.case_number && (
              <p className="text-xs text-slate-500 font-medium">
                Bound to Case:{' '}
                <Link
                  to={`/cases/${evidence.case_id}`}
                  className="font-bold text-blue-600 hover:underline"
                >
                  {evidence.case_number} ({evidence.case_name})
                </Link>
              </p>
            )}
          </div>

          <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 text-xs space-y-1.5 shrink-0 min-w-[200px]">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
              Forensic Ingestion Status
            </span>
            <div className="flex items-center gap-2 text-emerald-700 font-bold">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span>{evidence.status}</span>
            </div>
            <p className="text-[11px] text-slate-500 font-mono">
              {new Date(evidence.created_at).toLocaleString()}
            </p>
          </div>
        </div>

        {/* 3 Core Forensic Telemetry Cards */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* 1. Cryptographic Hashes Card */}
          <div className="bg-slate-50/70 border border-slate-200 rounded-xl p-5 space-y-3.5">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-900 border-b border-slate-200/80 pb-2">
              <ShieldCheck className="w-4 h-4 text-blue-600" />
              <span>Cryptographic Identity</span>
            </div>

            <div className="space-y-2 text-xs">
              <div>
                <div className="flex items-center justify-between text-[11px] text-slate-500 font-bold mb-0.5">
                  <span>SHA-256 (Primary Vault Hash)</span>
                  <button
                    onClick={() => handleCopy(evidence.sha256, 'sha256')}
                    className="text-blue-600 hover:text-blue-800 flex items-center gap-1 font-semibold"
                  >
                    {copiedField === 'sha256' ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-600" />
                        <span className="text-emerald-600">Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy</span>
                      </>
                    )}
                  </button>
                </div>
                <div className="p-2 bg-white border border-slate-200 rounded-lg font-mono text-[11px] text-slate-800 break-all select-all">
                  {evidence.sha256}
                </div>
              </div>

              {evidence.md5 && (
                <div>
                  <div className="flex items-center justify-between text-[11px] text-slate-500 font-bold mb-0.5">
                    <span>MD5 Hash</span>
                    <button
                      onClick={() => handleCopy(evidence.md5!, 'md5')}
                      className="text-blue-600 hover:text-blue-800 flex items-center gap-1 font-semibold"
                    >
                      {copiedField === 'md5' ? (
                        <Check className="w-3 h-3 text-emerald-600" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                  <div className="p-2 bg-white border border-slate-200 rounded-lg font-mono text-[11px] text-slate-800 select-all">
                    {evidence.md5}
                  </div>
                </div>
              )}

              <div className="pt-1 flex justify-between text-[11px] text-slate-600">
                <span>Total File Size:</span>
                <span className="font-mono font-bold text-slate-900">
                  {evidence.readable_size || `${evidence.file_size_bytes} B`} ({evidence.file_size_bytes.toLocaleString()} bytes)
                </span>
              </div>
            </div>
          </div>

          {/* 2. Filesystem Timestamps (MACB) Card */}
          <div className="bg-slate-50/70 border border-slate-200 rounded-xl p-5 space-y-3.5">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-900 border-b border-slate-200/80 pb-2">
              <Clock className="w-4 h-4 text-emerald-600" />
              <span>Observed Timestamps (MACB)</span>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-bold text-slate-700">Created ($FILE_CREATE)</p>
                  <p className="text-[10px] text-slate-400 font-medium">Filesystem birth timestamp</p>
                </div>
                <p className="font-mono font-bold text-slate-900 text-right">
                  {evidence.created_time
                    ? new Date(evidence.created_time).toLocaleString()
                    : 'Not Available'}
                </p>
              </div>

              <div className="flex items-start justify-between">
                <div>
                  <p className="font-bold text-slate-700">Modified ($FILE_MODIFY)</p>
                  <p className="text-[10px] text-slate-400 font-medium">Last content write</p>
                </div>
                <p className="font-mono font-bold text-slate-900 text-right">
                  {evidence.modified_time
                    ? new Date(evidence.modified_time).toLocaleString()
                    : 'Not Available'}
                </p>
              </div>

              <div className="flex items-start justify-between">
                <div>
                  <p className="font-bold text-slate-700">Accessed ($FILE_ACCESS)</p>
                  <p className="text-[10px] text-slate-400 font-medium">Last metadata/read access</p>
                </div>
                <p className="font-mono font-bold text-slate-900 text-right">
                  {evidence.accessed_time
                    ? new Date(evidence.accessed_time).toLocaleString()
                    : 'Not Available'}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-200/70 text-[10px] text-slate-500 italic">
                * Extracted directly from OS filesystem stat. Ordinary metadata is never categorized as deleted-file reconstruction.
              </div>
            </div>
          </div>

          {/* 3. Forensic Attributes & Entropy Card */}
          <div className="bg-slate-50/70 border border-slate-200 rounded-xl p-5 space-y-3.5">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-900 border-b border-slate-200/80 pb-2">
              <Cpu className="w-4 h-4 text-purple-600" />
              <span>Attributes & Header Telemetry</span>
            </div>

            <div className="space-y-2.5 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-slate-600 font-medium">MIME Type:</span>
                <span className="font-mono font-bold text-slate-800">{evidence.mime_type || 'Unknown'}</span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-slate-600 font-medium">Magic Header (HEX):</span>
                <span className="font-mono font-bold text-blue-700">
                  {evidence.metadata_json?.magic_header_hex || 'N/A'}
                </span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-slate-600 font-medium">Shannon Entropy:</span>
                <span className="font-mono font-bold text-slate-900">
                  {evidence.metadata_json?.entropy !== undefined
                    ? `${evidence.metadata_json.entropy} / 8.0`
                    : 'N/A'}
                </span>
              </div>

              <div className="flex justify-between items-center">
                <span className="text-slate-600 font-medium">Execution Policy:</span>
                <span className="font-bold text-emerald-700 flex items-center gap-1">
                  <Lock className="w-3 h-3" />
                  Read-Only (Non-Executable)
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="border-b border-slate-200 flex gap-4 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('overview')}
            className={`pb-2.5 transition-colors border-b-2 ${activeTab === 'overview'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
          >
            Overview & Acquisition Notes
          </button>
          <button
            onClick={() => setActiveTab('metadata')}
            className={`pb-2.5 transition-colors border-b-2 ${activeTab === 'metadata'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
          >
            Extracted Metadata JSON
          </button>
          <button
            onClick={() => setActiveTab('custody')}
            className={`pb-2.5 transition-colors border-b-2 ${activeTab === 'custody'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
          >
            Chain of Custody Provenance
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="space-y-4 text-xs">
            <div className="bg-slate-50 p-4 rounded-xl space-y-2">
              <p className="font-bold text-slate-800 uppercase text-[11px] tracking-wider">
                Investigator Acquisition Notes
              </p>
              <p className="text-slate-600 leading-relaxed">
                {evidence.notes || 'No acquisition notes recorded upon ingestion.'}
              </p>
            </div>
          </div>
        )}

        {activeTab === 'metadata' && (
          <div className="bg-[#0B132B] rounded-xl p-4 text-slate-200 font-mono text-xs overflow-x-auto">
            <pre className="whitespace-pre-wrap">
              {JSON.stringify(evidence.metadata_json || {}, null, 2)}
            </pre>
          </div>
        )}

        {activeTab === 'custody' && (
          <div className="space-y-3 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="bg-slate-50 p-4 rounded-xl space-y-1">
                <span className="text-[11px] font-bold text-slate-500 uppercase">Evidence Identifier</span>
                <p className="font-mono font-bold text-slate-800">{evidence.evidence_number}</p>
              </div>

              <div className="bg-slate-50 p-4 rounded-xl space-y-1">
                <span className="text-[11px] font-bold text-slate-500 uppercase">Vault Physical Storage</span>
                <p className="font-mono text-slate-700 break-all">{evidence.metadata_json?.filename ? `./data/uploads/...` : 'Local Evidence Vault'}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
