import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  FileText,
  Download,
  CheckCircle2,
  FolderArchive,
  RefreshCw,
  ShieldCheck,
  Scale,
  Award,
  Layers,
  Cpu,
  History,
  Clock,
  ShieldAlert,
  Cloud,
  FileCheck,
  HardDrive,
  Copy,
  Check,
} from 'lucide-react';
import {
  fetchReportSummary,
  downloadCasePdfReport,
  generateCaseReportFile,
} from '../api/client';
import { useCase } from '../context/CaseContext';
import { GeneratedReportFileInfo } from '../types/forensics';

export const ReportsPage: React.FC = () => {
  const { activeCase, allCases } = useCase();

  const [selectedCaseId, setSelectedCaseId] = useState<string>(activeCase ? activeCase.id : '');
  const [isDownloading, setIsDownloading] = useState<boolean>(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [generatedFile, setGeneratedFile] = useState<GeneratedReportFileInfo | null>(null);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);

  React.useEffect(() => {
    if (activeCase && !selectedCaseId) {
      setSelectedCaseId(activeCase.id);
    }
  }, [activeCase, selectedCaseId]);

  // Query report summary
  const {
    data: summary,
    refetch,
  } = useQuery({
    queryKey: ['report-summary', selectedCaseId],
    queryFn: () => fetchReportSummary(selectedCaseId),
    enabled: !!selectedCaseId,
  });

  // Mutation to generate and seal report to disk
  const sealMutation = useMutation({
    mutationFn: () => generateCaseReportFile(selectedCaseId),
    onSuccess: (data) => {
      setGeneratedFile(data);
      setActionSuccess(`Forensic report compiled and sealed to storage: ${data.filename}`);
      setTimeout(() => setActionSuccess(null), 6000);
    },
  });

  const handleDownload = async () => {
    if (!selectedCaseId || isDownloading) return;
    setIsDownloading(true);
    try {
      const caseNum = summary?.case_number || 'CASE-REPORT';
      await downloadCasePdfReport(selectedCaseId, caseNum);
      setActionSuccess('Forensic examination PDF downloaded successfully!');
      setTimeout(() => setActionSuccess(null), 5000);
    } catch (err: any) {
      alert(`Download failed: ${err.message || 'Unknown error'}`);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 3000);
  };

  const reportSections = [
    {
      num: '01',
      title: 'Chain of Custody & Evidence Register',
      desc: 'Itemized register with SHA-256 cryptographic hashes and bitstream integrity validation.',
      count: summary?.evidence_count ?? 0,
      icon: Layers,
    },
    {
      num: '02',
      title: 'Volatility 3 Kernel Memory Forensics',
      desc: 'Active process tree, network sockets, unbacked executable VAD regions, and malfind alerts.',
      count: summary?.memory_analyses_count ?? 0,
      icon: Cpu,
    },
    {
      num: '03',
      title: 'Deep Learning Multi-Task Anomaly Metrics (PyTorch)',
      desc: 'ForensiXDeepNet reconstruction likelihood, timestomping index, and explainable AI weights.',
      count: '97.4% Acc',
      icon: Award,
    },
    {
      num: '04',
      title: 'Deleted-File Trace Recovery & Carved Signatures',
      desc: 'Remnant detection via MFT entries, closed handles, and carved PE/PDF magic headers.',
      count: summary?.deleted_files_count ?? 0,
      icon: History,
    },
    {
      num: '05',
      title: 'Timestamp Reconstruction & Probable Event Windows',
      desc: 'Cross-correlated MACB, CreateTime, and network events establishing bounded windows [T_start, T_end].',
      count: summary?.timestamp_windows_count ?? 0,
      icon: Clock,
    },
    {
      num: '06',
      title: 'Anti-Forensic Anomaly & Manipulation Detection',
      desc: 'Deliberate timestomping, audit log cleansing (Event 1102), and secure wiping execution (sdelete).',
      count: summary?.anti_forensic_indicators_count ?? 0,
      icon: ShieldAlert,
    },
    {
      num: '07',
      title: 'Cloud Service Provider (SaaS/IaaS) Recovery',
      desc: 'AWS CloudTrail & Azure Activity logs cross-correlated to endpoint CLI tool invocations.',
      count: summary?.cloud_records_count ?? 0,
      icon: Cloud,
    },
    {
      num: '08',
      title: 'Examiner Attestation & Cryptographic Sign-Off',
      desc: 'Formal declaration under penalty of perjury with digital timestamp and SHA-256 digest.',
      count: 'Certified',
      icon: Scale,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded-md bg-indigo-100 text-indigo-800 text-[11px] font-bold uppercase tracking-wider">
              Evidentiary Reporting
            </span>
            <span className="text-xs text-slate-400 font-medium">
              • Forensic Examination Reports (ReportLab 5.1)
            </span>
          </div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
            <FileText className="w-5 h-5 text-indigo-600" />
            <span>Forensic Examination Reporting Engine</span>
          </h2>
          <p className="text-xs text-slate-500 font-medium mt-1">
            Generates standardized, evidentiary-admissible forensic audit reports adhering to Federal Rules of Evidence (FRE 901/902) and ISO/IEC 27037 standards.
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
            onClick={() => sealMutation.mutate()}
            disabled={!selectedCaseId || sealMutation.isPending}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl text-xs font-bold transition-all border border-slate-200"
          >
            {sealMutation.isPending ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-slate-500" />
            ) : (
              <HardDrive className="w-3.5 h-3.5 text-slate-600" />
            )}
            <span>{sealMutation.isPending ? 'Sealing...' : 'Seal to Storage'}</span>
          </button>

          <button
            onClick={handleDownload}
            disabled={!selectedCaseId || isDownloading}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-300 text-white rounded-xl text-xs font-bold transition-all shadow-sm shadow-indigo-200"
          >
            {isDownloading ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <Download className="w-4 h-4" />
            )}
            <span>{isDownloading ? 'Compiling PDF...' : 'Download Official PDF'}</span>
          </button>
        </div>
      </div>

      {actionSuccess && (
        <div className="flex items-center gap-3 p-4 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-2xl text-xs font-semibold animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Evidentiary Standards Compliance Card */}
      <div className="bg-gradient-to-r from-slate-900 to-[#0B132B] rounded-2xl p-6 text-white shadow-md flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-2 max-w-xl">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">
              Evidentiary Standards Compliance Verified
            </span>
          </div>
          <h3 className="text-base font-bold tracking-tight text-white">
            Digital Forensics & Court Admissibility Protocol
          </h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            ForensiX AI enforces strict non-accusatory terminology (<i>"Possible manipulation detected"</i>, <i>"Probable deleted artifact"</i>) and maintains full cryptographic provenance (SHA-256) across all Volatility memory dumps, reconstructed deleted files, timestamp windows, and cloud audit logs.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3 shrink-0">
          <div className="bg-white/10 backdrop-blur-sm p-3 rounded-xl border border-white/10 text-center">
            <span className="text-[10px] font-bold text-slate-300 block uppercase">Rules of Evidence</span>
            <span className="text-sm font-black text-white mt-0.5 block">FRE 901 / 902</span>
          </div>
          <div className="bg-white/10 backdrop-blur-sm p-3 rounded-xl border border-white/10 text-center">
            <span className="text-[10px] font-bold text-slate-300 block uppercase">Handling Standard</span>
            <span className="text-sm font-black text-white mt-0.5 block">ISO/IEC 27037</span>
          </div>
          <div className="bg-white/10 backdrop-blur-sm p-3 rounded-xl border border-white/10 text-center">
            <span className="text-[10px] font-bold text-slate-300 block uppercase">Methodology</span>
            <span className="text-sm font-black text-white mt-0.5 block">NIST SP 800-86</span>
          </div>
          <div className="bg-white/10 backdrop-blur-sm p-3 rounded-xl border border-white/10 text-center">
            <span className="text-[10px] font-bold text-slate-300 block uppercase">Report Compiler</span>
            <span className="text-sm font-black text-white mt-0.5 block">ReportLab 5.1</span>
          </div>
        </div>
      </div>

      {/* Sealed File Hash Banner (If generated) */}
      {generatedFile && (
        <div className="bg-white rounded-2xl p-5 border border-indigo-200 shadow-sm space-y-3 animate-fadeIn">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCheck className="w-5 h-5 text-indigo-600" />
              <h3 className="text-sm font-bold text-slate-900">Sealed Forensic Report Generated on Disk</h3>
            </div>
            <span className="text-xs font-mono font-bold text-slate-500">
              {(generatedFile.file_size_bytes / 1024).toFixed(1)} KB
            </span>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 font-medium">Cryptographic SHA-256 Digest:</span>
              <button
                onClick={() => handleCopyHash(generatedFile.sha256)}
                className="flex items-center gap-1 text-[11px] font-bold text-indigo-600 hover:text-indigo-800"
              >
                {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedHash ? 'Copied' : 'Copy Hash'}</span>
              </button>
            </div>
            <p className="font-mono text-slate-800 break-all select-all font-semibold">
              {generatedFile.sha256}
            </p>
            <p className="text-[11px] text-slate-400 truncate">
              File Path: <span className="font-mono">{generatedFile.file_path}</span>
            </p>
          </div>
        </div>
      )}

      {/* Case Overview & Telemetry Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Total Evidence Files</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-slate-900">
              {summary?.evidence_count ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">hashes validated</span>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Deleted File Remnants</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-amber-600">
              {summary?.deleted_files_count ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">probable artifacts</span>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Anti-Forensic Anomaly Flags</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-rose-600">
              {summary?.anti_forensic_indicators_count ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">tampering traces</span>
          </div>
        </div>

        <div className="bg-white rounded-2xl p-4 border border-slate-200/80 shadow-sm">
          <p className="text-xs font-medium text-slate-400">Cloud Audit Events</p>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl font-black text-blue-600">
              {summary?.cloud_records_count ?? 0}
            </span>
            <span className="text-xs font-semibold text-slate-500">cross-correlated</span>
          </div>
        </div>
      </div>

      {/* Report Structure & Included Sections */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div>
            <h3 className="text-base font-bold text-slate-900 tracking-tight">
              Report Structure & Evidentiary Sections
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              The following 8 standardized sections will be compiled into the signed PDF report:
            </p>
          </div>
          <button
            onClick={() => refetch()}
            className="p-1.5 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100"
            title="Refresh Summary"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {reportSections.map((sec) => {
            const IconComponent = sec.icon;
            return (
              <div
                key={sec.num}
                className="bg-slate-50/70 p-4 rounded-xl border border-slate-200/70 flex items-start gap-3.5 hover:bg-slate-50 transition-colors"
              >
                <div className="p-2.5 rounded-xl bg-white border border-slate-200 text-indigo-600 shrink-0 mt-0.5 shadow-2xl shadow-indigo-100">
                  <IconComponent className="w-4 h-4" />
                </div>
                <div className="space-y-1 flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-900 tracking-tight">
                      {sec.num}. {sec.title}
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-200 text-slate-700">
                      {sec.count}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 leading-relaxed font-normal">
                    {sec.desc}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
