import React from 'react';
import { CheckCircle2, FileText, Clock, AlertTriangle, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export const InvestigationOverview: React.FC = () => {
  const steps = [
    { label: 'Memory Dump Analyzed', done: true },
    { label: 'Artifacts Extracted', done: true },
    { label: 'Deep Learning Analysis', done: true },
    { label: 'Timestamp Correlation', done: true },
    { label: 'Anti-Forensic Check', done: true },
    { label: 'Report Generated', done: true },
  ];

  return (
    <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-4 bg-blue-600 rounded-full" />
          <h3 className="font-bold text-slate-900 text-base">Investigation Overview</h3>
        </div>
        <Link
          to="/cases"
          className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1 group"
        >
          <span>View Details</span>
          <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
        </Link>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-5 items-center">
        {/* Left: Circular Progress Ring */}
        <div className="md:col-span-4 flex flex-col items-center justify-center text-center">
          <div className="relative w-28 h-28 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="40"
                stroke="#E2E8F0"
                strokeWidth="8"
                fill="none"
              />
              <circle
                cx="50"
                cy="50"
                r="40"
                stroke="#10B981"
                strokeWidth="8"
                fill="none"
                strokeDasharray="251.2"
                strokeDashoffset="20" // ~92%
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-black text-slate-900 tracking-tight">92%</span>
            </div>
          </div>
          <p className="mt-2 text-xs font-bold text-slate-800">Analysis Complete</p>
          <div className="mt-1 flex items-center gap-1.5 text-[11px] text-slate-500 font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span>Completed in 2m 14s</span>
          </div>
        </div>

        {/* Center: Stage Verification Checklist */}
        <div className="md:col-span-4 space-y-2 border-t md:border-t-0 md:border-l border-slate-100 pt-3 md:pt-0 md:pl-4">
          {steps.map((step, idx) => (
            <div key={idx} className="flex items-center gap-2 text-xs font-medium text-slate-700">
              <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
              <span>{step.label}</span>
            </div>
          ))}
        </div>

        {/* Right: Key Findings Box */}
        <div className="md:col-span-4 bg-[#F8FAFC] border border-slate-200/70 rounded-xl p-3.5 space-y-2.5">
          <p className="text-[11px] font-bold text-slate-800 uppercase tracking-wider mb-1">
            Key Findings
          </p>

          <Link
            to="/deleted-files"
            className="flex items-start gap-2.5 hover:bg-slate-100/70 p-1 rounded-lg transition-colors group cursor-pointer"
          >
            <div className="w-6 h-6 rounded-lg bg-blue-500/10 text-blue-600 flex items-center justify-center shrink-0 mt-0.5 group-hover:scale-105 transition-transform">
              <FileText className="w-3.5 h-3.5" />
            </div>
            <div>
              <p className="text-xs font-bold text-slate-900 group-hover:text-blue-600 transition-colors">Deleted File Detected</p>
              <p className="text-[10px] text-slate-500 font-medium">(High Confidence)</p>
            </div>
          </Link>

          <Link
            to="/timestamps"
            className="flex items-start gap-2.5 hover:bg-slate-100/70 p-1 rounded-lg transition-colors group cursor-pointer"
          >
            <div className="w-6 h-6 rounded-lg bg-amber-500/10 text-amber-600 flex items-center justify-center shrink-0 mt-0.5 group-hover:scale-105 transition-transform">
              <Clock className="w-3.5 h-3.5" />
            </div>
            <div>
              <p className="text-xs font-bold text-slate-900 group-hover:text-amber-600 transition-colors">Timestamp Anomaly</p>
              <p className="text-[10px] text-slate-500 font-medium">(Possible Manipulation)</p>
            </div>
          </Link>

          <div className="flex items-start gap-2.5">
            <div className="w-6 h-6 rounded-lg bg-rose-500/10 text-rose-600 flex items-center justify-center shrink-0 mt-0.5">
              <AlertTriangle className="w-3.5 h-3.5" />
            </div>
            <div>
              <p className="text-xs font-bold text-slate-900">Suspicious Process</p>
              <p className="text-[10px] text-slate-500 font-medium">(Malware Activity)</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

