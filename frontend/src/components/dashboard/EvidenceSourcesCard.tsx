import React from 'react';
import { CheckCircle2, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export const EvidenceSourcesCard: React.FC = () => {
  const sources = [
    { label: 'Memory Image', sub: '(memory.raw)' },
    { label: 'System Logs', sub: '(windows.evtx)' },
    { label: 'Cloud Logs', sub: '(AWS CloudTrail)' },
    { label: 'File Artifacts', sub: '(extracted files)' },
  ];

  return (
    <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-4 bg-blue-600 rounded-full" />
          <h3 className="font-bold text-slate-900 text-base">Evidence Sources</h3>
        </div>
        <Link
          to="/evidence"
          className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1 group"
        >
          <span>View All</span>
          <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
        </Link>
      </div>

      <div className="flex items-center justify-between gap-4">
        {/* Checklist */}
        <div className="space-y-3">
          {sources.map((src, idx) => (
            <div key={idx} className="flex items-center gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
              <div>
                <span className="text-xs font-bold text-slate-800">{src.label} </span>
                <span className="text-[11px] font-mono text-slate-500">{src.sub}</span>
              </div>
            </div>
          ))}
        </div>

        {/* 3D Server Graphic */}
        <div className="w-24 h-24 relative flex items-center justify-center shrink-0">
          <div className="absolute inset-0 bg-blue-500/10 rounded-full blur-xl" />
          <svg className="w-20 h-20 text-blue-600 relative" viewBox="0 0 80 80" fill="none">
            {/* Top Server Tray */}
            <path d="M20 22L40 12L60 22L40 32L20 22Z" fill="#2563EB" />
            <path d="M20 22L40 32V38L20 28V22Z" fill="#1D4ED8" />
            <path d="M60 22L40 32V38L60 28V22Z" fill="#1E40AF" />
            <circle cx="28" cy="27" r="1.5" fill="#60A5FA" />
            <circle cx="33" cy="29.5" r="1.5" fill="#34D399" />

            {/* Middle Server Tray */}
            <path d="M20 36L40 26L60 36L40 46L20 36Z" fill="#3B82F6" />
            <path d="M20 36L40 46V52L20 42V36Z" fill="#2563EB" />
            <path d="M60 36L40 46V52L60 42V36Z" fill="#1D4ED8" />
            <circle cx="28" cy="41" r="1.5" fill="#60A5FA" />
            <circle cx="33" cy="43.5" r="1.5" fill="#34D399" />

            {/* Bottom Server Tray */}
            <path d="M20 50L40 40L60 50L40 60L20 50Z" fill="#60A5FA" />
            <path d="M20 50L40 60V66L20 56V50Z" fill="#3B82F6" />
            <path d="M60 50L40 60V66L60 56V50Z" fill="#2563EB" />
            <circle cx="28" cy="55" r="1.5" fill="#93C5FD" />
            <circle cx="33" cy="57.5" r="1.5" fill="#34D399" />
          </svg>
        </div>
      </div>
    </div>
  );
};

