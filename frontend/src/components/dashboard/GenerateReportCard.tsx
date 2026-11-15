import React from 'react';
import { FileText, Download, Mail, Scale } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const GenerateReportCard: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center gap-2 mb-2">
        <div className="w-1.5 h-4 bg-blue-600 rounded-full" />
        <div className="flex items-center gap-1.5">
          <FileText className="w-4 h-4 text-blue-600" />
          <h3 className="font-bold text-slate-900 text-base">Generate Report</h3>
        </div>
      </div>

      <div className="flex items-center justify-between gap-4 my-2">
        <p className="text-xs text-slate-500 font-medium leading-relaxed max-w-[180px]">
          Download a detailed forensic report with findings and evidence summary.
        </p>

        {/* Scales of Justice Icon */}
        <div className="w-16 h-16 rounded-2xl bg-amber-500/10 flex items-center justify-center shrink-0 border border-amber-300/40 text-amber-700">
          <Scale className="w-9 h-9" />
        </div>
      </div>

      {/* Buttons */}
      <div className="space-y-2 pt-2">
        <button
          onClick={() => navigate('/reports')}
          className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-[#0B132B] hover:bg-[#15234A] text-white text-xs font-semibold transition-all shadow-sm"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Download Report</span>
        </button>

        <button
          onClick={() => alert('ForensiX AI: Report dispatched to configured investigator mail relay.')}
          className="w-full flex items-center justify-center gap-2 py-2 px-4 rounded-xl border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-semibold transition-all"
        >
          <Mail className="w-3.5 h-3.5 text-slate-500" />
          <span>Email Report</span>
        </button>
      </div>
    </div>
  );
};
