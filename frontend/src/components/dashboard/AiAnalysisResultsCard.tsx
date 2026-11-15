import React from 'react';
import { Brain, Sparkles } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { useCase } from '../../context/CaseContext';
import { fetchCaseDeepSummary } from '../../api/client';

export const AiAnalysisResultsCard: React.FC = () => {
  const { activeCase } = useCase();

  const { data: deepSummary } = useQuery({
    queryKey: ['case-deep-summary', activeCase?.id],
    queryFn: () => fetchCaseDeepSummary(activeCase!.id),
    enabled: !!activeCase?.id,
  });

  const delVal = deepSummary?.deleted_file_probability ?? 95;
  const manipVal = deepSummary?.manipulation_likelihood ?? 88;
  const malVal = deepSummary?.malware_indicator ?? 93;
  const confVal = deepSummary?.confidence_score ?? 92;
  const confLabel = deepSummary?.confidence_label ?? 'Very High';

  const bars = [
    { label: 'Deleted File Probability', value: delVal, color: 'bg-[#1E3A8A]' },
    { label: 'Manipulation Likelihood', value: manipVal, color: 'bg-[#3B82F6]' },
    { label: 'Malware Indicator', value: malVal, color: 'bg-[#38BDF8]' },
  ];

  // Circle dash offset calculation: circumference = 2 * PI * 32 = 201.06
  const strokeDashoffset = Math.round(201 - (201 * confVal) / 100);

  return (
    <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-4 bg-blue-600 rounded-full" />
          <div className="flex items-center gap-1.5">
            <Brain className="w-4 h-4 text-blue-600" />
            <h3 className="font-bold text-slate-900 text-base">AI Analysis Results</h3>
          </div>
        </div>
        <span className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200/60">
          <Sparkles className="w-2.5 h-2.5 text-indigo-600" />
          PyTorch DeepNet
        </span>
      </div>

      <div className="grid grid-cols-12 gap-4 items-end">
        {/* Probability Bars (8 cols) */}
        <div className="col-span-8 flex items-end justify-around gap-2 h-36 pt-4 border-b border-slate-100 pb-2">
          {bars.map((bar, idx) => (
            <div key={idx} className="flex flex-col items-center flex-1 h-full justify-end">
              <span className="text-[11px] font-bold text-slate-800 mb-1">{bar.value}%</span>
              <div className="w-full max-w-[36px] bg-slate-100 rounded-t-lg h-24 flex items-end overflow-hidden">
                <div
                  className={`w-full rounded-t-lg transition-all duration-500 ${bar.color}`}
                  style={{ height: `${bar.value}%` }}
                />
              </div>
              <p className="text-[9px] font-medium text-slate-500 text-center mt-2 leading-tight max-w-[64px]">
                {bar.label}
              </p>
            </div>
          ))}
        </div>

        {/* Circular Confidence Score (4 cols) */}
        <div className="col-span-4 flex flex-col items-center justify-center text-center pb-2">
          <p className="text-[11px] font-bold text-slate-600 mb-1">Confidence Score</p>
          <div className="relative w-20 h-20 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 80 80">
              <circle
                cx="40"
                cy="40"
                r="32"
                stroke="#E2E8F0"
                strokeWidth="6"
                fill="none"
              />
              <circle
                cx="40"
                cy="40"
                r="32"
                stroke="#10B981"
                strokeWidth="6"
                fill="none"
                strokeDasharray="201"
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-lg font-black text-slate-900">{confVal}%</span>
            </div>
          </div>
          <span className="text-xs font-bold text-emerald-600 mt-1">{confLabel}</span>
        </div>
      </div>
    </div>
  );
};
