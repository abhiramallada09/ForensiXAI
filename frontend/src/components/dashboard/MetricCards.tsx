import React from 'react';
import { Folder, ShieldCheck, ShieldAlert, Cloud, ArrowUpRight } from 'lucide-react';

interface MetricCardsProps {
  totalCases?: number;
  recoveredEvidencePct?: number;
  suspiciousActivityCount?: number;
  cloudSourcesCount?: number;
}

export const MetricCards: React.FC<MetricCardsProps> = ({
  totalCases = 24,
  recoveredEvidencePct = 87,
  suspiciousActivityCount = 6,
  cloudSourcesCount = 8,
}) => {
  const cards = [
    {
      label: 'Total Cases',
      value: totalCases.toString(),
      trend: '+12%',
      trendPositive: true,
      icon: Folder,
      iconBg: 'bg-blue-500/10 text-blue-600',
      sparklineColor: '#2563EB',
      points: '0,18 15,14 30,16 45,9 60,11 75,4 90,7',
    },
    {
      label: 'Recovered Evidence',
      value: `${recoveredEvidencePct}%`,
      trend: '+5%',
      trendPositive: true,
      icon: ShieldCheck,
      iconBg: 'bg-emerald-500/10 text-emerald-600',
      sparklineColor: '#10B981',
      points: '0,17 15,15 30,12 45,14 60,8 75,10 90,3',
    },
    {
      label: 'Suspicious Activity',
      value: suspiciousActivityCount.toString(),
      trend: '↑ 2%',
      trendPositive: false, // warning
      icon: ShieldAlert,
      iconBg: 'bg-rose-500/10 text-rose-600',
      sparklineColor: '#EF4444',
      points: '0,19 15,16 30,17 45,11 60,13 75,7 90,5',
    },
    {
      label: 'Cloud Sources',
      value: cloudSourcesCount.toString(),
      trend: '+1%',
      trendPositive: true,
      icon: Cloud,
      iconBg: 'bg-cyan-500/10 text-cyan-600',
      sparklineColor: '#06B6D4',
      points: '0,18 15,16 30,14 45,15 60,10 75,11 90,6',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className="bg-white rounded-2xl p-5 border border-slate-200/80 shadow-sm flex items-center justify-between hover:shadow-md transition-shadow"
          >
            <div className="flex items-center gap-3.5">
              <div className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0 ${card.iconBg}`}>
                <Icon className="w-6 h-6" />
              </div>
              <div>
                <p className="text-xs text-slate-500 font-medium mb-0.5">{card.label}</p>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-slate-900 tracking-tight">{card.value}</span>
                  <span
                    className={`inline-flex items-center text-[11px] font-semibold ${
                      card.trendPositive ? 'text-emerald-600' : 'text-rose-600'
                    }`}
                  >
                    <ArrowUpRight className="w-3 h-3 stroke-[2.5]" />
                    {card.trend}
                  </span>
                </div>
              </div>
            </div>

            {/* Mini Sparkline Curve */}
            <div className="w-16 h-8 shrink-0">
              <svg className="w-full h-full overflow-visible" viewBox="0 0 90 22">
                <polyline
                  fill="none"
                  stroke={card.sparklineColor}
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  points={card.points}
                />
              </svg>
            </div>
          </div>
        );
      })}
    </div>
  );
};

