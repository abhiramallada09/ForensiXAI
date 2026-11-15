import React from 'react';
import { ArrowRight, MapPin, AlertOctagon } from 'lucide-react';
import { Link } from 'react-router-dom';

export const ReconstructedTimeline: React.FC = () => {
  const events = [
    {
      time: '10:02:15 AM',
      title: 'User Login',
      desc: 'User accessed the system',
      dotColor: 'bg-blue-500 ring-blue-100',
    },
    {
      time: '10:03:40 AM',
      title: 'Malicious Process Started',
      desc: 'Suspicious process detected',
      dotColor: 'bg-emerald-500 ring-emerald-100',
    },
    {
      time: '10:04:12 AM',
      title: 'Network Connection',
      desc: 'Connected to external server',
      dotColor: 'bg-rose-500 ring-rose-100',
    },
    {
      time: '10:05:20 AM',
      title: 'File Modified',
      desc: 'System file changed',
      dotColor: 'bg-emerald-500 ring-emerald-100',
    },
    {
      time: '10:06:18 AM',
      title: 'File Deleted',
      desc: 'Evidence of deletion found',
      dotColor: 'bg-slate-400 ring-slate-100',
    },
  ];

  return (
    <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col justify-between">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-4 bg-blue-600 rounded-full" />
          <h3 className="font-bold text-slate-900 text-base">Reconstructed Timeline</h3>
        </div>
        <Link
          to="/timeline"
          className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1 group"
        >
          <span>View Full Timeline</span>
          <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
        </Link>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-center">
        {/* Left: Vertical Event Timeline */}
        <div className="lg:col-span-7 relative pl-3 space-y-3.5">
          {/* Vertical connecting line */}
          <div className="absolute top-2.5 bottom-2.5 left-[19px] w-0.5 bg-slate-200" />

          {events.map((evt, idx) => (
            <div key={idx} className="relative flex items-start gap-3">
              <span
                className={`w-3.5 h-3.5 rounded-full ring-4 shrink-0 mt-0.5 z-10 ${evt.dotColor}`}
              />
              <div className="flex-1">
                <div className="flex items-baseline gap-2">
                  <span className="text-[11px] font-mono font-semibold text-slate-500">
                    {evt.time}
                  </span>
                  <span className="text-xs font-bold text-slate-900">{evt.title}</span>
                </div>
                <p className="text-[11px] text-slate-500 font-medium">{evt.desc}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Right: Geolocation / Cloud Map Widget */}
        <div className="lg:col-span-5 flex flex-col items-center">
          <div className="w-full bg-[#0C1938] rounded-xl p-3 border border-[#1C2C5E] relative overflow-hidden text-white">
            {/* World Map Vector Graphic */}
            <svg className="w-full h-24 text-blue-500/40" viewBox="0 0 200 100" fill="currentColor">
              {/* Simplified world map silhouettes */}
              <circle cx="45" cy="35" r="14" fill="#1A3366" />
              <circle cx="55" cy="65" r="12" fill="#1A3366" />
              <circle cx="105" cy="30" r="16" fill="#1A3366" />
              <circle cx="115" cy="55" r="14" fill="#1A3366" />
              <circle cx="150" cy="40" r="18" fill="#1A3366" />
              <circle cx="165" cy="70" r="10" fill="#1A3366" />
              {/* Glowing signal dots */}
              <circle cx="50" cy="35" r="2.5" fill="#00F0FF" className="animate-ping" />
              <circle cx="50" cy="35" r="2" fill="#00F0FF" />
              <circle cx="110" cy="35" r="2" fill="#2563EB" />
              <circle cx="155" cy="45" r="2.5" fill="#EF4444" />
              {/* Connecting dashed arc */}
              <path d="M50 35 Q100 15 155 45" stroke="#00F0FF" strokeWidth="1" strokeDasharray="2 2" fill="none" opacity="0.7" />
            </svg>

            {/* Location & Risk Footer */}
            <div className="mt-2 pt-2 border-t border-[#1C2C5E] flex items-center justify-between text-xs">
              <div className="flex items-center gap-1 text-slate-300">
                <MapPin className="w-3.5 h-3.5 text-blue-400" />
                <span className="text-[11px] font-medium">Location: <strong>Unknown (Cloud)</strong></span>
              </div>
              <div className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-500/20 border border-rose-500/30 text-rose-300 text-[10px] font-bold">
                <AlertOctagon className="w-3 h-3 text-rose-400" />
                <span>Risk: High</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

