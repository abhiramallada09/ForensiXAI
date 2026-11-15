import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Search,
  FolderArchive,
  FileText,
  BarChart3,
  Settings,
  Info,
  Layers,
  Cpu,
  History,
  GitCompare,
  FileX2,
  Clock,
  ShieldAlert,
  Cloud,
} from 'lucide-react';
import { useCase } from '../../context/CaseContext';

interface SidebarProps {
  systemStatusText?: string;
  isOnline?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  systemStatusText = 'System Online',
  isOnline = true,
}) => {
  const { activeCase } = useCase();

  const mainNavItems = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/cases/new', label: 'New Investigation', icon: Search },
    { to: '/cases', label: 'Cases', icon: FolderArchive },
    { to: '/evidence', label: 'Evidence', icon: Layers },
    { to: '/memory', label: 'Memory Analysis', icon: Cpu },
    { to: '/timeline', label: 'Timeline', icon: History },
    { to: '/correlation', label: 'Correlation', icon: GitCompare },
    { to: '/deleted-files', label: 'Deleted Files', icon: FileX2 },
    { to: '/timestamps', label: 'Timestamps', icon: Clock },
    { to: '/anti-forensics', label: 'Anti-Forensics', icon: ShieldAlert },
    { to: '/cloud', label: 'Cloud Evidence', icon: Cloud },
    { to: '/reports', label: 'Reports', icon: FileText },
    { to: '/analytics', label: 'Analytics', icon: BarChart3 },
    { to: '/settings', label: 'Settings', icon: Settings },
    { to: '/about', label: 'About', icon: Info },
  ];

  return (
    <aside className="w-64 bg-[#0B132B] text-slate-300 flex flex-col shrink-0 h-screen sticky top-0 border-r border-[#15234A] select-none z-20">
      {/* Brand Header */}
      <div className="p-5 flex flex-col items-center border-b border-[#15234A]/80 text-center">
        {/* Shield with Fingerprint pattern */}
        <div className="w-14 h-14 relative flex items-center justify-center mb-3">
          <div className="absolute inset-0 bg-blue-600/20 blur-md rounded-full" />
          <svg className="w-12 h-12 text-[#2B79FF] relative" viewBox="0 0 48 48" fill="none">
            <path
              d="M24 4L8 10V22C8 32.5 14.8 42.2 24 45C33.2 42.2 40 32.5 40 22V10L24 4Z"
              stroke="currentColor"
              strokeWidth="2.5"
              fill="#0E1E45"
            />
            <path
              d="M24 16C21.8 16 20 17.8 20 20V27C20 29.2 21.8 31 24 31C26.2 31 28 29.2 28 27V20C28 17.8 26.2 16 24 16Z"
              stroke="#59B2FF"
              strokeWidth="1.75"
              strokeLinecap="round"
            />
            <path
              d="M16 22C16 17.6 19.6 14 24 14C28.4 14 32 17.6 32 22V26"
              stroke="#59B2FF"
              strokeWidth="1.75"
              strokeLinecap="round"
            />
            <path
              d="M24 20V26"
              stroke="#A5DBFF"
              strokeWidth="1.75"
              strokeLinecap="round"
            />
          </svg>
        </div>
        <h1 className="text-white font-bold text-lg tracking-tight leading-snug">
          Memory Forensics AI
        </h1>
        <p className="text-[11px] text-[#5A7FB3] font-medium tracking-wide mt-0.5">
          Investigate • Reconstruct • Reveal
        </p>
      </div>

      {/* Navigation Links */}
      <div className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
        {mainNavItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3.5 px-3.5 py-2.5 rounded-xl font-medium text-sm transition-all duration-150 ${
                  isActive
                    ? 'bg-[#1E50FF] text-white shadow-lg shadow-blue-600/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-[#14234E]/60'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </div>

      {/* Active Case Footer Bar */}
      {activeCase && (
        <div className="mx-3 px-3 py-2 rounded-xl bg-[#0D1A3B] border border-[#1A2E63] text-xs">
          <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
            Current Case
          </div>
          <div className="font-bold text-white truncate text-xs mt-0.5">
            {activeCase.name}
          </div>
          <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mt-0.5">
            <span>{activeCase.case_number}</span>
            <span className="text-blue-400 font-sans font-semibold">{activeCase.status}</span>
          </div>
        </div>
      )}

      {/* Footer Cyber Widget */}
      <div className="p-3.5 m-3 rounded-2xl bg-[#111C3D] border border-[#1C2C5E] relative overflow-hidden">
        <div className="flex items-center justify-between mb-2">
          {/* Cyber Server Illustration */}
          <div className="w-full flex items-center justify-center py-2 opacity-90">
            <svg className="w-16 h-10 text-cyan-400" viewBox="0 0 64 40" fill="none">
              <rect x="14" y="6" width="36" height="8" rx="2" stroke="#3B82F6" strokeWidth="1.5" fill="#0C1B3E" />
              <rect x="14" y="16" width="36" height="8" rx="2" stroke="#3B82F6" strokeWidth="1.5" fill="#0C1B3E" />
              <rect x="14" y="26" width="36" height="8" rx="2" stroke="#3B82F6" strokeWidth="1.5" fill="#0C1B3E" />
              <circle cx="20" cy="10" r="1.5" fill="#00F0FF" />
              <circle cx="25" cy="10" r="1.5" fill="#3B82F6" />
              <circle cx="20" cy="20" r="1.5" fill="#00F0FF" />
              <circle cx="25" cy="20" r="1.5" fill="#3B82F6" />
              <circle cx="20" cy="30" r="1.5" fill="#00F0FF" />
              <circle cx="25" cy="30" r="1.5" fill="#3B82F6" />
            </svg>
          </div>
        </div>
        <div className="text-center">
          <p className="text-[12px] font-semibold text-slate-200">
            Powered by Deep Learning
          </p>
          <div className="mt-1 flex items-center justify-center gap-1.5 text-[11px] font-medium text-emerald-400">
            <span className={`w-2 h-2 rounded-full ${isOnline ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
            <span>{systemStatusText}</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
