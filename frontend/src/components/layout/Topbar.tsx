import React, { useState } from 'react';
import {
  Search,
  Bell,
  ChevronDown,
  Shield,
  FolderArchive,
  Check,
  LogOut,
  User as UserIcon,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useCase } from '../../context/CaseContext';
import { useAuth } from '../../context/AuthContext';

export const Topbar: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { activeCase, allCases, setActiveCaseId } = useCase();
  const [isCaseDropdownOpen, setIsCaseDropdownOpen] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);

  const displayName = user?.full_name || user?.username || 'A. Abhiram';
  const displayRole = user?.role || 'Lead Forensic Examiner';

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="h-16 bg-[#0B132B] border-b border-[#15234A] px-6 flex items-center justify-between sticky top-0 z-30 text-slate-100">
      {/* Search Bar */}
      <div className="relative w-full max-w-xs md:max-w-sm">
        <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
          <Search className="w-4 h-4" />
        </div>
        <input
          type="text"
          placeholder="Search cases, files or evidence..."
          className="w-full pl-10 pr-4 py-2 bg-[#121E42] border border-[#1E2E5C] rounded-xl text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
        />
      </div>

      {/* Active Case Selector & Status Badge */}
      <div className="hidden lg:flex items-center gap-3">
        {activeCase ? (
          <div className="relative">
            <button
              onClick={() => setIsCaseDropdownOpen(!isCaseDropdownOpen)}
              className="flex items-center gap-2.5 px-3 py-1.5 rounded-xl bg-[#131F45] border border-[#1F3169] text-xs hover:border-blue-500 transition-all text-slate-200 cursor-pointer"
            >
              <FolderArchive className="w-3.5 h-3.5 text-blue-400 shrink-0" />
              <span className="font-semibold text-slate-100 max-w-[150px] truncate">
                {activeCase.case_number}
              </span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-300">
                {activeCase.status}
              </span>
              <ChevronDown className="w-3 h-3 text-slate-400" />
            </button>

            {/* Quick Switch Dropdown */}
            {isCaseDropdownOpen && (
              <div className="absolute left-0 mt-2 w-72 rounded-2xl bg-[#0E1A3D] border border-[#1D2F66] shadow-2xl py-2 z-50 text-xs">
                <div className="px-3.5 py-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400 border-b border-[#1D2F66]">
                  Switch Active Investigation
                </div>
                <div className="max-h-60 overflow-y-auto py-1">
                  {allCases.map((c) => (
                    <button
                      key={c.id}
                      onClick={() => {
                        setActiveCaseId(c.id);
                        setIsCaseDropdownOpen(false);
                      }}
                      className="w-full text-left px-3.5 py-2 hover:bg-[#152554] flex items-center justify-between text-slate-200 transition-colors"
                    >
                      <div className="truncate mr-2">
                        <div className="font-bold text-white truncate">{c.name}</div>
                        <div className="text-[10px] font-mono text-slate-400">{c.case_number}</div>
                      </div>
                      {c.id === activeCase.id && (
                        <Check className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                      )}
                    </button>
                  ))}
                </div>
                <div className="border-t border-[#1D2F66] p-2">
                  <button
                    onClick={() => {
                      setIsCaseDropdownOpen(false);
                      navigate('/cases');
                    }}
                    className="w-full py-1 text-center text-blue-400 hover:text-blue-300 font-semibold text-[11px]"
                  >
                    View All Cases →
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <span className="text-xs text-slate-400 italic font-mono">No active case</span>
        )}
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Notification Bell */}
        <button
          className="relative p-2 rounded-xl text-slate-400 hover:text-white hover:bg-[#15234A] transition-colors"
          title="Investigation Alerts"
        >
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-blue-500 rounded-full ring-2 ring-[#0B132B]" />
        </button>

        {/* Vertical Divider */}
        <div className="h-6 w-px bg-[#1D2B57]" />

        {/* User Profile & Dropdown */}
        <div className="relative">
          <button
            onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
            className="flex items-center gap-3 cursor-pointer group p-1 rounded-xl hover:bg-[#131F45] transition-all text-left"
          >
            <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center text-white font-semibold text-xs ring-2 ring-blue-400/30">
              <Shield className="w-4 h-4" />
            </div>
            <div className="hidden sm:block text-left">
              <div className="text-xs font-semibold text-white group-hover:text-blue-400 transition-colors">
                {displayName}
              </div>
              <div className="text-[10px] text-slate-400 font-medium">
                {displayRole}
              </div>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-white transition-colors" />
          </button>

          {/* User Profile Dropdown */}
          {isUserMenuOpen && (
            <div className="absolute right-0 mt-2 w-64 rounded-2xl bg-[#0E1A3D] border border-[#1D2F66] shadow-2xl py-2 z-50 text-xs">
              <div className="px-4 py-2.5 border-b border-[#1D2F66]">
                <div className="font-bold text-white text-sm">{displayName}</div>
                <div className="text-[11px] text-blue-400 font-mono">{user?.email || 'investigator@forensix.ai'}</div>
                <div className="text-[10px] text-slate-400 mt-1 uppercase font-semibold tracking-wider">
                  {displayRole}
                </div>
              </div>

              <div className="p-1.5">
                <button
                  onClick={() => {
                    setIsUserMenuOpen(false);
                    navigate('/settings');
                  }}
                  className="w-full text-left px-3 py-2 rounded-xl hover:bg-[#152554] text-slate-300 hover:text-white flex items-center gap-2 transition-colors"
                >
                  <UserIcon className="w-3.5 h-3.5 text-blue-400" />
                  <span>Profile & Settings</span>
                </button>

                <button
                  onClick={handleLogout}
                  className="w-full text-left px-3 py-2 rounded-xl hover:bg-rose-500/10 text-rose-300 hover:text-rose-200 flex items-center gap-2 transition-colors mt-1"
                >
                  <LogOut className="w-3.5 h-3.5 text-rose-400" />
                  <span className="font-semibold">Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
