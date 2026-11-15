import React from 'react';
import { Server } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { fetchSystemStatus } from '../api/client';

export const SettingsPage: React.FC = () => {
  const { data: status } = useQuery({
    queryKey: ['systemStatus'],
    queryFn: fetchSystemStatus,
  });

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm">
        <h2 className="text-xl font-bold text-slate-900 tracking-tight">
          System & Forensic Engine Configuration
        </h2>
        <p className="text-xs text-slate-500 font-medium mt-1">
          Local analysis directories, database connections, and tool paths.
        </p>
      </div>

      <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm space-y-4 max-w-3xl">
        <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
          <Server className="w-5 h-5 text-blue-600" />
          <h3 className="text-sm font-bold text-slate-900">Environment Diagnostics</h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="bg-slate-50 p-3.5 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase">System Status</span>
            <p className="font-bold text-emerald-600 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              {status?.status || 'ONLINE'}
            </p>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase">Database Dialect</span>
            <p className="font-mono text-slate-800">SQLite (Migration ready for PostgreSQL)</p>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase">Evidence Upload Directory</span>
            <p className="font-mono text-slate-800">./data/uploads/ (Read-Only Original)</p>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase">Analysis Working Directory</span>
            <p className="font-mono text-slate-800">./data/working/ (Isolated Workspaces)</p>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase">Application Environment</span>
            <p className="font-mono text-slate-800">{status?.environment || 'development'}</p>
          </div>

          <div className="bg-slate-50 p-3.5 rounded-xl space-y-1">
            <span className="text-[11px] font-bold text-slate-500 uppercase">Backend API Version</span>
            <p className="font-mono text-slate-800">{status?.app_version || '0.1.0'}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

