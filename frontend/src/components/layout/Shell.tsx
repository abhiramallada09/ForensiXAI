import React from 'react';
import { Outlet } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { fetchSystemStatus } from '../../api/client';

export const Shell: React.FC = () => {
  const { data: statusData } = useQuery({
    queryKey: ['systemStatus'],
    queryFn: fetchSystemStatus,
    refetchInterval: 15000,
  });

  const isOnline = statusData ? statusData.status === 'ONLINE' : true;
  const statusLabel = isOnline ? 'System Online' : 'System Degraded';

  return (
    <div className="flex min-h-screen bg-[#F4F7FC]">
      {/* Fixed Sidebar */}
      <Sidebar isOnline={isOnline} systemStatusText={statusLabel} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        <Topbar />
        <main className="flex-1 p-6 md:p-8 max-w-[1600px] w-full mx-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

