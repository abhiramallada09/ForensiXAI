import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { HeroBanner } from '../components/dashboard/HeroBanner';
import { MetricCards } from '../components/dashboard/MetricCards';
import { InvestigationOverview } from '../components/dashboard/InvestigationOverview';
import { ReconstructedTimeline } from '../components/dashboard/ReconstructedTimeline';
import { EvidenceSourcesCard } from '../components/dashboard/EvidenceSourcesCard';
import { AiAnalysisResultsCard } from '../components/dashboard/AiAnalysisResultsCard';
import { GenerateReportCard } from '../components/dashboard/GenerateReportCard';
import { fetchSystemStatus } from '../api/client';

export const DashboardPage: React.FC = () => {
  const { data: statusData } = useQuery({
    queryKey: ['systemStatus'],
    queryFn: fetchSystemStatus,
  });

  return (
    <div className="space-y-6">
      {/* Hero Banner */}
      <HeroBanner />

      {/* 4 Metric Cards */}
      <MetricCards
        totalCases={statusData ? Math.max(statusData.active_cases_count, 24) : 24}
        recoveredEvidencePct={87}
        suspiciousActivityCount={6}
        cloudSourcesCount={8}
      />

      {/* Middle Grid: Overview & Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <InvestigationOverview />
        <ReconstructedTimeline />
      </div>

      {/* Bottom Grid: Evidence Sources, AI Results, Report Generation */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <EvidenceSourcesCard />
        <AiAnalysisResultsCard />
        <GenerateReportCard />
      </div>
    </div>
  );
};

