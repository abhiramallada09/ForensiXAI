import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './context/AuthContext';
import { CaseProvider } from './context/CaseContext';
import { Shell } from './components/layout/Shell';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { CasesPage } from './pages/CasesPage';
import { CaseDetailPage } from './pages/CaseDetailPage';
import { EvidencePage } from './pages/EvidencePage';
import { EvidenceDetailPage } from './pages/EvidenceDetailPage';
import { MemoryAnalysisPage } from './pages/MemoryAnalysisPage';
import { TimelinePage } from './pages/TimelinePage';
import { CorrelationPage } from './pages/CorrelationPage';
import { DeletedFilesPage } from './pages/DeletedFilesPage';
import { TimestampReconstructionPage } from './pages/TimestampReconstructionPage';
import { AntiForensicsPage } from './pages/AntiForensicsPage';
import { CloudEvidencePage } from './pages/CloudEvidencePage';
import { ReportsPage } from './pages/ReportsPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { SettingsPage } from './pages/SettingsPage';
import { AboutPage } from './pages/AboutPage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 15,
      retry: 1,
    },
  },
});

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#070D1F] flex items-center justify-center text-slate-400 text-xs">
        <div className="flex items-center gap-2.5">
          <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <span>Verifying investigator session...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <CaseProvider>
          <BrowserRouter>
            <Routes>
              {/* Public Authentication Route */}
              <Route path="/login" element={<LoginPage />} />

              {/* Protected Investigation Console Routes */}
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <Shell />
                  </ProtectedRoute>
                }
              >
                <Route index element={<DashboardPage />} />
                <Route path="cases" element={<CasesPage />} />
                <Route path="cases/new" element={<CasesPage />} />
                <Route path="cases/:id" element={<CaseDetailPage />} />
                <Route path="evidence" element={<EvidencePage />} />
                <Route path="evidence/:id" element={<EvidenceDetailPage />} />
                <Route path="memory" element={<MemoryAnalysisPage />} />
                <Route path="timeline" element={<TimelinePage />} />
                <Route path="correlation" element={<CorrelationPage />} />
                <Route path="deleted-files" element={<DeletedFilesPage />} />
                <Route path="timestamps" element={<TimestampReconstructionPage />} />
                <Route path="anti-forensics" element={<AntiForensicsPage />} />
                <Route path="cloud" element={<CloudEvidencePage />} />
                <Route path="reports" element={<ReportsPage />} />
                <Route path="analytics" element={<AnalyticsPage />} />
                <Route path="settings" element={<SettingsPage />} />
                <Route path="about" element={<AboutPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </CaseProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
};

export default App;
