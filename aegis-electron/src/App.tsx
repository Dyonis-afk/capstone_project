import React, { useEffect } from 'react';
import { HashRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import ReportScreen from './screens/report/ReportScreen';
import ChatScreen from './screens/ChatScreen';
import TestScreen from './screens/TestScreen'; // TEMPORARY - Delete after testing
import './index.css';
import AppLayout from './components/AppLayout';
import HomeContent from './components/HomeContent';
import SettingsPage from './components/Settingspage';
import UpdateNotification from './components/UpdateNotification';
import { FeedbackButton } from './components/feedback';
import ReportProgressCard from './components/ReportProgressCard';
import { useConnectionStore } from './stores/connectionStore';
import { useReportJobStore } from './stores/reportJobStore';

/**
 * ReportJobTimer - Ticks elapsed/step timers while a report job is running.
 * Keeps timers updating even when the user navigates away from the report screen.
 */
const ReportJobTimer: React.FC = () => {
  const isRunning = useReportJobStore(s => s.isRunning);
  const tickTimers = useReportJobStore(s => s.tickTimers);

  useEffect(() => {
    if (!isRunning) return;
    const interval = setInterval(() => tickTimers(), 1000);
    return () => clearInterval(interval);
  }, [isRunning, tickTimers]);

  return null;
};

/**
 * ReportJobNavigator - Sets up navigation callback for background report jobs
 * Must be inside HashRouter to use useNavigate
 */
const ReportJobNavigator: React.FC = () => {
  const navigate = useNavigate();
  const setNavigateCallback = useReportJobStore(s => s.setNavigateCallback);

  useEffect(() => {
    setNavigateCallback((projectId: string, state: any) => {
      navigate(`/chat/${projectId}`, { state, replace: true });
    });
  }, [navigate, setNavigateCallback]);

  return (
    <>
      <ReportJobTimer />
      <ReportProgressCard />
    </>
  );
};

const App: React.FC = () => {
  const { startSmartPolling, stopPolling, loadNeo4jMode } = useConnectionStore();

  // Initialize smart connection polling on app startup
  // Smart polling: 15s when services DOWN, 60s when UP (no UI flicker)
  useEffect(() => {
    // Load Neo4j mode from localStorage first (before polling starts)
    console.log('[App] Loading Neo4j connection mode from storage');
    loadNeo4jMode();

    console.log('[App] Starting smart connection status polling');
    startSmartPolling();

    return () => {
      console.log('[App] Stopping connection status polling');
      stopPolling();
    };
  }, [startSmartPolling, stopPolling, loadNeo4jMode]);
  return (
    <>
      <Toaster 
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#1a1a2e',
            color: '#fff',
            border: '1px solid #2a2a4a',
            maxWidth: '400px',
            wordBreak: 'break-word',
          },
          error: {
            style: {
              background: '#ef4444',
              color: '#fff',
              border: '1px solid #dc2626',
            },
            iconTheme: { primary: '#fff', secondary: '#ef4444' },
            duration: 5000,
          },
          success: {
            style: {
              background: '#22c55e',
              color: '#fff',
              border: '1px solid #16a34a',
            },
            iconTheme: { primary: '#fff', secondary: '#22c55e' },
            duration: 3000,
          },
        }}
      />
      <HashRouter>
        {/* Set up navigation callback for background report jobs */}
        <ReportJobNavigator />
        <Routes>
          {/* Report Screen - FULL SCREEN (no sidebar during generation) */}
          <Route path="/report" element={<ReportScreen />} />

          {/* All other routes use AppLayout (shared sidebar) */}
          <Route path="/*" element={
            <AppLayout>
              <Routes>
                {/* Home - Upload BloodHound data (index route for exact match) */}
                <Route index element={<HomeContent />} />

                {/* Chat - Uses projectId */}
                <Route path="chat/:projectId" element={<ChatScreen />} />

                {/* Settings */}
                <Route path="settings" element={<SettingsPage />} />

                {/* TEMPORARY: Graph Test Screen - Delete after testing */}
                <Route path="test" element={<TestScreen />} />

                {/* Catch-all: redirect unknown routes to home */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </AppLayout>
          } />
        </Routes>
      </HashRouter>
      <UpdateNotification />
      <FeedbackButton />
    </>
  );
};

export default App;
