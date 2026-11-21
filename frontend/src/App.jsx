import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import OverviewPage from './pages/OverviewPage';
import EventsPage from './pages/EventsPage';
import DetectionPage from './pages/DetectionPage';
import TimelinePage from './pages/TimelinePage';
import NetworkPage from './pages/NetworkPage';
import SimulationPage from './pages/SimulationPage';
import InvestigationPage from './pages/InvestigationPage';
import ReportsSettingsPage from './pages/ReportsSettingsPage';
import { api } from './api/client';

export default function App() {
  const [systemHealth, setSystemHealth] = useState('NORMAL');

  const refreshGlobalState = async () => {
    try {
      const res = await api.getDashboardSummary();
      setSystemHealth(res.data?.system_health || 'NORMAL');
    } catch {
      // Backend may be offline or booting
    }
  };

  useEffect(() => {
    refreshGlobalState();
    const interval = setInterval(refreshGlobalState, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <BrowserRouter>
      <div className="flex flex-col h-screen w-screen overflow-hidden bg-slate-950 text-slate-100 font-sans selection:bg-cyan-500 selection:text-slate-950">
        {/* Top Navbar */}
        <Navbar onRefresh={refreshGlobalState} systemHealth={systemHealth} />

        {/* Main Body */}
        <div className="flex flex-1 overflow-hidden">
          {/* Left Sidebar */}
          <Sidebar />

          {/* Page View Area */}
          <main className="flex-1 overflow-y-auto p-6 bg-slate-950">
            <Routes>
              <Route path="/" element={<OverviewPage />} />
              <Route path="/events" element={<EventsPage />} />
              <Route path="/detection" element={<DetectionPage />} />
              <Route path="/timeline" element={<TimelinePage />} />
              <Route path="/network" element={<NetworkPage />} />
              <Route path="/simulation" element={<SimulationPage />} />
              <Route path="/investigation" element={<InvestigationPage />} />
              <Route path="/settings" element={<ReportsSettingsPage />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}
