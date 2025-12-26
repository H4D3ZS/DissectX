import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import LiveLog from './components/LiveLog';
import Dashboard from './pages/Dashboard';
import Pentest from './pages/Pentest';
import Phisher from './pages/Phisher';
import NetworkGraph from './pages/NetworkGraph';
import Decompiler from './pages/Decompiler';
import Debugger from './pages/Debugger';
import Settings from './pages/Settings';
import MobileRev from './pages/MobileRev';
import Reports from './pages/Reports';
import socket from './utils/socket';
import './App.css';

const AppContent = () => {
  const location = useLocation();
  const [logs, setLogs] = useState([]);

  // Hide LiveLog on Dashboard, Settings, and Reports pages - but keep it mounted!
  const isHiddenPage = ['/', '/settings', '/reports'].includes(location.pathname);

  useEffect(() => {
    const handleLog = (data) => {
      const timestamp = new Date().toLocaleTimeString();
      setLogs(prev => [...prev.slice(-499), { timestamp, message: data.data, level: data.level }]);
    };

    const handleClear = () => setLogs([]);

    socket.on('log', handleLog);
    socket.on('clear_logs', handleClear);

    return () => {
      socket.off('log', handleLog);
      socket.off('clear_logs', handleClear);
    };
  }, []);

  const clearLogs = () => {
    socket.emit('request_clear_logs');
    setLogs([]);
  };

  return (
    <div className="app-container">
      <Sidebar />
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/pentest" element={<Pentest />} />
          <Route path="/phisher" element={<Phisher />} />
          <Route path="/network" element={<NetworkGraph />} />
          <Route path="/decompiler" element={<Decompiler />} />
          <Route path="/debugger" element={<Debugger />} />
          <Route path="/mobile-rev" element={<MobileRev />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </main>
      <div style={{ display: isHiddenPage ? 'none' : 'block' }}>
        <LiveLog logs={logs} onClear={clearLogs} />
      </div>
    </div>
  );
};

function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}

export default App;
