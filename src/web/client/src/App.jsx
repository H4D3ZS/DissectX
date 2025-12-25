import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import LiveLog from './components/LiveLog';
import Dashboard from './pages/Dashboard';
import Pentest from './pages/Pentest';
import NetworkGraph from './pages/NetworkGraph';
import Decompiler from './pages/Decompiler';
import Debugger from './pages/Debugger';
import Settings from './pages/Settings';
import MobileRev from './pages/MobileRev';
import './App.css';

const AppContent = () => {
  const location = useLocation();
  // Hide LiveLog on Dashboard and Settings pages
  const showLiveLog = !['/', '/settings'].includes(location.pathname);

  return (
    <div className="app-container">
      <Sidebar />
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/pentest" element={<Pentest />} />
          <Route path="/network" element={<NetworkGraph />} />
          <Route path="/decompiler" element={<Decompiler />} />
          <Route path="/debugger" element={<Debugger />} />
          <Route path="/mobile-rev" element={<MobileRev />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
      {showLiveLog && <LiveLog />}
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
