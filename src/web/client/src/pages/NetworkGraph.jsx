import React, { useState } from 'react';

const NetworkGraph = () => {
    const [status, setStatus] = useState("Idle");

    const handleAnalyze = () => {
        setStatus("Analyzing network topology...");
        setTimeout(() => setStatus("Graph rendered (Mock Data)"), 1500);
    };

    return (
        <div className="page-container">
            <header className="page-header">
                <div>
                    <h1>Network Graph</h1>
                    <p className="subtitle">Visualize relationships and data flow</p>
                </div>
                <div className="header-actions">
                    <button className="primary-btn" onClick={handleAnalyze}>Analyze & Render</button>
                    <div className="status-indicator">
                        <span className={`status-dot ${status === 'Idle' ? 'gray' : 'green'}`}></span>
                        {status}
                    </div>
                </div>
            </header>

            <div className="graph-container" style={{
                background: '#1a1a1a',
                border: '1px solid #333',
                borderRadius: '8px',
                height: '600px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                position: 'relative'
            }}>
                <div style={{ textAlign: 'center', color: '#666' }}>
                    {status === "Idle" ? (
                        <>
                            <p style={{ fontSize: '48px', marginBottom: '20px' }}>🕸️</p>
                            <h3>No Graph Data</h3>
                            <p>Click "Analyze & Render" to visualize the network.</p>
                        </>
                    ) : (
                        // Placeholder for D3.js or Cytoscape.js
                        <div className="mock-graph-animation">
                            <div className="node node-1" style={{ position: 'absolute', top: '40%', left: '40%', width: '20px', height: '20px', background: '#00ccff', borderRadius: '50%' }}></div>
                            <div className="node node-2" style={{ position: 'absolute', top: '30%', left: '60%', width: '20px', height: '20px', background: '#ffcc00', borderRadius: '50%' }}></div>
                            <div className="node node-3" style={{ position: 'absolute', top: '60%', left: '50%', width: '20px', height: '20px', background: '#ff3366', borderRadius: '50%' }}></div>
                            <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
                                <line x1="40%" y1="40%" x2="60%" y2="30%" stroke="#444" strokeWidth="2" />
                                <line x1="40%" y1="40%" x2="50%" y2="60%" stroke="#444" strokeWidth="2" />
                            </svg>
                            <p style={{ marginTop: '300px' }}>Interactive Graph Visualization Loaded</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default NetworkGraph;
