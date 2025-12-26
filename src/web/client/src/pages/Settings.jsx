import React, { useState, useEffect } from 'react';

const Settings = () => {
    const [ideStatus, setIdeStatus] = useState([]);
    const [apiKeys, setApiKeys] = useState({
        openai: '',
        anthropic: '',
        gemini: ''
    });
    const [message, setMessage] = useState('');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Fetch system status (IDEs)
        fetch('/api/system/status')
            .then(res => res.json())
            .then(data => {
                setIdeStatus(data.ide_servers || []);
                setLoading(false);
            })
            .catch(err => {
                console.error("Failed to fetch system status", err);
                setLoading(false);
            });

        // Fetch saved settings
        fetch('/api/settings')
            .then(res => res.json())
            .then(data => {
                if (data) {
                    setApiKeys(prev => ({
                        ...prev,
                        openai: data.openai || '',
                        anthropic: data.anthropic || '',
                        gemini: data.gemini || ''
                    }));
                }
            })
            .catch(err => console.error("Failed to fetch settings", err));
    }, []);

    const handleSaveKeys = async () => {
        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(apiKeys)
            });
            const data = await res.json();
            setMessage(data.message);
            setTimeout(() => setMessage(''), 3000); // Clear message after 3s
        } catch (err) {
            setMessage("Error saving settings");
        }
    };

    return (
        <div className="page-container fade-in" style={{ maxWidth: '1000px', margin: '0 auto' }}>
            <div className="dashboard-header">
                <h1 className="gradient-text"><i className="fas fa-cogs me-2"></i> Configuration</h1>
                <p className="text-secondary">System preferences and AI integrations</p>
            </div>

            <div className="layout-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>

                {/* AI Configuration */}
                <section className="glass-panel shine-effect">
                    <h2 style={{ marginBottom: '1.5rem', fontWeight: 300, borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '10px' }}>
                        <i className="fas fa-robot me-2" style={{ color: 'var(--primary)' }}></i> AI Model Keys
                    </h2>

                    <div className="form-group" style={{ marginBottom: '20px' }}>
                        <label style={{ display: 'block', marginBottom: '8px', color: '#aaa', fontSize: '0.9rem' }}>OpenAI API Key</label>
                        <div className="input-group" style={{ marginTop: 0 }}>
                            <span style={{ background: 'rgba(255,255,255,0.05)', padding: '10px 15px', border: '1px solid var(--secondary)', borderRight: 'none', borderRadius: '6px 0 0 6px', display: 'flex', alignItems: 'center' }}>
                                <i className="fas fa-key"></i>
                            </span>
                            <input
                                type="password"
                                className="form-input"
                                value={apiKeys.openai}
                                onChange={(e) => setApiKeys({ ...apiKeys, openai: e.target.value })}
                                placeholder="sk-..."
                                style={{ borderRadius: '0 6px 6px 0', width: '100%' }}
                            />
                        </div>
                    </div>

                    <div className="form-group" style={{ marginBottom: '20px' }}>
                        <label style={{ display: 'block', marginBottom: '8px', color: '#aaa', fontSize: '0.9rem' }}>Anthropic API Key</label>
                        <div className="input-group" style={{ marginTop: 0 }}>
                            <span style={{ background: 'rgba(255,255,255,0.05)', padding: '10px 15px', border: '1px solid var(--secondary)', borderRight: 'none', borderRadius: '6px 0 0 6px', display: 'flex', alignItems: 'center' }}>
                                <i className="fas fa-brain"></i>
                            </span>
                            <input
                                type="password"
                                className="form-input"
                                value={apiKeys.anthropic}
                                onChange={(e) => setApiKeys({ ...apiKeys, anthropic: e.target.value })}
                                placeholder="sk-ant-..."
                                style={{ borderRadius: '0 6px 6px 0', width: '100%' }}
                            />
                        </div>
                    </div>

                    <div className="form-group" style={{ marginBottom: '25px' }}>
                        <label style={{ display: 'block', marginBottom: '8px', color: '#aaa', fontSize: '0.9rem' }}>Gemini API Key</label>
                        <div className="input-group" style={{ marginTop: 0 }}>
                            <span style={{ background: 'rgba(255,255,255,0.05)', padding: '10px 15px', border: '1px solid var(--secondary)', borderRight: 'none', borderRadius: '6px 0 0 6px', display: 'flex', alignItems: 'center' }}>
                                <i className="fas fa-star"></i>
                            </span>
                            <input
                                type="password"
                                className="form-input"
                                value={apiKeys.gemini}
                                onChange={(e) => setApiKeys({ ...apiKeys, gemini: e.target.value })}
                                placeholder="AIza..."
                                style={{ borderRadius: '0 6px 6px 0', width: '100%' }}
                            />
                        </div>
                    </div>

                    <button className="btn btn-primary btn-block" onClick={handleSaveKeys}>
                        <i className="fas fa-save me-2"></i> Save Configuration
                    </button>
                    {message && <div className="fade-in" style={{ marginTop: '15px', padding: '10px', background: 'rgba(76, 175, 80, 0.2)', color: '#4caf50', borderRadius: '4px', textAlign: 'center', border: '1px solid #4caf50' }}>{message}</div>}
                </section>

                {/* IDE Integrations */}
                <section className="glass-panel">
                    <h2 style={{ marginBottom: '1.5rem', fontWeight: 300, borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '10px' }}>
                        <i className="fas fa-laptop-code me-2" style={{ color: '#ff9800' }}></i> IDE Integrations
                    </h2>
                    <p style={{ color: '#888', marginBottom: '20px', fontSize: '0.95rem' }}>
                        Auto-detected Model Context Protocol (MCP) servers available on your local system.
                    </p>

                    <div className="ide-list" style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                        {loading ? (
                            <div className="text-center p-4">
                                <i className="fas fa-circle-notch fa-spin fa-2x text-primary"></i>
                                <p className="mt-2 text-secondary">Scanning system...</p>
                            </div>
                        ) : ideStatus.length > 0 ? (
                            ideStatus.map((ide, idx) => (
                                <div key={idx} className="ide-item fade-in" style={{
                                    padding: '15px',
                                    background: 'rgba(255,255,255,0.03)',
                                    border: '1px solid rgba(255,255,255,0.05)',
                                    borderRadius: '8px',
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'space-between',
                                    transition: 'all 0.2s'
                                }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                        <div style={{
                                            width: '40px',
                                            height: '40px',
                                            borderRadius: '8px',
                                            background: ide.name === 'Antigravity' ? 'rgba(156, 39, 176, 0.2)' : 'rgba(0, 122, 204, 0.2)',
                                            display: 'flex',
                                            alignItems: 'center',
                                            justifyContent: 'center',
                                            color: ide.name === 'Antigravity' ? '#ce93d8' : 'var(--primary)'
                                        }}>
                                            <i className={`fas ${ide.name === 'Antigravity' ? 'fa-rocket' : 'fa-code'}`}></i>
                                        </div>
                                        <div>
                                            <h4 style={{ margin: 0, fontWeight: 600 }}>{ide.name}</h4>
                                            <span style={{ fontSize: '0.8rem', color: '#666' }}>{ide.config_path.split('/').pop()}</span>
                                        </div>
                                    </div>
                                    <span className="badge" style={{
                                        background: 'rgba(76, 175, 80, 0.2)',
                                        color: '#4caf50',
                                        padding: '4px 10px',
                                        borderRadius: '20px',
                                        fontSize: '0.8rem',
                                        border: '1px solid rgba(76, 175, 80, 0.3)'
                                    }}>
                                        Active
                                    </span>
                                </div>
                            ))
                        ) : (
                            <div style={{ textAlign: 'center', padding: '30px', color: '#666', border: '1px dashed #444', borderRadius: '8px' }}>
                                <i className="fas fa-search mb-2" style={{ fontSize: '1.5rem' }}></i>
                                <p>No compatible IDEs detected.</p>
                            </div>
                        )}
                    </div>
                </section>
            </div>
        </div>
    );
};

export default Settings;
