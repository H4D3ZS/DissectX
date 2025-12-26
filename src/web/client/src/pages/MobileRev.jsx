import React, { useState, useEffect } from 'react';

const MobileRev = () => {
    const [activeTab, setActiveTab] = useState('apk'); // apk, ipa, frida, mobsf
    const [uploading, setUploading] = useState(false);
    const [analysisResult, setAnalysisResult] = useState(null);
    const [selectedFile, setSelectedFile] = useState(null);
    const [fileContent, setFileContent] = useState('');
    const [fridaDevices, setFridaDevices] = useState([]);
    const [fridaStatus, setFridaStatus] = useState('');
    const [mobsfUrl, setMobsfUrl] = useState('http://localhost:9090'); // Default to 9090 to prevent recursive embedding
    const [mobsfKey, setMobsfKey] = useState('');

    // APK Analysis Logic
    const handleApkUpload = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        setUploading(true);
        const formData = new FormData();
        formData.append('file', file);

        try {
            const upRes = await fetch('/api/mobile/upload', { method: 'POST', body: formData }).then(r => r.json());
            if (upRes.error) throw new Error(upRes.error);

            // Trigger Analysis
            const anRes = await fetch('/api/mobile/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: upRes.path })
            }).then(r => r.json());

            setAnalysisResult(anRes);
        } catch (err) {
            alert("Analysis failed: " + err.message);
        } finally {
            setUploading(false);
        }
    };

    const loadFile = async (file) => {
        setSelectedFile(file);
        const res = await fetch(`/api/mobile/file_content?root=${analysisResult.source_root}&path=${file.path}`).then(r => r.json());
        setFileContent(res.content);
    };

    // Frida Logic
    const loadDevices = async () => {
        const res = await fetch('/api/mobile/frida/devices').then(r => r.json());
        setFridaDevices(res.devices || []);
    };

    const bypassSSL = async (deviceId) => {
        setFridaStatus("Injecting SSL Pinning Bypass...");
        const res = await fetch('/api/mobile/frida/ssl_pinning', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_id: deviceId })
        }).then(r => r.json());
        setFridaStatus(res.message || res.error);
    };

    useEffect(() => {
        if (activeTab === 'frida') loadDevices();
    }, [activeTab]);

    return (
        <div className="page-container mobile-rev-layout fade-in">
            <header className="page-header" style={{ marginBottom: '2rem' }}>
                <h1><i className="fas fa-mobile-alt me-2" style={{ color: 'var(--primary)' }}></i> Mobile Reverse Engineering</h1>
                <p className="text-secondary">Advanced analysis suite for Android & iOS applications</p>

                <div className="cyber-tabs">
                    <button className={`cyber-tab ${activeTab === 'apk' ? 'active' : ''}`} onClick={() => setActiveTab('apk')}>
                        <i className="fab fa-android"></i> APK Analysis
                    </button>
                    <button className={`cyber-tab ${activeTab === 'ipa' ? 'active' : ''}`} onClick={() => setActiveTab('ipa')}>
                        <i className="fab fa-apple"></i> iOS Analysis
                    </button>
                    <button className={`cyber-tab ${activeTab === 'frida' ? 'active' : ''}`} onClick={() => setActiveTab('frida')}>
                        <i className="fas fa-ghost"></i> Frida Hooks
                    </button>
                    <button className={`cyber-tab ${activeTab === 'mobsf' ? 'active' : ''}`} onClick={() => setActiveTab('mobsf')}>
                        <i className="fas fa-shield-alt"></i> MobSF
                    </button>
                </div>
            </header>

            {/* APK Analysis Tab */}
            {activeTab === 'apk' && (
                <div className="tab-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: '0' }}>
                    {!analysisResult ? (
                        <div className="glass-panel center-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', borderStyle: 'dashed', borderWidth: '2px' }}>
                            <div className="icon-circle" style={{ fontSize: '4rem', color: 'var(--primary)', marginBottom: '1rem' }}>
                                <i className="fas fa-cloud-upload-alt"></i>
                            </div>
                            <h2 style={{ marginBottom: '0.5rem' }}>Upload APK Binary</h2>
                            <p style={{ color: '#888', marginBottom: '2rem' }}>Automated `apktool` decoding and `jadx` source recovery</p>

                            <input type="file" onChange={handleApkUpload} id="apkInput" hidden accept=".apk" />
                            <label htmlFor="apkInput" className="btn btn-primary btn-lg shine-effect">
                                {uploading ? <><i className="fas fa-cog fa-spin me-2"></i> Analyzing...</> : <><i className="fas fa-upload me-2"></i> Select APK File</>}
                            </label>
                        </div>
                    ) : (
                        <div className="ide-container glass-panel" style={{ flex: 1, display: 'flex', overflow: 'hidden', padding: 0 }}>
                            <div className="file-tree-sidebar" style={{ width: '280px', background: 'rgba(0,0,0,0.3)', overflowY: 'auto', borderRight: '1px solid var(--secondary)' }}>
                                <div style={{ padding: '10px', borderBottom: '1px solid var(--secondary)', fontWeight: 'bold', color: 'var(--primary)' }}>
                                    <i className="fas fa-folder-open me-2"></i> Package Explorer
                                </div>
                                {analysisResult.files.map((f, i) => (
                                    <div key={i}
                                        className={`tree-item ${selectedFile === f ? 'active' : ''}`}
                                        onClick={() => loadFile(f)}
                                    >
                                        <i className={`fas ${f.extension === '.java' ? 'fa-file-code' : 'fa-file'} me-2`} style={{ opacity: 0.7 }}></i>
                                        {f.name}
                                    </div>
                                ))}
                            </div>
                            <div className="code-editor-area" style={{ flex: 1, background: '#1e1e1e', position: 'relative' }}>
                                {fileContent ? (
                                    <textarea
                                        readOnly
                                        value={fileContent}
                                        spellCheck="false"
                                        style={{
                                            width: '100%',
                                            height: '100%',
                                            background: 'transparent',
                                            color: '#d4d4d4',
                                            border: 'none',
                                            padding: '15px',
                                            resize: 'none',
                                            fontFamily: "'Fira Code', Consolas, monospace",
                                            lineHeight: '1.5',
                                            fontSize: '14px'
                                        }}
                                    />
                                ) : (
                                    <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: '#555', flexDirection: 'column' }}>
                                        <i className="fas fa-code fa-3x mb-3"></i>
                                        <p>Select a file to view source</p>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Frida Tab */}
            {activeTab === 'frida' && (
                <div className="tab-content glass-panel" style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                        <h2><i className="fas fa-ghost me-2"></i> Dynamic Instrumentation</h2>
                        <button className="btn btn-sm btn-primary" onClick={loadDevices}> <i className="fas fa-sync-alt me-1"></i> Refresh Devices</button>
                    </div>

                    <div className="device-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '20px' }}>
                        {fridaDevices.map(d => (
                            <div key={d.id} className="device-card" style={{
                                background: 'rgba(255,255,255,0.05)',
                                padding: '20px',
                                borderRadius: '12px',
                                border: '1px solid var(--secondary)'
                            }}>
                                <div style={{ display: 'flex', alignItems: 'center', marginBottom: '15px' }}>
                                    <div style={{
                                        width: '40px', height: '40px', borderRadius: '50%',
                                        background: d.type === 'usb' ? 'var(--primary)' : '#444',
                                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        marginRight: '15px', fontSize: '1.2rem'
                                    }}>
                                        <i className={`fab ${d.type === 'usb' ? 'fa-android' : 'fa-linux'}`}></i>
                                    </div>
                                    <div>
                                        <h3 style={{ margin: 0, fontSize: '1.1rem' }}>{d.name}</h3>
                                        <span style={{ fontSize: '0.8rem', opacity: 0.7 }}>{d.id}</span>
                                    </div>
                                </div>
                                <div style={{ display: 'flex', gap: '10px' }}>
                                    <button className="btn btn-warning btn-sm btn-block" onClick={() => bypassSSL(d.id)}>
                                        <i className="fas fa-unlock me-2"></i> Bypas SSL
                                    </button>
                                    <button className="btn btn-sm btn-dark" title="Process List"><i className="fas fa-list"></i></button>
                                </div>
                            </div>
                        ))}
                    </div>

                    {fridaStatus && (
                        <div className="console-output" style={{
                            marginTop: '20px',
                            padding: '15px',
                            background: '#000',
                            borderRadius: '8px',
                            borderLeft: '4px solid var(--success)',
                            fontFamily: 'monospace'
                        }}>
                            <div style={{ color: '#888', marginBottom: '5px' }}>Frida Agent Output:</div>
                            <div style={{ color: 'var(--success)' }}>{fridaStatus}</div>
                        </div>
                    )}
                </div>
            )}

            {/* MobSF Tab */}
            {activeTab === 'mobsf' && (
                <div className="tab-content" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                    <div className="glass-panel" style={{ marginBottom: '15px', padding: '15px', display: 'flex', alignItems: 'center', gap: '15px' }}>
                        <i className="fas fa-shield-alt fa-2x" style={{ color: 'var(--primary)' }}></i>
                        <div style={{ flex: 1 }}>
                            <h3 style={{ margin: 0 }}>MobSF Integration</h3>
                            <p style={{ margin: 0, fontSize: '0.9rem', opacity: 0.8 }}>Mobile Security Framework Embedding</p>
                        </div>
                        <div className="input-group" style={{ margin: 0 }}>
                            <input
                                type="text"
                                className="form-input"
                                placeholder="http://localhost:9090"
                                value={mobsfUrl}
                                onChange={(e) => setMobsfUrl(e.target.value)}
                                style={{ width: '250px' }}
                            />
                            <button className="btn btn-primary" onClick={() => setActiveTab('mobsf-reload')}>
                                <i className="fas fa-link me-2"></i> Connect
                            </button>
                        </div>
                    </div>

                    <div style={{ flex: 1, background: '#fff', borderRadius: '12px', overflow: 'hidden', position: 'relative' }}>
                        {activeTab === 'mobsf' &&
                            <iframe
                                src={mobsfUrl}
                                style={{ width: '100%', height: '100%', border: 'none' }}
                                title="MobSF"
                                onError={() => alert("Could not load MobSF. Check URL and CORS.")}
                            />
                        }
                    </div>
                </div>
            )}

            {/* iOS Tab */}
            {activeTab === 'ipa' && (
                <div className="tab-content glass-panel center-content" style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                    <i className="fab fa-apple" style={{ fontSize: '5rem', opacity: 0.2, marginBottom: '20px' }}></i>
                    <h2>iOS Analysis Suite</h2>
                    <p style={{ marginBottom: '2rem', maxWidth: '400px', textAlign: 'center' }}>
                        Decrypt and analyze IPA files using `ipatool` and `class-dump`.
                        <br /><span className="badge badge-warning" style={{ marginTop: '10px', display: 'inline-block' }}>Coming Soon</span>
                    </p>
                    <button className="btn secondary-btn" disabled>Upload IPA Binary</button>
                </div>
            )}
        </div>
    );
};

export default MobileRev;
