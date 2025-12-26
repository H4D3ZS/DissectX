import React, { useState } from 'react';
import { Link } from 'react-router-dom';

function Dashboard() {
    const [uploading, setUploading] = useState(false);
    const [file, setFile] = useState(null);

    const handleFileChange = (e) => {
        if (e.target.files.length > 0) {
            setFile(e.target.files[0]);
        }
    };

    const handleUpload = async (e) => {
        e.preventDefault();
        if (!file) return;

        setUploading(true);
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/upload', { // Note: Ideally this should use the new API structure later
                method: 'POST',
                body: formData,
            });
            const data = await response.json();
            if (data.success) {
                // For now, redirect to decompiler or similar based on file type?
                // Just keeping original behavior for now
                window.location.href = data.redirect || '/';
            } else {
                alert('Upload failed: ' + data.error);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Upload failed');
        } finally {
            setUploading(false);
        }
    };

    return (
        <div className="dashboard-container fade-in">
            <div className="dashboard-header">
                <h1 className="gradient-text" style={{ fontSize: '2.5rem', marginBottom: '0.5rem' }}>DissectX Dashboard</h1>
                <p className="text-secondary" style={{ fontSize: '1.1rem' }}>Advanced Binary Analysis & Reverse Engineering Platform</p>
            </div>

            <div className="layout-grid" style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '2rem' }}>
                {/* Upload Section */}
                <div className="upload-section glass-panel shine-effect">
                    <h2 style={{ marginBottom: '1.5rem', fontWeight: 300 }}><i className="fas fa-microchip me-2" style={{ color: 'var(--primary)' }}></i> Quick Analysis</h2>
                    <form onSubmit={handleUpload}>
                        <div className="file-drop-area" onClick={() => document.getElementById('fileInput').click()}>
                            <input type="file" onChange={handleFileChange} id="fileInput" hidden />
                            <div className="upload-content">
                                <div className="icon-circle" style={{ margin: '0 auto 1.5rem' }}>
                                    <i className="fas fa-cloud-upload-alt fa-3x" style={{ color: 'var(--primary)' }}></i>
                                </div>
                                <h3 style={{ marginBottom: '0.5rem' }}>{file ? file.name : "Drop Binary Here"}</h3>
                                <p style={{ color: '#888', marginBottom: 0 }}>Supports ELF, PE, Mach-O, DEX, APK, IPA</p>
                            </div>
                        </div>
                        <button type="submit" className="btn btn-primary btn-block btn-lg" disabled={!file || uploading} style={{ height: '50px', fontSize: '1.1rem' }}>
                            {uploading ? <><i className="fas fa-spinner fa-spin me-2"></i> Analyzing...</> : "Start Analysis"}
                        </button>
                    </form>
                </div>

                {/* Tools Grid */}
                <div>
                    <h2 style={{ marginBottom: '1.5rem', fontWeight: 300 }}>Available Modules</h2>
                    <div className="grid-cards" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))' }}>
                        <Link to="/mobile-rev" className="card device-card" style={{ borderLeft: '4px solid var(--primary)' }}>
                            <div className="card-icon"><i className="fas fa-mobile-alt"></i></div>
                            <h3>Mobile RE</h3>
                            <p>APK/IPA Analysis, Frida Hooks, MobSF Integration.</p>
                            <span className="badge badge-primary" style={{ background: 'var(--primary)', alignSelf: 'flex-start', marginTop: 'auto' }}>NEW</span>
                        </Link>

                        <Link to="/pentest" className="card device-card" style={{ borderLeft: '4px solid #ff9800' }}>
                            <div className="card-icon" style={{ color: '#ff9800' }}><i className="fas fa-shield-alt"></i></div>
                            <h3>VulnChain Scanner</h3>
                            <p>Automated vulnerability assessment suite.</p>
                        </Link>

                        <Link to="/decompiler" className="card device-card">
                            <div className="card-icon"><i className="fas fa-code"></i></div>
                            <h3>Static Decompiler</h3>
                            <p>View Pseudo-code and assembly instructions.</p>
                        </Link>

                        <Link to="/debugger" className="card device-card">
                            <div className="card-icon"><i className="fas fa-bug"></i></div>
                            <h3>Dynamic Debugger</h3>
                            <p>Inspect registers, stack, and memory maps.</p>
                        </Link>

                        <Link to="/network" className="card device-card">
                            <div className="card-icon"><i className="fas fa-project-diagram"></i></div>
                            <h3>Network Graph</h3>
                            <p>Visualize function calls and control flow.</p>
                        </Link>

                        <Link to="/settings" className="card device-card" style={{ opacity: 0.7 }}>
                            <div className="card-icon"><i className="fas fa-cogs"></i></div>
                            <h3>System Config</h3>
                            <p>API Keys, IDE Detection, and Theme Settings.</p>
                        </Link>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Dashboard;
