import React, { useState, useEffect } from 'react';

function Reports() {
    const [reports, setReports] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchReports = async () => {
            try {
                // In a real app, we'd fetch from /api/hexstrike/reports
                // For now, we'll simulate or fetch what we can
                const response = await fetch('/api/hexstrike/scans');
                if (response.ok) {
                    const data = await response.json();
                    setReports(data || []);
                }
            } catch (error) {
                console.error('Failed to fetch reports:', error);
            } finally {
                setLoading(false);
            }
        };
        fetchReports();
    }, []);

    const downloadMarkdown = async (reportId) => {
        try {
            const response = await fetch(`/api/hexstrike/export/${reportId}`);
            if (!response.ok) throw new Error('Failed to export');
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `dissectx_report_${reportId}.md`;
            document.body.appendChild(a);
            a.click();
            a.remove();
        } catch (error) {
            console.error('Download failed:', error);
        }
    };

    return (
        <div className="page-container">
            <header className="page-header">
                <h1><i className="fas fa-file-contract"></i> Generated Security Audit Reports</h1>
                <p>Centralized hub for all mission documentation and finding summaries.</p>
            </header>

            <div className="glass-panel">
                <div className="report-history">
                    <h3><i className="fas fa-history"></i> Mission History</h3>
                    <div className="report-list">
                        {loading ? (
                            <div className="loading-spinner">Analyzing historical data...</div>
                        ) : reports.length > 0 ? (
                            reports.map(report => (
                                <div key={report.id} className="report-item" style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    padding: '1rem',
                                    background: 'rgba(255,255,255,0.05)',
                                    borderRadius: '8px',
                                    marginBottom: '1rem',
                                    borderLeft: '4px solid var(--primary)'
                                }}>
                                    <div>
                                        <div style={{ fontWeight: 'bold', fontSize: '1.1rem' }}>{report.target}</div>
                                        <div style={{ fontSize: '0.8rem', opacity: 0.7 }}>
                                            {new Date(report.timestamp).toLocaleString()} • {report.id}
                                        </div>
                                    </div>
                                    <div style={{ display: 'flex', gap: '10px' }}>
                                        <button className="btn btn-sm btn-primary" onClick={() => downloadMarkdown(report.id)}>
                                            <i className="fas fa-download"></i> Markdown
                                        </button>
                                        <button className="btn btn-sm btn-warning">
                                            <i className="fas fa-eye"></i> View Online
                                        </button>
                                    </div>
                                </div>
                            ))
                        ) : (
                            <div style={{ textAlign: 'center', padding: '3rem', opacity: 0.5 }}>
                                <i className="fas fa-folder-open" style={{ fontSize: '3rem', marginBottom: '1rem' }}></i>
                                <p>No completed missions found. Start an assessment to generate your first report.</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Reports;
