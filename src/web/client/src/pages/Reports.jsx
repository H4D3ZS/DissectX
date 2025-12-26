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

    const [selectedReport, setSelectedReport] = useState(null);
    const [viewing, setViewing] = useState(false);

    const downloadMarkdown = async (reportId) => {
        const a = document.createElement('a');
        a.href = `/api/hexstrike/export/${reportId}`;
        a.download = `dissectx_report_${reportId}.md`;
        a.click();
    };

    const downloadPDF = async (reportId) => {
        const a = document.createElement('a');
        a.href = `/api/hexstrike/export/pdf/${reportId}`;
        a.download = `dissectx_report_${reportId}.pdf`;
        a.click();
    };

    const viewReport = async (reportId) => {
        try {
            const response = await fetch(`/api/hexstrike/report/${reportId}`);
            if (response.ok) {
                const data = await response.json();
                setSelectedReport(data);
                setViewing(true);
            }
        } catch (error) {
            console.error('Failed to view report:', error);
        }
    };

    return (
        <div className="page-container" style={{ padding: '2rem', maxWidth: '1200px', margin: '0 auto' }}>
            <header className="page-header" style={{ marginBottom: '3rem', borderBottom: '2px solid rgba(255,255,255,0.1)', paddingBottom: '1.5rem' }}>
                <h1 style={{ fontSize: '2.5rem', fontWeight: '800', display: 'flex', alignItems: 'center', gap: '15px' }}>
                    <i className="fas fa-file-contract" style={{ color: 'var(--primary)' }}></i>
                    Security Audit Reports
                </h1>
                <p style={{ fontSize: '1.1rem', opacity: 0.7 }}>Centralized hub for mission intelligence and authenticated findings.</p>
            </header>

            <div className="glass-panel" style={{ background: 'rgba(20,20,30,0.6)', backdropFilter: 'blur(20px)', borderRadius: '16px', border: '1px solid rgba(255,255,255,0.1)', overflow: 'hidden' }}>
                <div className="report-history" style={{ padding: '2rem' }}>
                    <h3 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <i className="fas fa-history" style={{ color: '#4dabf7' }}></i> Assessment Timeline
                    </h3>
                    <div className="report-list">
                        {loading ? (
                            <div className="loading-spinner" style={{ textAlign: 'center', padding: '3rem' }}>
                                <i className="fas fa-circle-notch fa-spin fa-2x"></i>
                                <p style={{ marginTop: '1rem' }}>Parsing encrypted findings...</p>
                            </div>
                        ) : reports.length > 0 ? (
                            reports.map(report => (
                                <div key={report.id} className="report-item" style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    padding: '1.25rem',
                                    background: 'rgba(255,255,255,0.03)',
                                    borderRadius: '12px',
                                    marginBottom: '1rem',
                                    borderLeft: '4px solid var(--primary)',
                                    transition: 'transform 0.2s',
                                    cursor: 'pointer'
                                }} onMouseEnter={(e) => e.currentTarget.style.transform = 'translateX(5px)'}
                                    onMouseLeave={(e) => e.currentTarget.style.transform = 'translateX(0)'}>
                                    <div onClick={() => viewReport(report.id)}>
                                        <div style={{ fontWeight: 'bold', fontSize: '1.2rem', color: '#fff' }}>{report.target}</div>
                                        <div style={{ fontSize: '0.85rem', opacity: 0.6, marginTop: '4px' }}>
                                            <i className="far fa-clock me-1"></i> {new Date(report.timestamp).toLocaleString()} • <span style={{ fontFamily: 'monospace' }}>{report.id}</span>
                                        </div>
                                    </div>
                                    <div style={{ display: 'flex', gap: '10px' }}>
                                        <button className="btn btn-sm btn-outline-info" onClick={() => downloadMarkdown(report.id)}>
                                            <i className="fab fa-markdown"></i> MD
                                        </button>
                                        <button className="btn btn-sm btn-outline-danger" onClick={() => downloadPDF(report.id)}>
                                            <i className="fas fa-file-pdf"></i> PDF
                                        </button>
                                        <button className="btn btn-sm btn-primary" onClick={() => viewReport(report.id)}>
                                            <i className="fas fa-eye"></i> Online
                                        </button>
                                    </div>
                                </div>
                            ))
                        ) : (
                            <div style={{ textAlign: 'center', padding: '5rem 2rem', opacity: 0.5 }}>
                                <i className="fas fa-ghost" style={{ fontSize: '4rem', marginBottom: '1.5rem' }}></i>
                                <p style={{ fontSize: '1.2rem' }}>Shadows found nothing. No mission reports available.</p>
                                <button className="btn btn-primary mt-3" onClick={() => window.location.hash = 'pentest'}>Launch Assessment</button>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Online Report Viewer Modal */}
            {viewing && selectedReport && (
                <div style={{
                    position: 'fixed', top: 0, left: 0, width: '100%', height: '100%',
                    background: 'rgba(0,0,0,0.85)', backdropFilter: 'blur(10px)',
                    zIndex: 1000, display: 'flex', justifyContent: 'center', alignItems: 'center', padding: '20px'
                }} onClick={() => setViewing(false)}>
                    <div style={{
                        background: '#1a1a2e', width: '100%', maxWidth: '900px', maxHeight: '90vh',
                        borderRadius: '20px', border: '1px solid rgba(255,255,255,0.1)',
                        display: 'flex', flexDirection: 'column', overflow: 'hidden',
                        boxShadow: '0 25px 50px -12px rgba(0,0,0,0.5)'
                    }} onClick={e => e.stopPropagation()}>

                        <div style={{ padding: '1.5rem 2rem', background: '#252545', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div>
                                <h2 style={{ margin: 0 }}>Mission Intelligence Report</h2>
                                <span style={{ opacity: 0.6, fontSize: '0.9rem' }}>Target: {selectedReport.target}</span>
                            </div>
                            <button className="btn btn-sm btn-outline-light" onClick={() => setViewing(false)}>
                                <i className="fas fa-times"></i>
                            </button>
                        </div>

                        <div style={{ padding: '2rem', overflowY: 'auto', flex: 1, color: '#e0e0e0' }}>
                            <div className="report-section mb-4">
                                <h4 style={{ color: 'var(--primary)', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '10px' }}>
                                    <i className="fas fa-quote-left me-2"></i> Executive Summary
                                </h4>
                                <p style={{ padding: '1rem', background: 'rgba(255,255,255,0.05)', borderRadius: '8px' }}>
                                    {selectedReport.summary || "No automated summary available for this mission segment."}
                                </p>
                            </div>

                            <div className="report-section mb-4">
                                <h4 style={{ color: '#ffc107', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '10px' }}>
                                    <i className="fas fa-search me-2"></i> Detected Vulnerabilities
                                </h4>
                                {selectedReport.vulnerabilities && selectedReport.vulnerabilities.length > 0 ? (
                                    selectedReport.vulnerabilities.map((v, i) => (
                                        <div key={i} style={{ padding: '0.8rem', borderLeft: '3px solid #ffc107', background: 'rgba(255,193,7,0.05)', marginBottom: '10px' }}>
                                            {v}
                                        </div>
                                    ))
                                ) : (
                                    <p className="text-muted small">No critical vulnerabilities mapped by autonomous sensors.</p>
                                )}
                            </div>

                            <div className="report-section mb-4">
                                <h4 style={{ color: '#ff4d4d', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '10px' }}>
                                    <i className="fas fa-skull-crossbones me-2"></i> Validated Exploits
                                </h4>
                                {selectedReport.exploits && selectedReport.exploits.length > 0 ? (
                                    selectedReport.exploits.map((ex, i) => (
                                        <div key={i} style={{ padding: '1rem', background: '#2a1a1a', borderRadius: '8px', marginBottom: '1rem', border: '1px solid rgba(255,77,77,0.2)' }}>
                                            <div style={{ fontWeight: 'bold', color: '#ff4d4d', marginBottom: '8px' }}>Vector: {ex.vector}</div>
                                            <div style={{ fontFamily: 'monospace', background: '#000', padding: '10px', borderRadius: '4px', fontSize: '0.9rem', marginBottom: '8px' }}>
                                                PoC: {ex.poc}
                                            </div>
                                            <div style={{ fontSize: '0.85rem', opacity: 0.8 }}>Result: {ex.result}</div>
                                        </div>
                                    ))
                                ) : (
                                    <p className="text-muted small">No exploitation attempts were successful in this cycle.</p>
                                )}
                            </div>
                        </div>

                        <div style={{ padding: '1.5rem 2rem', background: '#101025', display: 'flex', gap: '15px' }}>
                            <button className="btn btn-outline-danger" onClick={() => downloadPDF(selectedReport.id)}>
                                <i className="fas fa-file-pdf me-2"></i> Download PDF
                            </button>
                            <button className="btn btn-outline-info" onClick={() => downloadMarkdown(selectedReport.id)}>
                                <i className="fab fa-markdown me-2"></i> Download Markdown
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default Reports;
