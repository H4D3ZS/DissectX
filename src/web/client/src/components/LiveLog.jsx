import React, { useState, useEffect, useRef } from 'react';
import socket from '../utils/socket';

function LiveLog({ logs, onClear }) {
    const [viewState, setViewState] = useState('normal');
    const [height, setHeight] = useState(200);
    const [isFullscreen, setIsFullscreen] = useState(false);
    const logEndRef = useRef(null);
    const containerRef = useRef(null);

    // Auto-scroll to bottom
    useEffect(() => {
        if (logEndRef.current) {
            logEndRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [logs]);

    const toggleMinimize = (e) => {
        e.stopPropagation();
        setViewState(current => current === 'minimized' ? 'normal' : 'minimized');
    };

    const toggleFullscreen = (e) => {
        e.stopPropagation();
        setIsFullscreen(!isFullscreen);
    };

    // Resize handling
    const startResizing = (e) => {
        e.preventDefault();
        const startY = e.clientY;
        const startHeight = height;

        const onMouseMove = (moveEvent) => {
            const newHeight = startHeight + (startY - moveEvent.clientY);
            if (newHeight > 100 && newHeight < window.innerHeight * 0.9) {
                setHeight(newHeight);
            }
        };

        const onMouseUp = () => {
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
        };

        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    };

    return (
        <div
            ref={containerRef}
            className={`live-log-container ${viewState} ${isFullscreen ? 'full-screen' : ''}`}
            style={{ '--log-height': `${height}px` }}
        >
            <div className="log-resize-handle" onMouseDown={startResizing} />

            <div className="log-header">
                <div onClick={toggleMinimize} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <i className="fas fa-terminal" style={{ color: 'var(--primary)' }}></i>
                    <span style={{ fontWeight: 'bold', letterSpacing: '1px' }}>LIVE OPERATIONS CENTER</span>
                    {logs.length > 0 && <span className="badge" style={{ background: 'rgba(255,255,255,0.1)', fontSize: '0.6rem' }}>{logs.length} EVENTS</span>}
                </div>
                <div className="log-controls">
                    <button onClick={(e) => { e.stopPropagation(); onClear(); }} className="btn btn-sm btn-primary" style={{ fontSize: '0.7rem', padding: '2px 8px', marginRight: '10px' }}>
                        <i className="fas fa-trash me-1"></i> CLEAR TERMINAL
                    </button>
                    <button onClick={toggleFullscreen} className="btn-icon" title={isFullscreen ? "Exit Fullscreen" : "Fullscreen"}>
                        <i className={`fas ${isFullscreen ? 'fa-compress' : 'fa-expand'}`}></i>
                    </button>
                    <button onClick={toggleMinimize} className="btn-icon" title={viewState === 'minimized' ? "Restore" : "Minimize"}>
                        <i className={`fas ${viewState === 'minimized' ? 'fa-chevron-up' : 'fa-chevron-down'}`}></i>
                    </button>
                </div>
            </div>
            <div className="log-body">
                {logs.map((log, index) => (
                    <div key={index} className={`log-entry ${log.level.toLowerCase()}`}>
                        <span className="log-time">[{log.timestamp}]</span>
                        <span className="log-level">{log.level}</span>
                        <span className="log-message">{log.message}</span>
                    </div>
                ))}
                <div ref={logEndRef} />
            </div>
        </div>
    );
}

export default LiveLog;
