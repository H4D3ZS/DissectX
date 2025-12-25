import React, { useState, useEffect, useRef } from 'react';
import socket from '../utils/socket';

function LiveLog() {
    const [logs, setLogs] = useState([]);
    const [viewState, setViewState] = useState('normal');
    const [height, setHeight] = useState(200);
    const [isFullscreen, setIsFullscreen] = useState(false);
    const logEndRef = useRef(null);
    const containerRef = useRef(null);

    useEffect(() => {
        socket.on('connect', () => {
            console.log('[SOCKET] Connected to Backend');
            addLog('Connected to Real-time Operations Center', 'INFO');
        });

        socket.on('log', (data) => {
            console.log('[SOCKET] Log Received:', data);
            addLog(data.data, data.level);
        });

        socket.on('clear_logs', () => {
            clearLogs();
        });

        return () => {
            socket.off('connect');
            socket.off('log');
            socket.off('clear_logs');
            socket.off('disconnect');
        };
    }, []);

    // Auto-scroll to bottom
    useEffect(() => {
        if (logEndRef.current) {
            logEndRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [logs]);

    const addLog = (message, level) => {
        const timestamp = new Date().toLocaleTimeString();
        setLogs(prev => [...prev.slice(-199), { timestamp, message, level }]); // Keep more logs
    };

    const clearLogs = () => setLogs([]);

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
                <span onClick={toggleMinimize}>
                    <i className="fas fa-terminal me-2"></i>Live Operations
                </span>
                <div className="log-controls">
                    <button onClick={(e) => { e.stopPropagation(); clearLogs(); }} className="btn-icon" title="Clear Logs">
                        <i className="fas fa-trash"></i>
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
