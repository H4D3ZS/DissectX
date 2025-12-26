import React, { useState } from 'react';

const Debugger = () => {
    const [status, setStatus] = useState("PAUSED");
    const [pc, setPc] = useState("0x401000");

    const controls = [
        { label: "Step Into (F7)", action: () => setPc("0x401004") },
        { label: "Step Over (F8)", action: () => setPc("0x401004") },
        { label: "Continue (F9)", action: () => setStatus("RUNNING") },
        { label: "Pause (F2)", action: () => setStatus("PAUSED") }
    ];

    return (
        <div className="page-container debugger-layout">
            <header className="page-header">
                <div>
                    <h1>Debugger</h1>
                    <div className="status-badge" style={{
                        display: 'inline-block',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        background: status === "RUNNING" ? '#1e4620' : '#463a1e',
                        color: status === "RUNNING" ? '#4caf50' : '#ffc107',
                        fontSize: '12px',
                        marginLeft: '10px'
                    }}>{status}</div>
                </div>
                <div className="controls">
                    {controls.map(c => (
                        <button key={c.label} className="secondary-btn" onClick={c.action} style={{ marginLeft: '10px' }}>{c.label}</button>
                    ))}
                </div>
            </header>

            <div className="debug-panels" style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: '20px', height: '600px' }}>
                {/* Disassembly View */}
                <div className="panel disassembly" style={{ background: '#1a1a1a', padding: '15px', borderRadius: '8px' }}>
                    <h3>Disassembly</h3>
                    <div className="code-lines" style={{ fontFamily: 'monospace', color: '#ccc' }}>
                        <div style={{ background: pc === "0x401000" ? '#333' : 'transparent' }}>0x401000  55             push rbp</div>
                        <div style={{ background: pc === "0x401001" ? '#333' : 'transparent' }}>0x401001  48 89 e5       mov rbp, rsp</div>
                        <div style={{ background: pc === "0x401004" ? '#333' : 'transparent' }}>0x401004  48 83 ec 10    sub rsp, 0x10</div>
                        <div style={{ background: pc === "0x401008" ? '#333' : 'transparent' }}>0x401008  c7 45 fc 00 00 mov dword ptr [rbp-4], 0</div>
                        <div>...</div>
                    </div>
                </div>

                {/* Registers & Stack */}
                <div className="sidebar" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <div className="panel registers" style={{ background: '#1a1a1a', padding: '15px', borderRadius: '8px', flex: 1 }}>
                        <h3>Registers</h3>
                        <div style={{ fontFamily: 'monospace' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>RAX</span> <span style={{ color: '#4caf50' }}>0x0000000000000000</span></div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>RBX</span> <span>0x00007fffffffde30</span></div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>RCX</span> <span>0x0000000000401000</span></div>
                            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>RIP</span> <span style={{ color: '#ffc107' }}>{pc}</span></div>
                        </div>
                    </div>

                    <div className="panel stack" style={{ background: '#1a1a1a', padding: '15px', borderRadius: '8px', flex: 1 }}>
                        <h3>Stack</h3>
                        <div style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                            <div>00007fffffffe000: 00 00 00 00 00 00 00 00</div>
                            <div>00007fffffffe008: 24 10 40 00 00 00 00 00</div>
                            <div>00007fffffffe010: 01 00 00 00 00 00 00 00</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Debugger;
