import React, { useState } from 'react';

const Decompiler = () => {
    const [code, setCode] = useState("// Pseudo-code will appear here after analysis...\n\nfunction main() {\n    // Waiting for binary input...\n    return 0;\n}");

    return (
        <div className="page-container decompiler-layout" style={{ display: 'flex', gap: '20px', height: 'calc(100vh - 100px)' }}>
            {/* Sidebar File Tree */}
            <aside className="file-tree" style={{ width: '250px', background: '#1e1e1e', padding: '15px', borderRadius: '8px', border: '1px solid #333' }}>
                <h3 style={{ marginTop: 0, borderBottom: '1px solid #333', paddingBottom: '10px' }}>Functions</h3>
                <ul style={{ listStyle: 'none', padding: 0, color: '#aaa' }}>
                    <li style={{ padding: '5px', cursor: 'pointer', color: '#fff' }}>main</li>
                    <li style={{ padding: '5px', cursor: 'pointer' }}>sub_401000</li>
                    <li style={{ padding: '5px', cursor: 'pointer' }}>sub_401050</li>
                    <li style={{ padding: '5px', cursor: 'pointer' }}>init_array</li>
                </ul>
            </aside>

            {/* Main Editor Area */}
            <div className="editor-container" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                <header className="editor-toolbar" style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                    <div>
                        <button className="secondary-btn" style={{ marginRight: '10px' }}>Save Patch</button>
                        <button className="secondary-btn">Export C</button>
                    </div>
                    <span className="badge" style={{ background: '#333' }}>x86_64</span>
                </header>

                <textarea
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    style={{
                        flex: 1,
                        background: '#151515',
                        color: '#d4d4d4',
                        border: '1px solid #333',
                        padding: '15px',
                        fontFamily: 'monospace',
                        fontSize: '14px',
                        resize: 'none',
                        outline: 'none'
                    }}
                    spellCheck="false"
                />
            </div>
        </div>
    );
};

export default Decompiler;
