import React from 'react';
import { NavLink } from 'react-router-dom';

function Sidebar() {
    return (
        <aside className="sidebar">
            <div className="brand">
                <h1><i className="fas fa-microchip"></i> DissectX</h1>
            </div>
            <nav className="nav-menu">
                <NavLink to="/" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                    <i className="fas fa-tachometer-alt"></i> Dashboard
                </NavLink>
                <NavLink to="/pentest" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                    <i className="fas fa-shield-alt"></i> Vulnerability Assessment
                </NavLink>
                <NavLink to="/phisher" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                    <i className="fas fa-fish"></i> Phisher
                </NavLink>
                <NavLink to="/network" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                    <i className="fas fa-network-wired"></i> Infrastructure Graph
                </NavLink>
                <NavLink to="/decompiler" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                    <i className="fas fa-code"></i> Reverse Engineering
                </NavLink>
                <NavLink to="/debugger" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                    <i className="fas fa-bug"></i> Dynamic Analysis
                </NavLink>
                <NavLink to="/reports" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                    <i className="fas fa-file-contract"></i> Security Audit Reports
                </NavLink>
                <div className="nav-divider"></div>
                <NavLink to="/mobile-rev" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                    <i className="fas fa-mobile-alt"></i> Mobile Security Research
                </NavLink>
                <NavLink to="/settings" className={({ isActive }) => isActive ? "nav-item active" : "nav-item"}>
                    <i className="fas fa-cog"></i> Configuration
                </NavLink>
            </nav>
            <div className="sidebar-footer">
                <div className="status-indicator online">
                    <span className="dot"></span> System Online
                </div>
            </div>
        </aside>
    );
}

export default Sidebar;
