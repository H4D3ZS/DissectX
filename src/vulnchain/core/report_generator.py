"""Report generation in multiple formats"""

import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class Evidence:
    """Evidence for a finding"""
    evidence_type: str  # request, response, screenshot, code
    data: str
    description: str
    timestamp: datetime


@dataclass
class Finding:
    """Security finding"""
    finding_id: str
    workspace_id: str
    vulnerability_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    affected_url: str
    proof_of_concept: str
    remediation: str
    discovered_at: datetime
    flags: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)


class ReportGenerator:
    """
    Generate reports in multiple formats (Markdown, PDF, HTML, JSON).
    Includes findings, evidence, and exploitation steps.
    """
    
    def __init__(self):
        """Initialize the Report Generator"""
        pass
    
    def generate_report(
        self,
        findings: List[Finding],
        format: str = "markdown",
        workspace_name: Optional[str] = None,
        target_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """
        Generate report in specified format.
        
        Args:
            findings: List of Finding objects
            format: Report format ('markdown', 'html', 'json', 'pdf')
            workspace_name: Optional workspace name
            target_url: Optional target URL
            metadata: Optional additional metadata
        
        Returns:
            Report data as bytes
        
        Raises:
            ValueError: If format not supported
        """
        if format == "markdown":
            return self._generate_markdown(findings, workspace_name, target_url, metadata)
        elif format == "html":
            return self._generate_html(findings, workspace_name, target_url, metadata)
        elif format == "json":
            return self._generate_json(findings, workspace_name, target_url, metadata)
        elif format == "pdf":
            return self._generate_pdf(findings, workspace_name, target_url, metadata)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_markdown(
        self,
        findings: List[Finding],
        workspace_name: Optional[str],
        target_url: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> bytes:
        """Generate Markdown report"""
        lines = []
        
        # Header
        lines.append("# VulnChain Security Assessment Report")
        lines.append("")
        
        # Metadata
        if workspace_name:
            lines.append(f"**Workspace:** {workspace_name}")
        if target_url:
            lines.append(f"**Target:** {target_url}")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"Total findings: {len(findings)}")
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.severity.lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            lines.append(f"- {severity.capitalize()}: {count}")
        
        lines.append("")
        
        # Findings
        lines.append("## Findings")
        lines.append("")
        
        for i, finding in enumerate(findings, 1):
            lines.append(f"### {i}. {finding.title}")
            lines.append("")
            lines.append(f"**Severity:** {finding.severity.upper()}")
            lines.append(f"**Vulnerability Type:** {finding.vulnerability_type}")
            lines.append(f"**Affected URL:** {finding.affected_url}")
            lines.append(f"**Discovered:** {finding.discovered_at.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append("")
            
            lines.append("**Description:**")
            lines.append("")
            lines.append(finding.description)
            lines.append("")
            
            if finding.proof_of_concept:
                lines.append("**Proof of Concept:**")
                lines.append("")
                lines.append("```")
                lines.append(finding.proof_of_concept)
                lines.append("```")
                lines.append("")
            
            if finding.flags:
                lines.append("**Flags Captured:**")
                lines.append("")
                for flag in finding.flags:
                    lines.append(f"- `{flag}`")
                lines.append("")
            
            if finding.evidence:
                lines.append("**Evidence:**")
                lines.append("")
                for j, evidence in enumerate(finding.evidence, 1):
                    lines.append(f"{j}. {evidence.description} ({evidence.evidence_type})")
                    if evidence.evidence_type in ["request", "response", "code"]:
                        lines.append("```")
                        lines.append(evidence.data[:500])  # Truncate long data
                        if len(evidence.data) > 500:
                            lines.append("... [truncated]")
                        lines.append("```")
                lines.append("")
            
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(finding.remediation)
            lines.append("")
            lines.append("---")
            lines.append("")
        
        # Footer
        lines.append("## Conclusion")
        lines.append("")
        lines.append("This report was automatically generated by VulnChain CTF Framework.")
        lines.append("")
        
        return "\n".join(lines).encode("utf-8")
    
    def _generate_html(
        self,
        findings: List[Finding],
        workspace_name: Optional[str],
        target_url: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> bytes:
        """Generate HTML report"""
        lines = []
        
        # HTML header
        lines.append("<!DOCTYPE html>")
        lines.append("<html>")
        lines.append("<head>")
        lines.append("<meta charset='UTF-8'>")
        lines.append("<title>VulnChain Security Assessment Report</title>")
        lines.append("<style>")
        lines.append(self._get_html_styles())
        lines.append("</style>")
        lines.append("</head>")
        lines.append("<body>")
        
        # Header
        lines.append("<div class='header'>")
        lines.append("<h1>VulnChain Security Assessment Report</h1>")
        if workspace_name:
            lines.append(f"<p><strong>Workspace:</strong> {workspace_name}</p>")
        if target_url:
            lines.append(f"<p><strong>Target:</strong> {target_url}</p>")
        lines.append(f"<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        lines.append("</div>")
        
        # Executive Summary
        lines.append("<div class='summary'>")
        lines.append("<h2>Executive Summary</h2>")
        lines.append(f"<p>Total findings: {len(findings)}</p>")
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.severity.lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        lines.append("<ul>")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            lines.append(f"<li class='severity-{severity}'>{severity.capitalize()}: {count}</li>")
        lines.append("</ul>")
        lines.append("</div>")
        
        # Findings
        lines.append("<div class='findings'>")
        lines.append("<h2>Findings</h2>")
        
        for i, finding in enumerate(findings, 1):
            severity_class = finding.severity.lower()
            lines.append(f"<div class='finding severity-{severity_class}'>")
            lines.append(f"<h3>{i}. {self._html_escape(finding.title)}</h3>")
            
            lines.append("<div class='finding-meta'>")
            lines.append(f"<span class='badge severity-{severity_class}'>{finding.severity.upper()}</span>")
            lines.append(f"<span class='badge'>{finding.vulnerability_type}</span>")
            lines.append("</div>")
            
            lines.append(f"<p><strong>Affected URL:</strong> {self._html_escape(finding.affected_url)}</p>")
            lines.append(f"<p><strong>Discovered:</strong> {finding.discovered_at.strftime('%Y-%m-%d %H:%M:%S')}</p>")
            
            lines.append("<h4>Description</h4>")
            lines.append(f"<p>{self._html_escape(finding.description)}</p>")
            
            if finding.proof_of_concept:
                lines.append("<h4>Proof of Concept</h4>")
                lines.append(f"<pre><code>{self._html_escape(finding.proof_of_concept)}</code></pre>")
            
            if finding.flags:
                lines.append("<h4>Flags Captured</h4>")
                lines.append("<ul>")
                for flag in finding.flags:
                    lines.append(f"<li><code>{self._html_escape(flag)}</code></li>")
                lines.append("</ul>")
            
            if finding.evidence:
                lines.append("<h4>Evidence</h4>")
                lines.append("<ol>")
                for evidence in finding.evidence:
                    lines.append(f"<li>{self._html_escape(evidence.description)} ({evidence.evidence_type})")
                    if evidence.evidence_type in ["request", "response", "code"]:
                        data = evidence.data[:500]
                        if len(evidence.data) > 500:
                            data += "\n... [truncated]"
                        lines.append(f"<pre><code>{self._html_escape(data)}</code></pre>")
                    lines.append("</li>")
                lines.append("</ol>")
            
            lines.append("<h4>Remediation</h4>")
            lines.append(f"<p>{self._html_escape(finding.remediation)}</p>")
            
            lines.append("</div>")
        
        lines.append("</div>")
        
        # Footer
        lines.append("<div class='footer'>")
        lines.append("<p>This report was automatically generated by VulnChain CTF Framework.</p>")
        lines.append("</div>")
        
        lines.append("</body>")
        lines.append("</html>")
        
        return "\n".join(lines).encode("utf-8")
    
    def _generate_json(
        self,
        findings: List[Finding],
        workspace_name: Optional[str],
        target_url: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> bytes:
        """Generate JSON report"""
        report = {
            "report_type": "vulnchain_security_assessment",
            "generated_at": datetime.now().isoformat(),
            "workspace_name": workspace_name,
            "target_url": target_url,
            "metadata": metadata or {},
            "summary": {
                "total_findings": len(findings),
                "by_severity": {},
            },
            "findings": [],
        }
        
        # Count by severity
        for finding in findings:
            severity = finding.severity.lower()
            report["summary"]["by_severity"][severity] = report["summary"]["by_severity"].get(severity, 0) + 1
        
        # Add findings
        for finding in findings:
            finding_dict = {
                "finding_id": finding.finding_id,
                "workspace_id": finding.workspace_id,
                "vulnerability_type": finding.vulnerability_type,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "affected_url": finding.affected_url,
                "proof_of_concept": finding.proof_of_concept,
                "remediation": finding.remediation,
                "discovered_at": finding.discovered_at.isoformat(),
                "flags": finding.flags,
                "evidence": [],
            }
            
            # Add evidence
            for evidence in finding.evidence:
                evidence_dict = {
                    "evidence_type": evidence.evidence_type,
                    "data": evidence.data,
                    "description": evidence.description,
                    "timestamp": evidence.timestamp.isoformat(),
                }
                finding_dict["evidence"].append(evidence_dict)
            
            report["findings"].append(finding_dict)
        
        return json.dumps(report, indent=2).encode("utf-8")
    
    def _generate_pdf(
        self,
        findings: List[Finding],
        workspace_name: Optional[str],
        target_url: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> bytes:
        """
        Generate PDF report.
        
        Note: This is a placeholder implementation that generates HTML
        and would require a library like weasyprint or reportlab for actual PDF generation.
        For now, we'll return HTML that can be converted to PDF by external tools.
        """
        # For a real implementation, you would use a library like:
        # - weasyprint: HTML to PDF
        # - reportlab: Direct PDF generation
        # - pdfkit: HTML to PDF using wkhtmltopdf
        
        # For now, generate HTML that can be printed to PDF
        html_content = self._generate_html(findings, workspace_name, target_url, metadata)
        
        # In a real implementation, convert HTML to PDF here
        # For example with weasyprint:
        # from weasyprint import HTML
        # pdf_bytes = HTML(string=html_content.decode()).write_pdf()
        # return pdf_bytes
        
        # For now, return HTML with a note
        note = b"<!-- PDF generation requires additional libraries like weasyprint or reportlab -->\n"
        return note + html_content
    
    def _get_html_styles(self) -> str:
        """Get CSS styles for HTML report"""
        return """
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0 0 10px 0;
        }
        .summary {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .findings {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .finding {
            border-left: 4px solid #3498db;
            padding: 15px;
            margin-bottom: 20px;
            background-color: #f9f9f9;
        }
        .finding.severity-critical {
            border-left-color: #e74c3c;
        }
        .finding.severity-high {
            border-left-color: #e67e22;
        }
        .finding.severity-medium {
            border-left-color: #f39c12;
        }
        .finding.severity-low {
            border-left-color: #3498db;
        }
        .finding.severity-info {
            border-left-color: #95a5a6;
        }
        .finding-meta {
            margin: 10px 0;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 5px;
            background-color: #3498db;
            color: white;
        }
        .badge.severity-critical {
            background-color: #e74c3c;
        }
        .badge.severity-high {
            background-color: #e67e22;
        }
        .badge.severity-medium {
            background-color: #f39c12;
        }
        .badge.severity-low {
            background-color: #3498db;
        }
        .badge.severity-info {
            background-color: #95a5a6;
        }
        pre {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        code {
            font-family: 'Courier New', monospace;
        }
        .footer {
            text-align: center;
            color: #7f8c8d;
            margin-top: 40px;
            padding: 20px;
        }
        ul.severity-list {
            list-style: none;
            padding: 0;
        }
        li.severity-critical { color: #e74c3c; }
        li.severity-high { color: #e67e22; }
        li.severity-medium { color: #f39c12; }
        li.severity-low { color: #3498db; }
        li.severity-info { color: #95a5a6; }
        """
    
    def _html_escape(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))
