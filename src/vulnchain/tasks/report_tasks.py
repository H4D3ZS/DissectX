"""Background tasks for report generation"""
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
from celery import Task
from celery.utils.log import get_task_logger

from src.vulnchain.core.celery_app import celery_app

logger = get_task_logger(__name__)


class ReportTask(Task):
    """Base task class for report generation with progress tracking"""
    
    def __init__(self):
        super().__init__()
        self._progress = 0
        self._status = "pending"
        self._current_step = ""
    
    def update_progress(self, progress: int, status: str, current_step: str = ""):
        """Update task progress"""
        self._progress = progress
        self._status = status
        self._current_step = current_step
        
        # Update task state
        self.update_state(
            state="PROGRESS",
            meta={
                "progress": progress,
                "status": status,
                "current_step": current_step,
            }
        )


@celery_app.task(
    bind=True,
    base=ReportTask,
    name="app.tasks.report_tasks.generate_markdown_report"
)
def generate_markdown_report(
    self,
    workspace_id: int,
    user_id: int,
    findings: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate Markdown report.
    
    Args:
        workspace_id: Workspace ID
        user_id: User ID
        findings: List of findings to include
        options: Optional report options
        
    Returns:
        Report generation result
    """
    logger.info(f"Generating Markdown report for workspace {workspace_id}")
    self.update_progress(0, "starting", "Initializing report generation")
    
    try:
        # Build report content
        self.update_progress(20, "building", "Building report structure")
        
        report_lines = [
            "# VulnChain Security Assessment Report",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Workspace ID:** {workspace_id}",
            "",
            "## Executive Summary",
            "",
            f"This report contains {len(findings)} findings from the security assessment.",
            "",
            "## Findings",
            "",
        ]
        
        # Add findings
        self.update_progress(40, "processing", "Processing findings")
        
        for i, finding in enumerate(findings):
            severity = finding.get("severity", "Unknown")
            title = finding.get("title", "Untitled Finding")
            description = finding.get("description", "No description")
            
            report_lines.extend([
                f"### {i + 1}. {title}",
                "",
                f"**Severity:** {severity}",
                "",
                f"**Description:**",
                description,
                "",
                "---",
                "",
            ])
        
        # Add recommendations
        self.update_progress(70, "finalizing", "Adding recommendations")
        
        report_lines.extend([
            "## Recommendations",
            "",
            "1. Review and remediate all critical and high severity findings",
            "2. Implement security best practices",
            "3. Conduct regular security assessments",
            "",
            "## Conclusion",
            "",
            "This assessment identified several security issues that should be addressed.",
            "",
        ])
        
        # Generate final report
        self.update_progress(90, "generating", "Generating final report")
        report_content = "\n".join(report_lines)
        
        self.update_progress(100, "completed", "Report generation complete")
        
        return {
            "status": "success",
            "workspace_id": workspace_id,
            "format": "markdown",
            "content": report_content,
            "findings_count": len(findings),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Markdown report generation failed: {e}")
        self.update_progress(0, "failed", f"Error: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "workspace_id": workspace_id,
        }


@celery_app.task(
    bind=True,
    base=ReportTask,
    name="app.tasks.report_tasks.generate_json_report"
)
def generate_json_report(
    self,
    workspace_id: int,
    user_id: int,
    findings: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate JSON report.
    
    Args:
        workspace_id: Workspace ID
        user_id: User ID
        findings: List of findings to include
        options: Optional report options
        
    Returns:
        Report generation result
    """
    logger.info(f"Generating JSON report for workspace {workspace_id}")
    self.update_progress(0, "starting", "Initializing report generation")
    
    try:
        self.update_progress(30, "building", "Building report structure")
        
        report_data = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "workspace_id": workspace_id,
                "user_id": user_id,
                "findings_count": len(findings),
            },
            "findings": findings,
            "summary": {
                "total": len(findings),
                "by_severity": {},
            },
        }
        
        # Count by severity
        self.update_progress(60, "processing", "Processing findings")
        
        for finding in findings:
            severity = finding.get("severity", "Unknown")
            report_data["summary"]["by_severity"][severity] = \
                report_data["summary"]["by_severity"].get(severity, 0) + 1
        
        # Generate JSON
        self.update_progress(90, "generating", "Generating final report")
        report_content = json.dumps(report_data, indent=2)
        
        self.update_progress(100, "completed", "Report generation complete")
        
        return {
            "status": "success",
            "workspace_id": workspace_id,
            "format": "json",
            "content": report_content,
            "findings_count": len(findings),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"JSON report generation failed: {e}")
        self.update_progress(0, "failed", f"Error: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "workspace_id": workspace_id,
        }


@celery_app.task(
    bind=True,
    base=ReportTask,
    name="app.tasks.report_tasks.generate_html_report"
)
def generate_html_report(
    self,
    workspace_id: int,
    user_id: int,
    findings: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate HTML report.
    
    Args:
        workspace_id: Workspace ID
        user_id: User ID
        findings: List of findings to include
        options: Optional report options
        
    Returns:
        Report generation result
    """
    logger.info(f"Generating HTML report for workspace {workspace_id}")
    self.update_progress(0, "starting", "Initializing report generation")
    
    try:
        self.update_progress(20, "building", "Building report structure")
        
        # Build HTML content
        html_parts = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "    <meta charset='UTF-8'>",
            "    <title>VulnChain Security Assessment Report</title>",
            "    <style>",
            "        body { font-family: Arial, sans-serif; margin: 40px; }",
            "        h1 { color: #333; }",
            "        .finding { border: 1px solid #ddd; padding: 15px; margin: 10px 0; }",
            "        .critical { border-left: 5px solid #d32f2f; }",
            "        .high { border-left: 5px solid #f57c00; }",
            "        .medium { border-left: 5px solid #fbc02d; }",
            "        .low { border-left: 5px solid #388e3c; }",
            "        .info { border-left: 5px solid #1976d2; }",
            "    </style>",
            "</head>",
            "<body>",
            "    <h1>VulnChain Security Assessment Report</h1>",
            f"    <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>",
            f"    <p><strong>Workspace ID:</strong> {workspace_id}</p>",
            "    <h2>Executive Summary</h2>",
            f"    <p>This report contains {len(findings)} findings from the security assessment.</p>",
            "    <h2>Findings</h2>",
        ]
        
        # Add findings
        self.update_progress(50, "processing", "Processing findings")
        
        for i, finding in enumerate(findings):
            severity = finding.get("severity", "Unknown").lower()
            title = finding.get("title", "Untitled Finding")
            description = finding.get("description", "No description")
            
            html_parts.extend([
                f"    <div class='finding {severity}'>",
                f"        <h3>{i + 1}. {title}</h3>",
                f"        <p><strong>Severity:</strong> {severity.upper()}</p>",
                f"        <p><strong>Description:</strong> {description}</p>",
                "    </div>",
            ])
        
        # Close HTML
        self.update_progress(80, "finalizing", "Finalizing report")
        
        html_parts.extend([
            "    <h2>Recommendations</h2>",
            "    <ul>",
            "        <li>Review and remediate all critical and high severity findings</li>",
            "        <li>Implement security best practices</li>",
            "        <li>Conduct regular security assessments</li>",
            "    </ul>",
            "</body>",
            "</html>",
        ])
        
        report_content = "\n".join(html_parts)
        
        self.update_progress(100, "completed", "Report generation complete")
        
        return {
            "status": "success",
            "workspace_id": workspace_id,
            "format": "html",
            "content": report_content,
            "findings_count": len(findings),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"HTML report generation failed: {e}")
        self.update_progress(0, "failed", f"Error: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "workspace_id": workspace_id,
        }


@celery_app.task(
    bind=True,
    base=ReportTask,
    name="app.tasks.report_tasks.generate_pdf_report"
)
def generate_pdf_report(
    self,
    workspace_id: int,
    user_id: int,
    findings: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate PDF report.
    
    Note: This is a placeholder. Actual PDF generation would require
    additional libraries like ReportLab or WeasyPrint.
    
    Args:
        workspace_id: Workspace ID
        user_id: User ID
        findings: List of findings to include
        options: Optional report options
        
    Returns:
        Report generation result
    """
    logger.info(f"Generating PDF report for workspace {workspace_id}")
    self.update_progress(0, "starting", "Initializing PDF generation")
    
    try:
        # For now, generate HTML and note that PDF conversion is needed
        self.update_progress(30, "generating", "Generating HTML content")
        
        html_result = generate_html_report(
            workspace_id,
            user_id,
            findings,
            options
        )
        
        self.update_progress(80, "converting", "Converting to PDF (placeholder)")
        
        # In a real implementation, you would convert HTML to PDF here
        # using libraries like WeasyPrint, ReportLab, or wkhtmltopdf
        
        self.update_progress(100, "completed", "PDF generation complete")
        
        return {
            "status": "success",
            "workspace_id": workspace_id,
            "format": "pdf",
            "note": "PDF generation requires additional setup. HTML content provided.",
            "html_content": html_result.get("content"),
            "findings_count": len(findings),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"PDF report generation failed: {e}")
        self.update_progress(0, "failed", f"Error: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "workspace_id": workspace_id,
        }
