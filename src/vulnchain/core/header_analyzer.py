"""Header Analysis Module

This module provides security header analysis, misconfiguration detection,
and information disclosure detection for HTTP responses.

Validates Requirements: 20.1, 20.2, 20.3, 20.4, 20.5
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum


class Severity(Enum):
    """Severity levels for security findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class HeaderFinding:
    """A security finding related to HTTP headers"""
    
    header_name: str
    severity: Severity
    issue_type: str  # "missing", "misconfigured", "information_disclosure"
    description: str
    current_value: Optional[str] = None
    recommended_value: Optional[str] = None
    remediation: str = ""
    cve_references: List[str] = field(default_factory=list)


@dataclass
class SecurityScore:
    """Overall security score for header analysis"""
    
    total_score: int  # 0-100
    grade: str  # A+, A, B, C, D, F
    findings_by_severity: Dict[Severity, int]
    total_findings: int
    headers_analyzed: int
    security_headers_present: int
    security_headers_missing: int


class HeaderAnalyzer:
    """
    Analyzes HTTP response headers for security issues.
    
    This class provides functionality to:
    - Extract and analyze security-relevant headers
    - Identify missing security headers
    - Detect weak or misconfigured headers
    - Flag information disclosure headers
    - Generate security score dashboard
    """
    
    # Security headers that should be present
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "severity": Severity.HIGH,
            "description": "Content Security Policy helps prevent XSS and data injection attacks",
            "recommended": "default-src 'self'; script-src 'self'; object-src 'none'",
            "remediation": "Implement a strict Content Security Policy to control resource loading"
        },
        "Strict-Transport-Security": {
            "severity": Severity.HIGH,
            "description": "HTTP Strict Transport Security enforces HTTPS connections",
            "recommended": "max-age=31536000; includeSubDomains; preload",
            "remediation": "Enable HSTS with a long max-age and includeSubDomains directive"
        },
        "X-Frame-Options": {
            "severity": Severity.MEDIUM,
            "description": "X-Frame-Options prevents clickjacking attacks",
            "recommended": "DENY or SAMEORIGIN",
            "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking"
        },
        "X-Content-Type-Options": {
            "severity": Severity.MEDIUM,
            "description": "X-Content-Type-Options prevents MIME type sniffing",
            "recommended": "nosniff",
            "remediation": "Set X-Content-Type-Options to nosniff to prevent MIME confusion attacks"
        },
        "Referrer-Policy": {
            "severity": Severity.LOW,
            "description": "Referrer-Policy controls referrer information leakage",
            "recommended": "no-referrer or strict-origin-when-cross-origin",
            "remediation": "Set Referrer-Policy to limit referrer information exposure"
        },
        "Permissions-Policy": {
            "severity": Severity.LOW,
            "description": "Permissions-Policy controls browser feature access",
            "recommended": "geolocation=(), microphone=(), camera=()",
            "remediation": "Use Permissions-Policy to restrict access to sensitive browser features"
        },
        "X-XSS-Protection": {
            "severity": Severity.LOW,
            "description": "X-XSS-Protection enables browser XSS filtering (deprecated but still useful)",
            "recommended": "1; mode=block",
            "remediation": "Enable X-XSS-Protection as defense-in-depth (use CSP as primary protection)"
        }
    }
    
    # Headers that may disclose sensitive information
    INFORMATION_DISCLOSURE_HEADERS = {
        "Server": {
            "severity": Severity.LOW,
            "description": "Server header reveals web server software and version",
            "remediation": "Remove or obfuscate the Server header to hide technology stack"
        },
        "X-Powered-By": {
            "severity": Severity.LOW,
            "description": "X-Powered-By header reveals application framework and version",
            "remediation": "Remove X-Powered-By header to hide framework information"
        },
        "X-AspNet-Version": {
            "severity": Severity.LOW,
            "description": "X-AspNet-Version reveals ASP.NET version",
            "remediation": "Disable X-AspNet-Version header in web.config"
        },
        "X-AspNetMvc-Version": {
            "severity": Severity.LOW,
            "description": "X-AspNetMvc-Version reveals ASP.NET MVC version",
            "remediation": "Disable X-AspNetMvc-Version header in Global.asax"
        },
        "X-Generator": {
            "severity": Severity.INFO,
            "description": "X-Generator reveals CMS or site generator",
            "remediation": "Remove X-Generator header to hide CMS information"
        }
    }
    
    # Weak configurations for security headers
    WEAK_CONFIGURATIONS = {
        "Content-Security-Policy": [
            ("unsafe-inline", Severity.HIGH, "CSP allows 'unsafe-inline' which defeats XSS protection"),
            ("unsafe-eval", Severity.HIGH, "CSP allows 'unsafe-eval' which enables code injection"),
            ("*", Severity.MEDIUM, "CSP uses wildcard (*) which is too permissive")
        ],
        "Strict-Transport-Security": [
            ("max-age=0", Severity.HIGH, "HSTS max-age is set to 0, disabling protection"),
            ("max-age=", Severity.MEDIUM, "HSTS max-age is too short (should be at least 31536000)")
        ],
        "X-Frame-Options": [
            ("ALLOW-FROM", Severity.MEDIUM, "X-Frame-Options ALLOW-FROM is deprecated and not widely supported")
        ],
        "Referrer-Policy": [
            ("unsafe-url", Severity.MEDIUM, "Referrer-Policy set to unsafe-url leaks full URL"),
            ("no-referrer-when-downgrade", Severity.LOW, "Referrer-Policy may leak information on downgrade")
        ]
    }
    
    def __init__(self):
        """Initialize the HeaderAnalyzer."""
        self.findings: List[HeaderFinding] = []
    
    def analyze_headers(self, headers: Dict[str, str]) -> List[HeaderFinding]:
        """
        Analyze HTTP response headers for security issues.
        
        Validates: Requirements 20.1, 20.2, 20.3, 20.4
        
        Args:
            headers: Dictionary of HTTP response headers (case-insensitive keys)
            
        Returns:
            List of HeaderFinding objects describing security issues
        """
        self.findings = []
        
        # Normalize header names to be case-insensitive
        normalized_headers = {k.lower(): (k, v) for k, v in headers.items()}
        
        # Check for missing security headers
        self._check_missing_headers(normalized_headers)
        
        # Check for misconfigured security headers
        self._check_misconfigurations(normalized_headers)
        
        # Check for information disclosure headers
        self._check_information_disclosure(normalized_headers)
        
        return self.findings
    
    def _check_missing_headers(self, normalized_headers: Dict[str, Tuple[str, str]]):
        """
        Check for missing security headers.
        
        Validates: Requirements 20.2
        
        Args:
            normalized_headers: Dictionary with lowercase keys mapping to (original_name, value)
        """
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name.lower() not in normalized_headers:
                finding = HeaderFinding(
                    header_name=header_name,
                    severity=header_info["severity"],
                    issue_type="missing",
                    description=f"Missing security header: {header_info['description']}",
                    current_value=None,
                    recommended_value=header_info["recommended"],
                    remediation=header_info["remediation"]
                )
                self.findings.append(finding)
    
    def _check_misconfigurations(self, normalized_headers: Dict[str, Tuple[str, str]]):
        """
        Check for misconfigured security headers.
        
        Validates: Requirements 20.3
        
        Args:
            normalized_headers: Dictionary with lowercase keys mapping to (original_name, value)
        """
        for header_name, weak_configs in self.WEAK_CONFIGURATIONS.items():
            header_key = header_name.lower()
            
            if header_key in normalized_headers:
                original_name, header_value = normalized_headers[header_key]
                header_value_lower = header_value.lower()
                
                for pattern, severity, description in weak_configs:
                    if pattern.lower() in header_value_lower:
                        # Special handling for max-age check
                        if "max-age=" in pattern and "max-age=" in header_value_lower:
                            try:
                                # Extract max-age value
                                max_age_part = [p for p in header_value_lower.split(';') if 'max-age=' in p][0]
                                max_age_value = int(max_age_part.split('=')[1].strip())
                                
                                # Check if max-age is too short (less than 1 year)
                                if max_age_value < 31536000 and max_age_value > 0:
                                    finding = HeaderFinding(
                                        header_name=original_name,
                                        severity=severity,
                                        issue_type="misconfigured",
                                        description=description,
                                        current_value=header_value,
                                        recommended_value=self.SECURITY_HEADERS[header_name]["recommended"],
                                        remediation=f"Increase max-age to at least 31536000 (1 year)"
                                    )
                                    self.findings.append(finding)
                                elif max_age_value == 0:
                                    finding = HeaderFinding(
                                        header_name=original_name,
                                        severity=Severity.HIGH,
                                        issue_type="misconfigured",
                                        description="HSTS max-age is set to 0, disabling protection",
                                        current_value=header_value,
                                        recommended_value=self.SECURITY_HEADERS[header_name]["recommended"],
                                        remediation="Set max-age to at least 31536000 (1 year)"
                                    )
                                    self.findings.append(finding)
                            except (ValueError, IndexError):
                                pass
                        else:
                            finding = HeaderFinding(
                                header_name=original_name,
                                severity=severity,
                                issue_type="misconfigured",
                                description=description,
                                current_value=header_value,
                                recommended_value=self.SECURITY_HEADERS[header_name]["recommended"],
                                remediation=self.SECURITY_HEADERS[header_name]["remediation"]
                            )
                            self.findings.append(finding)
    
    def _check_information_disclosure(self, normalized_headers: Dict[str, Tuple[str, str]]):
        """
        Check for headers that disclose sensitive information.
        
        Validates: Requirements 20.4
        
        Args:
            normalized_headers: Dictionary with lowercase keys mapping to (original_name, value)
        """
        for header_name, header_info in self.INFORMATION_DISCLOSURE_HEADERS.items():
            header_key = header_name.lower()
            
            if header_key in normalized_headers:
                original_name, header_value = normalized_headers[header_key]
                
                finding = HeaderFinding(
                    header_name=original_name,
                    severity=header_info["severity"],
                    issue_type="information_disclosure",
                    description=header_info["description"],
                    current_value=header_value,
                    recommended_value="<removed>",
                    remediation=header_info["remediation"]
                )
                self.findings.append(finding)
    
    def calculate_security_score(self, headers: Dict[str, str]) -> SecurityScore:
        """
        Calculate an overall security score based on header analysis.
        
        Validates: Requirements 20.5
        
        Args:
            headers: Dictionary of HTTP response headers
            
        Returns:
            SecurityScore object with overall security posture
        """
        # Analyze headers if not already done
        if not self.findings:
            self.analyze_headers(headers)
        
        # Count findings by severity
        findings_by_severity = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0
        }
        
        for finding in self.findings:
            findings_by_severity[finding.severity] += 1
        
        # Calculate score (start at 100, deduct points for findings)
        score = 100
        score -= findings_by_severity[Severity.CRITICAL] * 25
        score -= findings_by_severity[Severity.HIGH] * 15
        score -= findings_by_severity[Severity.MEDIUM] * 10
        score -= findings_by_severity[Severity.LOW] * 5
        score -= findings_by_severity[Severity.INFO] * 2
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        # Determine grade
        if score >= 95:
            grade = "A+"
        elif score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        # Count security headers
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        security_headers_present = sum(
            1 for h in self.SECURITY_HEADERS.keys()
            if h.lower() in normalized_headers
        )
        security_headers_missing = len(self.SECURITY_HEADERS) - security_headers_present
        
        return SecurityScore(
            total_score=score,
            grade=grade,
            findings_by_severity=findings_by_severity,
            total_findings=len(self.findings),
            headers_analyzed=len(headers),
            security_headers_present=security_headers_present,
            security_headers_missing=security_headers_missing
        )
    
    def generate_report(self, headers: Dict[str, str], format: str = "text") -> str:
        """
        Generate a formatted report of header analysis results.
        
        Args:
            headers: Dictionary of HTTP response headers
            format: Report format - "text", "json", or "markdown"
            
        Returns:
            Formatted report string
        """
        # Ensure analysis is done
        if not self.findings:
            self.analyze_headers(headers)
        
        score = self.calculate_security_score(headers)
        
        if format == "text":
            return self._generate_text_report(score)
        elif format == "markdown":
            return self._generate_markdown_report(score)
        elif format == "json":
            import json
            return json.dumps({
                "score": score.total_score,
                "grade": score.grade,
                "findings": [
                    {
                        "header": f.header_name,
                        "severity": f.severity.value,
                        "type": f.issue_type,
                        "description": f.description,
                        "current_value": f.current_value,
                        "recommended_value": f.recommended_value,
                        "remediation": f.remediation
                    }
                    for f in self.findings
                ]
            }, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_text_report(self, score: SecurityScore) -> str:
        """Generate plain text report."""
        lines = []
        lines.append("=" * 60)
        lines.append("HTTP SECURITY HEADER ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append(f"\nOverall Security Score: {score.total_score}/100 (Grade: {score.grade})")
        lines.append(f"Total Findings: {score.total_findings}")
        lines.append(f"Security Headers Present: {score.security_headers_present}/{len(self.SECURITY_HEADERS)}")
        lines.append(f"Security Headers Missing: {score.security_headers_missing}")
        lines.append("\nFindings by Severity:")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = score.findings_by_severity[severity]
            if count > 0:
                lines.append(f"  {severity.value.upper()}: {count}")
        
        if self.findings:
            lines.append("\n" + "=" * 60)
            lines.append("DETAILED FINDINGS")
            lines.append("=" * 60)
            
            for i, finding in enumerate(self.findings, 1):
                lines.append(f"\n[{i}] {finding.header_name}")
                lines.append(f"    Severity: {finding.severity.value.upper()}")
                lines.append(f"    Type: {finding.issue_type}")
                lines.append(f"    Description: {finding.description}")
                if finding.current_value:
                    lines.append(f"    Current Value: {finding.current_value}")
                if finding.recommended_value:
                    lines.append(f"    Recommended: {finding.recommended_value}")
                if finding.remediation:
                    lines.append(f"    Remediation: {finding.remediation}")
        
        return "\n".join(lines)
    
    def _generate_markdown_report(self, score: SecurityScore) -> str:
        """Generate markdown report."""
        lines = []
        lines.append("# HTTP Security Header Analysis Report")
        lines.append(f"\n## Overall Security Score: {score.total_score}/100 (Grade: {score.grade})")
        lines.append(f"\n- **Total Findings:** {score.total_findings}")
        lines.append(f"- **Security Headers Present:** {score.security_headers_present}/{len(self.SECURITY_HEADERS)}")
        lines.append(f"- **Security Headers Missing:** {score.security_headers_missing}")
        
        lines.append("\n### Findings by Severity")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = score.findings_by_severity[severity]
            if count > 0:
                lines.append(f"- **{severity.value.upper()}:** {count}")
        
        if self.findings:
            lines.append("\n## Detailed Findings")
            
            for i, finding in enumerate(self.findings, 1):
                lines.append(f"\n### [{i}] {finding.header_name}")
                lines.append(f"- **Severity:** {finding.severity.value.upper()}")
                lines.append(f"- **Type:** {finding.issue_type}")
                lines.append(f"- **Description:** {finding.description}")
                if finding.current_value:
                    lines.append(f"- **Current Value:** `{finding.current_value}`")
                if finding.recommended_value:
                    lines.append(f"- **Recommended:** `{finding.recommended_value}`")
                if finding.remediation:
                    lines.append(f"- **Remediation:** {finding.remediation}")
        
        return "\n".join(lines)
    
    def get_findings_by_severity(self, severity: Severity) -> List[HeaderFinding]:
        """
        Get all findings of a specific severity level.
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of findings matching the severity level
        """
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_type(self, issue_type: str) -> List[HeaderFinding]:
        """
        Get all findings of a specific type.
        
        Args:
            issue_type: Issue type to filter by ("missing", "misconfigured", "information_disclosure")
            
        Returns:
            List of findings matching the issue type
        """
        return [f for f in self.findings if f.issue_type == issue_type]
    
    def clear_findings(self):
        """Clear all stored findings."""
        self.findings.clear()
