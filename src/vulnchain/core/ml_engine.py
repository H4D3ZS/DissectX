"""
ML Engine for Vulnerability Prediction

This module provides machine learning capabilities for predicting vulnerabilities,
analyzing error messages, ranking attack vectors, and adaptive learning from
attack attempts.

Requirements: 36.1, 36.2, 36.3, 36.4, 36.5
"""

import re
import json
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict, Counter
import logging

logger = logging.getLogger(__name__)


@dataclass
class TargetInfo:
    """Information about a target for vulnerability prediction"""
    url: str
    technologies: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    server_software: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    status_codes: List[int] = field(default_factory=list)
    error_messages: List[str] = field(default_factory=list)
    detected_cms: Optional[str] = None
    detected_language: Optional[str] = None
    has_javascript: bool = False
    has_api: bool = False
    has_websocket: bool = False


@dataclass
class VulnerabilityPrediction:
    """Prediction of a vulnerability class"""
    vulnerability_type: str
    confidence: float  # 0.0 to 1.0
    reasoning: str
    suggested_modules: List[str] = field(default_factory=list)
    priority: int = 1  # 1 (highest) to 5 (lowest)


@dataclass
class ErrorAnalysis:
    """Analysis of an error message"""
    error_type: str
    hints: List[str] = field(default_factory=list)
    suggested_exploits: List[str] = field(default_factory=list)
    confidence: float = 0.0
    extracted_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackVector:
    """An attack vector to be ranked"""
    module_name: str
    vulnerability_type: str
    description: str
    estimated_time: float = 0.0  # seconds
    complexity: str = "medium"  # low, medium, high


@dataclass
class RankedVector:
    """A ranked attack vector"""
    vector: AttackVector
    score: float  # Combined score
    exploitation_probability: float
    time_to_flag: float
    rank: int


@dataclass
class AttackAttempt:
    """Record of an attack attempt"""
    module_name: str
    vulnerability_type: str
    target_url: str
    payload: str
    timestamp: datetime
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    """Result of an attack attempt"""
    success: bool
    vulnerability_found: bool
    response_time: float
    status_code: int
    error_message: Optional[str] = None
    flags_found: List[str] = field(default_factory=list)


class MLEngine:
    """
    Machine Learning Engine for vulnerability prediction and adaptive attacks.
    
    This is a rule-based implementation that simulates ML behavior using
    heuristics and pattern matching. In a production system, this would
    use trained models (scikit-learn, TensorFlow, etc.).
    """
    
    def __init__(self):
        """Initialize the ML engine with knowledge bases"""
        self.vulnerability_patterns = self._initialize_vulnerability_patterns()
        self.error_patterns = self._initialize_error_patterns()
        self.technology_vulnerabilities = self._initialize_technology_vulnerabilities()
        self.attack_history: List[Tuple[AttackAttempt, AttackResult]] = []
        self.success_patterns: Dict[str, List[str]] = defaultdict(list)
        self.failure_patterns: Dict[str, List[str]] = defaultdict(list)
        
    def _initialize_vulnerability_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize patterns for vulnerability prediction"""
        return {
            "sql_injection": {
                "indicators": ["mysql", "postgresql", "mssql", "oracle", "database", "db"],
                "response_patterns": ["sql", "syntax error", "mysql_", "pg_", "ora-"],
                "confidence_boost": 0.3,
                "modules": ["sql_injection"],
                "priority": 1
            },
            "xss": {
                "indicators": ["javascript", "react", "vue", "angular", "jquery"],
                "response_patterns": ["<script", "onerror", "onclick"],
                "confidence_boost": 0.25,
                "modules": ["xss"],
                "priority": 2
            },
            "command_injection": {
                "indicators": ["linux", "unix", "bash", "shell", "exec"],
                "response_patterns": ["sh:", "bash:", "command not found"],
                "confidence_boost": 0.35,
                "modules": ["command_injection"],
                "priority": 1
            },
            "ssrf": {
                "indicators": ["proxy", "fetch", "curl", "wget", "http client"],
                "response_patterns": ["connection refused", "timeout", "unreachable"],
                "confidence_boost": 0.3,
                "modules": ["ssrf"],
                "priority": 2
            },
            "xxe": {
                "indicators": ["xml", "soap", "xmlparser", "libxml"],
                "response_patterns": ["xml", "entity", "dtd"],
                "confidence_boost": 0.35,
                "modules": ["xxe"],
                "priority": 2
            },
            "ssti": {
                "indicators": ["jinja", "jinja2", "flask", "django", "twig", "freemarker"],
                "response_patterns": ["template", "render", "jinja"],
                "confidence_boost": 0.4,
                "modules": ["ssti"],
                "priority": 1
            },
            "jwt_manipulation": {
                "indicators": ["jwt", "json web token", "bearer"],
                "response_patterns": ["jwt", "token", "bearer"],
                "confidence_boost": 0.3,
                "modules": ["jwt_manipulation"],
                "priority": 2
            },
            "deserialization": {
                "indicators": ["java", "pickle", "serialize", "unserialize"],
                "response_patterns": ["serialization", "deserialize", "object"],
                "confidence_boost": 0.35,
                "modules": ["deserialization"],
                "priority": 1
            },
            "nosql_injection": {
                "indicators": ["mongodb", "couchdb", "nosql", "mongoose"],
                "response_patterns": ["mongo", "bson", "$where"],
                "confidence_boost": 0.3,
                "modules": ["nosql_injection"],
                "priority": 2
            },
            "prototype_pollution": {
                "indicators": ["node", "nodejs", "express", "javascript"],
                "response_patterns": ["__proto__", "constructor", "prototype"],
                "confidence_boost": 0.25,
                "modules": ["prototype_pollution"],
                "priority": 3
            },
            "graphql": {
                "indicators": ["graphql", "apollo", "relay"],
                "response_patterns": ["graphql", "query", "mutation"],
                "confidence_boost": 0.4,
                "modules": ["api_testing"],
                "priority": 2
            },
            "api_vulnerabilities": {
                "indicators": ["rest", "api", "swagger", "openapi"],
                "response_patterns": ["api", "endpoint", "swagger"],
                "confidence_boost": 0.2,
                "modules": ["api_testing"],
                "priority": 3
            }
        }
    
    def _initialize_error_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize patterns for error message analysis"""
        return {
            "sql_error": {
                "patterns": [
                    r"SQL syntax.*?error",
                    r"ORA-\d+",
                    r"SQLite.*?error",
                    r"SQLSTATE\[\d+\]",
                    r"Unclosed quotation mark",
                    r"quoted string not properly terminated",
                    r"error in your SQL syntax"
                ],
                "hints": [
                    "SQL injection vulnerability likely present",
                    "Database error messages are being exposed",
                    "Try single quote (') to break out of query"
                ],
                "exploits": [
                    "Time-based blind SQL injection",
                    "Boolean-based blind SQL injection",
                    "Error-based SQL injection",
                    "UNION-based SQL injection"
                ],
                "extracted_fields": ["database_type", "table_name", "column_name"]
            },
            "php_error": {
                "patterns": [
                    r"Warning:.*?in /.*?\.php",
                    r"Fatal error:.*?in /.*?\.php",
                    r"Parse error:.*?in /.*?\.php",
                    r"Notice:.*?in /.*?\.php",
                    r"mysql_fetch"
                ],
                "hints": [
                    "PHP error disclosure reveals file paths",
                    "Application may be vulnerable to LFI/RFI",
                    "Error messages expose internal structure"
                ],
                "exploits": [
                    "Local file inclusion",
                    "Remote file inclusion",
                    "Directory traversal",
                    "PHP deserialization"
                ],
                "extracted_fields": ["file_path", "line_number", "function_name"]
            },
            "python_error": {
                "patterns": [
                    r"Traceback \(most recent call last\)",
                    r"File \".*?\.py\", line \d+",
                    r"[A-Z][a-z]+Error:",
                    r"django\.",
                    r"flask\."
                ],
                "hints": [
                    "Python stack trace reveals application structure",
                    "Framework information exposed",
                    "Potential SSTI if template engine is used"
                ],
                "exploits": [
                    "Server-side template injection",
                    "Python deserialization (pickle)",
                    "Command injection via subprocess",
                    "Path traversal"
                ],
                "extracted_fields": ["file_path", "framework", "error_type"]
            },
            "java_error": {
                "patterns": [
                    r"java\.[a-z]+\.[A-Z][a-zA-Z]+Exception",
                    r"at [a-z]+\.[a-z]+\.[A-Z]",
                    r"Caused by:",
                    r"springframework",
                    r"javax\."
                ],
                "hints": [
                    "Java stack trace reveals class structure",
                    "Potential deserialization vulnerability",
                    "Framework version may be exploitable"
                ],
                "exploits": [
                    "Java deserialization (ysoserial)",
                    "XXE in XML parsers",
                    "Expression language injection",
                    "Spring framework exploits"
                ],
                "extracted_fields": ["class_name", "framework", "library_version"]
            },
            "command_error": {
                "patterns": [
                    r"sh: .*?: command not found",
                    r"bash: .*?: command not found",
                    r"/bin/sh",
                    r"/bin/bash",
                    r"Permission denied"
                ],
                "hints": [
                    "Command injection vulnerability confirmed",
                    "Shell access may be possible",
                    "System commands are being executed"
                ],
                "exploits": [
                    "Command injection with OOB",
                    "Reverse shell",
                    "File read/write via shell",
                    "Privilege escalation"
                ],
                "extracted_fields": ["shell_type", "command", "user"]
            },
            "template_error": {
                "patterns": [
                    r"jinja2\.exceptions",
                    r"TemplateSyntaxError",
                    r"UndefinedError",
                    r"Template.*?not found",
                    r"Twig_Error"
                ],
                "hints": [
                    "Template engine error indicates SSTI potential",
                    "Template syntax is being evaluated",
                    "Server-side template injection likely"
                ],
                "exploits": [
                    "Jinja2 SSTI to RCE",
                    "Twig SSTI",
                    "Freemarker SSTI",
                    "Velocity SSTI"
                ],
                "extracted_fields": ["template_engine", "template_name"]
            },
            "xml_error": {
                "patterns": [
                    r"XML.*?error",
                    r"Entity.*?not defined",
                    r"DTD.*?forbidden",
                    r"External entity",
                    r"libxml"
                ],
                "hints": [
                    "XML parsing error indicates XXE potential",
                    "External entities may be processed",
                    "DTD processing is enabled"
                ],
                "exploits": [
                    "XXE file disclosure",
                    "XXE SSRF",
                    "XXE OOB data exfiltration",
                    "Billion laughs DoS"
                ],
                "extracted_fields": ["parser_type", "entity_name"]
            },
            "nosql_error": {
                "patterns": [
                    r"MongoError",
                    r"CouchDB",
                    r"\$where",
                    r"BSON",
                    r"Invalid.*?operator"
                ],
                "hints": [
                    "NoSQL database error exposed",
                    "Operator injection may be possible",
                    "MongoDB query structure revealed"
                ],
                "exploits": [
                    "NoSQL operator injection",
                    "Authentication bypass via $ne",
                    "JavaScript injection in $where",
                    "Blind NoSQL injection"
                ],
                "extracted_fields": ["database_type", "operator", "collection"]
            }
        }
    
    def _initialize_technology_vulnerabilities(self) -> Dict[str, List[str]]:
        """Map technologies to common vulnerabilities"""
        return {
            "wordpress": ["sql_injection", "xss", "file_upload_bypass", "authentication_bypass"],
            "drupal": ["sql_injection", "xss", "deserialization", "rce"],
            "joomla": ["sql_injection", "xss", "file_upload_bypass"],
            "php": ["sql_injection", "command_injection", "file_inclusion", "deserialization"],
            "python": ["ssti", "command_injection", "deserialization", "xxe"],
            "java": ["deserialization", "xxe", "expression_injection", "ssrf"],
            "nodejs": ["prototype_pollution", "nosql_injection", "command_injection", "ssrf"],
            "flask": ["ssti", "session_manipulation", "debug_mode"],
            "django": ["ssti", "sql_injection", "mass_assignment"],
            "express": ["prototype_pollution", "nosql_injection", "jwt_manipulation"],
            "spring": ["deserialization", "expression_injection", "xxe"],
            "mongodb": ["nosql_injection", "authentication_bypass"],
            "mysql": ["sql_injection", "authentication_bypass"],
            "postgresql": ["sql_injection", "command_injection"],
            "graphql": ["introspection", "batching_attack", "depth_limit_bypass"],
            "jwt": ["algorithm_confusion", "weak_secret", "none_algorithm"],
            "oauth": ["redirect_uri_bypass", "state_bypass", "token_leakage"],
            "saml": ["xml_signature_wrapping", "assertion_replay"],
            "websocket": ["message_injection", "authentication_bypass", "hijacking"]
        }
    
    def predict_vulnerabilities(self, target_info: TargetInfo) -> List[VulnerabilityPrediction]:
        """
        Predict likely vulnerabilities based on target information.
        
        Requirements: 36.1
        """
        predictions = []
        
        # Combine all technology indicators
        all_tech = (
            target_info.technologies +
            target_info.frameworks +
            [target_info.server_software, target_info.detected_cms, target_info.detected_language]
        )
        all_tech = [t.lower() for t in all_tech if t]
        
        # Check each vulnerability pattern
        for vuln_type, pattern in self.vulnerability_patterns.items():
            confidence = 0.0
            reasoning_parts = []
            
            # Check technology indicators
            for indicator in pattern["indicators"]:
                if any(indicator in tech for tech in all_tech):
                    confidence += pattern["confidence_boost"]
                    reasoning_parts.append(f"Technology '{indicator}' detected")
            
            # Check response patterns in error messages
            for error_msg in target_info.error_messages:
                error_lower = error_msg.lower()
                for resp_pattern in pattern["response_patterns"]:
                    if resp_pattern in error_lower:
                        confidence += 0.15
                        reasoning_parts.append(f"Response pattern '{resp_pattern}' found in errors")
            
            # Check specific technology vulnerabilities
            for tech in all_tech:
                if tech in self.technology_vulnerabilities:
                    if vuln_type in self.technology_vulnerabilities[tech]:
                        confidence += 0.2
                        reasoning_parts.append(f"Known vulnerability for {tech}")
            
            # Boost confidence based on historical success
            if vuln_type in self.success_patterns:
                similar_targets = sum(1 for p in self.success_patterns[vuln_type] 
                                     if any(tech in p for tech in all_tech))
                if similar_targets > 0:
                    confidence += min(0.2, similar_targets * 0.05)
                    reasoning_parts.append(f"Historical success on similar targets")
            
            # Special case boosts
            if vuln_type == "graphql" and target_info.has_api:
                confidence += 0.2
                reasoning_parts.append("API endpoint detected")
            
            if vuln_type == "jwt_manipulation" and any("bearer" in h.lower() for h in target_info.response_headers.values()):
                confidence += 0.25
                reasoning_parts.append("Bearer token authentication detected")
            
            if vuln_type == "xss" and target_info.has_javascript:
                confidence += 0.15
                reasoning_parts.append("JavaScript-heavy application")
            
            # Cap confidence at 1.0
            confidence = min(1.0, confidence)
            
            # Only include predictions with reasonable confidence
            if confidence >= 0.2:
                predictions.append(VulnerabilityPrediction(
                    vulnerability_type=vuln_type,
                    confidence=confidence,
                    reasoning="; ".join(reasoning_parts) if reasoning_parts else "Pattern match",
                    suggested_modules=pattern["modules"],
                    priority=pattern["priority"]
                ))
        
        # Sort by confidence (descending) and priority (ascending)
        predictions.sort(key=lambda p: (-p.confidence, p.priority))
        
        return predictions
    
    def analyze_error_message(self, error: str) -> ErrorAnalysis:
        """
        Analyze error message using NLP-like pattern matching to extract hints.
        
        Requirements: 36.2
        """
        error_lower = error.lower()
        
        # Try to match error patterns in order of specificity
        # More specific patterns should be checked first
        pattern_order = [
            "template_error",  # Check template errors before python errors
            "nosql_error",     # Check NoSQL before generic errors
            "command_error",
            "xml_error",
            "php_error",
            "python_error",
            "java_error",
            "sql_error"
        ]
        
        for error_type in pattern_order:
            if error_type not in self.error_patterns:
                continue
                
            pattern_info = self.error_patterns[error_type]
            for pattern in pattern_info["patterns"]:
                if re.search(pattern, error, re.IGNORECASE):
                    # Extract specific information
                    extracted_info = {}
                    
                    # Extract file paths
                    file_match = re.search(r'["\']?(/[^\s"\']+\.(php|py|java|js))["\']?', error)
                    if file_match:
                        extracted_info["file_path"] = file_match.group(1)
                    
                    # Extract line numbers
                    line_match = re.search(r'line (\d+)', error, re.IGNORECASE)
                    if line_match:
                        extracted_info["line_number"] = line_match.group(1)
                    
                    # Extract database/table names
                    table_match = re.search(r'table ["\']?([a-z_]+)["\']?', error, re.IGNORECASE)
                    if table_match:
                        extracted_info["table_name"] = table_match.group(1)
                    
                    # Extract function/class names
                    func_match = re.search(r'function ["\']?([a-zA-Z_][a-zA-Z0-9_]*)["\']?', error, re.IGNORECASE)
                    if func_match:
                        extracted_info["function_name"] = func_match.group(1)
                    
                    # Calculate confidence based on pattern specificity
                    confidence = 0.7 + (len(extracted_info) * 0.1)
                    confidence = min(1.0, confidence)
                    
                    return ErrorAnalysis(
                        error_type=error_type,
                        hints=pattern_info["hints"],
                        suggested_exploits=pattern_info["exploits"],
                        confidence=confidence,
                        extracted_info=extracted_info
                    )
        
        # Generic analysis if no specific pattern matched
        generic_hints = []
        generic_exploits = []
        
        # Check for common keywords
        if "sql" in error_lower or "database" in error_lower:
            generic_hints.append("Database-related error detected")
            generic_exploits.append("SQL injection")
        
        if "file" in error_lower or "path" in error_lower:
            generic_hints.append("File system error detected")
            generic_exploits.append("Directory traversal")
        
        if "permission" in error_lower or "denied" in error_lower:
            generic_hints.append("Permission error may indicate successful injection")
            generic_exploits.append("Privilege escalation")
        
        if "timeout" in error_lower or "connection" in error_lower:
            generic_hints.append("Network error may indicate SSRF or blind injection")
            generic_exploits.append("SSRF", "Time-based blind injection")
        
        return ErrorAnalysis(
            error_type="generic",
            hints=generic_hints if generic_hints else ["Error message analysis inconclusive"],
            suggested_exploits=generic_exploits if generic_exploits else ["Manual analysis recommended"],
            confidence=0.3 if generic_hints else 0.1,
            extracted_info={}
        )
    
    def rank_attack_vectors(
        self,
        vectors: List[AttackVector],
        context: dict
    ) -> List[RankedVector]:
        """
        Rank attack vectors by exploitation probability and time-to-flag.
        
        Requirements: 36.3
        """
        ranked = []
        
        for vector in vectors:
            # Base exploitation probability
            exploitation_prob = 0.5
            
            # Adjust based on historical success
            if vector.vulnerability_type in self.success_patterns:
                success_count = len(self.success_patterns[vector.vulnerability_type])
                failure_count = len(self.failure_patterns.get(vector.vulnerability_type, []))
                total = success_count + failure_count
                if total > 0:
                    exploitation_prob = success_count / total
            
            # Adjust based on complexity
            complexity_multipliers = {
                "low": 1.2,
                "medium": 1.0,
                "high": 0.7
            }
            exploitation_prob *= complexity_multipliers.get(vector.complexity, 1.0)
            
            # Adjust based on context (detected technologies)
            if "technologies" in context:
                tech_list = [t.lower() for t in context["technologies"]]
                if vector.vulnerability_type in self.technology_vulnerabilities:
                    for tech in tech_list:
                        if tech in self.technology_vulnerabilities:
                            if vector.vulnerability_type in self.technology_vulnerabilities[tech]:
                                exploitation_prob *= 1.3
                                break
            
            # Estimate time to flag
            base_time = vector.estimated_time if vector.estimated_time > 0 else 60.0
            
            # Adjust time based on complexity
            complexity_time_multipliers = {
                "low": 0.5,
                "medium": 1.0,
                "high": 2.0
            }
            time_to_flag = base_time * complexity_time_multipliers.get(vector.complexity, 1.0)
            
            # Adjust time based on historical data
            if vector.vulnerability_type in self.success_patterns:
                # Faster if we've succeeded before
                time_to_flag *= 0.8
            
            # Calculate combined score (higher is better)
            # Score = exploitation_prob / (time_to_flag / 60)
            # This favors high probability and low time
            score = exploitation_prob / (time_to_flag / 60.0)
            
            # Cap probability at 1.0
            exploitation_prob = min(1.0, exploitation_prob)
            
            ranked.append(RankedVector(
                vector=vector,
                score=score,
                exploitation_probability=exploitation_prob,
                time_to_flag=time_to_flag,
                rank=0  # Will be set after sorting
            ))
        
        # Sort by score (descending)
        ranked.sort(key=lambda r: r.score, reverse=True)
        
        # Assign ranks
        for i, r in enumerate(ranked, 1):
            r.rank = i
        
        return ranked
    
    def learn_from_attempt(
        self,
        attempt: AttackAttempt,
        result: AttackResult
    ):
        """
        Learn from attack attempts to improve future predictions.
        
        Requirements: 36.4, 36.5
        """
        # Store the attempt and result
        self.attack_history.append((attempt, result))
        
        # Update success/failure patterns
        pattern_key = f"{attempt.target_url}:{attempt.vulnerability_type}"
        
        if result.success and result.vulnerability_found:
            self.success_patterns[attempt.vulnerability_type].append(pattern_key)
            logger.info(f"Learned successful pattern for {attempt.vulnerability_type}")
        else:
            self.failure_patterns[attempt.vulnerability_type].append(pattern_key)
            logger.debug(f"Recorded failure for {attempt.vulnerability_type}")
        
        # Limit history size to prevent memory issues
        max_history = 1000
        if len(self.attack_history) > max_history:
            self.attack_history = self.attack_history[-max_history:]
        
        # Limit pattern storage
        max_patterns = 500
        for vuln_type in list(self.success_patterns.keys()):
            if len(self.success_patterns[vuln_type]) > max_patterns:
                self.success_patterns[vuln_type] = self.success_patterns[vuln_type][-max_patterns:]
        
        for vuln_type in list(self.failure_patterns.keys()):
            if len(self.failure_patterns[vuln_type]) > max_patterns:
                self.failure_patterns[vuln_type] = self.failure_patterns[vuln_type][-max_patterns:]
    
    def get_adaptive_strategy(self, target_url: str, vulnerability_type: str) -> Dict[str, Any]:
        """
        Get adaptive strategy based on learning from previous attempts.
        
        Requirements: 36.4, 36.5
        """
        # Analyze historical attempts for this target and vulnerability type
        relevant_attempts = [
            (attempt, result) for attempt, result in self.attack_history
            if attempt.target_url == target_url and attempt.vulnerability_type == vulnerability_type
        ]
        
        if not relevant_attempts:
            return {
                "strategy": "default",
                "recommendations": ["No historical data available, using default strategy"],
                "adjustments": {}
            }
        
        # Analyze what worked and what didn't
        successful_attempts = [a for a, r in relevant_attempts if r.success]
        failed_attempts = [a for a, r in relevant_attempts if not r.success]
        
        recommendations = []
        adjustments = {}
        
        # Analyze successful payloads
        if successful_attempts:
            successful_payloads = [a.payload for a in successful_attempts]
            recommendations.append(f"Previous successful payloads: {len(successful_payloads)}")
            adjustments["use_similar_payloads"] = successful_payloads[:5]  # Top 5
        
        # Analyze failure patterns
        if failed_attempts:
            # Check if errors indicate WAF
            waf_indicators = sum(1 for a, r in relevant_attempts 
                               if r.error_message and any(w in r.error_message.lower() 
                                                         for w in ["blocked", "forbidden", "waf", "firewall"]))
            if waf_indicators > len(failed_attempts) * 0.3:
                recommendations.append("WAF detected, recommend bypass techniques")
                adjustments["enable_waf_bypass"] = True
            
            # Check if timeouts indicate rate limiting
            timeout_count = sum(1 for a, r in relevant_attempts 
                              if r.error_message and "timeout" in r.error_message.lower())
            if timeout_count > len(failed_attempts) * 0.3:
                recommendations.append("Rate limiting detected, reduce request rate")
                adjustments["reduce_rate"] = True
                adjustments["delay_between_requests"] = 2.0
        
        # Determine strategy
        success_rate = len(successful_attempts) / len(relevant_attempts) if relevant_attempts else 0
        
        if success_rate > 0.5:
            strategy = "aggressive"
            recommendations.append("High success rate, continue with aggressive testing")
        elif success_rate > 0.2:
            strategy = "moderate"
            recommendations.append("Moderate success rate, continue with current approach")
        else:
            strategy = "adaptive"
            recommendations.append("Low success rate, trying alternative techniques")
            adjustments["try_alternative_payloads"] = True
        
        return {
            "strategy": strategy,
            "recommendations": recommendations,
            "adjustments": adjustments,
            "success_rate": success_rate,
            "total_attempts": len(relevant_attempts)
        }
    
    def export_learning_data(self) -> Dict[str, Any]:
        """Export learning data for persistence"""
        return {
            "success_patterns": dict(self.success_patterns),
            "failure_patterns": dict(self.failure_patterns),
            "attack_history_count": len(self.attack_history)
        }
    
    def import_learning_data(self, data: Dict[str, Any]):
        """Import learning data from persistence"""
        if "success_patterns" in data:
            self.success_patterns = defaultdict(list, data["success_patterns"])
        if "failure_patterns" in data:
            self.failure_patterns = defaultdict(list, data["failure_patterns"])
        logger.info("Imported learning data successfully")
