"""Traffic Analysis Module

This module provides behavioral modeling, anomaly detection, and attack optimization
through traffic pattern analysis and recognition.

Validates Requirements: 49.1, 49.2, 49.3, 49.4, 49.5
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from enum import Enum
import statistics
import re
from urllib.parse import urlparse, parse_qs

from src.vulnchain.core.http_models import Request, Response


class EndpointType(Enum):
    """Types of discovered endpoints"""
    STATIC = "static"
    DYNAMIC = "dynamic"
    API = "api"
    AUTHENTICATION = "authentication"
    HIDDEN = "hidden"


@dataclass
class TrafficPattern:
    """Represents a pattern observed in application traffic"""
    
    pattern_id: str
    pattern_type: str  # "request_sequence", "timing", "parameter", "header"
    description: str
    frequency: int
    confidence: float  # 0.0 to 1.0
    examples: List[Tuple[Request, Response]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralModel:
    """Model of normal application behavior"""
    
    model_id: str
    created_at: datetime
    updated_at: datetime
    
    # Endpoint patterns
    known_endpoints: Set[str] = field(default_factory=set)
    endpoint_types: Dict[str, EndpointType] = field(default_factory=dict)
    
    # Request patterns
    common_sequences: List[List[str]] = field(default_factory=list)
    parameter_patterns: Dict[str, Set[str]] = field(default_factory=dict)
    
    # Timing patterns
    typical_response_times: Dict[str, Tuple[float, float]] = field(default_factory=dict)  # endpoint -> (mean, stddev)
    
    # Rate limiting
    rate_limits: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Anti-automation measures
    anti_automation_indicators: List[str] = field(default_factory=list)
    
    # State transitions
    state_machine: Dict[str, Set[str]] = field(default_factory=dict)  # current_state -> possible_next_states
    
    # Authentication flows
    auth_flows: List[List[str]] = field(default_factory=list)
    
    # Statistics
    total_requests: int = 0
    observation_period: timedelta = field(default_factory=lambda: timedelta(0))


@dataclass
class TrafficAnomaly:
    """Represents an anomalous traffic pattern"""
    
    anomaly_id: str
    anomaly_type: str
    severity: str  # "low", "medium", "high", "critical"
    description: str
    detected_at: datetime
    request: Optional[Request] = None
    response: Optional[Response] = None
    deviation_score: float = 0.0
    suggested_action: Optional[str] = None


@dataclass
class AttackOptimization:
    """Optimization recommendations for attack execution"""
    
    optimal_timing: Dict[str, Any]
    request_ordering: List[str]
    bypass_opportunities: List[Dict[str, Any]]
    multi_step_flows: List[List[str]]
    rate_limit_info: Dict[str, Any]
    confidence: float


class TrafficAnalyzer:
    """
    Analyzes HTTP traffic patterns to build behavioral models, detect anomalies,
    and optimize attack strategies.
    
    This class provides functionality to:
    - Build behavioral models of normal application flow
    - Identify hidden endpoints and rate limiting patterns
    - Detect anomalies in responses and timing
    - Optimize attack timing and request ordering
    - Map multi-step authentication flows
    """
    
    def __init__(self, learning_window: int = 100):
        """
        Initialize the TrafficAnalyzer.
        
        Args:
            learning_window: Number of requests to use for building behavioral model
        """
        self.learning_window = learning_window
        self.traffic_history: List[Tuple[Request, Response]] = []
        self.behavioral_model: Optional[BehavioralModel] = None
        self.anomalies: List[TrafficAnomaly] = []
        self.endpoint_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "count": 0,
            "timings": [],
            "status_codes": Counter(),
            "parameters": set(),
            "methods": set()
        })
        
    def observe_traffic(self, request: Request, response: Response):
        """
        Observe and record a request-response pair for analysis.
        
        Args:
            request: The HTTP request
            response: The HTTP response
        """
        self.traffic_history.append((request, response))
        
        # Update endpoint statistics
        endpoint = self._normalize_endpoint(request.url)
        stats = self.endpoint_stats[endpoint]
        stats["count"] += 1
        stats["timings"].append(response.elapsed_time)
        stats["status_codes"][response.status_code] += 1
        stats["methods"].add(request.method)
        
        # Extract parameters
        parsed = urlparse(request.url)
        if parsed.query:
            params = parse_qs(parsed.query)
            stats["parameters"].update(params.keys())
        
        # Keep history within window
        if len(self.traffic_history) > self.learning_window * 2:
            self.traffic_history = self.traffic_history[-self.learning_window:]
    
    def build_behavioral_model(self) -> BehavioralModel:
        """
        Build a behavioral model of normal application flow from observed traffic.
        
        Validates: Requirements 49.1
        
        Returns:
            BehavioralModel representing normal application behavior
        """
        if not self.traffic_history:
            raise ValueError("No traffic history available for modeling")
        
        model = BehavioralModel(
            model_id=f"model_{datetime.now().timestamp()}",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        # Identify known endpoints
        for req, resp in self.traffic_history:
            endpoint = self._normalize_endpoint(req.url)
            model.known_endpoints.add(endpoint)
            
            # Classify endpoint type
            if endpoint not in model.endpoint_types:
                model.endpoint_types[endpoint] = self._classify_endpoint(req, resp)
        
        # Identify common request sequences
        model.common_sequences = self._identify_request_sequences()
        
        # Build parameter patterns
        model.parameter_patterns = self._build_parameter_patterns()
        
        # Calculate typical response times
        model.typical_response_times = self._calculate_typical_timings()
        
        # Detect rate limiting
        model.rate_limits = self._detect_rate_limiting()
        
        # Identify anti-automation measures
        model.anti_automation_indicators = self._identify_anti_automation()
        
        # Build state machine
        model.state_machine = self._build_state_machine()
        
        # Identify authentication flows
        model.auth_flows = self._identify_auth_flows()
        
        # Update statistics
        model.total_requests = len(self.traffic_history)
        if self.traffic_history:
            first_time = self.traffic_history[0][1].request.timestamp if hasattr(self.traffic_history[0][1].request, 'timestamp') else datetime.now()
            last_time = self.traffic_history[-1][1].request.timestamp if hasattr(self.traffic_history[-1][1].request, 'timestamp') else datetime.now()
            model.observation_period = last_time - first_time
        
        self.behavioral_model = model
        return model
    
    def identify_hidden_endpoints(self) -> List[str]:
        """
        Identify hidden endpoints from traffic patterns.
        
        Validates: Requirements 49.2
        
        Returns:
            List of potentially hidden endpoint paths
        """
        hidden_endpoints = []
        
        # Look for endpoints accessed infrequently
        for endpoint, stats in self.endpoint_stats.items():
            if stats["count"] < 3:  # Accessed less than 3 times
                hidden_endpoints.append(endpoint)
        
        # Look for endpoints with unusual patterns
        for req, resp in self.traffic_history:
            endpoint = self._normalize_endpoint(req.url)
            
            # Check for debug/admin patterns
            if any(pattern in endpoint.lower() for pattern in [
                'debug', 'admin', 'test', 'dev', 'internal', 'api/v', 'hidden'
            ]):
                if endpoint not in hidden_endpoints:
                    hidden_endpoints.append(endpoint)
        
        return hidden_endpoints
    
    def detect_rate_limiting(self) -> Dict[str, Dict[str, Any]]:
        """
        Detect rate limiting patterns from traffic analysis.
        
        Validates: Requirements 49.2
        
        Returns:
            Dictionary mapping endpoints to rate limit information
        """
        return self._detect_rate_limiting()
    
    def _detect_rate_limiting(self) -> Dict[str, Dict[str, Any]]:
        """Internal method to detect rate limiting patterns"""
        rate_limits = {}
        
        # Group requests by endpoint and time window
        endpoint_requests = defaultdict(list)
        for req, resp in self.traffic_history:
            endpoint = self._normalize_endpoint(req.url)
            endpoint_requests[endpoint].append((req, resp))
        
        # Analyze each endpoint for rate limiting
        for endpoint, requests in endpoint_requests.items():
            # Look for 429 status codes
            rate_limit_responses = [
                resp for req, resp in requests
                if resp.status_code == 429
            ]
            
            if rate_limit_responses:
                # Extract rate limit headers
                retry_after = None
                limit_info = {}
                
                for resp in rate_limit_responses:
                    if 'Retry-After' in resp.headers:
                        retry_after = resp.headers['Retry-After']
                    if 'X-RateLimit-Limit' in resp.headers:
                        limit_info['limit'] = resp.headers['X-RateLimit-Limit']
                    if 'X-RateLimit-Remaining' in resp.headers:
                        limit_info['remaining'] = resp.headers['X-RateLimit-Remaining']
                    if 'X-RateLimit-Reset' in resp.headers:
                        limit_info['reset'] = resp.headers['X-RateLimit-Reset']
                
                rate_limits[endpoint] = {
                    'detected': True,
                    'retry_after': retry_after,
                    'limit_info': limit_info,
                    'occurrences': len(rate_limit_responses)
                }
        
        return rate_limits
    
    def identify_anti_automation(self) -> List[str]:
        """
        Identify anti-automation measures from traffic patterns.
        
        Validates: Requirements 49.2
        
        Returns:
            List of detected anti-automation indicators
        """
        return self._identify_anti_automation()
    
    def _identify_anti_automation(self) -> List[str]:
        """Internal method to identify anti-automation measures"""
        indicators = []
        
        for req, resp in self.traffic_history:
            # Check for CAPTCHA indicators
            if any(pattern in resp.text.lower() for pattern in [
                'captcha', 'recaptcha', 'hcaptcha', 'challenge'
            ]):
                if 'CAPTCHA detected' not in indicators:
                    indicators.append('CAPTCHA detected')
            
            # Check for rate limiting
            if resp.status_code == 429:
                if 'Rate limiting active' not in indicators:
                    indicators.append('Rate limiting active')
            
            # Check for bot detection headers
            bot_headers = ['cf-ray', 'x-amzn-waf-action', 'x-sucuri-id']
            if any(h in resp.headers for h in bot_headers):
                if 'WAF/Bot detection active' not in indicators:
                    indicators.append('WAF/Bot detection active')
            
            # Check for JavaScript challenges
            if 'challenge-platform' in resp.text.lower() or 'jschl' in resp.text.lower():
                if 'JavaScript challenge detected' not in indicators:
                    indicators.append('JavaScript challenge detected')
        
        return indicators

    
    def detect_anomalies(
        self,
        recent_window: int = 20
    ) -> List[TrafficAnomaly]:
        """
        Detect anomalies in recent traffic based on the behavioral model.
        
        Validates: Requirements 49.3
        
        Args:
            recent_window: Number of recent requests to analyze
            
        Returns:
            List of detected anomalies
        """
        if self.behavioral_model is None:
            raise ValueError("Behavioral model must be built before detecting anomalies")
        
        anomalies = []
        recent_traffic = self.traffic_history[-recent_window:]
        
        for req, resp in recent_traffic:
            endpoint = self._normalize_endpoint(req.url)
            
            # Check for unknown endpoints
            if endpoint not in self.behavioral_model.known_endpoints:
                anomaly = TrafficAnomaly(
                    anomaly_id=f"anomaly_{datetime.now().timestamp()}",
                    anomaly_type="unknown_endpoint",
                    severity="medium",
                    description=f"Request to unknown endpoint: {endpoint}",
                    detected_at=datetime.now(),
                    request=req,
                    response=resp,
                    deviation_score=1.0,
                    suggested_action="Investigate endpoint for hidden functionality"
                )
                anomalies.append(anomaly)
            
            # Check for unusual response times
            if endpoint in self.behavioral_model.typical_response_times:
                mean, stddev = self.behavioral_model.typical_response_times[endpoint]
                if stddev > 0:
                    z_score = abs((resp.elapsed_time - mean) / stddev)
                    if z_score > 3.0:  # More than 3 standard deviations
                        anomaly = TrafficAnomaly(
                            anomaly_id=f"anomaly_{datetime.now().timestamp()}",
                            anomaly_type="timing_anomaly",
                            severity="high" if z_score > 5.0 else "medium",
                            description=f"Unusual response time: {resp.elapsed_time:.3f}s (expected {mean:.3f}±{stddev:.3f}s)",
                            detected_at=datetime.now(),
                            request=req,
                            response=resp,
                            deviation_score=z_score / 10.0,
                            suggested_action="May indicate successful time-based exploitation"
                        )
                        anomalies.append(anomaly)
            
            # Check for unusual status codes
            # Use historical data from before this request was observed
            # Count status codes from traffic history excluding the current request
            historical_status_codes = set()
            for hist_req, hist_resp in self.traffic_history[:-recent_window]:
                hist_endpoint = self._normalize_endpoint(hist_req.url)
                if hist_endpoint == endpoint:
                    historical_status_codes.add(hist_resp.status_code)
            
            if historical_status_codes and resp.status_code not in historical_status_codes:
                anomaly = TrafficAnomaly(
                    anomaly_id=f"anomaly_{datetime.now().timestamp()}",
                    anomaly_type="status_code_anomaly",
                    severity="medium",
                    description=f"Unusual status code {resp.status_code} for endpoint {endpoint}",
                    detected_at=datetime.now(),
                    request=req,
                    response=resp,
                    deviation_score=0.8,
                    suggested_action="Investigate response for exploitation indicators"
                )
                anomalies.append(anomaly)
            
            # Check for state transition violations
            if self.behavioral_model.state_machine:
                current_state = self._get_current_state(req)
                if current_state in self.behavioral_model.state_machine:
                    expected_states = self.behavioral_model.state_machine[current_state]
                    next_state = self._get_next_state(resp)
                    if next_state and next_state not in expected_states:
                        anomaly = TrafficAnomaly(
                            anomaly_id=f"anomaly_{datetime.now().timestamp()}",
                            anomaly_type="state_transition_violation",
                            severity="high",
                            description=f"Unexpected state transition: {current_state} -> {next_state}",
                            detected_at=datetime.now(),
                            request=req,
                            response=resp,
                            deviation_score=0.9,
                            suggested_action="May indicate authentication bypass or privilege escalation"
                        )
                        anomalies.append(anomaly)
        
        self.anomalies.extend(anomalies)
        return anomalies
    
    def optimize_attack_strategy(self) -> AttackOptimization:
        """
        Analyze traffic patterns to optimize attack timing and request ordering.
        
        Validates: Requirements 49.4, 49.5
        
        Returns:
            AttackOptimization with recommendations for attack execution
        """
        if self.behavioral_model is None:
            raise ValueError("Behavioral model must be built before optimizing attacks")
        
        # Determine optimal timing
        optimal_timing = self._calculate_optimal_timing()
        
        # Determine optimal request ordering
        request_ordering = self._determine_request_ordering()
        
        # Identify bypass opportunities
        bypass_opportunities = self._identify_bypass_opportunities()
        
        # Extract multi-step flows
        multi_step_flows = self.behavioral_model.auth_flows + self.behavioral_model.common_sequences
        
        # Compile rate limit information
        rate_limit_info = self.behavioral_model.rate_limits
        
        # Calculate confidence based on data quality
        confidence = min(1.0, len(self.traffic_history) / self.learning_window)
        
        return AttackOptimization(
            optimal_timing=optimal_timing,
            request_ordering=request_ordering,
            bypass_opportunities=bypass_opportunities,
            multi_step_flows=multi_step_flows,
            rate_limit_info=rate_limit_info,
            confidence=confidence
        )
    
    def _calculate_optimal_timing(self) -> Dict[str, Any]:
        """
        Calculate optimal timing for attack requests.
        
        Validates: Requirements 49.4
        
        Returns:
            Dictionary with timing recommendations
        """
        timing_info = {
            "recommended_delay": 0.0,
            "burst_size": 1,
            "endpoint_specific": {}
        }
        
        # Check for rate limiting
        if self.behavioral_model.rate_limits:
            # If rate limiting detected, recommend slower timing
            timing_info["recommended_delay"] = 1.0
            timing_info["burst_size"] = 5
        else:
            # No rate limiting, can be more aggressive
            timing_info["recommended_delay"] = 0.1
            timing_info["burst_size"] = 20
        
        # Calculate endpoint-specific timing
        for endpoint, stats in self.endpoint_stats.items():
            if stats["timings"]:
                avg_time = statistics.mean(stats["timings"])
                timing_info["endpoint_specific"][endpoint] = {
                    "avg_response_time": avg_time,
                    "recommended_timeout": avg_time * 3
                }
        
        return timing_info
    
    def _determine_request_ordering(self) -> List[str]:
        """
        Determine optimal request ordering based on observed sequences.
        
        Validates: Requirements 49.4
        
        Returns:
            List of endpoints in recommended order
        """
        if not self.behavioral_model.common_sequences:
            # No sequences observed, return endpoints by frequency
            sorted_endpoints = sorted(
                self.endpoint_stats.items(),
                key=lambda x: x[1]["count"],
                reverse=True
            )
            return [endpoint for endpoint, _ in sorted_endpoints]
        
        # Use most common sequence
        most_common = max(
            self.behavioral_model.common_sequences,
            key=len,
            default=[]
        )
        return most_common
    
    def _identify_bypass_opportunities(self) -> List[Dict[str, Any]]:
        """
        Identify opportunities to bypass authentication or authorization.
        
        Validates: Requirements 49.5
        
        Returns:
            List of bypass opportunity descriptions
        """
        opportunities = []
        
        # Check for authentication flows
        if self.behavioral_model.auth_flows:
            for flow in self.behavioral_model.auth_flows:
                if len(flow) > 1:
                    opportunities.append({
                        "type": "multi_step_auth",
                        "description": f"Multi-step authentication flow detected: {' -> '.join(flow)}",
                        "bypass_strategy": "Try accessing later steps directly without completing earlier steps",
                        "endpoints": flow
                    })
        
        # Check for state machine vulnerabilities
        if self.behavioral_model.state_machine:
            for state, next_states in self.behavioral_model.state_machine.items():
                if len(next_states) > 1:
                    opportunities.append({
                        "type": "state_confusion",
                        "description": f"Multiple possible transitions from state: {state}",
                        "bypass_strategy": "Try unexpected state transitions to bypass checks",
                        "current_state": state,
                        "possible_states": list(next_states)
                    })
        
        # Check for endpoints with inconsistent authentication
        auth_endpoints = [
            ep for ep, etype in self.behavioral_model.endpoint_types.items()
            if etype == EndpointType.AUTHENTICATION
        ]
        
        if auth_endpoints:
            opportunities.append({
                "type": "auth_inconsistency",
                "description": "Authentication endpoints detected",
                "bypass_strategy": "Test for authentication bypass via parameter manipulation",
                "endpoints": auth_endpoints
            })
        
        return opportunities
    
    def map_authentication_flows(self) -> List[List[str]]:
        """
        Map multi-step authentication flows from traffic patterns.
        
        Validates: Requirements 49.5
        
        Returns:
            List of authentication flow sequences
        """
        if self.behavioral_model is None:
            self.build_behavioral_model()
        
        return self.behavioral_model.auth_flows
    
    def _identify_auth_flows(self) -> List[List[str]]:
        """Internal method to identify authentication flows"""
        auth_flows = []
        
        # Look for sequences involving authentication endpoints
        auth_keywords = ['login', 'auth', 'signin', 'authenticate', 'token', 'session']
        
        # Build sequences of requests
        sequences = []
        current_sequence = []
        
        for req, resp in self.traffic_history:
            endpoint = self._normalize_endpoint(req.url)
            
            # Check if this is an auth-related endpoint
            is_auth = any(keyword in endpoint.lower() for keyword in auth_keywords)
            
            if is_auth:
                current_sequence.append(endpoint)
            elif current_sequence:
                # End of auth sequence
                if len(current_sequence) > 0:
                    sequences.append(current_sequence.copy())
                current_sequence = []
        
        # Add final sequence if exists
        if current_sequence:
            sequences.append(current_sequence)
        
        # Deduplicate and return
        unique_flows = []
        for seq in sequences:
            if seq not in unique_flows:
                unique_flows.append(seq)
        
        return unique_flows
    
    def _normalize_endpoint(self, url: str) -> str:
        """Normalize URL to endpoint path"""
        parsed = urlparse(url)
        path = parsed.path
        
        # Remove trailing slashes
        path = path.rstrip('/')
        
        # Normalize UUIDs first (before numeric IDs to avoid partial matches)
        path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}', path, flags=re.IGNORECASE)
        
        # Normalize IDs and numbers in path
        path = re.sub(r'/\d+', '/{id}', path)
        
        return path or '/'
    
    def _classify_endpoint(self, request: Request, response: Response) -> EndpointType:
        """Classify endpoint type based on request/response characteristics"""
        endpoint = self._normalize_endpoint(request.url)
        
        # Check for authentication endpoints
        auth_keywords = ['login', 'auth', 'signin', 'authenticate', 'token', 'session']
        if any(keyword in endpoint.lower() for keyword in auth_keywords):
            return EndpointType.AUTHENTICATION
        
        # Check for API endpoints
        if '/api/' in endpoint or endpoint.startswith('/api'):
            return EndpointType.API
        
        # Check for static resources
        static_extensions = ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff']
        if any(endpoint.endswith(ext) for ext in static_extensions):
            return EndpointType.STATIC
        
        # Check for hidden/debug endpoints
        hidden_keywords = ['debug', 'admin', 'test', 'dev', 'internal']
        if any(keyword in endpoint.lower() for keyword in hidden_keywords):
            return EndpointType.HIDDEN
        
        # Default to dynamic
        return EndpointType.DYNAMIC
    
    def _identify_request_sequences(self) -> List[List[str]]:
        """Identify common sequences of requests"""
        sequences = []
        window_size = 5
        
        # Extract endpoint sequences
        endpoint_sequence = [
            self._normalize_endpoint(req.url)
            for req, resp in self.traffic_history
        ]
        
        # Find common subsequences
        sequence_counts = Counter()
        for i in range(len(endpoint_sequence) - window_size + 1):
            subseq = tuple(endpoint_sequence[i:i+window_size])
            sequence_counts[subseq] += 1
        
        # Return sequences that appear more than once
        for seq, count in sequence_counts.most_common(10):
            if count > 1:
                sequences.append(list(seq))
        
        return sequences
    
    def _build_parameter_patterns(self) -> Dict[str, Set[str]]:
        """Build patterns of parameters used with each endpoint"""
        patterns = defaultdict(set)
        
        for req, resp in self.traffic_history:
            endpoint = self._normalize_endpoint(req.url)
            parsed = urlparse(req.url)
            
            if parsed.query:
                params = parse_qs(parsed.query)
                patterns[endpoint].update(params.keys())
        
        return dict(patterns)
    
    def _calculate_typical_timings(self) -> Dict[str, Tuple[float, float]]:
        """Calculate typical response times for each endpoint"""
        timings = {}
        
        for endpoint, stats in self.endpoint_stats.items():
            if stats["timings"] and len(stats["timings"]) > 1:
                mean = statistics.mean(stats["timings"])
                stddev = statistics.stdev(stats["timings"])
                timings[endpoint] = (mean, stddev)
        
        return timings
    
    def _build_state_machine(self) -> Dict[str, Set[str]]:
        """Build state machine from observed transitions"""
        state_machine = defaultdict(set)
        
        # Use endpoint sequences to build state transitions
        for i in range(len(self.traffic_history) - 1):
            current_req, current_resp = self.traffic_history[i]
            next_req, next_resp = self.traffic_history[i + 1]
            
            current_state = self._normalize_endpoint(current_req.url)
            next_state = self._normalize_endpoint(next_req.url)
            
            state_machine[current_state].add(next_state)
        
        return dict(state_machine)
    
    def _get_current_state(self, request: Request) -> str:
        """Get current state from request"""
        return self._normalize_endpoint(request.url)
    
    def _get_next_state(self, response: Response) -> Optional[str]:
        """Get next state from response (e.g., from redirect)"""
        if 'Location' in response.headers:
            return self._normalize_endpoint(response.headers['Location'])
        return None
    
    def get_traffic_summary(self) -> Dict[str, Any]:
        """
        Get a summary of observed traffic patterns.
        
        Returns:
            Dictionary with traffic statistics and patterns
        """
        return {
            "total_requests": len(self.traffic_history),
            "unique_endpoints": len(self.endpoint_stats),
            "anomalies_detected": len(self.anomalies),
            "model_built": self.behavioral_model is not None,
            "endpoint_stats": {
                endpoint: {
                    "count": stats["count"],
                    "avg_time": statistics.mean(stats["timings"]) if stats["timings"] else 0,
                    "status_codes": dict(stats["status_codes"]),
                    "methods": list(stats["methods"])
                }
                for endpoint, stats in self.endpoint_stats.items()
            }
        }
    
    def clear_history(self):
        """Clear traffic history and reset analyzer"""
        self.traffic_history.clear()
        self.behavioral_model = None
        self.anomalies.clear()
        self.endpoint_stats.clear()
