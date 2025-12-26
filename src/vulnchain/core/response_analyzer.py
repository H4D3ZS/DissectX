"""Response Analysis Module

This module provides response comparison, diff analysis, and statistical timing analysis
for identifying subtle differences in responses that indicate successful exploitation.

Validates Requirements: 28.1, 28.2, 28.3, 28.4, 28.5
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
import difflib
import statistics
from collections import defaultdict

from src.vulnchain.core.http_models import Response


@dataclass
class ResponseComparison:
    """Result of comparing two responses"""
    
    similarity_score: float  # 0.0 to 1.0
    length_difference: int
    status_code_match: bool
    header_differences: Dict[str, Tuple[Optional[str], Optional[str]]]
    body_diff: List[str]  # Unified diff lines
    is_anomaly: bool
    
    
@dataclass
class BaselineResponse:
    """Baseline response for comparison"""
    
    response: Response
    captured_at: datetime
    label: str = "baseline"


@dataclass
class TimingStatistics:
    """Statistical analysis of response timings"""
    
    mean: float
    median: float
    std_dev: float
    min_time: float
    max_time: float
    outliers: List[Tuple[float, Response]]  # (timing, response) pairs
    threshold: float
    

class ResponseAnalyzer:
    """
    Analyzes HTTP responses for comparison, diff analysis, and timing anomalies.
    
    This class provides functionality to:
    - Capture and store baseline responses
    - Compare responses and compute similarity scores
    - Generate visual diffs highlighting differences
    - Perform statistical timing analysis
    - Detect anomalies based on configurable thresholds
    """
    
    def __init__(self, anomaly_threshold: float = 0.15, timing_threshold_sigma: float = 2.0):
        """
        Initialize the ResponseAnalyzer.
        
        Args:
            anomaly_threshold: Threshold for flagging responses as anomalous (0.0-1.0)
                             Lower similarity scores indicate more difference
            timing_threshold_sigma: Number of standard deviations for timing anomaly detection
        """
        self.baselines: Dict[str, BaselineResponse] = {}
        self.response_history: List[Response] = []
        self.anomaly_threshold = anomaly_threshold
        self.timing_threshold_sigma = timing_threshold_sigma
        
    def capture_baseline(self, response: Response, label: str = "baseline") -> BaselineResponse:
        """
        Capture a baseline response for future comparisons.
        
        Validates: Requirements 28.1
        
        Args:
            response: The response to use as baseline
            label: Label to identify this baseline
            
        Returns:
            BaselineResponse object
        """
        baseline = BaselineResponse(
            response=response,
            captured_at=datetime.now(),
            label=label
        )
        self.baselines[label] = baseline
        return baseline
    
    def get_baseline(self, label: str = "baseline") -> Optional[BaselineResponse]:
        """
        Retrieve a stored baseline response.
        
        Args:
            label: Label of the baseline to retrieve
            
        Returns:
            BaselineResponse if found, None otherwise
        """
        return self.baselines.get(label)
    
    def compute_similarity_score(
        self,
        response1: Response,
        response2: Response
    ) -> float:
        """
        Compute similarity score between two responses based on content length,
        headers, and body content.
        
        Validates: Requirements 28.2
        
        Args:
            response1: First response
            response2: Second response
            
        Returns:
            Similarity score from 0.0 (completely different) to 1.0 (identical)
        """
        scores = []
        
        # Status code similarity (binary: match or not)
        status_score = 1.0 if response1.status_code == response2.status_code else 0.0
        scores.append(status_score)
        
        # Content length similarity
        len1 = len(response1.body)
        len2 = len(response2.body)
        if len1 == 0 and len2 == 0:
            length_score = 1.0
        elif len1 == 0 or len2 == 0:
            length_score = 0.0
        else:
            length_score = 1.0 - abs(len1 - len2) / max(len1, len2)
        scores.append(length_score)
        
        # Header similarity (Jaccard similarity of header keys)
        headers1 = set(response1.headers.keys())
        headers2 = set(response2.headers.keys())
        if headers1 or headers2:
            header_score = len(headers1 & headers2) / len(headers1 | headers2)
        else:
            header_score = 1.0
        scores.append(header_score)
        
        # Body content similarity using SequenceMatcher
        text1 = response1.text
        text2 = response2.text
        if text1 or text2:
            matcher = difflib.SequenceMatcher(None, text1, text2)
            body_score = matcher.ratio()
        else:
            body_score = 1.0
        scores.append(body_score)
        
        # Weighted average (body content is most important)
        weights = [0.1, 0.2, 0.1, 0.6]  # status, length, headers, body
        similarity = sum(s * w for s, w in zip(scores, weights))
        
        return similarity
    
    def compare_responses(
        self,
        response1: Response,
        response2: Response,
        threshold: Optional[float] = None
    ) -> ResponseComparison:
        """
        Compare two responses and generate detailed comparison results.
        
        Validates: Requirements 28.1, 28.2
        
        Args:
            response1: First response (typically baseline)
            response2: Second response to compare
            threshold: Custom anomaly threshold (uses instance default if None)
            
        Returns:
            ResponseComparison object with detailed comparison results
        """
        if threshold is None:
            threshold = self.anomaly_threshold
            
        # Compute similarity score
        similarity = self.compute_similarity_score(response1, response2)
        
        # Length difference
        length_diff = len(response2.body) - len(response1.body)
        
        # Status code match
        status_match = response1.status_code == response2.status_code
        
        # Header differences
        header_diffs = self._compute_header_differences(response1, response2)
        
        # Body diff
        body_diff = self._compute_body_diff(response1, response2)
        
        # Determine if anomaly
        is_anomaly = similarity < (1.0 - threshold)
        
        return ResponseComparison(
            similarity_score=similarity,
            length_difference=length_diff,
            status_code_match=status_match,
            header_differences=header_diffs,
            body_diff=body_diff,
            is_anomaly=is_anomaly
        )
    
    def _compute_header_differences(
        self,
        response1: Response,
        response2: Response
    ) -> Dict[str, Tuple[Optional[str], Optional[str]]]:
        """
        Compute differences in headers between two responses.
        
        Args:
            response1: First response
            response2: Second response
            
        Returns:
            Dictionary mapping header names to (value1, value2) tuples
            Only includes headers that differ or are present in only one response
        """
        all_headers = set(response1.headers.keys()) | set(response2.headers.keys())
        differences = {}
        
        for header in all_headers:
            val1 = response1.headers.get(header)
            val2 = response2.headers.get(header)
            
            if val1 != val2:
                differences[header] = (val1, val2)
        
        return differences
    
    def _compute_body_diff(
        self,
        response1: Response,
        response2: Response,
        context_lines: int = 3
    ) -> List[str]:
        """
        Compute unified diff of response bodies.
        
        Validates: Requirements 28.3
        
        Args:
            response1: First response
            response2: Second response
            context_lines: Number of context lines to include in diff
            
        Returns:
            List of diff lines in unified diff format
        """
        text1_lines = response1.text.splitlines(keepends=True)
        text2_lines = response2.text.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            text1_lines,
            text2_lines,
            fromfile="baseline",
            tofile="current",
            n=context_lines
        )
        
        return list(diff)
    
    def generate_visual_diff(
        self,
        response1: Response,
        response2: Response,
        format: str = "unified"
    ) -> str:
        """
        Generate a visual diff highlighting differences between responses.
        
        Validates: Requirements 28.3
        
        Args:
            response1: First response (baseline)
            response2: Second response
            format: Diff format - "unified", "context", or "html"
            
        Returns:
            Formatted diff string
        """
        text1_lines = response1.text.splitlines(keepends=True)
        text2_lines = response2.text.splitlines(keepends=True)
        
        if format == "unified":
            diff = difflib.unified_diff(
                text1_lines,
                text2_lines,
                fromfile="baseline",
                tofile="current",
                lineterm=""
            )
            return "\n".join(diff)
        
        elif format == "context":
            diff = difflib.context_diff(
                text1_lines,
                text2_lines,
                fromfile="baseline",
                tofile="current",
                lineterm=""
            )
            return "\n".join(diff)
        
        elif format == "html":
            differ = difflib.HtmlDiff()
            return differ.make_file(
                text1_lines,
                text2_lines,
                fromdesc="Baseline Response",
                todesc="Current Response"
            )
        
        else:
            raise ValueError(f"Unsupported diff format: {format}")
    
    def add_response_timing(self, response: Response):
        """
        Add a response to the timing history for statistical analysis.
        
        Args:
            response: Response to add to history
        """
        self.response_history.append(response)
    
    def analyze_timing_statistics(
        self,
        responses: Optional[List[Response]] = None,
        threshold_sigma: Optional[float] = None
    ) -> TimingStatistics:
        """
        Perform statistical analysis on response timings to identify anomalies.
        
        Validates: Requirements 28.4, 28.5
        
        Args:
            responses: List of responses to analyze (uses history if None)
            threshold_sigma: Number of standard deviations for outlier detection
                           (uses instance default if None)
            
        Returns:
            TimingStatistics object with analysis results
        """
        if responses is None:
            responses = self.response_history
        
        if not responses:
            raise ValueError("No responses available for timing analysis")
        
        if threshold_sigma is None:
            threshold_sigma = self.timing_threshold_sigma
        
        # Extract timings
        timings = [r.elapsed_time for r in responses]
        
        # Compute statistics
        mean_time = statistics.mean(timings)
        median_time = statistics.median(timings)
        
        if len(timings) > 1:
            std_dev = statistics.stdev(timings)
        else:
            std_dev = 0.0
        
        min_time = min(timings)
        max_time = max(timings)
        
        # Identify outliers (beyond threshold_sigma standard deviations)
        threshold = mean_time + (threshold_sigma * std_dev)
        outliers = [
            (r.elapsed_time, r)
            for r in responses
            if r.elapsed_time > threshold
        ]
        
        return TimingStatistics(
            mean=mean_time,
            median=median_time,
            std_dev=std_dev,
            min_time=min_time,
            max_time=max_time,
            outliers=outliers,
            threshold=threshold
        )
    
    def detect_timing_anomalies(
        self,
        responses: Optional[List[Response]] = None,
        threshold_sigma: Optional[float] = None
    ) -> List[Response]:
        """
        Detect responses with anomalous timing that may indicate successful exploitation.
        
        Validates: Requirements 28.4, 28.5
        
        Args:
            responses: List of responses to analyze (uses history if None)
            threshold_sigma: Number of standard deviations for outlier detection
            
        Returns:
            List of responses flagged as timing anomalies
        """
        stats = self.analyze_timing_statistics(responses, threshold_sigma)
        return [response for _, response in stats.outliers]
    
    def flag_anomalies(
        self,
        responses: List[Response],
        baseline_label: str = "baseline",
        threshold: Optional[float] = None
    ) -> List[Tuple[Response, ResponseComparison]]:
        """
        Flag responses that deviate from baseline by configurable threshold.
        
        Validates: Requirements 28.5
        
        Args:
            responses: List of responses to check
            baseline_label: Label of baseline to compare against
            threshold: Custom anomaly threshold (uses instance default if None)
            
        Returns:
            List of (response, comparison) tuples for anomalous responses
        """
        baseline = self.get_baseline(baseline_label)
        if baseline is None:
            raise ValueError(f"No baseline found with label: {baseline_label}")
        
        anomalies = []
        for response in responses:
            comparison = self.compare_responses(baseline.response, response, threshold)
            if comparison.is_anomaly:
                anomalies.append((response, comparison))
        
        return anomalies
    
    def clear_history(self):
        """Clear response history."""
        self.response_history.clear()
    
    def clear_baselines(self):
        """Clear all stored baselines."""
        self.baselines.clear()
