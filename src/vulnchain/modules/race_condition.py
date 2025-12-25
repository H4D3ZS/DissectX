"""Race Condition module for automated TOCTOU testing

This module implements:
- Concurrent request sending with microsecond-level timing control
- TOCTOU (Time-of-Check-Time-of-Use) vulnerability testing
- Adaptive timing strategies to maximize collision probability
- Repeatable exploit generation with optimal parameters
- Detection of inconsistent states and duplicate transactions
"""

import asyncio
import time
import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Callable, Any
from concurrent.futures import ThreadPoolExecutor
import threading

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.models.target import TargetConfig


class RaceConditionType(Enum):
    """Types of race condition vulnerabilities"""
    
    TOCTOU = "toctou"  # Time-of-Check-Time-of-Use
    DUPLICATE_TRANSACTION = "duplicate_transaction"  # Duplicate processing
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Race to escalate privileges
    RESOURCE_EXHAUSTION = "resource_exhaustion"  # Race to exhaust resources
    STATE_INCONSISTENCY = "state_inconsistency"  # Inconsistent state


class TimingStrategy(Enum):
    """Timing strategies for race condition testing"""
    
    SIMULTANEOUS = "simultaneous"  # Send all requests at once
    STAGGERED = "staggered"  # Stagger requests with small delays
    ADAPTIVE = "adaptive"  # Adapt timing based on response patterns
    BURST = "burst"  # Send bursts of requests
    SYNCHRONIZED = "synchronized"  # Synchronize threads before sending


@dataclass
class RaceConditionTest:
    """Configuration for a race condition test"""
    
    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    num_requests: int = 10
    timing_strategy: TimingStrategy = TimingStrategy.SIMULTANEOUS
    delay_microseconds: int = 0
    check_function: Optional[Callable[[List[Response]], bool]] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class RaceConditionResult:
    """Result of race condition testing"""
    
    test: RaceConditionTest
    is_vulnerable: bool
    race_type: Optional[RaceConditionType] = None
    confidence: float = 0.0
    responses: List[Response] = field(default_factory=list)
    timing_data: Dict = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    exploit_params: Optional[Dict] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class ExploitParameters:
    """Optimal parameters for exploiting a race condition"""
    
    num_threads: int
    timing_strategy: TimingStrategy
    delay_microseconds: int
    success_rate: float
    avg_collision_time: float
    recommended_attempts: int
    exploit_code: str


class RaceConditionTester:
    """Race condition testing with microsecond timing control"""
    
    def __init__(
        self,
        request_handler: RequestHandler,
        max_workers: int = 50,
    ):
        """Initialize race condition tester
        
        Args:
            request_handler: Request handler for HTTP communication
            max_workers: Maximum number of concurrent workers
        """
        self.request_handler = request_handler
        self.max_workers = max_workers
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
    
    async def test_race_condition(
        self,
        test: RaceConditionTest,
    ) -> RaceConditionResult:
        """Test for race condition vulnerability
        
        Args:
            test: Race condition test configuration
        
        Returns:
            RaceConditionResult with findings
        """
        # Send concurrent requests based on timing strategy
        responses, timing_data = await self._send_concurrent_requests(test)
        
        # Analyze responses for race condition indicators
        is_vulnerable, race_type, evidence = self._analyze_responses(
            responses, test
        )
        
        # Calculate confidence based on evidence
        confidence = self._calculate_confidence(evidence, responses)
        
        # Generate exploit parameters if vulnerable
        exploit_params = None
        if is_vulnerable:
            exploit_params = await self._generate_exploit_params(test, responses, timing_data)
        
        return RaceConditionResult(
            test=test,
            is_vulnerable=is_vulnerable,
            race_type=race_type,
            confidence=confidence,
            responses=responses,
            timing_data=timing_data,
            evidence=evidence,
            exploit_params=exploit_params,
        )
    
    async def _send_concurrent_requests(
        self,
        test: RaceConditionTest,
    ) -> Tuple[List[Response], Dict]:
        """Send concurrent requests with precise timing control
        
        Args:
            test: Race condition test configuration
        
        Returns:
            Tuple of (responses, timing_data)
        """
        if test.timing_strategy == TimingStrategy.SIMULTANEOUS:
            return await self._send_simultaneous(test)
        elif test.timing_strategy == TimingStrategy.STAGGERED:
            return await self._send_staggered(test)
        elif test.timing_strategy == TimingStrategy.ADAPTIVE:
            return await self._send_adaptive(test)
        elif test.timing_strategy == TimingStrategy.BURST:
            return await self._send_burst(test)
        elif test.timing_strategy == TimingStrategy.SYNCHRONIZED:
            return await self._send_synchronized(test)
        else:
            return await self._send_simultaneous(test)
    
    async def _send_simultaneous(
        self,
        test: RaceConditionTest,
    ) -> Tuple[List[Response], Dict]:
        """Send all requests simultaneously
        
        Args:
            test: Race condition test configuration
        
        Returns:
            Tuple of (responses, timing_data)
        """
        start_times = []
        end_times = []
        responses = []
        
        # Create tasks for all requests
        tasks = []
        for i in range(test.num_requests):
            task = self._send_single_request(test, i)
            tasks.append(task)
        
        # Execute all tasks concurrently
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                continue
            response, req_start, req_end = result
            responses.append(response)
            start_times.append(req_start)
            end_times.append(req_end)
        
        # Calculate timing statistics
        timing_data = {
            "strategy": "simultaneous",
            "total_time": end_time - start_time,
            "num_requests": len(responses),
            "start_times": start_times,
            "end_times": end_times,
            "time_spread": max(start_times) - min(start_times) if start_times else 0,
            "avg_response_time": statistics.mean([e - s for s, e in zip(start_times, end_times)]) if start_times else 0,
        }
        
        return responses, timing_data
    
    async def _send_staggered(
        self,
        test: RaceConditionTest,
    ) -> Tuple[List[Response], Dict]:
        """Send requests with small staggered delays
        
        Args:
            test: Race condition test configuration
        
        Returns:
            Tuple of (responses, timing_data)
        """
        start_times = []
        end_times = []
        responses = []
        
        delay_seconds = test.delay_microseconds / 1_000_000
        
        for i in range(test.num_requests):
            result = await self._send_single_request(test, i)
            if not isinstance(result, Exception):
                response, req_start, req_end = result
                responses.append(response)
                start_times.append(req_start)
                end_times.append(req_end)
            
            # Small delay between requests
            if i < test.num_requests - 1:
                await asyncio.sleep(delay_seconds)
        
        timing_data = {
            "strategy": "staggered",
            "delay_microseconds": test.delay_microseconds,
            "num_requests": len(responses),
            "start_times": start_times,
            "end_times": end_times,
            "time_spread": max(start_times) - min(start_times) if start_times else 0,
        }
        
        return responses, timing_data
    
    async def _send_adaptive(
        self,
        test: RaceConditionTest,
    ) -> Tuple[List[Response], Dict]:
        """Send requests with adaptive timing based on response patterns
        
        Args:
            test: Race condition test configuration
        
        Returns:
            Tuple of (responses, timing_data)
        """
        # Start with simultaneous strategy
        responses, timing_data = await self._send_simultaneous(test)
        
        # Analyze initial results
        has_variation = self._has_response_variation(responses)
        
        if not has_variation:
            # Try with smaller batches and delays
            batch_size = max(2, test.num_requests // 5)
            responses = []
            start_times = []
            end_times = []
            
            for batch_start in range(0, test.num_requests, batch_size):
                batch_end = min(batch_start + batch_size, test.num_requests)
                batch_test = RaceConditionTest(
                    url=test.url,
                    method=test.method,
                    headers=test.headers,
                    data=test.data,
                    cookies=test.cookies,
                    num_requests=batch_end - batch_start,
                    timing_strategy=TimingStrategy.SIMULTANEOUS,
                )
                
                batch_responses, batch_timing = await self._send_simultaneous(batch_test)
                responses.extend(batch_responses)
                start_times.extend(batch_timing["start_times"])
                end_times.extend(batch_timing["end_times"])
                
                # Small delay between batches
                await asyncio.sleep(0.01)
            
            timing_data = {
                "strategy": "adaptive_batched",
                "batch_size": batch_size,
                "num_requests": len(responses),
                "start_times": start_times,
                "end_times": end_times,
            }
        else:
            timing_data["strategy"] = "adaptive_simultaneous"
        
        return responses, timing_data
    
    async def _send_burst(
        self,
        test: RaceConditionTest,
    ) -> Tuple[List[Response], Dict]:
        """Send requests in bursts
        
        Args:
            test: Race condition test configuration
        
        Returns:
            Tuple of (responses, timing_data)
        """
        burst_size = 5
        num_bursts = (test.num_requests + burst_size - 1) // burst_size
        
        responses = []
        start_times = []
        end_times = []
        
        for burst_num in range(num_bursts):
            burst_start = burst_num * burst_size
            burst_end = min(burst_start + burst_size, test.num_requests)
            
            # Send burst simultaneously
            burst_test = RaceConditionTest(
                url=test.url,
                method=test.method,
                headers=test.headers,
                data=test.data,
                cookies=test.cookies,
                num_requests=burst_end - burst_start,
                timing_strategy=TimingStrategy.SIMULTANEOUS,
            )
            
            burst_responses, burst_timing = await self._send_simultaneous(burst_test)
            responses.extend(burst_responses)
            start_times.extend(burst_timing["start_times"])
            end_times.extend(burst_timing["end_times"])
            
            # Delay between bursts
            if burst_num < num_bursts - 1:
                await asyncio.sleep(0.1)
        
        timing_data = {
            "strategy": "burst",
            "burst_size": burst_size,
            "num_bursts": num_bursts,
            "num_requests": len(responses),
            "start_times": start_times,
            "end_times": end_times,
        }
        
        return responses, timing_data
    
    async def _send_synchronized(
        self,
        test: RaceConditionTest,
    ) -> Tuple[List[Response], Dict]:
        """Send requests with thread synchronization for maximum collision
        
        Args:
            test: Race condition test configuration
        
        Returns:
            Tuple of (responses, timing_data)
        """
        barrier = threading.Barrier(test.num_requests)
        responses = []
        start_times = []
        end_times = []
        lock = threading.Lock()
        
        def synchronized_request(request_id: int):
            """Send request after barrier synchronization"""
            try:
                # Wait for all threads to be ready
                barrier.wait()
                
                # Record start time immediately after barrier
                req_start = time.time()
                
                # Send request synchronously (in thread)
                import requests
                
                if test.method.upper() == "GET":
                    resp = requests.get(
                        test.url,
                        headers=test.headers,
                        cookies=test.cookies,
                        timeout=30,
                    )
                elif test.method.upper() == "POST":
                    resp = requests.post(
                        test.url,
                        headers=test.headers,
                        data=test.data,
                        cookies=test.cookies,
                        timeout=30,
                    )
                else:
                    resp = requests.request(
                        test.method,
                        test.url,
                        headers=test.headers,
                        data=test.data,
                        cookies=test.cookies,
                        timeout=30,
                    )
                
                req_end = time.time()
                
                # Convert to our Response format
                from src.vulnchain.core.http_models import Request as HttpRequest
                http_request = HttpRequest(method=test.method, url=test.url)
                response = Response(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.content,
                    text=resp.text,
                    elapsed_time=req_end - req_start,
                    request=http_request,
                )
                
                # Thread-safe append
                with lock:
                    responses.append(response)
                    start_times.append(req_start)
                    end_times.append(req_end)
                
                return response
            
            except Exception as e:
                return None
        
        # Submit all tasks to thread pool
        futures = []
        for i in range(test.num_requests):
            future = self._executor.submit(synchronized_request, i)
            futures.append(future)
        
        # Wait for all to complete
        for future in futures:
            try:
                future.result(timeout=60)
            except Exception:
                pass
        
        timing_data = {
            "strategy": "synchronized",
            "num_requests": len(responses),
            "start_times": start_times,
            "end_times": end_times,
            "time_spread": max(start_times) - min(start_times) if start_times else 0,
            "max_collision_window": max(start_times) - min(start_times) if start_times else 0,
        }
        
        return responses, timing_data
    
    async def _send_single_request(
        self,
        test: RaceConditionTest,
        request_id: int,
    ) -> Tuple[Response, float, float]:
        """Send a single request and record timing
        
        Args:
            test: Race condition test configuration
            request_id: Request identifier
        
        Returns:
            Tuple of (response, start_time, end_time)
        """
        start_time = time.time()
        
        response = await self.request_handler.send_request(
            method=test.method,
            url=test.url,
            headers=test.headers,
            data=test.data,
            cookies=test.cookies,
        )
        
        end_time = time.time()
        
        return response, start_time, end_time
    
    def _analyze_responses(
        self,
        responses: List[Response],
        test: RaceConditionTest,
    ) -> Tuple[bool, Optional[RaceConditionType], List[str]]:
        """Analyze responses for race condition indicators
        
        Args:
            responses: List of responses
            test: Race condition test configuration
        
        Returns:
            Tuple of (is_vulnerable, race_type, evidence)
        """
        evidence = []
        
        # Use custom check function if provided
        if test.check_function:
            try:
                is_vulnerable = test.check_function(responses)
                if is_vulnerable:
                    evidence.append("Custom check function detected vulnerability")
                    return True, RaceConditionType.STATE_INCONSISTENCY, evidence
            except Exception as e:
                evidence.append(f"Custom check function error: {str(e)}")
        
        # Check for duplicate successful transactions
        success_count = sum(1 for r in responses if 200 <= r.status_code < 300)
        if success_count > 1:
            evidence.append(f"Multiple successful responses: {success_count}/{len(responses)}")
            
            # Check if responses are identical (likely duplicate processing)
            unique_bodies = set(r.text for r in responses if 200 <= r.status_code < 300)
            if len(unique_bodies) == 1:
                evidence.append("All successful responses identical - likely duplicate transaction")
                return True, RaceConditionType.DUPLICATE_TRANSACTION, evidence
        
        # Check for inconsistent states
        status_codes = [r.status_code for r in responses]
        unique_statuses = set(status_codes)
        
        if len(unique_statuses) > 1:
            evidence.append(f"Inconsistent status codes: {unique_statuses}")
            
            # Check for mix of success and failure
            has_success = any(200 <= s < 300 for s in status_codes)
            has_failure = any(s >= 400 for s in status_codes)
            
            if has_success and has_failure:
                evidence.append("Mix of success and failure responses - possible TOCTOU")
                return True, RaceConditionType.TOCTOU, evidence
        
        # Check response body variations
        response_bodies = [r.text for r in responses]
        unique_bodies = set(response_bodies)
        
        if len(unique_bodies) > 1:
            evidence.append(f"Response body variations: {len(unique_bodies)} unique responses")
            
            # Look for state-related keywords
            state_keywords = [
                "balance", "credit", "amount", "quantity", "count",
                "available", "remaining", "limit", "quota",
            ]
            
            for keyword in state_keywords:
                if any(keyword.lower() in body.lower() for body in response_bodies):
                    evidence.append(f"State-related keyword found: {keyword}")
                    return True, RaceConditionType.STATE_INCONSISTENCY, evidence
        
        # Check for error messages indicating race conditions
        race_error_patterns = [
            "deadlock",
            "lock timeout",
            "concurrent",
            "already exists",
            "duplicate",
            "conflict",
            "race",
        ]
        
        for response in responses:
            for pattern in race_error_patterns:
                if pattern.lower() in response.text.lower():
                    evidence.append(f"Race condition error pattern found: {pattern}")
                    return True, RaceConditionType.STATE_INCONSISTENCY, evidence
        
        # No clear vulnerability found
        return False, None, evidence
    
    def _has_response_variation(self, responses: List[Response]) -> bool:
        """Check if responses have significant variation
        
        Args:
            responses: List of responses
        
        Returns:
            True if responses vary significantly
        """
        if len(responses) < 2:
            return False
        
        # Check status code variation
        status_codes = set(r.status_code for r in responses)
        if len(status_codes) > 1:
            return True
        
        # Check body length variation
        body_lengths = [len(r.text) for r in responses]
        if len(set(body_lengths)) > 1:
            return True
        
        # Check body content variation
        unique_bodies = set(r.text for r in responses)
        if len(unique_bodies) > 1:
            return True
        
        return False
    
    def _calculate_confidence(
        self,
        evidence: List[str],
        responses: List[Response],
    ) -> float:
        """Calculate confidence score for vulnerability
        
        Args:
            evidence: List of evidence strings
            responses: List of responses
        
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not evidence:
            return 0.0
        
        confidence = 0.0
        
        # Base confidence from evidence count
        confidence += min(len(evidence) * 0.2, 0.6)
        
        # Bonus for multiple successful transactions
        success_count = sum(1 for r in responses if 200 <= r.status_code < 300)
        if success_count > 1:
            confidence += 0.2
        
        # Bonus for error messages
        if any("error" in e.lower() or "duplicate" in e.lower() for e in evidence):
            confidence += 0.1
        
        # Bonus for state inconsistency
        if any("inconsistent" in e.lower() or "state" in e.lower() for e in evidence):
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    async def _generate_exploit_params(
        self,
        test: RaceConditionTest,
        responses: List[Response],
        timing_data: Dict,
    ) -> ExploitParameters:
        """Generate optimal exploit parameters
        
        Args:
            test: Race condition test configuration
            responses: List of responses from test
            timing_data: Timing data from test
        
        Returns:
            ExploitParameters with optimal settings
        """
        # Calculate success rate
        success_count = sum(1 for r in responses if 200 <= r.status_code < 300)
        success_rate = success_count / len(responses) if responses else 0.0
        
        # Calculate average collision time
        if "time_spread" in timing_data:
            avg_collision_time = timing_data["time_spread"]
        else:
            avg_collision_time = 0.0
        
        # Determine optimal thread count
        # More threads if success rate is low
        if success_rate < 0.3:
            optimal_threads = min(test.num_requests * 2, 100)
        else:
            optimal_threads = test.num_requests
        
        # Determine optimal timing strategy
        if timing_data.get("strategy") == "synchronized":
            optimal_strategy = TimingStrategy.SYNCHRONIZED
        elif success_rate > 0.5:
            optimal_strategy = test.timing_strategy
        else:
            optimal_strategy = TimingStrategy.SYNCHRONIZED
        
        # Calculate recommended attempts
        if success_rate > 0.5:
            recommended_attempts = 5
        elif success_rate > 0.2:
            recommended_attempts = 10
        else:
            recommended_attempts = 20
        
        # Generate exploit code
        exploit_code = self._generate_exploit_code(
            test, optimal_threads, optimal_strategy, recommended_attempts
        )
        
        return ExploitParameters(
            num_threads=optimal_threads,
            timing_strategy=optimal_strategy,
            delay_microseconds=0,
            success_rate=success_rate,
            avg_collision_time=avg_collision_time,
            recommended_attempts=recommended_attempts,
            exploit_code=exploit_code,
        )
    
    def _generate_exploit_code(
        self,
        test: RaceConditionTest,
        num_threads: int,
        strategy: TimingStrategy,
        attempts: int,
    ) -> str:
        """Generate exploit code
        
        Args:
            test: Race condition test configuration
            num_threads: Number of threads to use
            strategy: Timing strategy
            attempts: Number of attempts
        
        Returns:
            Python exploit code as string
        """
        code = f'''#!/usr/bin/env python3
"""
Race Condition Exploit
Generated by VulnChain CTF Framework

Target: {test.url}
Method: {test.method}
Threads: {num_threads}
Strategy: {strategy.value}
Recommended Attempts: {attempts}
"""

import requests
import threading
from concurrent.futures import ThreadPoolExecutor
import time

# Configuration
URL = "{test.url}"
METHOD = "{test.method}"
HEADERS = {test.headers}
DATA = {test.data}
COOKIES = {test.cookies}
NUM_THREADS = {num_threads}
NUM_ATTEMPTS = {attempts}

def exploit_attempt():
    """Single exploit attempt with race condition"""
    responses = []
    
    def send_request(thread_id):
        """Send a single request"""
        try:
            if METHOD.upper() == "GET":
                resp = requests.get(URL, headers=HEADERS, cookies=COOKIES, timeout=30)
            elif METHOD.upper() == "POST":
                resp = requests.post(URL, headers=HEADERS, data=DATA, cookies=COOKIES, timeout=30)
            else:
                resp = requests.request(METHOD, URL, headers=HEADERS, data=DATA, cookies=COOKIES, timeout=30)
            
            responses.append(resp)
            return resp
        except Exception as e:
            print(f"Thread {{thread_id}} error: {{e}}")
            return None
    
    # Use ThreadPoolExecutor for concurrent requests
    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = [executor.submit(send_request, i) for i in range(NUM_THREADS)]
        
        # Wait for all to complete
        for future in futures:
            future.result(timeout=60)
    
    # Analyze results
    success_count = sum(1 for r in responses if r and 200 <= r.status_code < 300)
    print(f"  Responses: {{len(responses)}}, Successful: {{success_count}}")
    
    return success_count > 1

def main():
    """Main exploit function"""
    print(f"Starting race condition exploit...")
    print(f"Target: {{URL}}")
    print(f"Threads: {{NUM_THREADS}}")
    print(f"Attempts: {{NUM_ATTEMPTS}}")
    print()
    
    successful_attempts = 0
    
    for attempt in range(NUM_ATTEMPTS):
        print(f"Attempt {{attempt + 1}}/{{NUM_ATTEMPTS}}...")
        
        if exploit_attempt():
            successful_attempts += 1
            print(f"  ✓ Race condition triggered!")
        else:
            print(f"  ✗ No race detected")
        
        # Small delay between attempts
        time.sleep(0.5)
    
    print()
    print(f"Results: {{successful_attempts}}/{{NUM_ATTEMPTS}} successful")
    print(f"Success rate: {{successful_attempts / NUM_ATTEMPTS * 100:.1f}}%")

if __name__ == "__main__":
    main()
'''
        
        return code
    
    def __del__(self):
        """Cleanup executor on deletion"""
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)
