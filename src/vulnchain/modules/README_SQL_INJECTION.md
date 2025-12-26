# SQL Injection Module

This module provides automated SQL injection testing with multiple techniques and SQLMap integration.

## Features

### SQL Injection Testing Techniques

1. **Error-Based SQL Injection**
   - Detects database errors in responses
   - Identifies database type (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
   - Tests various error-inducing payloads

2. **Boolean-Based SQL Injection**
   - Tests true/false conditions
   - Compares response differences
   - Verifies consistency across multiple requests

3. **Time-Based Blind SQL Injection**
   - Adaptive delay detection with baseline measurement
   - Tests multiple database-specific time delay functions
   - Statistical analysis for reliable detection

### SQLMap Integration

- Export vulnerable requests to SQLMap format
- Generate SQLMap command lines
- Execute SQLMap for advanced exploitation

## Usage

### Basic SQL Injection Testing

```python
from app.modules.sql_injection import SQLInjectionTester, InjectionPoint
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
tester = SQLInjectionTester(request_handler)

# Define injection point
injection_point = InjectionPoint(
    parameter="id",
    location="query",  # query, post, header, cookie
    original_value="1",
    url="http://example.com/page?id=1",
    method="GET",
)

# Test for SQL injection
results = await tester.test_injection_point(injection_point)

for result in results:
    if result.is_vulnerable:
        print(f"Vulnerable to {result.injection_type.value}")
        print(f"Database: {result.database_type.value}")
        print(f"Payload: {result.payload}")
        print(f"Confidence: {result.confidence}")
```

### Testing Specific Techniques

```python
from app.modules.sql_injection import SQLInjectionType

# Test only time-based blind
results = await tester.test_injection_point(
    injection_point,
    techniques=[SQLInjectionType.TIME_BASED_BLIND]
)

# Test error-based and boolean-based
results = await tester.test_injection_point(
    injection_point,
    techniques=[
        SQLInjectionType.ERROR_BASED,
        SQLInjectionType.BOOLEAN_BASED,
    ]
)
```

### SQLMap Integration

```python
from app.modules.sql_injection import SQLMapIntegration

# Initialize SQLMap integration
sqlmap = SQLMapIntegration(sqlmap_path="/usr/bin/sqlmap")

# Export to SQLMap format
sqlmap_request = sqlmap.export_to_sqlmap_format(injection_point, result)

# Generate SQLMap command
command = sqlmap.generate_sqlmap_command(
    injection_point,
    result,
    options={
        "batch": True,
        "threads": 5,
        "level": 3,
        "risk": 2,
    }
)

print(f"SQLMap command: {command}")

# Execute SQLMap
return_code, stdout, stderr = await sqlmap.execute_sqlmap(command, timeout=300)
```

## Data Models

### InjectionPoint

Represents a potential SQL injection point:

```python
@dataclass
class InjectionPoint:
    parameter: str              # Parameter name
    location: str               # query, post, header, cookie
    original_value: str         # Original parameter value
    url: str                    # Target URL
    method: str = "GET"         # HTTP method
    headers: Dict = {}          # HTTP headers
    data: Optional[Dict] = None # POST data
```

### SQLInjectionResult

Result of SQL injection testing:

```python
@dataclass
class SQLInjectionResult:
    injection_point: InjectionPoint
    is_vulnerable: bool
    injection_type: Optional[SQLInjectionType]
    database_type: Optional[DatabaseType]
    payload: Optional[str]
    confidence: float           # 0.0 to 1.0
    response_time: Optional[float]
    error_message: Optional[str]
    evidence: List[str]
    metadata: Dict
```

## Supported Databases

- MySQL
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite

## Payload Categories

The module includes built-in payloads for:

1. **Time-Based Blind**
   - MySQL: `SLEEP()`
   - PostgreSQL: `pg_sleep()`
   - MSSQL: `WAITFOR DELAY`
   - Oracle: `DBMS_LOCK.SLEEP()`
   - SQLite: `RANDOMBLOB()`

2. **Boolean-Based**
   - True conditions: `OR 1=1`, `OR '1'='1'`
   - False conditions: `AND 1=2`, `AND '1'='2'`

3. **Error-Based**
   - Quote injection
   - Type confusion
   - Subquery errors

## Adaptive Time-Based Detection

The module uses statistical analysis for reliable time-based detection:

1. **Baseline Measurement**
   - Collects multiple samples of normal response times
   - Calculates mean, median, and standard deviation
   - Sets threshold at mean + 3σ (99.7% confidence)

2. **Delay Detection**
   - Compares response time to baseline threshold
   - Verifies with multiple requests
   - Adapts to network latency

## Requirements

- Python 3.11+
- aiohttp
- httpx
- SQLMap (optional, for advanced exploitation)

## Validation

Requirements validated:
- 6.1: Multiple SQL injection techniques (time-based, boolean-based, error-based)
- 6.2: Adaptive delay thresholds based on baseline measurements
- 6.3: Database type detection from error messages
- 6.4: True/false condition testing for boolean-based injection
- 6.5: SQLMap integration for advanced exploitation
