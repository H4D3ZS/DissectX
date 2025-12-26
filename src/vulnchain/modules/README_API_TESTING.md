# API Testing Module

## Overview

The API Testing module provides comprehensive security testing capabilities for REST and GraphQL APIs. It automates the discovery of API documentation, endpoint enumeration, and vulnerability detection.

## Features

### REST API Testing

1. **OpenAPI/Swagger Discovery**
   - Automatically discovers OpenAPI/Swagger documentation at common paths
   - Parses OpenAPI 2.0 (Swagger) and OpenAPI 3.x specifications
   - Extracts endpoint information, parameters, and security schemes

2. **Authentication & Authorization Testing**
   - Tests endpoints for authentication bypass
   - Validates token enforcement
   - Detects Insecure Direct Object Reference (IDOR) vulnerabilities
   - Tests for missing authorization checks

3. **API Vulnerability Detection**
   - **Excessive Data Exposure**: Detects sensitive fields in API responses
   - **Mass Assignment**: Tests for unfiltered input field acceptance
   - **Rate Limiting**: Identifies missing rate limiting controls

### GraphQL Testing

1. **Endpoint Detection**
   - Automatically detects GraphQL endpoints at common paths
   - Validates GraphQL server presence

2. **Schema Introspection**
   - Executes introspection queries to extract complete schema
   - Parses queries, mutations, subscriptions, and types
   - Identifies available fields and their relationships

3. **GraphQL-Specific Vulnerabilities**
   - **Query Depth Limits**: Tests for missing depth restrictions
   - **Query Batching**: Detects unlimited batch query acceptance
   - **Field Suggestions**: Identifies information disclosure through error messages

## Usage

### Basic REST API Testing

```python
from app.core.request_handler import RequestHandler
from app.models.target import TargetConfig
from app.modules.api_testing import APITestingModule

# Initialize
request_handler = RequestHandler()
api_module = APITestingModule(request_handler)

# Configure target
target = TargetConfig(
    url="https://api.example.com",
    custom_headers={"Authorization": "Bearer token123"}
)

# Run REST API tests
results = await api_module.test_rest_api(target)

# Access results
if results['openapi_spec']:
    print(f"Found OpenAPI spec: {results['openapi_spec']['title']}")
    print(f"Endpoints: {results['openapi_spec']['endpoints_count']}")

for vuln in results['vulnerabilities']:
    print(f"[{vuln['severity']}] {vuln['vulnerability_type']}: {vuln['description']}")
```

### Basic GraphQL Testing

```python
# Run GraphQL tests
results = await api_module.test_graphql_api(target)

# Access results
if results['graphql_endpoint']:
    print(f"Found GraphQL endpoint: {results['graphql_endpoint']}")
    
if results['schema']:
    print(f"Queries: {results['schema']['queries_count']}")
    print(f"Mutations: {results['schema']['mutations_count']}")

for vuln in results['vulnerabilities']:
    print(f"[{vuln['severity']}] {vuln['vulnerability_type']}")
```

### Comprehensive API Testing

```python
# Run both REST and GraphQL tests
results = await api_module.comprehensive_api_test(target)

# Access REST results
rest_results = results['rest_api']

# Access GraphQL results
graphql_results = results['graphql_api']
```

## Component Details

### RESTAPIDiscovery

Handles REST API discovery and OpenAPI/Swagger parsing.

**Key Methods:**
- `discover_openapi_spec(target)`: Discovers OpenAPI documentation
- `test_endpoints_for_auth_bypass(target, endpoints)`: Tests authentication/authorization
- `_parse_openapi_spec(url, spec_data)`: Parses OpenAPI specification

### GraphQLTesting

Handles GraphQL endpoint detection and security testing.

**Key Methods:**
- `detect_graphql_endpoint(target)`: Detects GraphQL endpoints
- `execute_introspection(target, graphql_url)`: Executes introspection query
- `test_query_depth_limits(target, graphql_url, schema)`: Tests depth limits
- `test_query_batching(target, graphql_url, schema)`: Tests batch queries
- `test_field_suggestions(target, graphql_url)`: Tests field suggestions

### APIVulnerabilityDetector

Detects common API vulnerabilities.

**Key Methods:**
- `detect_excessive_data_exposure(target, endpoint)`: Finds sensitive data in responses
- `detect_mass_assignment(target, endpoint)`: Tests for mass assignment
- `detect_rate_limiting(target, endpoint)`: Tests rate limiting

## Data Models

### APIEndpoint
Represents a discovered API endpoint with path, method, parameters, and schema information.

### OpenAPISpec
Contains parsed OpenAPI/Swagger specification with endpoints and security schemes.

### GraphQLSchema
Contains parsed GraphQL schema with queries, mutations, types, and directives.

### APIVulnerability
Represents a discovered vulnerability with type, severity, evidence, and remediation.

## Requirements Validation

This module implements:
- **Requirement 35.1**: REST API OpenAPI/Swagger discovery
- **Requirement 35.2**: GraphQL introspection query execution
- **Requirement 35.3**: Authentication bypass and authorization flaw testing
- **Requirement 35.4**: GraphQL query depth limits, batching, and field suggestion testing
- **Requirement 35.5**: Excessive data exposure, mass assignment, and rate limiting detection

## Security Considerations

- All tests are non-destructive and read-only where possible
- Rate limiting tests use configurable request counts
- Authentication tests respect existing credentials
- GraphQL introspection respects server permissions

## Future Enhancements

- SOAP API testing support
- WebSocket API testing integration
- API fuzzing capabilities
- Automated exploit generation for discovered vulnerabilities
- Integration with API security standards (OWASP API Top 10)
