"""API testing module for REST and GraphQL API security testing

This module implements:
- REST API discovery (OpenAPI/Swagger documentation)
- GraphQL introspection and testing
- API vulnerability detection (authentication bypass, authorization flaws, injection)
- Excessive data exposure and mass assignment detection
- Rate limiting analysis
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from src.vulnchain.core.request_handler import RequestHandler
from src.vulnchain.models.target import TargetConfig


@dataclass
class APIEndpoint:
    """Represents a discovered API endpoint"""
    
    path: str
    method: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    description: Optional[str] = None
    requires_auth: bool = False
    request_body_schema: Optional[Dict[str, Any]] = None
    response_schema: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class OpenAPISpec:
    """Represents an OpenAPI/Swagger specification"""
    
    url: str
    version: str  # OpenAPI version (2.0, 3.0, 3.1)
    title: Optional[str] = None
    description: Optional[str] = None
    base_path: Optional[str] = None
    endpoints: List[APIEndpoint] = field(default_factory=list)
    security_schemes: Dict[str, Any] = field(default_factory=dict)
    raw_spec: Optional[Dict[str, Any]] = None


@dataclass
class GraphQLSchema:
    """Represents a GraphQL schema"""
    
    url: str
    types: List[Dict[str, Any]] = field(default_factory=list)
    queries: List[Dict[str, Any]] = field(default_factory=list)
    mutations: List[Dict[str, Any]] = field(default_factory=list)
    subscriptions: List[Dict[str, Any]] = field(default_factory=list)
    directives: List[Dict[str, Any]] = field(default_factory=list)
    raw_schema: Optional[Dict[str, Any]] = None


@dataclass
class APIVulnerability:
    """Represents an API vulnerability finding"""
    
    vulnerability_type: str
    severity: str  # critical, high, medium, low, info
    endpoint: str
    method: str
    description: str
    evidence: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class RESTAPIDiscovery:
    """REST API discovery and OpenAPI/Swagger detection"""
    
    # Common paths for OpenAPI/Swagger documentation
    OPENAPI_PATHS = [
        '/swagger.json',
        '/swagger.yaml',
        '/swagger.yml',
        '/openapi.json',
        '/openapi.yaml',
        '/openapi.yml',
        '/api/swagger.json',
        '/api/swagger.yaml',
        '/api/openapi.json',
        '/api/openapi.yaml',
        '/api-docs',
        '/api-docs.json',
        '/api/docs',
        '/api/docs.json',
        '/v1/swagger.json',
        '/v2/swagger.json',
        '/v3/swagger.json',
        '/swagger/v1/swagger.json',
        '/swagger/v2/swagger.json',
        '/swagger-ui.html',
        '/api/swagger-ui.html',
        '/docs',
        '/redoc',
        '/api/redoc',
    ]

    
    def __init__(self, request_handler: RequestHandler):
        """Initialize REST API discovery
        
        Args:
            request_handler: RequestHandler instance for HTTP operations
        """
        self.request_handler = request_handler
    
    async def discover_openapi_spec(self, target: TargetConfig) -> Optional[OpenAPISpec]:
        """Discover OpenAPI/Swagger documentation
        
        Args:
            target: Target configuration
            
        Returns:
            OpenAPISpec if found, None otherwise
        """
        # Try common OpenAPI paths
        for path in self.OPENAPI_PATHS:
            try:
                url = urljoin(target.url, path)
                
                response = await self.request_handler.send_request(
                    method='GET',
                    url=url,
                    headers=target.custom_headers,
                    proxy=target.proxy,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    # Try to parse as JSON
                    try:
                        spec_data = json.loads(response.text)
                        
                        # Check if it's a valid OpenAPI/Swagger spec
                        if self._is_valid_openapi_spec(spec_data):
                            return self._parse_openapi_spec(url, spec_data)
                    
                    except json.JSONDecodeError:
                        # Try YAML parsing (would need PyYAML)
                        pass
            
            except Exception:
                continue
        
        return None

    
    def _is_valid_openapi_spec(self, spec_data: Dict[str, Any]) -> bool:
        """Check if data is a valid OpenAPI/Swagger spec
        
        Args:
            spec_data: Parsed JSON data
            
        Returns:
            True if valid OpenAPI spec, False otherwise
        """
        # Check for OpenAPI 3.x
        if 'openapi' in spec_data:
            return True
        
        # Check for Swagger 2.0
        if 'swagger' in spec_data and spec_data['swagger'] == '2.0':
            return True
        
        return False
    
    def _parse_openapi_spec(self, url: str, spec_data: Dict[str, Any]) -> OpenAPISpec:
        """Parse OpenAPI/Swagger specification
        
        Args:
            url: URL where spec was found
            spec_data: Parsed spec data
            
        Returns:
            OpenAPISpec object
        """
        spec = OpenAPISpec(url=url, version='', raw_spec=spec_data)
        
        # Determine version
        if 'openapi' in spec_data:
            spec.version = spec_data['openapi']
        elif 'swagger' in spec_data:
            spec.version = spec_data['swagger']
        
        # Extract metadata
        if 'info' in spec_data:
            info = spec_data['info']
            spec.title = info.get('title')
            spec.description = info.get('description')
        
        # Extract base path
        if 'basePath' in spec_data:
            spec.base_path = spec_data['basePath']
        elif 'servers' in spec_data and spec_data['servers']:
            # OpenAPI 3.x uses servers
            spec.base_path = spec_data['servers'][0].get('url', '')
        
        # Extract security schemes
        if 'securityDefinitions' in spec_data:
            spec.security_schemes = spec_data['securityDefinitions']
        elif 'components' in spec_data and 'securitySchemes' in spec_data['components']:
            spec.security_schemes = spec_data['components']['securitySchemes']
        
        # Parse endpoints
        if 'paths' in spec_data:
            spec.endpoints = self._parse_paths(spec_data['paths'], spec_data)
        
        return spec

    
    def _parse_paths(
        self, paths: Dict[str, Any], spec_data: Dict[str, Any]
    ) -> List[APIEndpoint]:
        """Parse paths from OpenAPI spec
        
        Args:
            paths: Paths object from spec
            spec_data: Full spec data for reference resolution
            
        Returns:
            List of APIEndpoint objects
        """
        endpoints = []
        
        for path, path_item in paths.items():
            # Each path can have multiple methods
            for method in ['get', 'post', 'put', 'patch', 'delete', 'options', 'head']:
                if method in path_item:
                    operation = path_item[method]
                    
                    endpoint = APIEndpoint(
                        path=path,
                        method=method.upper(),
                        description=operation.get('description') or operation.get('summary'),
                        tags=operation.get('tags', [])
                    )
                    
                    # Extract parameters
                    if 'parameters' in operation:
                        endpoint.parameters = operation['parameters']
                    
                    # Check if authentication is required
                    if 'security' in operation or 'security' in spec_data:
                        endpoint.requires_auth = True
                    
                    # Extract request body schema (OpenAPI 3.x)
                    if 'requestBody' in operation:
                        request_body = operation['requestBody']
                        if 'content' in request_body:
                            # Get first content type
                            content_type = list(request_body['content'].keys())[0]
                            if 'schema' in request_body['content'][content_type]:
                                endpoint.request_body_schema = request_body['content'][content_type]['schema']
                    
                    # Extract response schema
                    if 'responses' in operation:
                        # Get 200 response schema
                        if '200' in operation['responses']:
                            response_200 = operation['responses']['200']
                            if 'content' in response_200:
                                content_type = list(response_200['content'].keys())[0]
                                if 'schema' in response_200['content'][content_type]:
                                    endpoint.response_schema = response_200['content'][content_type]['schema']
                            elif 'schema' in response_200:
                                # Swagger 2.0 format
                                endpoint.response_schema = response_200['schema']
                    
                    endpoints.append(endpoint)
        
        return endpoints

    
    async def test_endpoints_for_auth_bypass(
        self, target: TargetConfig, endpoints: List[APIEndpoint]
    ) -> List[APIVulnerability]:
        """Test API endpoints for authentication and authorization flaws
        
        Args:
            target: Target configuration
            endpoints: List of endpoints to test
            
        Returns:
            List of discovered vulnerabilities
        """
        vulnerabilities = []
        
        for endpoint in endpoints:
            # Build full URL
            base_url = target.url
            if endpoint.path.startswith('/'):
                url = urljoin(base_url, endpoint.path)
            else:
                url = urljoin(base_url, '/' + endpoint.path)
            
            # Test 1: Access without authentication
            if endpoint.requires_auth:
                vuln = await self._test_unauthenticated_access(
                    url, endpoint.method, target
                )
                if vuln:
                    vulnerabilities.append(vuln)
            
            # Test 2: Test with invalid/expired token
            vuln = await self._test_invalid_token(url, endpoint.method, target)
            if vuln:
                vulnerabilities.append(vuln)
            
            # Test 3: Test for IDOR (if endpoint has ID parameter)
            if self._has_id_parameter(endpoint):
                vuln = await self._test_idor(url, endpoint, target)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_unauthenticated_access(
        self, url: str, method: str, target: TargetConfig
    ) -> Optional[APIVulnerability]:
        """Test if endpoint is accessible without authentication
        
        Args:
            url: Endpoint URL
            method: HTTP method
            target: Target configuration
            
        Returns:
            APIVulnerability if vulnerable, None otherwise
        """
        try:
            # Send request without authentication headers
            headers = target.custom_headers.copy() if target.custom_headers else {}
            # Remove common auth headers
            headers.pop('Authorization', None)
            headers.pop('X-API-Key', None)
            headers.pop('X-Auth-Token', None)
            
            response = await self.request_handler.send_request(
                method=method,
                url=url,
                headers=headers,
                proxy=target.proxy,
                timeout=10.0
            )
            
            # If we get 200 or 2xx, endpoint is accessible without auth
            if 200 <= response.status_code < 300:
                return APIVulnerability(
                    vulnerability_type='authentication_bypass',
                    severity='high',
                    endpoint=url,
                    method=method,
                    description='Endpoint accessible without authentication',
                    evidence=[
                        f'Request without auth headers returned {response.status_code}',
                        f'Response length: {len(response.body)} bytes'
                    ],
                    remediation='Implement proper authentication checks for this endpoint'
                )
        
        except Exception:
            pass
        
        return None

    
    async def _test_invalid_token(
        self, url: str, method: str, target: TargetConfig
    ) -> Optional[APIVulnerability]:
        """Test if endpoint accepts invalid/malformed tokens
        
        Args:
            url: Endpoint URL
            method: HTTP method
            target: Target configuration
            
        Returns:
            APIVulnerability if vulnerable, None otherwise
        """
        try:
            # Test with invalid token
            headers = target.custom_headers.copy() if target.custom_headers else {}
            headers['Authorization'] = 'Bearer invalid_token_12345'
            
            response = await self.request_handler.send_request(
                method=method,
                url=url,
                headers=headers,
                proxy=target.proxy,
                timeout=10.0
            )
            
            # If we get 200, endpoint doesn't validate tokens properly
            if 200 <= response.status_code < 300:
                return APIVulnerability(
                    vulnerability_type='weak_token_validation',
                    severity='high',
                    endpoint=url,
                    method=method,
                    description='Endpoint accepts invalid authentication tokens',
                    evidence=[
                        f'Request with invalid token returned {response.status_code}',
                        'Token validation may be missing or improperly implemented'
                    ],
                    remediation='Implement proper token validation'
                )
        
        except Exception:
            pass
        
        return None
    
    def _has_id_parameter(self, endpoint: APIEndpoint) -> bool:
        """Check if endpoint has an ID parameter (potential IDOR)
        
        Args:
            endpoint: API endpoint
            
        Returns:
            True if has ID parameter, False otherwise
        """
        # Check path for ID patterns
        id_patterns = [r'\{id\}', r'\{.*_id\}', r'/\d+', r'\{uuid\}']
        for pattern in id_patterns:
            if re.search(pattern, endpoint.path):
                return True
        
        # Check parameters
        for param in endpoint.parameters:
            if isinstance(param, dict):
                param_name = param.get('name', '').lower()
                if 'id' in param_name or 'uuid' in param_name:
                    return True
        
        return False

    
    async def _test_idor(
        self, url: str, endpoint: APIEndpoint, target: TargetConfig
    ) -> Optional[APIVulnerability]:
        """Test for Insecure Direct Object Reference (IDOR)
        
        Args:
            url: Endpoint URL
            endpoint: API endpoint
            target: Target configuration
            
        Returns:
            APIVulnerability if vulnerable, None otherwise
        """
        try:
            # Replace ID in URL with different values
            test_ids = ['1', '2', '999', 'admin', '../1']
            
            for test_id in test_ids:
                # Replace ID patterns in URL
                test_url = re.sub(r'\{id\}', test_id, url)
                test_url = re.sub(r'\{.*_id\}', test_id, test_url)
                test_url = re.sub(r'/\d+', f'/{test_id}', test_url)
                
                response = await self.request_handler.send_request(
                    method=endpoint.method,
                    url=test_url,
                    headers=target.custom_headers,
                    proxy=target.proxy,
                    timeout=10.0
                )
                
                # If we get 200, might be IDOR
                if 200 <= response.status_code < 300:
                    return APIVulnerability(
                        vulnerability_type='idor',
                        severity='high',
                        endpoint=url,
                        method=endpoint.method,
                        description='Potential Insecure Direct Object Reference (IDOR)',
                        evidence=[
                            f'Endpoint accessible with test ID: {test_id}',
                            f'Response status: {response.status_code}',
                            'Authorization checks may be missing'
                        ],
                        remediation='Implement proper authorization checks for object access',
                        metadata={'test_id': test_id}
                    )
        
        except Exception:
            pass
        
        return None


class GraphQLTesting:
    """GraphQL introspection and security testing"""
    
    # GraphQL introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    
    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }
    
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    
    def __init__(self, request_handler: RequestHandler):
        """Initialize GraphQL testing
        
        Args:
            request_handler: RequestHandler instance for HTTP operations
        """
        self.request_handler = request_handler
    
    async def detect_graphql_endpoint(self, target: TargetConfig) -> Optional[str]:
        """Detect GraphQL endpoint
        
        Args:
            target: Target configuration
            
        Returns:
            GraphQL endpoint URL if found, None otherwise
        """
        # Common GraphQL paths
        graphql_paths = [
            '/graphql',
            '/api/graphql',
            '/v1/graphql',
            '/v2/graphql',
            '/query',
            '/api/query',
            '/gql',
            '/api/gql',
        ]
        
        for path in graphql_paths:
            try:
                url = urljoin(target.url, path)
                
                # Try a simple GraphQL query
                response = await self.request_handler.send_request(
                    method='POST',
                    url=url,
                    headers={
                        **target.custom_headers,
                        'Content-Type': 'application/json'
                    },
                    data=json.dumps({'query': '{ __typename }'}),
                    proxy=target.proxy,
                    timeout=10.0
                )
                
                # Check if response looks like GraphQL
                if response.status_code == 200:
                    try:
                        data = json.loads(response.text)
                        if 'data' in data or 'errors' in data:
                            return url
                    except json.JSONDecodeError:
                        pass
            
            except Exception:
                continue
        
        return None

    
    async def execute_introspection(
        self, target: TargetConfig, graphql_url: str
    ) -> Optional[GraphQLSchema]:
        """Execute GraphQL introspection query
        
        Args:
            target: Target configuration
            graphql_url: GraphQL endpoint URL
            
        Returns:
            GraphQLSchema if successful, None otherwise
        """
        try:
            response = await self.request_handler.send_request(
                method='POST',
                url=graphql_url,
                headers={
                    **target.custom_headers,
                    'Content-Type': 'application/json'
                },
                data=json.dumps({'query': self.INTROSPECTION_QUERY}),
                proxy=target.proxy,
                timeout=30.0
            )
            
            if response.status_code == 200:
                data = json.loads(response.text)
                
                if 'data' in data and '__schema' in data['data']:
                    return self._parse_introspection_result(graphql_url, data['data']['__schema'])
        
        except Exception:
            pass
        
        return None
    
    def _parse_introspection_result(self, url: str, schema_data: Dict[str, Any]) -> GraphQLSchema:
        """Parse introspection result into GraphQLSchema
        
        Args:
            url: GraphQL endpoint URL
            schema_data: Schema data from introspection
            
        Returns:
            GraphQLSchema object
        """
        schema = GraphQLSchema(url=url, raw_schema=schema_data)
        
        # Extract types
        if 'types' in schema_data:
            schema.types = schema_data['types']
        
        # Extract queries
        if 'queryType' in schema_data and schema_data['queryType']:
            query_type_name = schema_data['queryType']['name']
            query_type = self._find_type_by_name(schema.types, query_type_name)
            if query_type and 'fields' in query_type:
                schema.queries = query_type['fields']
        
        # Extract mutations
        if 'mutationType' in schema_data and schema_data['mutationType']:
            mutation_type_name = schema_data['mutationType']['name']
            mutation_type = self._find_type_by_name(schema.types, mutation_type_name)
            if mutation_type and 'fields' in mutation_type:
                schema.mutations = mutation_type['fields']
        
        # Extract subscriptions
        if 'subscriptionType' in schema_data and schema_data['subscriptionType']:
            subscription_type_name = schema_data['subscriptionType']['name']
            subscription_type = self._find_type_by_name(schema.types, subscription_type_name)
            if subscription_type and 'fields' in subscription_type:
                schema.subscriptions = subscription_type['fields']
        
        # Extract directives
        if 'directives' in schema_data:
            schema.directives = schema_data['directives']
        
        return schema
    
    def _find_type_by_name(self, types: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
        """Find a type by name in the types list
        
        Args:
            types: List of types
            name: Type name to find
            
        Returns:
            Type object if found, None otherwise
        """
        for type_obj in types:
            if type_obj.get('name') == name:
                return type_obj
        return None

    
    async def test_query_depth_limits(
        self, target: TargetConfig, graphql_url: str, schema: GraphQLSchema
    ) -> List[APIVulnerability]:
        """Test GraphQL query depth limits
        
        Args:
            target: Target configuration
            graphql_url: GraphQL endpoint URL
            schema: GraphQL schema
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Generate deeply nested query
        if schema.queries:
            # Pick first query
            query_field = schema.queries[0]
            query_name = query_field['name']
            
            # Create nested query (depth 20)
            nested_query = self._generate_nested_query(query_name, depth=20)
            
            try:
                response = await self.request_handler.send_request(
                    method='POST',
                    url=graphql_url,
                    headers={
                        **target.custom_headers,
                        'Content-Type': 'application/json'
                    },
                    data=json.dumps({'query': nested_query}),
                    proxy=target.proxy,
                    timeout=30.0
                )
                
                # If query succeeds, depth limit may not be enforced
                if response.status_code == 200:
                    try:
                        data = json.loads(response.text)
                        if 'data' in data and not data.get('errors'):
                            vulnerabilities.append(APIVulnerability(
                                vulnerability_type='graphql_depth_limit',
                                severity='medium',
                                endpoint=graphql_url,
                                method='POST',
                                description='GraphQL query depth limits not enforced',
                                evidence=[
                                    'Deeply nested query (depth 20) was accepted',
                                    'This can lead to DoS attacks'
                                ],
                                remediation='Implement query depth limiting'
                            ))
                    except json.JSONDecodeError:
                        pass
            
            except Exception:
                pass
        
        return vulnerabilities
    
    def _generate_nested_query(self, field_name: str, depth: int) -> str:
        """Generate a deeply nested GraphQL query
        
        Args:
            field_name: Field name to query
            depth: Nesting depth
            
        Returns:
            Nested query string
        """
        # Simple nested query pattern
        query = f"query {{ {field_name} {{ "
        for i in range(depth):
            query += f"nested{i} {{ "
        query += "__typename "
        for i in range(depth):
            query += "} "
        query += "} }"
        return query

    
    async def test_query_batching(
        self, target: TargetConfig, graphql_url: str, schema: GraphQLSchema
    ) -> List[APIVulnerability]:
        """Test GraphQL query batching attacks
        
        Args:
            target: Target configuration
            graphql_url: GraphQL endpoint URL
            schema: GraphQL schema
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        if schema.queries:
            query_field = schema.queries[0]
            query_name = query_field['name']
            
            # Create batch of queries
            batch_size = 100
            batch_queries = []
            for i in range(batch_size):
                batch_queries.append({
                    'query': f'query {{ {query_name} {{ __typename }} }}'
                })
            
            try:
                response = await self.request_handler.send_request(
                    method='POST',
                    url=graphql_url,
                    headers={
                        **target.custom_headers,
                        'Content-Type': 'application/json'
                    },
                    data=json.dumps(batch_queries),
                    proxy=target.proxy,
                    timeout=30.0
                )
                
                # If batch succeeds, batching may not be limited
                if response.status_code == 200:
                    vulnerabilities.append(APIVulnerability(
                        vulnerability_type='graphql_batch_attack',
                        severity='medium',
                        endpoint=graphql_url,
                        method='POST',
                        description='GraphQL query batching not limited',
                        evidence=[
                            f'Batch of {batch_size} queries was accepted',
                            'This can lead to DoS or rate limit bypass'
                        ],
                        remediation='Implement query batching limits'
                    ))
            
            except Exception:
                pass
        
        return vulnerabilities
    
    async def test_field_suggestions(
        self, target: TargetConfig, graphql_url: str
    ) -> List[APIVulnerability]:
        """Test if GraphQL provides field suggestions for typos
        
        Args:
            target: Target configuration
            graphql_url: GraphQL endpoint URL
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Query with intentional typo
        typo_query = '{ usrr { id } }'  # Typo: usrr instead of user
        
        try:
            response = await self.request_handler.send_request(
                method='POST',
                url=graphql_url,
                headers={
                    **target.custom_headers,
                    'Content-Type': 'application/json'
                },
                data=json.dumps({'query': typo_query}),
                proxy=target.proxy,
                timeout=10.0
            )
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.text)
                    if 'errors' in data:
                        for error in data['errors']:
                            message = error.get('message', '')
                            # Check if error message suggests field names
                            if 'did you mean' in message.lower() or 'suggestion' in message.lower():
                                vulnerabilities.append(APIVulnerability(
                                    vulnerability_type='graphql_field_suggestion',
                                    severity='low',
                                    endpoint=graphql_url,
                                    method='POST',
                                    description='GraphQL provides field suggestions',
                                    evidence=[
                                        'Error messages reveal field names',
                                        f'Example: {message}'
                                    ],
                                    remediation='Disable field suggestions in production'
                                ))
                                break
                except json.JSONDecodeError:
                    pass
        
        except Exception:
            pass
        
        return vulnerabilities


class APIVulnerabilityDetector:
    """Detect common API vulnerabilities"""
    
    def __init__(self, request_handler: RequestHandler):
        """Initialize API vulnerability detector
        
        Args:
            request_handler: RequestHandler instance for HTTP operations
        """
        self.request_handler = request_handler

    
    async def detect_excessive_data_exposure(
        self, target: TargetConfig, endpoint: APIEndpoint
    ) -> Optional[APIVulnerability]:
        """Detect excessive data exposure in API responses
        
        Args:
            target: Target configuration
            endpoint: API endpoint to test
            
        Returns:
            APIVulnerability if found, None otherwise
        """
        try:
            url = urljoin(target.url, endpoint.path)
            
            response = await self.request_handler.send_request(
                method=endpoint.method,
                url=url,
                headers=target.custom_headers,
                proxy=target.proxy,
                timeout=10.0
            )
            
            if response.status_code == 200:
                try:
                    data = json.loads(response.text)
                    
                    # Check for sensitive fields in response
                    sensitive_fields = [
                        'password', 'secret', 'token', 'api_key', 'private_key',
                        'ssn', 'credit_card', 'cvv', 'pin', 'salt', 'hash'
                    ]
                    
                    found_sensitive = []
                    self._find_sensitive_fields(data, sensitive_fields, found_sensitive)
                    
                    if found_sensitive:
                        return APIVulnerability(
                            vulnerability_type='excessive_data_exposure',
                            severity='high',
                            endpoint=url,
                            method=endpoint.method,
                            description='API response contains sensitive data',
                            evidence=[
                                f'Sensitive fields found: {", ".join(found_sensitive)}',
                                'API may be exposing more data than necessary'
                            ],
                            remediation='Filter sensitive fields from API responses',
                            metadata={'sensitive_fields': found_sensitive}
                        )
                
                except json.JSONDecodeError:
                    pass
        
        except Exception:
            pass
        
        return None
    
    def _find_sensitive_fields(
        self, data: Any, sensitive_fields: List[str], found: List[str], prefix: str = ''
    ) -> None:
        """Recursively find sensitive fields in data
        
        Args:
            data: Data to search
            sensitive_fields: List of sensitive field names
            found: List to append found fields to
            prefix: Current path prefix
        """
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{prefix}.{key}" if prefix else key
                
                # Check if key is sensitive
                key_lower = key.lower()
                for sensitive in sensitive_fields:
                    if sensitive in key_lower:
                        found.append(current_path)
                        break
                
                # Recurse into nested structures
                self._find_sensitive_fields(value, sensitive_fields, found, current_path)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{prefix}[{i}]"
                self._find_sensitive_fields(item, sensitive_fields, found, current_path)

    
    async def detect_mass_assignment(
        self, target: TargetConfig, endpoint: APIEndpoint
    ) -> Optional[APIVulnerability]:
        """Detect mass assignment vulnerabilities
        
        Args:
            target: Target configuration
            endpoint: API endpoint to test
            
        Returns:
            APIVulnerability if found, None otherwise
        """
        # Only test POST/PUT/PATCH endpoints
        if endpoint.method not in ['POST', 'PUT', 'PATCH']:
            return None
        
        try:
            url = urljoin(target.url, endpoint.path)
            
            # Test with additional privileged fields
            test_fields = {
                'is_admin': True,
                'role': 'admin',
                'is_verified': True,
                'is_active': True,
                'permissions': ['admin', 'write', 'delete'],
                'user_type': 'admin',
                'account_type': 'premium'
            }
            
            # Combine with any existing request body
            test_data = {}
            if endpoint.request_body_schema:
                # Add some valid fields based on schema
                test_data['name'] = 'test'
                test_data['email'] = 'test@example.com'
            
            # Add privileged fields
            test_data.update(test_fields)
            
            response = await self.request_handler.send_request(
                method=endpoint.method,
                url=url,
                headers={
                    **target.custom_headers,
                    'Content-Type': 'application/json'
                },
                data=json.dumps(test_data),
                proxy=target.proxy,
                timeout=10.0
            )
            
            # If request succeeds, check if privileged fields were accepted
            if 200 <= response.status_code < 300:
                try:
                    response_data = json.loads(response.text)
                    
                    # Check if any privileged fields appear in response
                    accepted_fields = []
                    for field in test_fields.keys():
                        if self._field_in_response(field, response_data):
                            accepted_fields.append(field)
                    
                    if accepted_fields:
                        return APIVulnerability(
                            vulnerability_type='mass_assignment',
                            severity='high',
                            endpoint=url,
                            method=endpoint.method,
                            description='API may be vulnerable to mass assignment',
                            evidence=[
                                f'Privileged fields accepted: {", ".join(accepted_fields)}',
                                'API may not be filtering input fields properly'
                            ],
                            remediation='Implement input field whitelisting',
                            metadata={'accepted_fields': accepted_fields}
                        )
                
                except json.JSONDecodeError:
                    pass
        
        except Exception:
            pass
        
        return None
    
    def _field_in_response(self, field: str, data: Any) -> bool:
        """Check if field exists in response data
        
        Args:
            field: Field name to search for
            data: Response data
            
        Returns:
            True if field found, False otherwise
        """
        if isinstance(data, dict):
            if field in data:
                return True
            for value in data.values():
                if self._field_in_response(field, value):
                    return True
        elif isinstance(data, list):
            for item in data:
                if self._field_in_response(field, item):
                    return True
        
        return False

    
    async def detect_rate_limiting(
        self, target: TargetConfig, endpoint: APIEndpoint, num_requests: int = 50
    ) -> Optional[APIVulnerability]:
        """Detect lack of rate limiting
        
        Args:
            target: Target configuration
            endpoint: API endpoint to test
            num_requests: Number of requests to send
            
        Returns:
            APIVulnerability if rate limiting is missing, None otherwise
        """
        try:
            url = urljoin(target.url, endpoint.path)
            
            # Send multiple requests rapidly
            tasks = []
            for _ in range(num_requests):
                task = self.request_handler.send_request(
                    method=endpoint.method,
                    url=url,
                    headers=target.custom_headers,
                    proxy=target.proxy,
                    timeout=10.0
                )
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Count successful responses
            successful = 0
            rate_limited = 0
            
            for response in responses:
                if isinstance(response, Exception):
                    continue
                
                if 200 <= response.status_code < 300:
                    successful += 1
                elif response.status_code == 429:  # Too Many Requests
                    rate_limited += 1
            
            # If most requests succeeded, rate limiting may be missing
            if successful > num_requests * 0.8:  # 80% success rate
                return APIVulnerability(
                    vulnerability_type='missing_rate_limiting',
                    severity='medium',
                    endpoint=url,
                    method=endpoint.method,
                    description='API endpoint lacks rate limiting',
                    evidence=[
                        f'{successful}/{num_requests} requests succeeded',
                        'No rate limiting detected',
                        'API may be vulnerable to brute force or DoS attacks'
                    ],
                    remediation='Implement rate limiting on API endpoints',
                    metadata={
                        'successful_requests': successful,
                        'total_requests': num_requests
                    }
                )
        
        except Exception:
            pass
        
        return None


class APITestingModule:
    """Main API testing module combining all API testing capabilities"""
    
    def __init__(self, request_handler: RequestHandler):
        """Initialize API testing module
        
        Args:
            request_handler: RequestHandler instance for HTTP operations
        """
        self.request_handler = request_handler
        self.rest_discovery = RESTAPIDiscovery(request_handler)
        self.graphql_testing = GraphQLTesting(request_handler)
        self.vulnerability_detector = APIVulnerabilityDetector(request_handler)
    
    async def test_rest_api(self, target: TargetConfig) -> Dict[str, Any]:
        """Comprehensive REST API testing
        
        Args:
            target: Target configuration
            
        Returns:
            Dictionary containing test results
        """
        results = {
            'openapi_spec': None,
            'endpoints': [],
            'vulnerabilities': []
        }
        
        # Discover OpenAPI spec
        openapi_spec = await self.rest_discovery.discover_openapi_spec(target)
        if openapi_spec:
            results['openapi_spec'] = {
                'url': openapi_spec.url,
                'version': openapi_spec.version,
                'title': openapi_spec.title,
                'description': openapi_spec.description,
                'endpoints_count': len(openapi_spec.endpoints)
            }
            results['endpoints'] = [
                {
                    'path': ep.path,
                    'method': ep.method,
                    'description': ep.description,
                    'requires_auth': ep.requires_auth
                }
                for ep in openapi_spec.endpoints
            ]
            
            # Test endpoints for vulnerabilities
            auth_vulns = await self.rest_discovery.test_endpoints_for_auth_bypass(
                target, openapi_spec.endpoints
            )
            results['vulnerabilities'].extend([v.__dict__ for v in auth_vulns])
            
            # Test for other vulnerabilities
            for endpoint in openapi_spec.endpoints[:10]:  # Limit to first 10 endpoints
                # Test excessive data exposure
                vuln = await self.vulnerability_detector.detect_excessive_data_exposure(
                    target, endpoint
                )
                if vuln:
                    results['vulnerabilities'].append(vuln.__dict__)
                
                # Test mass assignment
                vuln = await self.vulnerability_detector.detect_mass_assignment(
                    target, endpoint
                )
                if vuln:
                    results['vulnerabilities'].append(vuln.__dict__)
                
                # Test rate limiting
                vuln = await self.vulnerability_detector.detect_rate_limiting(
                    target, endpoint, num_requests=20
                )
                if vuln:
                    results['vulnerabilities'].append(vuln.__dict__)
        
        return results

    
    async def test_graphql_api(self, target: TargetConfig) -> Dict[str, Any]:
        """Comprehensive GraphQL API testing
        
        Args:
            target: Target configuration
            
        Returns:
            Dictionary containing test results
        """
        results = {
            'graphql_endpoint': None,
            'schema': None,
            'vulnerabilities': []
        }
        
        # Detect GraphQL endpoint
        graphql_url = await self.graphql_testing.detect_graphql_endpoint(target)
        if graphql_url:
            results['graphql_endpoint'] = graphql_url
            
            # Execute introspection
            schema = await self.graphql_testing.execute_introspection(target, graphql_url)
            if schema:
                results['schema'] = {
                    'url': schema.url,
                    'queries_count': len(schema.queries),
                    'mutations_count': len(schema.mutations),
                    'types_count': len(schema.types)
                }
                
                # Test query depth limits
                depth_vulns = await self.graphql_testing.test_query_depth_limits(
                    target, graphql_url, schema
                )
                results['vulnerabilities'].extend([v.__dict__ for v in depth_vulns])
                
                # Test query batching
                batch_vulns = await self.graphql_testing.test_query_batching(
                    target, graphql_url, schema
                )
                results['vulnerabilities'].extend([v.__dict__ for v in batch_vulns])
            
            # Test field suggestions
            suggestion_vulns = await self.graphql_testing.test_field_suggestions(
                target, graphql_url
            )
            results['vulnerabilities'].extend([v.__dict__ for v in suggestion_vulns])
        
        return results
    
    async def comprehensive_api_test(self, target: TargetConfig) -> Dict[str, Any]:
        """Run comprehensive API testing (REST + GraphQL)
        
        Args:
            target: Target configuration
            
        Returns:
            Dictionary containing all test results
        """
        results = {
            'rest_api': await self.test_rest_api(target),
            'graphql_api': await self.test_graphql_api(target)
        }
        
        return results
