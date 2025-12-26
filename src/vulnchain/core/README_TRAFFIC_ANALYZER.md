# Traffic Analyzer Module

## Overview

The Traffic Analyzer module provides behavioral modeling, anomaly detection, and attack optimization through traffic pattern analysis and recognition. It observes HTTP traffic to build models of normal application behavior, detect anomalies, and provide recommendations for optimizing attack strategies.

**Validates Requirements:** 49.1, 49.2, 49.3, 49.4, 49.5

## Features

### 1. Behavioral Modeling (Requirement 49.1)

Build comprehensive models of normal application behavior by observing traffic patterns:

- **Endpoint Discovery**: Identify and classify all endpoints (static, dynamic, API, authentication, hidden)
- **Request Sequences**: Detect common sequences of requests
- **Parameter Patterns**: Map parameters used with each endpoint
- **Timing Patterns**: Calculate typical response times for each endpoint
- **State Machines**: Build state transition models from observed flows
- **Authentication Flows**: Identify multi-step authentication sequences

### 2. Hidden Endpoint & Rate Limit Detection (Requirement 49.2)

Identify hidden functionality and anti-automation measures:

- **Hidden Endpoints**: Detect infrequently accessed or debug/admin endpoints
- **Rate Limiting**: Identify rate limit patterns and extract limit information
- **Anti-Automation**: Detect CAPTCHAs, bot detection, WAF presence, and JavaScript challenges

### 3. Anomaly Detection (Requirement 49.3)

Detect unusual patterns that may indicate successful exploitation:

- **Unknown Endpoints**: Flag requests to previously unseen endpoints
- **Timing Anomalies**: Detect response times that deviate significantly from normal
- **Status Code Anomalies**: Identify unusual status codes for known endpoints
- **State Transition Violations**: Detect unexpected state transitions

### 4. Attack Optimization (Requirements 49.4, 49.5)

Optimize attack strategies based on traffic analysis:

- **Optimal Timing**: Calculate recommended delays and burst sizes
- **Request Ordering**: Determine optimal sequence for attack requests
- **Bypass Opportunities**: Identify authentication/authorization bypass opportunities
- **Multi-Step Flows**: Map authentication and business logic flows
- **Rate Limit Evasion**: Provide strategies to work within rate limits

## Usage

### Basic Usage

```python
from app.core.traffic_analyzer import TrafficAnalyzer
from app.core.http_models import Request, Response

# Initialize analyzer
analyzer = TrafficAnalyzer(learning_window=100)

# Observe traffic
for request, response in traffic_pairs:
    analyzer.observe_traffic(request, response)

# Build behavioral model
model = analyzer.build_behavioral_model()

# Detect anomalies
anomalies = analyzer.detect_anomalies(recent_window=20)

# Optimize attack strategy
optimization = analyzer.optimize_attack_strategy()
```

### Building Behavioral Models

```python
# Observe traffic during normal operation
for i in range(100):
    request, response = make_request(...)
    analyzer.observe_traffic(request, response)

# Build model
model = analyzer.build_behavioral_model()

print(f"Known endpoints: {len(model.known_endpoints)}")
print(f"Common sequences: {model.common_sequences}")
print(f"Auth flows: {model.auth_flows}")
print(f"Rate limits: {model.rate_limits}")
```

### Identifying Hidden Endpoints

```python
# After building model
hidden = analyzer.identify_hidden_endpoints()

for endpoint in hidden:
    print(f"Hidden endpoint discovered: {endpoint}")
```

### Detecting Rate Limiting

```python
rate_limits = analyzer.detect_rate_limiting()

for endpoint, info in rate_limits.items():
    if info['detected']:
        print(f"Rate limit on {endpoint}:")
        print(f"  Retry after: {info['retry_after']}")
        print(f"  Limit info: {info['limit_info']}")
```

### Detecting Anomalies

```python
# Build model first
model = analyzer.build_behavioral_model()

# Continue observing traffic
for request, response in new_traffic:
    analyzer.observe_traffic(request, response)

# Detect anomalies in recent traffic
anomalies = analyzer.detect_anomalies(recent_window=20)

for anomaly in anomalies:
    print(f"Anomaly detected: {anomaly.anomaly_type}")
    print(f"  Severity: {anomaly.severity}")
    print(f"  Description: {anomaly.description}")
    print(f"  Suggested action: {anomaly.suggested_action}")
```

### Optimizing Attack Strategy

```python
# After building model
optimization = analyzer.optimize_attack_strategy()

print(f"Recommended delay: {optimization.optimal_timing['recommended_delay']}s")
print(f"Burst size: {optimization.optimal_timing['burst_size']}")
print(f"Request ordering: {optimization.request_ordering}")

# Use bypass opportunities
for opportunity in optimization.bypass_opportunities:
    print(f"Bypass opportunity: {opportunity['type']}")
    print(f"  Strategy: {opportunity['bypass_strategy']}")
```

### Mapping Authentication Flows

```python
auth_flows = analyzer.map_authentication_flows()

for i, flow in enumerate(auth_flows):
    print(f"Authentication flow {i+1}: {' -> '.join(flow)}")
```

## Data Models

### BehavioralModel

Represents a model of normal application behavior:

```python
@dataclass
class BehavioralModel:
    model_id: str
    created_at: datetime
    updated_at: datetime
    known_endpoints: Set[str]
    endpoint_types: Dict[str, EndpointType]
    common_sequences: List[List[str]]
    parameter_patterns: Dict[str, Set[str]]
    typical_response_times: Dict[str, Tuple[float, float]]
    rate_limits: Dict[str, Dict[str, Any]]
    anti_automation_indicators: List[str]
    state_machine: Dict[str, Set[str]]
    auth_flows: List[List[str]]
    total_requests: int
    observation_period: timedelta
```

### TrafficAnomaly

Represents an anomalous traffic pattern:

```python
@dataclass
class TrafficAnomaly:
    anomaly_id: str
    anomaly_type: str  # "unknown_endpoint", "timing_anomaly", "status_code_anomaly", "state_transition_violation"
    severity: str  # "low", "medium", "high", "critical"
    description: str
    detected_at: datetime
    request: Optional[Request]
    response: Optional[Response]
    deviation_score: float
    suggested_action: Optional[str]
```

### AttackOptimization

Optimization recommendations for attack execution:

```python
@dataclass
class AttackOptimization:
    optimal_timing: Dict[str, Any]
    request_ordering: List[str]
    bypass_opportunities: List[Dict[str, Any]]
    multi_step_flows: List[List[str]]
    rate_limit_info: Dict[str, Any]
    confidence: float
```

## Advanced Usage

### Custom Learning Window

```python
# Use larger window for more stable models
analyzer = TrafficAnalyzer(learning_window=500)
```

### Endpoint Classification

The analyzer automatically classifies endpoints into types:

- **STATIC**: Static resources (.js, .css, images)
- **DYNAMIC**: Regular dynamic pages
- **API**: API endpoints (/api/*)
- **AUTHENTICATION**: Login/auth endpoints
- **HIDDEN**: Debug/admin/test endpoints

### State Machine Analysis

```python
model = analyzer.build_behavioral_model()

# Examine state transitions
for state, next_states in model.state_machine.items():
    print(f"From {state}, can transition to:")
    for next_state in next_states:
        print(f"  - {next_state}")
```

### Traffic Summary

```python
summary = analyzer.get_traffic_summary()

print(f"Total requests: {summary['total_requests']}")
print(f"Unique endpoints: {summary['unique_endpoints']}")
print(f"Anomalies detected: {summary['anomalies_detected']}")

for endpoint, stats in summary['endpoint_stats'].items():
    print(f"{endpoint}:")
    print(f"  Count: {stats['count']}")
    print(f"  Avg time: {stats['avg_time']:.3f}s")
    print(f"  Status codes: {stats['status_codes']}")
```

## Integration with Attack Modules

### Using with Fuzzing

```python
# Build model during reconnaissance
analyzer = TrafficAnalyzer()
# ... observe normal traffic ...
model = analyzer.build_behavioral_model()

# Get optimization for fuzzing
optimization = analyzer.optimize_attack_strategy()

# Use optimal timing
delay = optimization.optimal_timing['recommended_delay']
burst_size = optimization.optimal_timing['burst_size']

# Fuzz with optimized parameters
for payload in payloads:
    # Send burst
    for i in range(burst_size):
        send_payload(payload)
    time.sleep(delay)
```

### Using with Authentication Testing

```python
# Map authentication flows
auth_flows = analyzer.map_authentication_flows()

# Test bypass opportunities
optimization = analyzer.optimize_attack_strategy()
for opportunity in optimization.bypass_opportunities:
    if opportunity['type'] == 'multi_step_auth':
        # Try accessing later steps directly
        endpoints = opportunity['endpoints']
        for endpoint in endpoints[1:]:  # Skip first step
            test_direct_access(endpoint)
```

### Using with Timing Attacks

```python
# Build model to understand normal timing
model = analyzer.build_behavioral_model()

# Get typical timings for endpoint
endpoint = "/api/login"
if endpoint in model.typical_response_times:
    mean, stddev = model.typical_response_times[endpoint]
    
    # Use for timing attack detection
    response = send_timing_payload(endpoint)
    if response.elapsed_time > mean + (3 * stddev):
        print("Timing attack may have succeeded!")
```

## Best Practices

1. **Build Model First**: Always build a behavioral model before detecting anomalies or optimizing attacks
2. **Sufficient Data**: Collect at least 50-100 requests before building a model for accuracy
3. **Update Models**: Rebuild models periodically as application behavior may change
4. **Monitor Anomalies**: Continuously monitor for anomalies during attack execution
5. **Respect Rate Limits**: Use detected rate limit information to avoid detection
6. **Test Bypass Opportunities**: Systematically test all identified bypass opportunities

## Performance Considerations

- The analyzer maintains a sliding window of traffic history (default: 2x learning_window)
- Endpoint normalization replaces IDs and UUIDs with placeholders to reduce unique endpoints
- State machine building is O(n) where n is the number of requests
- Anomaly detection is O(m) where m is the recent window size

## Error Handling

```python
try:
    model = analyzer.build_behavioral_model()
except ValueError as e:
    print(f"Cannot build model: {e}")
    # Need more traffic data

try:
    anomalies = analyzer.detect_anomalies()
except ValueError as e:
    print(f"Cannot detect anomalies: {e}")
    # Need to build model first
```

## Testing

The module includes comprehensive functionality for:
- Building behavioral models from observed traffic
- Detecting various types of anomalies
- Optimizing attack strategies
- Mapping authentication flows
- Identifying hidden endpoints and rate limits

All functionality is validated against requirements 49.1-49.5.
