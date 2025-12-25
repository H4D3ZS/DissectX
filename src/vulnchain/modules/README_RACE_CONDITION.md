# Race Condition Module

## Overview

The Race Condition module provides automated testing for race condition and TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities. It implements microsecond-level timing control for concurrent request sending and adaptive strategies to maximize collision probability.

## Features

- **Microsecond Timing Control**: Send concurrent requests with precise timing
- **Multiple Timing Strategies**: Simultaneous, staggered, adaptive, burst, and synchronized
- **TOCTOU Detection**: Identify time-of-check-time-of-use vulnerabilities
- **Duplicate Transaction Detection**: Find duplicate processing vulnerabilities
- **State Inconsistency Detection**: Detect inconsistent application states
- **Exploit Generation**: Generate repeatable exploits with optimal parameters

## Race Condition Types

### TOCTOU (Time-of-Check-Time-of-Use)
Vulnerabilities where a check is performed before an operation, but the state can change between the check and the use.

### Duplicate Transaction
Vulnerabilities where the same transaction can be processed multiple times due to race conditions.

### Privilege Escalation
Race conditions that allow privilege escalation through concurrent requests.

### State Inconsistency
Race conditions that cause inconsistent application state.

## Timing Strategies

### Simultaneous
Send all requests at once using asyncio for maximum concurrency.

### Staggered
Send requests with small microsecond-level delays between them.

### Adaptive
Adapt timing based on response patterns - starts simultaneous, then adjusts.

### Burst
Send requests in bursts with delays between bursts.

### Synchronized
Use thread barriers to synchronize all threads before sending, maximizing collision probability.

## Usage Example

```python
from app.modules.race_condition import (
    RaceConditionTester,
    RaceConditionTest,
    TimingStrategy,
)
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
tester = RaceConditionTester(request_handler, max_workers=50)

# Configure test
test = RaceConditionTest(
    url="https://example.com/api/transfer",
    method="POST",
    headers={"Content-Type": "application/json"},
    data={"from": "user1", "to": "user2", "amount": 100},
    num_requests=20,
    timing_strategy=TimingStrategy.SYNCHRONIZED,
)

# Run test
result = await tester.test_race_condition(test)

if result.is_vulnerable:
    print(f"Race condition found: {result.race_type}")
    print(f"Confidence: {result.confidence}")
    print(f"Evidence: {result.evidence}")
    
    # Get exploit parameters
    if result.exploit_params:
        print(f"Optimal threads: {result.exploit_params.num_threads}")
        print(f"Success rate: {result.exploit_params.success_rate}")
        print(f"Exploit code:\n{result.exploit_params.exploit_code}")
```

## Custom Check Functions

You can provide custom check functions to detect specific race conditions:

```python
def check_balance_inconsistency(responses):
    """Check if balance is inconsistent across responses"""
    balances = []
    for response in responses:
        if response.status_code == 200:
            # Extract balance from response
            import json
            data = json.loads(response.text)
            if "balance" in data:
                balances.append(data["balance"])
    
    # If balances differ, we have a race condition
    return len(set(balances)) > 1

test = RaceConditionTest(
    url="https://example.com/api/balance",
    method="GET",
    num_requests=10,
    check_function=check_balance_inconsistency,
)
```

## Timing Data

The module provides detailed timing data for analysis:

```python
result = await tester.test_race_condition(test)

timing = result.timing_data
print(f"Strategy: {timing['strategy']}")
print(f"Total time: {timing['total_time']}")
print(f"Time spread: {timing['time_spread']}")  # How close requests were
print(f"Avg response time: {timing['avg_response_time']}")
```

## Exploit Parameters

When a vulnerability is found, optimal exploit parameters are generated:

```python
if result.exploit_params:
    params = result.exploit_params
    
    print(f"Optimal threads: {params.num_threads}")
    print(f"Timing strategy: {params.timing_strategy}")
    print(f"Success rate: {params.success_rate * 100:.1f}%")
    print(f"Avg collision time: {params.avg_collision_time * 1000:.2f}ms")
    print(f"Recommended attempts: {params.recommended_attempts}")
    
    # Save exploit code
    with open("exploit.py", "w") as f:
        f.write(params.exploit_code)
```

## Detection Indicators

The module looks for several indicators of race conditions:

1. **Multiple Successful Responses**: More than one 2xx response
2. **Inconsistent Status Codes**: Mix of success and failure
3. **Response Body Variations**: Different response content
4. **State Keywords**: Balance, credit, amount, quantity, etc.
5. **Error Patterns**: Deadlock, lock timeout, concurrent, duplicate, conflict

## Best Practices

1. **Start with Synchronized Strategy**: Provides best collision probability
2. **Use Sufficient Threads**: At least 10-20 concurrent requests
3. **Multiple Attempts**: Run the test multiple times for consistency
4. **Custom Checks**: Implement domain-specific checks for your target
5. **Monitor Server Load**: Be careful not to overwhelm the target

## Requirements Validation

This module validates the following requirements:

- **Requirement 37.1**: Send concurrent requests with microsecond-level timing control
- **Requirement 37.2**: Test for TOCTOU vulnerabilities by interleaving requests
- **Requirement 37.3**: Use adaptive timing strategies to maximize collision probability
- **Requirement 37.4**: Provide repeatable exploit with optimal parameters
- **Requirement 37.5**: Monitor for inconsistent states and duplicate transactions

## Technical Details

### Thread Synchronization

The synchronized strategy uses Python's `threading.Barrier` to ensure all threads start simultaneously:

```python
barrier = threading.Barrier(num_threads)

def synchronized_request():
    barrier.wait()  # All threads wait here
    # All threads proceed together
    send_request()
```

### Microsecond Timing

Timing is measured using `time.time()` which provides microsecond precision on most systems:

```python
start_time = time.time()
response = await send_request()
end_time = time.time()
elapsed_microseconds = (end_time - start_time) * 1_000_000
```

### Adaptive Strategy

The adaptive strategy analyzes initial results and adjusts:

1. Start with simultaneous requests
2. Check for response variation
3. If no variation, switch to batched approach
4. Adjust batch size based on results

## Limitations

- Maximum workers limited by system resources
- Network latency affects timing precision
- Some race conditions require specific server states
- Thread synchronization has overhead (~1-10ms)

## Future Enhancements

- Support for WebSocket race conditions
- Database-level race condition detection
- Distributed race condition testing across multiple machines
- Machine learning for optimal timing prediction
