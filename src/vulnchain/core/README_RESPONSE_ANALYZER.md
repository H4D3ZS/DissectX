# Response Analyzer Module

## Overview

The Response Analyzer module provides comprehensive response comparison, diff analysis, and statistical timing analysis capabilities for identifying subtle differences that indicate successful exploitation in blind vulnerabilities.

## Features

### 1. Response Comparison (Requirements 28.1, 28.2)

- **Baseline Capture**: Store baseline responses for comparison
- **Similarity Scoring**: Compute similarity scores based on:
  - Status codes
  - Content length
  - Headers
  - Body content
- **Detailed Comparison**: Generate comprehensive comparison results including:
  - Similarity score (0.0 to 1.0)
  - Length differences
  - Header differences
  - Body diffs
  - Anomaly detection

### 2. Visual Diff Display (Requirement 28.3)

- **Multiple Formats**: Support for unified, context, and HTML diff formats
- **Highlighted Differences**: Clear visualization of response differences
- **Configurable Context**: Adjustable context lines for diff output

### 3. Statistical Timing Analysis (Requirements 28.4, 28.5)

- **Timing Statistics**: Compute mean, median, standard deviation, min/max
- **Outlier Detection**: Identify timing anomalies using configurable sigma thresholds
- **Blind Vulnerability Detection**: Flag responses with timing differences indicating successful exploitation
- **Configurable Thresholds**: Adjust sensitivity for anomaly detection

## Usage Examples

### Basic Response Comparison

```python
from app.core.response_analyzer import ResponseAnalyzer
from app.core.http_models import Response

# Initialize analyzer
analyzer = ResponseAnalyzer(
    anomaly_threshold=0.15,  # Flag responses with <85% similarity
    timing_threshold_sigma=2.0  # Flag timings >2 std devs from mean
)

# Capture baseline response
baseline_response = # ... get response
analyzer.capture_baseline(baseline_response, label="normal")

# Compare subsequent responses
test_response = # ... get test response
comparison = analyzer.compare_responses(
    baseline_response,
    test_response
)

print(f"Similarity: {comparison.similarity_score:.2%}")
print(f"Length diff: {comparison.length_difference} bytes")
print(f"Is anomaly: {comparison.is_anomaly}")
```

### Visual Diff Generation

```python
# Generate unified diff
unified_diff = analyzer.generate_visual_diff(
    baseline_response,
    test_response,
    format="unified"
)
print(unified_diff)

# Generate HTML diff for web display
html_diff = analyzer.generate_visual_diff(
    baseline_response,
    test_response,
    format="html"
)
# Save or display html_diff
```

### Timing Analysis for Blind SQLi

```python
# Test for time-based blind SQL injection
responses = []

# Send baseline requests
for _ in range(10):
    response = await send_request("GET", f"{url}?id=1")
    analyzer.add_response_timing(response)
    responses.append(response)

# Send payload with time delay
payload_response = await send_request(
    "GET",
    f"{url}?id=1' AND SLEEP(5)--"
)
analyzer.add_response_timing(payload_response)
responses.append(payload_response)

# Analyze timing statistics
stats = analyzer.analyze_timing_statistics()
print(f"Mean: {stats.mean:.3f}s")
print(f"Std Dev: {stats.std_dev:.3f}s")
print(f"Threshold: {stats.threshold:.3f}s")
print(f"Outliers: {len(stats.outliers)}")

# Detect anomalies
anomalies = analyzer.detect_timing_anomalies()
if anomalies:
    print("Timing anomaly detected - possible blind SQLi!")
    for response in anomalies:
        print(f"  - {response.elapsed_time:.3f}s")
```

### Batch Anomaly Detection

```python
# Capture baseline
baseline = analyzer.capture_baseline(normal_response, "baseline")

# Test multiple payloads
test_responses = []
for payload in payloads:
    response = await send_request("POST", url, data={"input": payload})
    test_responses.append(response)

# Flag all anomalies
anomalies = analyzer.flag_anomalies(
    test_responses,
    baseline_label="baseline",
    threshold=0.20  # Custom threshold
)

for response, comparison in anomalies:
    print(f"Anomaly detected:")
    print(f"  Payload: {response.request.data}")
    print(f"  Similarity: {comparison.similarity_score:.2%}")
    print(f"  Length diff: {comparison.length_difference}")
    
    # Show diff
    if comparison.body_diff:
        print("  Diff:")
        for line in comparison.body_diff[:10]:  # First 10 lines
            print(f"    {line}")
```

### Header Difference Analysis

```python
comparison = analyzer.compare_responses(baseline, test_response)

if comparison.header_differences:
    print("Header differences detected:")
    for header, (val1, val2) in comparison.header_differences.items():
        print(f"  {header}:")
        print(f"    Baseline: {val1}")
        print(f"    Current:  {val2}")
```

## Configuration

### Anomaly Threshold

The `anomaly_threshold` parameter controls sensitivity for flagging anomalous responses:

- **0.05** (5% difference): Very sensitive - flags minor differences
- **0.15** (15% difference): Default - balanced sensitivity
- **0.30** (30% difference): Less sensitive - only major differences

### Timing Threshold Sigma

The `timing_threshold_sigma` parameter controls timing anomaly detection:

- **1.0**: Very sensitive - flags responses >1 std dev from mean
- **2.0**: Default - flags responses >2 std devs from mean (95% confidence)
- **3.0**: Less sensitive - flags responses >3 std devs from mean (99.7% confidence)

## Integration with Attack Modules

### SQL Injection Module

```python
# In sql_injection.py
from app.core.response_analyzer import ResponseAnalyzer

async def test_blind_sqli(url, param):
    analyzer = ResponseAnalyzer(timing_threshold_sigma=2.0)
    
    # Establish baseline
    for _ in range(5):
        response = await send_request("GET", f"{url}?{param}=1")
        analyzer.add_response_timing(response)
    
    # Test time-based payload
    response = await send_request(
        "GET",
        f"{url}?{param}=1' AND SLEEP(5)--"
    )
    analyzer.add_response_timing(response)
    
    # Check for timing anomaly
    anomalies = analyzer.detect_timing_anomalies()
    return len(anomalies) > 0
```

### Fuzzing Module

```python
# In fuzzing module
async def fuzz_with_comparison(url, payloads):
    analyzer = ResponseAnalyzer(anomaly_threshold=0.10)
    
    # Capture baseline
    baseline = await send_request("GET", url)
    analyzer.capture_baseline(baseline)
    
    # Fuzz and compare
    interesting_responses = []
    for payload in payloads:
        response = await send_request("GET", f"{url}?input={payload}")
        comparison = analyzer.compare_responses(baseline, response)
        
        if comparison.is_anomaly:
            interesting_responses.append((payload, response, comparison))
    
    return interesting_responses
```

## API Reference

### ResponseAnalyzer

#### Constructor

```python
ResponseAnalyzer(
    anomaly_threshold: float = 0.15,
    timing_threshold_sigma: float = 2.0
)
```

#### Methods

- `capture_baseline(response, label="baseline")` - Store baseline response
- `get_baseline(label)` - Retrieve stored baseline
- `compute_similarity_score(response1, response2)` - Calculate similarity (0.0-1.0)
- `compare_responses(response1, response2, threshold=None)` - Detailed comparison
- `generate_visual_diff(response1, response2, format="unified")` - Generate diff
- `add_response_timing(response)` - Add response to timing history
- `analyze_timing_statistics(responses=None, threshold_sigma=None)` - Compute timing stats
- `detect_timing_anomalies(responses=None, threshold_sigma=None)` - Find timing outliers
- `flag_anomalies(responses, baseline_label, threshold=None)` - Flag anomalous responses
- `clear_history()` - Clear response history
- `clear_baselines()` - Clear stored baselines

### Data Classes

#### ResponseComparison

```python
@dataclass
class ResponseComparison:
    similarity_score: float
    length_difference: int
    status_code_match: bool
    header_differences: Dict[str, Tuple[Optional[str], Optional[str]]]
    body_diff: List[str]
    is_anomaly: bool
```

#### TimingStatistics

```python
@dataclass
class TimingStatistics:
    mean: float
    median: float
    std_dev: float
    min_time: float
    max_time: float
    outliers: List[Tuple[float, Response]]
    threshold: float
```

## Testing

The module includes comprehensive unit tests covering:

- Baseline capture and retrieval
- Similarity score computation
- Response comparison
- Visual diff generation
- Timing statistics analysis
- Anomaly detection

Run tests with:

```bash
pytest backend/tests/test_response_analyzer.py -v
```

## Performance Considerations

- **Memory**: Baselines and response history are stored in memory. Clear periodically for long-running sessions.
- **Diff Generation**: Large responses may take time to diff. Consider truncating very large bodies.
- **Timing Analysis**: Requires multiple samples for accurate statistics (minimum 5-10 recommended).

## Future Enhancements

- Machine learning-based anomaly detection
- Response clustering for pattern identification
- Automatic baseline selection
- Persistent baseline storage
- Real-time streaming diff display
