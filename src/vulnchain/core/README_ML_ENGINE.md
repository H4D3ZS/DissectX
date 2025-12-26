# ML Engine

## Overview

The ML Engine provides machine learning capabilities for vulnerability prediction, error message analysis, attack vector ranking, and adaptive learning from attack attempts. This implementation uses rule-based heuristics and pattern matching to simulate ML behavior without requiring trained models.

## Requirements

- **36.1**: Predict vulnerability classes based on technology stack and response patterns
- **36.2**: Extract hints from error messages using NLP-like analysis
- **36.3**: Rank attack vectors by exploitation probability and time-to-flag
- **36.4**: Learn from failed attempts
- **36.5**: Dynamically adjust attack strategy

## Features

### 1. Vulnerability Prediction

Predicts likely vulnerabilities based on:
- Detected technologies and frameworks
- Server software and CMS
- Response patterns and error messages
- Historical success patterns

Supported vulnerability types:
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- SSRF (Server-Side Request Forgery)
- XXE (XML External Entity)
- SSTI (Server-Side Template Injection)
- JWT Manipulation
- Deserialization
- NoSQL Injection
- Prototype Pollution
- GraphQL vulnerabilities
- API vulnerabilities

### 2. Error Message Analysis

Analyzes error messages to extract:
- Error type (SQL, PHP, Python, Java, Command, Template, XML, NoSQL)
- Hints about vulnerable code paths
- Suggested exploits
- Extracted information (file paths, line numbers, table names, etc.)

### 3. Attack Vector Ranking

Ranks attack vectors by:
- Exploitation probability (based on historical success)
- Estimated time-to-flag
- Complexity (low, medium, high)
- Technology match with target

### 4. Adaptive Learning

Learns from attack attempts to:
- Track successful and failed patterns
- Adjust exploitation probability
- Recommend alternative strategies
- Detect WAF and rate limiting
- Suggest payload variations

## Usage

### Basic Usage

```python
from app.core.ml_engine import MLEngine, TargetInfo, AttackVector, AttackAttempt, AttackResult
from datetime import datetime

# Initialize the engine
ml_engine = MLEngine()

# Create target information
target_info = TargetInfo(
    url="https://example.com",
    technologies=["PHP", "MySQL", "Apache"],
    frameworks=["WordPress"],
    server_software="Apache/2.4.41",
    response_headers={"X-Powered-By": "PHP/7.4.3"},
    error_messages=["Warning: mysql_fetch_array() expects parameter 1"],
    detected_cms="wordpress",
    detected_language="php"
)

# Predict vulnerabilities
predictions = ml_engine.predict_vulnerabilities(target_info)
for pred in predictions:
    print(f"{pred.vulnerability_type}: {pred.confidence:.2f} - {pred.reasoning}")
```

### Error Analysis

```python
# Analyze an error message
error = "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/login.php on line 42"
analysis = ml_engine.analyze_error_message(error)

print(f"Error Type: {analysis.error_type}")
print(f"Confidence: {analysis.confidence:.2f}")
print(f"Hints: {', '.join(analysis.hints)}")
print(f"Suggested Exploits: {', '.join(analysis.suggested_exploits)}")
print(f"Extracted Info: {analysis.extracted_info}")
```

### Attack Vector Ranking

```python
# Create attack vectors
vectors = [
    AttackVector(
        module_name="sql_injection",
        vulnerability_type="sql_injection",
        description="Test for SQL injection",
        estimated_time=120.0,
        complexity="medium"
    ),
    AttackVector(
        module_name="xss",
        vulnerability_type="xss",
        description="Test for XSS",
        estimated_time=60.0,
        complexity="low"
    )
]

# Rank vectors
context = {"technologies": ["PHP", "MySQL"]}
ranked = ml_engine.rank_attack_vectors(vectors, context)

for r in ranked:
    print(f"Rank {r.rank}: {r.vector.module_name}")
    print(f"  Probability: {r.exploitation_probability:.2f}")
    print(f"  Time to Flag: {r.time_to_flag:.1f}s")
    print(f"  Score: {r.score:.2f}")
```

### Adaptive Learning

```python
# Record an attack attempt
attempt = AttackAttempt(
    module_name="sql_injection",
    vulnerability_type="sql_injection",
    target_url="https://example.com/login",
    payload="' OR '1'='1",
    timestamp=datetime.now(),
    parameters={"username": "admin"}
)

result = AttackResult(
    success=True,
    vulnerability_found=True,
    response_time=0.5,
    status_code=200,
    flags_found=["CTF{sql_injection_success}"]
)

# Learn from the attempt
ml_engine.learn_from_attempt(attempt, result)

# Get adaptive strategy for future attempts
strategy = ml_engine.get_adaptive_strategy(
    "https://example.com/login",
    "sql_injection"
)
print(f"Strategy: {strategy['strategy']}")
print(f"Recommendations: {', '.join(strategy['recommendations'])}")
```

### Persistence

```python
# Export learning data
learning_data = ml_engine.export_learning_data()
with open("ml_learning_data.json", "w") as f:
    json.dump(learning_data, f)

# Import learning data
with open("ml_learning_data.json", "r") as f:
    learning_data = json.load(f)
ml_engine.import_learning_data(learning_data)
```

## Data Models

### TargetInfo
Information about a target for vulnerability prediction.

### VulnerabilityPrediction
Prediction of a vulnerability class with confidence and reasoning.

### ErrorAnalysis
Analysis of an error message with hints and suggested exploits.

### AttackVector
An attack vector to be ranked.

### RankedVector
A ranked attack vector with score and probability.

### AttackAttempt
Record of an attack attempt.

### AttackResult
Result of an attack attempt.

## Implementation Notes

### Rule-Based Approach

This implementation uses rule-based heuristics rather than trained ML models. This approach:
- Requires no training data
- Is deterministic and explainable
- Can be easily extended with new patterns
- Provides immediate results

### Future Enhancements

For production use, consider:
- Training actual ML models (scikit-learn, TensorFlow)
- Using NLP models for error analysis (transformers)
- Implementing reinforcement learning for adaptive strategies
- Collecting and using real CTF data for training
- Adding model versioning and A/B testing

## Integration

The ML Engine integrates with:
- **Reconnaissance Module**: Provides technology information
- **Attack Modules**: Receives predictions and rankings
- **Core Engine**: Coordinates learning from all attempts
- **Workspace Manager**: Persists learning data

## Performance

- Vulnerability prediction: O(n*m) where n=vulnerabilities, m=technologies
- Error analysis: O(p) where p=number of patterns
- Vector ranking: O(n log n) where n=number of vectors
- Learning: O(1) per attempt

Memory usage scales with attack history (limited to 1000 entries).
