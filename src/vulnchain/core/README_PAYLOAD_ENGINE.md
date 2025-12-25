# Payload Engine

The Payload Engine is a centralized system for managing, encoding, and mutating attack payloads for the VulnChain CTF Framework.

## Features

### 1. Wordlist Management (Requirement 18.1)
- Load wordlists from files with automatic parsing
- Support for comments (lines starting with #) and empty lines
- Organize payloads by category (e.g., "sqli", "xss", "lfi")
- Add custom payloads programmatically
- Multiple wordlists can be loaded into the same category
- Clear categories when needed

### 2. Payload Encoding (Requirements 18.2, 18.3)
Supports multiple encoding types:
- **URL Encoding**: Single and double URL encoding
- **HTML Entity Encoding**: Convert special characters to HTML entities
- **Base64 Encoding**: Standard Base64 encoding
- **Unicode Encoding**: Convert to Unicode escape sequences (\uXXXX)
- **Hex Encoding**: Convert to hex escape sequences (\xXX)
- **Encoding Chaining**: Apply multiple encodings in sequence

### 3. Payload Iteration and Delivery (Requirement 18.1)
- Iterator-based payload delivery for memory efficiency
- Filter payloads by:
  - Maximum/minimum length
  - Contains substring
  - Regular expression pattern
- Preserve original payload alongside encoded version
- Track encoding chain applied to each payload

### 4. Payload Mutation (Requirements 22.1-22.5)
Four mutation strategies:

#### Encoding Variation
- Generate mutations with different encoding schemes
- Combine multiple encodings
- Useful for bypassing input filters

#### Case Variation
- Generate uppercase, lowercase, title case variations
- Random case mixing
- Effective against case-sensitive filters

#### Syntax Variation
- Add whitespace variations (tabs, newlines)
- Inject SQL/code comments (`/**/`, `--`)
- Add null bytes and padding
- Preserve semantic meaning

#### Genetic Algorithm
- Combine multiple mutation strategies
- Generate hybrid mutations
- Adaptive payload evolution
- Maintains payload semantics while varying syntax

## Usage Examples

### Basic Wordlist Loading
```python
from app.core.payload_engine import PayloadEngine

engine = PayloadEngine()

# Load wordlist
count = engine.load_wordlist("wordlists/sqli.txt", "sqli")
print(f"Loaded {count} payloads")

# Add custom payload
engine.add_custom_payload("' OR 1=1--", "sqli")

# Get payload count
print(f"Total payloads: {engine.get_payload_count('sqli')}")
```

### Payload Iteration with Encoding
```python
# Get payloads with URL encoding
for payload in engine.get_payloads("sqli", encoding=["url"]):
    print(f"Original: {payload.original}")
    print(f"Encoded: {payload.encoded}")

# Get payloads with encoding chain
for payload in engine.get_payloads("xss", encoding=["url", "base64"]):
    print(f"Encoded: {payload.encoded}")
```

### Filtering Payloads
```python
# Filter by length
payloads = engine.get_payloads("sqli", filters={"max_length": 50})

# Filter by content
payloads = engine.get_payloads("sqli", filters={"contains": "UNION"})

# Filter by regex
payloads = engine.get_payloads("sqli", filters={"regex": r"SELECT.*FROM"})
```

### Payload Mutation
```python
from app.core.payload_engine import MutationStrategy

original = "SELECT * FROM users"

# Generate case variations
mutations = engine.mutate_payload(
    original, 
    MutationStrategy.CASE_VARIATION, 
    count=5
)

# Generate syntax variations
mutations = engine.mutate_payload(
    original,
    MutationStrategy.SYNTAX_VARIATION,
    count=10
)

# Generate genetic mutations
mutations = engine.mutate_payload(
    original,
    MutationStrategy.GENETIC,
    count=20
)
```

### Complete Attack Workflow
```python
# 1. Load payloads
engine.load_wordlist("wordlists/sqli.txt", "sqli")

# 2. Get payloads with encoding
for payload in engine.get_payloads("sqli", encoding=["url"]):
    # 3. Send payload to target
    response = send_request(target_url, payload.encoded)
    
    # 4. If blocked, generate mutations
    if is_blocked(response):
        mutations = engine.mutate_payload(
            payload.original,
            MutationStrategy.GENETIC,
            count=10
        )
        for mutation in mutations:
            response = send_request(target_url, mutation)
            if not is_blocked(response):
                print(f"Bypass found: {mutation}")
                break
```

## Architecture

### Data Models

#### Payload
```python
@dataclass
class Payload:
    original: str              # Original payload
    encoded: str               # Encoded payload
    category: str              # Category (e.g., "sqli")
    encoding_chain: List[str]  # Applied encodings
    metadata: Dict[str, any]   # Additional metadata
```

#### EncodingType (Enum)
- URL
- DOUBLE_URL
- HTML_ENTITY
- BASE64
- UNICODE
- HEX
- CASE_VARIATION

#### MutationStrategy (Enum)
- ENCODING_VARIATION
- CASE_VARIATION
- SYNTAX_VARIATION
- GENETIC

### Key Methods

#### Wordlist Management
- `load_wordlist(path, category)`: Load wordlist from file
- `add_custom_payload(payload, category)`: Add custom payload
- `get_categories()`: Get all categories
- `get_payload_count(category)`: Get payload count
- `clear_category(category)`: Clear category

#### Payload Delivery
- `get_payloads(category, encoding, filters)`: Get payloads with options
- `encode_payload(payload, encoding)`: Apply single encoding

#### Mutation
- `mutate_payload(payload, strategy, count)`: Generate mutations

## Testing

Comprehensive test suite with 30 tests covering:
- Wordlist loading and management
- Payload iteration and filtering
- All encoding types
- Encoding chains
- All mutation strategies
- Semantic preservation
- Integration workflows

Run tests:
```bash
cd backend
python -m pytest tests/test_payload_engine.py -v
```

## Demo

Run the demo to see all features in action:
```bash
cd backend
PYTHONPATH=. python examples/payload_engine_demo.py
```

## Design Principles

1. **Memory Efficiency**: Iterator-based payload delivery
2. **Flexibility**: Support for multiple encoding and mutation strategies
3. **Semantic Preservation**: Mutations preserve payload meaning
4. **Extensibility**: Easy to add new encodings and mutation strategies
5. **Testability**: Comprehensive test coverage

## Integration

The Payload Engine integrates with:
- **Request Handler**: Deliver payloads in HTTP requests
- **Attack Modules**: Provide payloads for injection testing
- **WAF Bypass Engine**: Generate mutations to evade filters
- **Fuzzing Monitor**: Track payload delivery and results

## Future Enhancements

- Machine learning-based mutation generation
- Payload effectiveness tracking
- Automatic encoding selection based on target
- Collaborative payload sharing
- Real-time payload generation based on responses
