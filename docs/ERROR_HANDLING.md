# Error Handling Guide

This document describes the enhanced error handling system in DissectX.

## Overview

DissectX provides a comprehensive error handling system with:
- Detailed error messages with context
- Categorized error types
- Severity levels
- Helpful suggestions for resolution
- Debug mode for detailed tracebacks

## Error Categories

### 1. Input Errors
Errors related to invalid input files or parameters.

**Examples:**
- File not found
- Invalid binary format
- Corrupted file

**Typical Resolution:** Check file paths and formats

### 2. Analysis Errors
Errors during binary analysis operations.

**Examples:**
- Disassembly failures
- Invalid instructions
- Parsing errors

**Typical Resolution:** Check binary integrity, try different architecture

### 3. Emulation Errors
Errors during code emulation.

**Examples:**
- Unsupported instructions
- Memory access violations
- Timeout conditions

**Typical Resolution:** Adjust emulation parameters, check code validity

### 4. Resource Errors
Errors related to system resources.

**Examples:**
- Out of memory
- Disk space issues
- File permission errors

**Typical Resolution:** Free up resources, check permissions

### 5. Plugin Errors
Errors in the plugin system.

**Examples:**
- Plugin loading failures
- Hook execution errors
- API misuse

**Typical Resolution:** Check plugin compatibility, update plugins

### 6. Configuration Errors
Errors in configuration or setup.

**Examples:**
- Invalid configuration files
- Missing dependencies
- Incompatible versions

**Typical Resolution:** Check configuration, install dependencies

## Error Severity Levels

- **CRITICAL**: System cannot continue, immediate attention required
- **ERROR**: Operation failed, but system can continue
- **WARNING**: Potential issue, operation may have degraded results
- **INFO**: Informational message, no action required

## Using Error Handling

### Basic Usage

```python
from src.error_handling import InputError, ErrorContext

# Raise an error with context
context = ErrorContext(
    file="binary.exe",
    function="parse_binary",
    line_number=42
)

raise InputError(
    "Invalid binary format",
    context=context,
    suggestion="Ensure the file is a valid PE/ELF binary"
)
```

### Using Predefined Errors

```python
from src.error_handling import create_error

# Create a file not found error
error = create_error("file_not_found", path="/path/to/file")
raise error
```

### Graceful Error Handling

```python
from src.error_handling import handle_gracefully

@handle_gracefully
def risky_operation():
    # This function won't crash the program if it fails
    # Errors will be logged and None will be returned
    ...
```

### Using the Error Handler

```python
from src.error_handling import get_error_handler

handler = get_error_handler(debug_mode=True)

try:
    risky_operation()
except Exception as e:
    handler.handle_error(e, reraise=False)
```

## Error Message Format

Errors are formatted with comprehensive information:

```
======================================================================
ERROR: Analysis Error
======================================================================

Message: Disassembly failed at address 0x401000

File: analyzer.py
Function: disassemble_function
Line: 123
Binary: /path/to/binary.exe
Address: 0x401000

Additional Information:
  architecture: x86_64
  instruction_bytes: 0f 1f 44 00 00

Suggestion: The binary may contain invalid instructions or be corrupted.
Try using --arch flag to specify architecture manually.

Original Exception: CapstoneError
  Invalid instruction at address 0x401000
======================================================================
```

## Debug Mode

Enable debug mode for detailed tracebacks:

```python
from src.error_handling import get_error_handler

handler = get_error_handler(debug_mode=True)
```

Or via command line:
```bash
dissectx --debug binary.exe
```

## Adding New Error Types

1. Define the error in `ERROR_MESSAGES` dictionary:

```python
ERROR_MESSAGES = {
    "my_new_error": {
        "message": "Description of error: {param}",
        "suggestion": "How to fix it"
    }
}
```

2. Use it in your code:

```python
error = create_error("my_new_error", param="value")
raise error
```

## Best Practices

1. **Always provide context**: Include file, function, and line information
2. **Add helpful suggestions**: Tell users how to fix the problem
3. **Use appropriate severity**: Don't mark warnings as critical
4. **Include original exceptions**: Wrap exceptions to preserve stack traces
5. **Log before raising**: Use the error handler to log errors
6. **Test error paths**: Write tests for error conditions

## Common Error Patterns

### File Operations

```python
from src.error_handling import create_error, ErrorContext

try:
    with open(filepath, 'rb') as f:
        data = f.read()
except FileNotFoundError:
    raise create_error("file_not_found", path=filepath)
except IOError as e:
    context = ErrorContext(file=filepath)
    raise ResourceError(
        f"Failed to read file: {e}",
        context=context,
        original_exception=e
    )
```

### Analysis Operations

```python
from src.error_handling import AnalysisError, ErrorContext

try:
    instructions = disassemble(code)
except Exception as e:
    context = ErrorContext(
        function="disassemble",
        address=current_address,
        additional_info={"code_size": len(code)}
    )
    raise AnalysisError(
        "Disassembly failed",
        context=context,
        suggestion="Check binary integrity or try different architecture",
        original_exception=e
    )
```

### Graceful Degradation

```python
from src.error_handling import get_error_handler

handler = get_error_handler()

# Try optional analysis
try:
    advanced_analysis()
except Exception as e:
    handler.log_warning("Advanced analysis failed, continuing with basic analysis")
    handler.handle_error(e, reraise=False)
    basic_analysis()
```

## Testing Error Handling

Always test error conditions:

```python
import pytest
from src.error_handling import InputError

def test_invalid_input_handling():
    """Test that invalid input raises appropriate error."""
    with pytest.raises(InputError) as exc_info:
        process_invalid_input()
    
    assert "Invalid" in str(exc_info.value)
    assert exc_info.value.suggestion is not None
```

## Logging Configuration

Configure logging level:

```python
import logging
from src.error_handling import get_error_handler

# Set logging level
logging.getLogger("DissectX").setLevel(logging.DEBUG)

# Get handler with debug mode
handler = get_error_handler(debug_mode=True)
```

## Performance Considerations

- Error handling has minimal overhead in success cases
- Debug mode adds overhead for traceback generation
- Use graceful handling sparingly in performance-critical code
- Cache error handler instance instead of creating new ones

## Migration Guide

### From Old Error Handling

**Before:**
```python
raise Exception("Something went wrong")
```

**After:**
```python
from src.error_handling import DissectXError, ErrorContext

context = ErrorContext(function="my_function")
raise DissectXError(
    "Something went wrong",
    context=context,
    suggestion="Try this instead"
)
```

### From Print Statements

**Before:**
```python
print(f"Warning: {message}")
```

**After:**
```python
from src.error_handling import get_error_handler

handler = get_error_handler()
handler.log_warning(message)
```
