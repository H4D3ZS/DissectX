"""
Enhanced error handling and reporting for DissectX.

This module provides comprehensive error handling with detailed error messages,
context information, and debugging support.
"""

import sys
import traceback
import logging
from enum import Enum
from typing import Optional, Dict, Any
from dataclasses import dataclass


class ErrorSeverity(Enum):
    """Error severity levels."""
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class ErrorCategory(Enum):
    """Categories of errors that can occur."""
    INPUT_ERROR = "Input Error"
    ANALYSIS_ERROR = "Analysis Error"
    EMULATION_ERROR = "Emulation Error"
    RESOURCE_ERROR = "Resource Error"
    PLUGIN_ERROR = "Plugin Error"
    CONFIGURATION_ERROR = "Configuration Error"
    INTERNAL_ERROR = "Internal Error"


@dataclass
class ErrorContext:
    """Context information for an error."""
    file: Optional[str] = None
    function: Optional[str] = None
    line_number: Optional[int] = None
    binary_path: Optional[str] = None
    address: Optional[int] = None
    additional_info: Optional[Dict[str, Any]] = None


class DissectXError(Exception):
    """Base exception class for DissectX errors."""
    
    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.INTERNAL_ERROR,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        context: Optional[ErrorContext] = None,
        suggestion: Optional[str] = None,
        original_exception: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.category = category
        self.severity = severity
        self.context = context or ErrorContext()
        self.suggestion = suggestion
        self.original_exception = original_exception
    
    def __str__(self):
        """Format error message with all context."""
        lines = [
            f"\n{'='*70}",
            f"{self.severity.value}: {self.category.value}",
            f"{'='*70}",
            f"\nMessage: {self.message}",
        ]
        
        # Add context information
        if self.context.file:
            lines.append(f"File: {self.context.file}")
        if self.context.function:
            lines.append(f"Function: {self.context.function}")
        if self.context.line_number:
            lines.append(f"Line: {self.context.line_number}")
        if self.context.binary_path:
            lines.append(f"Binary: {self.context.binary_path}")
        if self.context.address is not None:
            lines.append(f"Address: {self.context.address:#x}")
        if self.context.additional_info:
            lines.append("\nAdditional Information:")
            for key, value in self.context.additional_info.items():
                lines.append(f"  {key}: {value}")
        
        # Add suggestion if available
        if self.suggestion:
            lines.append(f"\nSuggestion: {self.suggestion}")
        
        # Add original exception if available
        if self.original_exception:
            lines.append(f"\nOriginal Exception: {type(self.original_exception).__name__}")
            lines.append(f"  {str(self.original_exception)}")
        
        lines.append(f"{'='*70}\n")
        
        return "\n".join(lines)


class InputError(DissectXError):
    """Error related to invalid input."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.INPUT_ERROR,
            **kwargs
        )


class AnalysisError(DissectXError):
    """Error during binary analysis."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.ANALYSIS_ERROR,
            **kwargs
        )


class EmulationError(DissectXError):
    """Error during code emulation."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.EMULATION_ERROR,
            **kwargs
        )


class ResourceError(DissectXError):
    """Error related to system resources."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.RESOURCE_ERROR,
            **kwargs
        )


class PluginError(DissectXError):
    """Error related to plugin system."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.PLUGIN_ERROR,
            **kwargs
        )


class ConfigurationError(DissectXError):
    """Error related to configuration."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.CONFIGURATION_ERROR,
            **kwargs
        )


class ErrorHandler:
    """Central error handler for DissectX."""
    
    def __init__(self, debug_mode: bool = False):
        self.debug_mode = debug_mode
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger("DissectX")
        logger.setLevel(logging.DEBUG if self.debug_mode else logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.DEBUG if self.debug_mode else logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        
        logger.addHandler(console_handler)
        
        return logger
    
    def handle_error(
        self,
        error: Exception,
        context: Optional[ErrorContext] = None,
        reraise: bool = False
    ):
        """
        Handle an error with appropriate logging and reporting.
        
        Args:
            error: The exception to handle
            context: Additional context information
            reraise: Whether to re-raise the exception after handling
        """
        if isinstance(error, DissectXError):
            # Already a DissectX error, just log it
            self._log_dissectx_error(error)
        else:
            # Wrap in DissectX error
            dissectx_error = DissectXError(
                message=str(error),
                context=context,
                original_exception=error
            )
            self._log_dissectx_error(dissectx_error)
        
        if self.debug_mode:
            # Print full traceback in debug mode
            traceback.print_exc()
        
        if reraise:
            raise error
    
    def _log_dissectx_error(self, error: DissectXError):
        """Log a DissectX error with appropriate level."""
        error_message = str(error)
        
        if error.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(error_message)
        elif error.severity == ErrorSeverity.ERROR:
            self.logger.error(error_message)
        elif error.severity == ErrorSeverity.WARNING:
            self.logger.warning(error_message)
        else:
            self.logger.info(error_message)
    
    def log_warning(self, message: str, context: Optional[ErrorContext] = None):
        """Log a warning message."""
        warning = DissectXError(
            message=message,
            severity=ErrorSeverity.WARNING,
            context=context
        )
        self._log_dissectx_error(warning)
    
    def log_info(self, message: str):
        """Log an informational message."""
        self.logger.info(message)


# Global error handler instance
_error_handler: Optional[ErrorHandler] = None


def get_error_handler(debug_mode: bool = False) -> ErrorHandler:
    """Get or create the global error handler."""
    global _error_handler
    if _error_handler is None:
        _error_handler = ErrorHandler(debug_mode=debug_mode)
    return _error_handler


def handle_gracefully(func):
    """
    Decorator for graceful error handling.
    
    Catches exceptions and handles them appropriately without crashing.
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except DissectXError as e:
            handler = get_error_handler()
            handler.handle_error(e)
            return None
        except Exception as e:
            handler = get_error_handler()
            context = ErrorContext(
                function=func.__name__,
                additional_info={"args": str(args), "kwargs": str(kwargs)}
            )
            handler.handle_error(e, context=context)
            return None
    
    return wrapper


# Common error messages with suggestions
ERROR_MESSAGES = {
    "file_not_found": {
        "message": "Binary file not found: {path}",
        "suggestion": "Check that the file path is correct and the file exists."
    },
    "invalid_binary": {
        "message": "Invalid or corrupted binary file: {path}",
        "suggestion": "Ensure the file is a valid binary (ELF, PE, or Mach-O format)."
    },
    "unsupported_architecture": {
        "message": "Unsupported architecture: {arch}",
        "suggestion": "Use --arch flag to manually specify architecture (x86, arm, mips)."
    },
    "disassembly_failed": {
        "message": "Disassembly failed at address {address:#x}",
        "suggestion": "The binary may contain invalid instructions or be corrupted."
    },
    "emulation_failed": {
        "message": "Emulation failed at address {address:#x}",
        "suggestion": "The code may require specific setup or contain unsupported instructions."
    },
    "plugin_load_failed": {
        "message": "Failed to load plugin: {plugin_name}",
        "suggestion": "Check that the plugin file is valid and all dependencies are installed."
    },
    "out_of_memory": {
        "message": "Out of memory while processing binary",
        "suggestion": "Try processing a smaller binary or increase available memory."
    },
}


def create_error(
    error_key: str,
    severity: ErrorSeverity = ErrorSeverity.ERROR,
    context: Optional[ErrorContext] = None,
    **format_args
) -> DissectXError:
    """
    Create a DissectX error from a predefined error message.
    
    Args:
        error_key: Key in ERROR_MESSAGES dictionary
        severity: Error severity level
        context: Error context
        **format_args: Arguments to format the error message
    
    Returns:
        Configured DissectXError instance
    """
    if error_key not in ERROR_MESSAGES:
        return DissectXError(
            message=f"Unknown error: {error_key}",
            severity=severity,
            context=context
        )
    
    error_info = ERROR_MESSAGES[error_key]
    message = error_info["message"].format(**format_args)
    suggestion = error_info.get("suggestion")
    
    return DissectXError(
        message=message,
        severity=severity,
        context=context,
        suggestion=suggestion
    )
