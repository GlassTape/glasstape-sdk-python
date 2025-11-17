"""
GlassTape Request Context
=========================

Thread-safe context injection for runtime security decisions.

Philosophy:
    - Set context once per request
    - All @govern calls access it
    - Automatic cleanup
    - Zero configuration
"""

import contextvars
from typing import Dict, Any, Optional
from contextlib import contextmanager

# Context variable for async-safe storage
_request_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    'request_context',
    default={}
)

def set_context(**kwargs) -> None:
    """
    Set request context for policy evaluation.
    
    Use this to inject runtime information like:
    - User ID, role, permissions
    - Session ID, IP address
    - Request metadata
    
    Example:
        set_context(
            user_id="user123",
            user_role="standard",
            session_id="session456",
            ip_address="192.168.1.1"
        )
        
        # Now all @govern decorators can access this in policies
    """
    _request_context.set(kwargs)

def get_context() -> Dict[str, Any]:
    """
    Get current request context.
    
    Returns:
        Dict with context data, empty dict if not set
    """
    return _request_context.get()

def clear_context() -> None:
    """Clear request context"""
    _request_context.set({})

@contextmanager
def request_context(**kwargs):
    """
    Context manager for request-scoped context.
    
    Automatically sets and clears context.
    
    Example:
        with request_context(user_id="user123", role="admin"):
            result = protected_function()
            # Context automatically cleared after block
    """
    set_context(**kwargs)
    try:
        yield
    finally:
        clear_context()


__all__ = ['set_context', 'get_context', 'clear_context', 'request_context']


