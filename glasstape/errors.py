"""
Clean Error Definitions
=======================

Simple, focused error types for the MVP.
"""

class GlassTapeError(Exception):
    """Base exception for GlassTape"""
    pass

class GovernanceError(GlassTapeError):
    """Raised when policy denies tool execution"""
    
    def __init__(self, message: str, policy_id: str = None, bundle_id: str = None, reason: str = None):
        super().__init__(message)
        self.policy_id = policy_id or bundle_id  # Accept both for compatibility
        self.reason = reason

class ValidationError(GlassTapeError):
    """Raised when parameter validation fails"""
    pass

class AuthenticationError(GlassTapeError):
    """Raised when API key authentication fails"""
    pass

class ConfigurationError(GlassTapeError):
    """Raised when configuration is invalid"""
    pass

class PlatformError(GlassTapeError):
    """Raised when platform communication fails"""
    pass