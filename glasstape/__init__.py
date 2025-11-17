"""
GlassTape SDK - Local-First AI Agent Governance
================================================

Simple, self-contained governance for AI agents that works offline.

Features:
- File-based policy enforcement with built-in CEL evaluation (Cerbos-compatible)
- Local audit logging with cryptographic receipts
- Agent identity management for multi-agent systems
- Optional LLM parameter extraction

Usage:
    from glasstape import govern, monitor, configure
    
    # Configure (all optional - sensible defaults)
    configure(
        agent_id="my-agent",
        policy_dir="./policies",
        log_file="./audit.log"
    )
    
    # Govern tool calls with policies
    @govern("finance.payments.v1")
    def process_payment(amount: float):
        return f"Payment of ${amount} processed"
    
    # Monitor tool usage
    @monitor("analytics.usage.v1")
    def get_user_data(user_id: str):
        return f"User data for {user_id}"

Perfect for:
- Local development and testing
- Offline deployments
- Privacy-first applications
- Open-source AI agent projects
"""

from .config import configure, get_config, GlassTapeConfig
from .decorators import govern, monitor
from .router import ModeRouter
from .context import set_context, get_context, clear_context, request_context
from .errors import (
    GlassTapeError,
    ConfigurationError,
    GovernanceError,
    AuthenticationError,
    ValidationError
)

# Version
__version__ = "1.0.0"

# Main exports - elegant and minimal
__all__ = [
    # Core API
    "govern",
    "monitor",
    "configure",
    
    # Context injection (for runtime security)
    "set_context",
    "get_context",
    "clear_context",
    "request_context",
    
    # Configuration
    "get_config",
    "GlassTapeConfig",
    
    # Advanced
    "ModeRouter",
    
    # Errors
    "GlassTapeError",
    "ConfigurationError",
    "GovernanceError",
    "AuthenticationError",
    "ValidationError",
    
    # Version
    "__version__"
]