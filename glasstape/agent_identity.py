"""
Agent Identity Verification & LLM Causality Chains
====================================================

Provides async-safe agent identity management and LLM-to-tool causality tracking.

Key Features:
- Context variables for async/await safety (replaces thread-local storage)
- Ed25519 cryptographic identity for non-repudiation
- LLM trace context for complete audit trails
- Multi-agent isolation in single runtime

Security:
- Agent private keys for signing decision receipts
- Context isolation prevents cross-agent contamination
- Fail-closed authentication on missing context
"""

import os
import json
import logging
import contextvars
import uuid
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone

from .config import Config
from .errors import AuthenticationError

logger = logging.getLogger(__name__)

@dataclass
class AgentContext:
    """Agent context for non-repudiation with LLM trace support"""
    agent_id: str
    org_id: str
    private_key: str
    config: Config
    
    def sign_receipt(self, receipt_data: Dict[str, Any]) -> str:
        """Sign decision receipt with agent's Ed25519 key for non-repudiation.
        
        Args:
            receipt_data: Decision receipt dictionary to sign
            
        Returns:
            Base64 encoded Ed25519 signature
            
        Raises:
            AuthenticationError: If private key is invalid or missing
        """
        if not self.private_key:
            raise AuthenticationError("Agent private key not available for signing")
            
        try:
            # Import here to avoid circular imports
            from .crypto import ed25519_sign_b64
            
            # Serialize receipt deterministically for consistent signatures
            receipt_json = json.dumps(receipt_data, sort_keys=True, separators=(',', ':'))
            receipt_bytes = receipt_json.encode('utf-8')
            
            return ed25519_sign_b64(receipt_bytes, self.private_key)
            
        except Exception as e:
            logger.error(f"Failed to sign decision receipt: {e}")
            raise AuthenticationError(f"Decision receipt signing failed: {e}")

# Context variables for async-safe agent identity and LLM tracing
_agent_context: contextvars.ContextVar[Optional[AgentContext]] = contextvars.ContextVar('agent_context', default=None)
_llm_trace_context: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar('llm_trace', default=None)
_reasoning_context: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar('reasoning_context', default=None)

class AgentIdentityManager:
    """Manages agent identity verification and context variables for async safety"""
    
    def __init__(self):
        # No longer using thread-local storage
        pass
    
    def set_agent_context(self, config: Config) -> None:
        """Set agent context using context variables (async-safe).
        
        Args:
            config: GlassTape configuration with agent identity
            
        Raises:
            AuthenticationError: If required identity fields are missing
        """
        if not config.principal or not config.principal.org_id:
            raise AuthenticationError("Missing required principal configuration")
            
        if not config.identity or not config.identity.ed25519_private_key_b64:
            raise AuthenticationError("Missing required Ed25519 private key")
            
        agent_context = AgentContext(
            agent_id=config.agent_id or f"agent_{config.principal.instance}",
            org_id=config.principal.org_id,
            private_key=config.identity.ed25519_private_key_b64,
            config=config
        )
        _agent_context.set(agent_context)
        
        logger.debug(f"Set agent context: {agent_context.agent_id} in org {agent_context.org_id}")
    
    def get_agent_context(self) -> AgentContext:
        """Get agent context from context variables"""
        context = _agent_context.get()
        if context is None:
            raise AuthenticationError(
                "No agent context found. Agent must be configured in current context."
            )
        return context
    
    def verify_agent_identity(self, expected_agent_id: str) -> bool:
        """Verify that current thread's agent matches expected identity"""
        try:
            context = self.get_agent_context()
            return context.agent_id == expected_agent_id
        except AuthenticationError:
            return False
    
    def clear_agent_context(self) -> None:
        """Clear agent context from context variables"""
        _agent_context.set(None)
        _llm_trace_context.set(None)
        _reasoning_context.set(None)
    
    def set_llm_trace(self, trace_id: str, reasoning_data: Optional[Dict[str, Any]] = None) -> None:
        """Set LLM trace ID and reasoning context for causality chains.
        
        Args:
            trace_id: Unique identifier for LLM reasoning session
            reasoning_data: Optional LLM context (messages, model, etc.)
            
        Note:
            Context propagates automatically through async/await chains
        """
        if not trace_id or not isinstance(trace_id, str):
            logger.warning(f"Invalid trace_id: {trace_id}")
            return
            
        _llm_trace_context.set(trace_id)
        if reasoning_data:
            # Validate reasoning data structure
            if isinstance(reasoning_data, dict):
                _reasoning_context.set(reasoning_data)
            else:
                logger.warning(f"Invalid reasoning_data type: {type(reasoning_data)}")
    
    def get_llm_trace(self) -> Optional[str]:
        """Get current LLM trace ID for causality chains"""
        return _llm_trace_context.get()
    
    def get_reasoning_context(self) -> Optional[Dict[str, Any]]:
        """Get current LLM reasoning context for policy optimization"""
        return _reasoning_context.get()
    
    def clear_llm_trace(self) -> None:
        """Clear LLM trace context"""
        _llm_trace_context.set(None)
        _reasoning_context.set(None)

# Global agent identity manager
_agent_identity_manager = AgentIdentityManager()

def set_agent_context(config: Config) -> None:
    """Set agent context for current async context (not thread-local).
    
    Args:
        config: GlassTape configuration with agent identity
        
    Note:
        Uses context variables for async safety. Context propagates
        automatically through async/await execution chains.
    """
    _agent_identity_manager.set_agent_context(config)

def get_agent_context() -> AgentContext:
    """Get agent context from current async context.
    
    Returns:
        AgentContext with cryptographic identity
        
    Raises:
        AuthenticationError: If no agent context is set
    """
    return _agent_identity_manager.get_agent_context()

def verify_agent_identity(expected_agent_id: str) -> bool:
    """Verify agent identity for non-repudiation"""
    return _agent_identity_manager.verify_agent_identity(expected_agent_id)

def clear_agent_context() -> None:
    """Clear agent context"""
    _agent_identity_manager.clear_agent_context()

def set_llm_trace(trace_id: str, reasoning_data: Optional[Dict[str, Any]] = None) -> None:
    """Set LLM trace ID for current context (causality chain)"""
    _agent_identity_manager.set_llm_trace(trace_id, reasoning_data)

def get_llm_trace() -> Optional[str]:
    """Get current LLM trace ID"""
    return _agent_identity_manager.get_llm_trace()

def get_reasoning_context() -> Optional[Dict[str, Any]]:
    """Get current LLM reasoning context"""
    return _agent_identity_manager.get_reasoning_context()

def clear_llm_trace() -> None:
    """Clear LLM trace context"""
    _agent_identity_manager.clear_llm_trace()

def generate_trace_id() -> str:
    """Generate cryptographically secure unique trace ID for LLM causality chains.
    
    Returns:
        Unique trace ID with format: llm_trace_{uuid}_{timestamp}
        
    Example:
        'llm_trace_a1b2c3d4e5f6_1725721800'
    """
    return f"llm_trace_{uuid.uuid4().hex[:12]}_{int(datetime.now(timezone.utc).timestamp())}"